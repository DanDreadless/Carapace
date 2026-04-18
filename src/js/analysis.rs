use base64::Engine;
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast::visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::SourceType;
use tracing::debug;

use crate::threat::{CodeLocation, DecodedString, DomMutation, JsFlag, NetworkCall, ThreatReport};

/// Run static analysis on a JS source string and append findings to `report`.
/// Never executes the script.
pub fn analyse(source: &str, source_name: &str, report: &mut ThreatReport) {
    let allocator = Allocator::default();
    let source_type = SourceType::default().with_script(true);
    let result = Parser::new(&allocator, source, source_type).parse();

    if !result.errors.is_empty() {
        debug!(
            "{}: {} parse error(s) — continuing analysis on partial AST",
            source_name,
            result.errors.len()
        );
    }

    let mut visitor = SecurityVisitor {
        report,
        source_name: source_name.to_string(),
    };
    visitor.visit_program(&result.program);
}

struct SecurityVisitor<'r> {
    report: &'r mut ThreatReport,
    source_name: String,
}

impl SecurityVisitor<'_> {
    fn loc(&self, byte_offset: u32) -> CodeLocation {
        CodeLocation {
            source: self.source_name.clone(),
            line: byte_offset,
            col: 0,
        }
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

                // document.hasFocus() — always returns false in headless; exclusively
                // used in anti-bot fingerprinting to detect automated analysis.
                if prop == "hasFocus" {
                    if let Expression::Identifier(obj) = &member.object {
                        if obj.name == "document" {
                            self.report.add_js_flag(JsFlag::SandboxEvasion {
                                technique: "focus_probe".into(),
                                detail: "document.hasFocus() called — always false in headless; used to detect automated analysis environments".into(),
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
            Expression::NewExpression(new_expr) => {
                if let Expression::Identifier(ident) = &new_expr.callee {
                    if ident.name == "Function" && !new_expr.arguments.is_empty() {
                        let arg = last_string_arg(&new_expr.arguments);
                        self.report.add_js_flag(JsFlag::FunctionConstructor { loc, arg });
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
                    self.report.add_js_flag(JsFlag::FunctionConstructor { loc, arg });
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

            match (obj_name, prop) {
                // navigator.webdriver — THE headless detection property.
                // No legitimate code reads this; only anti-bot scripts do.
                ("navigator", "webdriver") => {
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: "webdriver_check".into(),
                        detail: "navigator.webdriver accessed — headless browser detection".into(),
                        loc,
                    });
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
                ("window", "chrome") => {
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: "chrome_runtime_probe".into(),
                        detail: "window.chrome accessed — undefined in headless; standard headless-Chrome detection probe".into(),
                        loc,
                    });
                }
                // chrome.runtime — accessed without the window. prefix.  Near-exclusive
                // indicator of headless browser detection; no legitimate page content reads this.
                ("chrome", "runtime") => {
                    self.report.add_js_flag(JsFlag::SandboxEvasion {
                        technique: "chrome_runtime_probe".into(),
                        detail: "chrome.runtime accessed — present in real Chrome extensions, absent in headless; used to detect automated analysis environments".into(),
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

        // StringLiteral has no children — no walk needed.
    }
}

// ── Utility functions ─────────────────────────────────────────────────────────

/// Extract the string value of the first argument if it's a string literal.
fn first_string_arg(args: &[Argument]) -> Option<String> {
    nth_string_arg(args, 0)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::threat::ThreatReport;

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
}
