//! Tier-0 static deobfuscation — constant folding by source-span rewriting.
//!
//! This is the first rung of the deobfuscation ladder
//! (`docs/research-large-js-deobfuscation-2026.md`). It performs **no execution**
//! — it parses with oxc, finds constant expressions that obfuscators rely on, and
//! rewrites them to their literal values directly in the source text, repeating to
//! a bounded fixpoint so layered encodings peel one round at a time.
//!
//! Folded primitives (all evaluated from AST literals only — never `eval`):
//!   * pure string concatenation:           `"al" + "ert"`            → `"alert"`
//!   * `String.fromCharCode(...)` of ints:   `String.fromCharCode(104,105)` → `"hi"`
//!   * `atob("<base64 literal>")`:            `atob("YWxlcnQ=")`        → `"alert"`
//!   * literal array indexing:               `["a","b","c"][1]`        → `"b"`
//!
//! The output is fed back through `analysis::analyse` so Carapace's AST checks see
//! the resolved payload, and is surfaced as a `NormalizedScript` artifact for the
//! Python engine. Hard line: this module NEVER executes script — pure static rewrite.

use base64::Engine;
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast::visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::SourceType;

/// Largest input the fold loop will attempt. Above this we return the source
/// unchanged — oxc parse is fast, but we cap to bound worst-case work.
const MAX_INPUT_BYTES: usize = 3 * 1024 * 1024;
/// Stop if a rewrite round pushes the source past this — a guard against
/// "deobfuscation bombs" where each layer expands the output.
const MAX_OUTPUT_BYTES: usize = 12 * 1024 * 1024;
/// Maximum fixpoint rounds.
const MAX_ITERATIONS: usize = 6;
/// Ignore decoded payloads larger than this per single fold (sanity bound).
const MAX_FOLD_VALUE_BYTES: usize = 256 * 1024;

/// Result of normalising one script.
pub struct NormalizeResult {
    /// The source with constants folded (still minified; pretty-printing is a
    /// later phase). Equal to the input when nothing folded.
    pub normalized: String,
    /// Total number of constant expressions folded across all rounds.
    pub fold_count: usize,
    /// Number of fixpoint rounds actually run.
    pub iterations: usize,
}

/// A single source-span rewrite: replace `[start, end)` with `replacement`.
struct Edit {
    start: u32,
    end: u32,
    replacement: String,
}

/// Run Tier-0 constant folding to a bounded fixpoint.
pub fn normalize(source: &str) -> NormalizeResult {
    if source.len() > MAX_INPUT_BYTES || source.trim().is_empty() {
        return NormalizeResult { normalized: source.to_string(), fold_count: 0, iterations: 0 };
    }

    let mut current = source.to_string();
    let mut total_folds = 0usize;
    let mut iterations = 0usize;

    for _ in 0..MAX_ITERATIONS {
        let edits = collect_edits(&current);
        if edits.is_empty() {
            break;
        }
        iterations += 1;
        let next = apply_edits(&current, edits, &mut total_folds);
        // Fixpoint reached, no textual change, or output-bomb guard tripped.
        if next == current || next.len() > MAX_OUTPUT_BYTES {
            if next != current && next.len() <= MAX_OUTPUT_BYTES {
                current = next;
            }
            break;
        }
        current = next;
    }

    NormalizeResult { normalized: current, fold_count: total_folds, iterations }
}

/// Parse `source` and collect all foldable spans in one immutable AST walk.
fn collect_edits(source: &str) -> Vec<Edit> {
    let allocator = Allocator::default();
    let source_type = SourceType::default().with_script(true);
    let ret = Parser::new(&allocator, source, source_type).parse();

    // A panicked parse leaves spans we cannot trust for splicing.
    if ret.panicked {
        return Vec::new();
    }

    let mut collector = FoldCollector { edits: Vec::new() };
    collector.visit_program(&ret.program);
    collector.edits
}

/// Apply non-overlapping edits to `source`, returning the rewritten string.
fn apply_edits(source: &str, mut edits: Vec<Edit>, total_folds: &mut usize) -> String {
    // Apply right-to-left so earlier offsets stay valid.
    edits.sort_by(|a, b| b.start.cmp(&a.start));
    let mut out = source.to_string();
    let mut last_applied_start = u32::MAX; // guard against overlapping spans
    for e in edits {
        if e.end > last_applied_start {
            continue; // overlaps an already-applied (later) edit — skip
        }
        let (s, en) = (e.start as usize, e.end as usize);
        if s > en || en > out.len() || !out.is_char_boundary(s) || !out.is_char_boundary(en) {
            continue;
        }
        out.replace_range(s..en, &e.replacement);
        last_applied_start = e.start;
        *total_folds += 1;
    }
    out
}

struct FoldCollector {
    edits: Vec<Edit>,
}

impl<'a> Visit<'a> for FoldCollector {
    fn visit_expression(&mut self, expr: &Expression<'a>) {
        if let Some((span, value)) = try_fold(expr) {
            if value.len() <= MAX_FOLD_VALUE_BYTES {
                self.edits.push(Edit {
                    start: span.0,
                    end: span.1,
                    replacement: quote_js(&value),
                });
                return; // do NOT descend into a folded subtree (keeps edits non-overlapping)
            }
        }
        walk::walk_expression(self, expr);
    }
}

/// If `expr` is a foldable constant string expression, return its (span, value).
fn try_fold(expr: &Expression) -> Option<((u32, u32), String)> {
    match expr {
        // "a" + "b" + ...  (pure string concatenation)
        Expression::BinaryExpression(b) if matches!(b.operator, BinaryOperator::Addition) => {
            let v = eval_string_concat(expr)?;
            Some(((b.span.start, b.span.end), v))
        }
        Expression::CallExpression(call) => {
            match &call.callee {
                // atob("<base64>")
                Expression::Identifier(id) if id.name.as_str() == "atob" => {
                    if call.arguments.len() != 1 {
                        return None;
                    }
                    if let Argument::StringLiteral(s) = &call.arguments[0] {
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(s.value.as_str())
                            .ok()?;
                        let text = String::from_utf8(decoded).ok()?;
                        return Some(((call.span.start, call.span.end), text));
                    }
                    None
                }
                // String.fromCharCode(104, 105, ...)
                Expression::StaticMemberExpression(m)
                    if m.property.name.as_str() == "fromCharCode"
                        && matches!(&m.object, Expression::Identifier(o) if o.name.as_str() == "String") =>
                {
                    let mut s = String::with_capacity(call.arguments.len());
                    for arg in &call.arguments {
                        let Argument::NumericLiteral(n) = arg else { return None };
                        let code = n.value;
                        if code < 0.0 || code.fract() != 0.0 || code > 0xFFFF as f64 {
                            return None;
                        }
                        let ch = char::from_u32(code as u32)?; // skips lone surrogates
                        s.push(ch);
                    }
                    Some(((call.span.start, call.span.end), s))
                }
                _ => None,
            }
        }
        // ["a", "b", "c"][1]
        Expression::ComputedMemberExpression(m) => {
            let Expression::ArrayExpression(arr) = &m.object else { return None };
            let Expression::NumericLiteral(idx) = &m.expression else { return None };
            if idx.value < 0.0 || idx.value.fract() != 0.0 {
                return None;
            }
            let i = idx.value as usize;
            let elem = arr.elements.get(i)?;
            if let ArrayExpressionElement::StringLiteral(s) = elem {
                return Some(((m.span.start, m.span.end), s.value.as_str().to_string()));
            }
            None
        }
        _ => None,
    }
}

/// Evaluate an expression that is a pure concatenation of string literals.
/// Returns None if any leaf is not a string literal (so we never coerce numbers
/// or fold partial/dynamic concatenations in Tier-0).
fn eval_string_concat(expr: &Expression) -> Option<String> {
    match expr {
        Expression::StringLiteral(s) => Some(s.value.as_str().to_string()),
        Expression::ParenthesizedExpression(p) => eval_string_concat(&p.expression),
        Expression::BinaryExpression(b) if matches!(b.operator, BinaryOperator::Addition) => {
            let mut left = eval_string_concat(&b.left)?;
            let right = eval_string_concat(&b.right)?;
            if left.len() + right.len() > MAX_FOLD_VALUE_BYTES {
                return None;
            }
            left.push_str(&right);
            Some(left)
        }
        _ => None,
    }
}

/// Render `s` as a double-quoted JS string literal with the necessary escapes.
fn quote_js(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\x{:02x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn norm(src: &str) -> NormalizeResult {
        normalize(src)
    }

    #[test]
    fn folds_string_concat() {
        let r = norm(r#"var x = "al" + "ert" + "(1)";"#);
        assert!(r.fold_count >= 1, "expected a fold");
        assert!(r.normalized.contains(r#""alert(1)""#), "got: {}", r.normalized);
    }

    #[test]
    fn folds_from_char_code() {
        // 104,105 -> "hi"
        let r = norm("var s = String.fromCharCode(104, 105);");
        assert!(r.normalized.contains(r#""hi""#), "got: {}", r.normalized);
    }

    #[test]
    fn folds_atob_literal() {
        // atob("YWxlcnQoMSk=") -> alert(1)
        let r = norm(r#"eval(atob("YWxlcnQoMSk="));"#);
        assert!(r.normalized.contains(r#""alert(1)""#), "got: {}", r.normalized);
    }

    #[test]
    fn folds_array_index() {
        let r = norm(r#"var u = ["safe","evil","ok"][1];"#);
        assert!(r.normalized.contains(r#""evil""#), "got: {}", r.normalized);
    }

    #[test]
    fn layered_fixpoint_exposes_eval_payload() {
        // First round folds the concat to a base64 literal; second folds the atob.
        // "ZmV0Y2g=" -> "fetch"
        let r = norm(r#"var f = atob("ZmV0" + "Y2g=");"#);
        assert!(r.iterations >= 2, "expected >=2 fixpoint rounds, got {}", r.iterations);
        assert!(r.normalized.contains(r#""fetch""#), "got: {}", r.normalized);
    }

    #[test]
    fn obfuscated_charcode_url_becomes_visible() {
        // String.fromCharCode for "//evil.tld" — the kind of hidden string a
        // regex on the raw source would miss but sees plainly after folding.
        let codes: Vec<String> = "//evil.tld".chars().map(|c| (c as u32).to_string()).collect();
        let src = format!("location.href = String.fromCharCode({});", codes.join(","));
        let r = norm(&src);
        assert!(r.normalized.contains("//evil.tld"), "got: {}", r.normalized);
    }

    #[test]
    fn clean_code_is_untouched() {
        let src = "function add(a, b) { return a + b; }";
        let r = norm(src);
        assert_eq!(r.fold_count, 0);
        assert_eq!(r.normalized, src);
    }

    #[test]
    fn numeric_addition_not_folded_as_string() {
        // 1 + 2 must NOT become "12" — Tier-0 only folds pure string concat.
        let r = norm("var n = 1 + 2;");
        assert_eq!(r.fold_count, 0, "numeric addition should not fold in Tier-0");
    }

    #[test]
    fn oversized_input_returns_unchanged() {
        let big = "x".repeat(MAX_INPUT_BYTES + 1);
        let r = norm(&big);
        assert_eq!(r.fold_count, 0);
        assert_eq!(r.iterations, 0);
    }

    #[test]
    fn quote_escapes_specials() {
        assert_eq!(quote_js("a\"b\\c\n"), r#""a\"b\\c\n""#);
    }
}
