pub mod analysis;
pub mod deobfuscate;
pub mod runtime;
pub mod vdom;

use sha2::{Digest, Sha256};
use tracing::info;

use crate::error::Result;
use crate::html::{Framework, ProcessedHtml};
use crate::threat::{NormalizedScript, ThreatReport};
use runtime::SandboxLimits;
use vdom::DomSnapshot;

/// Per-script cap on the folded source we transport back to the caller.
const MAX_NORMALIZED_BYTES: usize = 256 * 1024;

fn sha256_hex(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    format!("{:x}", h.finalize())
}

/// Tier-0 deobfuscation for one script: fold constants, and when anything
/// folded, (1) re-run static analysis on the resolved source so Carapace's AST
/// checks see the payload, and (2) record the artifact for the Python engine.
/// Used by both the render pipeline (`process`) and the `/analyse` endpoint.
pub fn deobfuscate_and_reanalyse(name: &str, source: &str, report: &mut ThreatReport) {
    let result = deobfuscate::normalize(source);
    if result.fold_count == 0 {
        return;
    }
    info!(
        "deobf: {} folded {} constant(s) in {} round(s) ({} -> {} bytes)",
        name,
        result.fold_count,
        result.iterations,
        source.len(),
        result.normalized.len(),
    );
    analysis::analyse(&result.normalized, &format!("{name}+deobf"), report);

    let mut normalized = result.normalized;
    if normalized.len() > MAX_NORMALIZED_BYTES {
        normalized.truncate(MAX_NORMALIZED_BYTES);
    }
    report.add_normalized_script(NormalizedScript {
        name: name.to_string(),
        sha256: sha256_hex(source),
        fold_count: result.fold_count,
        normalized,
    });
}

/// Output of the JS processing stage.
pub struct JsOutput {
    /// DOM snapshot after any framework rendering (or the static HTML DOM if no runtime).
    pub dom_snapshot: Option<DomSnapshot>,
    /// Console output collected from the sandbox.
    pub console_output: Vec<String>,
    /// Network requests that were blocked.
    pub blocked_network: Vec<String>,
}

/// Orchestrates static analysis + optional sandboxed execution.
pub struct JsProcessor {
    pub enable_sandbox: bool,
    pub limits: SandboxLimits,
}

impl JsProcessor {
    pub fn new(enable_sandbox: bool) -> Self {
        Self {
            enable_sandbox,
            limits: SandboxLimits::default(),
        }
    }

    /// Run static analysis on all collected scripts.
    /// If a framework is detected and the sandbox is enabled, also run
    /// the sandboxed virtual DOM render.
    pub fn process(
        &self,
        page: &ProcessedHtml,
        report: &mut ThreatReport,
    ) -> Result<JsOutput> {
        // ── Static analysis ────────────────────────────────────────────────────
        info!(
            "static analysis: {} inline + {} external scripts",
            page.scripts.inline_scripts.len(),
            page.scripts.external_scripts.len()
        );

        for (i, script) in page.scripts.inline_scripts.iter().enumerate() {
            let name = format!("inline[{}]", i);
            analysis::analyse(script, &name, report);
            // Tier-0 static deobfuscation: fold constants and re-analyse the
            // resolved source (no execution). (Large-JS deobfuscation — Phase 1)
            deobfuscate_and_reanalyse(&name, script, report);
        }

        // External scripts: analysis of their source requires fetching.
        // That is handled by the pipeline in lib.rs; their content arrives here
        // through `page.scripts.inline_scripts` after being fetched and appended.

        // ── Sandbox execution (framework pages only) ───────────────────────────
        let should_sandbox = self.enable_sandbox
            && !matches!(page.framework, Framework::Unknown);

        if should_sandbox {
            info!(
                "running JS sandbox for framework: {:?}",
                page.framework
            );

            let sandbox_result = runtime::run_sandbox(
                &page.scripts.inline_scripts,
                page.base_url.as_str(),
                &self.limits,
                report,
            )?;

            // Record blocked network calls in the threat report
            for url in &sandbox_result.network_attempts {
                report.add_blocked_network(url.clone());
            }

            // Record clipboard writes — the payload delivery vector in ClickFix attacks.
            // Skip empty-payload entries (e.g. bare execCommand detections with no content).
            for (method, payload) in &sandbox_result.clipboard_writes {
                if !payload.is_empty() {
                    report.add_js_flag(crate::threat::JsFlag::ClipboardWrite {
                        method: method.clone(),
                        payload: payload.clone(),
                    });
                }
            }

            return Ok(JsOutput {
                dom_snapshot: Some(sandbox_result.dom_snapshot),
                console_output: sandbox_result.console_output,
                blocked_network: sandbox_result.network_attempts,
            });
        }

        Ok(JsOutput {
            dom_snapshot: None,
            console_output: vec![],
            blocked_network: vec![],
        })
    }
}
