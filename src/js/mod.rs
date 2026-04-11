pub mod analysis;
pub mod runtime;
pub mod vdom;

use tracing::info;

use crate::error::Result;
use crate::html::{Framework, ProcessedHtml};
use crate::threat::ThreatReport;
use runtime::SandboxLimits;
use vdom::DomSnapshot;

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
            analysis::analyse(script, &format!("inline[{}]", i), report);
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
