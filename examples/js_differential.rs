//! Differential harness for the JS analysis stack.
//!
//! Runs every `*.js` file in a directory through the same three stages the render
//! pipeline and `/analyse` use, and writes one JSON line per file:
//!
//!   * `ast_flags`      — `analysis::analyse` (the oxc AST visitor)
//!   * `fold`           — `deobfuscate::normalize` (Tier-0 static folding): count + SHA-256
//!   * `pipeline_flags` — `js::deobfuscate_pipeline` (Tier-0 + Tier-2 sandbox + Tier-3)
//!
//! Built at two commits and run over the same corpus, the outputs must be identical:
//! that is how a parser/toolchain upgrade (oxc, rquickjs, Rust) proves it changed no
//! detection. Flags are sorted so ordering differences do not register as changes.
//!
//!   cargo run --release --example js_differential -- <dir-of-js> <out.jsonl>
//!
//! `pipeline_flags` involves the sandbox's wall-clock deadline, so a script that sits on
//! the deadline can differ between runs on a loaded machine; the AST and fold columns
//! are fully deterministic.
use std::{env, fs, io::Write, path::Path};

use carapace::js::{analysis, deobfuscate, deobfuscate_pipeline};
use carapace::threat::ThreatReport;
use sha2::{Digest, Sha256};

fn sorted_flags(report: &ThreatReport) -> Vec<String> {
    let mut v: Vec<String> = report
        .flags
        .iter()
        .map(|f| serde_json::to_string(f).unwrap_or_default())
        .collect();
    v.sort();
    v
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: js_differential <dir-of-js> <out.jsonl>");
    let mut paths: Vec<_> = fs::read_dir(&args[1])?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "js"))
        .collect();
    paths.sort();
    let mut out = fs::File::create(&args[2])?;
    for (i, path) in paths.iter().enumerate() {
        let bytes = fs::read(path)?;
        let src = String::from_utf8_lossy(&bytes);
        let name = Path::new(path).file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();

        let mut ast = ThreatReport::new("differential");
        analysis::analyse(&src, &name, &mut ast);

        let fold = deobfuscate::normalize(&src);
        let fold_sha = hex_sha(&fold.normalized);

        let mut pipe = ThreatReport::new("differential");
        deobfuscate_pipeline(&name, &src, &mut pipe);

        let line = serde_json::json!({
            "file": name,
            "ast_flags": sorted_flags(&ast),
            "fold": {"count": fold.fold_count, "sha256": fold_sha},
            "pipeline_flags": sorted_flags(&pipe),
            "decoded_payloads": pipe.decoded_payloads.len(),
        });
        writeln!(out, "{line}")?;
        if (i + 1) % 200 == 0 {
            eprintln!("  {}/{}", i + 1, paths.len());
        }
    }
    eprintln!("wrote {} rows to {}", paths.len(), args[2]);
    Ok(())
}

fn hex_sha(s: &str) -> String {
    Sha256::digest(s.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}
