//! Dump the sink index (js::sinks) for every `*.js` file in a directory as JSONL, with
//! per-file timing. Used to check the index for panics / pathological cost over a
//! corpus and to inspect what it extracts.
//!
//!   cargo run --release --example js_sinks -- <dir-of-js> <out.jsonl>
use std::{env, fs, io::Write, time::Instant};

use carapace::js::sinks;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    anyhow::ensure!(args.len() == 3, "usage: js_sinks <dir-of-js> <out.jsonl>");
    let mut paths: Vec<_> = fs::read_dir(&args[1])?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "js"))
        .collect();
    paths.sort();
    let mut out = fs::File::create(&args[2])?;
    let started = Instant::now();
    for path in &paths {
        let src = String::from_utf8_lossy(&fs::read(path)?).to_string();
        let t = Instant::now();
        let ix = sinks::index(&src);
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        let name = path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        writeln!(out, "{}", serde_json::json!({"file": name, "bytes": src.len(), "ms": ms, "index": ix}))?;
    }
    eprintln!("{} files in {:.2}s", paths.len(), started.elapsed().as_secs_f64());
    Ok(())
}
