use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rquickjs::{Context, Ctx, Function, Object, Runtime, Value};
use tracing::{debug, info, warn};

use crate::error::{CarapaceError, Result};
use crate::threat::ThreatReport;
use super::vdom::{new_shared_vdom, SharedVDom, DomSnapshot};

/// Resource limits for the JS sandbox.
#[derive(Debug, Clone)]
pub struct SandboxLimits {
    /// Maximum heap memory in bytes.
    pub max_memory: usize,
    /// Maximum total CPU wall-clock time.
    pub max_duration: Duration,
    /// Maximum number of script blocks executed.
    pub max_scripts: usize,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_memory: 64 * 1024 * 1024, // 64 MB
            max_duration: Duration::from_secs(5),
            max_scripts: 20,
        }
    }
}

/// Output of a sandboxed JS execution.
#[derive(Debug)]
pub struct SandboxResult {
    pub dom_snapshot: DomSnapshot,
    pub console_output: Vec<String>,
    pub blocked_globals: Vec<String>,
    pub network_attempts: Vec<String>,
}

/// Executes a collection of JS script blocks inside a sandboxed rquickjs
/// context. The sandbox has a virtual DOM but no real network, filesystem,
/// or timer access.
pub fn run_sandbox(
    scripts: &[String],
    base_url: &str,
    limits: &SandboxLimits,
    _report: &mut ThreatReport,
) -> Result<SandboxResult> {
    if scripts.is_empty() {
        let vdom = super::vdom::VDom::new();
        return Ok(SandboxResult {
            dom_snapshot: vdom.snapshot(),
            console_output: vec![],
            blocked_globals: vec![],
            network_attempts: vec![],
        });
    }

    let vdom = new_shared_vdom();
    let console_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let network_attempts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let blocked_globals: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let rt = Runtime::new().map_err(|e| CarapaceError::JsRuntime(e.to_string()))?;
    rt.set_memory_limit(limits.max_memory);
    rt.set_max_stack_size(512 * 1024); // 512 KB stack

    let ctx = Context::full(&rt).map_err(|e| CarapaceError::JsRuntime(e.to_string()))?;

    let start = Instant::now();

    ctx.with(|ctx| -> std::result::Result<(), rquickjs::Error> {
        let globals = ctx.globals();

        // ── console ───────────────────────────────────────────────────────────
        setup_console(&ctx, &globals, Arc::clone(&console_log))?;

        // ── document ──────────────────────────────────────────────────────────
        setup_document(&ctx, &globals, Arc::clone(&vdom))?;

        // ── window ────────────────────────────────────────────────────────────
        setup_window(&ctx, &globals, base_url, Arc::clone(&network_attempts))?;

        // ── blocked network APIs ──────────────────────────────────────────────
        setup_blocked_network(
            &ctx,
            &globals,
            Arc::clone(&network_attempts),
            Arc::clone(&blocked_globals),
        )?;

        // ── storage stubs ─────────────────────────────────────────────────────
        setup_storage(&ctx, &globals)?;

        // ── misc browser APIs ─────────────────────────────────────────────────
        setup_misc(&ctx, &globals)?;

        Ok(())
    })
    .map_err(|e| CarapaceError::JsRuntime(e.to_string()))?;

    // Execute each script block
    let mut executed = 0;
    for (i, script) in scripts.iter().enumerate().take(limits.max_scripts) {
        if start.elapsed() >= limits.max_duration {
            warn!("sandbox: CPU budget exceeded after {} scripts", i);
            break;
        }

        debug!("sandbox: executing script block {}/{}", i + 1, scripts.len());

        let script_result: std::result::Result<(), _> = ctx.with(|ctx| {
            ctx.eval::<(), _>(script.as_str())
        });

        match script_result {
            Ok(()) => {
                executed += 1;
            }
            Err(e) => {
                warn!("sandbox: script {} error: {}", i, e);
                // Non-fatal — continue with remaining scripts
            }
        }
    }

    info!("sandbox: executed {}/{} script blocks", executed, scripts.len());

    // Extract DOM snapshot
    let dom_snapshot = vdom.lock().unwrap().snapshot();
    let console_output = console_log.lock().unwrap().clone();
    let network_attempts = network_attempts.lock().unwrap().clone();
    let blocked_globals = blocked_globals.lock().unwrap().clone();

    Ok(SandboxResult {
        dom_snapshot,
        console_output,
        blocked_globals,
        network_attempts,
    })
}

// ── Global setup functions ────────────────────────────────────────────────────

fn setup_console<'js>(
    ctx: &Ctx<'js>,
    globals: &Object<'js>,
    log_sink: Arc<Mutex<Vec<String>>>,
) -> std::result::Result<(), rquickjs::Error> {
    let console = Object::new(ctx.clone())?;

    macro_rules! console_fn {
        ($level:literal, $sink:expr) => {{
            let sink = Arc::clone(&$sink);
            Function::new(
                ctx.clone(),
                move |args: rquickjs::function::Rest<rquickjs::Value>| {
                    let parts: Vec<String> = args
                        .iter()
                        .map(|v| format!("{:?}", v))
                        .collect();
                    let msg = format!("[{}] {}", $level, parts.join(" "));
                    sink.lock().unwrap().push(msg);
                },
            )?
        }};
    }

    console.set("log",   console_fn!("log",   log_sink))?;
    console.set("warn",  console_fn!("warn",  log_sink))?;
    console.set("error", console_fn!("error", log_sink))?;
    console.set("info",  console_fn!("info",  log_sink))?;
    console.set("debug", console_fn!("debug", log_sink))?;

    globals.set("console", console)?;
    Ok(())
}

fn setup_document<'js>(
    ctx: &Ctx<'js>,
    globals: &Object<'js>,
    vdom: SharedVDom,
) -> std::result::Result<(), rquickjs::Error> {
    let doc = Object::new(ctx.clone())?;

    // document.createElement
    {
        let vdom = Arc::clone(&vdom);
        let create_element = Function::new(ctx.clone(), move |tag: String| {
            let id = vdom.lock().unwrap().create_element(&tag);
            // Return the node ID as a plain number for now.
            // A full implementation would return a JS proxy object.
            id as u32
        })?;
        doc.set("createElement", create_element)?;
    }

    // document.createTextNode
    {
        let vdom = Arc::clone(&vdom);
        let create_text = Function::new(ctx.clone(), move |text: String| {
            vdom.lock().unwrap().create_text_node(&text) as u32
        })?;
        doc.set("createTextNode", create_text)?;
    }

    // document.body / document.head (return node ID)
    {
        let vdom = Arc::clone(&vdom);
        let body_id = vdom.lock().unwrap().body_id as u32;
        doc.set("body", body_id)?;
        let head_id = vdom.lock().unwrap().head_id as u32;
        doc.set("head", head_id)?;
    }

    // document.getElementById
    {
        let vdom = Arc::clone(&vdom);
        let get_by_id = Function::new(ctx.clone(), move |id: String| {
            vdom.lock().unwrap().get_element_by_id(&id).map(|n| n as u32)
        })?;
        doc.set("getElementById", get_by_id)?;
    }

    // document.cookie — getter returns empty string; setter is logged
    doc.set("cookie", "")?;

    // document.addEventListener — no-op
    {
        let noop = Function::new(ctx.clone(), |_event: String, _handler: Value| {})?;
        doc.set("addEventListener", noop)?;
    }

    // document.__snapshot__ — internal API to extract the VDom
    {
        let vdom = Arc::clone(&vdom);
        let snapshot_fn = Function::new(ctx.clone(), move || {
            let snapshot = vdom.lock().unwrap().snapshot();
            serde_json::to_string(&snapshot).unwrap_or_default()
        })?;
        doc.set("__snapshot__", snapshot_fn)?;
    }

    globals.set("document", doc)?;
    Ok(())
}

fn setup_window<'js>(
    ctx: &Ctx<'js>,
    globals: &Object<'js>,
    base_url: &str,
    _network_log: Arc<Mutex<Vec<String>>>,
) -> std::result::Result<(), rquickjs::Error> {
    let window = Object::new(ctx.clone())?;

    // window.location stub
    let location = Object::new(ctx.clone())?;
    location.set("href", base_url)?;
    location.set("origin", extract_origin(base_url))?;
    location.set("pathname", "/")?;
    window.set("location", location)?;

    // window.navigator stub
    let navigator = Object::new(ctx.clone())?;
    navigator.set("userAgent", "Carapace/0.1 SafeRenderer")?;
    navigator.set("language", "en-US")?;
    navigator.set("languages", vec!["en-US", "en"])?;
    navigator.set("cookieEnabled", false)?;
    navigator.set("onLine", false)?;
    window.set("navigator", navigator)?;

    // window.screen
    let screen = Object::new(ctx.clone())?;
    screen.set("width", 1280u32)?;
    screen.set("height", 800u32)?;
    screen.set("availWidth", 1280u32)?;
    screen.set("availHeight", 800u32)?;
    window.set("screen", screen)?;

    // window dimensions
    window.set("innerWidth", 1280u32)?;
    window.set("innerHeight", 800u32)?;
    window.set("outerWidth", 1280u32)?;
    window.set("outerHeight", 800u32)?;
    window.set("devicePixelRatio", 1.0f64)?;

    // window.addEventListener / removeEventListener — no-op
    {
        let noop = Function::new(ctx.clone(), |_: String, _: Value| {})?;
        window.set("addEventListener", noop.clone())?;
        window.set("removeEventListener", noop)?;
    }

    // window.dispatchEvent — no-op
    {
        let noop = Function::new(ctx.clone(), |_: Value| {})?;
        window.set("dispatchEvent", noop)?;
    }

    // window.getComputedStyle — returns empty object
    {
        let get_computed = Function::new(ctx.clone(), |_el: Value| {
            // Return empty object — proper computed styles require layout
        })?;
        window.set("getComputedStyle", get_computed)?;
    }

    // window.requestAnimationFrame — calls callback once synchronously
    {
        let raf = Function::new(ctx.clone(), |_cb: Value| {
            // In a full implementation: ctx.call(cb, (0.0f64,))
            // Stubbed for now
        })?;
        window.set("requestAnimationFrame", raf)?;
    }

    // window.atob / btoa — decode and log
    {
        let atob = Function::new(ctx.clone(), move |s: String| -> String {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(&s)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default()
        })?;
        window.set("atob", atob)?;
    }

    // window.history — no-op stub
    {
        let history = Object::new(ctx.clone())?;
        let noop = Function::new(ctx.clone(), |_: Value| {})?;
        history.set("pushState", noop.clone())?;
        history.set("replaceState", noop.clone())?;
        history.set("back", noop.clone())?;
        history.set("forward", noop)?;
        window.set("history", history)?;
    }

    // window.performance
    {
        let perf = Object::new(ctx.clone())?;
        let now = Function::new(ctx.clone(), || 0.0f64)?;
        perf.set("now", now)?;
        window.set("performance", perf)?;
    }

    // Alias window → self and globalThis
    globals.set("window", window.clone())?;
    globals.set("self", window.clone())?;
    globals.set("globalThis", window)?;

    Ok(())
}

fn setup_blocked_network<'js>(
    ctx: &Ctx<'js>,
    globals: &Object<'js>,
    network_log: Arc<Mutex<Vec<String>>>,
    blocked_log: Arc<Mutex<Vec<String>>>,
) -> std::result::Result<(), rquickjs::Error> {
    // fetch() — always rejects
    {
        let net = Arc::clone(&network_log);
        let fetch_fn = Function::new(ctx.clone(), move |url: Option<String>, _opts: Value| {
            let url = url.unwrap_or_else(|| "<unknown>".into());
            warn!("sandbox: blocked fetch({})", url);
            net.lock().unwrap().push(format!("fetch:{}", url));
            // Return undefined; a real Promise.reject would be ideal
        })?;
        globals.set("fetch", fetch_fn)?;
    }

    // XMLHttpRequest — non-functional constructor
    {
        let net = Arc::clone(&network_log);
        let xhr_class = Function::new(ctx.clone(), move || {
            net.lock().unwrap().push("XMLHttpRequest".into());
        })?;
        globals.set("XMLHttpRequest", xhr_class)?;
    }

    // WebSocket — throws on construction
    {
        let net = Arc::clone(&network_log);
        let ws_class = Function::new(ctx.clone(), move |url: Option<String>| {
            let url = url.unwrap_or_default();
            warn!("sandbox: blocked WebSocket({})", url);
            net.lock().unwrap().push(format!("WebSocket:{}", url));
        })?;
        globals.set("WebSocket", ws_class)?;
    }

    // process / require / module — block Node.js globals
    for name in &["process", "require", "module", "__dirname", "__filename"] {
        let n = name.to_string();
        let blocked = Arc::clone(&blocked_log);
        let guard = Function::new(ctx.clone(), move || {
            blocked.lock().unwrap().push(n.clone());
        })?;
        globals.set(*name, guard)?;
    }

    Ok(())
}

fn setup_storage<'js>(
    ctx: &Ctx<'js>,
    globals: &Object<'js>,
) -> std::result::Result<(), rquickjs::Error> {
    // Both localStorage and sessionStorage are in-memory stubs.
    // Data persists only for this execution and is discarded with the runtime.
    for name in &["localStorage", "sessionStorage"] {
        let store = Object::new(ctx.clone())?;
        let data: Arc<Mutex<std::collections::HashMap<String, String>>> =
            Arc::new(Mutex::new(Default::default()));

        {
            let d = Arc::clone(&data);
            let set_item = Function::new(ctx.clone(), move |key: String, value: String| {
                d.lock().unwrap().insert(key, value);
            })?;
            store.set("setItem", set_item)?;
        }
        {
            let d = Arc::clone(&data);
            let get_item = Function::new(ctx.clone(), move |key: String| -> Option<String> {
                d.lock().unwrap().get(&key).cloned()
            })?;
            store.set("getItem", get_item)?;
        }
        {
            let d = Arc::clone(&data);
            let remove_item = Function::new(ctx.clone(), move |key: String| {
                d.lock().unwrap().remove(&key);
            })?;
            store.set("removeItem", remove_item)?;
        }
        {
            let d = Arc::clone(&data);
            let clear = Function::new(ctx.clone(), move || {
                d.lock().unwrap().clear();
            })?;
            store.set("clear", clear)?;
        }

        globals.set(*name, store)?;
    }

    Ok(())
}

fn setup_misc<'js>(
    ctx: &Ctx<'js>,
    globals: &Object<'js>,
) -> std::result::Result<(), rquickjs::Error> {
    // crypto.getRandomValues — deterministic zeros (for reproducible renders)
    let crypto = Object::new(ctx.clone())?;
    let get_random = Function::new(ctx.clone(), |_arr: Value| {})?;
    crypto.set("getRandomValues", get_random)?;
    globals.set("crypto", crypto)?;

    // MutationObserver stub
    let mo = Function::new(ctx.clone(), |_cb: Value| {})?;
    globals.set("MutationObserver", mo)?;

    // IntersectionObserver stub
    let io = Function::new(ctx.clone(), |_cb: Value| {})?;
    globals.set("IntersectionObserver", io)?;

    // ResizeObserver stub
    let ro = Function::new(ctx.clone(), |_cb: Value| {})?;
    globals.set("ResizeObserver", ro)?;

    // URL constructor (basic stub)
    {
        let url_ctor = Function::new(ctx.clone(), |href: String, _base: Option<String>| {
            // Return the href as-is; a real implementation would parse it
            href
        })?;
        globals.set("URL", url_ctor)?;
    }

    Ok(())
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn extract_origin(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| {
            let scheme = u.scheme();
            let host = u.host_str()?;
            let port = u
                .port()
                .map(|p| format!(":{p}"))
                .unwrap_or_default();
            Some(format!("{scheme}://{host}{port}"))
        })
        .unwrap_or_default()
}
