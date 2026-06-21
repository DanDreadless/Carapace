use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rquickjs::{Context, Ctx, Function, Object, Runtime, Value};
use tracing::{debug, info, warn};

/// Injected before user scripts to set up copy-event handler capture.
/// Replaces `document.addEventListener` with a version that stores 'copy'
/// handlers in `window.__cc_copy_handlers__` for the teardown to fire.
const CLIPBOARD_PREAMBLE: &str = r#"(function(){
  window.__cc_copy_handlers__=[];
  var _oa=document.addEventListener;
  document.addEventListener=function(t,f,o){
    if(typeof t==='string'&&t==='copy'&&typeof f==='function')
      window.__cc_copy_handlers__.push(f);
    if(typeof _oa==='function')_oa(t,f,o);
  };
  try{Object.defineProperty(document,'oncopy',{configurable:true,set:function(f){
    if(typeof f==='function')window.__cc_copy_handlers__.push(f);
  }});}catch(e){}
})();"#;

/// Run after all user scripts to synthetically fire a copy event and capture
/// any payload written via `clipboardData.setData`. Returns a JSON array of
/// strings (one per handler that called setData with a non-empty value).
const CLIPBOARD_TEARDOWN: &str = r#"(function(){
  var r=[];
  var hs=window.__cc_copy_handlers__||[];
  hs.forEach(function(h){
    try{
      var c=null;
      var ev={
        clipboardData:{
          setData:function(t,v){if(c===null&&typeof v==='string'&&v!=='')c=v;},
          getData:function(){return '';}
        },
        preventDefault:function(){},
        stopPropagation:function(){}
      };
      h(ev);
      if(c!==null)r.push(c);
    }catch(e){}
  });
  return JSON.stringify(r);
})();"#;

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
    /// Clipboard writes intercepted during execution: (method, payload).
    /// `method` is `"navigator.clipboard.writeText"` or `"copy_event"`.
    pub clipboard_writes: Vec<(String, String)>,
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
            clipboard_writes: vec![],
        });
    }

    let vdom = new_shared_vdom();
    let console_log: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let network_attempts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let blocked_globals: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let clipboard_writes: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));

    let rt = Runtime::new().map_err(|e| CarapaceError::JsRuntime(e.to_string()))?;
    rt.set_memory_limit(limits.max_memory);
    rt.set_max_stack_size(512 * 1024); // 512 KB stack
    // Abort runaway loops in a single script block at the deadline — without this
    // a `while(1){}` would hang the worker (the per-block budget check only runs
    // between blocks, not during one).
    let interrupt_deadline = Instant::now() + limits.max_duration;
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() >= interrupt_deadline)));

    let ctx = Context::full(&rt).map_err(|e| CarapaceError::JsRuntime(e.to_string()))?;

    let start = Instant::now();

    ctx.with(|ctx| -> std::result::Result<(), rquickjs::Error> {
        let globals = ctx.globals();

        // ── console ───────────────────────────────────────────────────────────
        setup_console(&ctx, &globals, Arc::clone(&console_log))?;

        // ── document ──────────────────────────────────────────────────────────
        setup_document(&ctx, &globals, Arc::clone(&vdom), Arc::clone(&clipboard_writes))?;

        // ── window ────────────────────────────────────────────────────────────
        setup_window(&ctx, &globals, base_url, Arc::clone(&network_attempts), Arc::clone(&clipboard_writes))?;

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

    // Inject preamble first to capture copy event handlers registered by user scripts.
    let mut all_scripts: Vec<&str> = Vec::with_capacity(scripts.len() + 1);
    all_scripts.push(CLIPBOARD_PREAMBLE);
    all_scripts.extend(scripts.iter().map(|s| s.as_str()));

    // Execute each script block
    let mut executed = 0;
    for (i, script) in all_scripts.iter().enumerate().take(limits.max_scripts) {
        if start.elapsed() >= limits.max_duration {
            warn!("sandbox: CPU budget exceeded after {} scripts", i);
            break;
        }

        debug!("sandbox: executing script block {}/{}", i + 1, all_scripts.len());

        let script_result: std::result::Result<(), _> = ctx.with(|ctx| {
            ctx.eval::<(), _>(*script)
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

    // Fire synthetic copy event to capture any registered copy event handlers.
    let event_writes: Vec<String> = ctx.with(|ctx| -> Vec<String> {
        ctx.eval::<String, _>(CLIPBOARD_TEARDOWN)
            .ok()
            .and_then(|json| serde_json::from_str::<Vec<String>>(&json).ok())
            .unwrap_or_default()
    });
    {
        let mut cw = clipboard_writes.lock().unwrap();
        for payload in event_writes {
            cw.push(("copy_event".to_string(), payload));
        }
    }

    // Extract DOM snapshot
    let dom_snapshot = vdom.lock().unwrap().snapshot();
    let console_output = console_log.lock().unwrap().clone();
    let network_attempts = network_attempts.lock().unwrap().clone();
    let blocked_globals = blocked_globals.lock().unwrap().clone();
    let clipboard_writes = clipboard_writes.lock().unwrap().clone();

    Ok(SandboxResult {
        dom_snapshot,
        console_output,
        blocked_globals,
        network_attempts,
        clipboard_writes,
    })
}

// ── Deobfuscation sink-capture sandbox (Tier-2) ─────────────────────────────────

/// Installed before the analysed script. Neuters the dynamic-code and decode
/// sinks so that, instead of *executing* a deobfuscated payload, the sandbox
/// *captures* it. The obfuscated script's own decoder still runs (in the
/// capability-free sandbox) and assembles the cleartext — we intercept it at the
/// final sink (`eval`, `Function`, `document.write`, `setTimeout(string)`) and at
/// the common decode primitives (`atob`/`unescape`/`decodeURIComponent`).
///
/// Captures accumulate in `globalThis.__cap__` as `"<sink> <payload>"`.
/// `atob`/`unescape`/`decodeURIComponent` still RETURN the real decoded value so
/// layered decoders keep working; `eval`/`Function` do NOT execute the payload.
const DEOBF_PREAMBLE: &str = r#"(function(){
  var C = (globalThis.__cap__ = []);
  function rec(sink, v){ try{ if(typeof v==='string' && v.length>0 && v.length<4000000) C.push(sink+' '+v); }catch(e){} }
  try{ globalThis.eval = function(c){ rec('eval', c); return undefined; }; }catch(e){}
  try{
    var _F = globalThis.Function;
    var NF = function(){ var a=arguments; var b=a.length?a[a.length-1]:''; rec('Function', b); return function(){}; };
    try{ NF.prototype = _F.prototype; }catch(e){}
    globalThis.Function = NF;
  }catch(e){}
  try{ var _a=globalThis.atob; globalThis.atob=function(s){ var r=''; try{r=_a?_a(s):''}catch(e){} rec('atob', r); return r; }; }catch(e){}
  try{ var _u=globalThis.unescape; globalThis.unescape=function(s){ var r=s; try{r=_u?_u(s):s}catch(e){} rec('unescape', r); return r; }; }catch(e){}
  try{ var _d=globalThis.decodeURIComponent; globalThis.decodeURIComponent=function(s){ var r=s; try{r=_d(s)}catch(e){} rec('decodeURIComponent', r); return r; }; }catch(e){}
  try{ if(globalThis.document){ globalThis.document.write=function(h){ rec('document.write', h); }; globalThis.document.writeln=function(h){ rec('document.write', h); }; } }catch(e){}
  try{ globalThis.setTimeout=function(f){ if(typeof f==='string') rec('setTimeout', f); return 0; }; }catch(e){}
  try{ globalThis.setInterval=function(f){ if(typeof f==='string') rec('setInterval', f); return 0; }; }catch(e){}
})();"#;

const DEOBF_TEARDOWN: &str = r#"(function(){ try{ return JSON.stringify(globalThis.__cap__||[]); }catch(e){ return "[]"; } })()"#;

/// One sink-capture pass over a single script. Captured payloads are the strings
/// the script tried to `eval`/`Function`/`document.write`/`setTimeout` or decode.
#[derive(Debug, Default)]
pub struct DeobResult {
    /// `(sink, payload)` pairs, e.g. `("eval", "fetch('https://c2')")`.
    pub captured: Vec<(String, String)>,
}

/// Execute `script` in a capability-free QuickJS sandbox with the dynamic-code
/// sinks neutered to *capture* rather than execute. Network, filesystem, process
/// and timers are all absent/blocked; memory, stack and wall-clock are capped and
/// an interrupt handler aborts runaway loops at the deadline. Never returns an
/// error — capture is best-effort.
pub fn run_deobfuscation_sandbox(script: &str, limits: &SandboxLimits) -> DeobResult {
    let rt = match Runtime::new() {
        Ok(r) => r,
        Err(e) => { warn!("deobf-sandbox: runtime init failed: {}", e); return DeobResult::default(); }
    };
    rt.set_memory_limit(limits.max_memory);
    rt.set_max_stack_size(512 * 1024);

    // Hard stop for infinite loops in hostile code — without this a `while(1){}`
    // in a sample would hang the worker. The handler returns true once the
    // deadline passes, raising an uncatchable exception inside the interpreter.
    let deadline = Instant::now() + limits.max_duration;
    rt.set_interrupt_handler(Some(Box::new(move || Instant::now() >= deadline)));

    let ctx = match Context::full(&rt) {
        Ok(c) => c,
        Err(e) => { warn!("deobf-sandbox: context init failed: {}", e); return DeobResult::default(); }
    };

    // Reuse the standard capability-free environment, then add a native global
    // `atob` so the preamble can wrap a real base64 decoder.
    let vdom = new_shared_vdom();
    let throwaway: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let cw: Arc<Mutex<Vec<(String, String)>>> = Arc::new(Mutex::new(Vec::new()));
    let _ = ctx.with(|ctx| -> std::result::Result<(), rquickjs::Error> {
        let g = ctx.globals();
        setup_console(&ctx, &g, Arc::clone(&throwaway))?;
        setup_document(&ctx, &g, Arc::clone(&vdom), Arc::clone(&cw))?;
        setup_window(&ctx, &g, "https://analysis.local/", Arc::clone(&throwaway), Arc::clone(&cw))?;
        setup_blocked_network(&ctx, &g, Arc::clone(&throwaway), Arc::clone(&throwaway))?;
        setup_storage(&ctx, &g)?;
        setup_misc(&ctx, &g)?;
        let atob = Function::new(ctx.clone(), |s: String| -> String {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD
                .decode(s.as_bytes())
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .unwrap_or_default()
        })?;
        g.set("atob", atob)?;
        Ok(())
    });

    // Eval in NON-strict mode: rquickjs defaults to strict, where
    // `(function(){return this;})()` yields undefined. Non-strict + global scope
    // makes that idiom return the real global so the hooks bind correctly, and is
    // also more compatible with the sloppy-mode code obfuscators tend to emit.
    fn eval_loose(ctx: &Ctx, src: &str) {
        let mut opts = rquickjs::context::EvalOptions::default();
        opts.strict = false;
        let _ = ctx.eval_with_options::<(), _>(src, opts);
    }

    // The sandbox setup binds `globalThis` to the window stub; rebind it to the
    // REAL global object so the preamble's `globalThis.eval = ...` overrides the
    // binding that bare `eval(...)` calls actually resolve against.
    ctx.with(|ctx| eval_loose(&ctx,
        "(function(){var g=(function(){return this;})();if(g){g.globalThis=g;}})();"));
    // Install the capture hooks, then run the (potentially hostile) script.
    ctx.with(|ctx| eval_loose(&ctx, DEOBF_PREAMBLE));
    ctx.with(|ctx| eval_loose(&ctx, script));

    let json = ctx.with(|ctx| {
        let mut opts = rquickjs::context::EvalOptions::default();
        opts.strict = false;
        ctx.eval_with_options::<String, _>(DEOBF_TEARDOWN, opts)
            .unwrap_or_else(|_| "[]".to_string())
    });
    let mut captured = Vec::new();
    if let Ok(items) = serde_json::from_str::<Vec<String>>(&json) {
        for item in items {
            if let Some((sink, payload)) = item.split_once(' ') {
                captured.push((sink.to_string(), payload.to_string()));
            }
        }
    }
    DeobResult { captured }
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
    clipboard_writes: Arc<Mutex<Vec<(String, String)>>>,
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

    // document.addEventListener — no-op (copy event handlers are captured via JS preamble)
    {
        let noop = Function::new(ctx.clone(), |_event: String, _handler: Value| {})?;
        doc.set("addEventListener", noop)?;
    }

    // document.execCommand — flag copy commands; other commands are no-ops.
    // Content capture is not possible without DOM selection, but detection
    // of the copy intent is valuable as a corroborating ClickFix signal.
    {
        let cw = Arc::clone(&clipboard_writes);
        let exec_command = Function::new(ctx.clone(), move |cmd: Option<String>, _show: Value, _val: Value| -> bool {
            let cmd = cmd.unwrap_or_default();
            if cmd.to_ascii_lowercase() == "copy" {
                warn!("sandbox: document.execCommand('copy') intercepted");
                cw.lock().unwrap().push(("document.execCommand".to_string(), String::new()));
            }
            true
        })?;
        doc.set("execCommand", exec_command)?;
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
    clipboard_writes: Arc<Mutex<Vec<(String, String)>>>,
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

    // navigator.clipboard — intercept writeText to capture ClickFix payloads
    {
        let clipboard_obj = Object::new(ctx.clone())?;
        let cw = Arc::clone(&clipboard_writes);
        let write_text = Function::new(ctx.clone(), move |text: String| {
            debug!("sandbox: navigator.clipboard.writeText intercepted ({} bytes)", text.len());
            cw.lock().unwrap().push(("navigator.clipboard.writeText".to_string(), text));
        })?;
        clipboard_obj.set("writeText", write_text)?;
        // readText returns a resolved empty promise stub
        let read_text = Function::new(ctx.clone(), || -> String { String::new() })?;
        clipboard_obj.set("readText", read_text)?;
        navigator.set("clipboard", clipboard_obj)?;
    }

    // Expose navigator as a top-level global so pages can access it without `window.`
    globals.set("navigator", navigator.clone())?;
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

#[cfg(test)]
mod deobf_tests {
    use super::*;
    use std::time::Duration;

    fn capture(script: &str) -> Vec<(String, String)> {
        let limits = SandboxLimits {
            max_memory: 64 * 1024 * 1024,
            max_duration: Duration::from_secs(3),
            max_scripts: 20,
        };
        run_deobfuscation_sandbox(script, &limits).captured
    }

    fn has(caps: &[(String, String)], sink: &str, needle: &str) -> bool {
        caps.iter().any(|(s, p)| s == sink && p.contains(needle))
    }

    #[test]
    fn captures_eval_of_atob() {
        // atob("ZmV0Y2goJ2h0dHBzOi8vYzInKQ==") -> fetch('https://c2')
        let caps = capture(r#"eval(atob("ZmV0Y2goJ2h0dHBzOi8vYzInKQ=="));"#);
        assert!(has(&caps, "eval", "fetch('https://c2')"), "caps: {:?}", caps);
    }

    #[test]
    fn captures_function_constructor_body() {
        let caps = capture(r#"new Function("return fetch('https://c2/x')")();"#);
        assert!(has(&caps, "Function", "fetch('https://c2/x')"), "caps: {:?}", caps);
    }

    #[test]
    fn captures_document_write_unescape() {
        let caps = capture(r#"document.write(unescape("%3Cscript%3Ealert(1)%3C/script%3E"));"#);
        assert!(has(&caps, "document.write", "<script>"), "caps: {:?}", caps);
    }

    #[test]
    fn cracks_string_array_decoder() {
        // Minimal obfuscator.io-style: a string-array + decoder, eval'd.
        // atob('ZmV0Y2g=')='fetch'  -> eval("fetch('x')")
        let caps = capture(
            r#"var a=['ZmV0Y2g='];function d(i){return atob(a[i]);}eval(d(0)+"('x')");"#,
        );
        assert!(has(&caps, "eval", "fetch('x')"), "caps: {:?}", caps);
    }

    #[test]
    fn infinite_loop_is_interrupted() {
        // Must not hang: the interrupt handler aborts at the (short) deadline.
        let limits = SandboxLimits {
            max_memory: 32 * 1024 * 1024,
            max_duration: Duration::from_millis(400),
            max_scripts: 20,
        };
        let start = std::time::Instant::now();
        let _ = run_deobfuscation_sandbox("while(true){}", &limits);
        assert!(start.elapsed() < Duration::from_secs(5), "interrupt did not fire");
    }

    #[test]
    fn clean_script_captures_nothing() {
        let caps = capture("var x = 1 + 2; function f(a){ return a*2; } f(x);");
        assert!(caps.is_empty(), "clean script should capture nothing, got: {:?}", caps);
    }
}
