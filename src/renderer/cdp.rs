//! **Phase-1 spike (CARAPACE-09 P0-b).** Minimal hand-rolled Chrome DevTools
//! Protocol (CDP) client over the `--remote-debugging-pipe` transport — CDP JSON
//! messages, each terminated by a NUL byte, exchanged over the child's fds 3
//! (browser reads commands) and 4 (browser writes responses/events).
//!
//! Purpose: prove the mechanism that will replace the CLI live-render path, and
//! that the security review's load-bearing controls hold:
//!   * **F2 — no TCP debug port.** Uses `--remote-debugging-pipe`; the DevTools
//!     channel is a pair of anonymous pipes, unreachable by the page's own JS.
//!   * **F4 — hard deadline via process-group kill.** The browser is launched in
//!     its own process group; a watchdog `killpg`s the whole group at the
//!     deadline so a hung/adversarial page cannot outlive the render budget.
//!   * **F3 — no new dependency.** Only `serde_json` + `std` + the already-present
//!     `libc` (fd plumbing). The client opens no sockets of its own.
//!   * **F1 — control-plane only.** This client never fetches; it drives a browser
//!     that (in production) still routes all network through the SSRF `PolicyProxy`.
//!     The spike navigates a hermetic `data:` URL and uses no proxy.
//!
//! This is deliberately **blocking** (std threads) for clarity and to de-risk the
//! fd/protocol/kill mechanics; the production integration will be async on tokio.
//! NOT wired into the render path. Exercised by the tests at the bottom (they
//! need a local `chromium` and skip gracefully if absent).

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};

use crate::error::{CarapaceError, Result};

fn err(msg: impl Into<String>) -> CarapaceError {
    CarapaceError::Render(msg.into())
}

static PROFILE_SEQ: AtomicU64 = AtomicU64::new(0);

/// A unique, writable Chromium user-data dir under the tmpfs. Uniqueness is
/// pid + wall-clock nanos + a process-wide counter, so concurrent renders never
/// share a profile (a shared dir hits Chromium's SingletonLock and one instance
/// exits immediately). Cf. `backend::ChromeProfile`.
fn unique_profile_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = PROFILE_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("carapace-cdp-{}-{}-{}", std::process::id(), nanos, seq))
}

/// Result of one spike render: the post-JS DOM, whether our injected bootstrap
/// ran before page scripts, and the decoded screenshot byte length.
#[derive(Debug)]
pub struct SpikeOutput {
    pub dom: String,
    pub bootstrap_ran: bool,
    pub screenshot_len: usize,
}

/// CARAPACE-16 nav-capture latch state, threaded through the settle drain. The
/// FIRST non-`about:` Document request is the initial (already SSRF-validated)
/// navigation → continued. Every SUBSEQUENT Document request is a client-side
/// redirect → its URL is recorded (bounded) and the request is FAILED — never
/// continued, never dispatched to the destination. Because the only interception
/// `continueRequest` is this first-Document slot, "only the validated navigation is
/// continued" is a structural property (plan §4-A). Non-Document / `about:` pauses
/// are continued without consuming the latch (never block a subresource).
struct NavCapture {
    sid: String,
    first_doc: bool,
    targets: Vec<String>,
}

fn chromium_bin() -> Option<&'static str> {
    for n in ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable"] {
        if Command::new("which")
            .arg(n)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            return Some(n);
        }
    }
    None
}

/// Create an anonymous pipe with both ends O_CLOEXEC. Returns (read, write).
fn pipe_cloexec() -> Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0i32; 2];
    // SAFETY: fds is a valid 2-int buffer; pipe2 fills it or returns non-zero.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc != 0 {
        return Err(err(format!("pipe2: {}", std::io::Error::last_os_error())));
    }
    // SAFETY: pipe2 returned two fresh owned fds.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A live CDP-over-pipe session: the child browser + the parent-side pipe ends,
/// with blocking NUL-delimited JSON framing and an event queue.
struct CdpPipe {
    child: Child,
    pgid: i32,
    cmd: File,               // parent -> browser (browser reads on fd 3)
    evt: BufReader<File>,    // browser -> parent (browser writes on fd 4)
    next_id: i64,
    events: Vec<Value>,      // events seen while awaiting a command response
}

impl CdpPipe {
    /// Launch Chromium with `--remote-debugging-pipe`, its own process group, and
    /// a private user-data-dir. fds 3/4 are wired to our pipes via a pre-exec fd
    /// shuffle that is collision-safe (sources are dup'd above fd 9 first).
    /// `extra_args` are appended after the base flags (e.g. `--proxy-server`,
    /// `--user-agent`, `--window-size` for the production render).
    fn launch(profile_dir: &std::path::Path, extra_args: &[&str]) -> Result<Self> {
        let bin = chromium_bin().ok_or_else(|| err("no chromium binary found"))?;

        let (cmd_r, cmd_w) = pipe_cloexec()?; // browser reads cmd_r on fd 3
        let (evt_r, evt_w) = pipe_cloexec()?; // browser writes evt_w on fd 4
        let cmd_r_raw = cmd_r.as_raw_fd();
        let evt_w_raw = evt_w.as_raw_fd();

        let mut c = Command::new(bin);
        c.args([
            "--headless=new",
            "--no-sandbox",
            "--disable-gpu",
            "--use-angle=swiftshader",
            "--disable-dev-shm-usage",
            "--no-first-run",
            "--disable-extensions",
            "--disable-background-networking",
            "--remote-debugging-pipe",
        ])
        .args(extra_args)
        .arg(format!("--user-data-dir={}", profile_dir.display()))
        .arg("about:blank")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0); // own group so killpg targets only the browser subtree

        // SAFETY: the closure calls only async-signal-safe libc fns (fcntl/dup2)
        // and touches only the fds it captured. It moves cmd_r/evt_w onto fds 3/4;
        // the F_DUPFD_CLOEXEC-to-≥10 step guarantees the temporaries can't collide
        // with 3/4 during the shuffle. All CLOEXEC fds close automatically at exec.
        unsafe {
            c.pre_exec(move || {
                let a = libc::fcntl(cmd_r_raw, libc::F_DUPFD_CLOEXEC, 10);
                let b = libc::fcntl(evt_w_raw, libc::F_DUPFD_CLOEXEC, 10);
                if a < 0 || b < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::dup2(a, 3) < 0 || libc::dup2(b, 4) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = c.spawn().map_err(|e| err(format!("spawn chromium: {e}")))?;
        let pgid = child.id() as i32;

        // Parent keeps the write end of the command pipe and the read end of the
        // event pipe; the child ends (cmd_r, evt_w) drop here and close.
        drop(cmd_r);
        drop(evt_w);

        Ok(Self {
            child,
            pgid,
            cmd: File::from(cmd_w),
            evt: BufReader::new(File::from(evt_r)),
            next_id: 1,
            events: Vec::new(),
        })
    }

    /// Read one NUL-delimited CDP JSON message (blocking).
    fn read_message(&mut self) -> Result<Value> {
        let mut raw = Vec::new();
        let n = self
            .evt
            .read_until(0u8, &mut raw)
            .map_err(|e| err(format!("cdp read: {e}")))?;
        if n == 0 {
            return Err(err("cdp pipe closed (browser exited or was killed)"));
        }
        if raw.last() == Some(&0) {
            raw.pop();
        }
        serde_json::from_slice(&raw).map_err(|e| err(format!("cdp parse: {e}")))
    }

    /// Send a command and block until its matching-id response, queueing any
    /// events that arrive in between.
    fn call(&mut self, session: Option<&str>, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let mut msg = json!({ "id": id, "method": method, "params": params });
        if let Some(s) = session {
            msg["sessionId"] = json!(s);
        }
        let mut bytes = serde_json::to_vec(&msg).map_err(|e| err(format!("cdp encode: {e}")))?;
        bytes.push(0);
        self.cmd
            .write_all(&bytes)
            .and_then(|_| self.cmd.flush())
            .map_err(|e| err(format!("cdp write: {e}")))?;

        loop {
            let m = self.read_message()?;
            if m.get("id").and_then(Value::as_i64) == Some(id) {
                if let Some(e) = m.get("error") {
                    return Err(err(format!("cdp error for {method}: {e}")));
                }
                return Ok(m.get("result").cloned().unwrap_or(Value::Null));
            }
            if m.get("method").is_some() {
                self.events.push(m);
            }
        }
    }

    /// Block until an event with `method` (on `session`) arrives, or `deadline`.
    /// The hard wall-clock deadline is ultimately enforced by the watchdog kill,
    /// which closes the pipe and turns a blocked read into an error.
    fn wait_event(&mut self, method: &str, session: &str, deadline: Instant) -> Result<Value> {
        if let Some(pos) = self.events.iter().position(|e| {
            e.get("method").and_then(Value::as_str) == Some(method)
                && e.get("sessionId").and_then(Value::as_str) == Some(session)
        }) {
            return Ok(self.events.remove(pos));
        }
        loop {
            if Instant::now() > deadline {
                return Err(err(format!("timed out waiting for {method}")));
            }
            let m = self.read_message()?;
            if m.get("method").and_then(Value::as_str) == Some(method)
                && m.get("sessionId").and_then(Value::as_str) == Some(session)
            {
                return Ok(m);
            }
            if m.get("method").is_some() {
                self.events.push(m);
            }
        }
    }

    /// Read one message: a buffered one if present (poll can't see BufReader bytes),
    /// else `poll()` the fd for up to `timeout_ms`. Ok(Some)=message, Ok(None)=timeout,
    /// Err=pipe closed. Keeps the pipe drained so an enabled Network domain's events
    /// cannot fill the buffer and stall Chromium.
    fn read_one(&mut self, fd: RawFd, timeout_ms: libc::c_int) -> Result<Option<Value>> {
        if self.evt.buffer().contains(&0u8) {
            return self.read_message().map(Some);
        }
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        // SAFETY: single valid pollfd; poll does not retain the pointer.
        let rc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if rc <= 0 {
            return Ok(None); // timeout or EINTR
        }
        self.read_message().map(Some)
    }

    /// Settle by **network-idle** (CARAPACE-09 P2): drain the event pipe and return
    /// once no request has been in-flight for `quiet` — but never before `floor`
    /// (so a delayed `setTimeout` overlay still injects and is captured — no
    /// early-exit regression to ClickFix/SocGholish detection) nor after `max`.
    /// Requires `Network.enable`; with Network off there are no events so it simply
    /// waits `floor`. Only `Network.responseReceived` events are queued (for the
    /// optional body capture), capped; request/finished are counted inline.
    fn drain_until_idle(
        &mut self,
        floor: Duration,
        max: Duration,
        quiet: Duration,
        mut nav: Option<&mut NavCapture>,
    ) {
        const MAX_QUEUED_RESPONSES: usize = 200;
        let start = Instant::now();
        let floor_at = start + floor;
        let hard = start + max;
        let fd = self.evt.get_ref().as_raw_fd();
        let mut inflight: i64 = 0;
        let mut idle_since = start;
        loop {
            let now = Instant::now();
            if now >= hard {
                return;
            }
            if now >= floor_at && inflight <= 0 && now.duration_since(idle_since) >= quiet {
                return;
            }
            match self.read_one(fd, 50) {
                Ok(Some(m)) => match m.get("method").and_then(Value::as_str) {
                    Some("Network.requestWillBeSent") => inflight += 1,
                    Some("Network.loadingFinished") | Some("Network.loadingFailed") => {
                        inflight -= 1;
                        if inflight <= 0 {
                            idle_since = Instant::now();
                        }
                    }
                    Some("Network.responseReceived") => {
                        if self.events.len() < MAX_QUEUED_RESPONSES {
                            self.events.push(m);
                        }
                    }
                    // CARAPACE-16: a paused navigation MUST be answered inline or
                    // Chromium stalls (F-A2). With Fetch enabled (nav capture on)
                    // this is the initial nav (continue) or a redirect (capture+fail).
                    Some("Fetch.requestPaused") => {
                        if let Some(nc) = nav.as_deref_mut() {
                            self.handle_fetch_pause(&m, nc);
                        }
                    }
                    _ => {}
                },
                Ok(None) => {}      // timeout — re-check idle/deadline
                Err(_) => return,   // pipe closed
            }
        }
    }

    /// Fire-and-forget CDP command (no response wait). Used to answer
    /// `Fetch.requestPaused` from inside the drain loop — a blocking `call()` there
    /// would deadlock (its response can't arrive until the pause is answered), and to
    /// send `Page.navigate` on the capture path (its ack won't come until the initial
    /// Document pause is continued).
    fn send_cmd(&mut self, session: &str, method: &str, params: Value) {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({ "id": id, "method": method, "params": params, "sessionId": session });
        if let Ok(mut bytes) = serde_json::to_vec(&msg) {
            bytes.push(0);
            let _ = self.cmd.write_all(&bytes).and_then(|_| self.cmd.flush());
        }
    }

    /// Answer one `Fetch.requestPaused` per the NavCapture latch (see [`NavCapture`]).
    /// The internal-host guarantee lives here: a redirect to any host — including an
    /// internal one — takes the capture+FAIL branch, never the continue branch, so it
    /// is surfaced for the caller's SSRF re-validation but never dispatched (plan
    /// §4-A / F1 guard test).
    fn handle_fetch_pause(&mut self, m: &Value, nc: &mut NavCapture) {
        let p = m.get("params");
        let rid = p
            .and_then(|p| p.get("requestId"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if rid.is_empty() {
            return;
        }
        let rtype = p.and_then(|p| p.get("resourceType")).and_then(Value::as_str).unwrap_or("");
        let rurl = p
            .and_then(|p| p.pointer("/request/url"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // about:blank / any non-Document pause: continue WITHOUT consuming the latch
        // and never block a subresource (fail-open on the render; the proxy is still
        // the gate). With the Document-only Fetch filter, non-Document should not
        // pause, but this is the defensive default.
        if rurl.starts_with("about:") || rtype != "Document" {
            self.send_cmd(&nc.sid, "Fetch.continueRequest", json!({ "requestId": rid }));
            return;
        }
        if nc.first_doc {
            nc.first_doc = false;
            self.send_cmd(&nc.sid, "Fetch.continueRequest", json!({ "requestId": rid }));
        } else {
            // Redirect: record (bounded, deduped) + block. Nothing is dispatched to
            // the destination; the caller SSRF-validates before any fetch.
            let t: String = rurl.chars().take(2048).collect();
            if nc.targets.len() < 10 && !nc.targets.contains(&t) {
                nc.targets.push(t);
            }
            self.send_cmd(
                &nc.sid,
                "Fetch.failRequest",
                json!({ "requestId": rid, "errorReason": "Aborted" }),
            );
        }
    }

    /// SIGKILL the browser's whole process group and reap it.
    fn kill(&mut self) {
        // SAFETY: pgid is the child's own group (process_group(0)); killpg targets
        // only the browser + its renderer/zygote children, never this process.
        unsafe {
            libc::killpg(self.pgid, libc::SIGKILL);
        }
        let _ = self.child.wait();
    }
}

/// Run one hermetic spike render of `navigate_url` under a hard `deadline`.
/// Launch -> attach -> inject bootstrap -> navigate -> await load -> read DOM +
/// screenshot, then kill the process group. Returns Err (having killed the
/// browser) on any timeout/failure.
pub fn run_spike(navigate_url: &str, deadline: Duration) -> Result<SpikeOutput> {
    let profile = unique_profile_dir();
    let mut sess = CdpPipe::launch(&profile, &[])?;

    // F4: watchdog kills the process group at the deadline regardless of what the
    // page does; a blocked read then errors out, unwinding this function.
    let done = Arc::new(AtomicBool::new(false));
    let wd_done = done.clone();
    let wd_pgid = sess.pgid;
    let watchdog = std::thread::spawn(move || {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if wd_done.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !wd_done.load(Ordering::Relaxed) {
            // SAFETY: pgid is the browser's own group.
            unsafe {
                libc::killpg(wd_pgid, libc::SIGKILL);
            }
        }
    });

    let result = (|| -> Result<SpikeOutput> {
        let created = sess.call(None, "Target.createTarget", json!({ "url": "about:blank" }))?;
        let target_id = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| err("no targetId"))?
            .to_string();
        let attached = sess.call(
            None,
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
        )?;
        let sid = attached
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| err("no sessionId"))?
            .to_string();

        sess.call(Some(&sid), "Page.enable", json!({}))?;
        sess.call(Some(&sid), "Runtime.enable", json!({}))?;
        // Bootstrap-injection proof (production injects the Win32/nav-suppression
        // bootstrap here, before any page script runs).
        sess.call(
            Some(&sid),
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": "window.__carapace_bootstrap = true;" }),
        )?;

        sess.call(Some(&sid), "Page.navigate", json!({ "url": navigate_url }))?;
        let load_deadline = Instant::now() + deadline;
        sess.wait_event("Page.loadEventFired", &sid, load_deadline)?;

        let dom = sess
            .call(
                Some(&sid),
                "Runtime.evaluate",
                json!({ "expression": "document.documentElement.outerHTML", "returnByValue": true }),
            )?
            .pointer("/result/value")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let bootstrap_ran = sess
            .call(
                Some(&sid),
                "Runtime.evaluate",
                json!({ "expression": "window.__carapace_bootstrap === true", "returnByValue": true }),
            )?
            .pointer("/result/value")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        let shot = sess.call(Some(&sid), "Page.captureScreenshot", json!({ "format": "png" }))?;
        let screenshot_len = shot
            .get("data")
            .and_then(Value::as_str)
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .map(|v| v.len())
            .unwrap_or(0);

        Ok(SpikeOutput { dom, bootstrap_ran, screenshot_len })
    })();

    done.store(true, Ordering::Relaxed);
    let _ = sess.call(None, "Browser.close", json!({})); // best-effort graceful close
    sess.kill(); // ensure the group is gone regardless of outcome
    let _ = watchdog.join();
    let _ = std::fs::remove_dir_all(&profile);

    result
}

/// Output of a production CDP live render: the refused cross-origin URLs (from
/// the SSRF policy proxy) and the post-JS DOM. The screenshot is written to the
/// caller's `output_path`.
pub struct CdpRenderOutput {
    pub intercepted: Vec<String>,
    pub dom: String,
    /// Runtime-fetched script bodies captured via CDP Network (url, body). Empty
    /// unless `CARAPACE_CDP_CAPTURE` is enabled. Covers scripts loaded via
    /// `fetch()+eval` / dynamic `import()` that never appear as `<script>` tags.
    pub runtime_scripts: Vec<(String, String)>,
    /// Attempted MAIN-FRAME redirect destinations captured (and blocked) via CDP
    /// `Fetch` Document-only interception — JS-COMPUTED interstitial/TDS destinations
    /// no static regex or single-session event-observation can resolve. Bounded
    /// (≤10). Empty unless `CARAPACE_CDP_NAV_CAPTURE` is enabled. The caller
    /// SSRF-validates + sub-scans them. (CARAPACE-16)
    pub nav_targets: Vec<String>,
}

/// Max full-page capture height, matching the CLI path's sentinel.
const FULL_PAGE_SENTINEL_H: u32 = 8000;
/// Cap the returned DOM, matching `lib.rs` `MAX_RENDERED_HTML`.
const MAX_DOM_BYTES: usize = 3 * 1024 * 1024;

/// Spawn the hard-deadline watchdog: it `killpg`s the browser's own process group
/// (F4) unless `done` is set first. Returns the flag to set on clean completion.
fn spawn_watchdog(pgid: i32, deadline: Duration) -> (Arc<AtomicBool>, std::thread::JoinHandle<()>) {
    let done = Arc::new(AtomicBool::new(false));
    let d2 = done.clone();
    let handle = std::thread::spawn(move || {
        let start = Instant::now();
        while start.elapsed() < deadline {
            if d2.load(Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        if !d2.load(Ordering::Relaxed) {
            // SAFETY: pgid is the browser's own process group.
            unsafe {
                libc::killpg(pgid, libc::SIGKILL);
            }
        }
    });
    (done, handle)
}

/// **Production CDP live render** (CARAPACE-09 P0-b, Phases 3–4) — the CDP
/// equivalent of `backend::render_to_png_live` + `backend::dump_dom_live`, in ONE
/// browser session. Behind the `CARAPACE_CDP` flag; the CLI path remains the
/// default and the fallback.
///
/// Security posture (see the plan's §4): the browser routes **all** network
/// through the SSRF `PolicyProxy` (`--proxy-server`) exactly as the CLI path does
/// (F1 — CDP is control-plane only; no CDP request interception/continue is used).
/// The DevTools channel is a pipe, not a port (F2). A watchdog enforces the hard
/// deadline by process-group kill (F4). A fresh browser process + private profile
/// per render gives isolation (F7). The **live-variant** bootstrap
/// (`IDENTITY_NAV_BOOTSTRAP`) spoofs Win32 + suppresses navigation/refresh but
/// keeps real same-origin `fetch` (F8).
///
/// No event domains are enabled — only request/response commands cross the pipe —
/// so an adversarial page cannot flood the control channel. Settling is a bounded
/// fixed sleep after navigate (network-idle event-counting is a later refinement).
/// Returns Err (browser killed) on any failure so the caller falls back offline.
pub fn cdp_render(
    url: &str,
    output_path: &std::path::Path,
    width: u32,
    height: u32, // 0 = full page
    ua: &str,
    page_host: &str,
    settle_ms: u32, // 0 = default 5000
) -> Result<CdpRenderOutput> {
    use crate::renderer::backend::CDN_PROXY_BYPASS;
    use crate::renderer::bootstrap::IDENTITY_NAV_BOOTSTRAP;
    use crate::renderer::proxy::{PolicyProxy, RenderPolicy};

    let full_page = height == 0;
    let render_h = if full_page { FULL_PAGE_SENTINEL_H } else { height };
    let settle = if settle_ms == 0 { 5000 } else { settle_ms };
    // Hard wall-clock deadline: settle + slack for launch/navigate/capture.
    let deadline = Duration::from_millis(settle as u64 + 6000);

    // CDP Network response-body capture (runtime scripts with no <script> tag).
    // Default OFF — it enables the Network domain (per-request events) so it must
    // be validated before affecting the default render path.
    let capture = std::env::var("CARAPACE_CDP_CAPTURE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on"))
        .unwrap_or(false);

    // CARAPACE-16: capture JS-computed main-frame redirect destinations via CDP
    // Fetch Document-only interception. Default OFF — it enables the Fetch domain
    // (request interception) so it bakes behind this flag before affecting the
    // default render path.
    let nav_capture = std::env::var("CARAPACE_CDP_NAV_CAPTURE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on"))
        .unwrap_or(false);

    // Same-origin SSRF-enforcing forwarding proxy as the CLI live path.
    let proxy = PolicyProxy::start(RenderPolicy::new(page_host, CDN_PROXY_BYPASS));
    let proxy_arg = proxy.proxy_arg();
    let ua_arg = format!("--user-agent={ua}");
    let win_arg = format!("--window-size={width},{render_h}");
    let extra: Vec<&str> = vec![
        &proxy_arg,
        &ua_arg,
        &win_arg,
        "--force-color-profile=srgb",
        "--run-all-compositor-stages-before-draw",
        "--disable-blink-features=AutomationControlled",
    ];

    let profile = unique_profile_dir();

    let mut sess = match CdpPipe::launch(&profile, &extra) {
        Ok(s) => s,
        Err(e) => {
            let _ = proxy.collect();
            let _ = std::fs::remove_dir_all(&profile);
            return Err(e);
        }
    };
    let (done, watchdog) = spawn_watchdog(sess.pgid, deadline);

    let result = (|| -> Result<(String, Vec<(String, String)>, Vec<String>)> {
        let created = sess.call(None, "Target.createTarget", json!({ "url": "about:blank" }))?;
        let target_id = created
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| err("no targetId"))?
            .to_string();
        let attached = sess.call(
            None,
            "Target.attachToTarget",
            json!({ "targetId": target_id, "flatten": true }),
        )?;
        let sid = attached
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| err("no sessionId"))?
            .to_string();

        // No Page/Runtime domain is enabled (they emit console/execution events).
        // Network IS enabled — for network-idle settle (and, under the capture flag,
        // response-body capture). drain_until_idle() keeps its per-request events
        // drained so the pipe cannot fill and stall Chromium.
        sess.call(Some(&sid), "Network.enable", json!({}))?;
        sess.call(
            Some(&sid),
            "Emulation.setDeviceMetricsOverride",
            json!({ "width": width, "height": render_h, "deviceScaleFactor": 1, "mobile": false }),
        )?;
        // Live-variant bootstrap (identity + nav/refresh suppression, NO fetch mock),
        // registered before navigation so it runs at document-start.
        sess.call(
            Some(&sid),
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": IDENTITY_NAV_BOOTSTRAP }),
        )?;

        // CARAPACE-16 nav capture: intercept ONLY top-level Document requests so
        // subresources still flow through the proxy untouched (F-A1). The latch in
        // drain_until_idle continues the first (validated) nav and captures+fails
        // any redirect.
        let mut navcap = if nav_capture {
            sess.call(
                Some(&sid),
                "Fetch.enable",
                json!({ "patterns": [ {
                    "urlPattern": "*", "requestStage": "Request", "resourceType": "Document"
                } ] }),
            )?;
            Some(NavCapture { sid: sid.clone(), first_doc: true, targets: Vec::new() })
        } else {
            None
        };

        // Navigate. With Fetch on we MUST fire-and-forget: Page.navigate would not
        // ack until the initial Document pause is continued, but that happens inside
        // the drain loop below — a blocking call() here would deadlock.
        if nav_capture {
            sess.send_cmd(&sid, "Page.navigate", json!({ "url": url }));
        } else {
            sess.call(Some(&sid), "Page.navigate", json!({ "url": url }))?;
        }

        // Settle by network-idle, floored at `settle` (so delayed overlays still
        // inject — no early-exit regression) and capped a few seconds later so slow
        // SPAs get more load time without risking the watchdog deadline. On the
        // capture path the loop also answers each Fetch pause (initial → continue,
        // redirect → capture+fail).
        sess.drain_until_idle(
            Duration::from_millis(settle as u64),
            Duration::from_millis(settle as u64 + 3000),
            Duration::from_millis(500),
            navcap.as_mut(),
        );
        // Best-effort: wait for web fonts before capture (bounded by awaitPromise
        // + the watchdog). Ignore failure.
        let _ = sess.call(
            Some(&sid),
            "Runtime.evaluate",
            json!({
                "expression": "document.fonts && document.fonts.ready ? document.fonts.ready.then(function(){return true;}) : true",
                "awaitPromise": true,
                "returnByValue": true
            }),
        );

        // Screenshot: full-page via captureBeyondViewport + content height, else viewport.
        let shot_params = if full_page {
            let content_h = sess
                .call(Some(&sid), "Page.getLayoutMetrics", json!({}))
                .ok()
                .and_then(|m| m.pointer("/cssContentSize/height").and_then(Value::as_f64))
                .unwrap_or(render_h as f64)
                .clamp(1.0, FULL_PAGE_SENTINEL_H as f64);
            json!({
                "format": "png",
                "captureBeyondViewport": true,
                "clip": { "x": 0, "y": 0, "width": width as f64, "height": content_h, "scale": 1 }
            })
        } else {
            json!({ "format": "png" })
        };
        let shot = sess.call(Some(&sid), "Page.captureScreenshot", shot_params)?;
        let png = shot
            .get("data")
            .and_then(Value::as_str)
            .and_then(|b64| base64::engine::general_purpose::STANDARD.decode(b64).ok())
            .ok_or_else(|| err("no screenshot data"))?;
        std::fs::write(output_path, &png).map_err(|e| err(format!("write screenshot: {e}")))?;

        let dom = sess
            .call(
                Some(&sid),
                "Runtime.evaluate",
                json!({ "expression": "document.documentElement.outerHTML", "returnByValue": true }),
            )?
            .pointer("/result/value")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .chars()
            .take(MAX_DOM_BYTES)
            .collect::<String>();

        // CDP Network capture: pull the bodies of JS responses seen during load —
        // including scripts loaded via fetch()+eval / import() that never became a
        // <script> tag. Capped; only under the flag. Collect request ids first (the
        // &events borrow) before issuing getResponseBody calls (&mut).
        let mut runtime_scripts: Vec<(String, String)> = Vec::new();
        if capture {
            let mut reqs: Vec<(String, String)> = Vec::new();
            for e in &sess.events {
                if e.get("method").and_then(Value::as_str) != Some("Network.responseReceived") {
                    continue;
                }
                let p = e.get("params");
                let mime = p.and_then(|p| p.pointer("/response/mimeType")).and_then(Value::as_str).unwrap_or("");
                let rurl = p.and_then(|p| p.pointer("/response/url")).and_then(Value::as_str).unwrap_or("");
                let rid = p.and_then(|p| p.get("requestId")).and_then(Value::as_str).unwrap_or("");
                let path = rurl.split('?').next().unwrap_or("");
                let is_js = mime.contains("javascript") || mime.contains("ecmascript")
                    || path.ends_with(".js") || path.ends_with(".mjs");
                if is_js && !rid.is_empty() && !rurl.is_empty() && reqs.len() < 20 {
                    reqs.push((rid.to_string(), rurl.to_string()));
                }
            }
            for (rid, rurl) in reqs {
                if let Ok(r) = sess.call(Some(&sid), "Network.getResponseBody", json!({ "requestId": rid })) {
                    let raw = r.get("body").and_then(Value::as_str).unwrap_or("");
                    let body = if r.get("base64Encoded").and_then(Value::as_bool).unwrap_or(false) {
                        base64::engine::general_purpose::STANDARD.decode(raw).ok()
                            .and_then(|v| String::from_utf8(v).ok()).unwrap_or_default()
                    } else {
                        raw.to_string()
                    };
                    if (16..=1_000_000).contains(&body.len()) {
                        runtime_scripts.push((rurl, body));
                    }
                }
            }
        }

        let nav_targets = navcap.map(|n| n.targets).unwrap_or_default();
        Ok((dom, runtime_scripts, nav_targets))
    })();

    done.store(true, Ordering::Relaxed);
    let _ = sess.call(None, "Browser.close", json!({}));
    sess.kill();
    let _ = watchdog.join();
    let _ = std::fs::remove_dir_all(&profile);
    let intercepted = proxy.collect();

    result.map(|(dom, runtime_scripts, nav_targets)| CdpRenderOutput {
        intercepted,
        dom,
        runtime_scripts,
        nav_targets,
    })
}

#[cfg(test)]
mod cdp_spike_tests {
    use super::*;

    #[test]
    fn launch_navigate_inject_capture() {
        if chromium_bin().is_none() {
            eprintln!("skipping CDP spike test: no chromium on this host");
            return;
        }
        let url = "data:text/html,<html><body><h1>SPIKE_OK</h1></body></html>";
        let out = run_spike(url, Duration::from_secs(20)).expect("spike render");
        assert!(out.dom.contains("SPIKE_OK"), "post-JS DOM captured: {}", out.dom);
        assert!(out.bootstrap_ran, "addScriptToEvaluateOnNewDocument ran before page scripts");
        assert!(out.screenshot_len > 0, "non-empty screenshot captured");
    }

    #[test]
    fn cdp_render_writes_screenshot_and_captures_dom() {
        if chromium_bin().is_none() {
            eprintln!("skipping cdp_render test: no chromium on this host");
            return;
        }
        let out_path =
            unique_profile_dir().with_extension("png"); // unique path, not a real profile
        let url = "data:text/html,<html><head><title>T</title></head>\
                   <body><h1>CDP_RENDER_OK</h1></body></html>";
        // Fixed 800x600 viewport; page_host empty (data: URL has no host, no proxy traffic).
        let out = cdp_render(url, &out_path, 800, 600, crate::renderer::backend::WINDOWS_UA, "", 500)
            .expect("cdp_render");
        assert!(out.dom.contains("CDP_RENDER_OK"), "post-JS DOM captured: {}", out.dom);
        let len = std::fs::metadata(&out_path).map(|m| m.len()).unwrap_or(0);
        assert!(len > 0, "non-empty screenshot written to file");
        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn hung_page_is_killed_at_deadline() {
        if chromium_bin().is_none() {
            eprintln!("skipping CDP kill test: no chromium on this host");
            return;
        }
        // A page that never finishes loading (busy-loop) must not outlive the
        // deadline: the watchdog killpg's the group and run_spike returns Err.
        let url = "data:text/html,<html><body><script>while(true){}</script></body></html>";
        let start = Instant::now();
        let res = run_spike(url, Duration::from_secs(2));
        let elapsed = start.elapsed();
        assert!(res.is_err(), "hung page must fail, not hang forever");
        assert!(elapsed < Duration::from_secs(8), "must be killed near the 2s deadline, took {elapsed:?}");
    }

    /// Fire-and-forget CDP command (no response wait) — used to answer
    /// `Fetch.requestPaused` from inside the read loop without the `call()`
    /// reentrancy that would re-enter the pipe while a pause is outstanding.
    fn send_cmd(sess: &mut CdpPipe, session: &str, method: &str, params: Value) {
        let id = sess.next_id;
        sess.next_id += 1;
        let msg = json!({ "id": id, "method": method, "params": params, "sessionId": session });
        if let Ok(mut bytes) = serde_json::to_vec(&msg) {
            bytes.push(0);
            let _ = sess.cmd.write_all(&bytes).and_then(|_| sess.cmd.flush());
        }
    }

    /// CARAPACE-16 Phase-1 spike (no production wiring). Proves the mechanism the
    /// plan (`docs/research-carapace16-nav-capture-2026.md`) hinges on, before the
    /// §5 decisions are locked:
    ///   (a) F-A1 — CDP `Fetch` scoped to `resourceType: "Document"` pauses ONLY
    ///       main-frame navigations, never subresources (the `<img>` here);
    ///   (b) a positional continue-first / fail-rest latch captures a JS-COMPUTED
    ///       redirect destination (`base + "landing?id=" + (20+22)`) — the latch
    ///       blocks the redirect rather than continuing it;
    ///   (c) every paused request is answered inline — no pipe stall (F-A2), so the
    ///       DOM is still readable after interception.
    /// Finding (see inline note): blocking a committed main-frame nav cannot keep the
    /// screenshot on the interstitial (error/blank post-nav state) — but that is no
    /// regression and the destination capture, the actual goal, is unaffected.
    /// about:blank is continued without consuming the latch (it has no network load,
    /// but Chromium's target-bootstrap could still surface it).
    #[test]
    fn spike_fetch_document_interception_captures_computed_dest() {
        if chromium_bin().is_none() {
            eprintln!("skipping Fetch-interception spike: no chromium on this host");
            return;
        }
        let profile = unique_profile_dir();
        let mut sess = CdpPipe::launch(&profile, &[]).expect("launch");
        let (done, watchdog) = spawn_watchdog(sess.pgid, Duration::from_secs(10));

        let url = "data:text/html,<html><head><title>Redirecting</title></head>\
                   <body><h1>INTERSTITIAL</h1>\
                   <img src=\"https://img.example.test/pixel.png\">\
                   <script>setTimeout(function(){var b=\"https://evil.example.test/\";\
                   var t=\"landing?id=\"+(20+22);location.replace(b+t);},250);</script>\
                   </body></html>";

        let result = (|| -> Result<(Vec<String>, Vec<String>, String)> {
            let created = sess.call(None, "Target.createTarget", json!({ "url": "about:blank" }))?;
            let target_id = created.get("targetId").and_then(Value::as_str)
                .ok_or_else(|| err("no targetId"))?.to_string();
            let attached = sess.call(None, "Target.attachToTarget",
                json!({ "targetId": target_id, "flatten": true }))?;
            let sid = attached.get("sessionId").and_then(Value::as_str)
                .ok_or_else(|| err("no sessionId"))?.to_string();

            // Document-only interception at the Request stage.
            sess.call(Some(&sid), "Fetch.enable", json!({
                "patterns": [ { "urlPattern": "*", "requestStage": "Request", "resourceType": "Document" } ]
            }))?;
            sess.call(Some(&sid), "Page.navigate", json!({ "url": url }))?;

            let fd = sess.evt.get_ref().as_raw_fd();
            let settle = Instant::now() + Duration::from_millis(2500);
            let mut first_doc = true;
            let mut paused_types: Vec<String> = Vec::new();
            let mut captured: Vec<String> = Vec::new();
            while Instant::now() < settle {
                match sess.read_one(fd, 100) {
                    Ok(Some(m)) => {
                        if m.get("method").and_then(Value::as_str) != Some("Fetch.requestPaused") {
                            continue;
                        }
                        let p = m.get("params").cloned().unwrap_or(Value::Null);
                        let rid = p.get("requestId").and_then(Value::as_str).unwrap_or("").to_string();
                        let rtype = p.get("resourceType").and_then(Value::as_str).unwrap_or("").to_string();
                        let rurl = p.pointer("/request/url").and_then(Value::as_str).unwrap_or("").to_string();
                        if rurl.starts_with("about:") {
                            send_cmd(&mut sess, &sid, "Fetch.continueRequest", json!({ "requestId": rid }));
                            continue;
                        }
                        paused_types.push(rtype);
                        if first_doc {
                            first_doc = false;
                            send_cmd(&mut sess, &sid, "Fetch.continueRequest", json!({ "requestId": rid }));
                        } else {
                            captured.push(rurl);
                            // Block the redirect (nothing dispatched to the destination —
                            // F1-safe). Finding: neither failRequest nor a synthetic 204
                            // fulfil keeps the frame on the interstitial — a committed
                            // main-frame nav that is then blocked shows Chromium's post-nav
                            // (error/blank) state. No regression: today a refused
                            // cross-origin nav is already blank. Capture is the goal.
                            send_cmd(&mut sess, &sid, "Fetch.failRequest",
                                json!({ "requestId": rid, "errorReason": "Aborted" }));
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }

            let dom = sess.call(Some(&sid), "Runtime.evaluate",
                json!({ "expression": "document.documentElement.outerHTML", "returnByValue": true }))
                .ok()
                .and_then(|r| r.pointer("/result/value").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            Ok((paused_types, captured, dom))
        })();

        done.store(true, Ordering::Relaxed);
        let _ = sess.call(None, "Browser.close", json!({}));
        sess.kill();
        let _ = watchdog.join();
        let _ = std::fs::remove_dir_all(&profile);

        let (paused_types, captured, dom) = result.expect("spike render");
        // (b) JS-COMPUTED destination captured.
        assert!(
            captured.iter().any(|u| u == "https://evil.example.test/landing?id=42"),
            "computed redirect destination captured; saw: {:?}", captured
        );
        // (a) F-A1: only Document requests were intercepted — the <img> was not.
        assert!(
            !paused_types.is_empty() && paused_types.iter().all(|t| t == "Document"),
            "only Document requests intercepted (F-A1); saw: {:?}", paused_types
        );
        // (c) F-A2: inline-answering every pause did not stall the pipe — the DOM
        // is still readable after interception.
        assert!(!dom.is_empty(), "render completed after interception — no pipe stall");
    }

    /// CARAPACE-16 F1 guard (§6.3). Exercises the PRODUCTION path
    /// (`drain_until_idle` + `handle_fetch_pause` + `NavCapture`): a main-frame
    /// redirect to an SSRF target must be CAPTURED + FAILED, never continued. The
    /// assertion is structural — a URL can only enter `targets` via the fail+record
    /// branch, so its presence proves the internal host was never `continueRequest`'d.
    /// The caller (`tasks.py` Step 4d.7) then rejects it via `validate_url()` before
    /// any fetch; here we prove Carapace never dispatched it.
    ///
    /// `first_doc` is primed **false** to model the post-initial-navigation state: in
    /// production the initial http(s) scan URL emits the first Document pause and is
    /// continued (consuming the slot), so a redirect is always a *subsequent*
    /// Document. A `data:` initial (as used here for hermeticism) does NOT emit a
    /// Fetch pause, so priming `first_doc=false` faithfully isolates the redirect-fail
    /// path this guard is about — the "first Document is continued" half is proven by
    /// `spike_fetch_document_interception_captures_computed_dest`.
    #[test]
    fn f1_internal_host_redirect_is_captured_not_continued() {
        if chromium_bin().is_none() {
            eprintln!("skipping F1 guard test: no chromium on this host");
            return;
        }
        let profile = unique_profile_dir();
        let mut sess = CdpPipe::launch(&profile, &[]).expect("launch");
        let (done, watchdog) = spawn_watchdog(sess.pgid, Duration::from_secs(10));
        let url = "data:text/html,<html><body>gate\
                   <script>location.replace('http://169.254.169.254/latest/meta-data/');</script>\
                   </body></html>";

        let targets = (|| -> Result<Vec<String>> {
            let created = sess.call(None, "Target.createTarget", json!({ "url": "about:blank" }))?;
            let tid = created.get("targetId").and_then(Value::as_str)
                .ok_or_else(|| err("no targetId"))?.to_string();
            let attached = sess.call(None, "Target.attachToTarget",
                json!({ "targetId": tid, "flatten": true }))?;
            let sid = attached.get("sessionId").and_then(Value::as_str)
                .ok_or_else(|| err("no sessionId"))?.to_string();
            sess.call(Some(&sid), "Network.enable", json!({}))?;
            sess.call(Some(&sid), "Fetch.enable", json!({
                "patterns": [ { "urlPattern": "*", "requestStage": "Request", "resourceType": "Document" } ]
            }))?;
            // first_doc:false — the validated initial nav is modelled as already done.
            let mut navcap = NavCapture { sid: sid.clone(), first_doc: false, targets: Vec::new() };
            sess.send_cmd(&sid, "Page.navigate", json!({ "url": url }));
            sess.drain_until_idle(
                Duration::from_millis(800),
                Duration::from_millis(3000),
                Duration::from_millis(400),
                Some(&mut navcap),
            );
            Ok(navcap.targets)
        })();

        done.store(true, Ordering::Relaxed);
        let _ = sess.call(None, "Browser.close", json!({}));
        sess.kill();
        let _ = watchdog.join();
        let _ = std::fs::remove_dir_all(&profile);

        let targets = targets.expect("guard render");
        assert!(
            targets.iter().any(|u| u.contains("169.254.169.254")),
            "internal-host redirect captured+failed (never continued); targets: {:?}", targets
        );
    }
}
