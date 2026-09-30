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
    /// frameId of the initial (main-frame) Document request. Every later Document in
    /// THIS frame is a client-side redirect; a Document in any other frame is an
    /// **iframe**, which is not a navigation and must not be captured or blocked.
    main_frame: String,
}

/// The main frame's id for a page target.
///
/// Chromium sets a page target's main-frame id equal to its **targetId**, so this needs
/// no extra CDP round-trip and — critically — no `Page.enable`, which would switch on an
/// event domain the CDP design deliberately keeps off (see the module header: no event
/// domains means an adversarial page cannot flood the control pipe).
///
/// Do NOT infer the main frame from "whichever Document paused first": an iframe is a
/// Document too, so if the initial navigation does not pause (a `data:` URL, or a nav
/// committed before `Fetch.enable`) the first pause seen IS an iframe, which would then
/// define itself as the main frame and let the real navigation be treated as a sub-frame.
fn main_frame_id_from_target(target_id: &str) -> String {
    target_id.to_string()
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
            // ── Memory bounds (2026-08-18) ────────────────────────────────────
            // The container's `mem_limit: 1g` is a DoS bound on a process that
            // executes attacker JS, so it is a backstop, not a budget: when
            // Chromium reached it the cgroup OOM killer took the process mid-render
            // and the client saw a timeout or a closed connection with no error
            // anywhere. Asset-heavy pages (naver.com) hit it on every holdout run.
            // Bound the browser instead of raising the container limit.
            //
            // One renderer process: we render exactly one page per browser, so the
            // default process-per-site pool is pure overhead here.
            "--renderer-process-limit=1",
            // Cap the V8 heap well under the container limit, so a page that
            // allocates without bound loses its own renderer rather than taking the
            // whole container — including the Carapace process serving the request.
            "--js-flags=--max-old-space-size=256",
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
                // Make the browser the kernel's preferred OOM victim.
                //
                // `mem_limit: 1g` is a container-wide cgroup bound, so when a page
                // exhausts it the kernel picks a victim by score — and it sometimes
                // picked the Carapace process itself. That took down the server
                // mid-request (the client saw a closed connection or a bare timeout,
                // never an error), and every render that followed ran in a degraded
                // container: edx.org rendered fine in 16s alone but timed out when a
                // memory-hungry page had run before it. One page could therefore
                // corrupt an entire corpus run.
                //
                // oom_score_adj=1000 pins the browser to the top of the kill list, so a
                // runaway page loses its own renderer and the request fails honestly
                // while the server and subsequent renders survive. Best-effort: a
                // failure to write it must not abort the spawn.
                //
                // SAFETY: open/write/close are async-signal-safe.
                let path = b"/proc/self/oom_score_adj\0";
                let fd = libc::open(path.as_ptr() as *const libc::c_char, libc::O_WRONLY);
                if fd >= 0 {
                    let v = b"1000\n";
                    let _ = libc::write(fd, v.as_ptr() as *const libc::c_void, v.len());
                    let _ = libc::close(fd);
                }

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
            if m.get("method").is_some() && self.events.len() < Self::MAX_QUEUED_EVENTS {
                self.events.push(m);
            }
        }
    }

    /// Cap on retained out-of-band CDP events.
///
/// `Network.enable` is always on (its drain prevents a pipe stall), so a request-heavy
/// page emits events continuously. `drain_for` already bounded its queue, but `call`
/// and `wait_event` pushed every non-matching event with **no bound** — so any page
/// that kept issuing requests while we waited for one response grew this Vec of
/// serde_json Values without limit. On naver.com the render reached 2.65 GiB and was
/// still climbing, which is what the cgroup OOM killer was reacting to. Retaining a
/// bounded window is enough: these events exist only so a later `wait_event` can find
/// one that arrived early.
const MAX_QUEUED_EVENTS: usize = 200;

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
            if m.get("method").is_some() && self.events.len() < Self::MAX_QUEUED_EVENTS {
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
                        if self.events.len() < Self::MAX_QUEUED_EVENTS {
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
        let frame_id = p
            .and_then(|p| p.get("frameId"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // Frame check FIRST. An iframe is a `resourceType: Document` too — the plan's
        // "Document-only excludes subresources" holds for scripts/images/XHR but not for
        // sub-frames — and nothing here checked the frame. Two real consequences:
        // legitimate iframes were FAILED mid-render, and their URLs were handed to the
        // Python side as client-side redirect destinations. citi.com's anti-fraud vendor
        // loads three `crossdomain.html` iframes on per-session rotating hex domains;
        // each was followed as a redirect hop, scored DGA=1.00 and reported HIGH,
        // flipping a major bank to SUSPICIOUS on ~half of scans.
        //
        // This must run BEFORE the first_doc latch: the iframe request routinely arrives
        // FIRST, so a latch that consumed it would both mis-bind the main frame and
        // spend the initial-navigation slot on a sub-frame.
        if !nc.main_frame.is_empty() && !frame_id.is_empty() && frame_id != nc.main_frame {
            // An IFRAME, not a navigation. `resourceType: Document` covers sub-frames as
            // well as the main frame — the plan's "Document-only excludes subresources"
            // is true of scripts/images/XHR but NOT of iframes, and nothing here checked
            // the frame. Two consequences, both real: legitimate sub-frames were being
            // FAILED mid-render, and their URLs were reported to the Python side as
            // client-side redirect destinations. citi.com's anti-fraud vendor loads three
            // `crossdomain.html` iframes on per-session rotating hex domains; each was
            // followed as a "redirect hop", scored DGA=1.00 and reported HIGH, flipping a
            // major bank to SUSPICIOUS on roughly half of scans.
            self.send_cmd(&nc.sid, "Fetch.continueRequest", json!({ "requestId": rid }));
        } else if nc.first_doc {
            // The initial, already-SSRF-validated navigation.
            nc.first_doc = false;
            if nc.main_frame.is_empty() {
                // Fallback only: main_frame is normally seeded from the targetId.
                nc.main_frame = frame_id;
            }
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
            let mf = main_frame_id_from_target(&target_id);
            Some(NavCapture { sid: sid.clone(), first_doc: true, targets: Vec::new(),
                              main_frame: mf })
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

// ── Cloudflare challenge solver (/solve) ──────────────────────────────────────
//
// FlareSolverr-equivalent, built on the render path's confinement instead of a second,
// unconfined browser: a real Chromium executes the Cloudflare managed/JS challenge and
// the solver returns the DOCUMENT THE SERVER SENT — raw body bytes and response
// headers, captured over CDP `Network` — for the Python pipeline to analyse.
//
// Why the document and not the cookies. The first version returned the clearance
// cookies for the Python fetcher to replay. That cannot work behind the VPN egress:
// Cloudflare binds `cf_clearance` to the IP that solved the challenge, and NordVPN
// gives every session its own exit IP from the server's pool (measured 2026-09-30:
// Carapace's tunnel exited on .219, celery's on .216). A replay from another container
// is a replay from another IP. Returning the page itself keeps the whole exchange on
// one IP, and also covers the case replay never could — Cloudflare waving the real
// browser straight through while still blocking curl_cffi's TLS fingerprint
// (capterra.com: no challenge in Chromium, "Just a moment..." to curl_cffi).
//
// Clearance is still REUSED, but inside Carapace: a per-host cache feeds the cookies
// back into the next solve's browser before it navigates, so a repeat scan of a
// challenged site skips the challenge. Clearance values never leave this process.
//
// What differs from `cdp_render`, and why each difference is safe:
//   * NO bootstrap. The render bootstrap suppresses navigation (the challenge completes
//     by reloading the page) and redefines `navigator` getters (a tamper signal the
//     challenge script checks for). The solver has nothing to screenshot.
//   * The policy proxy additionally allows `challenges.cloudflare.com` — the Turnstile
//     host a managed challenge loads cross-origin. It is Cloudflare's own service, not
//     attacker infrastructure; SSRF enforcement on every connection is unchanged.
//   * The UA is Chromium's own with the `HeadlessChrome` token rewritten to `Chrome`,
//     set by the `--user-agent` FLAG, which keeps the native Sec-CH-UA client hints
//     consistent (measured on Chromium 151).
//   * `Network` is enabled (to see the main-frame response and read its body) but
//     `Runtime`/`Page` are not — `Runtime.enable` is a well-known automation tell.
//     Every Network event is drained by `pump`/`absorb`, and `call()` bounds its queue,
//     so a request-heavy page cannot stall the pipe or grow memory without limit.

/// Cloudflare cookie names. Only these are cached; nothing else a page sets survives
/// the solve.
const CF_COOKIE_NAMES: &[&str] = &["cf_clearance", "__cf_bm", "_cfuvid"];
/// Extra host the solver's proxy allows: Cloudflare Turnstile / challenge platform.
const CF_CHALLENGE_HOSTS: &str = "challenges.cloudflare.com";
/// How often the solver polls for clearance while the challenge runs.
const SOLVE_POLL: Duration = Duration::from_millis(500);
/// Largest document body returned (matches the Python fetcher's page cap).
const MAX_DOC_BYTES: usize = 5 * 1024 * 1024;
/// Bounds on the returned response headers.
const MAX_DOC_HEADERS: usize = 64;
const MAX_HEADER_VALUE: usize = 8192;
/// A cached clearance is dropped after this long even if Cloudflare's own expiry is
/// later: the egress IP it is bound to can change on a VPN reconnect, and a stale
/// entry only costs one re-solve.
const CLEARANCE_TTL_MAX: Duration = Duration::from_secs(25 * 60);
const CLEARANCE_CACHE_MAX: usize = 256;

/// The main-frame document the server returned to Chromium.
#[derive(Debug, serde::Serialize)]
pub struct SolvedDocument {
    pub url: String,
    pub status: u16,
    pub headers: std::collections::BTreeMap<String, String>,
    /// Raw response body, base64 (the page may not be UTF-8).
    pub body_b64: String,
    pub truncated: bool,
}

/// Result of one challenge solve.
#[derive(Debug, serde::Serialize)]
pub struct SolveOutput {
    /// `cf_clearance` present AND the challenge interstitial is gone.
    pub solved: bool,
    /// The page loaded without any challenge interstitial (nothing to solve).
    pub challenge_absent: bool,
    /// "fresh" (challenge solved now), "cached" (a cached clearance was accepted), or
    /// "none" (no clearance involved).
    pub clearance_source: String,
    pub final_url: String,
    pub title: String,
    /// Names only, for evidence — clearance values never leave Carapace.
    pub cookie_names: Vec<String>,
    pub user_agent: String,
    /// The last main-frame document response. `None` when it could not be captured.
    pub document: Option<SolvedDocument>,
    /// Ordered main-frame navigations the browser attempted (http/https, ≤10), server
    /// redirects included — the path a JavaScript gate sends a visitor down. A
    /// cross-origin hop appears here even though the policy proxy refused to fetch it.
    pub nav_chain: Vec<String>,
    pub elapsed_ms: u64,
    /// Cross-origin requests the policy proxy refused during the solve.
    pub intercepted: Vec<String>,
}

// ── Per-host clearance cache ──────────────────────────────────────────────────

struct CachedClearance {
    /// CDP `Network.CookieParam` objects, ready for `Network.setCookies`.
    cookies: Vec<Value>,
    expires_at: Instant,
}

fn clearance_cache() -> &'static std::sync::Mutex<std::collections::HashMap<String, CachedClearance>> {
    static CACHE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<String, CachedClearance>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

/// RFC 6265 domain-match: `host` equals the cookie domain or is a subdomain of it.
fn cookie_domain_matches(cookie_domain: &str, host: &str) -> bool {
    let d = cookie_domain.trim_start_matches('.').to_ascii_lowercase();
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    !d.is_empty() && d.contains('.') && (h == d || h.ends_with(&format!(".{d}")))
}

fn cached_clearance(host: &str) -> Option<Vec<Value>> {
    let mut cache = clearance_cache().lock().ok()?;
    let now = Instant::now();
    cache.retain(|_, c| c.expires_at > now);
    cache.get(host).map(|c| c.cookies.clone())
}

fn drop_clearance(host: &str) {
    if let Ok(mut cache) = clearance_cache().lock() {
        cache.remove(host);
    }
}

/// Cache the Cloudflare cookies from a `Storage.getCookies` result for `host`. Only
/// cookies whose domain covers `host` are kept; nothing is stored without a
/// `cf_clearance`.
fn store_clearance(host: &str, all_cookies: &[Value]) {
    let mut kept: Vec<Value> = Vec::new();
    let mut ttl = CLEARANCE_TTL_MAX;
    for c in all_cookies {
        let (Some(name), Some(value), Some(domain)) = (
            c.get("name").and_then(Value::as_str),
            c.get("value").and_then(Value::as_str),
            c.get("domain").and_then(Value::as_str),
        ) else { continue };
        if !CF_COOKIE_NAMES.contains(&name) || !cookie_domain_matches(domain, host) || value.len() > 4096 {
            continue;
        }
        let expires = c.get("expires").and_then(Value::as_f64).unwrap_or(-1.0);
        if name == "cf_clearance" && expires > 0.0 {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            let left = (expires - now - 60.0).max(0.0);
            ttl = ttl.min(Duration::from_secs_f64(left));
        }
        let mut p = json!({
            "name": name,
            "value": value,
            "domain": domain,
            "path": c.get("path").and_then(Value::as_str).unwrap_or("/"),
            "secure": c.get("secure").and_then(Value::as_bool).unwrap_or(false),
            "httpOnly": c.get("httpOnly").and_then(Value::as_bool).unwrap_or(false),
        });
        if expires > 0.0 {
            p["expires"] = json!(expires);
        }
        kept.push(p);
    }
    if !kept.iter().any(|c| c["name"] == "cf_clearance") || ttl.is_zero() {
        return;
    }
    if let Ok(mut cache) = clearance_cache().lock() {
        let now = Instant::now();
        cache.retain(|_, c| c.expires_at > now);
        if cache.len() >= CLEARANCE_CACHE_MAX && !cache.contains_key(host) {
            // Evict whichever entry expires soonest.
            if let Some(k) = cache.iter().min_by_key(|(_, c)| c.expires_at).map(|(k, _)| k.clone()) {
                cache.remove(&k);
            }
        }
        cache.insert(host.to_string(), CachedClearance { cookies: kept, expires_at: now + ttl });
    }
}

// ── Main-frame document tracking ──────────────────────────────────────────────

/// Remembers the LAST main-frame `Document` response seen — after a challenge clears,
/// that is the real page, not the interstitial — and the ordered chain of main-frame
/// navigations the browser attempted. Sub-frame documents (the Turnstile iframe, any
/// page iframe) are ignored by frame id, the same rule as nav capture.
///
/// The chain is how a JavaScript cloaking gate is followed: the gate re-enters its own
/// site with a proof-of-JS token and the server then forwards the visitor — often
/// off-site into a traffic broker. Every hop, server redirects included, reaches
/// `Network.requestWillBeSent` as a Document request, INCLUDING a cross-origin hop the
/// policy proxy then refuses. So the destination is recorded without any cross-origin
/// content ever being fetched here; the caller SSRF-validates it before following.
struct DocTracker {
    main_frame: String,
    last: Option<(String, String, u16, Value)>, // (requestId, url, status, headers)
    nav_chain: Vec<String>,
}

/// Bound on recorded main-frame hops.
const MAX_NAV_CHAIN: usize = 10;

impl DocTracker {
    fn new(main_frame: String) -> Self {
        Self { main_frame, last: None, nav_chain: Vec::new() }
    }

    fn observe(&mut self, m: &Value) {
        let method = m.get("method").and_then(Value::as_str);
        if method == Some("Network.requestWillBeSent") {
            let Some(p) = m.get("params") else { return };
            if p.get("type").and_then(Value::as_str) == Some("Document")
                && p.get("frameId").and_then(Value::as_str) == Some(self.main_frame.as_str())
            {
                let u = p.pointer("/request/url").and_then(Value::as_str).unwrap_or("");
                if (u.starts_with("http://") || u.starts_with("https://"))
                    && self.nav_chain.len() < MAX_NAV_CHAIN
                    && self.nav_chain.last().map(String::as_str) != Some(u)
                {
                    self.nav_chain.push(u.chars().take(2048).collect());
                }
            }
            return;
        }
        if method != Some("Network.responseReceived") {
            return;
        }
        let Some(p) = m.get("params") else { return };
        if p.get("type").and_then(Value::as_str) != Some("Document")
            || p.get("frameId").and_then(Value::as_str) != Some(self.main_frame.as_str())
        {
            return;
        }
        let rid = p.get("requestId").and_then(Value::as_str).unwrap_or("").to_string();
        let url = p.pointer("/response/url").and_then(Value::as_str).unwrap_or("").to_string();
        let status = p.pointer("/response/status").and_then(Value::as_f64).unwrap_or(0.0) as u16;
        let headers = p.pointer("/response/headers").cloned().unwrap_or(Value::Null);
        if !rid.is_empty() {
            self.last = Some((rid, url, status, headers));
        }
    }
}

/// Feed any events `call()` queued while waiting for a response into the tracker.
fn absorb(sess: &mut CdpPipe, docs: &mut DocTracker) {
    for e in std::mem::take(&mut sess.events) {
        docs.observe(&e);
    }
}

/// Read CDP messages for `dur`, feeding each to the tracker — keeps the pipe drained
/// between polls (Network is enabled, so events arrive continuously).
fn pump(sess: &mut CdpPipe, dur: Duration, docs: &mut DocTracker) {
    absorb(sess, docs);
    let fd = sess.evt.get_ref().as_raw_fd();
    let until = Instant::now() + dur;
    while Instant::now() < until {
        match sess.read_one(fd, 50) {
            Ok(Some(m)) => docs.observe(&m),
            Ok(None) => {}
            Err(_) => return,
        }
    }
}

fn header_map(v: &Value) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    if let Some(obj) = v.as_object() {
        for (k, val) in obj.iter().take(MAX_DOC_HEADERS) {
            if let Some(s) = val.as_str() {
                out.insert(
                    k.chars().take(128).collect(),
                    s.chars().take(MAX_HEADER_VALUE).collect(),
                );
            }
        }
    }
    out
}

/// Chromium's own UA with the headless token removed, in reduced-UA form
/// (`Chrome/<major>.0.0.0`, the shape real Chrome has sent since UA reduction).
/// Derived once from `chromium --version`; falls back to the render UA's major.
fn solver_user_agent() -> &'static str {
    static UA: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    UA.get_or_init(|| {
        let major = chromium_bin()
            .and_then(|b| Command::new(b).arg("--version").output().ok())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|v| {
                v.split_whitespace()
                    .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
                    .and_then(|t| t.split('.').next().map(str::to_string))
            })
            .filter(|m| !m.is_empty() && m.chars().all(|c| c.is_ascii_digit()))
            .unwrap_or_else(|| "133".to_string());
        format!(
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/{major}.0.0.0 Safari/537.36"
        )
    })
}

/// True while the document is still a Cloudflare challenge interstitial. Mirrors the
/// Python `fetcher._is_cf_challenge_response` markers — NOT `/cdn-cgi/challenge-platform/`,
/// which is the passive JS Detections beacon present on ordinary pages.
const CHALLENGE_PRESENT_JS: &str = r#"(function(){try{
  var t=(document.title||'').toLowerCase();
  var h=document.documentElement?document.documentElement.innerHTML:'';
  return t.indexOf('just a moment')>=0 || h.indexOf('_cf_chl_opt')>=0
      || h.indexOf('cf_challenge_form')>=0 || h.indexOf('cf-turnstile')>=0;
}catch(e){return true;}})()"#;

fn eval_value(sess: &mut CdpPipe, sid: &str, expr: &str) -> Option<Value> {
    sess.call(
        Some(sid),
        "Runtime.evaluate",
        json!({ "expression": expr, "returnByValue": true }),
    )
    .ok()
    .and_then(|r| r.pointer("/result/value").cloned())
}

fn browser_cookies(sess: &mut CdpPipe) -> Vec<Value> {
    sess.call(None, "Storage.getCookies", json!({}))
        .ok()
        .and_then(|r| r.get("cookies").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

/// **Cloudflare challenge solver.** Navigate `url` in a confined Chromium, let the
/// challenge run, and return the main-frame document the server sent once it clears.
/// `deadline` is a hard wall clock (watchdog `killpg`, as `cdp_render`).
///
/// Never errors merely because the challenge was not cleared — an interactive Turnstile
/// is expected to fail, and that is reported as `solved: false`. Err only for
/// launch/protocol failure.
pub fn cdp_solve_challenge(url: &str, page_host: &str, deadline: Duration) -> Result<SolveOutput> {
    use crate::renderer::backend::CDN_PROXY_BYPASS;
    use crate::renderer::proxy::{PolicyProxy, RenderPolicy};

    let started = Instant::now();
    let host = page_host.to_ascii_lowercase();
    let allow = format!("{CDN_PROXY_BYPASS},{CF_CHALLENGE_HOSTS}");
    let proxy = PolicyProxy::start_with_budget(RenderPolicy::new(&host, &allow), deadline);
    let proxy_arg = proxy.proxy_arg();
    let ua = solver_user_agent();
    let ua_arg = format!("--user-agent={ua}");
    let extra: Vec<&str> = vec![
        &proxy_arg,
        &ua_arg,
        "--window-size=1280,800",
        "--lang=en-GB",
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
    // Stop polling with enough slack left to read the result before the watchdog fires.
    let poll_until = started + deadline.saturating_sub(Duration::from_millis(3000));

    let result = (|| -> Result<SolveOutput> {
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

        // Retain response bodies so the document can be read after the challenge's own
        // reload; bounded so a hostile page cannot pin unbounded browser memory.
        sess.call(
            Some(&sid),
            "Network.enable",
            json!({ "maxTotalBufferSize": 24 * 1024 * 1024, "maxResourceBufferSize": 8 * 1024 * 1024 }),
        )?;
        let mut docs = DocTracker::new(main_frame_id_from_target(&target_id));

        // Reuse a clearance this Carapace earned earlier for the same host (same egress
        // IP), so a repeat scan of a challenged site skips the challenge.
        let injected = match (!host.is_empty()).then(|| cached_clearance(&host)).flatten() {
            Some(cookies) => sess
                .call(Some(&sid), "Network.setCookies", json!({ "cookies": cookies }))
                .is_ok(),
            None => false,
        };

        sess.call(Some(&sid), "Page.navigate", json!({ "url": url }))?;

        let mut solved = false;
        let mut challenge_absent = false;
        let mut saw_challenge = false;
        while Instant::now() < poll_until {
            pump(&mut sess, SOLVE_POLL, &mut docs);
            // Evaluate fails transiently while the challenge reloads the document
            // ("execution context destroyed") — treat that as not-ready.
            let ready = eval_value(&mut sess, &sid, "document.readyState")
                .and_then(|v| v.as_str().map(|s| s == "complete"))
                .unwrap_or(false);
            if !ready {
                continue;
            }
            // Success is decided by the two things the interstitial cannot fake at once:
            // Cloudflare issued `cf_clearance`, and the document is no longer the
            // "Just a moment..." page. The broader marker scan is NOT used here —
            // measured on nowsecure.nl (2026-09-30), the real post-challenge page still
            // matched it (a `.cf-turnstile` CSS rule), so gating success on it left a
            // solved challenge polling to the deadline.
            let interstitial_title = eval_value(&mut sess, &sid, "(document.title||'').toLowerCase()")
                .and_then(|v| v.as_str().map(|t| t.contains("just a moment")))
                .unwrap_or(true);
            let has_clearance = browser_cookies(&mut sess)
                .iter()
                .any(|c| c.get("name").and_then(Value::as_str) == Some("cf_clearance"));
            if has_clearance && !interstitial_title {
                solved = true;
                break;
            }
            let challenged = interstitial_title
                || eval_value(&mut sess, &sid, CHALLENGE_PRESENT_JS)
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true);
            if challenged {
                saw_challenge = true;
                continue;
            }
            // Loaded, no interstitial, no clearance: the page was never challenged for
            // this client. (A cleared challenge sets its cookie before it reloads.)
            if !saw_challenge {
                challenge_absent = true;
                break;
            }
        }
        if solved {
            // Let the post-challenge document finish its own loading before reading it.
            pump(&mut sess, Duration::from_millis(1000), &mut docs);
        } else {
            // A JavaScript gate navigates immediately, but the first poll can land on the
            // gate document before its re-entry commits and report it challenge-absent.
            // Give the gate time to play out so the chain and the landing document are
            // what a visitor actually reaches, not the gate itself.
            pump(&mut sess, Duration::from_millis(2500), &mut docs);
        }
        absorb(&mut sess, &mut docs);

        let cookies = browser_cookies(&mut sess);
        if solved && !host.is_empty() {
            store_clearance(&host, &cookies);
        } else if injected {
            // The cached clearance was not accepted (VPN exit changed, or expired early).
            drop_clearance(&host);
        }
        let mut cookie_names: Vec<String> = cookies
            .iter()
            .filter_map(|c| c.get("name").and_then(Value::as_str))
            .filter(|n| CF_COOKIE_NAMES.contains(n))
            .map(str::to_string)
            .collect();
        cookie_names.sort();
        cookie_names.dedup();

        let clearance_source = match (solved, saw_challenge, injected) {
            (true, false, true) => "cached",
            (true, _, _) => "fresh",
            _ => "none",
        }
        .to_string();

        // The document is only worth returning once the browser got past the gate.
        let document = if solved || challenge_absent {
            docs.last.take().and_then(|(rid, durl, status, hdrs)| {
                let r = sess
                    .call(Some(&sid), "Network.getResponseBody", json!({ "requestId": rid }))
                    .ok()?;
                let raw = r.get("body").and_then(Value::as_str).unwrap_or("");
                let mut bytes = if r.get("base64Encoded").and_then(Value::as_bool).unwrap_or(false) {
                    base64::engine::general_purpose::STANDARD.decode(raw).ok()?
                } else {
                    raw.as_bytes().to_vec()
                };
                let truncated = bytes.len() > MAX_DOC_BYTES;
                bytes.truncate(MAX_DOC_BYTES);
                Some(SolvedDocument {
                    url: durl.chars().take(2048).collect(),
                    status,
                    headers: header_map(&hdrs),
                    body_b64: base64::engine::general_purpose::STANDARD.encode(&bytes),
                    truncated,
                })
            })
        } else {
            None
        };

        let str_of = |v: Option<Value>| v.and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default();
        let final_url = str_of(eval_value(&mut sess, &sid, "location.href")).chars().take(2048).collect();
        let title = str_of(eval_value(&mut sess, &sid, "document.title")).chars().take(512).collect();

        Ok(SolveOutput {
            solved,
            challenge_absent,
            clearance_source,
            final_url,
            title,
            cookie_names,
            user_agent: ua.to_string(),
            document,
            nav_chain: std::mem::take(&mut docs.nav_chain),
            elapsed_ms: 0,
            intercepted: Vec::new(),
        })
    })();

    done.store(true, Ordering::Relaxed);
    let _ = sess.call(None, "Browser.close", json!({}));
    sess.kill();
    let _ = watchdog.join();
    let _ = std::fs::remove_dir_all(&profile);
    let intercepted = proxy.collect();

    result.map(|mut out| {
        out.elapsed_ms = started.elapsed().as_millis() as u64;
        // Chromium's own update/telemetry traffic is not the page's (see lib.rs).
        out.intercepted = intercepted
            .into_iter()
            .filter(|u| !crate::is_browser_infrastructure(u))
            .collect();
        out
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
    fn solver_ua_has_no_headless_token() {
        let ua = solver_user_agent();
        assert!(!ua.contains("Headless"), "headless token must not leak: {ua}");
        assert!(ua.contains("Chrome/") && ua.contains(".0.0.0"), "reduced-UA form: {ua}");
    }

    /// A page with no challenge comes back `challenge_absent`, not `solved`, reports no
    /// Cloudflare cookies (a page's own cookies are never surfaced), and involves no
    /// clearance.
    #[test]
    fn solver_reports_absent_challenge_on_plain_page() {
        if chromium_bin().is_none() {
            eprintln!("skipping solver test: no chromium on this host");
            return;
        }
        let url = "data:text/html,<html><head><title>Plain</title></head><body>hi\
                   <script>document.cookie='tracker=1';</script></body></html>";
        let out = cdp_solve_challenge(url, "", Duration::from_secs(15)).expect("solve");
        assert!(!out.solved, "nothing to solve");
        assert!(out.challenge_absent, "plain page is challenge-absent");
        assert!(out.cookie_names.is_empty(), "non-Cloudflare cookies are never surfaced");
        assert_eq!(out.clearance_source, "none");
        assert_eq!(out.title, "Plain");
    }

    /// An interstitial that never clears must time out as unsolved — not hang, not
    /// error — inside the deadline, and must return no document.
    #[test]
    fn solver_gives_up_on_uncleared_challenge() {
        if chromium_bin().is_none() {
            eprintln!("skipping solver test: no chromium on this host");
            return;
        }
        let url = "data:text/html,<html><head><title>Just a moment...</title></head>\
                   <body><script>window._cf_chl_opt={};</script></body></html>";
        let start = Instant::now();
        let out = cdp_solve_challenge(url, "", Duration::from_secs(6)).expect("solve");
        assert!(!out.solved && !out.challenge_absent);
        assert!(out.document.is_none(), "an uncleared interstitial is never returned as the page");
        assert!(start.elapsed() < Duration::from_secs(9), "bounded by the deadline");
    }

    /// Only the MAIN frame's documents are tracked, and the last one wins (after a
    /// challenge clears, that is the real page, not the interstitial).
    #[test]
    fn doc_tracker_keeps_last_main_frame_document_only() {
        let ev = |frame: &str, rtype: &str, rid: &str, url: &str| json!({
            "method": "Network.responseReceived",
            "params": { "requestId": rid, "frameId": frame, "type": rtype,
                        "response": { "url": url, "status": 200, "headers": {"server": "cloudflare"} } }
        });
        let mut t = DocTracker::new("MAIN".into());
        t.observe(&ev("MAIN", "Document", "1", "https://site.test/"));          // interstitial
        t.observe(&ev("TURNSTILE", "Document", "2", "https://challenges.cloudflare.com/x"));
        t.observe(&ev("MAIN", "Script", "3", "https://site.test/app.js"));
        t.observe(&ev("MAIN", "Document", "4", "https://site.test/"));          // real page
        let (rid, url, status, _) = t.last.expect("tracked");
        assert_eq!((rid.as_str(), url.as_str(), status), ("4", "https://site.test/", 200));
    }

    /// The navigation chain records main-frame Document requests in order — server
    /// redirects and a cross-origin hop included — and nothing from sub-frames or
    /// subresources.
    #[test]
    fn doc_tracker_records_main_frame_nav_chain() {
        let req = |frame: &str, rtype: &str, url: &str| json!({
            "method": "Network.requestWillBeSent",
            "params": { "frameId": frame, "type": rtype, "request": { "url": url } }
        });
        let mut t = DocTracker::new("MAIN".into());
        t.observe(&req("MAIN", "Document", "https://gate.test/"));
        t.observe(&req("MAIN", "Script", "https://gate.test/a.js"));
        t.observe(&req("MAIN", "Document", "https://gate.test/?ch=1&js=tok"));
        t.observe(&req("MAIN", "Document", "https://gate.test/?ch=1&js=tok")); // repeat
        t.observe(&req("FRAME", "Document", "https://iframe.test/"));
        t.observe(&req("MAIN", "Document", "http://tds.test/click?i=1"));
        t.observe(&req("MAIN", "Document", "chrome-error://chromewebdata/"));
        assert_eq!(t.nav_chain, vec![
            "https://gate.test/", "https://gate.test/?ch=1&js=tok", "http://tds.test/click?i=1",
        ]);
    }

    /// The clearance cache keeps only Cloudflare cookies scoped to the host, requires a
    /// cf_clearance, and honours a near expiry.
    #[test]
    fn clearance_cache_scoping_and_expiry() {
        let far = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 86_400) as f64;
        let c = |name: &str, domain: &str, exp: f64| json!({
            "name": name, "value": "v1", "domain": domain, "path": "/", "expires": exp,
            "secure": true, "httpOnly": true
        });
        let host = "cache-test-a.example";
        store_clearance(host, &[
            c("cf_clearance", ".cache-test-a.example", far),
            c("__cf_bm", ".cache-test-a.example", far),
            c("session", ".cache-test-a.example", far),       // not Cloudflare's
            c("_cfuvid", ".other.example", far),               // another site's
        ]);
        let got = cached_clearance(host).expect("cached");
        let names: Vec<&str> = got.iter().filter_map(|v| v["name"].as_str()).collect();
        assert_eq!(names, vec!["cf_clearance", "__cf_bm"]);

        // No cf_clearance -> nothing cached.
        store_clearance("cache-test-b.example", &[c("__cf_bm", ".cache-test-b.example", far)]);
        assert!(cached_clearance("cache-test-b.example").is_none());

        // Expiring inside the 60s safety margin -> not cached.
        let soon = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 30) as f64;
        store_clearance("cache-test-c.example", &[c("cf_clearance", ".cache-test-c.example", soon)]);
        assert!(cached_clearance("cache-test-c.example").is_none());

        drop_clearance(host);
        assert!(cached_clearance(host).is_none());
    }

    #[test]
    fn cookie_domain_match_is_rfc6265() {
        assert!(cookie_domain_matches(".example.com", "www.example.com"));
        assert!(cookie_domain_matches("example.com", "example.com"));
        assert!(!cookie_domain_matches("example.com", "notexample.com"));
        assert!(!cookie_domain_matches(".com", "example.com"), "bare TLD never matches");
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
            let mut navcap = NavCapture { sid: sid.clone(), first_doc: false, targets: Vec::new(),
                                          main_frame: String::new() };
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

    /// An IFRAME is a `resourceType: Document` too, and the latch had no frame check —
    /// so every sub-frame was recorded as a "client-side redirect destination" AND
    /// failed mid-render. citi.com's anti-fraud vendor loads three `crossdomain.html`
    /// iframes on per-session rotating hex domains; the Python side followed each as a
    /// redirect hop, scored it DGA=1.00 and reported HIGH, flipping a major bank to
    /// SUSPICIOUS on roughly half of scans.
    ///
    /// Drives the PRODUCTION drain + handler, like the F1 guard above. The main-frame
    /// redirect must still be captured — that is the whole feature — while the iframe
    /// must be continued and absent from the targets.
    #[test]
    fn iframe_document_is_not_captured_as_a_navigation() {
        if chromium_bin().is_none() {
            eprintln!("skipping iframe nav-capture test: no chromium on this host");
            return;
        }
        let profile = unique_profile_dir();
        let mut sess = CdpPipe::launch(&profile, &[]).expect("launch");
        let (done, watchdog) = spawn_watchdog(sess.pgid, Duration::from_secs(10));
        // An iframe to one host, then a main-frame redirect to another.
        let url = "data:text/html,<html><body>page\
                   <iframe src=\"https://frame.example.test/crossdomain.html\"></iframe>\
                   <script>setTimeout(function(){location.replace('https://dest.example.test/go');},300);</script>\
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
            // first_doc:false — like the F1 guard above, the validated initial navigation
            // is modelled as already done (a `data:` URL does not pause, so it cannot
            // consume the latch here). main_frame is seeded from the targetId exactly as
            // production seeds it, which is the behaviour under test.
            let mf = main_frame_id_from_target(&tid);
            let mut navcap = NavCapture { sid: sid.clone(), first_doc: false, targets: Vec::new(),
                                          main_frame: mf };
            sess.send_cmd(&sid, "Page.navigate", json!({ "url": url }));
            sess.drain_until_idle(
                Duration::from_millis(1200),
                Duration::from_millis(4000),
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

        let targets = targets.expect("iframe render");
        assert!(
            !targets.iter().any(|u| u.contains("frame.example.test")),
            "iframe Document must NOT be captured as a navigation; targets: {:?}", targets
        );
        assert!(
            targets.iter().any(|u| u.contains("dest.example.test")),
            "main-frame redirect must still be captured; targets: {:?}", targets
        );
    }
}
