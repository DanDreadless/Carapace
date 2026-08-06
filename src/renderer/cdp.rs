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
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use serde_json::{json, Value};

use crate::error::{CarapaceError, Result};

fn err(msg: impl Into<String>) -> CarapaceError {
    CarapaceError::Render(msg.into())
}

/// Result of one spike render: the post-JS DOM, whether our injected bootstrap
/// ran before page scripts, and the decoded screenshot byte length.
#[derive(Debug)]
pub struct SpikeOutput {
    pub dom: String,
    pub bootstrap_ran: bool,
    pub screenshot_len: usize,
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
    fn launch(profile_dir: &std::path::Path) -> Result<Self> {
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
    let profile = std::env::temp_dir().join(format!(
        "carapace-cdp-spike-{}-{}",
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ));
    let mut sess = CdpPipe::launch(&profile)?;

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
}
