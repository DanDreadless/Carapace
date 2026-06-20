//! Forwarding **policy proxy** for live-navigation rendering (CARAPACE-09 / P0).
//!
//! The offline render path (`file://` self-contained HTML) uses the dead
//! `LoggingProxy` that refuses every request — safe, but SPA/data-driven pages
//! render an empty shell because their runtime data never loads.  This proxy lets
//! Chromium navigate the **real** page and load **same-origin** content (CSS, JS,
//! fonts, images, and the page's own XHR/`fetch` API) so the page renders as a real
//! browser would, while still **refusing and recording** cross-origin requests
//! (the C2 / exfil signal).
//!
//! Security model (every guarantee from the offline path is preserved):
//!   * **SSRF on every forwarded request** — the proxy resolves the host itself and
//!     rejects the connection if *any* resolved IP is private/loopback/link-local/
//!     metadata/CGNAT (reusing `fetcher::ssrf::is_safe_ip`).  Because Chromium routes
//!     all DNS through the proxy, this also defeats DNS-rebinding.
//!   * **Same-origin only** — allowed hosts are the scanned page's host (and its
//!     subdomains, `www.` normalised) plus a vetted read-only CDN/font allow-list.
//!     A same-origin request cannot leak anything: the attacker already controls that
//!     server, and the render container holds no cookies or secrets.
//!   * **Cross-origin refused + recorded** — third-party XHR/`fetch`/beacon/WebSocket
//!     get a 503 and are surfaced as intercepted-request evidence.
//!   * **Bounded** — max forwarded connections, per-connection timeouts, and a
//!     per-connection byte cap so a hostile server cannot hang or DoS the render.

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tracing::debug;

use crate::fetcher::ssrf::is_safe_ip;

/// Max upstream connections forwarded in one render session.
const MAX_FORWARDED: u32 = 400;
/// Per-connection read/write timeout.
const CONN_TIMEOUT: Duration = Duration::from_secs(12);
/// Max bytes copied per direction per connection — guards against a hostile
/// same-origin server streaming forever to hang the render or exhaust memory.
const MAX_BYTES_PER_DIR: u64 = 16 * 1024 * 1024;

/// Network policy for a render, anchored on the scanned page's host.
#[derive(Clone)]
pub struct RenderPolicy {
    /// Page host, `www.`-stripped and lowercased.
    page_host: String,
    /// Vetted CDN/font/payment host suffixes (no leading dot, lowercased).
    cdn_suffixes: Arc<Vec<String>>,
}

impl RenderPolicy {
    /// `cdn_bypass_csv` is the comma-separated allow-list (the same value used for
    /// the offline `--proxy-bypass-list`); leading dots are stripped.
    pub fn new(page_host: &str, cdn_bypass_csv: &str) -> Self {
        let page_host = page_host
            .strip_prefix("www.")
            .unwrap_or(page_host)
            .to_ascii_lowercase();
        let cdn_suffixes: Vec<String> = cdn_bypass_csv
            .split(',')
            .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Self { page_host, cdn_suffixes: Arc::new(cdn_suffixes) }
    }

    /// Same-site: the page host or a subdomain of it (mirrors `lib.rs::is_same_site`,
    /// which is page-host-anchored — no public-suffix over-allow risk).
    pub fn is_same_site(&self, host: &str) -> bool {
        let h = host.strip_prefix("www.").unwrap_or(host).to_ascii_lowercase();
        !self.page_host.is_empty()
            && (h == self.page_host || h.ends_with(&format!(".{}", self.page_host)))
    }

    /// Vetted read-only CDN / font / payment / consent host.
    pub fn is_known_good(&self, host: &str) -> bool {
        let h = host.to_ascii_lowercase();
        self.cdn_suffixes
            .iter()
            .any(|s| h == *s || h.ends_with(&format!(".{}", s)))
    }

    /// A host may be reached live when it is same-site or a vetted CDN.
    pub fn allows(&self, host: &str) -> bool {
        self.is_same_site(host) || self.is_known_good(host)
    }
}

/// A forwarding HTTP/CONNECT proxy that enforces a `RenderPolicy`.
pub struct PolicyProxy {
    port: u16,
    intercepted: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl PolicyProxy {
    pub fn start(policy: RenderPolicy) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind policy proxy");
        let port = listener.local_addr().expect("no local addr").port();
        listener.set_nonblocking(true).ok();

        let intercepted: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let forwarded = Arc::new(AtomicU32::new(0));

        let i2 = Arc::clone(&intercepted);
        let s2 = Arc::clone(&stop);
        std::thread::spawn(move || {
            loop {
                if s2.load(Ordering::Relaxed) {
                    break;
                }
                match listener.accept() {
                    Ok((stream, _)) => {
                        let pol = policy.clone();
                        let ic = Arc::clone(&i2);
                        let fc = Arc::clone(&forwarded);
                        // One thread per connection: CONNECT tunnels are long-lived
                        // and Chromium opens many in parallel.
                        std::thread::spawn(move || handle_conn(stream, pol, ic, fc));
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self { port, intercepted, stop }
    }

    pub fn proxy_arg(&self) -> String {
        format!("--proxy-server=http://127.0.0.1:{}", self.port)
    }

    /// Stop the proxy and return the deduplicated list of **refused cross-origin**
    /// URLs (the intercepted-request evidence set).
    pub fn collect(self) -> Vec<String> {
        self.stop.store(true, Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(50));
        let urls = self.intercepted.lock().unwrap().clone();
        dedup_by_domain(urls)
    }
}

fn record(intercepted: &Mutex<Vec<String>>, url: String) {
    let mut v = intercepted.lock().unwrap();
    if v.len() < 200 {
        v.push(url);
    }
}

fn refuse(client: &mut TcpStream) {
    let _ = client.write_all(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    );
    let _ = client.shutdown(Shutdown::Both);
}

/// Outcome of attempting to reach an upstream host.
enum ConnectOutcome {
    /// Connected — the stream to forward through.
    Ok(TcpStream),
    /// Rejected by SSRF (a resolved IP is internal, or DNS failed) — recorded as
    /// evidence: a page pointing an allowed host at an internal IP is suspicious.
    Ssrf,
    /// Resolved to safe public IP(s) but could not connect (transient network /
    /// upstream-down). NOT recorded — a same-origin/CDN request we *allowed* but
    /// couldn't reach is a benign failure, not cross-origin exfil evidence.
    Unreachable,
}

/// Resolve `host:port`, reject if **any** resolved IP is unsafe (strict
/// DNS-rebinding defense) or DNS fails, then connect to the first safe address.
fn safe_connect(host: &str, port: u16) -> ConnectOutcome {
    let addrs: Vec<_> = match (host, port).to_socket_addrs() {
        Ok(a) => a.collect(),
        // Unresolvable host: no IP, no connection possible — a benign network
        // outcome, NOT an SSRF block. (An allowed same-origin host that simply
        // doesn't resolve from the render container — e.g. metrics.roblox.com —
        // must not be recorded as intercepted-exfil evidence.) Only a resolution
        // to an internal IP below is SSRF.
        Err(_) => return ConnectOutcome::Unreachable,
    };
    if addrs.is_empty() {
        return ConnectOutcome::Unreachable;
    }
    for a in &addrs {
        if is_safe_ip(&a.ip()).is_err() {
            debug!("policy proxy: SSRF-blocked {host} -> {}", a.ip());
            return ConnectOutcome::Ssrf;
        }
    }
    for a in &addrs {
        if let Ok(s) = TcpStream::connect_timeout(a, CONN_TIMEOUT) {
            s.set_read_timeout(Some(CONN_TIMEOUT)).ok();
            s.set_write_timeout(Some(CONN_TIMEOUT)).ok();
            return ConnectOutcome::Ok(s);
        }
    }
    ConnectOutcome::Unreachable
}

fn handle_conn(
    mut client: TcpStream,
    policy: RenderPolicy,
    intercepted: Arc<Mutex<Vec<String>>>,
    forwarded: Arc<AtomicU32>,
) {
    client.set_read_timeout(Some(CONN_TIMEOUT)).ok();
    client.set_write_timeout(Some(CONN_TIMEOUT)).ok();

    let head = match read_request_head(&mut client) {
        Some(h) if !h.is_empty() => h,
        _ => {
            refuse(&mut client);
            return;
        }
    };
    let first = head.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        // CONNECT host:port — HTTPS tunnel (we see only the host, not the path).
        let (host, port) = split_host_port(target, 443);
        if host.is_empty() || !policy.allows(&host) {
            record(&intercepted, format!("https://{}", host));
            refuse(&mut client);
            return;
        }
        if forwarded.fetch_add(1, Ordering::Relaxed) >= MAX_FORWARDED {
            refuse(&mut client);
            return;
        }
        match safe_connect(&host, port) {
            ConnectOutcome::Ok(upstream) => {
                if client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .is_ok()
                {
                    tunnel(client, upstream);
                }
            }
            // The host was already allowed by policy (same-origin / vetted CDN), so a
            // connect failure — whether SSRF (resolved to an internal IP) or simply
            // unreachable — is NOT cross-origin exfil evidence and must not pollute
            // the intercepted list. We still refuse the connection (the SSRF is
            // blocked; security is unaffected — the protection is the block, not the
            // record). Cross-origin requests are recorded at the policy-deny branch.
            ConnectOutcome::Ssrf | ConnectOutcome::Unreachable => refuse(&mut client),
        }
    } else if let Some(rest) = target.strip_prefix("http://") {
        // Plain-HTTP absolute-form: GET http://host/path HTTP/1.1
        let slash = rest.find('/').unwrap_or(rest.len());
        let authority = &rest[..slash];
        let path = if slash < rest.len() { &rest[slash..] } else { "/" };
        let (host, port) = split_host_port(authority, 80);
        if host.is_empty() || !policy.allows(&host) {
            record(&intercepted, target.to_string());
            refuse(&mut client);
            return;
        }
        if forwarded.fetch_add(1, Ordering::Relaxed) >= MAX_FORWARDED {
            refuse(&mut client);
            return;
        }
        match safe_connect(&host, port) {
            ConnectOutcome::Ok(mut upstream) => {
                // Rewrite to origin-form and force Connection: close so each proxied
                // request is its own connection (no keep-alive re-use to rewrite).
                let rewritten = rewrite_http_head(&head, path);
                if upstream.write_all(rewritten.as_bytes()).is_ok() {
                    tunnel(client, upstream);
                }
            }
            // Allowed host that failed to connect (SSRF or unreachable) — refuse but
            // do not record; only policy-denied cross-origin requests are evidence.
            ConnectOutcome::Ssrf | ConnectOutcome::Unreachable => refuse(&mut client),
        }
    } else {
        refuse(&mut client);
    }
}

/// Read the request head (up to the blank line, or 16 KB).
fn read_request_head(client: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        match client.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() >= 16 * 1024 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    if buf.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&buf).to_string())
    }
}

/// Rewrite a proxied absolute-form HTTP head to origin-form, dropping any
/// proxy/keep-alive headers and forcing `Connection: close`.
fn rewrite_http_head(head: &str, path: &str) -> String {
    let mut lines = head.lines();
    let first = lines.next().unwrap_or("");
    let mut p = first.split_whitespace();
    let method = p.next().unwrap_or("GET");
    let version = p.nth(1).unwrap_or("HTTP/1.1");
    let mut out = format!("{} {} {}\r\n", method, path, version);
    for line in lines {
        if line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("proxy-")
            || lower.starts_with("connection:")
            || lower.starts_with("keep-alive:")
        {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    out
}

/// Blind bidirectional pipe between client and upstream, byte-capped per
/// direction.  Used for both the CONNECT tunnel and plain-HTTP forwarding.
fn tunnel(client: TcpStream, upstream: TcpStream) {
    let (Ok(client_w), Ok(up_w)) = (client.try_clone(), upstream.try_clone()) else {
        return;
    };
    let h = std::thread::spawn(move || copy_capped(client, up_w));
    let _ = copy_capped(upstream, client_w);
    let _ = h.join();
}

/// Copy `src` → `dst` up to `MAX_BYTES_PER_DIR`, then shut both halves so the peer
/// pipe terminates promptly.
fn copy_capped(mut src: TcpStream, mut dst: TcpStream) {
    let mut buf = [0u8; 16 * 1024];
    let mut total: u64 = 0;
    loop {
        match src.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if dst.write_all(&buf[..n]).is_err() {
                    break;
                }
                total += n as u64;
                if total >= MAX_BYTES_PER_DIR {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    let _ = dst.shutdown(Shutdown::Write);
    let _ = src.shutdown(Shutdown::Read);
}

fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    // Handle IPv6 literals [::1]:443 and host:port.
    if let Some(rest) = authority.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let port = rest[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (host.to_ascii_lowercase(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_ascii_lowercase(), p.parse().unwrap_or(default_port)),
        None => (authority.to_ascii_lowercase(), default_port),
    }
}

fn dedup_by_domain(urls: Vec<String>) -> Vec<String> {
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for url in urls {
        let domain = url
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(&url)
            .to_string();
        if seen.insert(domain) {
            out.push(url);
            if out.len() >= 50 {
                break;
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(host: &str) -> RenderPolicy {
        RenderPolicy::new(host, ".googleapis.com,.gstatic.com,cdnjs.cloudflare.com,.stripe.com")
    }

    #[test]
    fn same_site_allowed() {
        let p = policy("www.example.com");
        assert!(p.allows("example.com"));
        assert!(p.allows("www.example.com"));
        assert!(p.allows("api.example.com"));      // SPA backend on a subdomain
        assert!(p.allows("cdn.example.com"));
    }

    #[test]
    fn cross_origin_refused() {
        let p = policy("www.example.com");
        assert!(!p.allows("evil-c2.com"));
        assert!(!p.allows("example.com.attacker.net")); // suffix-trick must NOT match
        assert!(!p.allows("notexample.com"));
    }

    #[test]
    fn known_good_cdn_allowed() {
        let p = policy("shop.test");
        assert!(p.allows("fonts.googleapis.com"));
        assert!(p.allows("ajax.googleapis.com"));
        assert!(p.allows("cdnjs.cloudflare.com"));
        assert!(p.allows("js.stripe.com"));
        assert!(!p.allows("cloudflare.com"));   // parent not in the list (only cdnjs.*)
    }

    #[test]
    fn deep_subdomain_page_is_conservative() {
        // A page on a deep subdomain only allows its own subtree (safe/strict).
        let p = policy("dashboard.example.com");
        assert!(p.allows("dashboard.example.com"));
        assert!(p.allows("x.dashboard.example.com"));
        assert!(!p.allows("api.example.com"));  // sibling subdomain → denied (conservative)
    }

    #[test]
    fn split_host_port_forms() {
        assert_eq!(split_host_port("example.com:443", 443), ("example.com".into(), 443));
        assert_eq!(split_host_port("example.com", 80), ("example.com".into(), 80));
        assert_eq!(split_host_port("[::1]:8443", 443), ("::1".into(), 8443));
    }

    #[test]
    fn safe_connect_rejects_internal_targets() {
        // The SSRF gate must refuse hosts that resolve to internal IPs even if the
        // policy would otherwise allow them — this is the core protection when
        // scanning a malicious page that points an allowed host at an internal IP.
        assert!(matches!(safe_connect("127.0.0.1", 80), ConnectOutcome::Ssrf));        // loopback literal
        assert!(matches!(safe_connect("localhost", 80), ConnectOutcome::Ssrf));        // resolves to loopback
        assert!(matches!(safe_connect("169.254.169.254", 80), ConnectOutcome::Ssrf));  // cloud metadata
        assert!(matches!(safe_connect("10.0.0.1", 80), ConnectOutcome::Ssrf));         // RFC1918 private
        assert!(matches!(safe_connect("192.168.1.1", 80), ConnectOutcome::Ssrf));      // RFC1918 private
    }

    #[test]
    fn http_head_rewritten_to_origin_form() {
        let head = "GET http://example.com/api/x HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nConnection: keep-alive\r\nUser-Agent: x\r\n\r\n";
        let out = rewrite_http_head(head, "/api/x");
        assert!(out.starts_with("GET /api/x HTTP/1.1\r\n"));
        assert!(out.contains("Host: example.com\r\n"));
        assert!(out.contains("User-Agent: x\r\n"));
        assert!(!out.to_ascii_lowercase().contains("proxy-connection"));
        assert!(out.trim_end().ends_with("Connection: close"));
    }
}
