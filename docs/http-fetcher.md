# HTTP Fetcher

## Overview
`SafeFetcher` in `src/fetcher/` is the only network-access point in Carapace.
All HTTP requests go through SSRF validation before and during execution.

## SSRF Protection (`ssrf.rs`)

### Blocked IPv4 Ranges
| Range | Reason |
|-------|--------|
| `127.0.0.0/8` | Loopback |
| `10.0.0.0/8` | RFC 1918 private |
| `172.16.0.0/12` | RFC 1918 private |
| `192.168.0.0/16` | RFC 1918 private |
| `169.254.0.0/16` | Link-local (APIPA) |
| `100.64.0.0/10` | Carrier-grade NAT |
| `192.0.2.0/24` | TEST-NET-1 documentation |
| `198.51.100.0/24` | TEST-NET-2 documentation |
| `203.0.113.0/24` | TEST-NET-3 documentation |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Reserved |
| `0.0.0.0/8` | Unspecified |
| `255.255.255.255` | Broadcast |

### Blocked IPv6 Ranges
| Range | Reason |
|-------|--------|
| `::1` | Loopback |
| `fc00::/7` | Unique local (private) |
| `fe80::/10` | Link-local |
| `ff00::/8` | Multicast |
| `::ffff:0:0/96` | IPv4-mapped (re-validates embedded IPv4) |

### Scheme Allowlist
Only `http` and `https` are permitted. `file://`, `ftp://`, `data:`, `javascript:` are all rejected at URL-parse time.

## DNS Rebinding Prevention
1. Before making the TCP connection, the target hostname is resolved via `tokio::net::lookup_host`.
2. Every returned IP is checked against the SSRF blocklist.
3. If **any** resolved IP is blocked, the request is aborted.
4. This prevents attacks where DNS returns a legitimate IP for validation but rebinds to a private IP for the actual request.

Note: for full protection against time-of-check/time-of-use rebinding, a custom DNS resolver with pinning (via `hickory-resolver`) should be wired into the reqwest connector. This is marked as a TODO in `fetcher/mod.rs`.

## Redirect Validation
- Redirects are followed **manually** (reqwest is configured with `Policy::none()`).
- Each redirect target URL is re-validated through the full SSRF stack.
- Maximum 5 redirect hops (configurable via CLI).
- Redirects to `file://`, private IPs, or credential-bearing URLs are rejected.

## Decompression Bomb Limits
- Default max response size: **10 MB** (post-decompression).
- Responses are consumed as a stream with a running byte counter.
- If the counter exceeds the limit mid-stream, reading stops and `CarapaceError::DecompressionBomb` is returned.
- The limit is configurable via `--max-size` (e.g. `--max-size 5MB`).

## TLS
- `reqwest` is built with `rustls-tls` and `default-features = false` to exclude native-tls.
- This ensures a consistent, auditable TLS stack regardless of the host OS.

## Configuration (`FetchOptions`)
```rust
pub struct FetchOptions {
    pub block_private_ips: bool,  // default: true
    pub https_only: bool,         // default: false
    pub max_size: Option<u64>,    // bytes; default: 10MB
    pub max_redirects: u32,       // default: 5
    pub timeout_secs: u64,        // default: 30
    pub no_assets: bool,          // skip sub-resource fetches
}
```
