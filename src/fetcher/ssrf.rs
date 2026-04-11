use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use crate::error::{CarapaceError, Result};

/// Checks whether an IP address is safe to connect to.
///
/// Returns `Ok(())` if safe, or `Err(CarapaceError::Ssrf(...))` if the address
/// falls within any blocked range (loopback, private, link-local, multicast,
/// reserved, carrier-grade NAT, IPv4-mapped private, etc.).
pub fn is_safe_ip(ip: &IpAddr) -> Result<()> {
    match ip {
        IpAddr::V4(v4) => check_ipv4(v4),
        IpAddr::V6(v6) => check_ipv6(v6),
    }
}

fn check_ipv4(ip: &Ipv4Addr) -> Result<()> {
    if ip.is_loopback() {
        return Err(ssrf(format!("loopback: {ip}")));
    }
    if ip.is_private() {
        return Err(ssrf(format!("private range: {ip}")));
    }
    if ip.is_link_local() {
        return Err(ssrf(format!("link-local: {ip}")));
    }
    if ip.is_broadcast() {
        return Err(ssrf(format!("broadcast: {ip}")));
    }
    if ip.is_multicast() {
        return Err(ssrf(format!("multicast: {ip}")));
    }
    if ip.is_unspecified() {
        return Err(ssrf(format!("unspecified: {ip}")));
    }

    let [a, b, c, _] = ip.octets();

    // 100.64.0.0/10 — Carrier-grade NAT (RFC 6598)
    if a == 100 && (b & 0xC0) == 64 {
        return Err(ssrf(format!("carrier-grade NAT (RFC 6598): {ip}")));
    }

    // 192.0.0.0/24 — IETF Protocol Assignments (RFC 6890)
    if a == 192 && b == 0 && c == 0 {
        return Err(ssrf(format!("IETF protocol assignments: {ip}")));
    }

    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — Documentation (RFC 5737)
    if (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        return Err(ssrf(format!("documentation range (RFC 5737): {ip}")));
    }

    // 198.18.0.0/15 — Benchmarking (RFC 2544)
    if a == 198 && (b == 18 || b == 19) {
        return Err(ssrf(format!("benchmarking range (RFC 2544): {ip}")));
    }

    // 240.0.0.0/4 — Reserved (future use)
    if a >= 240 {
        return Err(ssrf(format!("reserved (future use): {ip}")));
    }

    Ok(())
}

fn check_ipv6(ip: &Ipv6Addr) -> Result<()> {
    if ip.is_loopback() {
        return Err(ssrf(format!("loopback: {ip}")));
    }
    if ip.is_unspecified() {
        return Err(ssrf(format!("unspecified: {ip}")));
    }
    if ip.is_multicast() {
        return Err(ssrf(format!("multicast: {ip}")));
    }

    let segs = ip.segments();

    // fc00::/7 — Unique local addresses (private, RFC 4193)
    if (segs[0] & 0xFE00) == 0xFC00 {
        return Err(ssrf(format!("unique local (private, RFC 4193): {ip}")));
    }

    // fe80::/10 — Link-local
    if (segs[0] & 0xFFC0) == 0xFE80 {
        return Err(ssrf(format!("link-local: {ip}")));
    }

    // 2001:db8::/32 — Documentation (RFC 3849)
    if segs[0] == 0x2001 && segs[1] == 0x0DB8 {
        return Err(ssrf(format!("documentation range (RFC 3849): {ip}")));
    }

    // 64:ff9b::/96 and ::ffff:0:0/96 — IPv4-mapped / NAT64
    // Re-validate the embedded IPv4 address.
    if segs[0] == 0 && segs[1] == 0 && segs[2] == 0
        && segs[3] == 0 && segs[4] == 0
        && (segs[5] == 0xFFFF || (segs[4] == 0 && segs[5] == 0))
    {
        let v4 = Ipv4Addr::new(
            (segs[6] >> 8) as u8,
            (segs[6] & 0xFF) as u8,
            (segs[7] >> 8) as u8,
            (segs[7] & 0xFF) as u8,
        );
        // Only check if non-zero (avoids false positive on ::)
        if !v4.is_unspecified() {
            return check_ipv4(&v4).map_err(|_| {
                ssrf(format!("IPv4-mapped private address: {ip} (embedded {v4})"))
            });
        }
    }

    // 100::/64 — Discard-only (RFC 6666)
    if segs[0] == 0x0100 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0 {
        return Err(ssrf(format!("discard-only range (RFC 6666): {ip}")));
    }

    Ok(())
}

/// Validate that a URL scheme is permitted.
/// Only `http` and `https` are allowed; everything else is rejected.
pub fn validate_scheme(scheme: &str) -> Result<()> {
    match scheme {
        "http" | "https" => Ok(()),
        other => Err(ssrf(format!("scheme not allowed: '{other}'"))),
    }
}

#[inline]
fn ssrf(msg: impl Into<String>) -> CarapaceError {
    CarapaceError::Ssrf(msg.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }
    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn blocks_loopback() {
        assert!(is_safe_ip(&v4("127.0.0.1")).is_err());
        assert!(is_safe_ip(&v6("::1")).is_err());
    }

    #[test]
    fn blocks_private() {
        assert!(is_safe_ip(&v4("10.0.0.1")).is_err());
        assert!(is_safe_ip(&v4("172.16.0.1")).is_err());
        assert!(is_safe_ip(&v4("192.168.1.1")).is_err());
        assert!(is_safe_ip(&v6("fc00::1")).is_err());
    }

    #[test]
    fn blocks_link_local() {
        assert!(is_safe_ip(&v4("169.254.169.254")).is_err()); // AWS metadata endpoint
        assert!(is_safe_ip(&v6("fe80::1")).is_err());
    }

    #[test]
    fn blocks_cgnat() {
        assert!(is_safe_ip(&v4("100.64.0.1")).is_err());
        assert!(is_safe_ip(&v4("100.127.255.255")).is_err());
    }

    #[test]
    fn blocks_ipv4_mapped_private() {
        // ::ffff:192.168.1.1
        assert!(is_safe_ip(&v6("::ffff:192.168.1.1")).is_err());
        assert!(is_safe_ip(&v6("::ffff:127.0.0.1")).is_err());
    }

    #[test]
    fn allows_public() {
        assert!(is_safe_ip(&v4("1.1.1.1")).is_ok());
        assert!(is_safe_ip(&v4("8.8.8.8")).is_ok());
        assert!(is_safe_ip(&v6("2606:4700:4700::1111")).is_ok());
    }

    #[test]
    fn scheme_allowlist() {
        assert!(validate_scheme("https").is_ok());
        assert!(validate_scheme("http").is_ok());
        assert!(validate_scheme("file").is_err());
        assert!(validate_scheme("javascript").is_err());
        assert!(validate_scheme("ftp").is_err());
        assert!(validate_scheme("data").is_err());
    }
}
