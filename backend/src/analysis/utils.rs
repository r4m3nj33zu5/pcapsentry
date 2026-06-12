/// Shannon entropy of a string (bits per character).
pub fn shannon_entropy(s: &str) -> f64 {
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut freq = [0u32; 256];
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// True for any address that should be treated as "internal" for the purposes
/// of threat detection: RFC1918, loopback, link-local, CGNAT (RFC6598),
/// benchmarking (RFC2544), and the unspecified address. IPv6 covers
/// loopback, link-local, and ULA (fc00::/7).
pub fn is_private_ip(ip: &str) -> bool {
    match ip.parse::<IpAddr>() {
        Ok(addr) => is_private_addr(&addr),
        Err(_) => false,
    }
}

pub fn is_private_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

fn is_private_v4(v4: &Ipv4Addr) -> bool {
    // std-provided checks cover RFC1918, loopback, link-local, broadcast,
    // unspecified. Add CGNAT (100.64.0.0/10), benchmarking (198.18.0.0/15),
    // and TEST-NET ranges explicitly.
    if v4.is_private() || v4.is_loopback() || v4.is_link_local()
        || v4.is_broadcast() || v4.is_unspecified() || v4.is_documentation()
    {
        return true;
    }
    let o = v4.octets();
    // 100.64.0.0/10 — CGNAT
    if o[0] == 100 && (o[1] & 0xC0) == 64 { return true; }
    // 198.18.0.0/15 — benchmarking
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) { return true; }
    false
}

fn is_private_v6(v6: &Ipv6Addr) -> bool {
    if v6.is_loopback() || v6.is_unspecified() {
        return true;
    }
    let seg0 = v6.segments()[0];
    // fe80::/10 — link-local
    if (seg0 & 0xFFC0) == 0xFE80 { return true; }
    // fc00::/7 — unique local
    if (seg0 & 0xFE00) == 0xFC00 { return true; }
    false
}

/// Canonical 5-tuple flow ID. IPs are parsed and ordered numerically so
/// bidirectional flow matching is correct (string compare would put
/// "10.0.0.2" before "9.0.0.1").
pub fn flow_id(
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    proto: &str,
) -> String {
    let src_addr = src_ip.parse::<IpAddr>().ok();
    let dst_addr = dst_ip.parse::<IpAddr>().ok();
    let src_first = match (src_addr, dst_addr) {
        (Some(s), Some(d)) => s <= d,
        // Fall back to lexicographic when either side is unparseable.
        _ => src_ip <= dst_ip,
    };
    let (a_ip, b_ip, a_port, b_port) = if src_first {
        (src_ip, dst_ip, src_port.unwrap_or(0), dst_port.unwrap_or(0))
    } else {
        (dst_ip, src_ip, dst_port.unwrap_or(0), src_port.unwrap_or(0))
    };
    format!("{a_ip}:{a_port}-{b_ip}:{b_port}-{proto}")
}

pub fn format_bytes(b: usize) -> String {
    if b >= 1_073_741_824 {
        format!("{:.1} GB", b as f64 / 1_073_741_824.0)
    } else if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}
