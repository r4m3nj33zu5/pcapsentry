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

pub fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || ip == "127.0.0.1"
        || ip.starts_with("169.254.")
    {
        return true;
    }
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return true;
                }
            }
        }
    }
    if ip == "::1" || ip.starts_with("fe80:") {
        return true;
    }
    false
}

/// Canonical 5-tuple flow ID (always src < dst for bidir matching).
pub fn flow_id(
    src_ip: &str,
    dst_ip: &str,
    src_port: Option<u16>,
    dst_port: Option<u16>,
    proto: &str,
) -> String {
    let (a_ip, b_ip, a_port, b_port) = if src_ip <= dst_ip {
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
