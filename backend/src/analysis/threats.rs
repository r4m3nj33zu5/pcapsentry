use std::collections::HashMap;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use crate::analysis::indexed::IndexedView;
use crate::analysis::utils::is_private_addr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub first_seen: f64,
    pub packet_indices: Vec<usize>,
}

pub fn detect(view: &IndexedView, thresholds: &crate::config::AlertThresholds, whitelist: &crate::config::Whitelist) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    findings.extend(detect_port_scan(view, thresholds));
    findings.extend(detect_arp_spoofing(view));
    findings.extend(detect_icmp_sweep(view));
    findings.extend(detect_icmp_ping_activity(view));
    findings.extend(detect_icmp_flood(view, thresholds));
    findings.extend(detect_large_icmp(view));
    findings.extend(detect_udp_flood(view, thresholds));
    findings.extend(detect_suspicious_ports(view));
    findings.extend(detect_telnet(view));
    findings.extend(detect_syn_flood(view, thresholds));
    findings.extend(detect_xmas_null_fin(view));
    findings.extend(detect_beaconing(view, thresholds));
    findings.extend(detect_traffic_spikes(view, thresholds));
    findings.extend(detect_cleartext_credentials(view));

    // Apply whitelist via post-filter on the title — the legacy threats
    // schema doesn't carry an explicit affected_hosts list. Drop any finding
    // whose title contains a whitelisted IP. Comparing parsed IpAddr avoids
    // "::1" vs "0:0:0:0:0:0:0:1" formatting drift.
    if !whitelist.ips.is_empty() {
        let wl: std::collections::HashSet<IpAddr> = whitelist.ips.iter()
            .filter_map(|s| s.parse().ok()).collect();
        findings.retain(|f| {
            !wl.iter().any(|ip| f.title.contains(&ip.to_string())
                || f.description.contains(&ip.to_string()))
        });
    }

    // Sort by severity
    let sev_order = |s: &str| match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        _ => 3,
    };
    findings.sort_by_key(|f| sev_order(&f.severity));
    findings
}

fn detect_port_scan(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<ThreatFinding> {
    let mut syn_map: HashMap<IpAddr, HashMap<IpAddr, Vec<(u16, usize)>>> = HashMap::new();
    let mut synack_map: HashMap<IpAddr, usize> = HashMap::new();
    let mut first_seen_map: HashMap<IpAddr, f64> = HashMap::new();

    for &i in &view.tcp_syn {
        let pkt = &view.packets[i];
        let (src, dst) = match (pkt.src_ip, pkt.dst_ip) {
            (Some(s), Some(d)) => (s, d),
            _ => continue,
        };
        let dst_port = pkt.dst_port.unwrap_or(0);
        syn_map.entry(src).or_default().entry(dst).or_default().push((dst_port, pkt.index));
        let fs = first_seen_map.entry(src).or_insert(f64::INFINITY);
        if pkt.timestamp < *fs { *fs = pkt.timestamp; }
    }
    for &i in &view.tcp_synack {
        let pkt = &view.packets[i];
        if let Some(dst) = pkt.dst_ip {
            *synack_map.entry(dst).or_insert(0) += 1;
        }
    }

    let mut findings = Vec::new();
    for (src, dst_map) in &syn_map {
        let total_ports: usize = dst_map.values().map(|v| v.len()).sum();
        let distinct_dsts = dst_map.len();
        let synacks = synack_map.get(src).copied().unwrap_or(0);

        // Port scan: many SYNs, few SYN-ACKs back
        if total_ports >= thresholds.port_scan_syn_minimum && synacks < (total_ports as f64 * thresholds.port_scan_response_ratio) as usize {
            let packet_indices: Vec<usize> = dst_map.values().flatten().map(|(_, i)| *i).take(100).collect();
            let first_seen = first_seen_map.get(src).copied().unwrap_or(f64::INFINITY);
            let first_seen = if first_seen.is_finite() { first_seen } else { 0.0 };

            findings.push(ThreatFinding {
                severity: if total_ports > 100 { "Critical".to_string() } else { "High".to_string() },
                category: "Reconnaissance".to_string(),
                title: format!("Port Scan Detected from {}", src),
                description: format!(
                    "{} sent SYN packets to {} ports across {} destination(s) with only {} responses, \
                    indicating an active port scan — likely reconnaissance prior to exploitation.",
                    src, total_ports, distinct_dsts, synacks
                ),
                first_seen,
                packet_indices,
            });
        }
    }
    findings
}

fn detect_icmp_sweep(view: &IndexedView) -> Vec<ThreatFinding> {
    let mut icmp_sources: HashMap<IpAddr, Vec<(IpAddr, usize)>> = HashMap::new();

    for &i in &view.icmp {
        let pkt = &view.packets[i];
        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            icmp_sources.entry(src).or_default().push((dst, pkt.index));
        }
    }

    let mut findings = Vec::new();
    for (src, targets) in &icmp_sources {
        let unique_targets: std::collections::HashSet<&IpAddr> = targets.iter().map(|(ip, _)| ip).collect();
        if unique_targets.len() >= 10 {
            let packet_indices: Vec<usize> = targets.iter().map(|(_, i)| *i).take(50).collect();
            let first_seen = packet_indices.iter()
                .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "Medium".to_string(),
                category: "Reconnaissance".to_string(),
                title: format!("ICMP Sweep from {}", src),
                description: format!(
                    "{} sent ICMP echo requests to {} unique hosts, suggesting a ping sweep \
                    used to discover live hosts on the network.",
                    src, unique_targets.len()
                ),
                first_seen,
                packet_indices,
            });
        }
    }
    findings
}

fn detect_xmas_null_fin(view: &IndexedView) -> Vec<ThreatFinding> {
    let mut xmas_packets: Vec<(IpAddr, usize, f64)> = Vec::new();
    let mut null_packets: Vec<(IpAddr, usize, f64)> = Vec::new();
    let mut fin_packets: Vec<(IpAddr, usize, f64)> = Vec::new();

    let push = |bucket: &mut Vec<(IpAddr, usize, f64)>, i: usize| {
        let pkt = &view.packets[i];
        if let Some(src) = pkt.src_ip {
            bucket.push((src, pkt.index, pkt.timestamp));
        }
    };
    for &i in &view.tcp_xmas { push(&mut xmas_packets, i); }
    for &i in &view.tcp_null { push(&mut null_packets, i); }
    for &i in &view.tcp_fin_only { push(&mut fin_packets, i); }

    let mut findings = Vec::new();

    if !xmas_packets.is_empty() {
        let first_seen = xmas_packets.iter().map(|(_, _, ts)| *ts).fold(f64::INFINITY, f64::min);
        findings.push(ThreatFinding {
            severity: "High".to_string(),
            category: "Reconnaissance".to_string(),
            title: "Xmas Scan Detected".to_string(),
            description: format!(
                "{} Xmas scan packets detected (FIN+PSH+URG flags set). This technique is used \
                to probe for open ports on systems that respond differently to illegal flag combinations.",
                xmas_packets.len()
            ),
            first_seen,
            packet_indices: xmas_packets.iter().map(|(_, i, _)| *i).take(50).collect(),
        });
    }
    if null_packets.len() >= 5 {
        let first_seen = null_packets.iter().map(|(_, _, ts)| *ts).fold(f64::INFINITY, f64::min);
        findings.push(ThreatFinding {
            severity: "High".to_string(),
            category: "Reconnaissance".to_string(),
            title: "NULL Scan Detected".to_string(),
            description: format!(
                "{} NULL scan packets detected (no TCP flags set). NULL scans are used to evade \
                stateless firewalls and fingerprint operating systems based on RFC compliance.",
                null_packets.len()
            ),
            first_seen,
            packet_indices: null_packets.iter().map(|(_, i, _)| *i).take(50).collect(),
        });
    }
    if fin_packets.len() >= 5 {
        let first_seen = fin_packets.iter().map(|(_, _, ts)| *ts).fold(f64::INFINITY, f64::min);
        findings.push(ThreatFinding {
            severity: "Medium".to_string(),
            category: "Reconnaissance".to_string(),
            title: "FIN Scan Detected".to_string(),
            description: format!(
                "{} isolated FIN packets detected without preceding SYN/ACK handshake. FIN scans \
                exploit TCP state handling to enumerate open ports while evading basic IDS rules.",
                fin_packets.len()
            ),
            first_seen,
            packet_indices: fin_packets.iter().map(|(_, i, _)| *i).take(50).collect(),
        });
    }
    findings
}

fn detect_arp_spoofing(view: &IndexedView) -> Vec<ThreatFinding> {
    let mut ip_mac_map: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut ip_mac_packets: HashMap<String, Vec<usize>> = HashMap::new();

    for &i in &view.arp_reply {
        let pkt = &view.packets[i];
        if let Some(arp) = &pkt.layers.arp {
            ip_mac_map.entry(arp.sender_ip.clone()).or_default().insert(arp.sender_mac.clone());
            ip_mac_packets.entry(arp.sender_ip.clone()).or_default().push(pkt.index);
        }
    }

    let mut findings = Vec::new();
    for (ip, macs) in &ip_mac_map {
        if macs.len() > 1 {
            let packet_indices = ip_mac_packets.get(ip).cloned().unwrap_or_default();
            let first_seen = packet_indices.iter()
                .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "Critical".to_string(),
                category: "Network Attack".to_string(),
                title: format!("ARP Spoofing Detected for {}", ip),
                description: format!(
                    "IP address {} appeared with {} different MAC addresses in ARP replies: {}. \
                    This is a strong indicator of ARP cache poisoning, which attackers use to \
                    intercept traffic (man-in-the-middle).",
                    ip,
                    macs.len(),
                    macs.iter().cloned().collect::<Vec<_>>().join(", ")
                ),
                first_seen,
                packet_indices: packet_indices.into_iter().take(50).collect(),
            });
        }
    }
    findings
}

fn detect_beaconing(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<ThreatFinding> {
    let mut conn_times: HashMap<(IpAddr, IpAddr), Vec<f64>> = HashMap::new();
    let mut conn_packets: HashMap<(IpAddr, IpAddr), Vec<usize>> = HashMap::new();

    for &i in &view.tcp_syn {
        let pkt = &view.packets[i];
        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            if !is_private_addr(&dst) {
                let key = (src, dst);
                conn_times.entry(key).or_default().push(pkt.timestamp);
                conn_packets.entry(key).or_default().push(pkt.index);
            }
        }
    }

    let mut findings = Vec::new();
    for ((src, dst), mut times) in conn_times {
        if times.len() < thresholds.beaconing_min_connections { continue; }
        times.sort_by(|a, b| a.total_cmp(b));

        let intervals: Vec<f64> = times.windows(2).map(|w| w[1] - w[0]).collect();
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let cv = if mean > 0.0 { variance.sqrt() / mean } else { f64::INFINITY };

        // Low coefficient of variation suggests beaconing
        if cv < thresholds.beaconing_max_cv && mean > 1.0 && mean < 3600.0 {
            let packet_indices = conn_packets.get(&(src, dst)).cloned().unwrap_or_default();
            let first_seen = times[0];
            findings.push(ThreatFinding {
                severity: "High".to_string(),
                category: "Command & Control".to_string(),
                title: format!("Beaconing Behavior Detected: {} → {}", src, dst),
                description: format!(
                    "{} connected to {} {} times with an unusually regular interval of ~{:.1}s \
                    (jitter coefficient: {:.3}). This pattern is consistent with malware \
                    performing periodic C2 callbacks.",
                    src, dst, times.len(), mean, cv
                ),
                first_seen,
                packet_indices: packet_indices.into_iter().take(50).collect(),
            });
        }
    }
    findings
}

fn detect_traffic_spikes(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<ThreatFinding> {
    if view.packets.is_empty() { return Vec::new(); }

    let mut bytes_per_ip: HashMap<IpAddr, usize> = HashMap::new();
    let mut packets_per_ip: HashMap<IpAddr, Vec<usize>> = HashMap::new();
    let total_bytes: usize = view.packets.iter().map(|p| p.length).sum();

    for pkt in view.packets {
        if let Some(src) = pkt.src_ip {
            *bytes_per_ip.entry(src).or_insert(0) += pkt.length;
            packets_per_ip.entry(src).or_default().push(pkt.index);
        }
    }

    let _mean_bytes = if bytes_per_ip.is_empty() { 0.0 } else {
        total_bytes as f64 / bytes_per_ip.len() as f64
    };

    let mut findings = Vec::new();
    for (ip, bytes) in &bytes_per_ip {
        let pct = *bytes as f64 / total_bytes as f64;
        if pct > thresholds.traffic_spike_percentage && bytes_per_ip.len() > 2 {
            let packet_indices = packets_per_ip.get(ip).cloned().unwrap_or_default();
            let first_seen = packet_indices.iter()
                .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "Medium".to_string(),
                category: "Anomalous Traffic".to_string(),
                title: format!("Abnormal Traffic Volume from {}", ip),
                description: format!(
                    "{} is responsible for {:.1}% of all traffic in this capture ({} bytes), \
                    which is disproportionate relative to the baseline. This may indicate \
                    data exfiltration, DDoS participation, or a misconfigured service.",
                    ip, pct * 100.0, bytes
                ),
                first_seen,
                packet_indices: packet_indices.into_iter().take(50).collect(),
            });
        }
    }
    findings
}

fn detect_cleartext_credentials(view: &IndexedView) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    // HTTP Basic Auth — iterate the HTTP bucket only.
    for &i in &view.http {
        let pkt = &view.packets[i];
        let Some(app) = &pkt.layers.application else { continue };
        let Some(headers) = app.data.get("headers") else { continue };
        let Some(auth) = headers.get("Authorization") else { continue };
        if auth.as_str().unwrap_or("").starts_with("Basic ") {
            findings.push(ThreatFinding {
                severity: "High".to_string(),
                category: "Credential Exposure".to_string(),
                title: format!("HTTP Basic Auth Credentials in Cleartext (Packet #{})", pkt.index),
                description: format!(
                    "Packet #{} contains an HTTP Basic Authorization header transmitting \
                    credentials in plaintext (base64-encoded). Anyone capturing this \
                    traffic can decode and replay these credentials.",
                    pkt.index
                ),
                first_seen: pkt.timestamp,
                packet_indices: vec![pkt.index],
            });
        }
    }

    // FTP cleartext check — first matching TCP packet.
    if let Some(pkt) = view.tcp.iter().map(|&i| &view.packets[i])
        .find(|p| matches!(p.src_port, Some(21)) || matches!(p.dst_port, Some(21)))
    {
        findings.push(ThreatFinding {
            severity: "High".to_string(),
            category: "Credential Exposure".to_string(),
            title: "FTP Session Detected (Cleartext Protocol)".to_string(),
            description: "FTP traffic was observed, which transmits credentials and data \
                in plaintext. Any FTP username and password exchanged in this capture \
                can be read directly from the packet stream."
                .to_string(),
            first_seen: pkt.timestamp,
            packet_indices: vec![pkt.index],
        });
    }

    findings.dedup_by(|a, b| a.title == b.title);
    findings
}

fn detect_icmp_ping_activity(view: &IndexedView) -> Vec<ThreatFinding> {
    let mut pairs: HashMap<(IpAddr, IpAddr), Vec<usize>> = HashMap::new();

    for &i in &view.icmp_echo_req {
        let pkt = &view.packets[i];
        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            pairs.entry((src, dst)).or_default().push(pkt.index);
        }
    }

    if pairs.is_empty() {
        return Vec::new();
    }

    let unique_sources: std::collections::HashSet<IpAddr> = pairs.keys().map(|(s, _)| *s).collect();
    let unique_targets: std::collections::HashSet<IpAddr> = pairs.keys().map(|(_, d)| *d).collect();
    let total_requests: usize = pairs.values().map(|v| v.len()).sum();
    let packet_indices: Vec<usize> = pairs.values().flatten().copied().take(50).collect();
    let first_seen = packet_indices.iter()
        .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
        .fold(f64::INFINITY, f64::min);

    vec![ThreatFinding {
        severity: "Info".to_string(),
        category: "Reconnaissance".to_string(),
        title: "ICMP Ping Activity Detected".to_string(),
        description: format!(
            "{} ICMP echo requests detected from {} source(s) to {} target(s). \
            Ping activity may indicate network discovery or host availability scanning.",
            total_requests, unique_sources.len(), unique_targets.len()
        ),
        first_seen,
        packet_indices,
    }]
}

fn detect_icmp_flood(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<ThreatFinding> {
    let mut src_counts: HashMap<IpAddr, Vec<usize>> = HashMap::new();

    for &i in &view.icmp_echo_req {
        let pkt = &view.packets[i];
        if let Some(src) = pkt.src_ip {
            src_counts.entry(src).or_default().push(pkt.index);
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &src_counts {
        if indices.len() > thresholds.icmp_flood_minimum {
            let first_seen = indices.iter()
                .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "High".to_string(),
                category: "DoS".to_string(),
                title: format!("ICMP Flood from {}", src),
                description: format!(
                    "{} sent {} ICMP echo requests, which exceeds the flood threshold of {}. \
                    This volume of ping traffic may indicate a denial-of-service attack or aggressive \
                    network scanning.",
                    src, indices.len(), thresholds.icmp_flood_minimum
                ),
                first_seen,
                packet_indices: indices.iter().copied().take(50).collect(),
            });
        }
    }
    findings
}

fn detect_large_icmp(view: &IndexedView) -> Vec<ThreatFinding> {
    let large: Vec<usize> = view.icmp.iter()
        .copied()
        .filter(|&i| view.packets[i].length > 1024)
        .collect();

    if large.is_empty() {
        return Vec::new();
    }

    let first_seen = large.iter()
        .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
        .fold(f64::INFINITY, f64::min);

    vec![ThreatFinding {
        severity: "Medium".to_string(),
        category: "Exfiltration".to_string(),
        title: "Oversized ICMP Packets Detected".to_string(),
        description: format!(
            "{} ICMP packet(s) exceeding 1024 bytes detected. Unusually large ICMP packets \
            can be used to exfiltrate data via covert channel or as part of a Ping of Death attack.",
            large.len()
        ),
        first_seen,
        packet_indices: large.into_iter().take(50).collect(),
    }]
}

fn detect_udp_flood(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<ThreatFinding> {
    let mut src_counts: HashMap<IpAddr, Vec<usize>> = HashMap::new();

    for &i in &view.udp {
        let pkt = &view.packets[i];
        if let Some(src) = pkt.src_ip {
            src_counts.entry(src).or_default().push(pkt.index);
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &src_counts {
        if indices.len() > thresholds.udp_flood_minimum {
            let first_seen = indices.iter()
                .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "Medium".to_string(),
                category: "DoS".to_string(),
                title: format!("UDP Flood from {}", src),
                description: format!(
                    "{} sent {} UDP packets, exceeding the flood threshold of {}. \
                    High-rate UDP traffic from a single source is a common indicator of \
                    a UDP-based denial-of-service attack.",
                    src, indices.len(), thresholds.udp_flood_minimum
                ),
                first_seen,
                packet_indices: indices.iter().copied().take(50).collect(),
            });
        }
    }
    findings
}

fn detect_suspicious_ports(view: &IndexedView) -> Vec<ThreatFinding> {
    let suspicious: &[(u16, &str, &str, &str)] = &[
        (4444,  "Critical", "Malware",           "Metasploit default handler"),
        (31337, "Critical", "Malware",            "Back Orifice / elite hacking"),
        (12345, "Critical", "Malware",            "NetBus trojan"),
        (6666,  "High",     "Command & Control",  "IRC (common botnet C2)"),
        (6667,  "High",     "Command & Control",  "IRC (common botnet C2)"),
        (1337,  "High",     "Malware",            "Common backdoor port"),
    ];

    // Single pass: bucket all matching packets by port.
    let suspicious_set: std::collections::HashSet<u16> =
        suspicious.iter().map(|(p, _, _, _)| *p).collect();
    let mut matched_by_port: HashMap<u16, Vec<usize>> = HashMap::new();
    for pkt in view.packets {
        for port in [pkt.dst_port, pkt.src_port].into_iter().flatten() {
            if suspicious_set.contains(&port) {
                matched_by_port.entry(port).or_default().push(pkt.index);
                break;
            }
        }
    }

    let mut findings = Vec::new();
    for &(port, severity, category, label) in suspicious {
        let matched = match matched_by_port.remove(&port) {
            Some(m) if !m.is_empty() => m,
            _ => continue,
        };
        let first_seen = matched.iter()
            .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
            .fold(f64::INFINITY, f64::min);

        findings.push(ThreatFinding {
            severity: severity.to_string(),
            category: category.to_string(),
            title: format!("Suspicious Port {} Traffic ({})", port, label),
            description: format!(
                "{} packet(s) detected on port {} ({}) — a port historically associated with \
                malware, remote access trojans, or command-and-control infrastructure. \
                Investigate the endpoints involved.",
                matched.len(), port, label
            ),
            first_seen,
            packet_indices: matched.into_iter().take(50).collect(),
        });
    }
    findings
}

fn detect_telnet(view: &IndexedView) -> Vec<ThreatFinding> {
    let matched: Vec<usize> = view.packets.iter()
        .filter(|p| p.dst_port == Some(23) || p.src_port == Some(23))
        .map(|p| p.index)
        .collect();

    if matched.is_empty() {
        return Vec::new();
    }

    let first_seen = matched.iter()
        .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
        .fold(f64::INFINITY, f64::min);

    vec![ThreatFinding {
        severity: "High".to_string(),
        category: "Cleartext Protocol".to_string(),
        title: "Telnet Traffic Detected (Port 23)".to_string(),
        description: format!(
            "{} packet(s) observed on Telnet port 23. Telnet transmits all data including \
            credentials in plaintext, making it trivially interceptable. \
            Modern environments should use SSH instead.",
            matched.len()
        ),
        first_seen,
        packet_indices: matched.into_iter().take(50).collect(),
    }]
}

fn detect_syn_flood(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<ThreatFinding> {
    let mut syn_counts: HashMap<IpAddr, Vec<usize>> = HashMap::new();
    let mut synack_received: HashMap<IpAddr, usize> = HashMap::new();

    for &i in &view.tcp_syn {
        let pkt = &view.packets[i];
        if let Some(src) = pkt.src_ip {
            syn_counts.entry(src).or_default().push(pkt.index);
        }
    }
    for &i in &view.tcp_synack {
        let pkt = &view.packets[i];
        if let Some(dst) = pkt.dst_ip {
            *synack_received.entry(dst).or_insert(0) += 1;
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &syn_counts {
        if indices.len() <= thresholds.syn_flood_minimum { continue; }
        let responses = synack_received.get(src).copied().unwrap_or(0);
        // Flood if SYNs >> SYN-ACKs (handshakes rarely completed)
        if responses < indices.len() / 10 {
            let first_seen = indices.iter()
                .filter_map(|&i| view.packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "Critical".to_string(),
                category: "DoS".to_string(),
                title: format!("SYN Flood from {}", src),
                description: format!(
                    "{} sent {} TCP SYN packets with only {} SYN-ACK responses received, \
                    indicating handshakes are not completing. This is a strong indicator of \
                    a SYN flood denial-of-service attack designed to exhaust server connection tables.",
                    src, indices.len(), responses
                ),
                first_seen,
                packet_indices: indices.iter().copied().take(50).collect(),
            });
        }
    }
    findings
}
