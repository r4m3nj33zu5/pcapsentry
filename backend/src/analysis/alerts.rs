use std::collections::HashMap;
use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use crate::parser::PacketMeta;
use crate::analysis::flows::ConnectionFlow;
use crate::analysis::dns_http::DnsEntry;
use crate::analysis::indexed::IndexedView;
use crate::analysis::utils::{is_private_ip, is_private_addr, shannon_entropy};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AlertFinding {
    pub id: String,
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub first_seen: f64,
    pub last_seen: f64,
    pub packet_indices: Vec<usize>,
    pub affected_hosts: Vec<String>,
    pub mitre_tactic: String,
    pub mitre_technique: String,
    pub mitre_technique_name: String,
    pub mitre_url: String,
    pub confidence: f32,
    pub ioc_refs: Vec<String>,
}

impl AlertFinding {
    fn new(
        severity: &str,
        category: &str,
        title: String,
        description: String,
        first_seen: f64,
        last_seen: f64,
        packet_indices: Vec<usize>,
        affected_hosts: Vec<String>,
        tactic: &str,
        technique: &str,
        technique_name: &str,
        confidence: f32,
    ) -> Self {
        let technique_id = technique.to_string();
        AlertFinding {
            id: Uuid::new_v4().to_string(),
            severity: severity.to_string(),
            category: category.to_string(),
            title,
            description,
            first_seen,
            last_seen,
            packet_indices,
            affected_hosts,
            mitre_tactic: tactic.to_string(),
            mitre_technique: technique_id.clone(),
            mitre_technique_name: technique_name.to_string(),
            mitre_url: format!("https://attack.mitre.org/techniques/{}/", technique_id.replace('.', "/")),
            confidence,
            ioc_refs: Vec::new(),
        }
    }
}

pub fn detect(view: &IndexedView, flows: &[ConnectionFlow], dns_log: &[DnsEntry], thresholds: &crate::config::AlertThresholds, whitelist: &crate::config::Whitelist) -> Vec<AlertFinding> {
    // Detection runs against the shared IndexedView — each detector iterates
    // only the protocol bucket it cares about (TCP SYNs, ICMP echo requests,
    // etc.) instead of re-scanning the entire packet vec. Whitelisting is
    // applied *after* detection so we never have to clone the packet slice.
    let mut findings = Vec::new();

    // Ported from threats.rs (with MITRE metadata)
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

    // New rules
    findings.extend(detect_dns_tunneling(view, dns_log, thresholds));
    findings.extend(detect_smb_lateral(view));
    findings.extend(detect_rdp_brute(view));
    findings.extend(detect_http_password_in_post(view));
    findings.extend(detect_long_lived_external_flow(flows, whitelist));
    findings.extend(detect_high_entropy_dns(dns_log, thresholds));
    findings.extend(detect_nonstandard_tls_port(view));
    findings.extend(detect_ldap_enumeration(view));

    if !whitelist.ips.is_empty() {
        let wl: std::collections::HashSet<&str> = whitelist.ips.iter().map(|s| s.as_str()).collect();
        findings.retain(|f| !f.affected_hosts.iter().any(|h| wl.contains(h.as_str())));
    }

    let sev_order = |s: &str| match s {
        "Critical" => 0,
        "High" => 1,
        "Medium" => 2,
        _ => 3,
    };
    findings.sort_by_key(|f| sev_order(&f.severity));
    findings
}

fn first_ts(packet_indices: &[usize], packets: &[PacketMeta]) -> (f64, f64) {
    let first = packet_indices.iter()
        .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
        .fold(f64::INFINITY, f64::min);
    let last = packet_indices.iter()
        .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
        .fold(f64::NEG_INFINITY, f64::max);
    (if first.is_finite() { first } else { 0.0 }, if last.is_finite() { last } else { 0.0 })
}

// ─── Ported Detectors ────────────────────────────────────────────────────────

fn detect_port_scan(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
    let mut syn_map: HashMap<IpAddr, HashMap<IpAddr, Vec<(u16, usize)>>> = HashMap::new();
    let mut synack_map: HashMap<IpAddr, usize> = HashMap::new();
    let mut span_map: HashMap<IpAddr, (f64, f64)> = HashMap::new();

    for &i in &view.tcp_syn {
        let pkt = &view.packets[i];
        let (src, dst) = match (pkt.src_ip, pkt.dst_ip) {
            (Some(s), Some(d)) => (s, d),
            _ => continue,
        };
        let dst_port = pkt.dst_port.unwrap_or(0);
        syn_map.entry(src).or_default().entry(dst).or_default().push((dst_port, pkt.index));
        let span = span_map.entry(src).or_insert((f64::INFINITY, f64::NEG_INFINITY));
        if pkt.timestamp < span.0 { span.0 = pkt.timestamp; }
        if pkt.timestamp > span.1 { span.1 = pkt.timestamp; }
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
        if total_ports >= thresholds.port_scan_syn_minimum && synacks < (total_ports as f64 * thresholds.port_scan_response_ratio) as usize {
            let packet_indices: Vec<usize> = dst_map.values().flatten().map(|(_, i)| *i).take(100).collect();
            let (fs, ls) = span_map.get(src).copied().unwrap_or((0.0, 0.0));
            let fs = if fs.is_finite() { fs } else { 0.0 };
            let ls = if ls.is_finite() { ls } else { 0.0 };
            let severity = if total_ports > 100 { "Critical" } else { "High" };
            findings.push(AlertFinding::new(
                severity, "Reconnaissance",
                format!("Port Scan Detected from {}", src),
                format!("{} sent SYN packets to {} ports across {} destination(s) with only {} responses.",
                    src, total_ports, distinct_dsts, synacks),
                fs, ls, packet_indices,
                vec![src.to_string()],
                "Discovery", "T1046", "Network Service Discovery", 0.85,
            ));
        }
    }
    findings
}

fn detect_arp_spoofing(view: &IndexedView) -> Vec<AlertFinding> {
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
            let (fs, ls) = first_ts(&packet_indices, view.packets);
            findings.push(AlertFinding::new(
                "Critical", "Network Attack",
                format!("ARP Spoofing Detected for {}", ip),
                format!("IP {} appeared with {} MACs in ARP replies: {}. Possible ARP cache poisoning (MITM).",
                    ip, macs.len(), macs.iter().cloned().collect::<Vec<_>>().join(", ")),
                fs, ls, packet_indices.into_iter().take(50).collect(),
                vec![ip.clone()],
                "Credential Access", "T1557.002", "ARP Cache Poisoning", 0.95,
            ));
        }
    }
    findings
}

fn detect_icmp_sweep(view: &IndexedView) -> Vec<AlertFinding> {
    let mut icmp_sources: HashMap<IpAddr, Vec<(IpAddr, usize)>> = HashMap::new();
    for &i in &view.icmp {
        let pkt = &view.packets[i];
        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            icmp_sources.entry(src).or_default().push((dst, pkt.index));
        }
    }

    let mut findings = Vec::new();
    for (src, targets) in &icmp_sources {
        let unique: std::collections::HashSet<&IpAddr> = targets.iter().map(|(ip, _)| ip).collect();
        if unique.len() >= 10 {
            let packet_indices: Vec<usize> = targets.iter().map(|(_, i)| *i).take(50).collect();
            let (fs, ls) = first_ts(&packet_indices, view.packets);
            findings.push(AlertFinding::new(
                "Medium", "Reconnaissance",
                format!("ICMP Sweep from {}", src),
                format!("{} sent ICMP echo requests to {} unique hosts — ping sweep.", src, unique.len()),
                fs, ls, packet_indices, vec![src.to_string()],
                "Discovery", "T1018", "Remote System Discovery", 0.75,
            ));
        }
    }
    findings
}

fn detect_icmp_ping_activity(view: &IndexedView) -> Vec<AlertFinding> {
    let mut pairs: HashMap<(IpAddr, IpAddr), Vec<usize>> = HashMap::new();
    for &i in &view.icmp_echo_req {
        let pkt = &view.packets[i];
        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            pairs.entry((src, dst)).or_default().push(pkt.index);
        }
    }
    if pairs.is_empty() { return Vec::new(); }

    let total: usize = pairs.values().map(|v| v.len()).sum();
    let packet_indices: Vec<usize> = pairs.values().flatten().copied().take(50).collect();
    let (fs, ls) = first_ts(&packet_indices, view.packets);
    let sources: std::collections::HashSet<IpAddr> = pairs.keys().map(|(s, _)| *s).collect();
    let targets: std::collections::HashSet<IpAddr> = pairs.keys().map(|(_, d)| *d).collect();

    vec![AlertFinding::new(
        "Info", "Reconnaissance",
        "ICMP Ping Activity Detected".to_string(),
        format!("{} ICMP echo requests from {} source(s) to {} target(s).", total, sources.len(), targets.len()),
        fs, ls, packet_indices, sources.iter().map(|s| s.to_string()).collect(),
        "Discovery", "T1018", "Remote System Discovery", 0.5,
    )]
}

fn detect_icmp_flood(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
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
            let (fs, ls) = first_ts(indices, view.packets);
            findings.push(AlertFinding::new(
                "High", "DoS",
                format!("ICMP Flood from {}", src),
                format!("{} sent {} ICMP echo requests (threshold: {}). Possible DoS.", src, indices.len(), thresholds.icmp_flood_minimum),
                fs, ls, indices.iter().copied().take(50).collect(), vec![src.to_string()],
                "Impact", "T1498.002", "Network Flood", 0.8,
            ));
        }
    }
    findings
}

fn detect_large_icmp(view: &IndexedView) -> Vec<AlertFinding> {
    let large: Vec<usize> = view.icmp.iter()
        .copied()
        .filter(|&i| view.packets[i].length > 1024)
        .collect();
    if large.is_empty() { return Vec::new(); }
    let (fs, ls) = first_ts(&large, view.packets);
    vec![AlertFinding::new(
        "Medium", "Exfiltration",
        "Oversized ICMP Packets Detected".to_string(),
        format!("{} ICMP packet(s) >1024 bytes. May indicate covert channel or Ping of Death.", large.len()),
        fs, ls, large.into_iter().take(50).collect(), Vec::new(),
        "Exfiltration", "T1048.003", "Exfiltration Over Alternative Protocol", 0.6,
    )]
}

fn detect_udp_flood(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
    let mut src_counts: HashMap<IpAddr, Vec<usize>> = HashMap::new();
    for &i in &view.udp {
        let pkt = &view.packets[i];
        // UDP/443 is QUIC: a single HTTPS session generates thousands of
        // packets in either direction, so counting it guarantees false
        // positives on any capture with ordinary web browsing.
        if pkt.src_port == Some(443) || pkt.dst_port == Some(443) {
            continue;
        }
        if let Some(src) = pkt.src_ip {
            src_counts.entry(src).or_default().push(pkt.index);
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &src_counts {
        if indices.len() > thresholds.udp_flood_minimum {
            let (fs, ls) = first_ts(indices, view.packets);
            findings.push(AlertFinding::new(
                "Medium", "DoS",
                format!("UDP Flood from {}", src),
                format!("{} sent {} UDP packets (threshold: {}). Possible UDP flood DoS.", src, indices.len(), thresholds.udp_flood_minimum),
                fs, ls, indices.iter().copied().take(50).collect(), vec![src.to_string()],
                "Impact", "T1498.002", "Network Flood", 0.75,
            ));
        }
    }
    findings
}

fn detect_suspicious_ports(view: &IndexedView) -> Vec<AlertFinding> {
    let suspicious: &[(u16, &str, &str, &str)] = &[
        (4444,  "Critical", "Malware",          "Metasploit default handler"),
        (31337, "Critical", "Malware",           "Back Orifice / elite hacking"),
        (12345, "Critical", "Malware",           "NetBus trojan"),
        (6666,  "High",     "Command & Control", "IRC botnet C2"),
        (6667,  "High",     "Command & Control", "IRC botnet C2"),
        (1337,  "High",     "Malware",           "Common backdoor port"),
    ];

    // Single pass over all packets bucketing matches by port — replaces the
    // previous 6 independent O(N) scans (one per port).
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
        let (fs, ls) = first_ts(&matched, view.packets);
        findings.push(AlertFinding::new(
            severity, category,
            format!("Suspicious Port {} Traffic ({})", port, label),
            format!("{} packet(s) on port {} ({}) — historically associated with malware/C2.", matched.len(), port, label),
            fs, ls, matched.into_iter().take(50).collect(), Vec::new(),
            "Command and Control", "T1571", "Non-Standard Port", 0.85,
        ));
    }
    findings
}

fn detect_telnet(view: &IndexedView) -> Vec<AlertFinding> {
    let matched: Vec<usize> = view.packets.iter()
        .filter(|p| p.dst_port == Some(23) || p.src_port == Some(23))
        .map(|p| p.index).collect();
    if matched.is_empty() { return Vec::new(); }
    let (fs, ls) = first_ts(&matched, view.packets);
    vec![AlertFinding::new(
        "High", "Cleartext Protocol",
        "Telnet Traffic Detected (Port 23)".to_string(),
        format!("{} packet(s) on Telnet port 23. Transmits credentials in plaintext.", matched.len()),
        fs, ls, matched.into_iter().take(50).collect(), Vec::new(),
        "Lateral Movement", "T1021.004", "Remote Services: SSH", 0.9,
    )]
}

fn detect_syn_flood(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
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
        if responses < indices.len() / 10 {
            let (fs, ls) = first_ts(indices, view.packets);
            findings.push(AlertFinding::new(
                "Critical", "DoS",
                format!("SYN Flood from {}", src),
                format!("{} sent {} TCP SYNs with only {} SYN-ACKs. Possible SYN flood DoS.", src, indices.len(), responses),
                fs, ls, indices.iter().copied().take(50).collect(), vec![src.to_string()],
                "Impact", "T1498.001", "Direct Network Flood", 0.9,
            ));
        }
    }
    findings
}

fn detect_xmas_null_fin(view: &IndexedView) -> Vec<AlertFinding> {
    let mut findings = Vec::new();
    if !view.tcp_xmas.is_empty() {
        let indices: Vec<usize> = view.tcp_xmas.iter().copied().take(50).collect();
        let (fs, ls) = first_ts(&indices, view.packets);
        findings.push(AlertFinding::new(
            "High", "Reconnaissance",
            "Xmas Scan Detected".to_string(),
            format!("{} Xmas scan packets (FIN+PSH+URG). Used to probe open ports.", view.tcp_xmas.len()),
            fs, ls, indices, Vec::new(),
            "Discovery", "T1046", "Network Service Discovery", 0.9,
        ));
    }
    if view.tcp_null.len() >= 5 {
        let indices: Vec<usize> = view.tcp_null.iter().copied().take(50).collect();
        let (fs, ls) = first_ts(&indices, view.packets);
        findings.push(AlertFinding::new(
            "High", "Reconnaissance",
            "NULL Scan Detected".to_string(),
            format!("{} NULL scan packets (no TCP flags). Evades stateless firewalls.", view.tcp_null.len()),
            fs, ls, indices, Vec::new(),
            "Discovery", "T1046", "Network Service Discovery", 0.85,
        ));
    }
    if view.tcp_fin_only.len() >= 5 {
        let indices: Vec<usize> = view.tcp_fin_only.iter().copied().take(50).collect();
        let (fs, ls) = first_ts(&indices, view.packets);
        findings.push(AlertFinding::new(
            "Medium", "Reconnaissance",
            "FIN Scan Detected".to_string(),
            format!("{} isolated FIN packets without SYN/ACK. FIN scan technique.", view.tcp_fin_only.len()),
            fs, ls, indices, Vec::new(),
            "Discovery", "T1046", "Network Service Discovery", 0.75,
        ));
    }
    findings
}

fn detect_beaconing(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
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
        if cv < thresholds.beaconing_max_cv && mean > 1.0 && mean < 3600.0 {
            let packet_indices = conn_packets.get(&(src, dst)).cloned().unwrap_or_default();
            let (fs, ls) = first_ts(&packet_indices, view.packets);
            findings.push(AlertFinding::new(
                "High", "Command & Control",
                format!("Beaconing Behavior: {} → {}", src, dst),
                format!("{} → {} connected {} times at ~{:.1}s intervals (jitter CV: {:.3}). Possible C2 callback.",
                    src, dst, times.len(), mean, cv),
                fs, ls, packet_indices.into_iter().take(50).collect(),
                vec![src.to_string(), dst.to_string()],
                "Command and Control", "T1071.001", "Application Layer Protocol: Web Protocols", 0.85,
            ));
        }
    }
    findings
}

fn detect_traffic_spikes(view: &IndexedView, thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
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

    let mut findings = Vec::new();
    for (ip, bytes) in &bytes_per_ip {
        let pct = *bytes as f64 / total_bytes as f64;
        if pct > thresholds.traffic_spike_percentage && bytes_per_ip.len() > 2 {
            let packet_indices = packets_per_ip.get(ip).cloned().unwrap_or_default();
            let (fs, ls) = first_ts(&packet_indices, view.packets);
            findings.push(AlertFinding::new(
                "Medium", "Anomalous Traffic",
                format!("Abnormal Traffic Volume from {}", ip),
                format!("{} is responsible for {:.1}% of all traffic ({} bytes). Possible exfiltration or DoS.",
                    ip, pct * 100.0, bytes),
                fs, ls, packet_indices.into_iter().take(50).collect(), vec![ip.to_string()],
                "Exfiltration", "T1030", "Data Transfer Size Limits", 0.6,
            ));
        }
    }
    findings
}

fn detect_cleartext_credentials(view: &IndexedView) -> Vec<AlertFinding> {
    let mut findings = Vec::new();

    // HTTP Basic Auth check — only iterate the http bucket.
    for &i in &view.http {
        let pkt = &view.packets[i];
        let Some(app) = &pkt.layers.application else { continue };
        let Some(headers) = app.data.get("headers") else { continue };
        let Some(auth) = headers.get("Authorization") else { continue };
        if auth.as_str().unwrap_or("").starts_with("Basic ") {
            findings.push(AlertFinding::new(
                "High", "Credential Exposure",
                format!("HTTP Basic Auth Credentials in Cleartext (Packet #{})", pkt.index),
                format!("Packet #{} contains HTTP Basic Auth header transmitting credentials in plaintext.", pkt.index),
                pkt.timestamp, pkt.timestamp, vec![pkt.index],
                pkt.src_ip.map(|ip| vec![ip.to_string()]).unwrap_or_default(),
                "Credential Access", "T1552.001", "Credentials In Files", 0.95,
            ));
        }
    }
    // FTP cleartext check — fire on the first matching TCP packet.
    if let Some(pkt) = view.tcp.iter().map(|&i| &view.packets[i])
        .find(|p| matches!(p.src_port, Some(21)) || matches!(p.dst_port, Some(21)))
    {
        findings.push(AlertFinding::new(
            "High", "Credential Exposure",
            "FTP Session Detected (Cleartext Protocol)".to_string(),
            "FTP traffic observed — transmits credentials in plaintext.".to_string(),
            pkt.timestamp, pkt.timestamp, vec![pkt.index], Vec::new(),
            "Credential Access", "T1552.001", "Credentials In Files", 0.9,
        ));
    }
    findings.dedup_by(|a, b| a.title == b.title);
    findings
}

// ─── New Detection Rules ─────────────────────────────────────────────────────

fn detect_dns_tunneling(view: &IndexedView, dns_log: &[DnsEntry], thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
    let mut apex_counts: HashMap<String, usize> = HashMap::new();
    let mut suspicious_packets: Vec<usize> = Vec::new();
    let mut sources: std::collections::HashSet<String> = std::collections::HashSet::new();

    for entry in dns_log {
        if entry.is_response { continue; }
        let name = &entry.name;
        let labels: Vec<&str> = name.split('.').collect();
        let depth = labels.len();
        let longest_label = labels.iter().map(|l| l.len()).max().unwrap_or(0);
        let entropy = shannon_entropy(name);
        let apex = if labels.len() >= 2 {
            labels[labels.len()-2..].join(".")
        } else {
            name.clone()
        };

        let is_suspicious = longest_label > thresholds.dns_tunnel_label_length || depth > 5 || (entropy > thresholds.dns_tunnel_entropy && longest_label > 12);
        if is_suspicious {
            suspicious_packets.push(entry.packet_index);
            sources.insert(entry.src_ip.clone());
            *apex_counts.entry(apex).or_insert(0) += 1;
        }
    }

    if suspicious_packets.len() >= 3 {
        let (fs, ls) = first_ts(&suspicious_packets, view.packets);
        vec![AlertFinding::new(
            "High", "Exfiltration",
            "DNS Tunneling Indicators Detected".to_string(),
            format!("{} DNS queries with long/deep/high-entropy labels targeting {} apex domain(s). Possible DNS tunneling.",
                suspicious_packets.len(), apex_counts.len()),
            fs, ls, suspicious_packets.into_iter().take(50).collect(),
            sources.into_iter().collect(),
            "Exfiltration", "T1048.003", "Exfiltration Over Alternative Protocol: DNS", 0.75,
        )]
    } else {
        Vec::new()
    }
}

fn detect_smb_lateral(view: &IndexedView) -> Vec<AlertFinding> {
    let smb_ports = [445u16, 139, 137];
    let mut lateral_packets: Vec<usize> = Vec::new();
    let mut pairs: std::collections::HashSet<(IpAddr, IpAddr)> = std::collections::HashSet::new();

    for pkt in view.packets {
        let dp = pkt.dst_port.unwrap_or(0);
        if !smb_ports.contains(&dp) { continue; }
        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            if is_private_addr(&src) && is_private_addr(&dst) {
                // Check different /24 networks. Only meaningful for IPv4.
                let crosses_subnet = match (src, dst) {
                    (IpAddr::V4(s), IpAddr::V4(d)) => s.octets()[2] != d.octets()[2],
                    _ => false,
                };
                if crosses_subnet {
                    lateral_packets.push(pkt.index);
                    pairs.insert((src, dst));
                }
            }
        }
    }

    if lateral_packets.len() >= 5 {
        let (fs, ls) = first_ts(&lateral_packets, view.packets);
        vec![AlertFinding::new(
            "High", "Lateral Movement",
            "SMB Lateral Movement Detected".to_string(),
            format!("{} SMB packets (ports 445/139/137) crossing RFC1918 subnets across {} pairs. Possible lateral movement.",
                lateral_packets.len(), pairs.len()),
            fs, ls, lateral_packets.into_iter().take(50).collect(),
            pairs.into_iter().flat_map(|(s, d)| vec![s.to_string(), d.to_string()]).collect(),
            "Lateral Movement", "T1021.002", "Remote Services: SMB/Windows Admin Shares", 0.8,
        )]
    } else {
        Vec::new()
    }
}

fn detect_rdp_brute(view: &IndexedView) -> Vec<AlertFinding> {
    let mut syn_per_src: HashMap<IpAddr, Vec<usize>> = HashMap::new();
    for &i in &view.tcp_syn {
        let pkt = &view.packets[i];
        if pkt.dst_port != Some(3389) { continue; }
        if let Some(src) = pkt.src_ip {
            syn_per_src.entry(src).or_default().push(pkt.index);
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &syn_per_src {
        if indices.len() >= 10 {
            let (fs, ls) = first_ts(indices, view.packets);
            findings.push(AlertFinding::new(
                "High", "Credential Access",
                format!("RDP Brute Force from {}", src),
                format!("{} SYN packets to RDP port 3389 from {}. Possible brute force attempt.", indices.len(), src),
                fs, ls, indices.iter().copied().take(50).collect(), vec![src.to_string()],
                "Credential Access", "T1110", "Brute Force", 0.8,
            ));
        }
    }
    findings
}

fn detect_http_password_in_post(view: &IndexedView) -> Vec<AlertFinding> {
    let keywords = ["password=", "passwd=", "pwd=", "pass="];
    let mut findings = Vec::new();

    for &i in &view.http {
        let pkt = &view.packets[i];
        let Some(app) = &pkt.layers.application else { continue };
        let method = app.data.get("method").and_then(|v| v.as_str()).unwrap_or("");
        if method != "POST" { continue; }
        let preview_hex = &pkt.app_payload_preview;
        // Guard against odd-length hex strings (would panic on slice).
        let hex_len = preview_hex.len() & !1;
        let Ok(bytes) = (0..hex_len)
            .step_by(2)
            .map(|j| u8::from_str_radix(&preview_hex[j..j+2], 16))
            .collect::<Result<Vec<u8>, _>>()
        else { continue };
        let Ok(text) = std::str::from_utf8(&bytes) else { continue };
        let lower = text.to_lowercase();
        for kw in keywords {
            if lower.contains(kw) {
                findings.push(AlertFinding::new(
                    "High", "Credential Exposure",
                    format!("HTTP POST Contains Password Field (Packet #{})", pkt.index),
                    format!("POST body contains '{}' keyword — credentials transmitted in cleartext HTTP.", kw),
                    pkt.timestamp, pkt.timestamp, vec![pkt.index],
                    pkt.src_ip.map(|ip| vec![ip.to_string()]).unwrap_or_default(),
                    "Credential Access", "T1552.001", "Credentials In Files", 0.85,
                ));
                break;
            }
        }
    }
    findings
}

fn detect_long_lived_external_flow(flows: &[ConnectionFlow], whitelist: &crate::config::Whitelist) -> Vec<AlertFinding> {
    let threshold = 30.0 * 60.0; // 30 minutes
    let mut findings = Vec::new();

    for flow in flows {
        let duration = flow.last_seen - flow.first_seen;
        let wl_ip = whitelist.ips.iter().any(|ip| ip == &flow.src_ip || ip == &flow.dst_ip);
        if duration >= threshold && !is_private_ip(&flow.dst_ip) && !wl_ip {
            findings.push(AlertFinding {
                id: Uuid::new_v4().to_string(),
                severity: "Medium".to_string(),
                category: "Command & Control".to_string(),
                title: format!("Long-Lived External Flow: {} → {}:{}", flow.src_ip, flow.dst_ip, flow.dst_port.unwrap_or(0)),
                description: format!("Flow from {} to {} lasted {:.1} minutes. Persistent external connections may indicate C2 or data exfiltration.",
                    flow.src_ip, flow.dst_ip, duration / 60.0),
                first_seen: flow.first_seen,
                last_seen: flow.last_seen,
                packet_indices: Vec::new(),
                affected_hosts: vec![flow.src_ip.clone(), flow.dst_ip.clone()],
                mitre_tactic: "Command and Control".to_string(),
                mitre_technique: "T1102".to_string(),
                mitre_technique_name: "Web Service".to_string(),
                mitre_url: "https://attack.mitre.org/techniques/T1102/".to_string(),
                confidence: 0.6,
                ioc_refs: Vec::new(),
            });
        }
    }
    findings
}

fn detect_high_entropy_dns(dns_log: &[DnsEntry], thresholds: &crate::config::AlertThresholds) -> Vec<AlertFinding> {
    let mut suspicious: Vec<usize> = Vec::new();
    let mut domains: Vec<String> = Vec::new();
    let mut first_seen = f64::INFINITY;
    let mut last_seen = f64::NEG_INFINITY;

    for entry in dns_log {
        if entry.is_response { continue; }
        let labels: Vec<&str> = entry.name.split('.').collect();
        for label in &labels {
            if label.len() > 12 && shannon_entropy(label) > thresholds.dns_tunnel_entropy {
                suspicious.push(entry.packet_index);
                domains.push(entry.name.clone());
                if entry.timestamp < first_seen { first_seen = entry.timestamp; }
                if entry.timestamp > last_seen { last_seen = entry.timestamp; }
                break;
            }
        }
    }

    if suspicious.len() >= 2 {
        vec![AlertFinding {
            id: Uuid::new_v4().to_string(),
            severity: "Medium".to_string(),
            category: "Command & Control".to_string(),
            title: "High-Entropy DNS Labels Detected".to_string(),
            description: format!("{} DNS queries with high-entropy labels (entropy >{:.1}, length >12). May indicate DGA or DNS-based C2.",
                suspicious.len(), thresholds.dns_tunnel_entropy),
            first_seen: if first_seen.is_finite() { first_seen } else { 0.0 },
            last_seen: if last_seen.is_finite() { last_seen } else { 0.0 },
            packet_indices: suspicious.into_iter().take(50).collect(),
            affected_hosts: Vec::new(),
            mitre_tactic: "Command and Control".to_string(),
            mitre_technique: "T1568".to_string(),
            mitre_technique_name: "Dynamic Resolution".to_string(),
            mitre_url: "https://attack.mitre.org/techniques/T1568/".to_string(),
            confidence: 0.7,
            ioc_refs: domains.into_iter().take(5).collect(),
        }]
    } else {
        Vec::new()
    }
}

fn detect_nonstandard_tls_port(view: &IndexedView) -> Vec<AlertFinding> {
    let standard_tls_ports = [443u16, 8443, 465, 993, 995, 8080, 4433];
    let mut suspicious: Vec<usize> = Vec::new();
    let mut ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
    let mut first_seen = f64::INFINITY;
    let mut last_seen = f64::NEG_INFINITY;

    for &i in &view.tls {
        let pkt = &view.packets[i];
        let dp = pkt.dst_port.unwrap_or(0);
        let sp = pkt.src_port.unwrap_or(0);
        if !standard_tls_ports.contains(&dp) && !standard_tls_ports.contains(&sp) {
            suspicious.push(pkt.index);
            ports.insert(dp);
            if pkt.timestamp < first_seen { first_seen = pkt.timestamp; }
            if pkt.timestamp > last_seen { last_seen = pkt.timestamp; }
        }
    }

    if !suspicious.is_empty() {
        let fs = if first_seen.is_finite() { first_seen } else { 0.0 };
        let ls = if last_seen.is_finite() { last_seen } else { 0.0 };
        vec![AlertFinding::new(
            "Medium", "Command & Control",
            format!("TLS on Non-Standard Port(s): {:?}", ports.iter().collect::<Vec<_>>()),
            format!("{} TLS ClientHello packets on non-standard ports {:?}. Possible encrypted C2.", suspicious.len(), ports),
            fs, ls, suspicious.into_iter().take(50).collect(), Vec::new(),
            "Command and Control", "T1573", "Encrypted Channel", 0.7,
        )]
    } else {
        Vec::new()
    }
}

fn detect_ldap_enumeration(view: &IndexedView) -> Vec<AlertFinding> {
    let ldap_ports = [389u16, 636, 3268, 3269];
    let mut src_counts: HashMap<IpAddr, Vec<usize>> = HashMap::new();

    for pkt in view.packets {
        let dp = pkt.dst_port.unwrap_or(0);
        if ldap_ports.contains(&dp) {
            if let Some(src) = pkt.src_ip {
                src_counts.entry(src).or_default().push(pkt.index);
            }
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &src_counts {
        if indices.len() >= 20 {
            let (fs, ls) = first_ts(indices, view.packets);
            findings.push(AlertFinding::new(
                "Medium", "Reconnaissance",
                format!("LDAP Enumeration from {}", src),
                format!("{} LDAP packets (port 389/636) from {}. High-volume LDAP may indicate directory enumeration.",
                    indices.len(), src),
                fs, ls, indices.iter().copied().take(50).collect(), vec![src.to_string()],
                "Discovery", "T1018", "Remote System Discovery", 0.7,
            ));
        }
    }
    findings
}
