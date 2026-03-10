use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatFinding {
    pub severity: String,
    pub category: String,
    pub title: String,
    pub description: String,
    pub first_seen: f64,
    pub packet_indices: Vec<usize>,
}

pub fn detect(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    findings.extend(detect_port_scan(packets));
    findings.extend(detect_arp_spoofing(packets));
    findings.extend(detect_icmp_sweep(packets));
    findings.extend(detect_icmp_ping_activity(packets));
    findings.extend(detect_icmp_flood(packets));
    findings.extend(detect_large_icmp(packets));
    findings.extend(detect_udp_flood(packets));
    findings.extend(detect_suspicious_ports(packets));
    findings.extend(detect_telnet(packets));
    findings.extend(detect_syn_flood(packets));
    findings.extend(detect_xmas_null_fin(packets));
    findings.extend(detect_beaconing(packets));
    findings.extend(detect_traffic_spikes(packets));
    findings.extend(detect_cleartext_credentials(packets));

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

fn detect_port_scan(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    // Track SYN packets per source: dst_ip -> set of ports
    // Finding: one src sends SYN to many distinct dst_ports with few SYN-ACK responses
    let mut syn_map: HashMap<String, HashMap<String, Vec<(u16, usize)>>> = HashMap::new();
    let mut synack_map: HashMap<String, usize> = HashMap::new();

    for pkt in packets {
        if pkt.protocol != "TCP" { continue; }
        if let Some(layers) = &pkt.layers.transport {
            if let Some(flags) = &layers.flags {
                let src = pkt.src_ip.clone().unwrap_or_default();
                let dst = pkt.dst_ip.clone().unwrap_or_default();
                let dst_port = pkt.dst_port.unwrap_or(0);

                if flags.contains("SYN") && !flags.contains("ACK") {
                    syn_map
                        .entry(src.clone())
                        .or_default()
                        .entry(dst.clone())
                        .or_default()
                        .push((dst_port, pkt.index));
                }
                if flags.contains("SYN") && flags.contains("ACK") {
                    *synack_map.entry(dst.clone()).or_insert(0) += 1;
                }
            }
        }
    }

    let mut findings = Vec::new();
    for (src, dst_map) in &syn_map {
        let total_ports: usize = dst_map.values().map(|v| v.len()).sum();
        let distinct_dsts = dst_map.len();
        let synacks = synack_map.get(src).copied().unwrap_or(0);

        // Port scan: many SYNs, few SYN-ACKs back
        if total_ports >= 20 && synacks < total_ports / 5 {
            let packet_indices: Vec<usize> = dst_map.values().flatten().map(|(_, i)| *i).take(100).collect();
            let first_seen = packet_indices.iter()
                .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

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

fn detect_icmp_sweep(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut icmp_sources: HashMap<String, Vec<(String, usize)>> = HashMap::new();

    for pkt in packets {
        if pkt.protocol == "ICMP" {
            if let (Some(src), Some(dst)) = (&pkt.src_ip, &pkt.dst_ip) {
                icmp_sources.entry(src.clone()).or_default().push((dst.clone(), pkt.index));
            }
        }
    }

    let mut findings = Vec::new();
    for (src, targets) in &icmp_sources {
        let unique_targets: std::collections::HashSet<&String> = targets.iter().map(|(ip, _)| ip).collect();
        if unique_targets.len() >= 10 {
            let packet_indices: Vec<usize> = targets.iter().map(|(_, i)| *i).take(50).collect();
            let first_seen = packet_indices.iter()
                .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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

fn detect_xmas_null_fin(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut xmas_packets: Vec<(String, usize, f64)> = Vec::new();
    let mut null_packets: Vec<(String, usize, f64)> = Vec::new();
    let mut fin_packets: Vec<(String, usize, f64)> = Vec::new();

    for pkt in packets {
        if pkt.protocol != "TCP" { continue; }
        if let Some(layers) = &pkt.layers.transport {
            if let Some(flags) = &layers.flags {
                let src = pkt.src_ip.clone().unwrap_or_default();
                if flags.contains("FIN") && flags.contains("PSH") && flags.contains("URG") {
                    xmas_packets.push((src, pkt.index, pkt.timestamp));
                } else if flags == "NONE" {
                    null_packets.push((src, pkt.index, pkt.timestamp));
                } else if flags == "FIN" {
                    fin_packets.push((src, pkt.index, pkt.timestamp));
                }
            }
        }
    }

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

fn detect_arp_spoofing(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    // Track IP -> set of MACs seen in ARP replies
    let mut ip_mac_map: HashMap<String, std::collections::HashSet<String>> = HashMap::new();
    let mut ip_mac_packets: HashMap<String, Vec<usize>> = HashMap::new();

    for pkt in packets {
        if pkt.protocol != "ARP" { continue; }
        if let Some(arp) = &pkt.layers.arp {
            if arp.operation == "Reply" {
                ip_mac_map
                    .entry(arp.sender_ip.clone())
                    .or_default()
                    .insert(arp.sender_mac.clone());
                ip_mac_packets.entry(arp.sender_ip.clone()).or_default().push(pkt.index);
            }
        }
    }

    let mut findings = Vec::new();
    for (ip, macs) in &ip_mac_map {
        if macs.len() > 1 {
            let packet_indices = ip_mac_packets.get(ip).cloned().unwrap_or_default();
            let first_seen = packet_indices.iter()
                .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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

fn detect_beaconing(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    // Look for regular outbound connection intervals to a single external IP
    let mut conn_times: HashMap<(String, String), Vec<f64>> = HashMap::new();
    let mut conn_packets: HashMap<(String, String), Vec<usize>> = HashMap::new();

    for pkt in packets {
        if pkt.protocol != "TCP" { continue; }
        if let Some(layers) = &pkt.layers.transport {
            if let Some(flags) = &layers.flags {
                if flags.contains("SYN") && !flags.contains("ACK") {
                    if let (Some(src), Some(dst)) = (&pkt.src_ip, &pkt.dst_ip) {
                        if !is_private_ip(dst) {
                            let key = (src.clone(), dst.clone());
                            conn_times.entry(key.clone()).or_default().push(pkt.timestamp);
                            conn_packets.entry(key).or_default().push(pkt.index);
                        }
                    }
                }
            }
        }
    }

    let mut findings = Vec::new();
    for ((src, dst), mut times) in conn_times {
        if times.len() < 5 { continue; }
        times.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let intervals: Vec<f64> = times.windows(2).map(|w| w[1] - w[0]).collect();
        let mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        let variance = intervals.iter().map(|&x| (x - mean).powi(2)).sum::<f64>() / intervals.len() as f64;
        let cv = if mean > 0.0 { variance.sqrt() / mean } else { f64::INFINITY };

        // Low coefficient of variation suggests beaconing (< 0.2 is very regular)
        if cv < 0.2 && mean > 1.0 && mean < 3600.0 {
            let packet_indices = conn_packets.get(&(src.clone(), dst.clone())).cloned().unwrap_or_default();
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

fn detect_traffic_spikes(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    if packets.is_empty() { return Vec::new(); }

    let mut bytes_per_ip: HashMap<String, usize> = HashMap::new();
    let mut packets_per_ip: HashMap<String, Vec<usize>> = HashMap::new();
    let total_bytes: usize = packets.iter().map(|p| p.length).sum();

    for pkt in packets {
        if let Some(src) = &pkt.src_ip {
            *bytes_per_ip.entry(src.clone()).or_insert(0) += pkt.length;
            packets_per_ip.entry(src.clone()).or_default().push(pkt.index);
        }
    }

    let _mean_bytes = if bytes_per_ip.is_empty() { 0.0 } else {
        total_bytes as f64 / bytes_per_ip.len() as f64
    };

    let mut findings = Vec::new();
    for (ip, bytes) in &bytes_per_ip {
        let pct = *bytes as f64 / total_bytes as f64;
        if pct > 0.5 && bytes_per_ip.len() > 2 {
            let packet_indices = packets_per_ip.get(ip).cloned().unwrap_or_default();
            let first_seen = packet_indices.iter()
                .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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

fn detect_cleartext_credentials(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut findings = Vec::new();

    for pkt in packets {
        if let Some(app) = &pkt.layers.application {
            if app.protocol == "HTTP" {
                let data = &app.data;
                // Check for HTTP Basic Auth header
                if let Some(headers) = data.get("headers") {
                    if let Some(auth) = headers.get("Authorization") {
                        let auth_str = auth.as_str().unwrap_or("");
                        if auth_str.starts_with("Basic ") {
                            findings.push(ThreatFinding {
                                severity: "High".to_string(),
                                category: "Credential Exposure".to_string(),
                                title: format!(
                                    "HTTP Basic Auth Credentials in Cleartext (Packet #{})",
                                    pkt.index
                                ),
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
                }
            }
        }

        // FTP credential check
        if pkt.protocol == "TCP" {
            if let (Some(sp), Some(dp)) = (pkt.src_port, pkt.dst_port) {
                if sp == 21 || dp == 21 {
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
                    break; // one finding is enough
                }
            }
        }
    }

    // Deduplicate
    findings.dedup_by(|a, b| a.title == b.title);
    findings
}

fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip == "127.0.0.1" {
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
    false
}

fn detect_icmp_ping_activity(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut pairs: HashMap<(String, String), Vec<usize>> = HashMap::new();

    for pkt in packets {
        if pkt.protocol == "ICMP" && pkt.info.contains("Echo Request") {
            if let (Some(src), Some(dst)) = (&pkt.src_ip, &pkt.dst_ip) {
                pairs.entry((src.clone(), dst.clone())).or_default().push(pkt.index);
            }
        }
    }

    if pairs.is_empty() {
        return Vec::new();
    }

    let unique_sources: std::collections::HashSet<&str> = pairs.keys().map(|(s, _)| s.as_str()).collect();
    let unique_targets: std::collections::HashSet<&str> = pairs.keys().map(|(_, d)| d.as_str()).collect();
    let total_requests: usize = pairs.values().map(|v| v.len()).sum();
    let packet_indices: Vec<usize> = pairs.values().flatten().copied().take(50).collect();
    let first_seen = packet_indices.iter()
        .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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

fn detect_icmp_flood(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut src_counts: HashMap<String, Vec<usize>> = HashMap::new();

    for pkt in packets {
        if pkt.protocol == "ICMP" && pkt.info.contains("Echo Request") {
            if let Some(src) = &pkt.src_ip {
                src_counts.entry(src.clone()).or_default().push(pkt.index);
            }
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &src_counts {
        if indices.len() > 50 {
            let first_seen = indices.iter()
                .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "High".to_string(),
                category: "DoS".to_string(),
                title: format!("ICMP Flood from {}", src),
                description: format!(
                    "{} sent {} ICMP echo requests, which exceeds the flood threshold of 50. \
                    This volume of ping traffic may indicate a denial-of-service attack or aggressive \
                    network scanning.",
                    src, indices.len()
                ),
                first_seen,
                packet_indices: indices.iter().copied().take(50).collect(),
            });
        }
    }
    findings
}

fn detect_large_icmp(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let large: Vec<usize> = packets.iter()
        .filter(|p| p.protocol == "ICMP" && p.length > 1024)
        .map(|p| p.index)
        .collect();

    if large.is_empty() {
        return Vec::new();
    }

    let first_seen = large.iter()
        .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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

fn detect_udp_flood(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut src_counts: HashMap<String, Vec<usize>> = HashMap::new();

    for pkt in packets {
        if pkt.protocol == "UDP" {
            if let Some(src) = &pkt.src_ip {
                src_counts.entry(src.clone()).or_default().push(pkt.index);
            }
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &src_counts {
        if indices.len() > 500 {
            let first_seen = indices.iter()
                .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
                .fold(f64::INFINITY, f64::min);

            findings.push(ThreatFinding {
                severity: "Medium".to_string(),
                category: "DoS".to_string(),
                title: format!("UDP Flood from {}", src),
                description: format!(
                    "{} sent {} UDP packets, exceeding the flood threshold of 500. \
                    High-rate UDP traffic from a single source is a common indicator of \
                    a UDP-based denial-of-service attack.",
                    src, indices.len()
                ),
                first_seen,
                packet_indices: indices.iter().copied().take(50).collect(),
            });
        }
    }
    findings
}

fn detect_suspicious_ports(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let suspicious: &[(u16, &str, &str, &str)] = &[
        (4444,  "Critical", "Malware",           "Metasploit default handler"),
        (31337, "Critical", "Malware",            "Back Orifice / elite hacking"),
        (12345, "Critical", "Malware",            "NetBus trojan"),
        (6666,  "High",     "Command & Control",  "IRC (common botnet C2)"),
        (6667,  "High",     "Command & Control",  "IRC (common botnet C2)"),
        (1337,  "High",     "Malware",            "Common backdoor port"),
    ];

    let mut findings = Vec::new();
    for &(port, severity, category, label) in suspicious {
        let matched: Vec<usize> = packets.iter()
            .filter(|p| p.dst_port == Some(port) || p.src_port == Some(port))
            .map(|p| p.index)
            .collect();

        if matched.is_empty() {
            continue;
        }

        let first_seen = matched.iter()
            .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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

fn detect_telnet(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let matched: Vec<usize> = packets.iter()
        .filter(|p| p.dst_port == Some(23) || p.src_port == Some(23))
        .map(|p| p.index)
        .collect();

    if matched.is_empty() {
        return Vec::new();
    }

    let first_seen = matched.iter()
        .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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

fn detect_syn_flood(packets: &[PacketMeta]) -> Vec<ThreatFinding> {
    let mut syn_counts: HashMap<String, Vec<usize>> = HashMap::new();
    let mut synack_received: HashMap<String, usize> = HashMap::new();

    for pkt in packets {
        if pkt.protocol != "TCP" { continue; }
        if let Some(layers) = &pkt.layers.transport {
            if let Some(flags) = &layers.flags {
                if flags.contains("SYN") && !flags.contains("ACK") {
                    if let Some(src) = &pkt.src_ip {
                        syn_counts.entry(src.clone()).or_default().push(pkt.index);
                    }
                }
                if flags.contains("SYN") && flags.contains("ACK") {
                    if let Some(dst) = &pkt.dst_ip {
                        *synack_received.entry(dst.clone()).or_insert(0) += 1;
                    }
                }
            }
        }
    }

    let mut findings = Vec::new();
    for (src, indices) in &syn_counts {
        if indices.len() <= 200 { continue; }
        let responses = synack_received.get(src).copied().unwrap_or(0);
        // Flood if SYNs >> SYN-ACKs (handshakes rarely completed)
        if responses < indices.len() / 10 {
            let first_seen = indices.iter()
                .filter_map(|&i| packets.get(i).map(|p| p.timestamp))
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
