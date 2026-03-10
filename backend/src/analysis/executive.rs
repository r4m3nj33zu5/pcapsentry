use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::analysis::alerts::AlertFinding;
use crate::analysis::flows::ConnectionFlow;
use crate::analysis::geo::GeoPoint;
use crate::analysis::tls::TlsSession;
use crate::analysis::utils::is_private_ip;
use crate::analysis::Overview;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SuspiciousHost {
    pub ip: String,
    pub score: u32,
    pub reasons: Vec<String>,
    pub packet_count: usize,
    pub bytes: usize,
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ExecutiveSummary {
    pub threat_score: u32,       // 0-100
    pub risk_level: String,      // None / Low / Medium / High / Critical
    pub top_suspicious_hosts: Vec<SuspiciousHost>,
    pub key_findings: Vec<String>,
    pub c2_candidates: Vec<String>,
    pub data_exfil_candidates: Vec<String>,
    pub alert_count_by_severity: HashMap<String, usize>,
}

pub fn summarize(
    alerts: &[AlertFinding],
    flows: &[ConnectionFlow],
    geo_points: &[GeoPoint],
    overview: &Overview,
    tls_sessions: &[TlsSession],
) -> ExecutiveSummary {
    // ── Alert severity counts ────────────────────────────────────────────────
    let mut alert_count_by_severity: HashMap<String, usize> = HashMap::new();
    for a in alerts {
        *alert_count_by_severity.entry(a.severity.clone()).or_insert(0) += 1;
    }

    // ── Threat score (0-100) ─────────────────────────────────────────────────
    let critical = *alert_count_by_severity.get("Critical").unwrap_or(&0);
    let high = *alert_count_by_severity.get("High").unwrap_or(&0);
    let medium = *alert_count_by_severity.get("Medium").unwrap_or(&0);

    let raw_score = (critical * 25 + high * 10 + medium * 3).min(100) as u32;
    let threat_score = raw_score;
    let risk_level = match threat_score {
        0 => "None",
        1..=20 => "Low",
        21..=50 => "Medium",
        51..=75 => "High",
        _ => "Critical",
    }.to_string();

    // ── C2 candidates: beaconing + long-lived external ───────────────────────
    let mut c2_candidates: Vec<String> = Vec::new();
    for a in alerts {
        if a.category == "Command & Control" || a.category == "Command and Control" {
            for host in &a.affected_hosts {
                if !is_private_ip(host) && !c2_candidates.contains(host) {
                    c2_candidates.push(host.clone());
                }
            }
        }
    }
    c2_candidates.truncate(5);

    // ── Known-bad JA3 hosts ──────────────────────────────────────────────────
    for s in tls_sessions {
        if s.known_bad_ja3.is_some() && !c2_candidates.contains(&s.dst_ip) {
            c2_candidates.push(s.dst_ip.clone());
        }
    }
    c2_candidates.truncate(10);

    // ── Data exfil candidates: high traffic to external + large ICMP ─────────
    let mut exfil_candidates: Vec<String> = Vec::new();
    for a in alerts {
        if a.category == "Exfiltration" || a.category == "Anomalous Traffic" {
            for host in &a.affected_hosts {
                if !exfil_candidates.contains(host) {
                    exfil_candidates.push(host.clone());
                }
            }
        }
    }
    exfil_candidates.truncate(5);

    // ── Suspicious hosts (IPs with multiple alert references) ────────────────
    let mut host_scores: HashMap<String, (u32, Vec<String>, usize, usize)> = HashMap::new();
    for a in alerts {
        let sev_score = match a.severity.as_str() {
            "Critical" => 25u32,
            "High" => 10,
            "Medium" => 5,
            _ => 1,
        };
        for host in &a.affected_hosts {
            let e = host_scores.entry(host.clone()).or_insert((0, Vec::new(), 0, 0));
            e.0 += sev_score;
            if !e.1.contains(&a.title) { e.1.push(a.title.clone()); }
        }
    }
    // Add packet/byte counts from flows
    for flow in flows {
        for ip in [&flow.src_ip, &flow.dst_ip] {
            if let Some(e) = host_scores.get_mut(ip) {
                e.2 += flow.packets;
                e.3 += flow.bytes;
            }
        }
    }
    // Add geo info
    let geo_map: HashMap<&str, &str> = geo_points.iter()
        .map(|g| (g.ip.as_str(), g.country.as_str()))
        .collect();

    let mut top_suspicious_hosts: Vec<SuspiciousHost> = host_scores
        .into_iter()
        .filter(|(_, (score, _, _, _))| *score > 0)
        .map(|(ip, (score, reasons, packets, bytes))| SuspiciousHost {
            country: geo_map.get(ip.as_str()).map(|s| s.to_string()),
            ip,
            score: score.min(100),
            reasons,
            packet_count: packets,
            bytes,
        })
        .collect();
    top_suspicious_hosts.sort_by(|a, b| b.score.cmp(&a.score));
    top_suspicious_hosts.truncate(10);

    // ── Key findings (human-readable summary) ────────────────────────────────
    let mut key_findings = Vec::new();
    if critical > 0 {
        key_findings.push(format!("{} critical-severity alert(s) detected — immediate investigation required.", critical));
    }
    if !c2_candidates.is_empty() {
        key_findings.push(format!("Potential C2 communication to: {}", c2_candidates.join(", ")));
    }
    if !exfil_candidates.is_empty() {
        key_findings.push(format!("Data exfiltration indicators from: {}", exfil_candidates.join(", ")));
    }
    let bad_ja3_count = tls_sessions.iter().filter(|s| s.known_bad_ja3.is_some()).count();
    if bad_ja3_count > 0 {
        key_findings.push(format!("{} TLS session(s) matched known-malicious JA3 fingerprints.", bad_ja3_count));
    }
    let expired_cert_count = tls_sessions.iter().filter(|s| s.is_expired).count();
    if expired_cert_count > 0 {
        key_findings.push(format!("{} TLS session(s) with expired certificates.", expired_cert_count));
    }
    let weak_cipher_count = tls_sessions.iter().filter(|s| s.is_cipher_weak).count();
    if weak_cipher_count > 0 {
        key_findings.push(format!("{} TLS session(s) using weak/deprecated cipher suites.", weak_cipher_count));
    }
    if key_findings.is_empty() {
        key_findings.push("No significant threats detected in this capture.".to_string());
    }

    ExecutiveSummary {
        threat_score,
        risk_level,
        top_suspicious_hosts,
        key_findings,
        c2_candidates,
        data_exfil_candidates: exfil_candidates,
        alert_count_by_severity,
    }
}
