use serde::{Deserialize, Serialize};
use crate::analysis::alerts::AlertFinding;
use crate::analysis::dns_http::{DnsEntry, HttpEntry};
use crate::analysis::tls::TlsSession;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: f64,
    pub event_type: String,    // "alert" | "dns" | "http" | "tls"
    pub severity: String,
    pub description: String,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    pub packet_index: Option<usize>,
    pub alert_id: Option<String>,
    pub mitre_technique: Option<String>,
}

pub fn merge(
    alerts: &[AlertFinding],
    dns_log: &[DnsEntry],
    http_log: &[HttpEntry],
    tls_sessions: &[TlsSession],
) -> Vec<TimelineEvent> {
    let mut events: Vec<TimelineEvent> = Vec::new();

    // Alerts
    for alert in alerts {
        if alert.first_seen == 0.0 { continue; }
        events.push(TimelineEvent {
            timestamp: alert.first_seen,
            event_type: "alert".to_string(),
            severity: alert.severity.clone(),
            description: alert.title.clone(),
            src_ip: alert.affected_hosts.first().cloned(),
            dst_ip: alert.affected_hosts.get(1).cloned(),
            packet_index: alert.packet_indices.first().copied(),
            alert_id: Some(alert.id.clone()),
            mitre_technique: Some(alert.mitre_technique.clone()),
        });
    }

    // Suspicious DNS
    for entry in dns_log {
        if entry.suspicious {
            events.push(TimelineEvent {
                timestamp: entry.timestamp,
                event_type: "dns".to_string(),
                severity: "Medium".to_string(),
                description: format!("Suspicious DNS: {} ({})", entry.name,
                    entry.suspicious_reason.as_deref().unwrap_or("unknown")),
                src_ip: Some(entry.src_ip.clone()),
                dst_ip: Some(entry.dst_ip.clone()),
                packet_index: Some(entry.packet_index),
                alert_id: None,
                mitre_technique: None,
            });
        }
    }

    // Suspicious HTTP
    for entry in http_log {
        if entry.suspicious {
            events.push(TimelineEvent {
                timestamp: entry.timestamp,
                event_type: "http".to_string(),
                severity: "Medium".to_string(),
                description: format!("Suspicious HTTP {}: {} {}",
                    entry.entry_type,
                    entry.host.as_deref().unwrap_or(""),
                    entry.path.as_deref().unwrap_or("")),
                src_ip: Some(entry.src_ip.clone()),
                dst_ip: Some(entry.dst_ip.clone()),
                packet_index: Some(entry.packet_index),
                alert_id: None,
                mitre_technique: None,
            });
        }
    }

    // Known-bad TLS
    for session in tls_sessions {
        if let Some(family) = &session.known_bad_ja3 {
            events.push(TimelineEvent {
                timestamp: session.first_seen,
                event_type: "tls".to_string(),
                severity: "High".to_string(),
                description: format!("Known-bad JA3 ({}) matched: {} → {}",
                    family, session.src_ip, session.dst_ip),
                src_ip: Some(session.src_ip.clone()),
                dst_ip: Some(session.dst_ip.clone()),
                packet_index: session.packet_indices.first().copied(),
                alert_id: None,
                mitre_technique: Some("T1573".to_string()),
            });
        }
    }

    events.sort_by(|a, b| a.timestamp.partial_cmp(&b.timestamp).unwrap_or(std::cmp::Ordering::Equal));
    events.truncate(2000);
    events
}
