//! Suspicious conversation isolation.
//!
//! Builds *bidirectional* conversations (canonical 5-tuple, both directions
//! merged) from the packet list, then joins every existing detection signal
//! onto them: alert findings (via packet indices), beaconing candidates,
//! TLS session intel (known-bad JA3, self-signed/expired certs), and the
//! reassembled stream index. Each conversation gets a score, a severity
//! bucket, a plain-English reason list, and the full set of packet indices
//! so the UI can isolate it for review with one click.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use serde::{Deserialize, Serialize};

use crate::parser::PacketMeta;
use crate::reassembly::ReassembledStream;
use crate::analysis::alerts::AlertFinding;
use crate::analysis::beaconing::BeaconingCandidate;
use crate::analysis::tls::TlsSession;
use crate::analysis::flows::guess_service;
use crate::analysis::utils::{format_bytes, is_private_addr};

/// Cap on packet indices stored per conversation (UI isolation list).
const MAX_INDICES: usize = 5_000;
/// Cap on conversations returned (worst-first).
const MAX_CONVERSATIONS: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationReason {
    pub label: String,
    pub detail: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousConversation {
    pub conv_id: String,
    /// Endpoint that sent the first packet of the conversation.
    pub initiator_ip: String,
    pub initiator_port: u16,
    pub responder_ip: String,
    pub responder_port: u16,
    pub transport: String,
    pub app_protocols: Vec<String>,
    pub service_guess: String,
    pub state: String,
    pub is_external: bool,
    pub total_packets: usize,
    pub packets_out: usize,
    pub packets_in: usize,
    pub bytes_out: usize,
    pub bytes_in: usize,
    pub first_seen: f64,
    pub last_seen: f64,
    pub duration_secs: f64,
    /// Packet indices belonging to this conversation (capped — see
    /// `total_packets` for the true count).
    pub packet_indices: Vec<usize>,
    pub stream_index: Option<usize>,
    pub sni: Option<String>,
    pub ja3_hash: Option<String>,
    pub score: f32,
    pub severity: String,
    pub reasons: Vec<ConversationReason>,
    pub summary: String,
}

type EndpointKey = (IpAddr, u16, IpAddr, u16, String);

fn endpoint_key(ip1: IpAddr, p1: u16, ip2: IpAddr, p2: u16, transport: &str) -> EndpointKey {
    if (ip1, p1) <= (ip2, p2) {
        (ip1, p1, ip2, p2, transport.to_string())
    } else {
        (ip2, p2, ip1, p1, transport.to_string())
    }
}

struct Agg {
    initiator_ip: IpAddr,
    initiator_port: u16,
    responder_ip: IpAddr,
    responder_port: u16,
    transport: String,
    app_protocols: BTreeSet<String>,
    packets_out: usize,
    packets_in: usize,
    bytes_out: usize,
    bytes_in: usize,
    first_seen: f64,
    last_seen: f64,
    has_syn: bool,
    has_synack: bool,
    has_rst: bool,
    indices: Vec<usize>,
    total_packets: usize,
}

pub fn compute(
    packets: &[PacketMeta],
    alerts: &[AlertFinding],
    beacons: &[BeaconingCandidate],
    tls_sessions: &[TlsSession],
    streams: &[ReassembledStream],
) -> Vec<SuspiciousConversation> {
    // ── Phase 1: aggregate bidirectional conversations ──────────────────────
    let mut convs: HashMap<EndpointKey, Agg> = HashMap::new();
    // Conversation keys in first-seen order; positions are stable handles
    // used by the packet→conversation join map.
    let mut keys: Vec<EndpointKey> = Vec::new();
    let mut key_pos: HashMap<EndpointKey, u32> = HashMap::new();
    let mut key_of_packet: HashMap<usize, u32> = HashMap::new();

    for pkt in packets {
        let (src, dst) = match (pkt.src_ip, pkt.dst_ip) {
            (Some(s), Some(d)) => (s, d),
            _ => continue,
        };
        let transport = pkt.layers.transport.as_ref()
            .map(|t| t.protocol.clone())
            .unwrap_or_else(|| pkt.protocol.clone());
        let sp = pkt.src_port.unwrap_or(0);
        let dp = pkt.dst_port.unwrap_or(0);
        let key = endpoint_key(src, sp, dst, dp, &transport);

        let pos = *key_pos.entry(key.clone()).or_insert_with(|| {
            keys.push(key.clone());
            (keys.len() - 1) as u32
        });
        key_of_packet.insert(pkt.index, pos);

        let agg = convs.entry(key).or_insert_with(|| Agg {
            initiator_ip: src,
            initiator_port: sp,
            responder_ip: dst,
            responder_port: dp,
            transport: transport.clone(),
            app_protocols: BTreeSet::new(),
            packets_out: 0, packets_in: 0,
            bytes_out: 0, bytes_in: 0,
            first_seen: pkt.timestamp,
            last_seen: pkt.timestamp,
            has_syn: false, has_synack: false, has_rst: false,
            indices: Vec::new(),
            total_packets: 0,
        });

        let outbound = src == agg.initiator_ip && sp == agg.initiator_port;
        if outbound {
            agg.packets_out += 1;
            agg.bytes_out += pkt.length;
        } else {
            agg.packets_in += 1;
            agg.bytes_in += pkt.length;
        }
        agg.total_packets += 1;
        if pkt.timestamp < agg.first_seen { agg.first_seen = pkt.timestamp; }
        if pkt.timestamp > agg.last_seen { agg.last_seen = pkt.timestamp; }
        if agg.indices.len() < MAX_INDICES { agg.indices.push(pkt.index); }
        if pkt.protocol != agg.transport { agg.app_protocols.insert(pkt.protocol.clone()); }

        if let Some(t) = &pkt.layers.transport {
            if let Some(flags) = &t.flags {
                let syn = flags.contains("SYN");
                let ack = flags.contains("ACK");
                if syn && !ack { agg.has_syn = true; }
                if syn && ack { agg.has_synack = true; }
                if flags.contains("RST") { agg.has_rst = true; }
            }
        }
    }

    // ── Phase 2: build join tables for the other signals ────────────────────
    // Unordered (ip, ip) pair → beacon refs.
    let pair = |a: IpAddr, b: IpAddr| if a <= b { (a, b) } else { (b, a) };
    let mut beacon_map: HashMap<(IpAddr, IpAddr, u16), &BeaconingCandidate> = HashMap::new();
    for b in beacons {
        if let (Ok(s), Ok(d)) = (b.src_ip.parse::<IpAddr>(), b.dst_ip.parse::<IpAddr>()) {
            let (lo, hi) = pair(s, d);
            beacon_map.entry((lo, hi, b.dst_port)).or_insert(b);
        }
    }
    let mut tls_map: HashMap<(IpAddr, u16, IpAddr, u16), &TlsSession> = HashMap::new();
    for t in tls_sessions {
        if let (Ok(s), Ok(d)) = (t.src_ip.parse::<IpAddr>(), t.dst_ip.parse::<IpAddr>()) {
            let k = endpoint_key(s, t.src_port, d, t.dst_port, "");
            tls_map.entry((k.0, k.1, k.2, k.3)).or_insert(t);
        }
    }
    let mut stream_map: HashMap<(IpAddr, u16, IpAddr, u16), usize> = HashMap::new();
    for (i, s) in streams.iter().enumerate() {
        if let (Ok(a), Ok(b)) = (s.src_ip.parse::<IpAddr>(), s.dst_ip.parse::<IpAddr>()) {
            let k = endpoint_key(a, s.src_port, b, s.dst_port, "");
            stream_map.entry((k.0, k.1, k.2, k.3)).or_insert(i);
        }
    }

    // Alert → conversations: walk each alert's packet indices through the
    // packet→conversation map; alerts without indices fall back to matching
    // both affected hosts against the conversation endpoints.
    let sev_weight = |sev: &str| -> f32 {
        match sev { "Critical" => 40.0, "High" => 25.0, "Medium" => 12.0, _ => 3.0 }
    };
    let mut alert_hits: HashMap<u32, Vec<&AlertFinding>> = HashMap::new();
    for alert in alerts {
        let mut hit_keys: BTreeSet<u32> = BTreeSet::new();
        for &pi in &alert.packet_indices {
            if let Some(&k) = key_of_packet.get(&pi) { hit_keys.insert(k); }
        }
        if hit_keys.is_empty() && alert.affected_hosts.len() >= 2 {
            let hosts: BTreeSet<&str> = alert.affected_hosts.iter().map(|s| s.as_str()).collect();
            for (pos, key) in keys.iter().enumerate() {
                let a = key.0.to_string();
                let b = key.2.to_string();
                if hosts.contains(a.as_str()) && hosts.contains(b.as_str()) {
                    hit_keys.insert(pos as u32);
                }
            }
        }
        for k in hit_keys {
            alert_hits.entry(k).or_default().push(alert);
        }
    }

    // ── Phase 3: score each conversation ────────────────────────────────────
    let mut out: Vec<SuspiciousConversation> = Vec::new();
    for (pos, key) in keys.iter().enumerate() {
        let agg = match convs.get(key) { Some(a) => a, None => continue };
        let mut score = 0.0f32;
        let mut reasons: Vec<ConversationReason> = Vec::new();

        if let Some(hits) = alert_hits.get(&(pos as u32)) {
            let mut seen_titles: BTreeSet<&str> = BTreeSet::new();
            for alert in hits {
                if !seen_titles.insert(alert.title.as_str()) { continue; }
                score += sev_weight(&alert.severity) * alert.confidence;
                reasons.push(ConversationReason {
                    label: alert.category.clone(),
                    detail: alert.title.clone(),
                    severity: alert.severity.clone(),
                });
            }
        }

        let (lo_ip, hi_ip) = pair(agg.initiator_ip, agg.responder_ip);
        for port in [agg.responder_port, agg.initiator_port] {
            if let Some(b) = beacon_map.get(&(lo_ip, hi_ip, port)) {
                score += 30.0 * b.confidence as f32;
                reasons.push(ConversationReason {
                    label: "Beaconing".to_string(),
                    detail: format!("Connected {}× at ~{:.0}s intervals ({}% jitter) — possible C2 callback.",
                        b.connection_count, b.mean_interval_secs, b.jitter_pct),
                    severity: "High".to_string(),
                });
                break;
            }
        }

        let ek = (key.0, key.1, key.2, key.3);
        let mut sni = None;
        let mut ja3_hash = None;
        if let Some(t) = tls_map.get(&ek) {
            sni = t.sni.clone();
            if !t.ja3_hash.is_empty() { ja3_hash = Some(t.ja3_hash.clone()); }
            if let Some(family) = &t.known_bad_ja3 {
                score += 60.0;
                reasons.push(ConversationReason {
                    label: "Known-Bad JA3".to_string(),
                    detail: format!("TLS fingerprint matches known malware family: {}.", family),
                    severity: "Critical".to_string(),
                });
            }
            if t.is_self_signed {
                score += 15.0;
                reasons.push(ConversationReason {
                    label: "Self-Signed Cert".to_string(),
                    detail: "Server presented a self-signed certificate.".to_string(),
                    severity: "Medium".to_string(),
                });
            }
            if t.is_expired {
                score += 8.0;
                reasons.push(ConversationReason {
                    label: "Expired Cert".to_string(),
                    detail: "Server certificate is expired.".to_string(),
                    severity: "Medium".to_string(),
                });
            }
            if t.is_cipher_weak {
                score += 8.0;
                reasons.push(ConversationReason {
                    label: "Weak Cipher".to_string(),
                    detail: "Weak or deprecated cipher suite offered/negotiated.".to_string(),
                    severity: "Medium".to_string(),
                });
            }
        }

        if score <= 0.0 { continue; }

        let severity = if score >= 60.0 { "Critical" }
            else if score >= 30.0 { "High" }
            else if score >= 12.0 { "Medium" }
            else { "Low" };

        let state = if agg.transport == "TCP" {
            if agg.has_syn && agg.has_synack { "established" }
            else if agg.has_syn { "attempted" }
            else if agg.has_rst { "reset" }
            else { "unknown" }
        } else { "stateless" };

        let is_external = !is_private_addr(&agg.initiator_ip) || !is_private_addr(&agg.responder_ip);
        let duration = agg.last_seen - agg.first_seen;
        let service = guess_service(Some(agg.responder_port));

        let summary = build_summary(agg, service, duration, &reasons);

        out.push(SuspiciousConversation {
            conv_id: format!("{}:{}-{}:{}-{}", key.0, key.1, key.2, key.3, agg.transport),
            initiator_ip: agg.initiator_ip.to_string(),
            initiator_port: agg.initiator_port,
            responder_ip: agg.responder_ip.to_string(),
            responder_port: agg.responder_port,
            transport: agg.transport.clone(),
            app_protocols: agg.app_protocols.iter().cloned().collect(),
            service_guess: service.to_string(),
            state: state.to_string(),
            is_external,
            total_packets: agg.total_packets,
            packets_out: agg.packets_out,
            packets_in: agg.packets_in,
            bytes_out: agg.bytes_out,
            bytes_in: agg.bytes_in,
            first_seen: agg.first_seen,
            last_seen: agg.last_seen,
            duration_secs: duration,
            packet_indices: agg.indices.clone(),
            stream_index: stream_map.get(&ek).copied(),
            sni,
            ja3_hash,
            score,
            severity: severity.to_string(),
            reasons,
            summary,
        });
    }

    out.sort_by(|a, b| b.score.total_cmp(&a.score).then(b.total_packets.cmp(&a.total_packets)));
    out.truncate(MAX_CONVERSATIONS);
    out
}

fn human_duration(secs: f64) -> String {
    if secs >= 3600.0 { format!("{:.1}h", secs / 3600.0) }
    else if secs >= 60.0 { format!("{:.1}m", secs / 60.0) }
    else { format!("{:.1}s", secs) }
}

fn build_summary(agg: &Agg, service: &str, duration: f64, reasons: &[ConversationReason]) -> String {
    let svc = if service == "Unknown" {
        agg.app_protocols.iter().cloned().collect::<Vec<_>>().join("/")
    } else {
        service.to_string()
    };
    let svc = if svc.is_empty() { agg.transport.clone() } else { svc };
    let mut s = format!(
        "{}:{} → {}:{} ({}) — {} packets, {} out / {} in over {}.",
        agg.initiator_ip, agg.initiator_port,
        agg.responder_ip, agg.responder_port,
        svc,
        agg.total_packets,
        format_bytes(agg.bytes_out), format_bytes(agg.bytes_in),
        human_duration(duration),
    );
    let top: Vec<&str> = reasons.iter().take(3).map(|r| r.detail.as_str()).collect();
    if !top.is_empty() {
        s.push(' ');
        s.push_str(&top.join(" "));
    }
    s
}
