pub mod threats;
pub mod talkers;
pub mod dns_http;
pub mod geo;
pub mod icmp;
pub mod flows;
pub mod utils;
pub mod alerts;
pub mod executive;
pub mod tls;
pub mod ioc;
pub mod proto_hierarchy;
pub mod timeline_events;
pub mod beaconing;
pub mod indexed;
pub mod conversations;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::parser::PacketMeta;
use self::threats::ThreatFinding;
use self::talkers::TalkerStats;
use self::dns_http::{DnsEntry, HttpEntry};
use self::geo::GeoPoint;
use self::flows::ConnectionFlow;
use self::alerts::AlertFinding;
use self::executive::ExecutiveSummary;
use self::tls::TlsSession;
use self::ioc::IocBundle;
use self::proto_hierarchy::ProtoNode;
use self::timeline_events::TimelineEvent;
use self::beaconing::BeaconingCandidate;
use self::conversations::SuspiciousConversation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overview {
    pub filename: String,
    pub total_packets: usize,
    pub shown_packets: usize,
    pub capture_duration_secs: f64,
    pub first_packet: Option<f64>,
    pub last_packet: Option<f64>,
    pub analyzed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineBucket {
    pub timestamp: f64,
    pub packet_count: usize,
    pub byte_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolStat {
    pub protocol: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpSummary {
    pub echo_requests: usize,
    pub echo_replies: usize,
    pub unique_sources: usize,
    pub unique_targets: usize,
    pub top_pairs: Vec<IcmpPair>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpPair {
    pub src: String,
    pub dst: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortStat {
    pub port: u16,
    pub packet_count: usize,
    pub service: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSizeStats {
    pub min: usize,
    pub max: usize,
    pub avg: usize,
    pub total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    pub overview: Overview,
    pub timeline: Vec<TimelineBucket>,
    pub protocol_stats: Vec<ProtocolStat>,
    pub top_senders: Vec<TalkerStats>,
    pub top_receivers: Vec<TalkerStats>,
    pub threats: Vec<ThreatFinding>,
    pub geo_points: Vec<GeoPoint>,
    pub dns_log: Vec<DnsEntry>,
    pub http_log: Vec<HttpEntry>,
    pub icmp_summary: IcmpSummary,
    pub top_ports: Vec<PortStat>,
    pub packet_size_stats: PacketSizeStats,
    pub flows: Vec<ConnectionFlow>,
    pub packets: Vec<PacketMeta>,
    // New SOC fields (all with serde default for backward compat)
    #[serde(default)]
    pub alerts: Vec<AlertFinding>,
    #[serde(default)]
    pub executive: Option<ExecutiveSummary>,
    #[serde(default)]
    pub tls_sessions: Vec<TlsSession>,
    #[serde(default)]
    pub ioc_bundle: Option<IocBundle>,
    #[serde(default)]
    pub timeline_events: Vec<TimelineEvent>,
    #[serde(default)]
    pub proto_hierarchy: Vec<ProtoNode>,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub beaconing: Vec<BeaconingCandidate>,
    #[serde(default)]
    pub suspicious_conversations: Vec<SuspiciousConversation>,
    /// TCP streams stored in-memory only (not persisted/serialized).
    #[serde(skip, default)]
    pub streams: Vec<crate::reassembly::ReassembledStream>,
}

impl AnalysisResult {
    pub fn highest_severity(&self) -> &'static str {
        // Check new alerts first
        for a in &self.alerts {
            if a.severity == "Critical" { return "Critical"; }
        }
        for a in &self.alerts {
            if a.severity == "High" { return "High"; }
        }
        // Fall back to old threats
        for finding in &self.threats {
            if finding.severity == "Critical" { return "Critical"; }
        }
        for finding in &self.threats {
            if finding.severity == "High" { return "High"; }
        }
        for finding in &self.threats {
            if finding.severity == "Medium" { return "Medium"; }
        }
        if !self.threats.is_empty() || !self.alerts.is_empty() {
            return "Info";
        }
        "None"
    }
}

pub fn analyze(
    overview: Overview,
    packets: Vec<PacketMeta>,
    streams: Vec<crate::reassembly::ReassembledStream>,
    geo_enabled: bool,
    config: &crate::config::AppConfig,
    progress: &Arc<AtomicU8>,
) -> Result<AnalysisResult> {
    // Build the shared index once: every detector that needs "all TCP SYNs"
    // / "all ICMP echo requests" / "all ARP replies" now reads from the
    // precomputed bucket instead of doing its own O(N) sweep.
    progress.store(60, Ordering::Relaxed);
    let view = indexed::IndexedView::build(&packets);
    progress.store(62, Ordering::Relaxed);
    let timeline = build_timeline(&packets, &overview);
    progress.store(63, Ordering::Relaxed);
    let protocol_stats = build_protocol_stats(&packets);
    progress.store(64, Ordering::Relaxed);
    let (top_senders, top_receivers) = talkers::compute(&packets);
    progress.store(66, Ordering::Relaxed);
    let threats = threats::detect(&view, &config.alert_thresholds, &config.whitelist);
    progress.store(68, Ordering::Relaxed);
    let geo_points = if geo_enabled {
        geo::geolocate(&packets)
    } else {
        Vec::new()
    };
    progress.store(70, Ordering::Relaxed);
    let (dns_log, mut http_log) = dns_http::extract(&packets);
    dns_http::extract_from_streams(&streams, &mut http_log);
    progress.store(73, Ordering::Relaxed);
    let icmp_summary = icmp::summarize(&view);
    progress.store(75, Ordering::Relaxed);
    let top_ports = compute_top_ports(&packets);
    let packet_size_stats = compute_packet_size_stats(&packets);
    progress.store(77, Ordering::Relaxed);
    let connection_flows = flows::compute(&packets);

    // New SOC analysis
    progress.store(80, Ordering::Relaxed);
    let alert_findings = alerts::detect(&view, &connection_flows, &dns_log, &config.alert_thresholds, &config.whitelist);
    progress.store(84, Ordering::Relaxed);
    let tls_sessions = tls::extract(&packets);
    progress.store(87, Ordering::Relaxed);
    let ioc = ioc::build_bundle(&packets, &dns_log, &http_log, &geo_points);
    progress.store(89, Ordering::Relaxed);
    let proto_hier = proto_hierarchy::build(&packets);
    progress.store(91, Ordering::Relaxed);
    let timeline_evts = timeline_events::merge(&alert_findings, &dns_log, &http_log, &tls_sessions);
    progress.store(93, Ordering::Relaxed);
    let exec = executive::summarize(&alert_findings, &connection_flows, &geo_points, &overview, &tls_sessions);
    progress.store(95, Ordering::Relaxed);
    let beaconing_candidates = beaconing::detect(&view);
    progress.store(96, Ordering::Relaxed);
    let suspicious_conversations = conversations::compute(
        &packets, &alert_findings, &beaconing_candidates, &tls_sessions, &streams);
    progress.store(97, Ordering::Relaxed);

    Ok(AnalysisResult {
        overview,
        timeline,
        protocol_stats,
        top_senders,
        top_receivers,
        threats,
        geo_points,
        dns_log,
        http_log,
        icmp_summary,
        top_ports,
        packet_size_stats,
        flows: connection_flows,
        packets,
        alerts: alert_findings,
        executive: Some(exec),
        tls_sessions,
        ioc_bundle: Some(ioc),
        timeline_events: timeline_evts,
        proto_hierarchy: proto_hier,
        notes: String::new(),
        beaconing: beaconing_candidates,
        suspicious_conversations,
        streams,
    })
}

fn build_timeline(packets: &[PacketMeta], overview: &Overview) -> Vec<TimelineBucket> {
    if packets.is_empty() {
        return Vec::new();
    }

    let duration = overview.capture_duration_secs;
    let bucket_count: usize = if duration < 10.0 { 20 } else if duration < 60.0 { 60 } else if duration < 3600.0 { 120 } else { 200 };
    // Guard against zero / negative / sub-nanosecond durations so we never
    // hit a divide-by-zero or NaN bucket index.
    let bucket_size = if duration > 1e-9 { duration / bucket_count as f64 } else { 1.0 };
    let start_ts = overview.first_packet.unwrap_or(0.0);

    let mut buckets: Vec<TimelineBucket> = (0..bucket_count)
        .map(|i| TimelineBucket {
            timestamp: start_ts + i as f64 * bucket_size,
            packet_count: 0,
            byte_count: 0,
        })
        .collect();

    let max_idx = bucket_count.saturating_sub(1);
    for pkt in packets {
        // Clamp negative offsets (out-of-order packets, clock-skew, etc.) and
        // non-finite values so the cast to usize never produces a bogus index.
        let offset = (pkt.timestamp - start_ts).max(0.0);
        let raw = offset / bucket_size;
        let idx = if raw.is_finite() { raw.floor() as usize } else { 0 };
        let idx = idx.min(max_idx);
        buckets[idx].packet_count += 1;
        buckets[idx].byte_count += pkt.length;
    }

    buckets
}

fn build_protocol_stats(packets: &[PacketMeta]) -> Vec<ProtocolStat> {
    let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for pkt in packets {
        *counts.entry(pkt.protocol.clone()).or_insert(0) += 1;
    }
    let mut stats: Vec<ProtocolStat> = counts
        .into_iter()
        .map(|(protocol, count)| ProtocolStat { protocol, count })
        .collect();
    stats.sort_by(|a, b| b.count.cmp(&a.count));
    stats
}

fn port_service(port: u16) -> &'static str {
    match port {
        80 => "HTTP",
        443 => "HTTPS",
        22 => "SSH",
        53 => "DNS",
        25 => "SMTP",
        21 => "FTP",
        23 => "Telnet",
        3389 => "RDP",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        3306 => "MySQL",
        5432 => "PostgreSQL",
        6379 => "Redis",
        27017 => "MongoDB",
        4444 => "Metasploit",
        31337 => "Back Orifice",
        12345 => "NetBus",
        6666 | 6667 => "IRC/C2",
        1337 => "Backdoor",
        _ => "Unknown",
    }
}

fn compute_top_ports(packets: &[PacketMeta]) -> Vec<PortStat> {
    let mut counts: std::collections::HashMap<u16, usize> = std::collections::HashMap::new();
    for pkt in packets {
        if let Some(port) = pkt.dst_port {
            *counts.entry(port).or_insert(0) += 1;
        }
    }
    let mut stats: Vec<PortStat> = counts
        .into_iter()
        .map(|(port, packet_count)| PortStat {
            service: port_service(port).to_string(),
            port,
            packet_count,
        })
        .collect();
    stats.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    stats.truncate(15);
    stats
}

fn compute_packet_size_stats(packets: &[PacketMeta]) -> PacketSizeStats {
    if packets.is_empty() {
        return PacketSizeStats { min: 0, max: 0, avg: 0, total_bytes: 0 };
    }
    let mut min = usize::MAX;
    let mut max = 0usize;
    let mut total_bytes: u64 = 0;
    for pkt in packets {
        if pkt.length < min { min = pkt.length; }
        if pkt.length > max { max = pkt.length; }
        total_bytes += pkt.length as u64;
    }
    let avg = (total_bytes / packets.len() as u64) as usize;
    PacketSizeStats { min, max, avg, total_bytes }
}
