pub mod threats;
pub mod talkers;
pub mod dns_http;
pub mod geo;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::parser::PacketMeta;
use self::threats::ThreatFinding;
use self::talkers::TalkerStats;
use self::dns_http::{DnsEntry, HttpEntry};
use self::geo::GeoPoint;

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
    pub packets: Vec<PacketMeta>,
}

impl AnalysisResult {
    pub fn highest_severity(&self) -> &'static str {
        for finding in &self.threats {
            if finding.severity == "Critical" {
                return "Critical";
            }
        }
        for finding in &self.threats {
            if finding.severity == "High" {
                return "High";
            }
        }
        for finding in &self.threats {
            if finding.severity == "Medium" {
                return "Medium";
            }
        }
        if !self.threats.is_empty() {
            return "Info";
        }
        "None"
    }
}

pub fn analyze(
    overview: Overview,
    packets: Vec<PacketMeta>,
    raw_packets: Vec<crate::parser::PacketMeta>,
    geo_enabled: bool,
) -> Result<AnalysisResult> {
    let timeline = build_timeline(&packets, &overview);
    let protocol_stats = build_protocol_stats(&packets);
    let (top_senders, top_receivers) = talkers::compute(&packets);
    let threats = threats::detect(&packets);
    let geo_points = if geo_enabled {
        geo::geolocate(&packets)
    } else {
        Vec::new()
    };
    let (dns_log, http_log) = dns_http::extract(&packets);

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
        packets,
    })
}

fn build_timeline(packets: &[PacketMeta], overview: &Overview) -> Vec<TimelineBucket> {
    if packets.is_empty() {
        return Vec::new();
    }

    let duration = overview.capture_duration_secs;
    let bucket_count = if duration < 10.0 { 20 } else if duration < 60.0 { 60 } else if duration < 3600.0 { 120 } else { 200 };
    let bucket_size = if duration == 0.0 { 1.0 } else { duration / bucket_count as f64 };
    let start_ts = overview.first_packet.unwrap_or(0.0);

    let mut buckets: Vec<TimelineBucket> = (0..bucket_count)
        .map(|i| TimelineBucket {
            timestamp: start_ts + i as f64 * bucket_size,
            packet_count: 0,
            byte_count: 0,
        })
        .collect();

    for pkt in packets {
        let idx = if bucket_size > 0.0 {
            ((pkt.timestamp - start_ts) / bucket_size) as usize
        } else {
            0
        };
        let idx = idx.min(bucket_count - 1);
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
