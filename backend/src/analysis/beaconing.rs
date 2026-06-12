use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use crate::analysis::indexed::IndexedView;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeaconingCandidate {
    pub src_ip: String,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub connection_count: usize,
    pub mean_interval_secs: f64,
    pub jitter_pct: f64,       // coefficient of variation × 100
    pub confidence: f64,       // 0.0 – 1.0
    pub total_duration_secs: f64,
}

pub fn detect(view: &IndexedView) -> Vec<BeaconingCandidate> {
    // Group SYN (TCP) or first-contact (UDP) timestamps by (src, dst, dport).
    // The IndexedView already filtered TCP SYNs and UDP packets — we iterate
    // those two buckets instead of scanning the entire packet vec.
    let mut groups: HashMap<(IpAddr, IpAddr, u16, String), Vec<f64>> = HashMap::new();

    let push = |groups: &mut HashMap<(IpAddr, IpAddr, u16, String), Vec<f64>>,
                    i: usize, proto: &str| {
        let pkt = &view.packets[i];
        let Some(src) = pkt.src_ip else { return };
        let Some(dst) = pkt.dst_ip else { return };
        let Some(dport) = pkt.dst_port else { return };
        groups.entry((src, dst, dport, proto.to_string())).or_default().push(pkt.timestamp);
    };
    for &i in &view.tcp_syn { push(&mut groups, i, "TCP"); }
    for &i in &view.udp {
        // Skip QUIC (UDP/443): browser connections poll at regular intervals
        // and read as high-confidence beacons. TCP/443 stays in scope — the
        // SYN cadence there is still a meaningful C2 signal.
        let pkt = &view.packets[i];
        if pkt.src_port == Some(443) || pkt.dst_port == Some(443) {
            continue;
        }
        push(&mut groups, i, "UDP");
    }

    let mut candidates: Vec<BeaconingCandidate> = Vec::new();

    for ((src_ip, dst_ip, dst_port, protocol), mut timestamps) in groups {
        if timestamps.len() < 4 {
            continue;
        }

        timestamps.sort_by(|a, b| a.total_cmp(b));

        // Deduplicate: collapse events within 0.5s of each other (same burst)
        let mut deduped: Vec<f64> = vec![timestamps[0]];
        for &ts in &timestamps[1..] {
            if ts - deduped.last().unwrap() > 0.5 {
                deduped.push(ts);
            }
        }
        if deduped.len() < 4 {
            continue;
        }

        // Compute inter-arrival intervals
        let intervals: Vec<f64> = deduped.windows(2).map(|w| w[1] - w[0]).collect();
        let n = intervals.len() as f64;
        let mean = intervals.iter().sum::<f64>() / n;
        if mean < 0.5 {
            // Too fast — flood, not beaconing
            continue;
        }

        let variance = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
        let std_dev = variance.sqrt();
        let cv = std_dev / mean; // coefficient of variation

        // Only flag if reasonably regular
        if cv > 0.5 {
            continue;
        }

        let confidence = if cv < 0.10 { 0.97 }
            else if cv < 0.20 { 0.88 }
            else if cv < 0.35 { 0.72 }
            else { 0.50 };

        let total_duration = deduped.last().unwrap() - deduped.first().unwrap();

        candidates.push(BeaconingCandidate {
            src_ip: src_ip.to_string(),
            dst_ip: dst_ip.to_string(),
            dst_port,
            protocol,
            connection_count: deduped.len(),
            mean_interval_secs: (mean * 10.0).round() / 10.0,
            jitter_pct: (cv * 1000.0).round() / 10.0,
            confidence,
            total_duration_secs: (total_duration * 10.0).round() / 10.0,
        });
    }

    // Sort by confidence desc, then connection count desc
    candidates.sort_by(|a, b| {
        b.confidence.total_cmp(&a.confidence)
            .then(b.connection_count.cmp(&a.connection_count))
    });
    candidates.truncate(50);
    candidates
}
