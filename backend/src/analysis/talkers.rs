use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkerStats {
    pub ip: String,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub total_bytes: usize,
    pub first_seen: f64,
    pub last_seen: f64,
    pub protocols: Vec<ProtocolCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCount {
    pub protocol: String,
    pub count: usize,
}

struct IpStats {
    packets_sent: usize,
    packets_received: usize,
    bytes_sent: usize,
    bytes_received: usize,
    first_seen: f64,
    last_seen: f64,
    protocols: HashMap<String, usize>,
}

impl IpStats {
    fn new(ts: f64) -> Self {
        IpStats {
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            first_seen: ts,
            last_seen: ts,
            protocols: HashMap::new(),
        }
    }

    fn update_ts(&mut self, ts: f64) {
        if ts < self.first_seen { self.first_seen = ts; }
        if ts > self.last_seen { self.last_seen = ts; }
    }
}

pub fn compute(packets: &[PacketMeta]) -> (Vec<TalkerStats>, Vec<TalkerStats>) {
    let mut stats: HashMap<String, IpStats> = HashMap::new();

    for pkt in packets {
        let ts = pkt.timestamp;

        if let Some(src) = &pkt.src_ip {
            let entry = stats.entry(src.clone()).or_insert_with(|| IpStats::new(ts));
            entry.update_ts(ts);
            entry.packets_sent += 1;
            entry.bytes_sent += pkt.length;
            *entry.protocols.entry(pkt.protocol.clone()).or_insert(0) += 1;
        }

        if let Some(dst) = &pkt.dst_ip {
            let entry = stats.entry(dst.clone()).or_insert_with(|| IpStats::new(ts));
            entry.update_ts(ts);
            entry.packets_received += 1;
            entry.bytes_received += pkt.length;
        }
    }

    let mut all: Vec<TalkerStats> = stats
        .into_iter()
        .map(|(ip, s)| {
            let mut protocols: Vec<ProtocolCount> = s.protocols
                .into_iter()
                .map(|(protocol, count)| ProtocolCount { protocol, count })
                .collect();
            protocols.sort_by(|a, b| b.count.cmp(&a.count));

            TalkerStats {
                total_bytes: s.bytes_sent + s.bytes_received,
                ip,
                packets_sent: s.packets_sent,
                packets_received: s.packets_received,
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
                first_seen: s.first_seen,
                last_seen: s.last_seen,
                protocols,
            }
        })
        .collect();

    let mut by_sent = all.clone();
    by_sent.sort_by(|a, b| b.bytes_sent.cmp(&a.bytes_sent));
    by_sent.truncate(20);

    let mut by_received = all.clone();
    by_received.sort_by(|a, b| b.bytes_received.cmp(&a.bytes_received));
    by_received.truncate(20);

    (by_sent, by_received)
}
