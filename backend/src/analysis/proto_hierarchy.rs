use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoNode {
    pub name: String,
    pub packet_count: usize,
    pub byte_count: usize,
    pub percent_packets: f32,
    pub percent_bytes: f32,
    pub children: Vec<ProtoNode>,
}

pub fn build(packets: &[PacketMeta]) -> Vec<ProtoNode> {
    if packets.is_empty() {
        return Vec::new();
    }

    let total_packets = packets.len();
    let total_bytes: usize = packets.iter().map(|p| p.length).sum();

    // Build 2-level hierarchy: L2 -> L3 -> L4/App
    // Level 1: Ethernet / Other
    // Level 2: IPv4, IPv6, ARP, ...
    // Level 3: TCP, UDP, ICMP, ...
    // Level 4: HTTP, DNS, TLS, ...

    #[derive(Default)]
    struct ProtoStats {
        packets: usize,
        bytes: usize,
        children: HashMap<String, ProtoStats>,
    }

    let mut root: HashMap<String, ProtoStats> = HashMap::new();

    for pkt in packets {
        let (l2, l3, l4) = classify_packet(pkt);
        let l2_entry = root.entry(l2).or_default();
        l2_entry.packets += 1;
        l2_entry.bytes += pkt.length;
        if !l3.is_empty() {
            let l3_entry = l2_entry.children.entry(l3).or_default();
            l3_entry.packets += 1;
            l3_entry.bytes += pkt.length;
            if !l4.is_empty() {
                let l4_entry = l3_entry.children.entry(l4).or_default();
                l4_entry.packets += 1;
                l4_entry.bytes += pkt.length;
            }
        }
    }

    fn build_node(name: String, stats: ProtoStats, total_packets: usize, total_bytes: usize) -> ProtoNode {
        let mut children: Vec<ProtoNode> = stats.children
            .into_iter()
            .map(|(n, s)| build_node(n, s, total_packets, total_bytes))
            .collect();
        children.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
        ProtoNode {
            name,
            packet_count: stats.packets,
            byte_count: stats.bytes,
            percent_packets: if total_packets > 0 { stats.packets as f32 / total_packets as f32 * 100.0 } else { 0.0 },
            percent_bytes: if total_bytes > 0 { stats.bytes as f32 / total_bytes as f32 * 100.0 } else { 0.0 },
            children,
        }
    }

    let mut nodes: Vec<ProtoNode> = root
        .into_iter()
        .map(|(name, stats)| build_node(name, stats, total_packets, total_bytes))
        .collect();
    nodes.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    nodes
}

fn classify_packet(pkt: &PacketMeta) -> (String, String, String) {
    let l2 = if pkt.layers.ethernet.is_some() || pkt.layers.arp.is_some() {
        "Ethernet"
    } else {
        "Other"
    };

    let l3 = if pkt.protocol == "ARP" {
        "ARP"
    } else if let Some(ip) = &pkt.layers.ip {
        if ip.version == 6 { "IPv6" } else { "IPv4" }
    } else {
        ""
    };

    let l4 = match pkt.protocol.as_str() {
        "TCP" | "HTTP" | "TLS" => {
            let base = if let Some(t) = &pkt.layers.transport { t.protocol.as_str() } else { "TCP" };
            if pkt.protocol == "HTTP" { "HTTP" }
            else if pkt.protocol == "TLS" { "TLS/SSL" }
            else { base }
        }
        "UDP" | "DNS" => {
            if pkt.protocol == "DNS" { "DNS" } else { "UDP" }
        }
        "ICMP" => "ICMP",
        "ICMPv6" => "ICMPv6",
        _ => "",
    };

    (l2.to_string(), l3.to_string(), l4.to_string())
}
