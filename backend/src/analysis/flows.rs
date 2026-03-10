use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;
use crate::analysis::utils::{flow_id, is_private_ip};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionFlow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub packets: usize,
    pub bytes: usize,
    pub first_seen: f64,
    pub last_seen: f64,
    // New fields
    pub flow_id: String,
    pub duration_secs: f64,
    pub bytes_per_second: f64,
    pub service_guess: String,
    pub tcp_flags_seen: String,
    pub payload_preview: Option<String>,
    pub is_suspicious: bool,
    pub state: String, // "established" | "scan" | "reset" | "unknown"
}

pub fn compute(packets: &[PacketMeta]) -> Vec<ConnectionFlow> {
    #[derive(Eq, PartialEq, Hash)]
    struct FlowKey {
        src_ip: String,
        dst_ip: String,
        dst_port: Option<u16>,
        protocol: String,
    }

    struct FlowData {
        src_port: Option<u16>,
        packets: usize,
        bytes: usize,
        first_seen: f64,
        last_seen: f64,
        flags_seen: std::collections::HashSet<String>,
        payload_preview: Option<String>,
        has_syn: bool,
        has_synack: bool,
        has_rst: bool,
    }

    let mut map: HashMap<FlowKey, FlowData> = HashMap::new();

    for pkt in packets {
        let src_ip = match &pkt.src_ip { Some(ip) => ip.clone(), None => continue };
        let dst_ip = match &pkt.dst_ip { Some(ip) => ip.clone(), None => continue };

        let key = FlowKey {
            src_ip,
            dst_ip,
            dst_port: pkt.dst_port,
            protocol: pkt.protocol.clone(),
        };

        let entry = map.entry(key).or_insert_with(|| FlowData {
            src_port: pkt.src_port,
            packets: 0,
            bytes: 0,
            first_seen: pkt.timestamp,
            last_seen: pkt.timestamp,
            flags_seen: std::collections::HashSet::new(),
            payload_preview: None,
            has_syn: false,
            has_synack: false,
            has_rst: false,
        });

        entry.packets += 1;
        entry.bytes += pkt.length;
        if pkt.timestamp < entry.first_seen { entry.first_seen = pkt.timestamp; }
        if pkt.timestamp > entry.last_seen { entry.last_seen = pkt.timestamp; }

        // Track TCP flags
        if let Some(transport) = &pkt.layers.transport {
            if let Some(flags) = &transport.flags {
                for f in flags.split('|') {
                    entry.flags_seen.insert(f.trim().to_string());
                }
                if flags.contains("SYN") && !flags.contains("ACK") { entry.has_syn = true; }
                if flags.contains("SYN") && flags.contains("ACK") { entry.has_synack = true; }
                if flags.contains("RST") { entry.has_rst = true; }
            }
        }

        // Capture first non-empty payload preview
        if entry.payload_preview.is_none() && !pkt.app_payload_preview.is_empty() {
            entry.payload_preview = Some(pkt.app_payload_preview.clone());
        }
    }

    let mut flows: Vec<ConnectionFlow> = map
        .into_iter()
        .map(|(k, v)| {
            let duration = v.last_seen - v.first_seen;
            let bps = if duration > 0.0 { v.bytes as f64 / duration } else { 0.0 };
            let mut flags_vec: Vec<String> = v.flags_seen.into_iter().collect();
            flags_vec.sort();
            let tcp_flags = flags_vec.join("|");

            let state = if k.protocol == "TCP" {
                if v.has_syn && v.has_synack { "established" }
                else if v.has_syn && !v.has_synack { "scan" }
                else if v.has_rst { "reset" }
                else { "unknown" }
            } else {
                "stateless"
            };

            let service = guess_service(k.dst_port);
            let is_suspicious = !is_private_ip(&k.dst_ip) && duration > 1800.0;
            let fid = flow_id(&k.src_ip, &k.dst_ip, Some(v.src_port.unwrap_or(0)), k.dst_port, &k.protocol);

            ConnectionFlow {
                src_ip: k.src_ip,
                dst_ip: k.dst_ip,
                src_port: v.src_port,
                dst_port: k.dst_port,
                protocol: k.protocol,
                packets: v.packets,
                bytes: v.bytes,
                first_seen: v.first_seen,
                last_seen: v.last_seen,
                flow_id: fid,
                duration_secs: duration,
                bytes_per_second: bps,
                service_guess: service.to_string(),
                tcp_flags_seen: tcp_flags,
                payload_preview: v.payload_preview,
                is_suspicious,
                state: state.to_string(),
            }
        })
        .collect();

    flows.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    flows.truncate(2000);
    flows
}

fn guess_service(port: Option<u16>) -> &'static str {
    match port {
        Some(80) => "HTTP",
        Some(443) => "HTTPS",
        Some(22) => "SSH",
        Some(53) => "DNS",
        Some(25) | Some(587) => "SMTP",
        Some(21) => "FTP",
        Some(23) => "Telnet",
        Some(3389) => "RDP",
        Some(8080) | Some(8000) => "HTTP-Alt",
        Some(8443) => "HTTPS-Alt",
        Some(3306) => "MySQL",
        Some(5432) => "PostgreSQL",
        Some(6379) => "Redis",
        Some(27017) => "MongoDB",
        Some(445) | Some(139) | Some(137) => "SMB",
        Some(389) | Some(636) => "LDAP",
        Some(4444) => "Metasploit",
        Some(4443) => "HTTPS-Alt",
        Some(31337) => "Back Orifice",
        Some(6666) | Some(6667) => "IRC/C2",
        _ => "Unknown",
    }
}
