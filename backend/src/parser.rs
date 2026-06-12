use anyhow::{anyhow, Result};
use chrono::{TimeZone, Utc};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use md5;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::analysis::{self, AnalysisResult, Overview};
use crate::reassembly::RawSegment;

const MAX_INSPECTOR_PACKETS: usize = 500_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketMeta {
    pub index: usize,
    pub timestamp: f64,
    pub timestamp_str: String,
    // Stored as IpAddr so HashMap keys built from these fields are 16-byte
    // copies rather than per-packet String allocations. IpAddr's default
    // serde impl emits/accepts the canonical string form, so the JSON wire
    // representation is unchanged.
    pub src_ip: Option<std::net::IpAddr>,
    pub dst_ip: Option<std::net::IpAddr>,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
    pub length: usize,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub info: String,
    pub layers: PacketLayers,
    pub raw_hex: String,
    /// First 64 bytes of application-layer payload (hex-encoded).
    #[serde(default)]
    pub app_payload_preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PacketLayers {
    pub ethernet: Option<EthernetLayer>,
    pub ip: Option<IpLayer>,
    pub transport: Option<TransportLayer>,
    pub application: Option<ApplicationLayer>,
    pub arp: Option<ArpLayer>,
    pub icmp: Option<IcmpLayer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpLayer {
    pub icmp_type: u8,
    pub code: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetLayer {
    pub src_mac: String,
    pub dst_mac: String,
    pub ether_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpLayer {
    pub version: u8,
    pub src: String,
    pub dst: String,
    pub ttl: u8,
    pub protocol: u8,
    pub total_length: u16,
    pub flags: String,
    pub fragment_offset: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportLayer {
    pub protocol: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: Option<String>,
    pub seq: Option<u32>,
    pub ack: Option<u32>,
    pub window: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApplicationLayer {
    pub protocol: String,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpLayer {
    pub operation: String,
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_mac: String,
    pub target_ip: String,
}

pub fn parse_capture(data: &[u8], filename: &str, geo_enabled: bool, config: &crate::config::AppConfig, progress: Arc<AtomicU8>) -> Result<AnalysisResult> {
    progress.store(5, Ordering::Relaxed);
    let mut packets: Vec<PacketMeta> = Vec::new();
    let mut raw_segments: Vec<RawSegment> = Vec::new();
    let mut total_count = 0usize;
    let mut first_ts: Option<f64> = None;
    let mut last_ts: Option<f64> = None;

    // Detect the format from content, not the filename: a pcapng file always
    // starts with the Section Header Block type 0x0A0D0D0A. The previous
    // filename-based fallback could re-run the second parser on top of
    // partially-populated state and double-count packets.
    let is_pcapng = data.len() >= 4 && data[0..4] == [0x0A, 0x0D, 0x0D, 0x0A];
    let result = if is_pcapng {
        parse_pcapng(data, &mut packets, &mut total_count, &mut first_ts, &mut last_ts, &mut raw_segments)
    } else {
        parse_pcap(data, &mut packets, &mut total_count, &mut first_ts, &mut last_ts, &mut raw_segments)
    };

    if let Err(e) = result {
        return Err(anyhow!("Parse error: {}", e));
    }

    progress.store(50, Ordering::Relaxed);

    let duration = match (first_ts, last_ts) {
        (Some(f), Some(l)) => l - f,
        _ => 0.0,
    };

    if total_count > MAX_INSPECTOR_PACKETS {
        eprintln!(
            "Warning: capture contains {} packets; inspector limited to first {}",
            total_count, MAX_INSPECTOR_PACKETS
        );
    }

    let overview = Overview {
        filename: filename.to_string(),
        total_packets: total_count,
        shown_packets: packets.len(),
        capture_duration_secs: duration,
        first_packet: first_ts,
        last_packet: last_ts,
        analyzed_at: Utc::now().to_rfc3339(),
    };

    let streams = crate::reassembly::reassemble(&raw_segments);
    progress.store(55, Ordering::Relaxed);

    analysis::analyze(overview, packets, streams, geo_enabled, config, &progress)
}

fn parse_pcap(
    data: &[u8],
    packets: &mut Vec<PacketMeta>,
    total_count: &mut usize,
    first_ts: &mut Option<f64>,
    last_ts: &mut Option<f64>,
    raw_segments: &mut Vec<RawSegment>,
) -> Result<()> {
    // 1 MiB window: comfortably larger than any legal snaplen-sized record,
    // so refill always makes progress on well-formed captures.
    let mut reader = LegacyPcapReader::new(1024 * 1024, data).map_err(|e| anyhow!("{:?}", e))?;
    let mut linktype = Linktype::ETHERNET;
    // 0xa1b23c4d = nanosecond-precision pcap magic (PCAP_NSEC_MAGIC)
    let mut ts_divisor = 1_000_000.0f64;
    let mut stalled = false;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                stalled = false;
                match &block {
                    PcapBlockOwned::LegacyHeader(hdr) => {
                        linktype = hdr.network;
                        if hdr.magic_number == 0xa1b23c4d {
                            ts_divisor = 1_000_000_000.0;
                        }
                    }
                    PcapBlockOwned::Legacy(pkt) => {
                        let ts = pkt.ts_sec as f64 + pkt.ts_usec as f64 / ts_divisor;
                        if first_ts.is_none() {
                            *first_ts = Some(ts);
                        }
                        *last_ts = Some(ts);
                        *total_count += 1;

                        if *total_count <= MAX_INSPECTOR_PACKETS {
                            let raw_data = pkt.data.to_vec();
                            let meta = decode_packet(*total_count - 1, ts, &raw_data, linktype, raw_segments);
                            packets.push(meta);
                        }
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                // The next record straddles the buffer window — refill and
                // continue. Two Incompletes with no record consumed in
                // between means a truncated final record; keep what we have.
                if stalled { break; }
                stalled = true;
                reader.refill().map_err(|e| anyhow!("pcap refill error: {:?}", e))?;
            }
            Err(e) => return Err(anyhow!("pcap read error: {:?}", e)),
        }
    }
    Ok(())
}

/// Read the `if_tsresol` option from a pcapng Interface Description Block.
/// Returns timestamp units per second (e.g. 1_000_000 for µs, 1_000_000_000 for ns).
/// Defaults to 1_000_000 (microseconds) if absent, per the pcapng spec.
fn read_tsresol(options: &[PcapNGOption<'_>]) -> f64 {
    for opt in options {
        if opt.code == OptionCode(9) {
            if let Some(&byte) = opt.value.first() {
                // bit 7: 0 = power-of-10, 1 = power-of-2
                return if byte & 0x80 == 0 {
                    10f64.powi((byte & 0x7f) as i32)
                } else {
                    2f64.powi((byte & 0x7f) as i32)
                };
            }
        }
    }
    1_000_000.0 // default: microseconds
}

fn parse_pcapng(
    data: &[u8],
    packets: &mut Vec<PacketMeta>,
    total_count: &mut usize,
    first_ts: &mut Option<f64>,
    last_ts: &mut Option<f64>,
    raw_segments: &mut Vec<RawSegment>,
) -> Result<()> {
    // 1 MiB window: comfortably larger than any legal snaplen-sized block,
    // so refill always makes progress on well-formed captures.
    let mut reader = PcapNGReader::new(1024 * 1024, data).map_err(|e| anyhow!("{:?}", e))?;
    let mut linktype = Linktype::ETHERNET;
    let mut ts_resolution: f64 = 1_000_000.0; // default microseconds
    let mut stalled = false;

    loop {
        match reader.next() {
            Ok((offset, block)) => {
                stalled = false;
                match &block {
                    PcapBlockOwned::NG(Block::SectionHeader(_)) => {}
                    PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                        linktype = idb.linktype;
                        ts_resolution = read_tsresol(&idb.options);
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                        let ts_raw = (epb.ts_high as u64) << 32 | epb.ts_low as u64;
                        let ts = ts_raw as f64 / ts_resolution;
                        if first_ts.is_none() {
                            *first_ts = Some(ts);
                        }
                        *last_ts = Some(ts);
                        *total_count += 1;
                        if *total_count <= MAX_INSPECTOR_PACKETS {
                            let raw_data = epb.data.to_vec();
                            let meta = decode_packet(*total_count - 1, ts, &raw_data, linktype, raw_segments);
                            packets.push(meta);
                        }
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                        let ts = first_ts.unwrap_or(0.0);
                        *total_count += 1;
                        if *total_count <= MAX_INSPECTOR_PACKETS {
                            let raw_data = spb.data.to_vec();
                            let meta = decode_packet(*total_count - 1, ts, &raw_data, linktype, raw_segments);
                            packets.push(meta);
                        }
                    }
                    _ => {}
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                // The next block straddles the buffer window — refill and
                // continue. Two Incompletes with no block consumed in
                // between means a truncated final block; keep what we have.
                if stalled { break; }
                stalled = true;
                reader.refill().map_err(|e| anyhow!("pcapng refill error: {:?}", e))?;
            }
            Err(e) => return Err(anyhow!("pcapng read error: {:?}", e)),
        }
    }
    Ok(())
}

fn decode_packet(index: usize, timestamp: f64, data: &[u8], linktype: Linktype, raw_segments: &mut Vec<RawSegment>) -> PacketMeta {
    let timestamp_str = {
        let secs = timestamp as i64;
        let nsecs = ((timestamp - secs as f64) * 1e9) as u32;
        Utc.timestamp_opt(secs, nsecs)
            .single()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S%.6f UTC").to_string())
            .unwrap_or_else(|| format!("{:.6}", timestamp))
    };

    let raw_hex = hex_dump(&data[..data.len().min(256)]);
    let mut meta = PacketMeta {
        index,
        timestamp,
        timestamp_str,
        src_ip: None,
        dst_ip: None,
        src_port: None,
        dst_port: None,
        protocol: "Unknown".to_string(),
        length: data.len(),
        src_mac: None,
        dst_mac: None,
        info: String::new(),
        layers: PacketLayers::default(),
        raw_hex,
        app_payload_preview: String::new(),
    };

    match linktype {
        Linktype::ETHERNET => decode_ethernet(data, &mut meta, raw_segments),
        Linktype::LINUX_SLL => decode_sll(data, &mut meta, raw_segments),
        Linktype::LINUX_SLL2 => decode_sll2(data, &mut meta, raw_segments),
        _ => {
            meta.protocol = format!("Linktype({:?})", linktype);
        }
    }

    meta
}

// Strip stacked 802.1Q (0x8100) / 802.1ad QinQ (0x88A8) tags — each is 4
// bytes: a 2-byte TCI holding the VLAN ID, then the inner ethertype — and
// dispatch the payload to the right L3 decoder. Without the stripping,
// tagged frames never get IP-decoded and are invisible to every detector.
// Returns a display string ("0x0800 (IPv4, VLAN 20)") for the link layer.
fn dispatch_ethertype(
    mut ether_type: u16,
    mut payload: &[u8],
    meta: &mut PacketMeta,
    raw_segments: &mut Vec<RawSegment>,
) -> String {
    let mut vlan_ids: Vec<u16> = Vec::new();
    while (ether_type == 0x8100 || ether_type == 0x88A8) && payload.len() >= 4 {
        vlan_ids.push(u16::from_be_bytes([payload[0], payload[1]]) & 0x0FFF);
        ether_type = u16::from_be_bytes([payload[2], payload[3]]);
        payload = &payload[4..];
    }

    let ether_type_str = match ether_type {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        0x8100 => "VLAN",
        _ => "Unknown",
    };
    let vlan_suffix = if vlan_ids.is_empty() {
        String::new()
    } else {
        format!(", VLAN {}", vlan_ids.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("."))
    };

    match ether_type {
        0x0800 => decode_ipv4(payload, meta, raw_segments),
        0x0806 => decode_arp(payload, meta),
        0x86DD => decode_ipv6(payload, meta, raw_segments),
        _ => {
            meta.protocol = format!("Ethernet (0x{:04X})", ether_type);
        }
    }

    format!("0x{:04X} ({}{})", ether_type, ether_type_str, vlan_suffix)
}

fn decode_ethernet(data: &[u8], meta: &mut PacketMeta, raw_segments: &mut Vec<RawSegment>) {
    if data.len() < 14 {
        return;
    }

    let dst_mac = format_mac(&data[0..6]);
    let src_mac = format_mac(&data[6..12]);
    let ether_type = u16::from_be_bytes([data[12], data[13]]);

    meta.src_mac = Some(src_mac.clone());
    meta.dst_mac = Some(dst_mac.clone());

    let display = dispatch_ethertype(ether_type, &data[14..], meta, raw_segments);
    meta.layers.ethernet = Some(EthernetLayer {
        src_mac,
        dst_mac,
        ether_type: display,
    });
}

// SLL packet-type field: where the packet was headed relative to the
// capturing host. Shown in place of the destination MAC, which cooked
// captures don't record.
fn sll_direction(packet_type: u16) -> &'static str {
    match packet_type {
        0 => "(to this host)",
        1 => "(broadcast)",
        2 => "(multicast)",
        3 => "(to other host)",
        4 => "(sent by this host)",
        _ => "(unknown direction)",
    }
}

// Linux cooked capture v1 (linktype 113), produced by `tcpdump -i any`:
// packet type (2), ARPHRD type (2), link address length (2), link address
// (8, zero-padded), ethertype (2), then the normal L3 payload.
fn decode_sll(data: &[u8], meta: &mut PacketMeta, raw_segments: &mut Vec<RawSegment>) {
    if data.len() < 16 {
        return;
    }

    let packet_type = u16::from_be_bytes([data[0], data[1]]);
    let addr_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let src_mac = if addr_len == 6 {
        let mac = format_mac(&data[6..12]);
        meta.src_mac = Some(mac.clone());
        mac
    } else {
        "—".to_string()
    };

    let ether_type = u16::from_be_bytes([data[14], data[15]]);
    let display = dispatch_ethertype(ether_type, &data[16..], meta, raw_segments);
    meta.layers.ethernet = Some(EthernetLayer {
        src_mac,
        dst_mac: sll_direction(packet_type).to_string(),
        ether_type: format!("{} [SLL]", display),
    });
}

// Linux cooked capture v2 (linktype 276), default for newer tcpdump `-i any`:
// ethertype (2), reserved (2), interface index (4), ARPHRD type (2),
// packet type (1), link address length (1), link address (8, zero-padded).
fn decode_sll2(data: &[u8], meta: &mut PacketMeta, raw_segments: &mut Vec<RawSegment>) {
    if data.len() < 20 {
        return;
    }

    let ether_type = u16::from_be_bytes([data[0], data[1]]);
    let packet_type = data[10] as u16;
    let addr_len = data[11] as usize;
    let src_mac = if addr_len == 6 {
        let mac = format_mac(&data[12..18]);
        meta.src_mac = Some(mac.clone());
        mac
    } else {
        "—".to_string()
    };

    let display = dispatch_ethertype(ether_type, &data[20..], meta, raw_segments);
    meta.layers.ethernet = Some(EthernetLayer {
        src_mac,
        dst_mac: sll_direction(packet_type).to_string(),
        ether_type: format!("{} [SLL2]", display),
    });
}

fn decode_arp(data: &[u8], meta: &mut PacketMeta) {
    if data.len() < 28 {
        meta.protocol = "ARP".to_string();
        return;
    }
    let operation = u16::from_be_bytes([data[6], data[7]]);
    let op_str = match operation {
        1 => "Request",
        2 => "Reply",
        _ => "Unknown",
    };
    let sender_mac = format_mac(&data[8..14]);
    let sender_addr = std::net::Ipv4Addr::new(data[14], data[15], data[16], data[17]);
    let target_mac = format_mac(&data[18..24]);
    let target_addr = std::net::Ipv4Addr::new(data[24], data[25], data[26], data[27]);
    let sender_ip = sender_addr.to_string();
    let target_ip = target_addr.to_string();

    meta.protocol = "ARP".to_string();
    meta.src_ip = Some(std::net::IpAddr::V4(sender_addr));
    meta.dst_ip = Some(std::net::IpAddr::V4(target_addr));
    meta.info = format!("ARP {} {} is-at {}", op_str, sender_ip, sender_mac);
    meta.layers.arp = Some(ArpLayer {
        operation: op_str.to_string(),
        sender_mac,
        sender_ip,
        target_mac,
        target_ip,
    });
}

fn decode_ipv4(data: &[u8], meta: &mut PacketMeta, raw_segments: &mut Vec<RawSegment>) {
    if data.len() < 20 {
        return;
    }
    let ihl = (data[0] & 0x0F) as usize * 4;
    let total_length = u16::from_be_bytes([data[2], data[3]]);
    let ttl = data[8];
    let protocol = data[9];
    let src_addr = std::net::Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let dst_addr = std::net::Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    let src = src_addr.to_string();
    let dst = dst_addr.to_string();
    let flags_raw = (data[6] >> 5) & 0x07;
    let frag_offset = u16::from_be_bytes([data[6] & 0x1F, data[7]]);
    let flags = format!(
        "{}{}{}",
        if flags_raw & 0x04 != 0 { "Reserved " } else { "" },
        if flags_raw & 0x02 != 0 { "DF " } else { "" },
        if flags_raw & 0x01 != 0 { "MF" } else { "" }
    )
    .trim()
    .to_string();

    meta.src_ip = Some(std::net::IpAddr::V4(src_addr));
    meta.dst_ip = Some(std::net::IpAddr::V4(dst_addr));
    meta.layers.ip = Some(IpLayer {
        version: 4,
        src: src.clone(),
        dst: dst.clone(),
        ttl,
        protocol,
        total_length,
        flags,
        fragment_offset: frag_offset,
    });

    // Minimum legal IHL is 5 (20 bytes). A smaller value is a malformed
    // header — skip protocol decode rather than slicing at the wrong offset.
    if ihl < 20 { return; }
    let payload = if ihl < data.len() { &data[ihl..] } else { &[] };
    decode_ip_protocol(protocol, payload, meta, &src, &dst, raw_segments);
}

fn decode_ipv6(data: &[u8], meta: &mut PacketMeta, raw_segments: &mut Vec<RawSegment>) {
    if data.len() < 40 {
        return;
    }
    let next_header = data[6];
    let src_octets: [u8; 16] = data[8..24].try_into().unwrap_or([0; 16]);
    let dst_octets: [u8; 16] = data[24..40].try_into().unwrap_or([0; 16]);
    let src_addr = std::net::Ipv6Addr::from(src_octets);
    let dst_addr = std::net::Ipv6Addr::from(dst_octets);
    let src = format_ipv6(&data[8..24]);
    let dst = format_ipv6(&data[24..40]);

    meta.src_ip = Some(std::net::IpAddr::V6(src_addr));
    meta.dst_ip = Some(std::net::IpAddr::V6(dst_addr));
    meta.layers.ip = Some(IpLayer {
        version: 6,
        src: src.clone(),
        dst: dst.clone(),
        ttl: data[7],
        protocol: next_header,
        total_length: u16::from_be_bytes([data[4], data[5]]),
        flags: String::new(),
        fragment_offset: 0,
    });

    let payload = &data[40..];
    decode_ip_protocol(next_header, payload, meta, &src, &dst, raw_segments);
}

fn decode_ip_protocol(protocol: u8, payload: &[u8], meta: &mut PacketMeta, src: &str, dst: &str, raw_segments: &mut Vec<RawSegment>) {
    match protocol {
        6 => decode_tcp(payload, meta, src, dst, raw_segments),
        17 => decode_udp(payload, meta, src, dst),
        1 => decode_icmp(payload, meta),
        58 => {
            meta.protocol = "ICMPv6".to_string();
            meta.info = "ICMPv6".to_string();
        }
        _ => {
            meta.protocol = format!("IP({})", protocol);
        }
    }
}

fn decode_tcp(data: &[u8], meta: &mut PacketMeta, _src: &str, _dst: &str, raw_segments: &mut Vec<RawSegment>) {
    if data.len() < 20 {
        meta.protocol = "TCP".to_string();
        return;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let seq = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let ack = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
    let data_offset = ((data[12] >> 4) as usize) * 4;
    let flags_byte = data[13];
    let window = u16::from_be_bytes([data[14], data[15]]);

    let flags = tcp_flags(flags_byte);
    meta.src_port = Some(src_port);
    meta.dst_port = Some(dst_port);
    meta.protocol = "TCP".to_string();
    meta.info = format!(
        "{} -> {} [{}] Seq={} Ack={} Win={}",
        src_port, dst_port, flags, seq, ack, window
    );

    meta.layers.transport = Some(TransportLayer {
        protocol: "TCP".to_string(),
        src_port,
        dst_port,
        flags: Some(flags),
        seq: Some(seq),
        ack: Some(ack),
        window: Some(window),
    });

    let app_payload = if data_offset < data.len() {
        &data[data_offset..]
    } else {
        &[]
    };

    // Store first 64 bytes of app payload as hex preview
    if !app_payload.is_empty() {
        let preview_len = app_payload.len().min(64);
        meta.app_payload_preview = app_payload[..preview_len]
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join("");
    }

    // Collect raw segment for TCP reassembly
    if !app_payload.is_empty() {
        if let (Some(src_ip), Some(dst_ip)) = (&meta.src_ip, &meta.dst_ip) {
            raw_segments.push(RawSegment {
                src_ip: src_ip.to_string(),
                dst_ip: dst_ip.to_string(),
                src_port,
                dst_port,
                seq,
                payload: app_payload.to_vec(),
                timestamp: meta.timestamp,
                packet_idx: meta.index,
                is_syn: flags_byte & 0x02 != 0 && flags_byte & 0x10 == 0,
            });
        }
    }

    if (src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080)
        && !app_payload.is_empty()
    {
        if let Some(http) = decode_http(app_payload) {
            meta.protocol = "HTTP".to_string();
            meta.layers.application = Some(ApplicationLayer {
                protocol: "HTTP".to_string(),
                data: http,
            });
        }
    } else if !app_payload.is_empty() {
        // TLS detection: ContentType=0x16 (Handshake), major version=0x03.
        // In TLS 1.2, ServerHello + Certificate are often delivered together
        // in the same TCP segment as multiple back-to-back TLS records, so we
        // walk every record in the segment.
        if app_payload.len() >= 5 && app_payload[0] == 0x16 && app_payload[1] == 0x03 {
            if let Some(tls) = decode_tls_records(app_payload) {
                meta.protocol = "TLS".to_string();
                meta.layers.application = Some(ApplicationLayer {
                    protocol: "TLS".to_string(),
                    data: tls,
                });
            }
        }
    }
}

/// Parse the body of a TLS ClientHello handshake message (post handshake
/// header). Returns JSON with SNI, JA3 components, cipher suites, extensions.
fn decode_client_hello_body(body: &[u8]) -> Option<serde_json::Value> {
    if body.len() < 34 {
        return None;
    }

    let mut off = 0usize;
    // legacy_version (2 bytes) - used for JA3 SSLVersion
    if off + 2 > body.len() { return None; }
    let legacy_version = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 2;
    // random (32 bytes)
    off += 32;
    if off > body.len() { return None; }
    // session_id length (1 byte) + session_id
    if off >= body.len() { return None; }
    let sid_len = body[off] as usize;
    off += 1 + sid_len;
    if off + 2 > body.len() { return None; }
    // cipher_suites length (2 bytes)
    let cs_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if off + cs_len > body.len() { return None; }
    let cs_data = &body[off..off + cs_len];
    let cipher_suites: Vec<u16> = cs_data.chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .filter(|&v| !is_grease(v))
        .collect();
    off += cs_len;
    // compression_methods length (1 byte) + methods
    if off >= body.len() { return None; }
    let cm_len = body[off] as usize;
    off += 1 + cm_len;
    if off + 2 > body.len() {
        // No extensions — build minimal JA3
        let ja3_str = format!("{},{},,,",
            legacy_version,
            cipher_suites.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-")
        );
        let ja3_hash = format!("{:x}", md5::compute(ja3_str.as_bytes()));
        return Some(serde_json::json!({
            "type": "ClientHello",
            "legacy_version": legacy_version,
            "cipher_suites": cipher_suites,
            "extensions": [],
            "sni": null,
            "supported_groups": [],
            "ec_point_formats": [],
            "ja3_string": ja3_str,
            "ja3_hash": ja3_hash,
        }));
    }
    // Extensions length (2 bytes)
    let ext_total_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if off + ext_total_len > body.len() { return None; }
    let ext_data = &body[off..off + ext_total_len];

    let mut sni: Option<String> = None;
    let mut ext_types: Vec<u16> = Vec::new();
    let mut supported_groups: Vec<u16> = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();

    let mut eoff = 0usize;
    while eoff + 4 <= ext_data.len() {
        let ext_type = u16::from_be_bytes([ext_data[eoff], ext_data[eoff + 1]]);
        let ext_len = u16::from_be_bytes([ext_data[eoff + 2], ext_data[eoff + 3]]) as usize;
        eoff += 4;
        if eoff + ext_len > ext_data.len() { break; }
        let ext_body = &ext_data[eoff..eoff + ext_len];
        if !is_grease(ext_type) {
            ext_types.push(ext_type);
        }
        match ext_type {
            0x0000 => {
                // SNI extension
                if ext_body.len() >= 5 {
                    let name_type = ext_body[2];
                    if name_type == 0 {
                        let name_len = u16::from_be_bytes([ext_body[3], ext_body[4]]) as usize;
                        if ext_body.len() >= 5 + name_len {
                            if let Ok(s) = std::str::from_utf8(&ext_body[5..5 + name_len]) {
                                sni = Some(s.to_string());
                            }
                        }
                    }
                }
            }
            0x000A => {
                // Supported Groups (elliptic_curves)
                if ext_body.len() >= 2 {
                    let groups_len = u16::from_be_bytes([ext_body[0], ext_body[1]]) as usize;
                    let groups_data = &ext_body[2..];
                    supported_groups = groups_data[..groups_len.min(groups_data.len())]
                        .chunks(2)
                        .filter(|c| c.len() == 2)
                        .map(|c| u16::from_be_bytes([c[0], c[1]]))
                        .filter(|&v| !is_grease(v))
                        .collect();
                }
            }
            0x000B => {
                // EC Point Formats
                if !ext_body.is_empty() {
                    let fmt_len = ext_body[0] as usize;
                    if ext_body.len() >= 1 + fmt_len {
                        ec_point_formats = ext_body[1..1 + fmt_len].to_vec();
                    }
                }
            }
            _ => {}
        }
        eoff += ext_len;
    }

    let ja3_str = format!(
        "{},{},{},{},{}",
        legacy_version,
        cipher_suites.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
        ext_types.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
        supported_groups.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
        ec_point_formats.iter().map(|v| v.to_string()).collect::<Vec<_>>().join("-"),
    );
    let ja3_hash = format!("{:x}", md5::compute(ja3_str.as_bytes()));

    Some(serde_json::json!({
        "type": "ClientHello",
        "legacy_version": legacy_version,
        "cipher_suites": cipher_suites,
        "extensions": ext_types,
        "sni": sni,
        "supported_groups": supported_groups,
        "ec_point_formats": ec_point_formats,
        "ja3_string": ja3_str,
        "ja3_hash": ja3_hash,
    }))
}

/// Walk every TLS record in `data` and merge whatever handshake info is
/// available across them — ClientHello on its own, or ServerHello +
/// Certificate combined when the server flight is in one TCP segment.
fn decode_tls_records(data: &[u8]) -> Option<serde_json::Value> {
    let mut off = 0usize;
    let mut merged: Option<serde_json::Map<String, serde_json::Value>> = None;
    // Cap iteration so a crafted stream of zero-length records can't loop.
    for _ in 0..32 {
        if off + 5 > data.len() { break; }
        if data[off] != 0x16 || data[off + 1] != 0x03 { break; }
        let record_len = u16::from_be_bytes([data[off + 3], data[off + 4]]) as usize;
        if record_len == 0 || off + 5 + record_len > data.len() { break; }
        let record = &data[off + 5..off + 5 + record_len];
        // Walk handshake messages inside this record.
        let mut hoff = 0usize;
        while hoff + 4 <= record.len() {
            let h_type = record[hoff];
            let h_len = ((record[hoff + 1] as usize) << 16)
                | ((record[hoff + 2] as usize) << 8)
                | record[hoff + 3] as usize;
            if hoff + 4 + h_len > record.len() { break; }
            let h_body = &record[hoff + 4..hoff + 4 + h_len];
            let extracted = match h_type {
                0x01 => decode_client_hello_body(h_body),
                0x02 => decode_server_hello_body(h_body),
                0x0B => decode_certificate_body(h_body),
                _ => None,
            };
            if let Some(serde_json::Value::Object(map)) = extracted {
                let target = merged.get_or_insert_with(serde_json::Map::new);
                for (k, v) in map { target.insert(k, v); }
            }
            hoff += 4 + h_len;
        }
        off += 5 + record_len;
    }
    merged.map(serde_json::Value::Object)
}

/// Parse the body (post handshake-header) of a Certificate handshake. Picks
/// the leaf certificate (first in the chain), extracts subject/issuer/
/// not_after, and derives is_self_signed and is_expired.
fn decode_certificate_body(body: &[u8]) -> Option<serde_json::Value> {
    if body.len() < 3 { return None; }
    let chain_len = ((body[0] as usize) << 16) | ((body[1] as usize) << 8) | body[2] as usize;
    if 3 + chain_len > body.len() { return None; }
    let mut off = 3usize;
    let end = 3 + chain_len;
    if off + 3 > end { return None; }
    let cert_len = ((body[off] as usize) << 16) | ((body[off + 1] as usize) << 8) | body[off + 2] as usize;
    off += 3;
    if cert_len == 0 || off + cert_len > end { return None; }
    let cert_der = &body[off..off + cert_len];

    let (_, parsed) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let tbs = parsed.tbs_certificate;
    let subject = tbs.subject.to_string();
    let issuer = tbs.issuer.to_string();
    let not_before = tbs.validity.not_before.to_rfc2822().ok();
    let not_after = tbs.validity.not_after.to_rfc2822().ok();
    let is_self_signed = subject == issuer;
    // Compare validity to current wall clock. We're parsing PCAPs after the
    // fact so this still means "expired by now"; the original PCAP timestamp
    // would be more accurate but isn't available at this layer.
    let now = x509_parser::time::ASN1Time::now();
    let is_expired = tbs.validity.not_after < now;

    Some(serde_json::json!({
        "type": "Certificate",
        "cert_subject": subject,
        "cert_issuer": issuer,
        "cert_not_before": not_before,
        "cert_not_after": not_after,
        "is_self_signed": is_self_signed,
        "is_expired": is_expired,
    }))
}

/// Parse the body of a TLS ServerHello handshake message. Extracts the
/// negotiated version and cipher suite. Bounds-checked throughout.
fn decode_server_hello_body(body: &[u8]) -> Option<serde_json::Value> {
    // ServerHello minimum: version(2) random(32) sid_len(1) cipher(2) compression(1)
    if body.len() < 38 { return None; }

    let mut off = 0usize;
    let legacy_version = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 2;
    off += 32; // random
    if off >= body.len() { return None; }
    let sid_len = body[off] as usize;
    off += 1 + sid_len;
    if off + 2 > body.len() { return None; }
    let cipher_suite = u16::from_be_bytes([body[off], body[off + 1]]);
    off += 2;
    if off >= body.len() { return None; }
    let _compression = body[off];
    off += 1;

    // Optional extensions — look for supported_versions (0x002B) which
    // carries the *actual* TLS 1.3 version. legacy_version is pinned to
    // 0x0303 in TLS 1.3 ServerHello.
    let mut negotiated_version = legacy_version;
    if off + 2 <= body.len() {
        let ext_total_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        if off + ext_total_len <= body.len() {
            let ext_data = &body[off..off + ext_total_len];
            let mut eoff = 0usize;
            while eoff + 4 <= ext_data.len() {
                let ext_type = u16::from_be_bytes([ext_data[eoff], ext_data[eoff + 1]]);
                let ext_len = u16::from_be_bytes([ext_data[eoff + 2], ext_data[eoff + 3]]) as usize;
                eoff += 4;
                if eoff + ext_len > ext_data.len() { break; }
                if ext_type == 0x002B && ext_len >= 2 {
                    negotiated_version = u16::from_be_bytes([ext_data[eoff], ext_data[eoff + 1]]);
                }
                eoff += ext_len;
            }
        }
    }

    let version_str = match negotiated_version {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    };

    Some(serde_json::json!({
        "type": "ServerHello",
        "legacy_version": legacy_version,
        "negotiated_version": negotiated_version,
        "negotiated_version_name": version_str,
        "cipher_suite": cipher_suite,
    }))
}

fn is_grease(v: u16) -> bool {
    // GREASE values: 0x?A?A pattern
    let lo = (v & 0xFF) as u8;
    let hi = ((v >> 8) & 0xFF) as u8;
    lo == hi && lo & 0x0F == 0x0A
}

fn decode_udp(data: &[u8], meta: &mut PacketMeta, _src: &str, _dst: &str) {
    if data.len() < 8 {
        meta.protocol = "UDP".to_string();
        return;
    }
    let src_port = u16::from_be_bytes([data[0], data[1]]);
    let dst_port = u16::from_be_bytes([data[2], data[3]]);
    let length = u16::from_be_bytes([data[4], data[5]]);

    meta.src_port = Some(src_port);
    meta.dst_port = Some(dst_port);
    meta.protocol = "UDP".to_string();
    meta.info = format!("{} -> {} Len={}", src_port, dst_port, length);

    meta.layers.transport = Some(TransportLayer {
        protocol: "UDP".to_string(),
        src_port,
        dst_port,
        flags: None,
        seq: None,
        ack: None,
        window: None,
    });

    let payload = &data[8..];
    if src_port == 53 || dst_port == 53 {
        if let Some(dns) = decode_dns(payload) {
            meta.protocol = "DNS".to_string();
            meta.layers.application = Some(ApplicationLayer {
                protocol: "DNS".to_string(),
                data: dns,
            });
        }
    }
}

fn decode_icmp(data: &[u8], meta: &mut PacketMeta) {
    meta.protocol = "ICMP".to_string();
    if data.len() >= 2 {
        let icmp_type = data[0];
        let code = data[1];
        meta.layers.icmp = Some(IcmpLayer { icmp_type, code });
        meta.info = match (icmp_type, code) {
            (0, _) => "Echo Reply".to_string(),
            (8, _) => "Echo Request".to_string(),
            (3, 0) => "Destination Unreachable (Net)".to_string(),
            (3, 1) => "Destination Unreachable (Host)".to_string(),
            (3, 3) => "Destination Unreachable (Port)".to_string(),
            (11, 0) => "Time Exceeded (TTL)".to_string(),
            _ => format!("ICMP Type={} Code={}", icmp_type, code),
        };
    }
}

fn decode_http(data: &[u8]) -> Option<serde_json::Value> {
    let text = std::str::from_utf8(data).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() {
        return None;
    }
    let first = lines[0];
    let parts: Vec<&str> = first.splitn(3, ' ').collect();
    if parts.len() == 3 {
        let method = parts[0];
        if matches!(
            method,
            "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH"
        ) {
            let mut headers = serde_json::Map::new();
            for line in &lines[1..] {
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(": ") {
                    headers.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                }
            }
            return Some(serde_json::json!({
                "type": "request",
                "method": method,
                "uri": parts[1],
                "version": parts[2],
                "headers": headers
            }));
        }
        if parts[0].starts_with("HTTP/") {
            let status: u16 = parts[1].parse().unwrap_or(0);
            let mut headers = serde_json::Map::new();
            for line in &lines[1..] {
                if line.is_empty() {
                    break;
                }
                if let Some((k, v)) = line.split_once(": ") {
                    headers.insert(k.to_string(), serde_json::Value::String(v.to_string()));
                }
            }
            return Some(serde_json::json!({
                "type": "response",
                "version": parts[0],
                "status": status,
                "reason": parts[2],
                "headers": headers
            }));
        }
    }
    None
}

fn decode_dns(data: &[u8]) -> Option<serde_json::Value> {
    if data.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 1;
    let qcount = u16::from_be_bytes([data[4], data[5]]);
    let acount = u16::from_be_bytes([data[6], data[7]]);

    let mut questions = Vec::new();
    let mut offset = 12usize;

    for _ in 0..qcount {
        if let Some((name, new_offset)) = parse_dns_name(data, offset) {
            offset = new_offset;
            if offset + 4 <= data.len() {
                let qtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let qclass = u16::from_be_bytes([data[offset + 2], data[offset + 3]]);
                offset += 4;
                questions.push(serde_json::json!({
                    "name": name,
                    "type": dns_type_str(qtype),
                    "class": qclass
                }));
            }
        } else {
            break;
        }
    }

    let mut answers = Vec::new();
    for _ in 0..acount {
        if let Some((name, new_offset)) = parse_dns_name(data, offset) {
            offset = new_offset;
            if offset + 10 <= data.len() {
                let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
                let ttl = u32::from_be_bytes([
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ]);
                let rdlen = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
                offset += 10;
                let rdata = if offset + rdlen <= data.len() {
                    &data[offset..offset + rdlen]
                } else {
                    &[]
                };
                let rdata_str = match rtype {
                    1 if rdata.len() == 4 => {
                        format!("{}.{}.{}.{}", rdata[0], rdata[1], rdata[2], rdata[3])
                    }
                    28 if rdata.len() == 16 => format_ipv6(rdata),
                    5 | 2 | 12 => parse_dns_name(rdata, 0)
                        .map(|(n, _)| n)
                        .unwrap_or_default(),
                    _ => hex_short(rdata),
                };
                offset += rdlen;
                answers.push(serde_json::json!({
                    "name": name,
                    "type": dns_type_str(rtype),
                    "ttl": ttl,
                    "data": rdata_str
                }));
            }
        } else {
            break;
        }
    }

    Some(serde_json::json!({
        "id": id,
        "is_response": qr == 1,
        "questions": questions,
        "answers": answers
    }))
}

fn parse_dns_name(data: &[u8], offset: usize) -> Option<(String, usize)> {
    parse_dns_name_inner(data, offset, &mut 10)
}

fn parse_dns_name_inner(data: &[u8], mut offset: usize, jump_limit: &mut u8) -> Option<(String, usize)> {
    let mut name = String::new();

    loop {
        if offset >= data.len() {
            return None;
        }
        let len = data[offset] as usize;
        if len == 0 {
            offset += 1;
            break;
        } else if len & 0xC0 == 0xC0 {
            if offset + 1 >= data.len() {
                return None;
            }
            let ptr = (len & 0x3F) << 8 | data[offset + 1] as usize;
            offset += 2;
            if *jump_limit == 0 {
                return None;
            }
            *jump_limit -= 1;
            let (part, _) = parse_dns_name_inner(data, ptr, jump_limit)?;
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(&part);
            return Some((name, offset));
        } else {
            offset += 1;
            if offset + len > data.len() {
                return None;
            }
            if !name.is_empty() {
                name.push('.');
            }
            name.push_str(
                std::str::from_utf8(&data[offset..offset + len]).unwrap_or("?"),
            );
            offset += len;
        }
    }
    Some((name, offset))
}

fn tcp_flags(f: u8) -> String {
    let mut flags = Vec::new();
    if f & 0x01 != 0 { flags.push("FIN"); }
    if f & 0x02 != 0 { flags.push("SYN"); }
    if f & 0x04 != 0 { flags.push("RST"); }
    if f & 0x08 != 0 { flags.push("PSH"); }
    if f & 0x10 != 0 { flags.push("ACK"); }
    if f & 0x20 != 0 { flags.push("URG"); }
    if f & 0x40 != 0 { flags.push("ECE"); }
    if f & 0x80 != 0 { flags.push("CWR"); }
    if flags.is_empty() { "NONE".to_string() } else { flags.join("|") }
}

fn format_mac(b: &[u8]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        b[0], b[1], b[2], b[3], b[4], b[5]
    )
}

fn format_ipv6(b: &[u8]) -> String {
    if b.len() < 16 {
        return "::".to_string();
    }
    let groups: Vec<String> = b
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect();
    groups.join(":")
}

fn dns_type_str(t: u16) -> &'static str {
    match t {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        255 => "ANY",
        _ => "Unknown",
    }
}

fn hex_dump(data: &[u8]) -> String {
    let lines: Vec<String> = data
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{:02X}", b)).collect();
            let ascii: String = chunk
                .iter()
                .map(|&b| if b >= 0x20 && b < 0x7F { b as char } else { '.' })
                .collect();
            format!("{:04X}  {:<48}  {}", i * 16, hex.join(" "), ascii)
        })
        .collect();
    lines.join("\n")
}

fn hex_short(data: &[u8]) -> String {
    data.iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}
