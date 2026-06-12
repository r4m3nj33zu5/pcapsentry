use std::collections::HashMap;
use std::net::IpAddr;

pub struct RawSegment {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub payload: Vec<u8>,
    pub timestamp: f64,
    pub packet_idx: usize,
    pub is_syn: bool,
}

#[derive(Clone, Default, Debug)]
pub struct ReassembledStream {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub forward_payload: Vec<u8>,
    pub backward_payload: Vec<u8>,
    pub first_packet_idx: usize,
    pub timestamp: f64,
}

#[derive(Hash, Eq, PartialEq, Clone)]
struct StreamKey { a_ip: String, a_port: u16, b_ip: String, b_port: u16 }

impl StreamKey {
    fn new(seg: &RawSegment) -> (Self, bool) {
        // Compare addresses numerically so "10.0.0.2" doesn't sort before
        // "9.0.0.1". Fall back to string compare if either side is unparseable.
        let src_first = match (seg.src_ip.parse::<IpAddr>(), seg.dst_ip.parse::<IpAddr>()) {
            (Ok(s), Ok(d)) => s < d || (s == d && seg.src_port <= seg.dst_port),
            _ => seg.src_ip < seg.dst_ip || (seg.src_ip == seg.dst_ip && seg.src_port <= seg.dst_port),
        };
        if src_first {
            (StreamKey { a_ip: seg.src_ip.clone(), a_port: seg.src_port, b_ip: seg.dst_ip.clone(), b_port: seg.dst_port }, true)
        } else {
            (StreamKey { a_ip: seg.dst_ip.clone(), a_port: seg.dst_port, b_ip: seg.src_ip.clone(), b_port: seg.src_port }, false)
        }
    }
}

struct Builder {
    fwd: Vec<(u32, Vec<u8>)>, bwd: Vec<(u32, Vec<u8>)>,
    // Running totals so we don't rescan all segments per push (O(n²)).
    fwd_bytes: usize, bwd_bytes: usize,
    fwd_isn: Option<u32>, bwd_isn: Option<u32>,
    src_ip: String, src_port: u16, dst_ip: String, dst_port: u16,
    first_packet_idx: usize, timestamp: f64,
}

pub fn reassemble(segments: &[RawSegment]) -> Vec<ReassembledStream> {
    const MAX_STREAMS: usize = 10_000;
    const MAX_DIR_BYTES: usize = 1024 * 1024;

    let mut builders: HashMap<StreamKey, Builder> = HashMap::new();

    for seg in segments {
        if builders.len() >= MAX_STREAMS { break; }
        let (key, is_fwd) = StreamKey::new(seg);
        let b = builders.entry(key).or_insert_with(|| Builder {
            fwd: Vec::new(), bwd: Vec::new(),
            fwd_bytes: 0, bwd_bytes: 0,
            fwd_isn: None, bwd_isn: None,
            src_ip: seg.src_ip.clone(), src_port: seg.src_port,
            dst_ip: seg.dst_ip.clone(), dst_port: seg.dst_port,
            first_packet_idx: seg.packet_idx, timestamp: seg.timestamp,
        });

        if seg.is_syn {
            if is_fwd { b.fwd_isn = Some(seg.seq.wrapping_add(1)); }
            else { b.bwd_isn = Some(seg.seq.wrapping_add(1)); }
        }

        if !seg.payload.is_empty() {
            if is_fwd {
                if b.fwd_bytes < MAX_DIR_BYTES {
                    b.fwd_bytes += seg.payload.len();
                    b.fwd.push((seg.seq, seg.payload.clone()));
                }
            } else if b.bwd_bytes < MAX_DIR_BYTES {
                b.bwd_bytes += seg.payload.len();
                b.bwd.push((seg.seq, seg.payload.clone()));
            }
        }
    }

    builders.into_values()
        .filter(|b| !b.fwd.is_empty() || !b.bwd.is_empty())
        .map(|mut b| ReassembledStream {
            src_ip: b.src_ip, src_port: b.src_port,
            dst_ip: b.dst_ip, dst_port: b.dst_port,
            forward_payload: assemble(&mut b.fwd, b.fwd_isn),
            backward_payload: assemble(&mut b.bwd, b.bwd_isn),
            first_packet_idx: b.first_packet_idx,
            timestamp: b.timestamp,
        })
        .collect()
}

fn assemble(segs: &mut Vec<(u32, Vec<u8>)>, isn: Option<u32>) -> Vec<u8> {
    if segs.is_empty() { return Vec::new(); }
    segs.sort_unstable_by_key(|(seq, _)| *seq);
    let base = isn.unwrap_or(segs[0].0);
    let mut out = Vec::new();
    let mut nxt = base;
    for (seq, payload) in segs.iter() {
        if payload.is_empty() { continue; }
        let rel_seq = seq.wrapping_sub(base);
        let rel_nxt = nxt.wrapping_sub(base);
        if rel_seq > rel_nxt {
            let gap = (rel_seq - rel_nxt) as usize;
            if gap > 65_536 { break; }
            out.extend(std::iter::repeat(0u8).take(gap));
        }
        let skip = rel_nxt.saturating_sub(rel_seq) as usize;
        if skip >= payload.len() { continue; }
        out.extend_from_slice(&payload[skip..]);
        nxt = base.wrapping_add(out.len() as u32);
    }
    out
}
