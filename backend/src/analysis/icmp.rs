use std::collections::{HashMap, HashSet};
use crate::parser::PacketMeta;
use super::{IcmpSummary, IcmpPair};

pub fn summarize(packets: &[PacketMeta]) -> IcmpSummary {
    let mut echo_requests = 0usize;
    let mut echo_replies = 0usize;
    let mut unique_sources: HashSet<String> = HashSet::new();
    let mut unique_targets: HashSet<String> = HashSet::new();
    // (src, dst) -> count
    let mut pair_counts: HashMap<(String, String), usize> = HashMap::new();

    for pkt in packets {
        if pkt.protocol != "ICMP" {
            continue;
        }
        let is_request = pkt.info.contains("Echo Request");
        let is_reply = pkt.info.contains("Echo Reply");

        if !is_request && !is_reply {
            continue;
        }

        if let (Some(src), Some(dst)) = (&pkt.src_ip, &pkt.dst_ip) {
            if is_request {
                echo_requests += 1;
                unique_sources.insert(src.clone());
                unique_targets.insert(dst.clone());
                *pair_counts.entry((src.clone(), dst.clone())).or_insert(0) += 1;
            } else {
                echo_replies += 1;
            }
        }
    }

    let mut top_pairs: Vec<IcmpPair> = pair_counts
        .into_iter()
        .map(|((src, dst), count)| IcmpPair { src, dst, count })
        .collect();
    top_pairs.sort_by(|a, b| b.count.cmp(&a.count));
    top_pairs.truncate(10);

    IcmpSummary {
        echo_requests,
        echo_replies,
        unique_sources: unique_sources.len(),
        unique_targets: unique_targets.len(),
        top_pairs,
    }
}
