use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use crate::analysis::indexed::IndexedView;
use super::{IcmpSummary, IcmpPair};

pub fn summarize(view: &IndexedView) -> IcmpSummary {
    let mut echo_requests = 0usize;
    let mut echo_replies = 0usize;
    let mut unique_sources: HashSet<IpAddr> = HashSet::new();
    let mut unique_targets: HashSet<IpAddr> = HashSet::new();
    let mut pair_counts: HashMap<(IpAddr, IpAddr), usize> = HashMap::new();

    // Iterate the prebuilt echo-request / echo-reply buckets — no protocol
    // string compares and no info-string sniffing per packet.
    for &i in &view.icmp_echo_req {
        let pkt = &view.packets[i];
        if let (Some(src), Some(dst)) = (pkt.src_ip, pkt.dst_ip) {
            echo_requests += 1;
            unique_sources.insert(src);
            unique_targets.insert(dst);
            *pair_counts.entry((src, dst)).or_insert(0) += 1;
        }
    }
    echo_replies += view.icmp_echo_reply.len();

    let mut top_pairs: Vec<IcmpPair> = pair_counts
        .into_iter()
        .map(|((src, dst), count)| IcmpPair { src: src.to_string(), dst: dst.to_string(), count })
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
