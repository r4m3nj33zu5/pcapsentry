//! Pre-bucketed index over a packet slice.
//!
//! Many detectors share the same scan: "all TCP SYN packets", "all ICMP echo
//! requests", "all ARP replies". Without a shared index each detector does its
//! own O(N) sweep, so a capture with K detectors costs O(K·N). The
//! `IndexedView` is computed once in a single pass over packets and every
//! detector then iterates only the bucket it needs — bringing the wall-clock
//! down to O(N) plus the sum of bucket sizes.
//!
//! The view borrows the packet slice (so detectors can fetch full
//! `PacketMeta` via `view.packets[i]`) and stores indices, not packet copies.
//! A packet may appear in multiple buckets (e.g. a TCP SYN is in both `tcp`
//! and `tcp_syn`); total memory is roughly `2 × N × sizeof(usize)`, which
//! is small next to the packet vec itself.

use crate::parser::PacketMeta;

pub struct IndexedView<'a> {
    pub packets: &'a [PacketMeta],

    // All packets matching the top-level protocol field.
    pub tcp: Vec<usize>,
    pub udp: Vec<usize>,
    pub icmp: Vec<usize>,
    pub arp: Vec<usize>,
    pub tls: Vec<usize>,
    pub http: Vec<usize>,
    pub dns: Vec<usize>,

    // Specialised sub-buckets for hot detectors.
    /// TCP SYN without ACK (scan / connect attempts).
    pub tcp_syn: Vec<usize>,
    /// TCP SYN+ACK (handshake responses).
    pub tcp_synack: Vec<usize>,
    /// TCP RST.
    pub tcp_rst: Vec<usize>,
    /// TCP FIN+PSH+URG (Xmas scan).
    pub tcp_xmas: Vec<usize>,
    /// TCP "NONE" flags (NULL scan).
    pub tcp_null: Vec<usize>,
    /// Isolated TCP FIN.
    pub tcp_fin_only: Vec<usize>,

    /// ICMP echo request (type 8).
    pub icmp_echo_req: Vec<usize>,
    /// ICMP echo reply (type 0).
    pub icmp_echo_reply: Vec<usize>,

    /// ARP reply packets.
    pub arp_reply: Vec<usize>,
}

impl<'a> IndexedView<'a> {
    pub fn build(packets: &'a [PacketMeta]) -> Self {
        let mut v = IndexedView {
            packets,
            tcp: Vec::new(),
            udp: Vec::new(),
            icmp: Vec::new(),
            arp: Vec::new(),
            tls: Vec::new(),
            http: Vec::new(),
            dns: Vec::new(),
            tcp_syn: Vec::new(),
            tcp_synack: Vec::new(),
            tcp_rst: Vec::new(),
            tcp_xmas: Vec::new(),
            tcp_null: Vec::new(),
            tcp_fin_only: Vec::new(),
            icmp_echo_req: Vec::new(),
            icmp_echo_reply: Vec::new(),
            arp_reply: Vec::new(),
        };

        for (i, pkt) in packets.iter().enumerate() {
            match pkt.protocol.as_str() {
                "TCP" => {
                    v.tcp.push(i);
                    if let Some(t) = &pkt.layers.transport {
                        if let Some(flags) = &t.flags {
                            let has_syn = flags.contains("SYN");
                            let has_ack = flags.contains("ACK");
                            let has_fin = flags.contains("FIN");
                            let has_rst = flags.contains("RST");
                            let has_psh = flags.contains("PSH");
                            let has_urg = flags.contains("URG");
                            if has_syn && !has_ack { v.tcp_syn.push(i); }
                            if has_syn && has_ack { v.tcp_synack.push(i); }
                            if has_rst { v.tcp_rst.push(i); }
                            if has_fin && has_psh && has_urg { v.tcp_xmas.push(i); }
                            // "NONE" is the parser's literal string for no flags.
                            if flags == "NONE" { v.tcp_null.push(i); }
                            if flags == "FIN" { v.tcp_fin_only.push(i); }
                        }
                    }
                }
                "UDP" => v.udp.push(i),
                "ICMP" => {
                    v.icmp.push(i);
                    if let Some(icmp) = &pkt.layers.icmp {
                        match icmp.icmp_type {
                            8 => v.icmp_echo_req.push(i),
                            0 => v.icmp_echo_reply.push(i),
                            _ => {}
                        }
                    }
                }
                "ARP" => {
                    v.arp.push(i);
                    if let Some(a) = &pkt.layers.arp {
                        if a.operation == "Reply" {
                            v.arp_reply.push(i);
                        }
                    }
                }
                "TLS" => v.tls.push(i),
                "HTTP" => v.http.push(i),
                "DNS" => v.dns.push(i),
                _ => {}
            }
        }

        v
    }
}
