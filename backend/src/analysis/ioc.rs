use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;
use crate::analysis::dns_http::{DnsEntry, HttpEntry};
use crate::analysis::geo::GeoPoint;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocIp {
    pub ip: String,
    pub is_private: bool,
    pub country: Option<String>,
    pub asn_org: Option<String>,
    pub packet_count: usize,
    pub bytes: usize,
    pub threat_reasons: Vec<String>,
    pub enrichment: Option<IocEnrichment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocDomain {
    pub domain: String,
    pub query_count: usize,
    pub is_suspicious: bool,
    pub suspicious_reason: Option<String>,
    pub answers: Vec<String>,
    pub enrichment: Option<IocEnrichment>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocUrl {
    pub url: String,
    pub method: Option<String>,
    pub host: String,
    pub path: String,
    pub is_suspicious: bool,
    pub packet_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocEnrichment {
    pub source: String,
    pub malicious: Option<bool>,
    pub score: Option<f32>,
    pub tags: Vec<String>,
    pub last_analysis: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IocBundle {
    pub ips: Vec<IocIp>,
    pub domains: Vec<IocDomain>,
    pub urls: Vec<IocUrl>,
}

pub fn build_bundle(
    packets: &[PacketMeta],
    dns_log: &[DnsEntry],
    http_log: &[HttpEntry],
    geo_points: &[GeoPoint],
) -> IocBundle {
    // Build IP stats from packets. Keyed by IpAddr (16-byte Copy) rather
    // than per-packet String alloc for the HashMap key.
    let mut ip_stats: HashMap<std::net::IpAddr, (usize, usize)> = HashMap::new();
    for pkt in packets {
        for ip in [pkt.src_ip, pkt.dst_ip].into_iter().flatten() {
            let e = ip_stats.entry(ip).or_insert((0, 0));
            e.0 += 1;
            e.1 += pkt.length;
        }
    }

    // Geo lookup map
    let geo_map: HashMap<&str, (&str, Option<&str>)> = geo_points.iter()
        .map(|g| (g.ip.as_str(), (g.country.as_str(), g.asn.as_deref())))
        .collect();

    let ips: Vec<IocIp> = ip_stats
        .into_iter()
        .filter(|(ip, _)| !crate::analysis::utils::is_private_addr(ip))
        .map(|(ip_addr, (packet_count, bytes))| {
            let ip = ip_addr.to_string();
            let (country, asn_org) = geo_map.get(ip.as_str())
                .map(|(c, a)| (Some(c.to_string()), a.map(|s| s.to_string())))
                .unwrap_or((None, None));
            IocIp {
                is_private: false,
                ip,
                country,
                asn_org,
                packet_count,
                bytes,
                threat_reasons: Vec::new(),
                enrichment: None,
            }
        })
        .collect();

    // Build domain stats from DNS log
    let mut domain_stats: HashMap<String, (usize, bool, Option<String>, Vec<String>)> = HashMap::new();
    for entry in dns_log {
        if entry.is_response { continue; }
        let e = domain_stats.entry(entry.name.clone()).or_insert((0, false, None, Vec::new()));
        e.0 += 1;
        if entry.suspicious {
            e.1 = true;
            e.2 = entry.suspicious_reason.clone();
        }
        for a in &entry.answers {
            if !e.3.contains(a) { e.3.push(a.clone()); }
        }
    }

    let domains: Vec<IocDomain> = domain_stats
        .into_iter()
        .map(|(domain, (query_count, is_suspicious, reason, answers))| IocDomain {
            domain,
            query_count,
            is_suspicious,
            suspicious_reason: reason,
            answers,
            enrichment: None,
        })
        .collect();

    // Build URL list from HTTP log
    let mut url_counts: HashMap<String, (Option<String>, String, String, bool, usize)> = HashMap::new();
    for entry in http_log {
        if entry.entry_type != "request" { continue; }
        let host = entry.host.clone().unwrap_or_default();
        let path = entry.path.clone().unwrap_or_default();
        let url = format!("{}{}", host, path);
        let e = url_counts.entry(url).or_insert((entry.method.clone(), host, path, entry.suspicious, 0));
        e.4 += 1;
    }

    let urls: Vec<IocUrl> = url_counts
        .into_iter()
        .map(|(url, (method, host, path, is_suspicious, count))| IocUrl {
            url,
            method,
            host,
            path,
            is_suspicious,
            packet_count: count,
        })
        .collect();

    let mut bundle = IocBundle { ips, domains, urls };
    // Sort by packet count descending
    bundle.ips.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    bundle.ips.truncate(200);
    bundle.domains.sort_by(|a, b| b.query_count.cmp(&a.query_count));
    bundle.domains.truncate(500);
    bundle.urls.sort_by(|a, b| b.packet_count.cmp(&a.packet_count));
    bundle.urls.truncate(200);
    bundle
}
