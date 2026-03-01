use std::net::IpAddr;
use std::str::FromStr;
use std::collections::HashSet;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoPoint {
    pub ip: String,
    pub lat: f64,
    pub lon: f64,
    pub country: String,
    pub city: String,
    pub asn: Option<String>,
    pub packet_count: usize,
    pub bytes: usize,
}

pub fn geolocate(packets: &[PacketMeta]) -> Vec<GeoPoint> {
    let db_path = "../assets/GeoLite2-City.mmdb";

    let reader = match maxminddb::Reader::open_readfile(db_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Could not open GeoLite2 database: {}", e);
            return Vec::new();
        }
    };

    let mut ip_stats: std::collections::HashMap<String, (usize, usize)> = std::collections::HashMap::new();

    for pkt in packets {
        for ip in [&pkt.src_ip, &pkt.dst_ip].into_iter().flatten() {
            if !is_private_ip(ip) {
                let entry = ip_stats.entry(ip.clone()).or_insert((0, 0));
                entry.0 += 1;
                entry.1 += pkt.length;
            }
        }
    }

    let mut points = Vec::new();
    for (ip, (packet_count, bytes)) in &ip_stats {
        let addr = match IpAddr::from_str(ip) {
            Ok(a) => a,
            Err(_) => continue,
        };

        let record: Result<maxminddb::geoip2::City, _> = reader.lookup(addr);
        if let Ok(city) = record {
            let lat = city.location.as_ref().and_then(|l| l.latitude).unwrap_or(0.0);
            let lon = city.location.as_ref().and_then(|l| l.longitude).unwrap_or(0.0);
            let country = city.country
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en"))
                .copied()
                .unwrap_or("Unknown")
                .to_string();
            let city_name = city.city
                .as_ref()
                .and_then(|c| c.names.as_ref())
                .and_then(|n| n.get("en"))
                .copied()
                .unwrap_or("")
                .to_string();

            if lat != 0.0 || lon != 0.0 {
                points.push(GeoPoint {
                    ip: ip.clone(),
                    lat,
                    lon,
                    country,
                    city: city_name,
                    asn: None,
                    packet_count: *packet_count,
                    bytes: *bytes,
                });
            }
        }
    }

    points
}

fn is_private_ip(ip: &str) -> bool {
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip == "127.0.0.1" || ip.starts_with("169.254.") {
        return true;
    }
    if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next() {
            if let Ok(n) = second.parse::<u8>() {
                if (16..=31).contains(&n) {
                    return true;
                }
            }
        }
    }
    // IPv6 loopback/link-local
    if ip == "::1" || ip.starts_with("fe80:") {
        return true;
    }
    false
}
