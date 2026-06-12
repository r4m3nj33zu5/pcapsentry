use std::net::IpAddr;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;
use crate::analysis::utils::is_private_addr;

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

// Locate the MaxMind DB. Search relative to the running executable so the
// binary works no matter what directory the user invokes it from, then fall
// back to the legacy CWD-relative path.
fn locate_geoip_db() -> Option<std::path::PathBuf> {
    let candidates: Vec<std::path::PathBuf> = std::env::current_exe()
        .ok()
        .into_iter()
        .flat_map(|exe| {
            let mut v = Vec::new();
            // target/release/pcapsentry → ../../../assets/GeoLite2-City.mmdb
            if let Some(p) = exe.parent().and_then(|p| p.parent()).and_then(|p| p.parent()) {
                v.push(p.join("assets").join("GeoLite2-City.mmdb"));
            }
            // sibling assets dir (when installed)
            if let Some(p) = exe.parent() {
                v.push(p.join("assets").join("GeoLite2-City.mmdb"));
            }
            v
        })
        .chain(std::iter::once(std::path::PathBuf::from("../assets/GeoLite2-City.mmdb")))
        .chain(std::iter::once(std::path::PathBuf::from("assets/GeoLite2-City.mmdb")))
        .collect();
    candidates.into_iter().find(|p| p.exists())
}

pub fn geolocate(packets: &[PacketMeta]) -> Vec<GeoPoint> {
    let db_path = match locate_geoip_db() {
        Some(p) => p,
        None => {
            eprintln!("Warning: GeoLite2-City.mmdb not found in any search path.");
            return Vec::new();
        }
    };

    let reader = match maxminddb::Reader::open_readfile(&db_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Warning: Could not open GeoLite2 database at {}: {}", db_path.display(), e);
            return Vec::new();
        }
    };

    let mut ip_stats: std::collections::HashMap<IpAddr, (usize, usize)> = std::collections::HashMap::new();

    for pkt in packets {
        for ip in [pkt.src_ip, pkt.dst_ip].into_iter().flatten() {
            if !is_private_addr(&ip) {
                let entry = ip_stats.entry(ip).or_insert((0, 0));
                entry.0 += 1;
                entry.1 += pkt.length;
            }
        }
    }

    let mut points = Vec::new();
    for (addr, (packet_count, bytes)) in &ip_stats {
        let addr = *addr;

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
                    ip: addr.to_string(),
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

