use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;
use crate::analysis::utils::flow_id;

/// Top known-bad JA3 hashes (Cobalt Strike, Emotet, Metasploit, etc.)
static KNOWN_BAD_JA3: &str = include_str!("../../../assets/ja3_known_bad.csv");

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TlsSession {
    pub flow_id: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub sni: Option<String>,
    pub ja3_hash: String,
    pub ja3_string: String,
    pub tls_version_offered: u16,
    pub tls_version_negotiated: Option<String>,
    pub cipher_suite: Option<u16>,
    pub is_cipher_weak: bool,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_not_after: Option<String>,
    pub is_self_signed: bool,
    pub is_expired: bool,
    pub known_bad_ja3: Option<String>, // malware family name if matched
    pub packet_indices: Vec<usize>,
    pub first_seen: f64,
}

fn load_known_bad() -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in KNOWN_BAD_JA3.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let mut parts = line.splitn(2, ',');
        if let (Some(hash), Some(family)) = (parts.next(), parts.next()) {
            map.insert(hash.trim().to_lowercase(), family.trim().to_string());
        }
    }
    map
}

// Weak cipher suites (RC4, NULL, export, anon, 3DES)
fn is_weak_cipher(cs: u16) -> bool {
    matches!(cs,
        0x0000..=0x000A | // NULL suites
        0x0018..=0x001B | // anon/export
        0x0028..=0x002F | // RC4 variants
        0x0067 | 0x006B | // some old
        0xFF00..=0xFFFF   // private/unknown
    )
}

pub fn extract(packets: &[PacketMeta]) -> Vec<TlsSession> {
    let known_bad = load_known_bad();
    let mut sessions_map: HashMap<String, TlsSession> = HashMap::new();

    for pkt in packets {
        let app = match &pkt.layers.application {
            Some(a) if a.protocol == "TLS" => &a.data,
            _ => continue,
        };

        let src_ip = pkt.src_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let dst_ip = pkt.dst_ip.map(|ip| ip.to_string()).unwrap_or_default();
        let src_port = pkt.src_port.unwrap_or(0);
        let dst_port = pkt.dst_port.unwrap_or(0);
        let fid = flow_id(&src_ip, &dst_ip, pkt.src_port, pkt.dst_port, "TLS");

        // A single packet may contain ClientHello, ServerHello, and
        // Certificate fields merged together (one TCP segment can carry the
        // full server flight). Check each field group independently rather
        // than dispatching on a single "type" tag.
        let has_client_hello = app.get("ja3_hash").is_some() || app.get("sni").is_some()
            || app.get("cipher_suites").is_some();
        let has_server_hello = app.get("negotiated_version_name").is_some()
            || app.get("cipher_suite").is_some();
        let has_certificate = app.get("cert_subject").is_some();

        if !has_client_hello && !has_server_hello && !has_certificate { continue; }

        let session = sessions_map.entry(fid.clone()).or_insert_with(|| TlsSession {
            flow_id: fid.clone(),
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            first_seen: pkt.timestamp,
            ..TlsSession::default()
        });

        if has_client_hello {
            let ja3_hash = app.get("ja3_hash").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let ja3_string = app.get("ja3_string").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let legacy_version = app.get("legacy_version").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
            let sni = app.get("sni").and_then(|v| v.as_str()).map(|s| s.to_string());
            let ciphers: Vec<u16> = app.get("cipher_suites").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect())
                .unwrap_or_default();
            let is_weak = ciphers.iter().any(|&cs| is_weak_cipher(cs));
            let known_bad_family = known_bad.get(&ja3_hash).cloned();

            if session.sni.is_none() { session.sni = sni; }
            if session.ja3_hash.is_empty() { session.ja3_hash = ja3_hash; }
            if session.ja3_string.is_empty() { session.ja3_string = ja3_string; }
            if session.tls_version_offered == 0 { session.tls_version_offered = legacy_version; }
            if known_bad_family.is_some() { session.known_bad_ja3 = known_bad_family; }
            session.is_cipher_weak = session.is_cipher_weak || is_weak;
        }

        if has_server_hello {
            let negotiated_version_name = app.get("negotiated_version_name")
                .and_then(|v| v.as_str()).map(|s| s.to_string());
            let cipher_suite = app.get("cipher_suite").and_then(|v| v.as_u64()).map(|n| n as u16);
            if session.tls_version_negotiated.is_none() {
                session.tls_version_negotiated = negotiated_version_name;
            }
            if session.cipher_suite.is_none() {
                session.cipher_suite = cipher_suite;
                if let Some(cs) = cipher_suite {
                    if is_weak_cipher(cs) { session.is_cipher_weak = true; }
                }
            }
        }

        if has_certificate {
            if session.cert_subject.is_none() {
                session.cert_subject = app.get("cert_subject").and_then(|v| v.as_str()).map(String::from);
            }
            if session.cert_issuer.is_none() {
                session.cert_issuer = app.get("cert_issuer").and_then(|v| v.as_str()).map(String::from);
            }
            if session.cert_not_after.is_none() {
                session.cert_not_after = app.get("cert_not_after").and_then(|v| v.as_str()).map(String::from);
            }
            if let Some(b) = app.get("is_self_signed").and_then(|v| v.as_bool()) {
                session.is_self_signed = session.is_self_signed || b;
            }
            if let Some(b) = app.get("is_expired").and_then(|v| v.as_bool()) {
                session.is_expired = session.is_expired || b;
            }
        }

        session.packet_indices.push(pkt.index);
        if pkt.timestamp < session.first_seen {
            session.first_seen = pkt.timestamp;
        }
    }

    let mut result: Vec<TlsSession> = sessions_map.into_values().collect();
    result.sort_by(|a, b| a.first_seen.total_cmp(&b.first_seen));
    result
}
