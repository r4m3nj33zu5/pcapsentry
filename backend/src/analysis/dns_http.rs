use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsEntry {
    pub timestamp: f64,
    pub timestamp_str: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub is_response: bool,
    pub query_type: String,
    pub name: String,
    pub answers: Vec<String>,
    pub suspicious: bool,
    pub suspicious_reason: Option<String>,
    pub packet_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpEntry {
    pub timestamp: f64,
    pub timestamp_str: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub entry_type: String,
    pub method: Option<String>,
    pub host: Option<String>,
    pub path: Option<String>,
    pub status: Option<u16>,
    pub user_agent: Option<String>,
    pub suspicious: bool,
    pub suspicious_reason: Option<String>,
    pub packet_index: usize,
}

const SUSPICIOUS_TLDS: &[&str] = &[".tk", ".xyz", ".ml", ".ga", ".cf", ".pw", ".top", ".click"];

pub fn extract(packets: &[PacketMeta]) -> (Vec<DnsEntry>, Vec<HttpEntry>) {
    let mut dns_log = Vec::new();
    let mut http_log = Vec::new();

    for pkt in packets {
        if let Some(app) = &pkt.layers.application {
            match app.protocol.as_str() {
                "DNS" => {
                    if let Some(entry) = parse_dns_entry(pkt, &app.data) {
                        dns_log.push(entry);
                    }
                }
                "HTTP" => {
                    if let Some(entry) = parse_http_entry(pkt, &app.data) {
                        http_log.push(entry);
                    }
                }
                _ => {}
            }
        }
    }

    (dns_log, http_log)
}

fn parse_dns_entry(pkt: &PacketMeta, data: &serde_json::Value) -> Option<DnsEntry> {
    let is_response = data["is_response"].as_bool().unwrap_or(false);
    let questions = data["questions"].as_array()?;
    let answers = data["answers"].as_array().cloned().unwrap_or_default();

    let first_q = questions.first()?;
    let name = first_q["name"].as_str().unwrap_or("").to_string();
    let query_type = first_q["type"].as_str().unwrap_or("").to_string();

    let answer_strs: Vec<String> = answers.iter()
        .filter_map(|a| {
            let rtype = a["type"].as_str().unwrap_or("");
            let rdata = a["data"].as_str().unwrap_or("");
            Some(format!("{}: {}", rtype, rdata))
        })
        .collect();

    let (suspicious, suspicious_reason) = check_dns_suspicious(&name, &answer_strs, is_response);

    Some(DnsEntry {
        timestamp: pkt.timestamp,
        timestamp_str: pkt.timestamp_str.clone(),
        src_ip: pkt.src_ip.clone().unwrap_or_default(),
        dst_ip: pkt.dst_ip.clone().unwrap_or_default(),
        is_response,
        query_type,
        name,
        answers: answer_strs,
        suspicious,
        suspicious_reason,
        packet_index: pkt.index,
    })
}

fn check_dns_suspicious(name: &str, answers: &[String], is_response: bool) -> (bool, Option<String>) {
    // Check suspicious TLDs
    for tld in SUSPICIOUS_TLDS {
        if name.ends_with(tld) {
            return (true, Some(format!("Suspicious TLD: {}", tld)));
        }
    }

    // DGA heuristic: very long random-looking labels (entropy check)
    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        if label.len() > 20 {
            // Check if it looks random (high consonant clusters, no vowels)
            let vowels = label.chars().filter(|c| "aeiou".contains(*c)).count();
            if vowels < label.len() / 5 {
                return (true, Some("Possible DGA domain (random-looking label)".to_string()));
            }
        }
    }

    // NXDOMAIN in answers
    if is_response && answers.is_empty() {
        return (true, Some("NXDOMAIN response — domain not found".to_string()));
    }

    (false, None)
}

fn parse_http_entry(pkt: &PacketMeta, data: &serde_json::Value) -> Option<HttpEntry> {
    let entry_type = data["type"].as_str()?.to_string();
    let headers = data["headers"].as_object();

    let (method, host, path, status, user_agent) = match entry_type.as_str() {
        "request" => {
            let method = data["method"].as_str().map(|s| s.to_string());
            let uri = data["uri"].as_str().unwrap_or("").to_string();
            let host = headers.and_then(|h| h.get("Host")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let ua = headers.and_then(|h| h.get("User-Agent")).and_then(|v| v.as_str()).map(|s| s.to_string());
            (method, host, Some(uri), None, ua)
        }
        "response" => {
            let status = data["status"].as_u64().map(|s| s as u16);
            (None, None, None, status, None)
        }
        _ => return None,
    };

    let (suspicious, suspicious_reason) = check_http_suspicious(data, headers);

    Some(HttpEntry {
        timestamp: pkt.timestamp,
        timestamp_str: pkt.timestamp_str.clone(),
        src_ip: pkt.src_ip.clone().unwrap_or_default(),
        dst_ip: pkt.dst_ip.clone().unwrap_or_default(),
        entry_type,
        method,
        host,
        path,
        status,
        user_agent,
        suspicious,
        suspicious_reason,
        packet_index: pkt.index,
    })
}

fn check_http_suspicious(data: &serde_json::Value, headers: Option<&serde_json::Map<String, serde_json::Value>>) -> (bool, Option<String>) {
    if let Some(headers) = headers {
        if let Some(auth) = headers.get("Authorization") {
            if auth.as_str().unwrap_or("").starts_with("Basic ") {
                return (true, Some("HTTP Basic Auth credentials in cleartext".to_string()));
            }
        }
    }
    (false, None)
}
