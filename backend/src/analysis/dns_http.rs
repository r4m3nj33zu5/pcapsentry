use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;
use crate::analysis::utils::shannon_entropy;

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
    // New fields
    #[serde(default)]
    pub entropy: f64,
    #[serde(default)]
    pub is_nxdomain: bool,
    #[serde(default)]
    pub ttl_min: Option<u32>,
    #[serde(default)]
    pub is_dga_candidate: bool,
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
    // New fields
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub body_preview: Option<String>,
    #[serde(default)]
    pub ua_category: Option<String>,
    #[serde(default)]
    pub is_ua_suspicious: bool,
    #[serde(default)]
    pub reassembled: bool,
}

const SUSPICIOUS_TLDS: &[&str] = &[".tk", ".xyz", ".ml", ".ga", ".cf", ".pw", ".top", ".click", ".ru"];

// Known-suspicious UA patterns
const SUSPICIOUS_UA_PATTERNS: &[(&str, &str)] = &[
    ("curl/", "Tool: curl"),
    ("python-requests/", "Tool: Python requests"),
    ("go-http-client/", "Tool: Go HTTP"),
    ("nmap scripting", "Tool: Nmap"),
    ("masscan/", "Tool: Masscan"),
    ("nikto/", "Tool: Nikto"),
    ("sqlmap/", "Tool: SQLMap"),
    ("dirbuster/", "Tool: DirBuster"),
    ("zgrab/", "Tool: ZGrab"),
    ("gobuster/", "Tool: GoBuster"),
];

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

    // TTL from first answer
    let ttl_min = answers.iter()
        .filter_map(|a| a["ttl"].as_u64().map(|t| t as u32))
        .min();

    let is_nxdomain = is_response && answer_strs.is_empty() && !name.is_empty();
    let entropy = shannon_entropy(&name);
    let is_dga_candidate = check_dga_candidate(&name, entropy);

    let (suspicious, suspicious_reason) = check_dns_suspicious(&name, &answer_strs, is_response, is_nxdomain, entropy);

    Some(DnsEntry {
        timestamp: pkt.timestamp,
        timestamp_str: pkt.timestamp_str.clone(),
        src_ip: pkt.src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        dst_ip: pkt.dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        is_response,
        query_type,
        name,
        answers: answer_strs,
        suspicious,
        suspicious_reason,
        packet_index: pkt.index,
        entropy,
        is_nxdomain,
        ttl_min,
        is_dga_candidate,
    })
}

fn check_dga_candidate(name: &str, entropy: f64) -> bool {
    let labels: Vec<&str> = name.split('.').collect();
    // Check longest label
    for label in &labels[..labels.len().saturating_sub(1)] {
        if label.len() >= 12 && entropy > 3.5 {
            return true;
        }
        if label.len() > 20 {
            let vowels = label.chars().filter(|c| "aeiou".contains(*c)).count();
            if vowels < label.len() / 6 {
                return true;
            }
        }
    }
    false
}

fn check_dns_suspicious(name: &str, answers: &[String], is_response: bool, is_nxdomain: bool, entropy: f64) -> (bool, Option<String>) {
    for tld in SUSPICIOUS_TLDS {
        if name.ends_with(tld) {
            return (true, Some(format!("Suspicious TLD: {}", tld)));
        }
    }

    let labels: Vec<&str> = name.split('.').collect();
    for label in &labels {
        if label.len() > 20 {
            let vowels = label.chars().filter(|c| "aeiou".contains(*c)).count();
            if vowels < label.len() / 5 {
                return (true, Some("Possible DGA domain (random-looking label)".to_string()));
            }
        }
    }

    if entropy > 3.8 && name.len() > 15 {
        return (true, Some(format!("High Shannon entropy ({:.2}) — possible DGA", entropy)));
    }

    if is_nxdomain {
        return (true, Some("NXDOMAIN response — domain not found".to_string()));
    }

    (false, None)
}

fn parse_http_entry(pkt: &PacketMeta, data: &serde_json::Value) -> Option<HttpEntry> {
    let entry_type = data["type"].as_str()?.to_string();
    let headers = data["headers"].as_object();

    let (method, host, path, status, user_agent, content_type) = match entry_type.as_str() {
        "request" => {
            let method = data["method"].as_str().map(|s| s.to_string());
            let uri = data["uri"].as_str().unwrap_or("").to_string();
            let host = headers.and_then(|h| h.get("Host")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let ua = headers.and_then(|h| h.get("User-Agent")).and_then(|v| v.as_str()).map(|s| s.to_string());
            let ct = None;
            (method, host, Some(uri), None, ua, ct)
        }
        "response" => {
            let status = data["status"].as_u64().map(|s| s as u16);
            let ct = headers.and_then(|h| h.get("Content-Type")).and_then(|v| v.as_str()).map(|s| s.to_string());
            (None, None, None, status, None, ct)
        }
        _ => return None,
    };

    let (ua_category, is_ua_suspicious) = categorize_ua(user_agent.as_deref());
    let (suspicious, suspicious_reason) = check_http_suspicious(data, headers, is_ua_suspicious);

    Some(HttpEntry {
        timestamp: pkt.timestamp,
        timestamp_str: pkt.timestamp_str.clone(),
        src_ip: pkt.src_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        dst_ip: pkt.dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
        entry_type,
        method,
        host,
        path,
        status,
        user_agent,
        suspicious,
        suspicious_reason,
        packet_index: pkt.index,
        content_type,
        body_preview: None,
        ua_category,
        is_ua_suspicious,
        reassembled: false,
    })
}

fn categorize_ua(ua: Option<&str>) -> (Option<String>, bool) {
    let ua = match ua {
        Some(s) if !s.is_empty() => s.to_lowercase(),
        _ => return (None, false),
    };

    for (pattern, category) in SUSPICIOUS_UA_PATTERNS {
        if ua.contains(*pattern) {
            return (Some(category.to_string()), true);
        }
    }

    if ua.contains("mozilla") || ua.contains("chrome") || ua.contains("safari") || ua.contains("firefox") {
        return (Some("Browser".to_string()), false);
    }
    if ua.contains("bot") || ua.contains("crawler") || ua.contains("spider") {
        return (Some("Bot/Crawler".to_string()), true);
    }

    (Some("Unknown Client".to_string()), false)
}

fn check_http_suspicious(_data: &serde_json::Value, headers: Option<&serde_json::Map<String, serde_json::Value>>, is_ua_suspicious: bool) -> (bool, Option<String>) {
    if let Some(headers) = headers {
        if let Some(auth) = headers.get("Authorization") {
            if auth.as_str().unwrap_or("").starts_with("Basic ") {
                return (true, Some("HTTP Basic Auth credentials in cleartext".to_string()));
            }
        }
    }
    if is_ua_suspicious {
        return (true, Some("Suspicious User-Agent (tool/scanner)".to_string()));
    }
    (false, None)
}

pub fn extract_from_streams(streams: &[crate::reassembly::ReassembledStream], http_log: &mut Vec<HttpEntry>) {
    const HTTP_PORTS: &[u16] = &[80, 8080, 8000, 8888, 3000, 3128];
    for stream in streams {
        if !HTTP_PORTS.contains(&stream.dst_port) && !HTTP_PORTS.contains(&stream.src_port) {
            continue;
        }
        // Parse forward (request) payload
        if !stream.forward_payload.is_empty() {
            if let Some(entry) = parse_stream_http(&stream.forward_payload, stream, "request") {
                http_log.push(entry);
            }
        }
        // Parse backward (response) payload
        if !stream.backward_payload.is_empty() {
            if let Some(entry) = parse_stream_http(&stream.backward_payload, stream, "response") {
                http_log.push(entry);
            }
        }
    }
}

fn parse_stream_http(payload: &[u8], stream: &crate::reassembly::ReassembledStream, expected_type: &str) -> Option<HttpEntry> {
    let text = std::str::from_utf8(payload).ok()?;
    let lines: Vec<&str> = text.lines().collect();
    if lines.is_empty() { return None; }
    let first = lines[0];
    let parts: Vec<&str> = first.splitn(3, ' ').collect();
    if parts.len() != 3 { return None; }

    let mut headers_map = serde_json::Map::new();
    for line in &lines[1..] {
        if line.is_empty() { break; }
        if let Some((k, v)) = line.split_once(": ") {
            headers_map.insert(k.to_string(), serde_json::Value::String(v.to_string()));
        }
    }

    // Find body (after blank line)
    let body_start = text.find("\r\n\r\n").map(|i| i + 4)
        .or_else(|| text.find("\n\n").map(|i| i + 2));
    let body_preview = body_start.map(|i| {
        let body = &text[i..];
        let preview_len = body.len().min(200);
        body[..preview_len].to_string()
    });

    if expected_type == "request" {
        let method = parts[0];
        if !matches!(method, "GET"|"POST"|"PUT"|"DELETE"|"HEAD"|"OPTIONS"|"PATCH"|"CONNECT"|"TRACE") {
            return None;
        }
        let host = headers_map.get("Host").and_then(|v| v.as_str()).map(|s| s.to_string());
        let ua = headers_map.get("User-Agent").and_then(|v| v.as_str()).map(|s| s.to_string());
        let (ua_category, is_ua_suspicious) = categorize_ua(ua.as_deref());
        let auth = headers_map.get("Authorization").and_then(|v| v.as_str()).unwrap_or("");
        let (suspicious, suspicious_reason) = if auth.starts_with("Basic ") {
            (true, Some("HTTP Basic Auth credentials in cleartext (reassembled)".to_string()))
        } else if is_ua_suspicious {
            (true, Some("Suspicious User-Agent (tool/scanner)".to_string()))
        } else {
            (false, None)
        };
        Some(HttpEntry {
            timestamp: stream.timestamp,
            timestamp_str: format!("{:.3}", stream.timestamp),
            src_ip: stream.src_ip.clone(),
            dst_ip: stream.dst_ip.clone(),
            entry_type: "request".to_string(),
            method: Some(method.to_string()),
            host,
            path: Some(parts[1].to_string()),
            status: None,
            user_agent: ua,
            suspicious,
            suspicious_reason,
            packet_index: stream.first_packet_idx,
            content_type: None,
            body_preview,
            ua_category,
            is_ua_suspicious,
            reassembled: true,
        })
    } else {
        // response
        if !parts[0].starts_with("HTTP/") { return None; }
        let status: u16 = parts[1].parse().ok()?;
        let ct = headers_map.get("Content-Type").and_then(|v| v.as_str()).map(|s| s.to_string());
        Some(HttpEntry {
            timestamp: stream.timestamp,
            timestamp_str: format!("{:.3}", stream.timestamp),
            src_ip: stream.dst_ip.clone(),
            dst_ip: stream.src_ip.clone(),
            entry_type: "response".to_string(),
            method: None,
            host: None,
            path: None,
            status: Some(status),
            user_agent: None,
            suspicious: false,
            suspicious_reason: None,
            packet_index: stream.first_packet_idx,
            content_type: ct,
            body_preview,
            ua_category: None,
            is_ua_suspicious: false,
            reassembled: true,
        })
    }
}
