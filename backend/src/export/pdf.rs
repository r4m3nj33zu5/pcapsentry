use anyhow::Result;
use printpdf::*;
use std::io::BufWriter;
use crate::analysis::AnalysisResult;

// Strip ASCII control characters from user-controlled text before rendering
// it into a PDF (filenames, hostnames, threat descriptions from pcap data).
fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() && c != ' ' { '?' } else { c }).collect()
}

pub fn generate_pdf(result: &AnalysisResult) -> Result<Vec<u8>> {
    let (doc, page1, layer1) = PdfDocument::new(
        "PcapSentry Report",
        Mm(210.0_f32),
        Mm(297.0_f32),
        "Page 1",
    );

    let font = doc.add_builtin_font(BuiltinFont::Helvetica)?;
    let font_bold = doc.add_builtin_font(BuiltinFont::HelveticaBold)?;

    let mut page_num: u32 = 1;
    let mut layer = doc.get_page(page1).get_layer(layer1);

    // Adds a new page when content runs past the bottom margin.
    let new_page = |doc: &PdfDocumentReference, page_num: &mut u32| {
        *page_num += 1;
        let (p, l) = doc.add_page(Mm(210.0_f32), Mm(297.0_f32), format!("Page {}", page_num));
        doc.get_page(p).get_layer(l)
    };

    // ─── Cover Section ────────────────────────────────────────────────────────
    let mut y = 270.0_f32;

    layer.use_text("PcapSentry", 28.0, Mm(20.0_f32), Mm(y), &font_bold);
    y -= 10.0;
    layer.use_text("Network Capture Analysis Report", 14.0, Mm(20.0_f32), Mm(y), &font);
    y -= 6.0;

    layer.use_text(
        format!("File: {}", sanitize(&result.overview.filename)),
        11.0, Mm(20.0_f32), Mm(y), &font,
    );
    y -= 6.0;

    let duration = result.overview.capture_duration_secs;
    let duration_str = if duration < 60.0 {
        format!("{:.2}s", duration)
    } else if duration < 3600.0 {
        format!("{:.1}m", duration / 60.0)
    } else {
        format!("{:.2}h", duration / 3600.0)
    };

    layer.use_text(
        &format!("Capture Duration: {}", duration_str),
        11.0, Mm(20.0_f32), Mm(y), &font,
    );
    y -= 6.0;

    layer.use_text(
        &format!("Analyzed: {}", result.overview.analyzed_at),
        11.0, Mm(20.0_f32), Mm(y), &font,
    );
    y -= 12.0;

    // ─── Executive Summary ───────────────────────────────────────────────────
    layer.use_text("Executive Summary", 16.0, Mm(20.0_f32), Mm(y), &font_bold);
    y -= 8.0;

    let unique_ips: std::collections::HashSet<std::net::IpAddr> = result.packets.iter()
        .flat_map(|p| [p.src_ip, p.dst_ip].into_iter().flatten())
        .collect();

    let summary_lines = vec![
        format!("Total Packets:    {}", result.overview.total_packets),
        format!("Unique IPs:       {}", unique_ips.len()),
        format!("Capture Duration: {}", duration_str),
        format!("Threats Found:    {}", result.threats.len()),
        format!("Highest Severity: {}", result.highest_severity()),
        format!("DNS Queries:      {}", result.dns_log.len()),
        format!("HTTP Transactions:{}", result.http_log.len()),
    ];

    for line in &summary_lines {
        layer.use_text(line, 11.0, Mm(25.0_f32), Mm(y), &font);
        y -= 6.0;
    }
    y -= 6.0;

    // ─── Threat Findings ─────────────────────────────────────────────────────
    layer.use_text("Threat Findings", 16.0, Mm(20.0_f32), Mm(y), &font_bold);
    y -= 8.0;

    if result.threats.is_empty() {
        layer.use_text("No threats detected in this capture.", 11.0, Mm(25.0_f32), Mm(y), &font);
        y -= 6.0;
    }

    for threat in result.threats.iter() {
        if y < 40.0 {
            layer = new_page(&doc, &mut page_num);
            y = 270.0;
        }

        let title = format!("[{}] {}", sanitize(&threat.severity), sanitize(&threat.title));
        layer.use_text(&title, 12.0, Mm(20.0_f32), Mm(y), &font_bold);
        y -= 6.0;

        for line in &wrap_text(&sanitize(&threat.description), 90) {
            if y < 30.0 {
                layer = new_page(&doc, &mut page_num);
                y = 270.0;
            }
            layer.use_text(line, 10.0, Mm(25.0_f32), Mm(y), &font);
            y -= 5.0;
        }

        layer.use_text(
            format!("Category: {}  |  Packets: {}", sanitize(&threat.category), threat.packet_indices.len()),
            9.0, Mm(25.0_f32), Mm(y), &font,
        );
        y -= 9.0;
    }

    // ─── Top Talkers ─────────────────────────────────────────────────────────
    y -= 4.0;
    if y < 50.0 { layer = new_page(&doc, &mut page_num); y = 270.0; }
    layer.use_text("Top Senders", 16.0, Mm(20.0_f32), Mm(y), &font_bold);
    y -= 7.0;

    layer.use_text(
        format!("{:<20} {:>12} {:>12}", "IP Address", "Packets", "Bytes"),
        10.0, Mm(20.0_f32), Mm(y), &font_bold,
    );
    y -= 5.0;

    for talker in result.top_senders.iter().take(10) {
        if y < 30.0 { layer = new_page(&doc, &mut page_num); y = 270.0; }
        layer.use_text(
            format!(
                "{:<20} {:>12} {:>12}",
                truncate(&sanitize(&talker.ip), 20),
                talker.packets_sent,
                format_bytes(talker.bytes_sent)
            ),
            10.0, Mm(20.0_f32), Mm(y), &font,
        );
        y -= 5.0;
    }

    y -= 8.0;
    if y < 50.0 { layer = new_page(&doc, &mut page_num); y = 270.0; }
    layer.use_text("DNS Summary", 16.0, Mm(20.0_f32), Mm(y), &font_bold);
    y -= 7.0;

    let suspicious_dns: Vec<_> = result.dns_log.iter().filter(|e| e.suspicious).collect();
    layer.use_text(
        format!(
            "Total DNS queries: {}  |  Suspicious: {}",
            result.dns_log.len(),
            suspicious_dns.len()
        ),
        11.0, Mm(25.0_f32), Mm(y), &font,
    );
    y -= 6.0;

    for entry in suspicious_dns.iter().take(10) {
        if y < 30.0 { layer = new_page(&doc, &mut page_num); y = 270.0; }
        layer.use_text(
            format!("  {} — {}", sanitize(&entry.name), sanitize(entry.suspicious_reason.as_deref().unwrap_or(""))),
            9.0, Mm(25.0_f32), Mm(y), &font,
        );
        y -= 5.0;
    }

    let mut buf = BufWriter::new(Vec::new());
    doc.save(&mut buf)?;
    Ok(buf.into_inner()?)
}

fn wrap_text(text: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if current.len() + word.len() + 1 > width {
            if !current.is_empty() {
                lines.push(current.clone());
                current.clear();
            }
        }
        if !current.is_empty() { current.push(' '); }
        current.push_str(word);
    }
    if !current.is_empty() { lines.push(current); }
    lines
}

fn format_bytes(b: usize) -> String {
    if b >= 1_073_741_824 { format!("{:.1} GB", b as f64 / 1_073_741_824.0) }
    else if b >= 1_048_576 { format!("{:.1} MB", b as f64 / 1_048_576.0) }
    else if b >= 1024 { format!("{:.1} KB", b as f64 / 1024.0) }
    else { format!("{} B", b) }
}

fn truncate(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}
