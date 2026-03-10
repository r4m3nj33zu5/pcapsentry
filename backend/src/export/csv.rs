use crate::analysis::flows::ConnectionFlow;
use crate::analysis::ioc::IocBundle;

pub fn flows_to_csv(flows: &[ConnectionFlow]) -> String {
    let mut out = String::from("flow_id,src_ip,src_port,dst_ip,dst_port,protocol,packets,bytes,first_seen,last_seen,duration_secs,bytes_per_second,service,state,is_suspicious\n");
    for f in flows {
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{},{:.3},{:.3},{:.3},{:.1},{},{},{}\n",
            csv_escape(&f.flow_id),
            f.src_ip,
            f.src_port.unwrap_or(0),
            f.dst_ip,
            f.dst_port.unwrap_or(0),
            f.protocol,
            f.packets,
            f.bytes,
            f.first_seen,
            f.last_seen,
            f.duration_secs,
            f.bytes_per_second,
            f.service_guess,
            f.state,
            f.is_suspicious,
        ));
    }
    out
}

pub fn ioc_to_csv(ioc: &IocBundle) -> String {
    let mut out = String::from("type,value,packet_count,bytes,country,asn_org,is_suspicious,reason\n");
    for ip in &ioc.ips {
        out.push_str(&format!(
            "ip,{},{},{},{},{},false,\n",
            ip.ip,
            ip.packet_count,
            ip.bytes,
            ip.country.as_deref().unwrap_or(""),
            ip.asn_org.as_deref().unwrap_or(""),
        ));
    }
    for domain in &ioc.domains {
        out.push_str(&format!(
            "domain,{},{},0,,{},{}\n",
            csv_escape(&domain.domain),
            domain.query_count,
            domain.is_suspicious,
            csv_escape(domain.suspicious_reason.as_deref().unwrap_or("")),
        ));
    }
    for url in &ioc.urls {
        out.push_str(&format!(
            "url,{},{},0,,,{},\n",
            csv_escape(&url.url),
            url.packet_count,
            url.is_suspicious,
        ));
    }
    out
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
