use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use crate::parser::PacketMeta;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TalkerStats {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub packets_sent: usize,
    pub packets_received: usize,
    pub bytes_sent: usize,
    pub bytes_received: usize,
    pub total_bytes: usize,
    pub first_seen: f64,
    pub last_seen: f64,
    pub protocols: Vec<ProtocolCount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCount {
    pub protocol: String,
    pub count: usize,
}

struct IpStats {
    packets_sent: usize,
    packets_received: usize,
    bytes_sent: usize,
    bytes_received: usize,
    first_seen: f64,
    last_seen: f64,
    protocols: HashMap<String, usize>,
}

impl IpStats {
    fn new(ts: f64) -> Self {
        IpStats {
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            first_seen: ts,
            last_seen: ts,
            protocols: HashMap::new(),
        }
    }

    fn update_ts(&mut self, ts: f64) {
        if ts < self.first_seen { self.first_seen = ts; }
        if ts > self.last_seen { self.last_seen = ts; }
    }
}

pub fn compute(packets: &[PacketMeta]) -> (Vec<TalkerStats>, Vec<TalkerStats>) {
    let mut stats: HashMap<String, IpStats> = HashMap::new();
    let mut ip_mac: HashMap<String, String> = HashMap::new();

    for pkt in packets {
        let ts = pkt.timestamp;

        if let Some(src) = &pkt.src_ip {
            let entry = stats.entry(src.clone()).or_insert_with(|| IpStats::new(ts));
            entry.update_ts(ts);
            entry.packets_sent += 1;
            entry.bytes_sent += pkt.length;
            *entry.protocols.entry(pkt.protocol.clone()).or_insert(0) += 1;

            if let Some(mac) = &pkt.src_mac {
                ip_mac.entry(src.clone()).or_insert_with(|| mac.clone());
            }
        }

        if let Some(dst) = &pkt.dst_ip {
            let entry = stats.entry(dst.clone()).or_insert_with(|| IpStats::new(ts));
            entry.update_ts(ts);
            entry.packets_received += 1;
            entry.bytes_received += pkt.length;
        }
    }

    let all: Vec<TalkerStats> = stats
        .into_iter()
        .map(|(ip, s)| {
            let mut protocols: Vec<ProtocolCount> = s.protocols
                .into_iter()
                .map(|(protocol, count)| ProtocolCount { protocol, count })
                .collect();
            protocols.sort_by(|a, b| b.count.cmp(&a.count));

            let mac = ip_mac.get(&ip).cloned();
            let vendor = mac.as_deref().and_then(oui_vendor).map(|v| v.to_string());

            TalkerStats {
                total_bytes: s.bytes_sent + s.bytes_received,
                ip,
                mac,
                vendor,
                packets_sent: s.packets_sent,
                packets_received: s.packets_received,
                bytes_sent: s.bytes_sent,
                bytes_received: s.bytes_received,
                first_seen: s.first_seen,
                last_seen: s.last_seen,
                protocols,
            }
        })
        .collect();

    let mut by_sent = all.clone();
    by_sent.sort_by(|a, b| b.bytes_sent.cmp(&a.bytes_sent));
    by_sent.truncate(20);

    let mut by_received = all.clone();
    by_received.sort_by(|a, b| b.bytes_received.cmp(&a.bytes_received));
    by_received.truncate(20);

    (by_sent, by_received)
}

/// Look up OUI vendor from a MAC address string (colon-separated or raw hex).
/// Strips separators, uppercases, and matches first 6 hex chars against a static table.
fn oui_vendor(mac: &str) -> Option<&'static str> {
    let clean: String = mac
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect::<String>()
        .to_ascii_uppercase();
    if clean.len() < 6 {
        return None;
    }
    let oui = &clean[..6];

    // Static OUI table — keys are 6 uppercase hex chars (no separators).
    static TABLE: &[(&str, &str)] = &[
        // Oracle VirtualBox
        ("080027", "Oracle VirtualBox"),
        // QEMU/KVM
        ("525400", "QEMU/KVM"),
        // Xen Virtual NIC
        ("00163E", "Xen Virtual"),
        // Realtek Semiconductor
        ("00E04C", "Realtek Semiconductor"),
        ("485079", "Realtek Semiconductor"),
        ("E04F43", "Realtek Semiconductor"),
        // Broadcom Corp.
        ("001018", "Broadcom Corp."),
        ("00904B", "Broadcom Corp."),
        ("003065", "Broadcom Corp."),
        // Espressif Systems (ESP32/ESP8266)
        ("18FE34", "Espressif Systems"),
        ("240AC4", "Espressif Systems"),
        ("30AEA4", "Espressif Systems"),
        ("34865D", "Espressif Systems"),
        ("545AA6", "Espressif Systems"),
        ("600194", "Espressif Systems"),
        ("7CDFA1", "Espressif Systems"),
        ("84CCA8", "Espressif Systems"),
        ("84F3EB", "Espressif Systems"),
        ("A4CF12", "Espressif Systems"),
        ("B4E62D", "Espressif Systems"),
        ("CC50E3", "Espressif Systems"),
        ("D8BFC0", "Espressif Systems"),
        ("E8DB84", "Espressif Systems"),
        ("ECFABC", "Espressif Systems"),
        ("F4CFA2", "Espressif Systems"),
        ("FCF5C4", "Espressif Systems"),
        // D-Link Systems
        ("00055D", "D-Link Systems"),
        ("000795", "D-Link Systems"),
        ("000D88", "D-Link Systems"),
        ("001346", "D-Link Systems"),
        ("0015E9", "D-Link Systems"),
        ("001B11", "D-Link Systems"),
        ("001CF0", "D-Link Systems"),
        ("00195B", "D-Link Systems"),
        ("002401", "D-Link Systems"),
        ("00265A", "D-Link Systems"),
        ("1C7EE5", "D-Link Systems"),
        ("28107B", "D-Link Systems"),
        ("340804", "D-Link Systems"),
        ("C8D3A3", "D-Link Systems"),
        ("B8A386", "D-Link Systems"),
        // Juniper Networks
        ("0010DB", "Juniper Networks"),
        ("001350", "Juniper Networks"),
        ("005028", "Juniper Networks"),
        ("00B0D0", "Juniper Networks"),
        ("3C614C", "Juniper Networks"),
        // Palo Alto Networks
        ("001B17", "Palo Alto Networks"),
        ("9C1463", "Palo Alto Networks"),
        // Murata Manufacturing (used in Apple/Sony wireless modules)
        ("04E536", "Murata Manufacturing"),
        ("20AB37", "Murata Manufacturing"),
        ("7C49EB", "Murata Manufacturing"),
        ("8C89A5", "Murata Manufacturing"),
        ("A0AFBD", "Murata Manufacturing"),
        ("D8CF9C", "Murata Manufacturing"),
        // Texas Instruments
        ("001F59", "Texas Instruments"),
        ("001CF1", "Texas Instruments"),
        ("0022B7", "Texas Instruments"),
        ("700288", "Texas Instruments"),
        // Nordic Semiconductor
        ("C41AFF", "Nordic Semiconductor"),
        ("E9E506", "Nordic Semiconductor"),
        // Zyxel Communications
        ("001349", "Zyxel Communications"),
        ("0019CB", "Zyxel Communications"),
        ("002293", "Zyxel Communications"),
        ("00A0C5", "Zyxel Communications"),
        ("001E7A", "Zyxel Communications"),
        ("28282C", "Zyxel Communications"),
        ("C44D63", "Zyxel Communications"),
        // Buffalo Technology
        ("00016D", "Buffalo Technology"),
        ("001D73", "Buffalo Technology"),
        ("002322", "Buffalo Technology"),
        ("0050FC", "Buffalo Technology"),
        // MikroTik
        ("001359", "MikroTik"),
        ("002369", "MikroTik"),
        ("4C5E0C", "MikroTik"),
        ("64D154", "MikroTik"),
        ("B8690A", "MikroTik"),
        ("CC2DE0", "MikroTik"),
        ("D4CA6D", "MikroTik"),
        ("E48D8C", "MikroTik"),
        ("DC2C6E", "MikroTik"),
        // Synology
        ("001132", "Synology"),
        ("BC5FF4", "Synology"),
        // Motorola Solutions
        ("000070", "Motorola Solutions"),
        ("00070E", "Motorola Solutions"),
        ("000A28", "Motorola Solutions"),
        ("000E5C", "Motorola Solutions"),
        ("001C6A", "Motorola Solutions"),
        ("006070", "Motorola Solutions"),
        // Nintendo
        ("001F32", "Nintendo"),
        ("002625", "Nintendo"),
        ("0025A0", "Nintendo"),
        ("002709", "Nintendo"),
        ("002732", "Nintendo"),
        ("00199D", "Nintendo"),
        ("001AE9", "Nintendo"),
        ("A438CC", "Nintendo"),
        // Sony
        ("000A4A", "Sony"),
        ("000EBE", "Sony"),
        ("0013A9", "Sony"),
        ("001918", "Sony"),
        ("001A80", "Sony"),
        ("0024BE", "Sony"),
        ("0050F1", "Sony"),
        ("0CF3EE", "Sony"),
        // LG Electronics
        ("001E75", "LG Electronics"),
        ("003A99", "LG Electronics"),
        ("18264D", "LG Electronics"),
        ("20CF30", "LG Electronics"),
        ("64989A", "LG Electronics"),
        ("700580", "LG Electronics"),
        ("ACC103", "LG Electronics"),
        // Apple, Inc.
        ("000393", "Apple, Inc."), ("000A95", "Apple, Inc."), ("000D93", "Apple, Inc."),
        ("001124", "Apple, Inc."), ("001451", "Apple, Inc."), ("0016CB", "Apple, Inc."),
        ("0019E3", "Apple, Inc."), ("001B63", "Apple, Inc."), ("001CB3", "Apple, Inc."),
        ("001EC2", "Apple, Inc."), ("0021E9", "Apple, Inc."), ("002312", "Apple, Inc."),
        ("0023DF", "Apple, Inc."), ("002436", "Apple, Inc."), ("0025BC", "Apple, Inc."),
        ("002608", "Apple, Inc."), ("0026B0", "Apple, Inc."), ("040CCE", "Apple, Inc."),
        ("1040F3", "Apple, Inc."), ("18AF61", "Apple, Inc."), ("1CABA7", "Apple, Inc."),
        ("283737", "Apple, Inc."), ("28CFE9", "Apple, Inc."), ("3C0754", "Apple, Inc."),
        ("40A6D9", "Apple, Inc."), ("44D884", "Apple, Inc."), ("581FAA", "Apple, Inc."),
        ("600308", "Apple, Inc."), ("685B35", "Apple, Inc."), ("7073CB", "Apple, Inc."),
        ("786C1C", "Apple, Inc."), ("8863DF", "Apple, Inc."), ("90B0ED", "Apple, Inc."),
        ("9801A7", "Apple, Inc."), ("A4B197", "Apple, Inc."), ("AC61EA", "Apple, Inc."),
        ("B48B19", "Apple, Inc."), ("BC3BAF", "Apple, Inc."), ("C82A14", "Apple, Inc."),
        ("D0034B", "Apple, Inc."), ("D49A20", "Apple, Inc."), ("DCA4CA", "Apple, Inc."),
        ("E05F45", "Apple, Inc."), ("F41BA1", "Apple, Inc."), ("F81EDF", "Apple, Inc."),
        // Cisco Systems
        ("00000C", "Cisco Systems"), ("000142", "Cisco Systems"), ("000163", "Cisco Systems"),
        ("000196", "Cisco Systems"), ("0001C7", "Cisco Systems"), ("000268", "Cisco Systems"),
        ("0002FC", "Cisco Systems"), ("000316", "Cisco Systems"), ("000496", "Cisco Systems"),
        ("000527", "Cisco Systems"), ("00053A", "Cisco Systems"), ("0005DC", "Cisco Systems"),
        ("000631", "Cisco Systems"), ("000664", "Cisco Systems"), ("00073A", "Cisco Systems"),
        ("000764", "Cisco Systems"), ("0007B3", "Cisco Systems"), ("0007EB", "Cisco Systems"),
        ("000849", "Cisco Systems"), ("0009B7", "Cisco Systems"), ("000A41", "Cisco Systems"),
        ("000AB7", "Cisco Systems"), ("000B45", "Cisco Systems"), ("000C30", "Cisco Systems"),
        ("000C85", "Cisco Systems"), ("000D28", "Cisco Systems"), ("000D86", "Cisco Systems"),
        ("000E08", "Cisco Systems"), ("000E83", "Cisco Systems"), ("000F23", "Cisco Systems"),
        ("001005", "Cisco Systems"), ("001048", "Cisco Systems"), ("001154", "Cisco Systems"),
        ("0012DA", "Cisco Systems"), ("001301", "Cisco Systems"), ("001420", "Cisco Systems"),
        ("001517", "Cisco Systems"), ("001636", "Cisco Systems"), ("001763", "Cisco Systems"),
        // Intel Corporate
        ("0002B3", "Intel Corporate"), ("000347", "Intel Corporate"), ("000423", "Intel Corporate"),
        ("001302", "Intel Corporate"), ("001320", "Intel Corporate"), ("001676", "Intel Corporate"),
        ("0018DE", "Intel Corporate"), ("001B21", "Intel Corporate"), ("001DE0", "Intel Corporate"),
        ("001E64", "Intel Corporate"), ("001E65", "Intel Corporate"), ("00216A", "Intel Corporate"),
        ("0022FA", "Intel Corporate"), ("002314", "Intel Corporate"), ("8C8D28", "Intel Corporate"),
        ("A44E31", "Intel Corporate"), ("F4060D", "Intel Corporate"),
        // Samsung Electronics
        ("001247", "Samsung Electronics"), ("0015B9", "Samsung Electronics"),
        ("001632", "Samsung Electronics"), ("0017C9", "Samsung Electronics"),
        ("0018AF", "Samsung Electronics"), ("001A8A", "Samsung Electronics"),
        ("001B98", "Samsung Electronics"), ("001C43", "Samsung Electronics"),
        ("001D25", "Samsung Electronics"), ("001E7D", "Samsung Electronics"),
        ("002119", "Samsung Electronics"), ("002339", "Samsung Electronics"),
        ("002454", "Samsung Electronics"), ("002567", "Samsung Electronics"),
        ("A00798", "Samsung Electronics"), ("AC36DD", "Samsung Electronics"),
        ("CC07AB", "Samsung Electronics"), ("F4428F", "Samsung Electronics"),
        // Dell Technologies
        ("00065B", "Dell Technologies"), ("000BDB", "Dell Technologies"),
        ("001143", "Dell Technologies"), ("00123F", "Dell Technologies"),
        ("001372", "Dell Technologies"), ("001422", "Dell Technologies"),
        ("0015C5", "Dell Technologies"), ("0016F0", "Dell Technologies"),
        ("001AA0", "Dell Technologies"), ("001C23", "Dell Technologies"),
        ("001E4F", "Dell Technologies"), ("002219", "Dell Technologies"),
        ("0023AE", "Dell Technologies"), ("0024E8", "Dell Technologies"),
        ("002564", "Dell Technologies"), ("0026B9", "Dell Technologies"),
        ("1C4024", "Dell Technologies"), ("549F35", "Dell Technologies"),
        ("90B11C", "Dell Technologies"),
        // Hewlett Packard
        ("0011BE", "Hewlett Packard"), ("0012A9", "Hewlett Packard"),
        ("001311", "Hewlett Packard"), ("001438", "Hewlett Packard"),
        ("001560", "Hewlett Packard"), ("001635", "Hewlett Packard"),
        ("00173A", "Hewlett Packard"), ("001871", "Hewlett Packard"),
        ("001A4B", "Hewlett Packard"), ("001B78", "Hewlett Packard"),
        ("001CC4", "Hewlett Packard"), ("001E0B", "Hewlett Packard"),
        ("001F29", "Hewlett Packard"), ("001FE1", "Hewlett Packard"),
        ("002255", "Hewlett Packard"), ("00237D", "Hewlett Packard"),
        ("00248D", "Hewlett Packard"), ("002569", "Hewlett Packard"),
        ("00266C", "Hewlett Packard"),
        // VMware, Inc.
        ("000569", "VMware, Inc."), ("000C29", "VMware, Inc."),
        ("001C14", "VMware, Inc."), ("005056", "VMware, Inc."),
        // Microsoft Corporation
        ("00155D", "Microsoft Corporation"), ("28180F", "Microsoft Corporation"),
        ("7C1E52", "Microsoft Corporation"),
        // Raspberry Pi Foundation
        ("B827EB", "Raspberry Pi Foundation"), ("DCA632", "Raspberry Pi Foundation"),
        ("E45F01", "Raspberry Pi Foundation"),
        // TP-Link Technologies
        ("14CC20", "TP-Link Technologies"), ("1C61B4", "TP-Link Technologies"),
        ("50BD5F", "TP-Link Technologies"), ("54A050", "TP-Link Technologies"),
        ("642737", "TP-Link Technologies"), ("6C5AB0", "TP-Link Technologies"),
        ("74EA3A", "TP-Link Technologies"), ("78A1B8", "TP-Link Technologies"),
        ("9CEFD5", "TP-Link Technologies"), ("A0F3C1", "TP-Link Technologies"),
        ("B0487A", "TP-Link Technologies"), ("D8EBC1", "TP-Link Technologies"),
        ("E84DD0", "TP-Link Technologies"), ("F81A67", "TP-Link Technologies"),
        ("FC3271", "TP-Link Technologies"),
        // Netgear
        ("00095B", "Netgear"), ("000F3D", "Netgear"), ("000FB5", "Netgear"),
        ("001221", "Netgear"), ("00146C", "Netgear"), ("0014BF", "Netgear"),
        ("001853", "Netgear"), ("001B2F", "Netgear"), ("001E2A", "Netgear"),
        ("001F33", "Netgear"), ("00224A", "Netgear"), ("00266E", "Netgear"),
        ("20E52A", "Netgear"), ("28C68E", "Netgear"), ("44940C", "Netgear"),
        ("74440B", "Netgear"), ("A021B7", "Netgear"),
        // ASUSTek Computer
        ("001A92", "ASUSTek Computer"), ("001D60", "ASUSTek Computer"),
        ("001E8C", "ASUSTek Computer"), ("002354", "ASUSTek Computer"),
        ("00248C", "ASUSTek Computer"), ("107B44", "ASUSTek Computer"),
        ("1C872C", "ASUSTek Computer"), ("2C56DC", "ASUSTek Computer"),
        ("4CE676", "ASUSTek Computer"), ("60A44C", "ASUSTek Computer"),
        ("74D02B", "ASUSTek Computer"), ("BC8E8A", "ASUSTek Computer"),
        ("E0CB4E", "ASUSTek Computer"), ("F46D04", "ASUSTek Computer"),
        // Ubiquiti Networks
        ("00156D", "Ubiquiti Networks"), ("002722", "Ubiquiti Networks"),
        ("04180F", "Ubiquiti Networks"), ("24A43C", "Ubiquiti Networks"),
        ("44D9E7", "Ubiquiti Networks"), ("68722D", "Ubiquiti Networks"),
        ("788A20", "Ubiquiti Networks"), ("80271D", "Ubiquiti Networks"),
        ("E063DA", "Ubiquiti Networks"), ("F09FC2", "Ubiquiti Networks"),
        ("FCECE2", "Ubiquiti Networks"),
        // Aruba Networks (HPE)
        ("000B86", "Aruba Networks"), ("001A1E", "Aruba Networks"),
        ("002390", "Aruba Networks"), ("0025EB", "Aruba Networks"),
        ("6CF37F", "Aruba Networks"), ("888AE1", "Aruba Networks"),
        ("ACA31E", "Aruba Networks"),
        // Google
        ("001A11", "Google"), ("3C5AB4", "Google"), ("546009", "Google"),
        ("A4770B", "Google"), ("F4F5D8", "Google"),
        // Amazon Technologies
        ("001337", "Amazon Technologies"), ("40B4CD", "Amazon Technologies"),
        ("44650D", "Amazon Technologies"), ("747548", "Amazon Technologies"),
        ("78F290", "Amazon Technologies"), ("84D6D0", "Amazon Technologies"),
        ("A002DC", "Amazon Technologies"), ("AC63BE", "Amazon Technologies"),
        ("F0272D", "Amazon Technologies"), ("FC65DE", "Amazon Technologies"),
        // Lenovo
        ("000D56", "Lenovo"), ("000F1F", "Lenovo"), ("001D72", "Lenovo"),
        ("002137", "Lenovo"), ("002154", "Lenovo"), ("0025B3", "Lenovo"),
        ("70F1A1", "Lenovo"), ("88703C", "Lenovo"), ("A447CA", "Lenovo"),
        ("C4B301", "Lenovo"),
        // Huawei Technologies
        ("00E0FC", "Huawei Technologies"), ("001882", "Huawei Technologies"),
        ("00259E", "Huawei Technologies"), ("0C37DC", "Huawei Technologies"),
        ("1C8E5C", "Huawei Technologies"), ("28A25E", "Huawei Technologies"),
        ("305A3A", "Huawei Technologies"), ("3C47C9", "Huawei Technologies"),
        ("485073", "Huawei Technologies"), ("54514F", "Huawei Technologies"),
        ("6CAB31", "Huawei Technologies"), ("8C0DED", "Huawei Technologies"),
        ("A4CAA0", "Huawei Technologies"), ("D07AB5", "Huawei Technologies"),
        ("E8CD2D", "Huawei Technologies"), ("F4559C", "Huawei Technologies"),
        // Fortinet
        ("000BC1", "Fortinet"), ("001648", "Fortinet"), ("004078", "Fortinet"),
        ("708781", "Fortinet"), ("80E01D", "Fortinet"), ("90EC77", "Fortinet"),
    ];

    TABLE.iter().find(|(k, _)| *k == oui).map(|(_, v)| *v)
}
