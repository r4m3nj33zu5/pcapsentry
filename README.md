# PcapSentry

A local .pcap file analysis tool with a blue team security focus. Drop a capture file in the browser, get a SOC-style dashboard with threat detections, suspicious conversation scoring, traffic timeline, geo map, DNS/HTTP/TLS logs, and packet inspection — all running offline on your machine.

## Prerequisites

- **Rust** (stable) — https://rustup.rs
- **Node.js 18+** — https://nodejs.org
- **Optional:** MaxMind GeoLite2-City.mmdb for IP geolocation (see below)

## Build

```bash
cd backend
cargo build --release
```

This will automatically run `npm install` and `npm run build` in the `frontend/` directory before compiling the Rust binary.

The compiled binary will be at `backend/target/release/pcapsentry`.

## GeoLite2 Setup (optional)

PcapSentry uses the free MaxMind GeoLite2-City database for IP geolocation on the map view.

1. Create a free account at https://www.maxmind.com
2. Download the **GeoLite2-City** database in `.mmdb` format
3. Place the file at `assets/GeoLite2-City.mmdb` (in the project root, next to the `backend/` and `frontend/` directories)

If this file is not present, PcapSentry will start normally — the geo map will display a placeholder explaining the setup steps.

## Run

```bash
cd backend
./target/release/pcapsentry
```

Then open http://localhost:7777 in your browser.

PcapSentry must be run from the `backend/` directory so it can locate the `../frontend/dist` static files and `../assets/` directory.

## Usage

1. Open http://localhost:7777
2. Drag and drop a `.pcap` or `.pcapng` file onto the upload zone (or click "Browse files")
3. A progress bar will appear while the capture is parsed
4. The dashboard loads with 13 modules: **Triage**, **Alerts**, **Conversations** (suspicious conversations scored by joined alert/beaconing/TLS signals), **Flows**, **DNS**, **HTTP**, **TLS**, **IOC**, **Geo**, **Stats**, **Timeline**, **Packets**, and **Notes**
5. Click any finding to isolate its packets in the Packet Inspector; TCP streams can be reassembled and viewed inline
6. "Export PDF" generates a report; CSV export is available per module
7. Sessions are saved to disk and reappear in the left sidebar after a restart
8. Alert thresholds, IP/domain whitelists, and optional VirusTotal/Shodan API keys are configurable in the Settings panel

## Supported Captures

- **Formats:** classic pcap and pcapng (auto-detected by magic bytes)
- **Link layers:** Ethernet (including 802.1Q VLAN and 802.1ad QinQ tagged frames), Linux cooked capture v1 (SLL, from `tcpdump -i any`) and v2 (SLL2)
- Not supported: 802.11/RadioTap wireless frames, and pcapng files that mix link layers across interfaces in one file

## Threat Detections

| Detection | Severity |
|---|---|
| ARP Spoofing | Critical |
| Known-malware ports (Metasploit, NetBus, IRC C2, …) | Critical / High |
| Port Scan (SYN) / Xmas / NULL / FIN Scans | Critical / High |
| Beaconing / C2 callbacks (TCP + UDP, QUIC exempted) | High |
| DNS Tunneling / High-entropy DNS labels | High / Medium |
| Cleartext Credentials (HTTP Basic, FTP) | High |
| TLS anomalies / known-bad JA3 fingerprints | High / Medium |
| SYN / ICMP / UDP Floods (QUIC exempted) | Medium |
| Oversized ICMP, ICMP Sweep | Medium |
| Abnormal Traffic Volume | Medium |

## Limitations

- Very large captures are truncated to the first 500,000 packets — analysis and detections only cover those packets
- No 802.11 wireless frame parsing
- PDF export uses server-side rendering via `printpdf`

## Project Structure

```
pcapsentry/
├── backend/          # Rust/Axum server
│   ├── src/
│   │   ├── main.rs           # Server, routes, session state
│   │   ├── parser.rs         # pcap/pcapng parsing, Ethernet/VLAN/SLL decode
│   │   ├── persistence.rs    # Session save/load (gzipped JSON in data dir)
│   │   ├── reassembly.rs     # TCP stream reassembly
│   │   ├── config.rs         # Alert thresholds, whitelist, API keys
│   │   ├── analysis/
│   │   │   ├── mod.rs            # Analysis orchestration
│   │   │   ├── indexed.rs        # Pre-indexed packet view for detectors
│   │   │   ├── alerts.rs         # Alert engine detections
│   │   │   ├── beaconing.rs      # Beaconing candidate detection
│   │   │   ├── conversations.rs  # Suspicious conversation scoring
│   │   │   ├── talkers.rs        # Top talker aggregation
│   │   │   ├── dns_http.rs       # DNS/HTTP extraction
│   │   │   ├── tls.rs            # TLS/JA3 analysis
│   │   │   └── geo.rs            # IP geolocation
│   │   └── export/           # PDF + CSV report generation
│   └── build.rs              # Builds frontend before Rust compile
├── frontend/         # Svelte/Vite SPA
│   └── src/
│       ├── App.svelte
│       ├── components/       # UI components and dashboard modules
│       └── stores/           # Svelte stores
└── assets/
    ├── ja3_known_bad.csv     # Known-bad JA3 fingerprint list
    └── GeoLite2-City.mmdb    # Place your MaxMind DB here (optional)
```
