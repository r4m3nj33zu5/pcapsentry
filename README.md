# PcapSentry

A local .pcap file analysis tool with a blue team security focus. Drop a capture file in the browser, get a dashboard with threat detections, traffic timeline, geo map, DNS/HTTP logs, and packet inspection — all running offline on your machine.

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
4. The dashboard loads automatically with:
   - **Overview bar** — packet count, duration, unique IPs, protocols, threat summary
   - **Traffic timeline** — packet volume over time
   - **Threat panel** — findings sorted by severity with plain-English descriptions
   - **Top talkers** — top senders and receivers by volume
   - **Geo map** — geolocated external IPs (requires GeoLite2 database)
   - **DNS/HTTP log** — filterable tables of DNS queries and HTTP transactions
5. Click "View Packets" on any threat finding to open the Packet Inspector
6. Click "Export PDF" (via `POST /api/export/:session_id`) to generate a report
7. Previous sessions from the current run appear in the left sidebar

## Threat Detections

| Detection | Severity |
|---|---|
| ARP Spoofing | Critical |
| Port Scan (SYN) | Critical / High |
| Xmas / NULL / FIN Scans | High |
| Beaconing / C2 Indicators | High |
| Cleartext Credentials (HTTP Basic, FTP) | High |
| ICMP Sweep | Medium |
| Abnormal Traffic Volume | Medium |

## Limitations

- In-memory only — sessions are lost when the process restarts
- Inspector is limited to the first 500,000 packets for large captures (analysis still runs on the full file)
- 802.11 wireless frame parsing requires a capture with RadioTap/IEEE 802.11 linktype
- PDF export uses server-side rendering via `printpdf`

## Project Structure

```
pcapsentry/
├── backend/          # Rust/Axum server
│   ├── src/
│   │   ├── main.rs           # Server, routes, session state
│   │   ├── parser.rs         # pcap/pcapng parsing and packet decoding
│   │   ├── analysis/
│   │   │   ├── mod.rs        # Analysis orchestration
│   │   │   ├── threats.rs    # Threat detection modules
│   │   │   ├── talkers.rs    # Top talker aggregation
│   │   │   ├── dns_http.rs   # DNS/HTTP extraction
│   │   │   └── geo.rs        # IP geolocation
│   │   └── export/
│   │       └── pdf.rs        # PDF report generation
│   └── build.rs              # Builds frontend before Rust compile
├── frontend/         # Svelte/Vite SPA
│   └── src/
│       ├── App.svelte
│       ├── components/       # UI components
│       └── stores/           # Svelte stores
└── assets/
    └── GeoLite2-City.mmdb    # Place your MaxMind DB here
```
