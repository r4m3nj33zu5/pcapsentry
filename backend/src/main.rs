mod parser;
mod analysis;
mod export;
mod config;
mod persistence;
pub mod reassembly;

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path as AxumPath, Query, State},
    http::StatusCode,
    http::Uri,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use include_dir::{include_dir, Dir};
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use uuid::Uuid;

use crate::analysis::AnalysisResult;
use crate::config::{AppConfig, ConfigPayload};

static FRONTEND_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../frontend/dist");

#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<DashMap<String, SessionState>>,
    pub geo_enabled: bool,
    pub config: Arc<dashmap::DashMap<(), AppConfig>>,
}

impl AppState {
    fn get_config(&self) -> AppConfig {
        self.config.get(&()).map(|c| c.clone()).unwrap_or_default()
    }
    fn set_config(&self, cfg: AppConfig) {
        self.config.insert((), cfg);
    }
}

#[derive(Clone)]
pub enum SessionState {
    Processing(Arc<AtomicU8>),
    Complete(Arc<AnalysisResult>),
    Error(String),
}

#[derive(Deserialize)]
struct FlowQuery {
    offset: Option<usize>,
    limit: Option<usize>,
    filter: Option<String>,
    sort: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let geo_enabled = Path::new("../assets/GeoLite2-City.mmdb").exists();
    if !geo_enabled {
        eprintln!(
            "Warning: GeoLite2-City.mmdb not found at assets/GeoLite2-City.mmdb — geo map disabled."
        );
    }

    let initial_config = AppConfig::load();
    let config_store: Arc<dashmap::DashMap<(), AppConfig>> = Arc::new(dashmap::DashMap::new());
    config_store.insert((), initial_config);

    let state = AppState {
        sessions: Arc::new(DashMap::new()),
        geo_enabled,
        config: config_store,
    };

    // Load persisted sessions
    for (sid, result) in persistence::load_all() {
        state.sessions.insert(sid, SessionState::Complete(Arc::new(result)));
    }

    let cors = CorsLayer::new()
        .allow_origin("http://localhost:7777".parse::<axum::http::HeaderValue>().unwrap())
        .allow_methods([axum::http::Method::GET, axum::http::Method::POST, axum::http::Method::DELETE])
        .allow_headers([axum::http::header::CONTENT_TYPE]);

    const TWO_GB: usize = 2 * 1024 * 1024 * 1024;

    let api = Router::new()
        // Core
        .route("/api/upload", post(upload_handler))
        .route("/api/progress/:session_id", get(progress_handler))
        .route("/api/results/:session_id", get(results_handler))
        .route("/api/packet/:session_id/:packet_index", get(packet_handler))
        .route("/api/export/:session_id", post(export_handler))
        .route("/api/sessions", get(sessions_handler))
        .route("/api/sessions/:session_id", axum::routing::delete(delete_session_handler))
        // Module-specific endpoints
        .route("/api/results/:session_id/executive", get(module_executive))
        .route("/api/results/:session_id/alerts", get(module_alerts))
        .route("/api/results/:session_id/flows", get(module_flows))
        .route("/api/results/:session_id/tls", get(module_tls))
        .route("/api/results/:session_id/dns", get(module_dns))
        .route("/api/results/:session_id/http", get(module_http))
        .route("/api/results/:session_id/geo", get(module_geo))
        .route("/api/results/:session_id/ioc", get(module_ioc))
        .route("/api/results/:session_id/timeline", get(module_timeline))
        .route("/api/results/:session_id/proto-hierarchy", get(module_proto_hierarchy))
        .route("/api/results/:session_id/notes", get(module_notes_get))
        .route("/api/results/:session_id/notes", post(module_notes_post))
        .route("/api/results/:session_id/beaconing", get(module_beaconing))
        .route("/api/results/:session_id/conversations", get(module_conversations))
        .route("/api/stream/:session_id", get(stream_list_handler))
        .route("/api/stream/:session_id/:stream_index", get(stream_detail_handler))
        // Export
        .route("/api/results/:session_id/export/csv/flows", get(export_csv_flows))
        .route("/api/results/:session_id/export/csv/ioc", get(export_csv_ioc))
        .route("/api/results/:session_id/export/pdf", post(export_pdf_handler))
        // Config
        .route("/api/config", get(config_get))
        .route("/api/config", post(config_post))
        // Enrichment (on-demand)
        .route("/api/enrich/ip/:ip", post(enrich_ip))
        .route("/api/enrich/domain/:domain", post(enrich_domain))
        .with_state(state)
        .layer(DefaultBodyLimit::max(TWO_GB))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    let app = api.fallback(serve_embedded);

    let listener = match tokio::net::TcpListener::bind("127.0.0.1:7777").await {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            println!("PcapSentry is already running at http://localhost:7777");
            let _ = open::that("http://localhost:7777");
            return;
        }
        Err(e) => { eprintln!("Failed to bind port 7777: {e}"); return; }
    };
    println!("PcapSentry running at http://localhost:7777");
    let _ = open::that("http://localhost:7777");
    axum::serve(listener, app).await.unwrap();
}

// ─── Helper ──────────────────────────────────────────────────────────────────

fn get_complete(state: &AppState, session_id: &str) -> Option<Arc<AnalysisResult>> {
    match state.sessions.get(session_id).map(|v| v.clone()) {
        Some(SessionState::Complete(r)) => Some(r),
        _ => None,
    }
}

// ─── Embedded Frontend ───────────────────────────────────────────────────────

async fn serve_embedded(uri: Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() { "index.html" } else { path };

    match FRONTEND_DIR.get_file(path) {
        Some(file) => {
            let mime = match path.rsplit('.').next() {
                Some("html")  => "text/html; charset=utf-8",
                Some("js")    => "application/javascript",
                Some("css")   => "text/css",
                Some("json")  => "application/json",
                Some("svg")   => "image/svg+xml",
                Some("png")   => "image/png",
                Some("ico")   => "image/x-icon",
                Some("woff2") => "font/woff2",
                Some("woff")  => "font/woff",
                _             => "application/octet-stream",
            };
            ([(axum::http::header::CONTENT_TYPE, mime)], file.contents()).into_response()
        }
        None => match FRONTEND_DIR.get_file("index.html") {
            Some(index) => ([(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], index.contents()).into_response(),
            // Frontend not bundled (e.g. dev build without npm). Surface a
            // useful error instead of panicking the request handler.
            None => (StatusCode::INTERNAL_SERVER_ERROR, "PcapSentry frontend assets not bundled — rebuild with the frontend present.").into_response(),
        },
    }
}

// ─── Upload & Progress ───────────────────────────────────────────────────────

async fn upload_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let session_id = Uuid::new_v4().to_string();

    const MAX_SESSIONS: usize = 50;
    if state.sessions.len() >= MAX_SESSIONS {
        return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": "Session limit reached. Close existing sessions before uploading."}))).into_response();
    }

    while let Ok(Some(mut field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let filename = field.file_name().unwrap_or("upload.pcap").to_string();
            let filename_clone = filename.clone();

            // Stream the upload body to a temp file rather than buffering the
            // whole pcap in memory (which used to peak at ~2× the file size
            // because field.bytes() + .to_vec() copies). The temp file is
            // dropped (auto-deleted) once we finish reading it back for parse.
            let mut tmp = match tempfile::NamedTempFile::new() {
                Ok(f) => f,
                Err(e) => {
                    return (StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": format!("Failed to create temp file: {}", e)}))).into_response();
                }
            };
            use std::io::Write;
            loop {
                match field.chunk().await {
                    Ok(Some(chunk)) => {
                        if let Err(e) = tmp.write_all(&chunk) {
                            return (StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"error": format!("Failed to write upload: {}", e)}))).into_response();
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        return (StatusCode::BAD_REQUEST,
                            Json(json!({"error": format!("Failed to read upload chunk: {}", e)}))).into_response();
                    }
                }
            }
            if let Err(e) = tmp.flush() {
                return (StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("Failed to flush upload: {}", e)}))).into_response();
            }

            let progress = Arc::new(AtomicU8::new(0));
            state.sessions.insert(session_id.clone(), SessionState::Processing(Arc::clone(&progress)));

            let sid = session_id.clone();
            let sessions = state.sessions.clone();
            let geo_enabled = state.geo_enabled;
            let cfg = state.get_config();
            let progress_clone = Arc::clone(&progress);

            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || -> anyhow::Result<crate::analysis::AnalysisResult> {
                    // Read the spooled body into a single Vec for parsing.
                    // Peak RSS is ~1× the file size instead of ~2×; the temp
                    // file is dropped on scope exit.
                    let data = std::fs::read(tmp.path())?;
                    parser::parse_capture(&data, &filename, geo_enabled, &cfg, progress_clone)
                }).await;

                match result {
                    Ok(Ok(analysis)) => {
                        let arc = Arc::new(analysis);
                        if let Err(e) = persistence::save(&sid, &arc) {
                            eprintln!("Warning: could not persist session {}: {}", sid, e);
                        }
                        sessions.insert(sid, SessionState::Complete(arc));
                    }
                    Ok(Err(e)) => { sessions.insert(sid, SessionState::Error(e.to_string())); }
                    Err(e) => { sessions.insert(sid, SessionState::Error(e.to_string())); }
                }
            });

            return Json(json!({ "session_id": session_id, "filename": filename_clone })).into_response();
        }
    }

    (StatusCode::BAD_REQUEST, Json(json!({"error": "No file field found in upload"}))).into_response()
}

async fn progress_handler(State(state): State<AppState>, AxumPath(session_id): AxumPath<String>) -> impl IntoResponse {
    match state.sessions.get(&session_id).map(|v| v.clone()) {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found"}))).into_response(),
        Some(SessionState::Processing(progress)) => Json(json!({"status": "processing", "progress": progress.load(Ordering::Relaxed)})).into_response(),
        Some(SessionState::Complete(_)) => Json(json!({"status": "complete", "progress": 100})).into_response(),
        Some(SessionState::Error(e)) => Json(json!({"status": "error", "error": e})).into_response(),
    }
}

async fn results_handler(State(state): State<AppState>, AxumPath(session_id): AxumPath<String>) -> impl IntoResponse {
    match state.sessions.get(&session_id).map(|v| v.clone()) {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found"}))).into_response(),
        Some(SessionState::Processing(progress)) => Json(json!({"status": "processing", "progress": progress.load(Ordering::Relaxed)})).into_response(),
        Some(SessionState::Complete(result)) => Json(serde_json::to_value(&*result).unwrap()).into_response(),
        Some(SessionState::Error(e)) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response(),
    }
}

async fn packet_handler(
    State(state): State<AppState>,
    AxumPath((session_id, packet_index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    match get_complete(&state, &session_id) {
        Some(result) => {
            if let Some(pkt) = result.packets.get(packet_index) {
                Json(serde_json::to_value(pkt).unwrap()).into_response()
            } else {
                (StatusCode::NOT_FOUND, Json(json!({"error": "Packet index out of range"}))).into_response()
            }
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found or not complete"}))).into_response(),
    }
}

async fn export_handler(State(state): State<AppState>, AxumPath(session_id): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &session_id) {
        Some(result) => match export::pdf::generate_pdf(&result) {
            Ok(bytes) => {
                let headers = [
                    ("Content-Type", "application/pdf"),
                    ("Content-Disposition", "attachment; filename=\"pcapsentry-report.pdf\""),
                ];
                (headers, bytes).into_response()
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("PDF generation failed: {}", e)}))).into_response(),
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found or not complete"}))).into_response(),
    }
}

async fn sessions_handler(State(state): State<AppState>) -> impl IntoResponse {
    let sessions: Vec<Value> = state.sessions.iter().map(|entry| {
        let id = entry.key().clone();
        match entry.value() {
            SessionState::Processing(progress) => json!({ "session_id": id, "status": "processing", "progress": progress.load(Ordering::Relaxed) }),
            SessionState::Complete(r) => json!({
                "session_id": id, "status": "complete",
                "filename": r.overview.filename,
                "total_packets": r.overview.total_packets,
                "highest_severity": r.highest_severity(),
                "analyzed_at": r.overview.analyzed_at
            }),
            SessionState::Error(e) => json!({ "session_id": id, "status": "error", "error": e }),
        }
    }).collect();
    Json(json!({"sessions": sessions}))
}

// ─── Module Endpoints ────────────────────────────────────────────────────────

async fn module_executive(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.executive).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_alerts(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.alerts).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_flows(
    State(state): State<AppState>,
    AxumPath(sid): AxumPath<String>,
    Query(q): Query<FlowQuery>,
) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => {
            let offset = q.offset.unwrap_or(0);
            let limit = q.limit.unwrap_or(100).min(1000);
            let filter = q.filter.as_deref().unwrap_or("").to_lowercase();

            let sort = q.sort.as_deref().unwrap_or("bytes");

            let mut filtered: Vec<_> = r.flows.iter()
                .filter(|f| {
                    if filter.is_empty() { return true; }
                    f.src_ip.contains(&filter) || f.dst_ip.contains(&filter)
                        || f.protocol.to_lowercase().contains(&filter)
                        || f.service_guess.to_lowercase().contains(&filter)
                })
                .collect();

            match sort {
                "packets" => filtered.sort_by(|a, b| b.packets.cmp(&a.packets)),
                "duration" => filtered.sort_by(|a, b| b.duration_secs.partial_cmp(&a.duration_secs).unwrap_or(std::cmp::Ordering::Equal)),
                "first_seen" => filtered.sort_by(|a, b| a.first_seen.partial_cmp(&b.first_seen).unwrap_or(std::cmp::Ordering::Equal)),
                "bps" => filtered.sort_by(|a, b| b.bytes_per_second.partial_cmp(&a.bytes_per_second).unwrap_or(std::cmp::Ordering::Equal)),
                _ => filtered.sort_by(|a, b| b.bytes.cmp(&a.bytes)), // "bytes" is default
            }

            let total = filtered.len();
            let page: Vec<_> = filtered.into_iter().skip(offset).take(limit).collect();

            Json(json!({
                "total": total,
                "offset": offset,
                "limit": limit,
                "flows": page
            })).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_tls(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.tls_sessions).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_dns(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.dns_log).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_http(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.http_log).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_geo(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.geo_points).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_ioc(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.ioc_bundle).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_timeline(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.timeline_events).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_proto_hierarchy(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.proto_hierarchy).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_notes_get(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(json!({ "notes": r.notes })).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

#[derive(Deserialize)]
struct NotesPayload {
    notes: String,
}

async fn module_notes_post(
    State(state): State<AppState>,
    AxumPath(sid): AxumPath<String>,
    Json(payload): Json<NotesPayload>,
) -> impl IntoResponse {
    // Replace the session's AnalysisResult atomically under the DashMap entry
    // lock so concurrent POSTs cannot lose writes, then persist to disk so
    // notes survive restart.
    let new_arc = {
        let Some(mut entry) = state.sessions.get_mut(&sid) else {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response();
        };
        let SessionState::Complete(ref result) = *entry else {
            return (StatusCode::NOT_FOUND, Json(json!({"error": "Session not complete"}))).into_response();
        };
        let mut new_result = (**result).clone();
        new_result.notes = payload.notes;
        let new_arc = Arc::new(new_result);
        *entry = SessionState::Complete(Arc::clone(&new_arc));
        new_arc
    };
    if let Err(e) = persistence::save(&sid, &new_arc) {
        eprintln!("Warning: could not persist notes for session {}: {}", sid, e);
    }
    Json(json!({"ok": true})).into_response()
}

// ─── Export Endpoints ────────────────────────────────────────────────────────

async fn export_csv_flows(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => {
            let csv = export::csv::flows_to_csv(&r.flows);
            let headers = [
                ("Content-Type", "text/csv"),
                ("Content-Disposition", "attachment; filename=\"pcapsentry-flows.csv\""),
            ];
            (headers, csv).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn export_csv_ioc(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => {
            let ioc = r.ioc_bundle.as_ref().cloned().unwrap_or_default();
            let csv = export::csv::ioc_to_csv(&ioc);
            let headers = [
                ("Content-Type", "text/csv"),
                ("Content-Disposition", "attachment; filename=\"pcapsentry-ioc.csv\""),
            ];
            (headers, csv).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn export_pdf_handler(State(state): State<AppState>, AxumPath(session_id): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &session_id) {
        Some(result) => match export::pdf::generate_pdf(&result) {
            Ok(bytes) => {
                let headers = [
                    ("Content-Type", "application/pdf"),
                    ("Content-Disposition", "attachment; filename=\"pcapsentry-report.pdf\""),
                ];
                (headers, bytes).into_response()
            }
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("PDF failed: {}", e)}))).into_response(),
        },
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn delete_session_handler(
    State(state): State<AppState>,
    AxumPath(sid): AxumPath<String>,
) -> impl IntoResponse {
    if state.sessions.remove(&sid).is_none() {
        return (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found"}))).into_response();
    }
    if let Err(e) = persistence::delete(&sid) {
        eprintln!("Warning: could not delete persisted session {}: {}", sid, e);
    }
    Json(json!({"ok": true})).into_response()
}

async fn module_beaconing(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.beaconing).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn module_conversations(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => Json(serde_json::to_value(&r.suspicious_conversations).unwrap()).into_response(),
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn stream_list_handler(State(state): State<AppState>, AxumPath(sid): AxumPath<String>) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => {
            let list: Vec<_> = r.streams.iter().enumerate().map(|(i, s)| {
                json!({
                    "index": i,
                    "src_ip": s.src_ip,
                    "src_port": s.src_port,
                    "dst_ip": s.dst_ip,
                    "dst_port": s.dst_port,
                    "forward_bytes": s.forward_payload.len(),
                    "backward_bytes": s.backward_payload.len(),
                    "timestamp": s.timestamp,
                })
            }).collect();
            Json(json!({ "streams": list, "total": list.len() })).into_response()
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response(),
    }
}

async fn stream_detail_handler(
    State(state): State<AppState>,
    AxumPath((sid, idx)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    match get_complete(&state, &sid) {
        Some(r) => {
            match r.streams.get(idx) {
                Some(s) => {
                    let fwd_text = decode_payload(&s.forward_payload);
                    let bwd_text = decode_payload(&s.backward_payload);
                    let fwd_hex = to_hex_dump(&s.forward_payload);
                    let bwd_hex = to_hex_dump(&s.backward_payload);
                    Json(json!({
                        "index": idx,
                        "src_ip": s.src_ip, "src_port": s.src_port,
                        "dst_ip": s.dst_ip, "dst_port": s.dst_port,
                        "timestamp": s.timestamp,
                        "forward": { "text": fwd_text, "hex": fwd_hex, "bytes": s.forward_payload.len() },
                        "backward": { "text": bwd_text, "hex": bwd_hex, "bytes": s.backward_payload.len() },
                    })).into_response()
                }
                None => (StatusCode::NOT_FOUND, Json(json!({"error": "Stream index out of range"}))).into_response(),
            }
        }
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found"}))).into_response(),
    }
}

fn decode_payload(bytes: &[u8]) -> String {
    let truncated = if bytes.len() > 65536 { &bytes[..65536] } else { bytes };
    match std::str::from_utf8(truncated) {
        Ok(s) => s.to_string(),
        Err(_) => {
            // Replace non-UTF8 bytes with replacement char
            String::from_utf8_lossy(truncated).into_owned()
        }
    }
}

fn to_hex_dump(bytes: &[u8]) -> String {
    let truncated = if bytes.len() > 4096 { &bytes[..4096] } else { bytes };
    let mut out = String::new();
    for (i, chunk) in truncated.chunks(16).enumerate() {
        out.push_str(&format!("{:08x}  ", i * 16));
        for (j, b) in chunk.iter().enumerate() {
            out.push_str(&format!("{:02x} ", b));
            if j == 7 { out.push(' '); }
        }
        // Pad short last line
        for j in chunk.len()..16 {
            out.push_str("   ");
            if j == 7 { out.push(' '); }
        }
        out.push(' ');
        for b in chunk {
            let c = *b as char;
            out.push(if c.is_ascii_graphic() { c } else { '.' });
        }
        out.push('\n');
    }
    out
}

// ─── Config Endpoints ────────────────────────────────────────────────────────

async fn config_get(State(state): State<AppState>) -> impl IntoResponse {
    let cfg = state.get_config();
    Json(serde_json::to_value(cfg.redacted()).unwrap()).into_response()
}

async fn config_post(
    State(state): State<AppState>,
    Json(payload): Json<ConfigPayload>,
) -> impl IntoResponse {
    let mut cfg = state.get_config();
    if let Some(key) = payload.virustotal_api_key {
        cfg.virustotal_api_key = if key.is_empty() { None } else { Some(key) };
    }
    if let Some(key) = payload.shodan_api_key {
        cfg.shodan_api_key = if key.is_empty() { None } else { Some(key) };
    }
    if let Some(thresholds) = payload.alert_thresholds {
        cfg.alert_thresholds = thresholds;
    }
    if let Some(whitelist) = payload.whitelist {
        cfg.whitelist = whitelist;
    }
    if let Err(e) = cfg.save() {
        return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": format!("Save failed: {}", e)}))).into_response();
    }
    state.set_config(cfg);
    Json(json!({"ok": true})).into_response()
}

// ─── Enrichment Endpoints ────────────────────────────────────────────────────

async fn enrich_ip(State(state): State<AppState>, AxumPath(ip): AxumPath<String>) -> impl IntoResponse {
    let cfg = state.get_config();
    if cfg.virustotal_api_key.is_none() && cfg.shodan_api_key.is_none() {
        return Json(json!({
            "error": "No API keys configured. Set VirusTotal or Shodan keys in Settings."
        })).into_response();
    }

    let mut results = serde_json::Map::new();

    // VirusTotal
    if let Some(vt_key) = &cfg.virustotal_api_key {
        let vt_key = vt_key.clone();
        let ip_clone = ip.clone();
        match tokio::spawn(async move { vt_lookup_ip(&ip_clone, &vt_key).await }).await {
            Ok(Ok(data)) => { results.insert("virustotal".to_string(), data); }
            Ok(Err(e)) => { results.insert("virustotal_error".to_string(), json!(e.to_string())); }
            Err(_) => {}
        }
    }

    Json(Value::Object(results)).into_response()
}

async fn enrich_domain(State(state): State<AppState>, AxumPath(domain): AxumPath<String>) -> impl IntoResponse {
    let cfg = state.get_config();
    if cfg.virustotal_api_key.is_none() {
        return Json(json!({
            "error": "No VirusTotal API key configured. Set it in Settings."
        })).into_response();
    }

    let mut results = serde_json::Map::new();
    if let Some(vt_key) = &cfg.virustotal_api_key {
        let vt_key = vt_key.clone();
        let domain_clone = domain.clone();
        match tokio::spawn(async move { vt_lookup_domain(&domain_clone, &vt_key).await }).await {
            Ok(Ok(data)) => { results.insert("virustotal".to_string(), data); }
            Ok(Err(e)) => { results.insert("virustotal_error".to_string(), json!(e.to_string())); }
            Err(_) => {}
        }
    }

    Json(Value::Object(results)).into_response()
}

async fn vt_lookup_ip(ip: &str, api_key: &str) -> anyhow::Result<Value> {
    // Validate that ip is a valid IP address before embedding in URL
    ip.parse::<std::net::IpAddr>()
        .map_err(|_| anyhow::anyhow!("Invalid IP address: {}", ip))?;
    let client = reqwest::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/ip_addresses/{}", ip);
    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await?
        .json::<Value>()
        .await?;
    Ok(resp)
}

async fn vt_lookup_domain(domain: &str, api_key: &str) -> anyhow::Result<Value> {
    // Validate domain: only allow alphanumeric, hyphens, dots, max 253 chars
    let valid = !domain.is_empty()
        && domain.len() <= 253
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
    if !valid {
        return Err(anyhow::anyhow!("Invalid domain: {}", domain));
    }
    let client = reqwest::Client::new();
    let url = format!("https://www.virustotal.com/api/v3/domains/{}", domain);
    let resp = client
        .get(&url)
        .header("x-apikey", api_key)
        .send()
        .await?
        .json::<Value>()
        .await?;
    Ok(resp)
}
