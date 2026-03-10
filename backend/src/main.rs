mod parser;
mod analysis;
mod export;
mod config;

use std::path::Path;
use std::sync::Arc;

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
use tower_http::cors::{Any, CorsLayer};
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
    Processing { progress: u8 },
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

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    const TWO_GB: usize = 2 * 1024 * 1024 * 1024;

    let api = Router::new()
        // Core
        .route("/api/upload", post(upload_handler))
        .route("/api/progress/:session_id", get(progress_handler))
        .route("/api/results/:session_id", get(results_handler))
        .route("/api/packet/:session_id/:packet_index", get(packet_handler))
        .route("/api/export/:session_id", post(export_handler))
        .route("/api/sessions", get(sessions_handler))
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

    let listener = tokio::net::TcpListener::bind("127.0.0.1:7777").await.unwrap();
    println!("PcapSentry running at http://localhost:7777");
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
        None => {
            let index = FRONTEND_DIR.get_file("index.html").unwrap();
            ([(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], index.contents()).into_response()
        }
    }
}

// ─── Upload & Progress ───────────────────────────────────────────────────────

async fn upload_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let session_id = Uuid::new_v4().to_string();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let filename = field.file_name().unwrap_or("upload.pcap").to_string();
            let filename_clone = filename.clone();
            let data = match field.bytes().await {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    return (StatusCode::BAD_REQUEST, Json(json!({"error": format!("Failed to read file: {}", e)}))).into_response();
                }
            };

            state.sessions.insert(session_id.clone(), SessionState::Processing { progress: 0 });

            let sid = session_id.clone();
            let sessions = state.sessions.clone();
            let geo_enabled = state.geo_enabled;

            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    parser::parse_capture(&data, &filename, geo_enabled)
                }).await;

                match result {
                    Ok(Ok(analysis)) => { sessions.insert(sid, SessionState::Complete(Arc::new(analysis))); }
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
        Some(SessionState::Processing { progress }) => Json(json!({"status": "processing", "progress": progress})).into_response(),
        Some(SessionState::Complete(_)) => Json(json!({"status": "complete", "progress": 100})).into_response(),
        Some(SessionState::Error(e)) => Json(json!({"status": "error", "error": e})).into_response(),
    }
}

async fn results_handler(State(state): State<AppState>, AxumPath(session_id): AxumPath<String>) -> impl IntoResponse {
    match state.sessions.get(&session_id).map(|v| v.clone()) {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found"}))).into_response(),
        Some(SessionState::Processing { progress }) => Json(json!({"status": "processing", "progress": progress})).into_response(),
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
            SessionState::Processing { progress } => json!({ "session_id": id, "status": "processing", "progress": progress }),
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

            let filtered: Vec<_> = r.flows.iter()
                .filter(|f| {
                    if filter.is_empty() { return true; }
                    f.src_ip.contains(&filter) || f.dst_ip.contains(&filter)
                        || f.protocol.to_lowercase().contains(&filter)
                        || f.service_guess.to_lowercase().contains(&filter)
                })
                .collect();

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
    // Notes are stored in the session; we need mutable access
    // Since AnalysisResult is in an Arc, we replace the arc with a new one
    if let Some(mut entry) = state.sessions.get_mut(&sid) {
        if let SessionState::Complete(ref result) = entry.clone() {
            let mut new_result = (**result).clone();
            new_result.notes = payload.notes;
            *entry = SessionState::Complete(Arc::new(new_result));
            return Json(json!({"ok": true})).into_response();
        }
    }
    (StatusCode::NOT_FOUND, Json(json!({"error": "Not found"}))).into_response()
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
