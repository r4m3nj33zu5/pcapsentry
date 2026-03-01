mod parser;
mod analysis;
mod export;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use axum::{
    extract::{Multipart, Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use dashmap::DashMap;
use include_dir::{include_dir, Dir};
use serde_json::{json, Value};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use uuid::Uuid;

use crate::analysis::AnalysisResult;
use crate::parser::ParsedCapture;

static FRONTEND_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../frontend/dist");

#[derive(Clone)]
pub struct AppState {
    pub sessions: Arc<DashMap<String, SessionState>>,
    pub geo_enabled: bool,
}

#[derive(Clone)]
pub enum SessionState {
    Processing { progress: u8 },
    Complete(Arc<AnalysisResult>),
    Error(String),
}

#[tokio::main]
async fn main() {
    let geo_enabled = Path::new("../assets/GeoLite2-City.mmdb").exists();
    if !geo_enabled {
        eprintln!(
            "Warning: GeoLite2-City.mmdb not found at assets/GeoLite2-City.mmdb — geo map disabled. \
            See README for instructions to obtain this free database."
        );
    }

    let state = AppState {
        sessions: Arc::new(DashMap::new()),
        geo_enabled,
    };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api = Router::new()
        .route("/api/upload", post(upload_handler))
        .route("/api/progress/:session_id", get(progress_handler))
        .route("/api/results/:session_id", get(results_handler))
        .route("/api/packet/:session_id/:packet_index", get(packet_handler))
        .route("/api/export/:session_id", post(export_handler))
        .route("/api/sessions", get(sessions_handler))
        .with_state(state)
        .layer(cors);

    // Try to serve embedded frontend, fall back to filesystem
    let app = api.fallback_service(ServeDir::new("../frontend/dist").append_index_html_on_directories(true));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:7777").await.unwrap();
    println!("PcapSentry running at http://localhost:7777");
    axum::serve(listener, app).await.unwrap();
}

async fn upload_handler(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let session_id = Uuid::new_v4().to_string();

    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().unwrap_or("").to_string();
        if name == "file" {
            let filename = field.file_name().unwrap_or("upload.pcap").to_string();
            let data = match field.bytes().await {
                Ok(b) => b.to_vec(),
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({"error": format!("Failed to read file: {}", e)})),
                    )
                        .into_response();
                }
            };

            state
                .sessions
                .insert(session_id.clone(), SessionState::Processing { progress: 0 });

            let sid = session_id.clone();
            let sessions = state.sessions.clone();
            let geo_enabled = state.geo_enabled;

            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    parser::parse_capture(&data, &filename, geo_enabled)
                })
                .await;

                match result {
                    Ok(Ok(analysis)) => {
                        sessions.insert(sid, SessionState::Complete(Arc::new(analysis)));
                    }
                    Ok(Err(e)) => {
                        sessions.insert(sid, SessionState::Error(e.to_string()));
                    }
                    Err(e) => {
                        sessions.insert(sid, SessionState::Error(e.to_string()));
                    }
                }
            });

            return Json(json!({
                "session_id": session_id,
                "filename": filename
            }))
            .into_response();
        }
    }

    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "No file field found in upload"})),
    )
        .into_response()
}

async fn progress_handler(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    match state.sessions.get(&session_id).map(|v| v.clone()) {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found"}))).into_response(),
        Some(SessionState::Processing { progress }) => {
            Json(json!({"status": "processing", "progress": progress})).into_response()
        }
        Some(SessionState::Complete(_)) => {
            Json(json!({"status": "complete", "progress": 100})).into_response()
        }
        Some(SessionState::Error(e)) => {
            Json(json!({"status": "error", "error": e})).into_response()
        }
    }
}

async fn results_handler(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    match state.sessions.get(&session_id).map(|v| v.clone()) {
        None => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found"}))).into_response(),
        Some(SessionState::Processing { progress }) => {
            Json(json!({"status": "processing", "progress": progress})).into_response()
        }
        Some(SessionState::Complete(result)) => Json(serde_json::to_value(&*result).unwrap()).into_response(),
        Some(SessionState::Error(e)) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e}))).into_response()
        }
    }
}

async fn packet_handler(
    State(state): State<AppState>,
    AxumPath((session_id, packet_index)): AxumPath<(String, usize)>,
) -> impl IntoResponse {
    match state.sessions.get(&session_id).map(|v| v.clone()) {
        Some(SessionState::Complete(result)) => {
            if let Some(pkt) = result.packets.get(packet_index) {
                Json(serde_json::to_value(pkt).unwrap()).into_response()
            } else {
                (StatusCode::NOT_FOUND, Json(json!({"error": "Packet index out of range"}))).into_response()
            }
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found or not complete"}))).into_response(),
    }
}

async fn export_handler(
    State(state): State<AppState>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    match state.sessions.get(&session_id).map(|v| v.clone()) {
        Some(SessionState::Complete(result)) => {
            match export::pdf::generate_pdf(&result) {
                Ok(bytes) => {
                    let headers = [
                        ("Content-Type", "application/pdf"),
                        ("Content-Disposition", "attachment; filename=\"pcapsentry-report.pdf\""),
                    ];
                    (headers, bytes).into_response()
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": format!("PDF generation failed: {}", e)})),
                )
                    .into_response(),
            }
        }
        _ => (StatusCode::NOT_FOUND, Json(json!({"error": "Session not found or not complete"}))).into_response(),
    }
}

async fn sessions_handler(State(state): State<AppState>) -> impl IntoResponse {
    let sessions: Vec<Value> = state
        .sessions
        .iter()
        .map(|entry| {
            let id = entry.key().clone();
            match entry.value() {
                SessionState::Processing { progress } => json!({
                    "session_id": id,
                    "status": "processing",
                    "progress": progress
                }),
                SessionState::Complete(r) => json!({
                    "session_id": id,
                    "status": "complete",
                    "filename": r.overview.filename,
                    "total_packets": r.overview.total_packets,
                    "highest_severity": r.highest_severity(),
                    "analyzed_at": r.overview.analyzed_at
                }),
                SessionState::Error(e) => json!({
                    "session_id": id,
                    "status": "error",
                    "error": e
                }),
            }
        })
        .collect();

    Json(json!({"sessions": sessions}))
}
