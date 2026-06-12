use anyhow::{anyhow, Result};
use flate2::{Compression, read::GzDecoder, write::GzEncoder};
use std::io::{Read, Write};
use std::path::PathBuf;
use crate::analysis::AnalysisResult;

// Hard cap on decompressed session size to defend against zip-bomb files
// dropped into the sessions directory by an attacker with disk access.
const MAX_DECOMPRESSED_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

fn sessions_dir() -> Result<PathBuf> {
    let dir = dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("pcapsentry")
        .join("sessions");
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Validate that a session_id is a plain UUIDv4-shaped string. This prevents
/// path-traversal and unexpected filename characters from reaching the
/// filesystem layer (the session_id is later interpolated into a filename).
fn validate_session_id(sid: &str) -> Result<()> {
    if sid.len() != 36 {
        return Err(anyhow!("invalid session id length"));
    }
    let bytes = sid.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let ok = match i {
            8 | 13 | 18 | 23 => *b == b'-',
            _ => b.is_ascii_hexdigit(),
        };
        if !ok {
            return Err(anyhow!("invalid session id character at {}", i));
        }
    }
    Ok(())
}

fn session_path(session_id: &str) -> Result<PathBuf> {
    validate_session_id(session_id)?;
    Ok(sessions_dir()?.join(format!("{}.json.gz", session_id)))
}

pub fn save(session_id: &str, result: &AnalysisResult) -> Result<()> {
    let path = session_path(session_id)?;
    let json = serde_json::to_vec(result)?;
    let file = std::fs::File::create(&path)?;
    let mut enc = GzEncoder::new(file, Compression::default());
    enc.write_all(&json)?;
    enc.finish()?;
    Ok(())
}

pub fn load(session_id: &str) -> Result<AnalysisResult> {
    let path = session_path(session_id)?;
    let file = std::fs::File::open(&path)?;
    // Cap decompressed bytes so a crafted file in the sessions dir
    // cannot OOM the process on startup.
    let mut dec = GzDecoder::new(file).take(MAX_DECOMPRESSED_BYTES);
    let mut buf = Vec::new();
    dec.read_to_end(&mut buf)?;
    if buf.len() as u64 >= MAX_DECOMPRESSED_BYTES {
        return Err(anyhow!("session file exceeds maximum size"));
    }
    Ok(serde_json::from_slice(&buf)?)
}

pub fn load_all() -> Vec<(String, AnalysisResult)> {
    let dir = match sessions_dir() {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if let Some(sid) = name.strip_suffix(".json.gz") {
                    if validate_session_id(sid).is_ok() {
                        if let Ok(result) = load(sid) {
                            out.push((sid.to_string(), result));
                        }
                    }
                }
            }
        }
    }
    out
}

pub fn delete(session_id: &str) -> Result<()> {
    let path = session_path(session_id)?;
    if path.exists() { std::fs::remove_file(&path)?; }
    Ok(())
}
