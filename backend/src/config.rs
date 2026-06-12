use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub port_scan_syn_minimum: usize,
    pub port_scan_response_ratio: f64,
    pub syn_flood_minimum: usize,
    pub icmp_flood_minimum: usize,
    pub udp_flood_minimum: usize,
    pub beaconing_min_connections: usize,
    pub beaconing_max_cv: f64,
    pub dns_tunnel_label_length: usize,
    pub dns_tunnel_entropy: f64,
    pub traffic_spike_percentage: f64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        AlertThresholds {
            port_scan_syn_minimum: 20,
            port_scan_response_ratio: 0.2,
            syn_flood_minimum: 200,
            icmp_flood_minimum: 50,
            udp_flood_minimum: 500,
            beaconing_min_connections: 5,
            beaconing_max_cv: 0.35,
            dns_tunnel_label_length: 50,
            dns_tunnel_entropy: 3.5,
            traffic_spike_percentage: 0.5,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Whitelist {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub virustotal_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
    #[serde(default)]
    pub alert_thresholds: AlertThresholds,
    #[serde(default)]
    pub whitelist: Whitelist,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfigRedacted {
    pub virustotal_configured: bool,
    pub shodan_configured: bool,
    pub alert_thresholds: AlertThresholds,
    pub whitelist: Whitelist,
}

impl AppConfig {
    pub fn load() -> Self {
        match Self::try_load() {
            Ok(cfg) => cfg,
            Err(_) => AppConfig::default(),
        }
    }

    fn try_load() -> Result<Self> {
        let path = config_path()?;
        if !path.exists() {
            return Ok(AppConfig::default());
        }
        let content = fs::read_to_string(&path)?;
        let cfg: AppConfig = toml::from_str(&content)?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        // Write atomically with restrictive permissions from the start, then
        // rename over the destination so there is no window where API keys
        // sit on disk as world-readable.
        let tmp = path.with_extension("toml.tmp");
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            // Remove any stale tmp file so create_new succeeds.
            let _ = fs::remove_file(&tmp);
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            fs::write(&tmp, &content)?;
        }
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn redacted(&self) -> AppConfigRedacted {
        AppConfigRedacted {
            virustotal_configured: self.virustotal_api_key.as_ref().map(|k| !k.is_empty()).unwrap_or(false),
            shodan_configured: self.shodan_api_key.as_ref().map(|k| !k.is_empty()).unwrap_or(false),
            alert_thresholds: self.alert_thresholds.clone(),
            whitelist: self.whitelist.clone(),
        }
    }
}

fn config_path() -> Result<PathBuf> {
    let dir = dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."));
    Ok(dir.join("pcapsentry").join("config.toml"))
}

#[derive(Debug, Deserialize)]
pub struct ConfigPayload {
    pub virustotal_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
    pub alert_thresholds: Option<AlertThresholds>,
    pub whitelist: Option<Whitelist>,
}
