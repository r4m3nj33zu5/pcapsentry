use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub virustotal_api_key: Option<String>,
    pub shodan_api_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfigRedacted {
    pub virustotal_configured: bool,
    pub shodan_configured: bool,
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
        fs::write(&path, content)?;
        // Set file permissions to 0600 on Unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&path)?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(&path, perms)?;
        }
        Ok(())
    }

    pub fn redacted(&self) -> AppConfigRedacted {
        AppConfigRedacted {
            virustotal_configured: self.virustotal_api_key.as_ref().map(|k| !k.is_empty()).unwrap_or(false),
            shodan_configured: self.shodan_api_key.as_ref().map(|k| !k.is_empty()).unwrap_or(false),
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
}
