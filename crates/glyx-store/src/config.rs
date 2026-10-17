use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::StoreError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionMode {
    #[default]
    Oneshot,
    Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DaemonExit {
    #[default]
    Stop,
    Keep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub path: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile: Option<PathBuf>,
    #[serde(default)]
    pub last_used_ms: u64,
}

impl VaultEntry {
    #[must_use]
    pub fn label(&self) -> String {
        self.name.clone().unwrap_or_else(|| {
            self.path.file_name().map_or_else(
                || self.path.display().to_string(),
                |n| n.to_string_lossy().into_owned(),
            )
        })
    }
}

fn default_ttl() -> u64 {
    crate::session::SESSION_TTL_DEFAULT_MIN
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub mode: SessionMode,
    #[serde(default = "default_ttl")]
    pub session_ttl_min: u64,
    #[serde(default)]
    pub daemon_on_exit: DaemonExit,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_vault: Option<PathBuf>,
    #[serde(default)]
    pub vaults: Vec<VaultEntry>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mode: SessionMode::Oneshot,
            session_ttl_min: default_ttl(),
            daemon_on_exit: DaemonExit::Stop,
            current_vault: None,
            vaults: Vec::new(),
        }
    }
}

impl AppConfig {
    #[must_use]
    pub fn find(&self, path: &Path) -> Option<&VaultEntry> {
        let want = normalize(path);
        self.vaults.iter().find(|v| normalize(&v.path) == want)
    }

    #[must_use]
    pub fn current_entry(&self) -> Option<&VaultEntry> {
        self.current_vault.as_deref().and_then(|p| self.find(p))
    }

    pub fn register(&mut self, mut entry: VaultEntry) -> &mut VaultEntry {
        entry.path = normalize(&entry.path);
        if let Some(idx) = self
            .vaults
            .iter()
            .position(|v| normalize(&v.path) == entry.path)
        {
            let existing = &mut self.vaults[idx];
            if entry.name.is_some() {
                existing.name = entry.name;
            }
            if entry.vault_id.is_some() {
                existing.vault_id = entry.vault_id;
            }
            if entry.keyfile.is_some() {
                existing.keyfile = entry.keyfile;
            }
            if entry.last_used_ms > existing.last_used_ms {
                existing.last_used_ms = entry.last_used_ms;
            }
            return &mut self.vaults[idx];
        }
        self.vaults.push(entry);
        self.vaults.last_mut().expect("just pushed")
    }

    pub fn select(&mut self, path: &Path) {
        let normalized = normalize(path);
        if self.find(&normalized).is_none() {
            self.register(VaultEntry {
                path: normalized.clone(),
                name: None,
                vault_id: None,
                keyfile: None,
                last_used_ms: 0,
            });
        }
        let now = glyx_core::ids::wall_ms_now();
        if let Some(entry) = self
            .vaults
            .iter_mut()
            .find(|v| normalize(&v.path) == normalized)
        {
            entry.last_used_ms = now;
        }
        self.current_vault = Some(normalized);
    }

    pub fn remove(&mut self, path: &Path) {
        let want = normalize(path);
        self.vaults.retain(|v| normalize(&v.path) != want);
        if self
            .current_vault
            .as_deref()
            .is_some_and(|p| normalize(p) == want)
        {
            self.current_vault = None;
        }
    }
}

#[must_use]
pub fn normalize(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

#[must_use]
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("GLYX_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(
        |_| {
            std::env::var("HOME")
                .map_or_else(|_| PathBuf::from("."), |h| PathBuf::from(h).join(".config"))
        },
        PathBuf::from,
    );
    base.join("glyx").join("config.toml")
}

#[must_use]
pub fn load() -> AppConfig {
    load_from(&config_path())
}

#[must_use]
pub fn load_from(path: &Path) -> AppConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|text| toml::from_str(&text).ok())
        .unwrap_or_default()
}

pub fn save(config: &AppConfig) -> Result<(), StoreError> {
    save_to(&config_path(), config)
}

pub fn save_to(path: &Path, config: &AppConfig) -> Result<(), StoreError> {
    let text = toml::to_string_pretty(config)
        .map_err(|e| StoreError::Config(format!("cannot render config: {e}")))?;
    crate::vault::atomic_write(path, text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_CONFIG", dir.path().join("config.toml"));
        dir
    }

    #[test]
    fn registry_roundtrip_and_selection() {
        let _g = guard();
        let path = config_path();
        let a = PathBuf::from("/tmp/a.glyx");
        let b = PathBuf::from("/tmp/b.glyx");
        let mut cfg = AppConfig::default();
        cfg.select(&a);
        cfg.register(VaultEntry {
            path: b.clone(),
            name: Some("B".into()),
            vault_id: Some(Uuid::now_v7()),
            keyfile: None,
            last_used_ms: 5,
        });
        cfg.select(&b);
        let keyfile = PathBuf::from("/tmp/b.kf");
        cfg.register(VaultEntry {
            path: b.clone(),
            name: None,
            vault_id: None,
            keyfile: Some(keyfile.clone()),
            last_used_ms: 9_000_000_000_000,
        });
        save_to(&path, &cfg).expect("save");
        let back = load_from(&path);
        assert_eq!(back.current_vault.as_deref(), Some(normalize(&b).as_path()));
        assert_eq!(back.vaults.len(), 2);
        let entry = back.find(&b).expect("b present");
        assert_eq!(entry.name.as_deref(), Some("B"));
        assert_eq!(entry.keyfile.as_deref(), Some(keyfile.as_path()));
        assert_eq!(entry.last_used_ms, 9_000_000_000_000);
    }

    #[test]
    fn daemon_exit_defaults_to_stop() {
        let cfg = AppConfig::default();
        assert_eq!(cfg.daemon_on_exit, DaemonExit::Stop);
    }
}
