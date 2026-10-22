use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{config, StoreError};

const MAX_BYTES: u64 = 5 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts_ms: u64,
    pub vault_id: Uuid,
    pub device: String,
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

fn audit_dir() -> PathBuf {
    config::config_path()
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
        .join("audit")
}

fn log_path(vault_id: &Uuid) -> PathBuf {
    audit_dir().join(format!("{}.jsonl", vault_id.as_simple()))
}

fn ensure_dir(path: &Path) -> Result<(), StoreError> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

pub fn append(
    vault_id: Uuid,
    device: &str,
    event: &str,
    item_id: Option<Uuid>,
    field: Option<&str>,
    outcome: Option<&str>,
    detail: Option<&str>,
) -> Result<(), StoreError> {
    let dir = audit_dir();
    ensure_dir(&dir)?;
    let path = log_path(&vault_id);
    if std::fs::metadata(&path).is_ok_and(|meta| meta.len() >= MAX_BYTES) {
        let _ = std::fs::rename(&path, path.with_extension("jsonl.1"));
    }
    let entry = AuditEvent {
        ts_ms: glyx_core::ids::wall_ms_now(),
        vault_id,
        device: device.to_owned(),
        event: event.to_owned(),
        item_id,
        field: field.map(str::to_owned),
        outcome: outcome.map(str::to_owned),
        detail: detail.map(str::to_owned),
    };
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut line = serde_json::to_vec(&entry).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    line.push(b'\n');
    file.write_all(&line)?;
    Ok(())
}

pub fn count(vault_id: &Uuid, event: Option<&str>) -> Result<usize, StoreError> {
    let path = log_path(vault_id);
    let mut count = 0;
    for file in [path.with_extension("jsonl.1"), path] {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines() {
            let Ok(entry) = serde_json::from_str::<AuditEvent>(line) else {
                continue;
            };
            if event.is_none_or(|want| entry.event == want) {
                count += 1;
            }
        }
    }
    Ok(count)
}

pub fn list(
    vault_id: &Uuid,
    limit: usize,
    offset: usize,
    event: Option<&str>,
) -> Result<Vec<AuditEvent>, StoreError> {
    let path = log_path(vault_id);
    let mut events = Vec::new();
    for file in [path.with_extension("jsonl.1"), path] {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        for line in text.lines() {
            let Ok(entry) = serde_json::from_str::<AuditEvent>(line) else {
                continue;
            };
            if event.is_none_or(|want| entry.event == want) {
                events.push(entry);
            }
        }
    }
    events.sort_by_key(|entry| std::cmp::Reverse(entry.ts_ms));
    Ok(events
        .into_iter()
        .skip(offset)
        .take(limit.min(1000))
        .collect())
}
