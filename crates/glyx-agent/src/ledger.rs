use std::io::Write as _;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum AgentError {
    #[error("agent storage: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("vault: {0}")]
    Store(#[from] glyx_store::StoreError),
    #[error("crypto: {0}")]
    Crypto(#[from] glyx_crypto::CryptoError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("tracked file is not valid UTF-8: {0}")]
    NotUtf8(String),
    #[error("tamper detected, refusing: {0}")]
    Tamper(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefInfo {
    pub item_id: Uuid,
    pub field: String,
    pub locked: String,
}

#[derive(Debug, Clone)]
pub struct ExportRow {
    pub id: String,
    pub target: PathBuf,
    pub kind: String,
    pub item_id: Option<Uuid>,
    pub field: Option<String>,
    pub blob_addr: Option<String>,
    pub keep_on_lock: bool,
    pub perm: u32,
}

#[derive(Debug, Clone)]
pub struct InjectRow {
    pub target: PathBuf,
    pub form: String,
    pub refs_json: String,
    pub locked_text: Option<String>,
    pub locked_hash: Option<String>,
    pub unlocked_hash: Option<String>,
}

#[must_use]
pub fn db_path() -> PathBuf {
    glyx_store::session::session_dir().join("agent-ledger.sqlite")
}

pub fn open_db() -> Result<Connection, AgentError> {
    let path = db_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS exports(
           id TEXT PRIMARY KEY, target TEXT UNIQUE NOT NULL, kind TEXT NOT NULL,
           item_id TEXT, field TEXT, blob_addr TEXT,
           keep_on_lock INTEGER NOT NULL DEFAULT 0, perm INTEGER NOT NULL DEFAULT 384);
         CREATE TABLE IF NOT EXISTS injects(
           target TEXT PRIMARY KEY, form TEXT NOT NULL DEFAULT 'encrypted-pointer',
           refs_json TEXT NOT NULL DEFAULT '[]', locked_text TEXT,
           locked_hash TEXT, unlocked_hash TEXT, mtime INTEGER, size INTEGER);",
    )?;
    Ok(conn)
}

#[must_use]
pub fn blake_hex(bytes: &[u8]) -> String {
    glyx_crypto::blake3_hex(bytes)
}

pub fn shred_file(path: &Path) -> Result<(), AgentError> {
    if !path.exists() {
        return Ok(());
    }
    let len = std::fs::metadata(path)?.len();
    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(path) {
        let zeros = vec![0u8; 65536];
        let mut remaining = len;
        let mut file = file;
        while remaining > 0 {
            let rest = usize::try_from(remaining % 65536).unwrap_or(0);
            let chunk = if remaining >= 65536 {
                &zeros[..]
            } else {
                &zeros[..rest]
            };
            if file.write_all(chunk).is_err() {
                break;
            }
            remaining = remaining.saturating_sub(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
            if chunk.is_empty() {
                break;
            }
        }
        let _ = file.sync_all();
    }
    std::fs::remove_file(path)?;
    Ok(())
}

#[must_use]
pub fn scan_refs(text: &str) -> Vec<(Uuid, String)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{glyx:") {
        let after = &rest[start + 7..];
        let Some(end) = after.find("}}") else {
            break;
        };
        let inner = &after[..end];
        if let Some((id, field)) = inner.split_once('/') {
            if let Ok(id) = id.parse::<Uuid>() {
                if !field.is_empty() && !field.contains(['}', '{', ' ', '\n']) {
                    out.push((id, field.to_owned()));
                }
            }
        }
        rest = &after[end + 2..];
    }
    out
}

pub fn parse_form(text: &str) -> Result<glyx_core::LockedForm, AgentError> {
    match text {
        "ref" => Ok(glyx_core::LockedForm::Ref),
        "encrypted-pointer" => Ok(glyx_core::LockedForm::EncryptedPointer),
        "masked" | "masked-shape" => Ok(glyx_core::LockedForm::MaskedShape),
        other => Err(AgentError::Crypto(glyx_crypto::CryptoError::Param(
            format!("unknown locked form {other}"),
        ))),
    }
}

#[derive(Debug, Clone)]
pub struct ExportSpec<'a> {
    pub target: &'a Path,
    pub kind: &'a str,
    pub item_id: Option<Uuid>,
    pub field: Option<&'a str>,
    pub blob_addr: Option<&'a str>,
    pub keep_on_lock: bool,
    pub perm: u32,
}

pub fn register_export(conn: &Connection, spec: &ExportSpec) -> Result<String, AgentError> {
    let id = Uuid::now_v7().as_simple().to_string();
    conn.execute(
        "INSERT INTO exports(id, target, kind, item_id, field, blob_addr, keep_on_lock, perm)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(target) DO UPDATE SET kind=excluded.kind, item_id=excluded.item_id,
           field=excluded.field, blob_addr=excluded.blob_addr,
           keep_on_lock=excluded.keep_on_lock, perm=excluded.perm",
        rusqlite::params![
            id,
            spec.target.to_string_lossy(),
            spec.kind,
            spec.item_id.map(|i| i.as_simple().to_string()),
            spec.field,
            spec.blob_addr,
            i64::from(spec.keep_on_lock),
            i64::from(spec.perm),
        ],
    )?;
    Ok(id)
}

pub fn register_inject(conn: &Connection, target: &Path, form: &str) -> Result<(), AgentError> {
    parse_form(form)?;
    conn.execute(
        "INSERT INTO injects(target, form) VALUES (?1, ?2)
         ON CONFLICT(target) DO UPDATE SET form=excluded.form",
        rusqlite::params![target.to_string_lossy(), form],
    )?;
    Ok(())
}

pub fn list_exports(conn: &Connection) -> Result<Vec<ExportRow>, AgentError> {
    let mut stmt = conn.prepare(
        "SELECT id, target, kind, item_id, field, blob_addr, keep_on_lock, perm FROM exports ORDER BY target",
    )?;
    let rows = stmt.query_map([], |r| {
        let target: String = r.get(1)?;
        let item_id: Option<String> = r.get(3)?;
        Ok(ExportRow {
            id: r.get(0)?,
            target: PathBuf::from(target),
            kind: r.get(2)?,
            item_id: item_id.and_then(|s| Uuid::parse_str(&s).ok()),
            field: r.get(4)?,
            blob_addr: r.get(5)?,
            keep_on_lock: r.get::<_, i64>(6)? != 0,
            perm: u32::try_from(r.get::<_, i64>(7)?).unwrap_or(0o600),
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(AgentError::from)
}

pub fn list_injects(conn: &Connection) -> Result<Vec<InjectRow>, AgentError> {
    let mut stmt = conn.prepare(
        "SELECT target, form, refs_json, locked_text, locked_hash, unlocked_hash FROM injects ORDER BY target",
    )?;
    let rows = stmt.query_map([], |r| {
        let target: String = r.get(0)?;
        Ok(InjectRow {
            target: PathBuf::from(target),
            form: r.get(1)?,
            refs_json: r.get(2)?,
            locked_text: r.get(3)?,
            locked_hash: r.get(4)?,
            unlocked_hash: r.get(5)?,
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(AgentError::from)
}

pub fn recall_target(conn: &Connection, target: &Path) -> Result<bool, AgentError> {
    let key = target.to_string_lossy().into_owned();
    let mut removed = false;
    if conn.execute("DELETE FROM exports WHERE target = ?1", [&key])? > 0 {
        removed = true;
    }
    if conn.execute("DELETE FROM injects WHERE target = ?1", [&key])? > 0 {
        removed = true;
    }
    if target.exists() {
        shred_file(target)?;
        removed = true;
    }
    Ok(removed)
}
