use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use uuid::Uuid;

use crate::ledger::{
    blake_hex, expand_inject_roots, list_exports, list_injects, open_db, parse_form,
    recall_target as ledger_recall, scan_pointers, scan_refs, shred_file, AgentError, ExpandReport,
    ExportRow, InjectRow, RefInfo,
};

#[derive(Debug, Clone, Default)]
pub struct MaterializeReport {
    pub files: usize,
    pub injected: usize,
    pub scanned: usize,
    pub skipped: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TeardownReport {
    pub wiped: usize,
    pub restored: usize,
    pub drifted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperKind {
    Residue,
    Drift,
    Missing,
}

#[derive(Debug, Clone)]
pub struct Tamper {
    pub target: String,
    pub kind: TamperKind,
    pub detail: String,
}

fn fetch_value(uv: &glyx_store::UnlockedVault, row: &ExportRow) -> Result<Vec<u8>, AgentError> {
    match row.kind.as_str() {
        "field" => {
            let id = row.item_id.ok_or_else(|| {
                AgentError::Crypto(glyx_crypto::CryptoError::Param("export lacks item".into()))
            })?;
            let field = row.field.clone().unwrap_or_else(|| "password".to_owned());
            let item = uv
                .get_item(&id)?
                .ok_or_else(|| AgentError::Tamper(format!("item {id} gone")))?;
            Ok(item
                .fields
                .get(&field)
                .ok_or_else(|| AgentError::Tamper(format!("field {field} gone")))?
                .value
                .expose()
                .as_bytes()
                .to_vec())
        }
        "blob" => {
            let addr = row.blob_addr.clone().ok_or_else(|| {
                AgentError::Crypto(glyx_crypto::CryptoError::Param("export lacks blob".into()))
            })?;
            Ok(uv.get_blob(&addr)?.to_vec())
        }
        "ssh" => {
            let id = row.item_id.ok_or_else(|| {
                AgentError::Crypto(glyx_crypto::CryptoError::Param("export lacks item".into()))
            })?;
            let item = uv
                .get_item(&id)?
                .ok_or_else(|| AgentError::Tamper(format!("item {id} gone")))?;
            Ok(item
                .fields
                .get("private")
                .ok_or_else(|| AgentError::Tamper("ssh item lacks private".into()))?
                .value
                .expose()
                .as_bytes()
                .to_vec())
        }
        other => Err(AgentError::Crypto(glyx_crypto::CryptoError::Param(
            format!("unknown export kind {other}"),
        ))),
    }
}

fn write_target(target: &Path, bytes: &[u8], perm: u32) -> Result<(), AgentError> {
    if let Some(parent) = target.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(target, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(target, std::fs::Permissions::from_mode(perm))?;
    }
    Ok(())
}

pub fn materialize_export(
    uv: &glyx_store::UnlockedVault,
    row: &ExportRow,
) -> Result<(), AgentError> {
    let bytes = fetch_value(uv, row)?;
    write_target(&row.target, &bytes, row.perm)
}

fn adopt_pointers(
    uv: &glyx_store::UnlockedVault,
    refs: &mut Vec<RefInfo>,
    new_text: &mut String,
    target_str: &str,
) -> Result<usize, AgentError> {
    let mut changed = 0;
    for token in scan_pointers(new_text) {
        if refs.iter().any(|r| r.locked == token) {
            continue;
        }
        let Ok((id, field)) = uv.open_locked_pointer(&token, target_str) else {
            continue;
        };
        let Some(item) = uv.get_item(&id)? else {
            continue;
        };
        let Some(field_value) = item.fields.get(&field) else {
            continue;
        };
        let value = field_value.value.expose().to_owned();
        *new_text = new_text.replace(&token, &value);
        refs.push(RefInfo {
            item_id: id,
            field,
            locked: token,
        });
        changed += 1;
    }
    Ok(changed)
}

pub fn materialize_inject(
    uv: &glyx_store::UnlockedVault,
    conn: &Connection,
    row: &InjectRow,
    force: bool,
) -> Result<usize, AgentError> {
    let target = &row.target;
    let text = std::fs::read_to_string(target)
        .map_err(|_| AgentError::Tamper(format!("{} unreadable", target.display())))?;
    if row.locked_text.is_none() {
        conn.execute(
            "UPDATE injects SET locked_text = ?1, locked_hash = ?2 WHERE target = ?3",
            rusqlite::params![text, blake_hex(text.as_bytes()), target.to_string_lossy()],
        )?;
    }
    let form = parse_form(&row.form)?;
    let target_str = target.to_string_lossy().into_owned();
    let mut refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
    let mut by_locked: BTreeMap<String, (Uuid, String)> = BTreeMap::new();
    for r in &refs {
        by_locked.insert(r.locked.clone(), (r.item_id, r.field.clone()));
    }
    let mut changed = 0;
    let mut new_text = text.clone();
    for (locked, (id, field)) in &by_locked {
        let plain_ref = glyx_core::ref_placeholder(id, field);
        let present = if new_text.contains(locked.as_str()) {
            Some(locked.clone())
        } else if new_text.contains(&plain_ref) {
            Some(plain_ref)
        } else {
            None
        };
        if let Some(found) = present {
            let item = uv
                .get_item(id)?
                .ok_or_else(|| AgentError::Tamper(format!("item {id} gone")))?;
            let value = item
                .fields
                .get(field)
                .ok_or_else(|| AgentError::Tamper(format!("field {field} gone")))?
                .value
                .expose()
                .to_owned();
            new_text = new_text.replace(found.as_str(), &value);
            changed += 1;
        } else if !force {
            return Err(AgentError::Tamper(format!(
                "{}: locked placeholder missing, file changed externally",
                target.display()
            )));
        }
    }
    for (id, field) in scan_refs(&new_text) {
        if refs.iter().any(|r| r.item_id == id && r.field == field) {
            continue;
        }
        let item = uv
            .get_item(&id)?
            .ok_or_else(|| AgentError::Tamper(format!("item {id} gone")))?;
        let value = item
            .fields
            .get(&field)
            .ok_or_else(|| AgentError::Tamper(format!("field {field} gone")))?
            .value
            .expose()
            .to_owned();
        let locked = uv.render_locked(&id, &field, &target_str, form)?;
        refs.push(RefInfo {
            item_id: id,
            field: field.clone(),
            locked: locked.clone(),
        });
        let placeholder = glyx_core::ref_placeholder(&id, &field);
        if new_text.contains(&placeholder) {
            new_text = new_text.replace(&placeholder, &value);
            changed += 1;
        }
    }
    changed += adopt_pointers(uv, &mut refs, &mut new_text, &target_str)?;
    if changed == 0 && new_text == text {
        return Ok(0);
    }
    std::fs::write(target, new_text.as_bytes())?;
    let meta = std::fs::metadata(target)?;
    conn.execute(
        "UPDATE injects SET refs_json = ?1, unlocked_hash = ?2, mtime = ?3, size = ?4 WHERE target = ?5",
        rusqlite::params![
            serde_json::to_string(&refs).unwrap_or_default(),
            blake_hex(new_text.as_bytes()),
            meta.modified().ok().and_then(|t| t
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().cast_signed())),
            meta.len().cast_signed(),
            target.to_string_lossy(),
        ],
    )?;
    Ok(changed)
}

pub fn check_all(conn: &Connection, locked: bool) -> Result<Vec<Tamper>, AgentError> {
    let mut out = Vec::new();
    for row in list_exports(conn)? {
        if row.keep_on_lock {
            continue;
        }
        if locked && row.target.exists() {
            out.push(Tamper {
                target: row.target.to_string_lossy().into_owned(),
                kind: TamperKind::Residue,
                detail: "file exists but vault was locked".to_owned(),
            });
        }
    }
    for row in list_injects(conn)? {
        let Ok(bytes) = std::fs::read(&row.target) else {
            if row.locked_text.is_some() {
                out.push(Tamper {
                    target: row.target.to_string_lossy().into_owned(),
                    kind: TamperKind::Missing,
                    detail: "tracked file deleted".to_owned(),
                });
            }
            continue;
        };
        let hash = blake_hex(&bytes);
        let locked_ok = row.locked_hash.as_deref() == Some(hash.as_str());
        let unlocked_ok = row.unlocked_hash.as_deref() == Some(hash.as_str());
        if row.locked_hash.is_some() && !locked_ok && !unlocked_ok {
            out.push(Tamper {
                target: row.target.to_string_lossy().into_owned(),
                kind: TamperKind::Drift,
                detail: "file changed while locked".to_owned(),
            });
        }
    }
    Ok(out)
}

pub fn materialize_all(
    uv: &mut glyx_store::UnlockedVault,
    force: bool,
) -> Result<MaterializeReport, AgentError> {
    let conn = open_db()?;
    let mut report = MaterializeReport::default();
    if let Ok(expanded) = expand_inject_roots(&conn) {
        report.scanned = expanded.files;
    }
    for row in list_exports(&conn)? {
        materialize_export(uv, &row)?;
        report.files += 1;
    }
    for row in list_injects(&conn)? {
        match materialize_inject(uv, &conn, &row, force) {
            Ok(n) => report.injected += n,
            Err(AgentError::Tamper(detail)) if !force => {
                report
                    .skipped
                    .push(format!("{}: {detail}", row.target.display()));
            }
            Err(e) => return Err(e),
        }
    }
    Ok(report)
}

pub fn scan_inject_roots() -> Result<ExpandReport, AgentError> {
    let conn = open_db()?;
    expand_inject_roots(&conn)
}

pub fn enforce_all(
    uv: &mut glyx_store::UnlockedVault,
    force: bool,
) -> Result<MaterializeReport, AgentError> {
    materialize_all(uv, force)
}

pub fn recall_target(target: &Path) -> Result<bool, AgentError> {
    let conn = open_db()?;
    ledger_recall(&conn, target)
}

pub fn forget_target(target: &Path) -> Result<bool, AgentError> {
    let conn = open_db()?;
    let key = target.to_string_lossy().into_owned();
    let mut removed = false;
    if conn.execute("DELETE FROM exports WHERE target = ?1", [&key])? > 0 {
        removed = true;
    }
    if conn.execute("DELETE FROM injects WHERE target = ?1", [&key])? > 0 {
        removed = true;
    }
    Ok(removed)
}

pub fn teardown_all(uv: &glyx_store::UnlockedVault) -> Result<TeardownReport, AgentError> {
    let conn = open_db()?;
    let mut report = TeardownReport::default();
    for row in list_exports(&conn)? {
        if row.keep_on_lock {
            continue;
        }
        if row.target.exists() {
            shred_file(&row.target)?;
            report.wiped += 1;
        }
    }
    for row in list_injects(&conn)? {
        let Ok(text) = std::fs::read_to_string(&row.target) else {
            continue;
        };
        let refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
        let mut locked_text = text.clone();
        let mut missing = Vec::new();
        for r in &refs {
            let value = uv.get_item(&r.item_id)?.and_then(|item| {
                item.fields
                    .get(&r.field)
                    .map(|f| f.value.expose().to_owned())
            });
            match value {
                Some(value) => {
                    if locked_text.contains(&value) {
                        locked_text = locked_text.replace(&value, &r.locked);
                    } else {
                        missing.push(format!("{}:{}", r.item_id.as_simple(), r.field));
                    }
                }
                None => missing.push(format!("{}:{}", r.item_id.as_simple(), r.field)),
            }
        }
        if !missing.is_empty() {
            report.drifted.push(format!(
                "{}: values not found ({})",
                row.target.display(),
                missing.join(",")
            ));
            continue;
        }
        std::fs::write(&row.target, locked_text.as_bytes())?;
        let meta = std::fs::metadata(&row.target)?;
        conn.execute(
            "UPDATE injects SET locked_text = ?1, locked_hash = ?2, mtime = ?3, size = ?4 WHERE target = ?5",
            rusqlite::params![
                locked_text,
                blake_hex(locked_text.as_bytes()),
                meta.modified().ok().and_then(|t| t
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs().cast_signed())),
                meta.len().cast_signed(),
                row.target.to_string_lossy(),
            ],
        )?;
        report.restored += 1;
    }
    Ok(report)
}

pub fn crash_replay(uv: &glyx_store::UnlockedVault) -> Result<TeardownReport, AgentError> {
    teardown_all(uv)
}

#[derive(Debug, Clone)]
pub struct MergePreview {
    pub target: PathBuf,
    pub hunks: Vec<crate::merge::Hunk>,
    pub trailing_newline: bool,
}

pub fn preview_merge(
    uv: &glyx_store::UnlockedVault,
    target: &Path,
) -> Result<MergePreview, AgentError> {
    let conn = open_db()?;
    let row = list_injects(&conn)?
        .into_iter()
        .find(|r| r.target.as_path() == target)
        .ok_or_else(|| AgentError::Tamper(format!("{} not tracked", target.display())))?;
    let base = row.locked_text.ok_or_else(|| {
        AgentError::Tamper(format!("{} has no locked baseline", target.display()))
    })?;
    let theirs = std::fs::read_to_string(target)
        .map_err(|_| AgentError::Tamper(format!("{} unreadable", target.display())))?;
    let refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
    let form = parse_form(&row.form)?;
    let target_str = target.to_string_lossy().into_owned();
    let mut ours = base.clone();
    let mut spans = Vec::new();
    for r in &refs {
        let item = uv
            .get_item(&r.item_id)?
            .ok_or_else(|| AgentError::Tamper(format!("item {} gone", r.item_id)))?;
        let value = item
            .fields
            .get(&r.field)
            .ok_or_else(|| AgentError::Tamper(format!("field {} gone", r.field)))?
            .value
            .expose()
            .to_owned();
        spans.push(r.locked.clone());
        spans.push(value.clone());
        let plain_ref = glyx_core::ref_placeholder(&r.item_id, &r.field);
        if ours.contains(r.locked.as_str()) {
            ours = ours.replace(r.locked.as_str(), &value);
        } else if ours.contains(&plain_ref) {
            ours = ours.replace(&plain_ref, &value);
        } else {
            let locked = uv.render_locked(&r.item_id, &r.field, &target_str, form)?;
            spans.push(locked.clone());
            if ours.contains(&locked) {
                ours = ours.replace(&locked, &value);
            }
        }
    }
    let hunks = crate::merge::diff_hunks(&base, &theirs, &ours, &spans);
    Ok(MergePreview {
        target: target.to_owned(),
        trailing_newline: base.ends_with('\n'),
        hunks,
    })
}

pub fn apply_merge(
    uv: &glyx_store::UnlockedVault,
    target: &Path,
    picks: &BTreeMap<usize, crate::merge::Pick>,
) -> Result<String, AgentError> {
    let preview = preview_merge(uv, target)?;
    let merged = crate::merge::apply_hunks(&preview.hunks, picks, preview.trailing_newline)
        .map_err(|idx| AgentError::Tamper(format!("hunk {idx} needs a pick")))?;
    let conn = open_db()?;
    let row = list_injects(&conn)?
        .into_iter()
        .find(|r| r.target.as_path() == target)
        .ok_or_else(|| AgentError::Tamper(format!("{} not tracked", target.display())))?;
    let form = parse_form(&row.form)?;
    let target_str = target.to_string_lossy().into_owned();
    let mut refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
    for (id, field) in scan_refs(&merged) {
        if refs.iter().any(|r| r.item_id == id && r.field == field) {
            continue;
        }
        let locked = uv.render_locked(&id, &field, &target_str, form)?;
        refs.push(RefInfo {
            item_id: id,
            field,
            locked,
        });
    }
    std::fs::write(target, merged.as_bytes())?;
    let meta = std::fs::metadata(target)?;
    conn.execute(
        "UPDATE injects SET refs_json = ?1, unlocked_hash = ?2, mtime = ?3, size = ?4 WHERE target = ?5",
        rusqlite::params![
            serde_json::to_string(&refs).unwrap_or_default(),
            blake_hex(merged.as_bytes()),
            meta.modified().ok().and_then(|t| t
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().cast_signed())),
            meta.len().cast_signed(),
            target.to_string_lossy(),
        ],
    )?;
    Ok(merged)
}

#[cfg(test)]
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::ENV_LOCK;
    use super::*;
    use crate::ledger::{register_export, register_inject};

    #[test]
    fn full_cycle_file_and_inject() {
        let _env = ENV_LOCK.lock().expect("lock");
        let runtime = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", runtime.path());
        let work = tempfile::tempdir().expect("tempdir");
        let vpath = work.path().join("v.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        glyx_store::Vault::init(&vpath, suite, b"pw", Some(&[1u8; 32])).expect("init");
        let vault = glyx_store::Vault::open(&vpath).expect("open");
        let mut uv = vault.unlock(b"pw", &[1u8; 32]).expect("unlock");
        let hlc = uv.next_hlc().expect("tick");
        let node = uv.device_node();
        let mut fields = BTreeMap::new();
        fields.insert(
            "password".to_owned(),
            glyx_core::Field {
                value: glyx_core::SecretString::new("s3cret".to_owned()),
                field_hlc: hlc,
            },
        );
        let item = glyx_core::Item {
            id: Uuid::now_v7(),
            item_type: glyx_core::ItemType::Login,
            name: "x".to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            fields,
            hlc,
            rev: 1,
            deleted: false,
            updated_by: node,
        };
        let id = item.id;
        uv.put_item(&item).expect("put");
        let conn = open_db().expect("db");
        let target = work.path().join("out.txt");
        register_export(
            &conn,
            &crate::ledger::ExportSpec {
                target: &target,
                kind: "field",
                item_id: Some(id),
                field: Some("password"),
                blob_addr: None,
                keep_on_lock: false,
                perm: 0o600,
            },
        )
        .expect("register");
        let env_file = work.path().join("app.env");
        std::fs::write(
            &env_file,
            format!("user=bob\npass={{{{glyx:{id}/password}}}}\n"),
        )
        .expect("write");
        register_inject(&conn, &env_file, "encrypted-pointer", None).expect("register");
        drop(conn);
        let rep = materialize_all(&mut uv, false).expect("materialize");
        assert_eq!(rep.files, 1);
        assert_eq!(rep.injected, 1);
        assert_eq!(std::fs::read(&target).expect("read"), b"s3cret");
        let injected = std::fs::read_to_string(&env_file).expect("read");
        assert!(injected.contains("s3cret"));
        assert!(!injected.contains("{{glyx:"));
        let rep = teardown_all(&uv).expect("teardown");
        assert_eq!(rep.wiped, 1);
        assert_eq!(rep.restored, 1);
        assert!(rep.drifted.is_empty());
        assert!(!target.exists());
        let locked = std::fs::read_to_string(&env_file).expect("read");
        assert!(!locked.contains("s3cret"));
        assert!(locked.contains("__GLYXENC:V1:"));
        let conn = open_db().expect("db");
        assert!(check_all(&conn, true).expect("check").is_empty());
        assert!(recall_target(&env_file).expect("recall"));
        assert!(!env_file.exists());
        assert!(list_injects(&conn).expect("list").is_empty());
        let stale = work.path().join("residue.txt");
        std::fs::write(&stale, b"stale secret").expect("write");
        register_export(
            &conn,
            &crate::ledger::ExportSpec {
                target: &stale,
                kind: "field",
                item_id: None,
                field: Some("password"),
                blob_addr: None,
                keep_on_lock: false,
                perm: 0o600,
            },
        )
        .expect("register");
        let tampers = check_all(&conn, true).expect("check");
        assert_eq!(tampers.len(), 1);
        assert_eq!(tampers[0].kind, TamperKind::Residue);
    }

    #[test]
    fn ref_scanner() {
        let id = Uuid::now_v7();
        let text = format!("a {{{{glyx:{id}/password}}}} b {{{{glyx:bad}}}} c");
        let refs = scan_refs(&text);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].1, "password");
    }

    #[test]
    fn resolves_committed_pointer_without_ledger_refs() {
        let _env = ENV_LOCK.lock().expect("lock");
        let runtime = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", runtime.path());
        let work = tempfile::tempdir().expect("tempdir");
        let vpath = work.path().join("v.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        glyx_store::Vault::init(&vpath, suite, b"pw", Some(&[1u8; 32])).expect("init");
        let vault = glyx_store::Vault::open(&vpath).expect("open");
        let mut uv = vault.unlock(b"pw", &[1u8; 32]).expect("unlock");
        let hlc = uv.next_hlc().expect("tick");
        let node = uv.device_node();
        let mut fields = BTreeMap::new();
        fields.insert(
            "password".to_owned(),
            glyx_core::Field {
                value: glyx_core::SecretString::new("s3cret".to_owned()),
                field_hlc: hlc,
            },
        );
        let item = glyx_core::Item {
            id: Uuid::now_v7(),
            item_type: glyx_core::ItemType::Login,
            name: "x".to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            fields,
            hlc,
            rev: 1,
            deleted: false,
            updated_by: node,
        };
        let id = item.id;
        uv.put_item(&item).expect("put");

        let target = work.path().join("public.env");
        let target_str = target.to_string_lossy().into_owned();
        let pointer = uv
            .render_locked(
                &id,
                "password",
                &target_str,
                glyx_core::LockedForm::EncryptedPointer,
            )
            .expect("seal");
        std::fs::write(&target, format!("user = abc\npassword = {pointer}\n")).expect("write");

        let conn = open_db().expect("db");
        register_inject(&conn, &target, "encrypted-pointer", None).expect("register");
        let row = list_injects(&conn)
            .expect("list")
            .into_iter()
            .find(|r| r.target == target)
            .expect("row");
        let n = materialize_inject(&uv, &conn, &row, false).expect("materialize");
        assert_eq!(n, 1);
        let unlocked_text = std::fs::read_to_string(&target).expect("read");
        assert!(
            unlocked_text.contains("password = s3cret"),
            "{unlocked_text}"
        );
        assert!(unlocked_text.contains("user = abc"), "{unlocked_text}");

        let row = list_injects(&conn)
            .expect("list")
            .into_iter()
            .find(|r| r.target == target)
            .expect("row");
        let refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).expect("refs");
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].item_id, id);

        teardown_all(&uv).expect("teardown");
        let locked_text = std::fs::read_to_string(&target).expect("read");
        assert!(locked_text.contains(&pointer), "{locked_text}");
        assert!(!locked_text.contains("s3cret"));

        let other = work.path().join("moved.env");
        std::fs::write(&other, format!("password = {pointer}\n")).expect("write");
        register_inject(&conn, &other, "encrypted-pointer", None).expect("register");
        let row = list_injects(&conn)
            .expect("list")
            .into_iter()
            .find(|r| r.target == other)
            .expect("row");
        let n = materialize_inject(&uv, &conn, &row, false).expect("materialize");
        assert_eq!(n, 0);
        let untouched = std::fs::read_to_string(&other).expect("read");
        assert!(untouched.contains(&pointer), "{untouched}");
    }
}

#[cfg(test)]
mod merge_e2e {
    use super::*;
    use std::collections::BTreeMap;

    fn vault_with_secret(dir: &std::path::Path) -> (glyx_store::Vault, Uuid) {
        let vpath = dir.join("v.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        glyx_store::Vault::init(&vpath, suite, b"pw", Some(&[1u8; 32])).expect("init");
        let vault = glyx_store::Vault::open(&vpath).expect("open");
        let mut uv = vault.unlock(b"pw", &[1u8; 32]).expect("unlock");
        let hlc = uv.next_hlc().expect("tick");
        let node = uv.device_node();
        let mut fields = BTreeMap::new();
        fields.insert(
            "password".to_owned(),
            glyx_core::Field {
                value: glyx_core::SecretString::new("s3cret".to_owned()),
                field_hlc: hlc,
            },
        );
        let item = glyx_core::Item {
            id: Uuid::now_v7(),
            item_type: glyx_core::ItemType::Login,
            name: "x".to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            fields,
            hlc,
            rev: 1,
            deleted: false,
            updated_by: node,
        };
        let id = item.id;
        uv.put_item(&item).expect("put");
        (glyx_store::Vault::open(&vpath).expect("open"), id)
    }

    #[test]
    fn drift_merges_with_picks() {
        let _env = ENV_LOCK.lock().expect("lock");
        let runtime = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", runtime.path());
        let work = tempfile::tempdir().expect("tempdir");
        let (vault, id) = vault_with_secret(work.path());
        let mut uv = vault.unlock(b"pw", &[1u8; 32]).expect("unlock");
        let target = work.path().join("app.env");
        let original = format!("user=bob\n# stays\npass={{{{glyx:{id}/password}}}}\nnote=keep\n");
        std::fs::write(&target, &original).expect("write");
        let conn = open_db().expect("db");
        crate::ledger::register_inject(&conn, &target, "ref", None).expect("register");
        drop(conn);
        materialize_all(&mut uv, false).expect("materialize");
        assert_eq!(teardown_all(&uv).expect("teardown").restored, 1);
        std::fs::write(
            &target,
            "user=alice\n# stays\npass={{glyx:PLACEHOLDER}}\nnote=keep\n",
        )
        .expect("drift");
        let preview = preview_merge(&uv, &target).expect("preview");
        let conflicts = crate::merge::conflict_indexes(&preview.hunks);
        assert!(!conflicts.is_empty());
        let mut picks = BTreeMap::new();
        for idx in &conflicts {
            picks.insert(*idx, crate::merge::Pick::Ours);
        }
        let merged = apply_merge(&uv, &target, &picks).expect("apply");
        assert!(merged.contains("user=alice"));
        assert!(merged.contains("s3cret"));
        assert!(merged.contains("note=keep"));
        assert!(!merged.contains("<<<<<<<"));
        let preview2 = preview_merge(&uv, &target).expect("preview");
        assert!(crate::merge::conflict_indexes(&preview2.hunks).is_empty());
    }

    #[test]
    fn clean_drift_auto_applies() {
        let _env = ENV_LOCK.lock().expect("lock");
        let runtime = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", runtime.path());
        let work = tempfile::tempdir().expect("tempdir");
        let (vault, id) = vault_with_secret(work.path());
        let mut uv = vault.unlock(b"pw", &[1u8; 32]).expect("unlock");
        let target = work.path().join("app.env");
        std::fs::write(
            &target,
            format!("pass={{{{glyx:{id}/password}}}}\n# tail\n"),
        )
        .expect("write");
        let conn = open_db().expect("db");
        crate::ledger::register_inject(&conn, &target, "ref", None).expect("register");
        drop(conn);
        materialize_all(&mut uv, false).expect("materialize");
        teardown_all(&uv).expect("teardown");
        let locked = std::fs::read_to_string(&target).expect("locked");
        std::fs::write(&target, format!("{locked}extra=1\n")).expect("drift");
        let preview = preview_merge(&uv, &target).expect("preview");
        assert!(crate::merge::conflict_indexes(&preview.hunks).is_empty());
        let merged = apply_merge(&uv, &target, &BTreeMap::new()).expect("apply");
        assert!(merged.contains("extra=1"));
        assert!(merged.contains("s3cret"));
    }
}
