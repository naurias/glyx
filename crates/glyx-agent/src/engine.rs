use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use rusqlite::Connection;
use serde::Serialize;
use uuid::Uuid;

use crate::ledger::{
    blake_hex, expand_inject_roots, get_inject, list_exports, list_injects, open_db, parse_form,
    recall_target as ledger_recall, scan_pointers, scan_refs, shred_file, update_inject_template,
    AgentError, ExpandReport, ExportRow, InjectRow, RefInfo,
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
        "file" => {
            let id = row.item_id.ok_or_else(|| {
                AgentError::Crypto(glyx_crypto::CryptoError::Param("export lacks item".into()))
            })?;
            let item = uv
                .get_item(&id)?
                .ok_or_else(|| AgentError::Tamper(format!("item {id} gone")))?;
            let addr = item
                .fields
                .get("blob")
                .ok_or_else(|| AgentError::Tamper("file item lacks blob".into()))?
                .value
                .expose()
                .to_owned();
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
            form: Some("encrypted-pointer".to_owned()),
            label: None,
        });
        changed += 1;
    }
    Ok(changed)
}

fn plain_ref(id: &Uuid, field: &str) -> String {
    glyx_core::ref_placeholder(id, field)
}

fn unique_refs(text: &str) -> Vec<(Uuid, String)> {
    scan_refs(text)
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn field_is_secret(item: &glyx_core::Item, field: &str) -> bool {
    glyx_core::template::spec(item.item_type)
        .iter()
        .any(|spec| spec.name == field && spec.secret)
}

fn read_text_limited(path: &Path) -> Result<String, AgentError> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > crate::ledger::MAX_INJECT_BYTES {
        return Err(AgentError::Tamper(format!(
            "{} is larger than the injection limit",
            path.display()
        )));
    }
    let bytes = std::fs::read(path)?;
    if bytes.contains(&0) {
        return Err(AgentError::Tamper(format!(
            "{} is binary, not text",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| AgentError::NotUtf8(path.display().to_string()))
}

fn validate_template(text: &str) -> Result<(), AgentError> {
    if text.len() as u64 > crate::ledger::MAX_INJECT_BYTES {
        return Err(AgentError::Tamper("template is too large".to_owned()));
    }
    if text.contains('\0') {
        return Err(AgentError::Tamper(
            "template contains a NUL byte".to_owned(),
        ));
    }
    Ok(())
}

fn derive_template(
    uv: &glyx_store::UnlockedVault,
    text: &str,
    mut refs: Vec<RefInfo>,
    target: &str,
) -> (String, Vec<RefInfo>) {
    let mut out = text.to_owned();
    for r in &refs {
        if !r.locked.is_empty() {
            out = out.replace(&r.locked, &plain_ref(&r.item_id, &r.field));
        }
    }
    for token in scan_pointers(&out) {
        if refs.iter().any(|r| r.locked == token) {
            continue;
        }
        let Ok((id, field)) = uv.open_locked_pointer(&token, target) else {
            continue;
        };
        out = out.replace(&token, &plain_ref(&id, &field));
        refs.push(RefInfo {
            item_id: id,
            field,
            locked: token,
            form: Some("encrypted-pointer".to_owned()),
            label: None,
        });
    }
    for (id, field) in unique_refs(&out) {
        if !refs.iter().any(|r| r.item_id == id && r.field == field) {
            refs.push(RefInfo {
                item_id: id,
                field,
                locked: String::new(),
                form: None,
                label: None,
            });
        }
    }
    (out, refs)
}

fn render_values_from_template(
    uv: &glyx_store::UnlockedVault,
    template: &str,
    mask: bool,
) -> Result<String, AgentError> {
    let mut out = template.to_owned();
    for (id, field) in unique_refs(template) {
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
        let shown = if mask && field_is_secret(&item, &field) {
            "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}".to_owned()
        } else {
            value
        };
        out = out.replace(&plain_ref(&id, &field), &shown);
    }
    Ok(out)
}

fn render_locked_from_template(
    uv: &glyx_store::UnlockedVault,
    template: &str,
    refs: &[RefInfo],
    default_form: &str,
    target: &str,
    regenerate: bool,
) -> Result<(String, Vec<RefInfo>), AgentError> {
    let mut out = template.to_owned();
    let mut out_refs = Vec::new();
    for (id, field) in unique_refs(template) {
        let existing = refs.iter().find(|r| r.item_id == id && r.field == field);
        let form_text = existing
            .and_then(|r| r.form.clone())
            .unwrap_or_else(|| default_form.to_owned());
        let form = parse_form(&form_text)?;
        let locked = if regenerate {
            uv.render_locked(&id, &field, target, form)?
        } else {
            existing
                .map(|r| r.locked.clone())
                .filter(|locked| !locked.is_empty())
                .unwrap_or(uv.render_locked(&id, &field, target, form)?)
        };
        out = out.replace(&plain_ref(&id, &field), &locked);
        out_refs.push(RefInfo {
            item_id: id,
            field,
            locked,
            form: Some(form_text),
            label: existing.and_then(|r| r.label.clone()),
        });
    }
    Ok((out, out_refs))
}

fn persist_unlocked_state(
    uv: &glyx_store::UnlockedVault,
    conn: &Connection,
    target: &Path,
    template: &str,
    refs: &[RefInfo],
    default_form: &str,
    unlocked_text: &str,
) -> Result<Vec<RefInfo>, AgentError> {
    let target_str = target.to_string_lossy().into_owned();
    let (locked_text, refs) =
        render_locked_from_template(uv, template, refs, default_form, &target_str, false)?;
    let refs_json = serde_json::to_string(&refs).unwrap_or_default();
    let meta = std::fs::metadata(target)?;
    conn.execute(
        "UPDATE injects SET template_text = ?1, refs_json = ?2, locked_text = ?3,
           locked_hash = ?4, unlocked_hash = ?5, mtime = ?6, size = ?7 WHERE target = ?8",
        rusqlite::params![
            template,
            refs_json,
            locked_text,
            blake_hex(locked_text.as_bytes()),
            blake_hex(unlocked_text.as_bytes()),
            meta.modified().ok().and_then(|t| t
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().cast_signed())),
            meta.len().cast_signed(),
            target.to_string_lossy(),
        ],
    )?;
    Ok(refs)
}

type InjectState = (Option<InjectRow>, String, Vec<RefInfo>, String, bool);

fn load_inject_state(
    uv: &glyx_store::UnlockedVault,
    target: &Path,
) -> Result<InjectState, AgentError> {
    let conn = open_db()?;
    let row = get_inject(&conn, target)?;
    let exists = target.exists();
    let disk_text = if exists {
        read_text_limited(target)?
    } else {
        String::new()
    };
    let mut refs: Vec<RefInfo> = row
        .as_ref()
        .map(|r| serde_json::from_str(&r.refs_json).unwrap_or_default())
        .unwrap_or_default();
    let target_str = target.to_string_lossy().into_owned();
    let template = if let Some(template) = row.as_ref().and_then(|r| r.template_text.clone()) {
        template
    } else {
        let (template, updated) = derive_template(uv, &disk_text, refs, &target_str);
        refs = updated;
        template
    };
    Ok((row, template, refs, disk_text, exists))
}

#[derive(Debug, Clone, Serialize)]
pub struct InjectRefView {
    pub item_id: String,
    pub field: String,
    pub item_name: String,
    pub secret: bool,
    pub form: String,
    pub locked: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct InjectContent {
    pub target: String,
    pub tracked: bool,
    pub form: String,
    pub status: String,
    pub template: String,
    pub hash: String,
    pub refs: Vec<InjectRefView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InjectPreview {
    pub template: String,
    pub unlocked: String,
    pub locked: String,
}

pub fn inject_content(
    uv: &glyx_store::UnlockedVault,
    target: &Path,
    reveal: bool,
) -> Result<InjectContent, AgentError> {
    let (row, template, refs, disk_text, exists) = load_inject_state(uv, target)?;
    let form = row
        .as_ref()
        .map_or_else(|| "encrypted-pointer".to_owned(), |r| r.form.clone());
    let status = if !exists {
        "missing"
    } else if let Some(r) = &row {
        let hash = blake_hex(disk_text.as_bytes());
        if r.unlocked_hash.as_deref() == Some(hash.as_str()) {
            "unlocked"
        } else if r.locked_hash.as_deref() == Some(hash.as_str()) {
            "locked"
        } else {
            "drift"
        }
    } else {
        "untracked"
    };
    let mut views = Vec::new();
    for (id, field) in unique_refs(&template) {
        let item = uv
            .get_item(&id)?
            .ok_or_else(|| AgentError::Tamper(format!("item {id} gone")))?;
        let secret = field_is_secret(&item, &field);
        let value = item
            .fields
            .get(&field)
            .ok_or_else(|| AgentError::Tamper(format!("field {field} gone")))?
            .value
            .expose()
            .to_owned();
        let existing = refs.iter().find(|r| r.item_id == id && r.field == field);
        views.push(InjectRefView {
            item_id: id.to_string(),
            field: field.clone(),
            item_name: item.name.clone(),
            secret,
            form: existing
                .and_then(|r| r.form.clone())
                .unwrap_or_else(|| form.clone()),
            locked: existing.map(|r| r.locked.clone()).unwrap_or_default(),
            value: if secret && !reveal {
                "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}".to_owned()
            } else {
                value
            },
        });
    }
    Ok(InjectContent {
        target: target.to_string_lossy().into_owned(),
        tracked: row.is_some(),
        form,
        status: status.to_owned(),
        template,
        hash: blake_hex(disk_text.as_bytes()),
        refs: views,
    })
}

pub fn inject_preview(
    uv: &glyx_store::UnlockedVault,
    target: &Path,
    reveal: bool,
) -> Result<InjectPreview, AgentError> {
    let (row, template, refs, _, _) = load_inject_state(uv, target)?;
    let form = row
        .as_ref()
        .map_or_else(|| "encrypted-pointer".to_owned(), |r| r.form.clone());
    let target_str = target.to_string_lossy().into_owned();
    let unlocked = render_values_from_template(uv, &template, !reveal)?;
    let (locked, _) = render_locked_from_template(uv, &template, &refs, &form, &target_str, false)?;
    Ok(InjectPreview {
        template,
        unlocked,
        locked,
    })
}

pub fn inject_save(
    uv: &glyx_store::UnlockedVault,
    target: &Path,
    template: &str,
    form: &str,
    expected_hash: Option<&str>,
    materialized: bool,
    ref_forms: &BTreeMap<String, String>,
) -> Result<InjectContent, AgentError> {
    validate_template(template)?;
    if target.is_dir() {
        return Err(AgentError::Tamper(format!(
            "{} is a directory",
            target.display()
        )));
    }
    let conn = open_db()?;
    let row = get_inject(&conn, target)?;
    if target.exists() {
        let current = read_text_limited(target)?;
        let current_hash = blake_hex(current.as_bytes());
        if let Some(expected) = expected_hash {
            if expected != current_hash {
                return Err(AgentError::Tamper(
                    "file changed since it was opened; reload before saving".to_owned(),
                ));
            }
        }
    }
    if row.is_none() {
        crate::ledger::register_inject(&conn, target, form, None)?;
    }
    let old_refs: Vec<RefInfo> = row
        .as_ref()
        .map(|r| serde_json::from_str(&r.refs_json).unwrap_or_default())
        .unwrap_or_default();
    let mut refs = Vec::new();
    for (id, field) in unique_refs(template) {
        let item = uv
            .get_item(&id)?
            .ok_or_else(|| AgentError::Tamper(format!("item {id} gone")))?;
        if !item.fields.contains_key(&field) {
            return Err(AgentError::Tamper(format!("field {field} gone")));
        }
        let key = format!("{id}/{field}");
        let existing = old_refs
            .iter()
            .find(|r| r.item_id == id && r.field == field);
        refs.push(RefInfo {
            item_id: id,
            field,
            locked: String::new(),
            form: Some(
                ref_forms
                    .get(&key)
                    .cloned()
                    .or_else(|| existing.and_then(|r| r.form.clone()))
                    .unwrap_or_else(|| form.to_owned()),
            ),
            label: existing.and_then(|r| r.label.clone()),
        });
    }
    let target_str = target.to_string_lossy().into_owned();
    let (locked_text, refs) =
        render_locked_from_template(uv, template, &refs, form, &target_str, true)?;
    let unlocked_text = render_values_from_template(uv, template, false)?;
    let write_text = if materialized {
        &unlocked_text
    } else {
        &locked_text
    };
    std::fs::write(target, write_text.as_bytes())?;
    let meta = std::fs::metadata(target)?;
    let refs_json = serde_json::to_string(&refs).unwrap_or_default();
    update_inject_template(&conn, target, form, template, &refs_json)?;
    conn.execute(
        "UPDATE injects SET locked_text = ?1, locked_hash = ?2, unlocked_hash = ?3,
           mtime = ?4, size = ?5 WHERE target = ?6",
        rusqlite::params![
            locked_text,
            blake_hex(locked_text.as_bytes()),
            blake_hex(unlocked_text.as_bytes()),
            meta.modified().ok().and_then(|t| t
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().cast_signed())),
            meta.len().cast_signed(),
            target.to_string_lossy(),
        ],
    )?;
    inject_content(uv, target, false)
}

pub fn materialize_inject(
    uv: &glyx_store::UnlockedVault,
    conn: &Connection,
    row: &InjectRow,
    force: bool,
) -> Result<usize, AgentError> {
    let target = &row.target;
    let text = read_text_limited(target)?;
    let form = parse_form(&row.form)?;
    let target_str = target.to_string_lossy().into_owned();
    let mut refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
    let mut by_locked: BTreeMap<String, (Uuid, String)> = BTreeMap::new();
    for r in &refs {
        if !r.locked.is_empty() {
            by_locked.insert(r.locked.clone(), (r.item_id, r.field.clone()));
        }
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
            form: Some(row.form.clone()),
            label: None,
        });
        let placeholder = glyx_core::ref_placeholder(&id, &field);
        if new_text.contains(&placeholder) {
            new_text = new_text.replace(&placeholder, &value);
            changed += 1;
        }
    }
    changed += adopt_pointers(uv, &mut refs, &mut new_text, &target_str)?;
    let (derived_template, derived_refs) = derive_template(uv, &text, refs, &target_str);
    refs = derived_refs;
    if changed == 0 && new_text == text {
        if row.template_text.is_none() || row.locked_text.is_none() {
            persist_unlocked_state(uv, conn, target, &derived_template, &refs, &row.form, &text)?;
        }
        return Ok(0);
    }
    std::fs::write(target, new_text.as_bytes())?;
    persist_unlocked_state(
        uv,
        conn,
        target,
        &derived_template,
        &refs,
        &row.form,
        &new_text,
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

pub fn materialize_target(
    uv: &mut glyx_store::UnlockedVault,
    target: &Path,
    force: bool,
) -> Result<MaterializeReport, AgentError> {
    let conn = open_db()?;
    let mut report = MaterializeReport::default();
    if target.is_dir() {
        if let Ok(expanded) = expand_inject_roots(&conn) {
            report.scanned = expanded.files;
        }
    }
    for row in list_exports(&conn)? {
        if row.target.as_path() == target {
            materialize_export(uv, &row)?;
            report.files += 1;
        }
    }
    for row in list_injects(&conn)? {
        if !in_scope(Some(target), &row.target) {
            continue;
        }
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
    teardown_targets(uv, None)
}

fn auto_merge_lock(
    uv: &glyx_store::UnlockedVault,
    row: &InjectRow,
    template: &str,
    text: &str,
) -> Result<Option<String>, AgentError> {
    let refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
    let target_str = row.target.to_string_lossy().into_owned();
    let base = render_values_from_template(uv, template, false)?;
    let (ours, _) =
        render_locked_from_template(uv, template, &refs, &row.form, &target_str, false)?;
    let mut spans = Vec::new();
    for r in &refs {
        if let Some(item) = uv.get_item(&r.item_id)? {
            if let Some(field) = item.fields.get(&r.field) {
                spans.push(field.value.expose().to_owned());
            }
        }
        if !r.locked.is_empty() {
            spans.push(r.locked.clone());
        }
    }
    let hunks = crate::merge::diff_hunks(&base, text, &ours, &spans);
    if hunks
        .iter()
        .any(|hunk| hunk.kind == crate::merge::HunkKind::Conflict)
    {
        return Ok(None);
    }
    let merged = crate::merge::apply_hunks(&hunks, &BTreeMap::new(), base.ends_with('\n'))
        .map_err(|_| AgentError::Tamper("merge needs a manual pick".to_owned()))?;
    Ok(Some(merged))
}

fn persist_merged_lock(
    uv: &glyx_store::UnlockedVault,
    conn: &Connection,
    row: &InjectRow,
    merged: &str,
) -> Result<(), AgentError> {
    let refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
    let target_str = row.target.to_string_lossy().into_owned();
    let (merged_template, new_refs) = derive_template(uv, merged, refs, &target_str);
    std::fs::write(&row.target, merged.as_bytes())?;
    let meta = std::fs::metadata(&row.target)?;
    conn.execute(
        "UPDATE injects SET template_text = ?1, refs_json = ?2, locked_text = ?3,
           locked_hash = ?4, mtime = ?5, size = ?6 WHERE target = ?7",
        rusqlite::params![
            merged_template,
            serde_json::to_string(&new_refs).unwrap_or_default(),
            merged,
            blake_hex(merged.as_bytes()),
            meta.modified().ok().and_then(|t| t
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs().cast_signed())),
            meta.len().cast_signed(),
            row.target.to_string_lossy(),
        ],
    )?;
    Ok(())
}

fn restore_locked_baseline(
    uv: &glyx_store::UnlockedVault,
    conn: &Connection,
    row: &InjectRow,
    refs: &mut Vec<RefInfo>,
    current_hash: &str,
) -> Result<bool, AgentError> {
    if row.unlocked_hash.as_deref() != Some(current_hash) {
        return Ok(false);
    }
    let Some(template) = &row.template_text else {
        return Ok(false);
    };
    let target_str = row.target.to_string_lossy().into_owned();
    let (locked_text, new_refs) =
        render_locked_from_template(uv, template, refs, &row.form, &target_str, false)?;
    *refs = new_refs;
    std::fs::write(&row.target, locked_text.as_bytes())?;
    let meta = std::fs::metadata(&row.target)?;
    conn.execute(
        "UPDATE injects SET refs_json = ?1, locked_text = ?2, locked_hash = ?3,
           mtime = ?4, size = ?5 WHERE target = ?6",
        rusqlite::params![
            serde_json::to_string(&refs).unwrap_or_default(),
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
    Ok(true)
}

pub fn teardown_targets(
    uv: &glyx_store::UnlockedVault,
    target: Option<&Path>,
) -> Result<TeardownReport, AgentError> {
    let conn = open_db()?;
    let mut report = TeardownReport::default();
    for row in list_exports(&conn)? {
        if row.keep_on_lock || !in_scope(target, &row.target) {
            continue;
        }
        if row.target.exists() {
            shred_file(&row.target)?;
            report.wiped += 1;
        }
    }
    for row in list_injects(&conn)? {
        if !in_scope(target, &row.target) {
            continue;
        }
        let Ok(text) = read_text_limited(&row.target) else {
            continue;
        };
        let mut refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
        let current_hash = blake_hex(text.as_bytes());
        if row.locked_hash.as_deref() == Some(current_hash.as_str()) {
            continue;
        }
        let target_str = row.target.to_string_lossy().into_owned();
        if restore_locked_baseline(uv, &conn, &row, &mut refs, &current_hash)? {
            report.restored += 1;
            continue;
        }
        if let Some(template) = &row.template_text {
            if let Some(merged) = auto_merge_lock(uv, &row, template, &text)? {
                persist_merged_lock(uv, &conn, &row, &merged)?;
                report.restored += 1;
                continue;
            }
        }
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
        let template = if let Some(template) = row.template_text.clone() {
            template
        } else {
            derive_template(uv, &locked_text, refs, &target_str).0
        };
        std::fs::write(&row.target, locked_text.as_bytes())?;
        let meta = std::fs::metadata(&row.target)?;
        conn.execute(
            "UPDATE injects SET template_text = ?1, locked_text = ?2, locked_hash = ?3,
               mtime = ?4, size = ?5 WHERE target = ?6",
            rusqlite::params![
                template,
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

#[derive(Debug, Clone, Default)]
pub struct RelocateReport {
    pub exports: usize,
    pub roots: usize,
    pub injects: usize,
}

pub fn relocate_target(
    uv: &glyx_store::UnlockedVault,
    old: &Path,
    new: &Path,
) -> Result<RelocateReport, AgentError> {
    let conn = open_db()?;
    let mut report = RelocateReport::default();
    let old_str = old.to_string_lossy().into_owned();
    let new_str = new.to_string_lossy().into_owned();
    report.exports = conn.execute(
        "UPDATE exports SET target = ?1 WHERE target = ?2",
        rusqlite::params![new_str, old_str],
    )?;
    if old.is_dir() {
        report.roots = conn.execute(
            "UPDATE inject_roots SET root = ?1 WHERE root = ?2",
            rusqlite::params![new_str, old_str],
        )?;
    }
    for row in list_injects(&conn)? {
        let row_str = row.target.to_string_lossy().into_owned();
        let under_root = old.is_dir() && row.target.starts_with(old);
        if row_str != old_str && !under_root {
            continue;
        }
        let new_target = if row_str == old_str {
            new.to_path_buf()
        } else {
            let rel = row
                .target
                .strip_prefix(old)
                .unwrap_or_else(|_| Path::new(""));
            new.join(rel)
        };
        let new_target_str = new_target.to_string_lossy().into_owned();
        let form = parse_form(&row.form)?;
        let mut refs: Vec<RefInfo> = serde_json::from_str(&row.refs_json).unwrap_or_default();
        let existing = std::fs::read_to_string(&new_target).ok();
        let mut rewritten = existing.clone();
        for r in &mut refs {
            let new_locked = uv.render_locked(&r.item_id, &r.field, &new_target_str, form)?;
            if let Some(text) = rewritten.as_mut() {
                if text.contains(&r.locked) {
                    *text = text.replace(&r.locked, &new_locked);
                }
            }
            r.locked = new_locked;
        }
        if let (Some(before), Some(after)) = (existing, rewritten.as_ref()) {
            if before != *after {
                std::fs::write(&new_target, after.as_bytes())?;
            }
        }
        conn.execute(
            "UPDATE injects SET target = ?1, refs_json = ?2 WHERE target = ?3",
            rusqlite::params![
                new_target_str,
                serde_json::to_string(&refs).unwrap_or_default(),
                row_str,
            ],
        )?;
        report.injects += 1;
    }
    Ok(report)
}

fn in_scope(target: Option<&Path>, candidate: &Path) -> bool {
    match target {
        None => true,
        Some(t) => candidate == t || (t.is_dir() && candidate.starts_with(t)),
    }
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
            form: Some(row.form.clone()),
            label: None,
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

    fn login_vault(work: &std::path::Path) -> (glyx_store::UnlockedVault, Uuid) {
        let vpath = work.join("v.glyx");
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
            favorite: false,
            fields,
            hlc,
            rev: 1,
            deleted: false,
            updated_by: node,
        };
        let id = item.id;
        uv.put_item(&item).expect("put");
        (uv, id)
    }

    #[test]
    fn full_cycle_file_and_inject() {
        let _env = ENV_LOCK.lock().expect("lock");
        let runtime = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", runtime.path());
        let work = tempfile::tempdir().expect("tempdir");
        let (mut uv, id) = login_vault(work.path());
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
    fn drift_merges_into_locked_template() {
        let _env = ENV_LOCK.lock().expect("lock");
        let runtime = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", runtime.path());
        let work = tempfile::tempdir().expect("tempdir");
        let (mut uv, id) = login_vault(work.path());
        let conn = open_db().expect("db");
        let env_file = work.path().join("drift.env");
        std::fs::write(
            &env_file,
            format!("user=bob\npass={{{{glyx:{id}/password}}}}\n"),
        )
        .expect("write");
        register_inject(&conn, &env_file, "encrypted-pointer", None).expect("register");
        drop(conn);
        materialize_all(&mut uv, false).expect("materialize");
        let injected = std::fs::read_to_string(&env_file).expect("read");
        std::fs::write(&env_file, format!("{injected}added=yes\n")).expect("edit");
        let rep = teardown_all(&uv).expect("teardown");
        assert_eq!(rep.restored, 1);
        assert!(rep.drifted.is_empty());
        let locked = std::fs::read_to_string(&env_file).expect("read");
        assert!(locked.contains("added=yes"));
        assert!(locked.contains("__GLYXENC:V1:"));
        assert!(!locked.contains("s3cret"));
        materialize_all(&mut uv, false).expect("materialize");
        let unlocked = std::fs::read_to_string(&env_file).expect("read");
        assert!(unlocked.contains("s3cret"));
        assert!(unlocked.contains("added=yes"));
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
        let (uv, id) = login_vault(work.path());

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

    #[test]
    fn relocate_reseals_pointers_and_scopes_targets() {
        let _env = ENV_LOCK.lock().expect("lock");
        let runtime = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", runtime.path());
        let work = tempfile::tempdir().expect("tempdir");
        let (mut uv, id) = login_vault(work.path());

        let conn = open_db().expect("db");
        let old = work.path().join("public.env");
        let other = work.path().join("other.env");
        std::fs::write(&old, format!("password = {{{{glyx:{id}/password}}}}\n")).expect("write");
        std::fs::write(&other, format!("password = {{{{glyx:{id}/password}}}}\n")).expect("write");
        register_inject(&conn, &old, "encrypted-pointer", None).expect("register old");
        register_inject(&conn, &other, "encrypted-pointer", None).expect("register other");

        let row = list_injects(&conn)
            .expect("list")
            .into_iter()
            .find(|r| r.target == old)
            .expect("row");
        materialize_inject(&uv, &conn, &row, false).expect("materialize");
        assert!(std::fs::read_to_string(&old)
            .expect("read")
            .contains("s3cret"));

        teardown_targets(&uv, Some(&old)).expect("lock target");
        let locked_old = std::fs::read_to_string(&old).expect("read");
        assert!(locked_old.contains("__GLYXENC:V1:"), "{locked_old}");
        let refs_old: Vec<RefInfo> = serde_json::from_str(
            &list_injects(&conn)
                .expect("list")
                .into_iter()
                .find(|r| r.target == old)
                .expect("row")
                .refs_json,
        )
        .expect("refs");
        let old_token = refs_old[0].locked.clone();

        let new = work.path().join("moved.env");
        std::fs::rename(&old, &new).expect("rename");
        let rep = relocate_target(&uv, &old, &new).expect("relocate");
        assert_eq!(rep.injects, 1);
        assert!(list_injects(&conn)
            .expect("list")
            .iter()
            .any(|r| r.target == new));
        assert!(!list_injects(&conn)
            .expect("list")
            .iter()
            .any(|r| r.target == old));

        let row_new = list_injects(&conn)
            .expect("list")
            .into_iter()
            .find(|r| r.target == new)
            .expect("row new");
        let refs_new: Vec<RefInfo> = serde_json::from_str(&row_new.refs_json).expect("refs");
        assert_ne!(
            refs_new[0].locked, old_token,
            "pointer resealed for new path"
        );
        let locked_new = std::fs::read_to_string(&new).expect("read");
        assert!(locked_new.contains(&refs_new[0].locked), "{locked_new}");

        let other_text = std::fs::read_to_string(&other).expect("read");
        assert!(
            other_text.contains(&format!("{{{{glyx:{id}/password}}}}")),
            "other target untouched: {other_text}"
        );

        let rep2 = materialize_target(&mut uv, &new, false).expect("materialize new");
        assert_eq!(rep2.injected, 1);
        assert!(std::fs::read_to_string(&new)
            .expect("read")
            .contains("s3cret"));

        teardown_targets(&uv, Some(&new)).expect("relock");
        assert!(std::fs::read_to_string(&new)
            .expect("read")
            .contains(&refs_new[0].locked));
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
            favorite: false,
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
