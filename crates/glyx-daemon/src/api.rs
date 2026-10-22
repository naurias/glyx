use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{middleware, Router};
use futures_util::StreamExt as _;
use serde::Deserialize;
use tokio::io::AsyncWriteExt as _;
use tokio_util::io::ReaderStream;
#[derive(Debug)]
pub struct AppState {
    pub active: Mutex<Option<PathBuf>>,
    pub vault: Mutex<Option<glyx_store::UnlockedVault>>,
    pub token: String,
    pub port: Mutex<u16>,
    pub idle_lock_ms: std::sync::atomic::AtomicU64,
    pub last_activity_ms: Mutex<u64>,
    pub agent_stop: Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>,
    pub tamper: Mutex<Vec<String>>,
}

impl AppState {
    fn active_path(&self) -> Option<PathBuf> {
        self.active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn active_vault(&self) -> Result<(PathBuf, glyx_store::Vault), glyx_store::StoreError> {
        let path = self
            .active_path()
            .ok_or_else(|| glyx_store::StoreError::Corrupt("no vault selected".into()))?;
        let vault = glyx_store::Vault::open(&path)?;
        Ok((path, vault))
    }

    fn publish_record(&self) {
        let active = self.active_path();
        let vault_id = active
            .as_ref()
            .and_then(|p| glyx_store::Vault::open(p).ok())
            .map(|v| v.config().vault_id);
        let port = *self
            .port
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = crate::runtime::write_record(&crate::runtime::DaemonRecord {
            port,
            pid: std::process::id(),
            token: self.token.clone(),
            vault_id,
            vault_path: active,
        });
    }
}

fn now_ms() -> u64 {
    glyx_core::ids::wall_ms_now()
}

fn temp_tag() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 8];
    if glyx_crypto::rand::fill_random(&mut bytes).is_ok() {
        let mut out = String::with_capacity(16);
        for b in bytes {
            let _ = write!(out, "{b:02x}");
        }
        return out;
    }
    format!("{}-{}", std::process::id(), now_ms())
}

fn hex16(bytes: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(32);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn audit(
    uv: &glyx_store::UnlockedVault,
    event: &str,
    item: Option<uuid::Uuid>,
    field: Option<&str>,
    outcome: &str,
    detail: Option<&str>,
) {
    let _ = glyx_store::audit::append(
        uv.config().vault_id,
        &uv.device_node().to_hex(),
        event,
        item,
        field,
        Some(outcome),
        detail,
    );
}

fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    request: axum::http::Request<axum::body::Body>,
    next: middleware::Next,
) -> impl IntoResponse {
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .is_some_and(|t| constant_time_eq(t, &state.token));
    if !ok {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "unauthorized"})),
        )
            .into_response();
    }
    *state
        .last_activity_ms
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = now_ms();
    next.run(request).await
}

fn locked_error() -> (StatusCode, Json<serde_json::Value>) {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "vault locked"})),
    )
}

fn store_error(e: &glyx_store::StoreError) -> (StatusCode, Json<serde_json::Value>) {
    let code = match e {
        glyx_store::StoreError::NotFound(_) => StatusCode::NOT_FOUND,
        glyx_store::StoreError::Ambiguous(_, _) => StatusCode::CONFLICT,
        glyx_store::StoreError::Limit(_) => StatusCode::PAYLOAD_TOO_LARGE,
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (code, Json(serde_json::json!({"error": e.to_string()})))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(ui_index))
        .fallback(ui_fallback)
        .route("/v1/health", get(health))
        .route("/v1/health/report", get(health_report))
        .route("/v1/devices", get(devices))
        .route("/v1/devices/label", post(set_device_label))
        .route("/v1/audit", get(audit_log))
        .route("/v1/generate", post(generate_password))
        .route("/v1/templates", get(list_templates))
        .route("/v1/status", get(status))
        .route(
            "/v1/vaults",
            get(list_vaults).post(add_vault).delete(forget_vault),
        )
        .route("/v1/vaults/create", post(create_vault))
        .route("/v1/vaults/select", post(select_vault))
        .route("/v1/vaults/rekey", post(rekey_vault))
        .route("/v1/vaults/backup", get(backup_vault))
        .route("/v1/vaults/restore", post(restore_vault))
        .route("/v1/settings", get(get_settings).post(set_settings))
        .route("/v1/library", get(library))
        .route("/v1/library/tags/rename", post(rename_tag))
        .route("/v1/library/tags/delete", post(delete_tag))
        .route("/v1/library/folders/rename", post(rename_folder))
        .route("/v1/library/folders/delete", post(delete_folder))
        .route("/v1/recents", get(recents))
        .route("/v1/unlock", post(unlock))
        .route("/v1/lock", post(lock))
        .route("/v1/items", get(list_items).post(create_item))
        .route("/v1/items/bulk", post(bulk_items))
        .route("/v1/items/duplicates", get(duplicate_items))
        .route(
            "/v1/items/:id",
            get(show_item).patch(edit_item).delete(delete_item),
        )
        .route("/v1/items/:id/totp", get(totp_code))
        .route("/v1/items/:id/rendered", get(rendered_item))
        .route("/v1/items/:id/fill", post(fill_item))
        .route("/v1/items/:id/history", get(item_history))
        .route(
            "/v1/items/:id/history/:file",
            get(show_history_item).post(restore_history_item),
        )
        .route(
            "/v1/items/:id/history/:file/compare",
            get(compare_history_item),
        )
        .route(
            "/v1/blobs",
            post(upload_blob).layer(DefaultBodyLimit::max(glyx_store::MAX_BLOB_BYTES)),
        )
        .route("/v1/blobs/gc", post(gc_blobs))
        .route("/v1/blobs/:addr", get(download_blob))
        .route("/v1/ssh-gen", post(ssh_gen))
        .route("/v1/ssh/export", post(ssh_export))
        .route("/v1/sync", post(sync))
        .route("/v1/conflicts", get(list_conflicts))
        .route("/v1/conflicts/:id", get(show_conflict))
        .route("/v1/conflicts/:id/resolve", post(resolve_conflict))
        .route("/v1/gc", post(gc))
        .route("/v1/doctor", get(doctor))
        .route(
            "/v1/exports",
            get(list_exports).post(add_export).delete(recall_export),
        )
        .route("/v1/exports/enforce", post(enforce_exports))
        .route("/v1/injects", post(add_inject))
        .route("/v1/injects/scan", post(scan_injects))
        .route("/v1/agent/tamper", get(agent_tamper))
        .route("/v1/agent/resolve", post(agent_resolve))
        .route("/v1/agent/unlock", post(agent_unlock_target))
        .route("/v1/agent/lock", post(agent_lock_target))
        .route("/v1/agent/relocate", post(agent_relocate))
        .route(
            "/v1/agent/merge",
            get(agent_merge_preview).post(agent_merge_apply),
        )
        .route("/v1/ssh/env", get(ssh_env))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .with_state(state)
}

#[derive(rust_embed::RustEmbed)]
#[folder = "../../apps/webui/build"]
struct Ui;

fn ui_bytes(path: &str) -> Response {
    let target = if path.is_empty() { "index.html" } else { path };
    match Ui::get(target).or_else(|| Ui::get("index.html")) {
        Some(file) => {
            let mime = mime_guess::from_path(target).first_or_octet_stream();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, mime.as_ref().to_owned())],
                file.data.to_vec(),
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no ui built").into_response(),
    }
}

async fn ui_index() -> impl IntoResponse {
    ui_bytes("index.html")
}

async fn ui_fallback(uri: axum::http::Uri) -> impl IntoResponse {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("v1/") {
        return (StatusCode::NOT_FOUND, "no such api").into_response();
    }
    ui_bytes(path)
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({"ok": true}))
}

async fn list_templates() -> impl IntoResponse {
    let out: Vec<serde_json::Value> = glyx_core::template::ALL_TYPES
        .iter()
        .map(|t| {
            let fields: Vec<serde_json::Value> = glyx_core::template::spec(*t)
                .iter()
                .map(|f| {
                    serde_json::json!({
                        "name": f.name, "secret": f.secret, "required": f.required,
                    })
                })
                .collect();
            serde_json::json!({
                "type": serde_json::to_value(t).unwrap_or(serde_json::Value::Null),
                "fields": fields,
            })
        })
        .collect();
    Json(serde_json::Value::Array(out))
}

async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state.active_path();
    let vault_info = active.as_ref().and_then(|p| {
        glyx_store::Vault::open(p).ok().map(|v| {
            let device = v.device_id().ok().map(|d| hex16(&d.0));
            serde_json::json!({
                "path": p,
                "vault_id": v.config().vault_id,
                "keyfile_required": v.keyfile_required(),
                "device_id": device,
            })
        })
    });
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut report = match guard.as_ref() {
        None => serde_json::json!({"locked": true}),
        Some(uv) => {
            let headers = uv.list(true).unwrap_or_default();
            let live = headers.iter().filter(|r| !r.deleted).count();
            let conflicts = uv.list_conflicts().map_or(0, |c| c.len());
            let last_merge = uv.last_merge_ms().unwrap_or(None);
            serde_json::json!({
                "locked": false,
                "envelopes": headers.len(),
                "live": live,
                "conflicts": conflicts,
                "last_merge_ms": last_merge,
            })
        }
    };
    report["vault"] = vault_info.unwrap_or(serde_json::Value::Null);
    Json(report)
}

#[derive(Deserialize)]
struct UnlockBody {
    password: Option<String>,
    keyfile: Option<String>,
    pin: Option<String>,
    new_pin: Option<String>,
    ttl_min: Option<u64>,
    materialize: Option<bool>,
}

#[allow(clippy::too_many_lines)]
async fn unlock(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnlockBody>,
) -> impl IntoResponse {
    if let Some(pin) = body.new_pin.as_ref() {
        if body.pin.is_none() && pin.chars().count() < 4 {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "PIN must be at least 4 characters"})),
            )
                .into_response();
        }
    }
    let vault = match state.active_vault() {
        Ok((_, v)) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    let vault_id = vault.config().vault_id;
    let device_hex = vault
        .device_id()
        .ok()
        .map(glyx_core::DeviceId::to_hex)
        .unwrap_or_default();
    let keyfile_required = vault.keyfile_required();
    let via_pin = body.pin.is_some();
    let new_pin = body.new_pin.clone();
    let ttl_min = body.ttl_min;
    let materialize = body.materialize;
    let result = tokio::task::spawn_blocking(move || {
        if let Some(pin) = body.pin {
            return vault.open_session(Some(pin.as_bytes())).and_then(|opt| {
                opt.ok_or_else(|| glyx_store::StoreError::Corrupt("bad PIN".into()))
            });
        }
        let kf = if keyfile_required {
            let kf_path = body.keyfile.ok_or_else(|| {
                glyx_store::StoreError::Corrupt("this vault requires a keyfile".into())
            })?;
            let bytes = std::fs::read(&kf_path).map_err(glyx_store::StoreError::from)?;
            if bytes.len() != 32 {
                return Err(glyx_store::StoreError::Corrupt("bad keyfile".into()));
            }
            let mut kf = [0u8; 32];
            kf.copy_from_slice(&bytes);
            kf
        } else {
            glyx_crypto::ZERO_KEYFILE
        };
        let pw = body.password.unwrap_or_default();
        vault.unlock(pw.as_bytes(), &kf)
    })
    .await;
    match result {
        Ok(Ok(mut uv)) => {
            audit(&uv, "unlock", None, None, "success", None);
            let cfg = glyx_store::config::load();
            if !via_pin {
                if let Some(pin) = new_pin.as_deref() {
                    let ttl = ttl_min.unwrap_or(cfg.session_ttl_min);
                    if let Err(e) = uv.seal_pin_session(pin.as_bytes(), ttl) {
                        return store_error(&e).into_response();
                    }
                } else if let Some(ttl) = ttl_min {
                    if let Err(e) = uv.write_plain_session(ttl) {
                        return store_error(&e).into_response();
                    }
                }
            }
            let agent_report = if materialize.unwrap_or(cfg.auto_materialize) {
                glyx_agent::enforce_all(&mut uv, false)
                    .map(|r| r.skipped)
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let identities = glyx_agent::ssh_agent::load_identities(&uv).unwrap_or_default();
            let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            if !identities.is_empty() {
                let sock = glyx_agent::ssh_agent::socket_path(&vault_id);
                let run_flag = flag.clone();
                std::thread::spawn(move || {
                    glyx_agent::ssh_agent::serve_until(&sock, &identities, &run_flag).ok();
                });
            }
            *state
                .agent_stop
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(flag);
            *state
                .tamper
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = agent_report;
            *state
                .vault
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(uv);
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Ok(Err(e)) => {
            let _ = glyx_store::audit::append(
                vault_id,
                &device_hex,
                "unlock",
                None,
                None,
                Some("failed"),
                None,
            );
            store_error(&e).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

fn stop_agent_socket(state: &AppState) {
    if let Some(flag) = state
        .agent_stop
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        flag.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

fn release_vault(uv: &glyx_store::UnlockedVault) {
    if glyx_agent::teardown_all(uv).is_err() {
        eprintln!("agent teardown failed");
    }
    let vault_id = uv.config().vault_id;
    glyx_agent::ssh_agent::stop(&glyx_agent::ssh_agent::socket_path(&vault_id));
    glyx_store::session::wipe_ticket(&vault_id);
}

fn do_lock(state: &AppState) {
    let taken = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    stop_agent_socket(state);
    if let Some(uv) = taken.as_ref() {
        audit(uv, "lock", None, None, "success", None);
        release_vault(uv);
    }
}

async fn lock(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    do_lock(&state);
    Json(serde_json::json!({"ok": true})).into_response()
}

#[derive(Deserialize)]
struct ListQuery {
    #[serde(rename = "type")]
    item_type: Option<String>,
    folder: Option<String>,
    tag: Option<String>,
    all: Option<bool>,
    q: Option<String>,
    favorite: Option<bool>,
    sort: Option<String>,
    order: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

fn row_json(row: &glyx_store::IndexRow) -> serde_json::Value {
    serde_json::json!({
        "id": row.id,
        "type": row.item_type,
        "name": row.name,
        "rev": row.rev,
        "deleted": row.deleted,
        "favorite": row.favorite,
        "folder": row.folder,
        "tags": row.tags,
        "updated_ms": row.updated_ms,
    })
}

async fn list_items(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ListQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let rows = match uv.list(q.all.unwrap_or(false)) {
        Ok(r) => r,
        Err(e) => return store_error(&e).into_response(),
    };
    let needle = q.q.as_ref().map(|s| s.to_lowercase());
    let mut out = Vec::new();
    for row in rows {
        if q.item_type.as_ref().is_some_and(|t| &row.item_type != t) {
            continue;
        }
        if q.favorite.is_some_and(|f| row.favorite != f) {
            continue;
        }
        if q.folder.as_ref().is_some_and(|f| &row.folder != f) {
            continue;
        }
        if q.tag
            .as_ref()
            .is_some_and(|t| !row.tags.iter().any(|x| x == t))
        {
            continue;
        }
        if let Some(needle) = needle.as_ref() {
            let mut hit = row.name.to_lowercase().contains(needle)
                || row.folder.to_lowercase().contains(needle)
                || row
                    .tags
                    .iter()
                    .any(|tag| tag.to_lowercase().contains(needle));
            if !hit {
                if let Some(item) = uv.get_item(&row.id).ok().flatten() {
                    hit = item.fields.iter().any(|(key, field)| {
                        glyx_store::present::display_value(item.item_type, key, false)
                            && field.value.expose().to_lowercase().contains(needle)
                    });
                }
            }
            if !hit {
                continue;
            }
        }
        out.push(row);
    }
    let sort = q.sort.as_deref().unwrap_or("updated");
    let desc = q
        .order
        .as_deref()
        .map_or(!matches!(sort, "name" | "type"), |order| order == "desc");
    out.sort_by(|a, b| {
        let ordering = match sort {
            "name" => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
            "type" => a.item_type.cmp(&b.item_type),
            "favorite" => a
                .favorite
                .cmp(&b.favorite)
                .then_with(|| b.updated_ms.cmp(&a.updated_ms)),
            _ => a.updated_ms.cmp(&b.updated_ms),
        };
        let ordering = if desc { ordering.reverse() } else { ordering };
        ordering.then_with(|| a.id.cmp(&b.id))
    });
    let total = out.len();
    let offset = q.offset.unwrap_or(0);
    let limit = q.limit.map_or(total, |limit| limit.min(500));
    let page: Vec<_> = out
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|row| row_json(&row))
        .collect();
    let mut response = Json(serde_json::Value::Array(page)).into_response();
    if let Ok(value) = HeaderValue::from_str(&total.to_string()) {
        response.headers_mut().insert("x-total-count", value);
    }
    response
}

#[derive(Deserialize)]
struct BulkBody {
    ids: Vec<uuid::Uuid>,
    action: String,
    tags: Option<Vec<String>>,
    folder: Option<String>,
}

async fn bulk_items(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BulkBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let result = match body.action.as_str() {
        "favorite" => uv.set_favorite_many(&body.ids, true),
        "unfavorite" => uv.set_favorite_many(&body.ids, false),
        "add_tags" => match body.tags {
            Some(tags) if !tags.is_empty() => uv.add_tags_many(&body.ids, &tags),
            _ => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "tags are required"})),
                )
                    .into_response();
            }
        },
        "remove_tags" => match body.tags {
            Some(tags) if !tags.is_empty() => uv.remove_tags_many(&body.ids, &tags),
            _ => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "tags are required"})),
                )
                    .into_response();
            }
        },
        "set_folder" => match body.folder {
            Some(folder) => uv.set_folder_many(&body.ids, &folder),
            None => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "folder is required"})),
                )
                    .into_response();
            }
        },
        "delete" => uv.delete_many(&body.ids),
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "unknown bulk action"})),
            )
                .into_response();
        }
    };
    match result {
        Ok(affected) => Json(serde_json::json!({"ok": true, "affected": affected})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct RenameBody {
    from: String,
    to: String,
}

#[derive(Deserialize)]
struct NameBody {
    name: String,
}

#[derive(Deserialize)]
struct FolderBody {
    folder: String,
}

async fn library(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.library() {
        Ok(library) => Json(library).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn rename_tag(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RenameBody>,
) -> impl IntoResponse {
    if body.from.trim().is_empty() || body.to.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "tag names must not be empty"})),
        )
            .into_response();
    }
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    match uv.rename_tag(&body.from, &body.to) {
        Ok(affected) => Json(serde_json::json!({"ok": true, "affected": affected})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn delete_tag(
    State(state): State<Arc<AppState>>,
    Json(body): Json<NameBody>,
) -> impl IntoResponse {
    if body.name.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "tag name must not be empty"})),
        )
            .into_response();
    }
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    match uv.delete_tag(&body.name) {
        Ok(affected) => Json(serde_json::json!({"ok": true, "affected": affected})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn rename_folder(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RenameBody>,
) -> impl IntoResponse {
    if body.from.trim().is_empty() || body.to.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "folder names must not be empty"})),
        )
            .into_response();
    }
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    match uv.rename_folder(&body.from, &body.to) {
        Ok(affected) => Json(serde_json::json!({"ok": true, "affected": affected})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn delete_folder(
    State(state): State<Arc<AppState>>,
    Json(body): Json<FolderBody>,
) -> impl IntoResponse {
    if body.folder.trim().is_empty() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "folder name must not be empty"})),
        )
            .into_response();
    }
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    match uv.delete_folder(&body.folder) {
        Ok(affected) => Json(serde_json::json!({"ok": true, "affected": affected})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn duplicate_items(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.duplicates() {
        Ok(groups) => Json(serde_json::json!({"groups": groups})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn recents(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let config = glyx_store::config::load();
    let mut out = Vec::new();
    for recent in config.recents(&uv.config().vault_id) {
        let Ok(Some(item)) = uv.get_item(&recent.item_id) else {
            continue;
        };
        if item.deleted {
            continue;
        }
        out.push(serde_json::json!({
            "id": item.id,
            "name": item.name,
            "type": serde_json::to_value(item.item_type).unwrap_or_default(),
            "favorite": item.favorite,
            "folder": item.folder,
            "at_ms": recent.at_ms,
        }));
    }
    Json(serde_json::Value::Array(out)).into_response()
}

#[derive(Deserialize)]
struct HealthQuery {
    min_length: Option<usize>,
    max_age_days: Option<u64>,
}

async fn health_report(
    State(state): State<Arc<AppState>>,
    Query(q): Query<HealthQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.health(q.min_length.unwrap_or(12), q.max_age_days.unwrap_or(365)) {
        Ok(report) => Json(report).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn devices(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.devices() {
        Ok(devices) => Json(serde_json::json!({"devices": devices})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct DeviceLabelBody {
    id: String,
    label: String,
}

async fn set_device_label(
    State(state): State<Arc<AppState>>,
    Json(body): Json<DeviceLabelBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let Some(device) = glyx_core::DeviceId::from_hex(&body.id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "bad device id"})),
        )
            .into_response();
    };
    let mut cfg = glyx_store::config::load();
    cfg.set_device_label(uv.config().vault_id, body.id.clone(), body.label.clone());
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    let _ = glyx_store::audit::append(
        uv.config().vault_id,
        &uv.device_node().to_hex(),
        "device_label",
        None,
        None,
        Some("success"),
        Some(&format!("{device:?} -> {}", body.label)),
    );
    Json(serde_json::json!({"ok": true})).into_response()
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
    offset: Option<usize>,
    event: Option<String>,
}

async fn audit_log(
    State(state): State<Arc<AppState>>,
    Query(q): Query<AuditQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let total = match glyx_store::audit::count(&uv.config().vault_id, q.event.as_deref()) {
        Ok(total) => total,
        Err(e) => return store_error(&e).into_response(),
    };
    match glyx_store::audit::list(
        &uv.config().vault_id,
        q.limit.unwrap_or(100),
        q.offset.unwrap_or(0),
        q.event.as_deref(),
    ) {
        Ok(events) => {
            let mut response = Json(serde_json::json!({"events": events})).into_response();
            if let Ok(value) = HeaderValue::from_str(&total.to_string()) {
                response.headers_mut().insert("x-total-count", value);
            }
            response
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn generate_password(
    Json(options): Json<glyx_crypto::pass::PasswordOptions>,
) -> impl IntoResponse {
    match glyx_crypto::pass::generate_with_options(options) {
        Ok(password) => Json(serde_json::json!({
            "password": password,
            "entropy_bits": glyx_crypto::pass::password_entropy_bits(&options),
        }))
        .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RevealQuery {
    reveal: Option<bool>,
}

async fn show_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<RevealQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.resolve(&id) {
        Ok(item) => {
            let _ = glyx_store::config::note_recent(uv.config().vault_id, item.id);
            if q.reveal.unwrap_or(false) {
                audit(uv, "item_reveal", Some(item.id), None, "success", None);
            }
            Json(glyx_store::present::item_json(
                &item,
                q.reveal.unwrap_or(false),
            ))
            .into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn rendered_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<RevealQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.resolve(&id) {
        Ok(item) => {
            if q.reveal.unwrap_or(false) {
                audit(
                    uv,
                    "item_reveal",
                    Some(item.id),
                    Some("body"),
                    "success",
                    None,
                );
            }
            match glyx_store::present::note_rendered(uv, &item, q.reveal.unwrap_or(false)) {
                Ok(body) => Json(serde_json::json!({
                    "id": item.id,
                    "name": item.name,
                    "type": item.item_type,
                    "body": body,
                }))
                .into_response(),
                Err(e) => store_error(&e).into_response(),
            }
        }
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct CreateBody {
    #[serde(rename = "type")]
    item_type: String,
    name: String,
    folder: Option<String>,
    tags: Option<Vec<String>>,
    fields: Option<BTreeMap<String, String>>,
    generate: Option<Vec<String>>,
}

async fn create_item(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let parsed = match glyx_core::template::parse_type(&body.item_type) {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let mut values = BTreeMap::new();
    for (k, v) in body.fields.unwrap_or_default() {
        values.insert(k, v);
    }
    for spec in body.generate.unwrap_or_default() {
        let (name, len) = match spec.split_once(':') {
            Some((n, l)) => (n.to_owned(), l.parse().unwrap_or(24)),
            None => (spec.clone(), 24),
        };
        match glyx_crypto::pass::generate_password(len) {
            Ok(pw) => {
                values.insert(name, pw);
            }
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    }
    for field in glyx_core::template::spec(parsed) {
        if field.required && !values.contains_key(field.name) {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(
                    serde_json::json!({"error": format!("missing required field {}", field.name)}),
                ),
            )
                .into_response();
        }
    }
    match glyx_store::present::build_new(
        uv,
        parsed,
        body.name,
        body.folder.unwrap_or_default(),
        body.tags.unwrap_or_default(),
        values,
    ) {
        Ok(item) => {
            let id = item.id;
            match uv.put_item(&item) {
                Ok(()) => {
                    audit(uv, "item_create", Some(id), None, "success", None);
                    Json(serde_json::json!({"ok": true, "id": id})).into_response()
                }
                Err(e) => store_error(&e).into_response(),
            }
        }
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct EditBody {
    rename: Option<String>,
    folder: Option<String>,
    tags: Option<Vec<String>>,
    favorite: Option<bool>,
    fields: Option<BTreeMap<String, String>>,
    delete_fields: Option<Vec<String>>,
}

async fn edit_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<EditBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let mut item = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let renamed = body.rename.is_some();
    if let Some(name) = body.rename {
        item.name = name;
    }
    let meta_touched = body.folder.is_some() || body.tags.is_some() || body.favorite.is_some();
    if let Some(folder) = body.folder {
        item.folder = folder;
    }
    if let Some(tags) = body.tags {
        item.tags = tags;
    }
    if let Some(favorite) = body.favorite {
        item.favorite = favorite;
    }
    let values = body.fields.unwrap_or_default();
    let touched = !values.is_empty() || body.delete_fields.is_some() || renamed || meta_touched;
    for k in body.delete_fields.unwrap_or_default() {
        item.fields.remove(&k);
    }
    if let Err(e) = glyx_store::present::apply_fields(uv, &mut item, values) {
        return store_error(&e).into_response();
    }
    if touched {
        if let Err(e) = uv.put_item(&item) {
            return store_error(&e).into_response();
        }
        audit(uv, "item_edit", Some(item.id), None, "success", None);
    }
    Json(serde_json::json!({"ok": true, "id": item.id, "rev": item.rev})).into_response()
}

async fn delete_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let item = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    match uv.delete_item(&item.id) {
        Ok(_) => {
            audit(uv, "item_delete", Some(item.id), None, "success", None);
            Json(serde_json::json!({"ok": true, "id": item.id})).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn totp_code(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let item = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let params = match glyx_store::present::totp_params(&item) {
        Ok(p) => p,
        Err(e) => return store_error(&e).into_response(),
    };
    match glyx_crypto::totp::generate_code(&params) {
        Ok(code) => {
            audit(uv, "totp", Some(item.id), None, "success", None);
            Json(serde_json::json!({"code": code, "period": params.step})).into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct SshGenBody {
    name: String,
    kind: Option<String>,
    comment: Option<String>,
    folder: Option<String>,
}

async fn ssh_gen(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SshGenBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let kind = body.kind.unwrap_or_else(|| "ed25519".to_owned());
    let pair = match glyx_crypto::ssh::generate(&kind, body.comment.as_deref().unwrap_or("")) {
        Ok(p) => p,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let mut values = BTreeMap::new();
    values.insert("private".to_owned(), pair.openssh_private);
    values.insert("public".to_owned(), pair.openssh_public.clone());
    values.insert("comment".to_owned(), body.comment.unwrap_or_default());
    values.insert("kind".to_owned(), kind);
    match glyx_store::present::build_new(
        uv,
        glyx_core::ItemType::SshKey,
        body.name,
        body.folder.unwrap_or_default(),
        Vec::new(),
        values,
    ) {
        Ok(item) => {
            let id = item.id;
            match uv.put_item(&item) {
                Ok(()) => {
                    Json(serde_json::json!({"ok": true, "id": id, "public": pair.openssh_public}))
                        .into_response()
                }
                Err(e) => store_error(&e).into_response(),
            }
        }
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct SyncBody {
    other: Option<PathBuf>,
    other_keyfile: Option<PathBuf>,
    other_password: Option<String>,
}

async fn sync(State(state): State<Arc<AppState>>, Json(body): Json<SyncBody>) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let heal = match uv.heal_conflict_files() {
        Ok(r) => r,
        Err(e) => return store_error(&e).into_response(),
    };
    let mut adopted = 0usize;
    let mut merged = heal.merged;
    let mut conflicts = heal.conflicts;
    let mut blobs = 0usize;
    let Some(other_path) = body.other else {
        return Json(serde_json::json!({
            "healed": heal.healed,
            "adopted": adopted,
            "merged": merged,
            "conflicts": conflicts,
            "blobs": blobs,
        }))
        .into_response();
    };
    let other_vault = match glyx_store::Vault::open(&other_path) {
        Ok(v) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    let kf = if other_vault.keyfile_required() {
        let Some(kf_path) = body.other_keyfile else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "other_keyfile required"})),
            )
                .into_response();
        };
        match std::fs::read(&kf_path) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut kf = [0u8; 32];
                kf.copy_from_slice(&bytes);
                kf
            }
            Ok(_) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "bad keyfile"})),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    } else {
        glyx_crypto::ZERO_KEYFILE
    };
    let pw = body.other_password.unwrap_or_default();
    let other_uv = match other_vault.unlock(pw.as_bytes(), &kf) {
        Ok(v) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    match uv.sync_from(&other_uv) {
        Ok(rep) => {
            adopted = rep.adopted;
            merged += rep.merged;
            conflicts += rep.conflicts;
            blobs = rep.blobs;
        }
        Err(e) => return store_error(&e).into_response(),
    }
    audit(
        uv,
        "sync",
        None,
        None,
        "success",
        Some(&format!("merged={merged} conflicts={conflicts}")),
    );
    Json(serde_json::json!({
        "healed": heal.healed,
        "adopted": adopted,
        "merged": merged,
        "conflicts": conflicts,
        "blobs": blobs,
    }))
    .into_response()
}

async fn list_conflicts(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.list_conflicts() {
        Ok(metas) => Json(
            metas
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "item": m.item_id,
                        "created_ms": m.created_ms,
                        "targets": m.race_targets,
                    })
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn show_conflict(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(q): Query<RevealQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let item = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    match uv.read_conflict(&item.id) {
        Ok(Some((winner, local, remote, targets))) => Json(serde_json::json!({
            "item": item.id,
            "targets": targets,
            "winner": glyx_store::present::item_json(&winner, q.reveal.unwrap_or(false)),
            "local": glyx_store::present::item_json(&local, q.reveal.unwrap_or(false)),
            "remote": glyx_store::present::item_json(&remote, q.reveal.unwrap_or(false)),
        }))
        .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no conflict"})),
        )
            .into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct ResolveBody {
    mode: String,
    fields: Option<BTreeMap<String, String>>,
}

async fn resolve_conflict(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<ResolveBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let item = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let resolution = match body.mode.as_str() {
        "mine" => glyx_store::Resolution::Mine,
        "theirs" => glyx_store::Resolution::Theirs,
        "fields" => glyx_store::Resolution::Fields(body.fields.unwrap_or_default()),
        _ => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "mode must be mine, theirs, or fields"})),
            )
                .into_response();
        }
    };
    match uv.resolve_conflict(&item.id, resolution) {
        Ok(true) => Json(serde_json::json!({"ok": true, "id": item.id})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "conflict vanished"})),
        )
            .into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct GcBody {
    older_than_ms: Option<u64>,
    dry_run: Option<bool>,
}

async fn gc(State(state): State<Arc<AppState>>, Json(body): Json<GcBody>) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let window = body.older_than_ms.unwrap_or(30 * 86_400_000);
    if body.dry_run.unwrap_or(false) {
        let now = now_ms();
        let cutoff = now.saturating_sub(window);
        let mut ids = Vec::new();
        for row in uv.list(true).unwrap_or_default() {
            if !row.deleted {
                continue;
            }
            if let Ok(Some(item)) = uv.get_item(&row.id) {
                if item.hlc.wall_ms < cutoff {
                    ids.push(row.id);
                }
            }
        }
        return Json(serde_json::json!({"ids": ids})).into_response();
    }
    match uv.gc_tombstones(window) {
        Ok(ids) => {
            audit(
                uv,
                "gc",
                None,
                None,
                "success",
                Some(&format!("purged={}", ids.len())),
            );
            Json(serde_json::json!({"ids": ids})).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn upload_blob(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.put_blob(&body) {
        Ok(addr) => Json(serde_json::json!({"addr": addr, "size": body.len()})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn download_blob(
    State(state): State<Arc<AppState>>,
    Path(addr): Path<String>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match uv.get_blob(&addr) {
        Ok(data) => {
            let mut headers = HeaderMap::new();
            headers.insert(
                CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            headers.insert(
                CONTENT_DISPOSITION,
                HeaderValue::from_str(&format!("attachment; filename=\"{addr}.bin\""))
                    .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
            );
            headers.insert(
                "x-content-type-options",
                HeaderValue::from_static("nosniff"),
            );
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
            (headers, data.to_vec()).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct GcBlobsBody {
    dry_run: Option<bool>,
}

async fn gc_blobs(
    State(state): State<Arc<AppState>>,
    Json(body): Json<GcBlobsBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let conn = match glyx_agent::ledger::open_db() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let exports = match glyx_agent::ledger::list_exports(&conn) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let refs: HashSet<String> = exports.into_iter().filter_map(|e| e.blob_addr).collect();
    match uv.gc_blobs(&refs, body.dry_run.unwrap_or(true)) {
        Ok(report) => Json(report).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn backup_vault(State(state): State<Arc<AppState>>) -> Response {
    if state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "lock the vault before creating a backup"})),
        )
            .into_response();
    }
    let Some(path) = state.active_path() else {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "no vault selected"})),
        )
            .into_response();
    };
    let cfg = glyx_store::config::load();
    let keyfile = cfg
        .find(&path)
        .and_then(|entry| entry.keyfile.as_deref())
        .map(std::path::Path::to_path_buf);
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();
    let tmp =
        std::env::temp_dir().join(format!("glyx-backup-{}-{stamp}.tar.gz", std::process::id()));
    let vault_path = path.clone();
    let tmp_path = tmp.clone();
    let result = tokio::task::spawn_blocking(move || {
        let vault = glyx_store::Vault::open(&vault_path)?;
        glyx_store::backup::create(&vault, &tmp_path, keyfile.as_deref())
    })
    .await;
    match result {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return store_error(&e).into_response();
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    let file = match tokio::fs::File::open(&tmp).await {
        Ok(f) => f,
        Err(e) => {
            let _ = tokio::fs::remove_file(&tmp).await;
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let _ = tokio::fs::remove_file(&tmp).await;
    let name: String = path
        .file_name()
        .map_or_else(|| "vault".to_owned(), |n| n.to_string_lossy().into_owned())
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{name}-{stamp}.tar.gz\""))
            .unwrap_or_else(|_| HeaderValue::from_static("attachment")),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    let stream = ReaderStream::new(file);
    (headers, Body::from_stream(stream)).into_response()
}

#[derive(Deserialize)]
struct RestoreQuery {
    dest: PathBuf,
}

async fn restore_vault(
    State(state): State<Arc<AppState>>,
    Query(params): Query<RestoreQuery>,
    request: axum::http::Request<Body>,
) -> Response {
    if state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .is_some()
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "lock the vault before restoring"})),
        )
            .into_response();
    }
    let dest = params.dest;
    let tmp = std::env::temp_dir().join(format!("glyx-restore-{}.tar.gz", temp_tag()));
    let std_file = {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&tmp) {
            Ok(f) => f,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }
    };
    if let Err((code, body)) = receive_archive(request, std_file).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return (code, body).into_response();
    }
    let tmp_path = tmp.clone();
    let dest_path = dest.clone();
    let result =
        tokio::task::spawn_blocking(move || glyx_store::backup::restore(&tmp_path, &dest_path))
            .await;
    let _ = tokio::fs::remove_file(&tmp).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return store_error(&e).into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    let vault = match glyx_store::Vault::open(&dest) {
        Ok(v) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    let mut cfg = glyx_store::config::load();
    let label = dest.file_name().map_or_else(
        || dest.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    cfg.register(glyx_store::config::VaultEntry {
        path: dest.clone(),
        name: Some(label),
        vault_id: Some(vault.config().vault_id),
        keyfile: None,
        last_used_ms: now_ms(),
    });
    if cfg.current_vault.is_none() {
        cfg.select(&dest);
    }
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    {
        let mut active = state
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if active.is_none() {
            *active = Some(dest.clone());
        }
    }
    Json(serde_json::json!({"ok": true, "path": dest, "vault_id": vault.config().vault_id}))
        .into_response()
}

async fn receive_archive(
    request: axum::http::Request<Body>,
    std_file: std::fs::File,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let mut file = tokio::fs::File::from_std(std_file);
    let mut stream = request.into_body().into_data_stream();
    let mut total = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
        total = total.saturating_add(chunk.len() as u64);
        if total > glyx_store::MAX_ARCHIVE_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({"error": "backup archive is too large"})),
            ));
        }
        file.write_all(&chunk).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
        })?;
    }
    file.sync_all().await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
    })?;
    Ok(())
}

#[derive(Deserialize)]
struct DoctorQuery {
    rebuild_index: Option<bool>,
    with_unlock: Option<bool>,
}

async fn doctor(
    State(state): State<Arc<AppState>>,
    Query(params): Query<DoctorQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let vault = match state.active_vault() {
        Ok((_, v)) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    let headers = vault.scan_headers().unwrap_or_default();
    let live = headers.iter().filter(|h| !h.deleted).count();
    let mut report = serde_json::json!({
        "format_version": vault.config().format_version,
        "envelopes": headers.len(),
        "live": live,
        "ok": true,
    });
    if let Some(uv) = guard.as_ref() {
        let mut ok = 0;
        for h in &headers {
            if uv.get_item(&h.id).ok().flatten().is_some() {
                ok += 1;
            }
        }
        report["decrypted_items"] = serde_json::json!(ok);
    }
    if params.with_unlock == Some(true) {
        report["with_unlock"] = serde_json::json!(guard.is_some());
    }
    if params.rebuild_index == Some(true) {
        if guard.is_some() {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "lock the vault before rebuilding the index"})),
            )
                .into_response();
        }
        match vault.rebuild_index() {
            Ok(n) => report["rebuilt_index"] = serde_json::json!(n),
            Err(e) => return store_error(&e).into_response(),
        }
    }
    Json(report).into_response()
}

async fn list_exports(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = state;
    let conn = match glyx_agent::ledger::open_db() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let exports = glyx_agent::ledger::list_exports(&conn).unwrap_or_default();
    let injects = glyx_agent::ledger::list_injects(&conn).unwrap_or_default();
    let roots = glyx_agent::ledger::list_inject_roots(&conn).unwrap_or_default();
    Json(serde_json::json!({
        "exports": exports.iter().map(|e| serde_json::json!({
            "target": e.target, "kind": e.kind, "keep": e.keep_on_lock,
        })).collect::<Vec<_>>(),
        "injects": injects.iter().map(|i| serde_json::json!({
            "target": i.target, "form": i.form,
        })).collect::<Vec<_>>(),
        "roots": roots.iter().map(|r| serde_json::json!({
            "root": r.root, "glob": r.glob, "form": r.form,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct AddExportBody {
    target: PathBuf,
    kind: String,
    item: Option<String>,
    field: Option<String>,
    blob: Option<String>,
    ssh: Option<String>,
    keep: Option<bool>,
    perm: Option<u32>,
}

async fn add_export(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddExportBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let resolved = match (&body.item, &body.ssh) {
        (Some(q), _) | (_, Some(q)) => match uv.resolve(q) {
            Ok(item) => Some(item.id),
            Err(e) => return store_error(&e).into_response(),
        },
        (None, None) => None,
    };
    if body.kind != "field" && body.kind != "blob" && body.kind != "ssh" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "kind must be field, blob, or ssh"})),
        )
            .into_response();
    }
    let conn = match glyx_agent::ledger::open_db() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    match glyx_agent::ledger::register_export(
        &conn,
        &glyx_agent::ledger::ExportSpec {
            target: &body.target,
            kind: &body.kind,
            item_id: resolved,
            field: body.field.as_deref(),
            blob_addr: body.blob.as_deref(),
            keep_on_lock: body.keep.unwrap_or(false),
            perm: body.perm.unwrap_or(0o600),
        },
    ) {
        Ok(id) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct TargetQuery {
    target: PathBuf,
}

async fn recall_export(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TargetQuery>,
) -> impl IntoResponse {
    let _ = state;
    if q.target.is_dir() {
        let conn = match glyx_agent::ledger::open_db() {
            Ok(c) => c,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };
        return match glyx_agent::ledger::forget_inject_root(&conn, &q.target) {
            Ok(removed) => {
                Json(serde_json::json!({"ok": true, "removed": removed})).into_response()
            }
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    match glyx_agent::engine::recall_target(&q.target) {
        Ok(removed) => Json(serde_json::json!({"ok": true, "removed": removed})).into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct EnforceBody {
    force: Option<bool>,
}

async fn enforce_exports(
    State(state): State<Arc<AppState>>,
    Json(body): Json<EnforceBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    match glyx_agent::enforce_all(uv, body.force.unwrap_or(false)) {
        Ok(rep) => {
            state
                .tamper
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone_from(&rep.skipped);
            Json(serde_json::json!({
                "files": rep.files, "injected": rep.injected, "skipped": rep.skipped,
            }))
            .into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct AddInjectBody {
    target: PathBuf,
    form: Option<String>,
    glob: Option<String>,
}

async fn add_inject(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AddInjectBody>,
) -> impl IntoResponse {
    let _ = state;
    let conn = match glyx_agent::ledger::open_db() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    if body.target.is_dir() {
        let glob = body.glob.unwrap_or_else(|| "*.md".to_owned());
        let form = body.form.unwrap_or_else(|| "ref".to_owned());
        if let Err(e) = glyx_agent::ledger::register_inject_root(&conn, &body.target, &glob, &form)
        {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
        return match glyx_agent::ledger::expand_inject_roots(&conn) {
            Ok(rep) => Json(serde_json::json!({
                "ok": true, "root": body.target, "glob": glob, "files": rep.files,
            }))
            .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    match glyx_agent::ledger::register_inject(
        &conn,
        &body.target,
        &body.form.unwrap_or_else(|| "encrypted-pointer".to_owned()),
        None,
    ) {
        Ok(()) => Json(serde_json::json!({"ok": true})).into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn scan_injects(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = state;
    let conn = match glyx_agent::ledger::open_db() {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    match glyx_agent::ledger::expand_inject_roots(&conn) {
        Ok(rep) => Json(serde_json::json!({
            "ok": true,
            "roots": rep.roots,
            "files": rep.files,
            "removed": rep.removed,
            "skipped": rep.skipped,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn agent_tamper(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if guard.as_ref().is_none() {
        let conn = match glyx_agent::ledger::open_db() {
            Ok(c) => c,
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        };
        return match glyx_agent::engine::check_all(&conn, true) {
            Ok(found) => Json(
                found
                    .iter()
                    .map(|t| {
                        serde_json::json!({
                            "target": t.target,
                            "kind": format!("{:?}", t.kind),
                            "detail": t.detail,
                        })
                    })
                    .collect::<Vec<_>>(),
            )
            .into_response(),
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    drop(guard);
    let pending = state
        .tamper
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    Json(serde_json::Value::Array(
        pending.into_iter().map(serde_json::Value::String).collect(),
    ))
    .into_response()
}

#[derive(Deserialize)]
struct AgentResolveBody {
    target: Option<PathBuf>,
    action: String,
}

async fn agent_resolve(
    State(state): State<Arc<AppState>>,
    Json(body): Json<AgentResolveBody>,
) -> impl IntoResponse {
    if body.action == "force" {
        let mut guard = state
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(uv) = guard.as_mut() else {
            return locked_error().into_response();
        };
        return match glyx_agent::enforce_all(uv, true) {
            Ok(rep) => {
                state
                    .tamper
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone_from(&rep.skipped);
                Json(serde_json::json!({"ok": true, "skipped": rep.skipped})).into_response()
            }
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    if body.action == "keep" {
        let Some(target) = body.target else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "keep needs a target"})),
            )
                .into_response();
        };
        return match glyx_agent::engine::forget_target(&target) {
            Ok(forgotten) => {
                Json(serde_json::json!({"ok": true, "forgotten": forgotten})).into_response()
            }
            Err(e) => (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response(),
        };
    }
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(serde_json::json!({"error": "action must be force or keep"})),
    )
        .into_response()
}

#[derive(Deserialize)]
struct TargetBody {
    target: PathBuf,
    force: Option<bool>,
}

async fn agent_unlock_target(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TargetBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    match glyx_agent::materialize_target(uv, &body.target, body.force.unwrap_or(false)) {
        Ok(rep) => Json(serde_json::json!({
            "ok": true, "files": rep.files, "injected": rep.injected,
            "scanned": rep.scanned, "skipped": rep.skipped,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn agent_lock_target(
    State(state): State<Arc<AppState>>,
    Json(body): Json<TargetBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match glyx_agent::teardown_targets(uv, Some(&body.target)) {
        Ok(rep) => Json(serde_json::json!({
            "ok": true, "wiped": rep.wiped, "restored": rep.restored, "drifted": rep.drifted,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct RelocateBody {
    old: PathBuf,
    new: PathBuf,
}

async fn agent_relocate(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RelocateBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match glyx_agent::relocate_target(uv, &body.old, &body.new) {
        Ok(rep) => Json(serde_json::json!({
            "ok": true, "exports": rep.exports, "roots": rep.roots, "injects": rep.injects,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn agent_merge_preview(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TargetQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match glyx_agent::engine::preview_merge(uv, &q.target) {
        Ok(preview) => Json(serde_json::json!({
            "target": preview.target,
            "hunks": preview.hunks,
        }))
        .into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct MergeApplyBody {
    target: PathBuf,
    picks: Option<std::collections::BTreeMap<String, serde_json::Value>>,
}

async fn agent_merge_apply(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MergeApplyBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let mut picks = std::collections::BTreeMap::new();
    for (idx, choice) in body.picks.unwrap_or_default() {
        let idx: usize = match idx.parse() {
            Ok(i) => i,
            Err(_) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "bad hunk index"})),
                )
                    .into_response();
            }
        };
        let pick = if choice == "theirs" {
            glyx_agent::merge::Pick::Theirs
        } else if choice == "ours" {
            glyx_agent::merge::Pick::Ours
        } else if let Some(custom) = choice.get("custom").and_then(|v| v.as_str()) {
            glyx_agent::merge::Pick::Custom(custom.to_owned())
        } else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "pick must be theirs, ours, or {custom}"})),
            )
                .into_response();
        };
        picks.insert(idx, pick);
    }
    match glyx_agent::engine::apply_merge(uv, &body.target, &picks) {
        Ok(merged) => Json(serde_json::json!({"ok": true, "bytes": merged.len()})).into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn ssh_env(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let _ = state;
    match glyx_agent::ssh_agent::live_socket() {
        Some(sock) => Json(serde_json::json!({"sock": sock})).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no agent socket"})),
        )
            .into_response(),
    }
}

fn preset_params(preset: Option<&str>) -> glyx_core::KdfParams {
    match preset {
        Some("hardened") => glyx_core::KdfParams::hardened(),
        Some("mobile") => glyx_core::KdfParams::mobile(),
        _ => glyx_core::KdfParams::balanced(),
    }
}

fn cipher_of(name: Option<&str>) -> glyx_core::Cipher {
    match name {
        Some("aesgcm" | "aes256gcm" | "aes-gcm" | "aes") => glyx_core::Cipher::Aes256gcm,
        _ => glyx_core::Cipher::Xchacha20poly1305,
    }
}

#[derive(Deserialize)]
struct VaultAddBody {
    path: PathBuf,
    name: Option<String>,
    keyfile: Option<String>,
}

#[derive(Deserialize)]
struct VaultCreateBody {
    path: PathBuf,
    name: Option<String>,
    preset: Option<String>,
    cipher: Option<String>,
    password: String,
    keyfile: Option<String>,
}

async fn item_history(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no such item"})),
        )
            .into_response();
    };
    match uv.history(&uuid) {
        Ok(items) => Json(serde_json::json!({"items": items})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn show_history_item(
    State(state): State<Arc<AppState>>,
    Path((id, file)): Path<(String, String)>,
    Query(params): Query<RevealQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no such item"})),
        )
            .into_response();
    };
    match uv.history_item(&uuid, &file) {
        Ok(item) => Json(serde_json::json!({
            "item": glyx_store::present::item_json(&item, params.reveal.unwrap_or(false))
        }))
        .into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn compare_history_item(
    State(state): State<Arc<AppState>>,
    Path((id, file)): Path<(String, String)>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no such item"})),
        )
            .into_response();
    };
    let history = match uv.history_item(&uuid, &file) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let current = match uv.get_item(&uuid) {
        Ok(Some(item)) => item,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "no such item"})),
            )
                .into_response();
        }
        Err(e) => return store_error(&e).into_response(),
    };
    let mut changed = Vec::new();
    if current.name != history.name {
        changed.push("name");
    }
    if current.folder != history.folder {
        changed.push("folder");
    }
    if current.tags != history.tags {
        changed.push("tags");
    }
    if current.favorite != history.favorite {
        changed.push("favorite");
    }
    let keys: std::collections::BTreeSet<_> =
        current.fields.keys().chain(history.fields.keys()).collect();
    for key in keys {
        let now = current.fields.get(key).map(|f| f.value.expose());
        let before = history.fields.get(key).map(|f| f.value.expose());
        if now != before {
            changed.push(key);
        }
    }
    Json(serde_json::json!({
        "current_rev": current.rev,
        "history_rev": history.rev,
        "changed": changed
    }))
    .into_response()
}

async fn restore_history_item(
    State(state): State<Arc<AppState>>,
    Path((id, file)): Path<(String, String)>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let Ok(uuid) = id.parse::<uuid::Uuid>() else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no such item"})),
        )
            .into_response();
    };
    match uv.restore_history(&uuid, &file) {
        Ok(item) => Json(serde_json::json!({"ok": true, "id": item.id})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct SshExportBody {
    item: String,
    to: Option<PathBuf>,
    perm: Option<u32>,
}

async fn ssh_export(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SshExportBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let item = match uv.resolve(&body.item) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let target = body.to.unwrap_or_else(|| {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());
        PathBuf::from(home)
            .join(".ssh")
            .join(format!("glyx_{}", item.name))
    });
    let conn = match glyx_agent::ledger::open_db() {
        Ok(conn) => conn,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    if let Err(e) = glyx_agent::ledger::register_export(
        &conn,
        &glyx_agent::ledger::ExportSpec {
            target: &target,
            kind: "ssh",
            item_id: Some(item.id),
            field: None,
            blob_addr: None,
            keep_on_lock: false,
            perm: body.perm.unwrap_or(0o600),
        },
    ) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    if let Err(e) = glyx_agent::engine::materialize_all(uv, false) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    Json(serde_json::json!({"ok": true, "target": target})).into_response()
}

#[derive(Deserialize)]
struct VaultSelectBody {
    path: PathBuf,
}

#[derive(Deserialize)]
struct ForgetQuery {
    path: PathBuf,
}

#[derive(Deserialize)]
struct SettingsBody {
    daemon_on_exit: Option<String>,
    mode: Option<String>,
    session_ttl_min: Option<u64>,
    auto_materialize: Option<bool>,
    idle_lock_min: Option<u64>,
}

fn vault_json(
    entry: &glyx_store::config::VaultEntry,
    current: Option<&std::path::Path>,
) -> serde_json::Value {
    let opened = glyx_store::Vault::open(&entry.path);
    let (valid, vault_id, keyfile_required, error) = match opened {
        Ok(v) => (
            true,
            Some(v.config().vault_id),
            Some(v.keyfile_required()),
            None,
        ),
        Err(e) => (false, entry.vault_id, None, Some(e.to_string())),
    };
    let is_current = current.is_some_and(|c| {
        glyx_store::config::normalize(c) == glyx_store::config::normalize(&entry.path)
    });
    serde_json::json!({
        "path": entry.path,
        "name": entry.name,
        "label": entry.label(),
        "vault_id": vault_id,
        "keyfile_required": keyfile_required,
        "keyfile": entry.keyfile,
        "last_used_ms": entry.last_used_ms,
        "valid": valid,
        "error": error,
        "current": is_current,
    })
}

async fn list_vaults(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = glyx_store::config::load();
    let current = cfg.current_vault.clone();
    let vaults: Vec<_> = cfg
        .vaults
        .iter()
        .map(|e| vault_json(e, current.as_deref()))
        .collect();
    Json(serde_json::json!({"current": current, "vaults": vaults}))
}

async fn add_vault(
    State(_state): State<Arc<AppState>>,
    Json(body): Json<VaultAddBody>,
) -> impl IntoResponse {
    let vault = match glyx_store::Vault::open(&body.path) {
        Ok(v) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    let mut cfg = glyx_store::config::load();
    cfg.register(glyx_store::config::VaultEntry {
        path: body.path.clone(),
        name: body.name,
        vault_id: Some(vault.config().vault_id),
        keyfile: body.keyfile.map(PathBuf::from),
        last_used_ms: 0,
    });
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    Json(serde_json::json!({"ok": true, "vault_id": vault.config().vault_id})).into_response()
}

async fn create_vault(
    State(state): State<Arc<AppState>>,
    Json(body): Json<VaultCreateBody>,
) -> impl IntoResponse {
    let suite = glyx_core::CipherSuiteConfig {
        kdf: glyx_core::KdfId::Argon2id,
        cipher: cipher_of(body.cipher.as_deref()),
        params: preset_params(body.preset.as_deref()),
    };
    let kf = match body.keyfile.as_deref() {
        Some(p) => match glyx_store::keyfile::load_or_create(std::path::Path::new(p)) {
            Ok(k) => Some(k),
            Err(e) => return store_error(&e).into_response(),
        },
        None => None,
    };
    let path = body.path.clone();
    let password = body.password.clone();
    let created = tokio::task::spawn_blocking(move || {
        glyx_store::Vault::init(&path, suite, password.as_bytes(), kf.as_ref())
    })
    .await;
    let vault = match created {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => return store_error(&e).into_response(),
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response()
        }
    };
    let mut cfg = glyx_store::config::load();
    cfg.register(glyx_store::config::VaultEntry {
        path: body.path.clone(),
        name: body.name,
        vault_id: Some(vault.config().vault_id),
        keyfile: body.keyfile.map(PathBuf::from),
        last_used_ms: 0,
    });
    cfg.select(&body.path);
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    do_lock(&state);
    *state
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(body.path.clone());
    state.publish_record();
    Json(serde_json::json!({
        "ok": true,
        "vault_id": vault.config().vault_id,
        "keyfile_required": vault.keyfile_required(),
    }))
    .into_response()
}

async fn select_vault(
    State(state): State<Arc<AppState>>,
    Json(body): Json<VaultSelectBody>,
) -> impl IntoResponse {
    if let Err(e) = glyx_store::Vault::open(&body.path) {
        return store_error(&e).into_response();
    }
    let mut cfg = glyx_store::config::load();
    cfg.select(&body.path);
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    do_lock(&state);
    *state
        .active
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(body.path.clone());
    state.publish_record();
    Json(serde_json::json!({"ok": true, "path": body.path})).into_response()
}

async fn forget_vault(
    State(state): State<Arc<AppState>>,
    Query(q): Query<ForgetQuery>,
) -> impl IntoResponse {
    let mut cfg = glyx_store::config::load();
    let was_current = cfg.current_vault.as_deref().is_some_and(|p| {
        glyx_store::config::normalize(p) == glyx_store::config::normalize(&q.path)
    });
    cfg.remove(&q.path);
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    if was_current {
        do_lock(&state);
        *state
            .active
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        state.publish_record();
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

async fn get_settings(State(_state): State<Arc<AppState>>) -> impl IntoResponse {
    let cfg = glyx_store::config::load();
    Json(serde_json::json!({
        "daemon_on_exit": cfg.daemon_on_exit,
        "mode": cfg.mode,
        "session_ttl_min": cfg.session_ttl_min,
        "auto_materialize": cfg.auto_materialize,
        "idle_lock_min": cfg.idle_lock_min,
    }))
}

async fn set_settings(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SettingsBody>,
) -> impl IntoResponse {
    let mut cfg = glyx_store::config::load();
    if let Some(v) = body.daemon_on_exit.as_deref() {
        cfg.daemon_on_exit = match v {
            "keep" => glyx_store::config::DaemonExit::Keep,
            _ => glyx_store::config::DaemonExit::Stop,
        };
    }
    if let Some(v) = body.mode.as_deref() {
        cfg.mode = match v {
            "session" => glyx_store::config::SessionMode::Session,
            _ => glyx_store::config::SessionMode::Oneshot,
        };
    }
    if let Some(ttl) = body.session_ttl_min {
        cfg.session_ttl_min = ttl;
    }
    if let Some(auto) = body.auto_materialize {
        cfg.auto_materialize = auto;
    }
    if let Some(min) = body.idle_lock_min {
        cfg.idle_lock_min = Some(min);
        state.idle_lock_ms.store(
            min.saturating_mul(60_000),
            std::sync::atomic::Ordering::Relaxed,
        );
    }
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    Json(serde_json::json!({
        "ok": true,
        "daemon_on_exit": cfg.daemon_on_exit,
        "mode": cfg.mode,
        "session_ttl_min": cfg.session_ttl_min,
        "auto_materialize": cfg.auto_materialize,
        "idle_lock_min": cfg.idle_lock_min,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct FillBody {
    field: Option<String>,
    timeout: Option<u64>,
}

async fn fill_item(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<FillBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let item = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let field = body.field.unwrap_or_else(|| "password".to_owned());
    let Some(field_value) = item.fields.get(&field) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": format!("no field {field}")})),
        )
            .into_response();
    };
    let value = field_value.value.expose().to_owned();
    let timeout = body.timeout.unwrap_or(15);
    audit(
        uv,
        "field_copy",
        Some(item.id),
        Some(&field),
        "success",
        None,
    );
    drop(guard);
    if glyx_autofill::clipboard::copy(&value).is_err() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "clipboard unavailable"})),
        )
            .into_response();
    }
    if timeout > 0 {
        let expected = value;
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(timeout));
            let _ = glyx_autofill::clipboard::clear_if_ours(&expected);
        });
    }
    Json(serde_json::json!({"ok": true, "field": field, "timeout_s": timeout})).into_response()
}

#[derive(Deserialize)]
struct RekeyBody {
    password: Option<String>,
    keyfile: Option<String>,
    no_keyfile: Option<bool>,
    cipher: Option<String>,
    preset: Option<String>,
    keep_old_slots: Option<bool>,
}

async fn rekey_vault(
    State(state): State<Arc<AppState>>,
    Json(body): Json<RekeyBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let no_keyfile = body.no_keyfile == Some(true);
    let rotate = body.password.is_some() || body.keyfile.is_some() || no_keyfile;
    if !rotate && body.cipher.is_none() && body.preset.is_none() {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "nothing to rotate"})),
        )
            .into_response();
    }
    let old_slots: Vec<uuid::Uuid> = uv
        .list_slots()
        .map(|s| s.into_iter().map(|(id, _)| id).collect())
        .unwrap_or_default();
    let params = match body.preset.as_deref() {
        Some(p) => preset_params(Some(p)),
        None => uv.config().cipher_suite.params,
    };
    if rotate {
        let Some(new_pw) = body.password.clone().filter(|p| !p.is_empty()) else {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "password required to rotate credentials"})),
            )
                .into_response();
        };
        let (new_kf, required) = if no_keyfile {
            (glyx_crypto::ZERO_KEYFILE, false)
        } else if let Some(path) = body.keyfile.as_deref() {
            match glyx_store::keyfile::load_or_create(std::path::Path::new(path)) {
                Ok(kf) => (kf, true),
                Err(e) => return store_error(&e).into_response(),
            }
        } else if uv.config().keyfile_required {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": "this vault needs a keyfile path"})),
            )
                .into_response();
        } else {
            (glyx_crypto::ZERO_KEYFILE, false)
        };
        let id = match uv.add_slot_with_params(new_pw.as_bytes(), &new_kf, params) {
            Ok(id) => id,
            Err(e) => return store_error(&e).into_response(),
        };
        if let Ok(vault) = glyx_store::Vault::open(&uv.vault_path()) {
            if !vault
                .verify_slot(&id, new_pw.as_bytes(), &new_kf)
                .unwrap_or(false)
            {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(serde_json::json!({"error": "new keyslot failed verification"})),
                )
                    .into_response();
            }
        }
        if let Err(e) = uv.set_keyfile_required(required) {
            return store_error(&e).into_response();
        }
    }
    if let Some(cipher) = body.cipher.as_deref() {
        if let Err(e) = uv.reencrypt(cipher_of(Some(cipher))) {
            return store_error(&e).into_response();
        }
    }
    if rotate && body.keep_old_slots != Some(true) {
        for id in &old_slots {
            if uv
                .list_slots()
                .is_ok_and(|s| s.iter().any(|(x, _)| x == id))
            {
                let _ = uv.retire_slot(id);
            }
        }
    }
    Json(serde_json::json!({"ok": true})).into_response()
}

pub async fn serve(
    config: DaemonConfig,
    token: String,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let state = Arc::new(AppState {
        active: Mutex::new(config.vault.clone()),
        vault: Mutex::new(None),
        token,
        port: Mutex::new(addr.port()),
        idle_lock_ms: std::sync::atomic::AtomicU64::new(config.idle_lock_ms),
        last_activity_ms: Mutex::new(now_ms()),
        agent_stop: Mutex::new(None),
        tamper: Mutex::new(Vec::new()),
    });
    state.publish_record();
    let app = router(state.clone());
    let idle = state.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let idle_for = now_ms().saturating_sub(
                *idle
                    .last_activity_ms
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            let idle_limit = idle.idle_lock_ms.load(std::sync::atomic::Ordering::Relaxed);
            if idle_limit > 0 && idle_for >= idle_limit {
                do_lock(&idle);
            }
        }
    });
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap_or_else(|e| {
            eprintln!("daemon serve error: {e}");
        });
    });
    Ok((addr, handle))
}

#[derive(Debug)]
pub struct DaemonConfig {
    pub vault: Option<PathBuf>,
    pub idle_lock_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    fn ensure_runtime_dir() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let dir =
                std::env::temp_dir().join(format!("glyx-daemon-tests-{}", std::process::id()));
            std::fs::create_dir_all(&dir).ok();
            std::env::set_var("GLYX_RUNTIME_DIR", dir);
        });
    }

    fn state_for(path: std::path::PathBuf) -> Arc<AppState> {
        Arc::new(AppState {
            active: Mutex::new(Some(path)),
            vault: Mutex::new(None),
            token: "test-token".to_owned(),
            port: Mutex::new(0),
            idle_lock_ms: std::sync::atomic::AtomicU64::new(0),
            last_activity_ms: Mutex::new(now_ms()),
            agent_stop: Mutex::new(None),
            tamper: Mutex::new(Vec::new()),
        })
    }

    fn test_state() -> (tempfile::TempDir, Arc<AppState>) {
        ensure_runtime_dir();
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        glyx_store::Vault::init(&path, suite, b"pw", Some(&[1u8; 32])).expect("init");
        (dir, state_for(path))
    }

    async fn call(
        state: Arc<AppState>,
        method: &str,
        uri: &str,
        body: Option<serde_json::Value>,
        token: &str,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let app = router(state);
        let req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"));
        let req = if let Some(body) = body {
            req.header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).expect("json")))
        } else {
            req.body(Body::empty())
        }
        .expect("request");
        let res = app.oneshot(req).await.expect("oneshot");
        let status = res.status();
        let bytes = axum::body::to_bytes(res.into_body(), 1024 * 1024)
            .await
            .expect("bytes");
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    async fn call_raw(
        state: Arc<AppState>,
        method: &str,
        uri: &str,
        body: Body,
        content_type: Option<&str>,
        token: &str,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let app = router(state);
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {token}"));
        if let Some(content_type) = content_type {
            req = req.header("content-type", content_type);
        }
        let req = req.body(body).expect("request");
        let res = app.oneshot(req).await.expect("oneshot");
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = axum::body::to_bytes(res.into_body(), 32 * 1024 * 1024)
            .await
            .expect("bytes")
            .to_vec();
        (status, headers, bytes)
    }

    #[tokio::test]
    async fn blob_routes_attach_download_and_gc() {
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, bytes) = call_raw(
            state.clone(),
            "POST",
            "/v1/blobs",
            Body::from("payload"),
            Some("application/octet-stream"),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let addr = json["addr"].as_str().expect("addr").to_owned();
        let (status, headers, body) = call_raw(
            state.clone(),
            "GET",
            &format!("/v1/blobs/{addr}"),
            Body::empty(),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"payload");
        assert_eq!(
            headers
                .get("x-content-type-options")
                .and_then(|v| v.to_str().ok()),
            Some("nosniff")
        );
        assert!(headers
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("attachment")));
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "file", "name": "doc", "fields": {"blob": addr, "filename": "doc.bin"}
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _, bytes) = call_raw(
            state.clone(),
            "POST",
            "/v1/blobs",
            Body::from("orphan"),
            Some("application/octet-stream"),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let json: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        let orphan = json["addr"].as_str().expect("addr").to_owned();
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/blobs/gc",
            Some(serde_json::json!({"dry_run": false})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["purged"], 1);
        let (status, _, _) = call_raw(
            state.clone(),
            "GET",
            &format!("/v1/blobs/{orphan}"),
            Body::empty(),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn backup_download_and_restore_roundtrip() {
        let cfg = tempfile::tempdir().expect("config dir");
        std::env::set_var("GLYX_CONFIG", cfg.path().join("config.toml"));
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "login", "name": "web",
                "fields": {"username": "u", "password": "p"},
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(state.clone(), "POST", "/v1/lock", None, "test-token").await;
        assert_eq!(status, StatusCode::OK);
        let (status, headers, archive) = call_raw(
            state.clone(),
            "GET",
            "/v1/vaults/backup",
            Body::empty(),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("content-type").and_then(|v| v.to_str().ok()),
            Some("application/gzip")
        );
        assert_eq!(&archive[..2], &[0x1f, 0x8b]);
        let dest = cfg.path().join("restored.glyx");
        let (status, _, body) = call_raw(
            state,
            "POST",
            &format!("/v1/vaults/restore?dest={}", dest.display()),
            Body::from(archive),
            Some("application/gzip"),
            "test-token",
        )
        .await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        assert_eq!(status, StatusCode::OK, "{json}");
        let vault = glyx_store::Vault::open(&dest).expect("restored vault");
        let uv = vault.unlock(b"pw", &[1u8; 32]).expect("unlock");
        assert_eq!(uv.list(false).expect("list").len(), 1);
    }

    #[tokio::test]
    async fn auth_rejects_bad_token() {
        let (_d, state) = test_state();
        let (status, _) = call(state, "GET", "/v1/health", None, "wrong").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn full_crud_cycle() {
        let (_d, state) = test_state();
        let (status, _) = call(state.clone(), "GET", "/v1/status", None, "test-token").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(state.clone(), "GET", "/v1/items", None, "test-token").await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": ""})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "login", "name": "web",
                "fields": {"username": "u", "password": "p"},
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let id = body["id"].as_str().expect("id").to_owned();
        let (status, body) = call(state.clone(), "GET", "/v1/items", None, "test-token").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().expect("array").len(), 1);
        let (status, _) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{id}"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            state.clone(),
            "PATCH",
            &format!("/v1/items/{id}"),
            Some(serde_json::json!({"fields": {"username": "v"}})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            state.clone(),
            "DELETE",
            &format!("/v1/items/{id}"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(state.clone(), "POST", "/v1/lock", None, "test-token").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(state.clone(), "GET", "/v1/items", None, "test-token").await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn history_restore_and_settings() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_CONFIG", dir.path().join("config.toml"));
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({
                "password": "pw", "keyfile": kf_path, "ttl_min": 5,
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "login", "name": "web",
                "fields": {"username": "u", "password": "p"},
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let id = body["id"].as_str().expect("id").to_owned();
        let (status, _) = call(
            state.clone(),
            "PATCH",
            &format!("/v1/items/{id}"),
            Some(serde_json::json!({"rename": "renamed"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{id}/history"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let entries = body["items"].as_array().expect("history");
        assert_eq!(entries.len(), 1);
        let file = entries[0]["file"].as_str().expect("file").to_owned();
        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{id}/history/{file}"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["item"]["name"], serde_json::json!("web"));
        let (status, body) = call(
            state.clone(),
            "POST",
            &format!("/v1/items/{id}/history/{file}"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{id}"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["name"], serde_json::json!("web"));

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/settings",
            Some(serde_json::json!({"idle_lock_min": 5})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["idle_lock_min"], serde_json::json!(5));
        assert_eq!(
            state
                .idle_lock_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            300_000
        );
    }

    #[tokio::test]
    async fn ssh_export_endpoint_writes_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_CONFIG", dir.path().join("config.toml"));
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh-gen",
            Some(serde_json::json!({"name": "key"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let target = dir.path().join("id_ed25519");
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh/export",
            Some(serde_json::json!({"item": "key", "to": target, "perm": 384})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(target.exists());
    }

    fn test_kf() -> String {
        let path = std::env::temp_dir().join(format!("glyx-test-kf-{}", std::process::id()));
        if !path.exists() {
            std::fs::write(&path, [1u8; 32]).expect("kf");
        }
        path.to_string_lossy().into_owned()
    }

    #[tokio::test]
    async fn sync_gc_doctor_paths() {
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/sync",
            Some(serde_json::json!({})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, _) = call(state.clone(), "GET", "/v1/conflicts", None, "test-token").await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/gc",
            Some(serde_json::json!({"dry_run": true})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(state.clone(), "GET", "/v1/doctor", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn unlock_seals_pin_session() {
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({
                "password": "pw", "keyfile": kf_path, "new_pin": "9876",
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let path = state.active_path().expect("active");
        *state
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;

        let fresh = state_for(path);
        let (status, body) = call(
            fresh,
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"pin": "9876"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn unlock_rejects_short_new_pin() {
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state,
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({
                "password": "pw", "keyfile": kf_path, "new_pin": "12",
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn doctor_rebuild_requires_lock() {
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = call(
            state.clone(),
            "GET",
            "/v1/doctor?rebuild_index=true",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = call(state.clone(), "POST", "/v1/lock", None, "test-token").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            state.clone(),
            "GET",
            "/v1/doctor?rebuild_index=true&with_unlock=true",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("rebuilt_index").is_some(), "{body}");
        assert_eq!(body["with_unlock"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn vault_management_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_CONFIG", dir.path().join("config.toml"));
        let (_d, state) = test_state();

        let (status, body) = call(state.clone(), "GET", "/v1/vaults", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["vaults"].as_array().expect("vaults").len(), 0);

        let new_path = dir.path().join("second.glyx");
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/vaults/create",
            Some(serde_json::json!({"path": new_path, "password": "pw", "preset": "mobile"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["keyfile_required"], serde_json::json!(false));

        let (status, body) = call(state.clone(), "GET", "/v1/vaults", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let list = body["vaults"].as_array().expect("vaults");
        assert_eq!(list.len(), 1);
        assert_eq!(list[0]["current"], serde_json::json!(true));
        assert_eq!(list[0]["valid"], serde_json::json!(true));

        let (status, body) = call(state.clone(), "GET", "/v1/status", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["vault"]["keyfile_required"], serde_json::json!(false));

        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/vaults/select",
            Some(serde_json::json!({"path": new_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, _) = call(
            state.clone(),
            "DELETE",
            &format!("/v1/vaults?path={}", new_path.display()),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(new_path.exists());
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn library_pagination_bulk_duplicates_and_recents() {
        let (dir, state) = test_state();
        std::env::set_var("GLYX_CONFIG", dir.path().join("config.toml"));
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let mut ids = Vec::new();
        for (name, username, password) in [
            ("Alpha", "alice", "same"),
            (" alpha ", "alice", "same"),
            ("Beta", "bob", "other"),
        ] {
            let (status, body) = call(
                state.clone(),
                "POST",
                "/v1/items",
                Some(serde_json::json!({
                    "type": "login",
                    "name": name,
                    "folder": "Work",
                    "tags": ["old"],
                    "fields": {
                        "url": "https://example.com",
                        "username": username,
                        "password": password
                    }
                })),
                "test-token",
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            ids.push(body["id"].as_str().expect("id").to_owned());
        }

        let (status, body) = call(
            state.clone(),
            "PATCH",
            &format!("/v1/items/{}?reveal=true", ids[0]),
            Some(serde_json::json!({"favorite": true})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, headers, bytes) = call_raw(
            state.clone(),
            "GET",
            "/v1/items?sort=name&limit=2&offset=0",
            Body::empty(),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers.get("x-total-count").and_then(|v| v.to_str().ok()),
            Some("3")
        );
        let page: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
        assert_eq!(page.as_array().expect("array").len(), 2);

        let (status, body) = call(
            state.clone(),
            "GET",
            "/v1/items?favorite=true",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().expect("array").len(), 1);
        assert_eq!(body[0]["favorite"], serde_json::json!(true));

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/items/bulk",
            Some(serde_json::json!({
                "ids": [ids[0], ids[1]],
                "action": "add_tags",
                "tags": ["new"]
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["affected"], serde_json::json!(2));

        let (status, body) = call(state.clone(), "GET", "/v1/library", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["tags"]["new"], serde_json::json!(2));
        assert_eq!(body["folders"]["Work"], serde_json::json!(3));

        let (status, body) = call(
            state.clone(),
            "GET",
            "/v1/items/duplicates",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let groups = body["groups"].as_array().expect("groups");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0]["same_password"], serde_json::json!(true));

        let (status, _) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{}?reveal=true", ids[0]),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(state.clone(), "GET", "/v1/recents", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body[0]["id"], serde_json::json!(ids[0]));

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/library/tags/delete",
            Some(serde_json::json!({"name": "new"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["affected"], serde_json::json!(2));

        let (status, body) = call(
            state.clone(),
            "GET",
            "/v1/health/report",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["summary"]["weak"].as_u64().is_some(), "{body}");

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/generate",
            Some(serde_json::json!({
                "length": 20, "lowercase": true, "uppercase": true,
                "digits": true, "symbols": true, "exclude_ambiguous": true
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["password"].as_str().map(str::len), Some(20));

        let (status, body) = call(state.clone(), "GET", "/v1/devices", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let device = body["devices"][0]["id"]
            .as_str()
            .expect("device")
            .to_owned();
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/devices/label",
            Some(serde_json::json!({"id": device, "label": "Laptop"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            state.clone(),
            "GET",
            "/v1/audit?event=item_reveal",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["events"]
            .as_array()
            .is_some_and(|events| !events.is_empty()));
    }
}
