use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{delete, get, patch, post};
use axum::{middleware, Router};
use futures_util::StreamExt as _;
use serde::Deserialize;
use tokio::io::AsyncWriteExt as _;
use tokio_util::io::ReaderStream;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::passkey;

#[derive(Debug)]
pub struct AppState {
    pub active: Mutex<Option<PathBuf>>,
    pub vault: Mutex<Option<glyx_store::UnlockedVault>>,
    pub token: String,
    pub port: Mutex<u16>,
    pub idle_lock_ms: std::sync::atomic::AtomicU64,
    pub last_activity_ms: Mutex<u64>,
    pub ssh_agent: Mutex<Option<Arc<glyx_agent::ssh_agent::AgentState>>>,
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

fn cors_layer() -> CorsLayer {
    let origins = [
        "tauri://localhost",
        "http://tauri.localhost",
        "https://tauri.localhost",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]
    .into_iter()
    .filter_map(|origin| origin.parse::<HeaderValue>().ok())
    .collect::<Vec<_>>();
    CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(move |origin, _| {
            origins.iter().any(|allowed| allowed == origin)
                || origin.to_str().is_ok_and(is_loopback_origin)
        }))
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([AUTHORIZATION, CONTENT_TYPE])
        .expose_headers([
            HeaderName::from_static("x-total-count"),
            CONTENT_DISPOSITION,
        ])
        .max_age(std::time::Duration::from_secs(600))
}

fn is_loopback_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split('/').next().unwrap_or(rest);
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
        || host.starts_with("localhost:")
        || host.starts_with("127.0.0.1:")
        || host.starts_with("[::1]:")
}

#[allow(clippy::too_many_lines)]
pub fn router(state: Arc<AppState>) -> Router {
    let api = Router::new()
        .route("/v1/health", get(health))
        .route("/v1/health/report", get(health_report))
        .route("/v1/devices", get(devices))
        .route("/v1/devices/label", post(set_device_label))
        .route("/v1/audit", get(audit_log))
        .route("/v1/generate", post(generate_password))
        .route("/v1/templates", get(list_templates))
        .route("/v1/passkeys", get(list_passkeys))
        .route("/v1/passkeys/lookup", post(passkey_lookup))
        .route("/v1/passkeys/create", post(passkey_create))
        .route("/v1/passkeys/get", post(passkey_get))
        .route("/v1/logins/match", post(match_login))
        .route("/v1/logins/list", post(list_logins))
        .route("/v1/status", get(status))
        .route(
            "/v1/vaults",
            get(list_vaults).post(add_vault).delete(forget_vault),
        )
        .route("/v1/vaults/create", post(create_vault))
        .route("/v1/vaults/slots", post(add_biometric_slot))
        .route("/v1/vaults/slots/:id", delete(retire_biometric_slot))
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
        .route("/v1/items/:id/related", get(item_related))
        .route("/v1/items/:id/link", post(item_link))
        .route("/v1/items/:id/unlink", post(item_unlink))
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
        .route("/v1/ssh", get(ssh_keys))
        .route("/v1/ssh/keys/:id", patch(ssh_toggle))
        .route("/v1/ssh/agent/start", post(ssh_agent_start))
        .route("/v1/ssh/agent/stop", post(ssh_agent_stop))
        .route("/v1/ssh/agent/reload", post(ssh_agent_reload))
        .route("/v1/ssh/import", post(ssh_import))
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
            get(list_exports)
                .post(add_export)
                .delete(recall_export)
                .patch(update_export),
        )
        .route("/v1/exports/enforce", post(enforce_exports))
        .route(
            "/v1/injects",
            get(list_exports).post(add_inject).patch(set_inject_policy),
        )
        .route("/v1/injects/content", get(inject_content).put(inject_save))
        .route("/v1/injects/preview", get(inject_preview))
        .route("/v1/injects/scan", post(scan_injects))
        .route("/v1/pick/file", post(pick_file_dialog))
        .route("/v1/pick/folder", post(pick_folder_dialog))
        .route("/v1/pick/save", post(pick_save_dialog))
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
        .layer(middleware::from_fn_with_state(state.clone(), require_auth));
    Router::new()
        .route("/", get(ui_index))
        .fallback(ui_fallback)
        .merge(api)
        .with_state(state)
        .layer(cors_layer())
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

#[allow(clippy::needless_pass_by_value)]
fn passkey_error(e: passkey::PasskeyError) -> Response {
    let status = match &e {
        passkey::PasskeyError::BadRequest(_) | passkey::PasskeyError::NotSupported(_) => {
            StatusCode::UNPROCESSABLE_ENTITY
        }
        passkey::PasskeyError::InvalidState(_) => StatusCode::CONFLICT,
        passkey::PasskeyError::NotAllowed(_) | passkey::PasskeyError::Security(_) => {
            StatusCode::FORBIDDEN
        }
    };
    (
        status,
        Json(serde_json::json!({"error": e.to_string(), "name": e.name()})),
    )
        .into_response()
}

fn passkey_locked() -> Response {
    (
        StatusCode::CONFLICT,
        Json(serde_json::json!({"error": "vault locked", "name": "NotAllowedError"})),
    )
        .into_response()
}

async fn list_passkeys(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return passkey_locked();
    };
    let rows = match uv.list(false) {
        Ok(rows) => rows,
        Err(e) => return store_error(&e).into_response(),
    };
    let mut out = Vec::new();
    for row in rows {
        match uv.get_item(&row.id) {
            Ok(Some(item)) => {
                if let Some(meta) = passkey::metadata(&item) {
                    out.push(meta);
                }
            }
            Ok(None) => {}
            Err(e) => return store_error(&e).into_response(),
        }
    }
    out.sort_by(|a, b| a.rp_name.cmp(&b.rp_name).then_with(|| a.name.cmp(&b.name)));
    Json(out).into_response()
}

#[derive(Deserialize)]
struct PasskeyLookupBody {
    origin: String,
    rp_id: String,
    #[serde(default)]
    allow_credentials: Vec<String>,
}

async fn passkey_lookup(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasskeyLookupBody>,
) -> impl IntoResponse {
    if let Err(e) = passkey::validate_origin_rp(&body.origin, &body.rp_id) {
        return passkey_error(e);
    }
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return passkey_locked();
    };
    let rows = match uv.list(false) {
        Ok(rows) => rows,
        Err(e) => return store_error(&e).into_response(),
    };
    let mut items = Vec::new();
    for row in rows {
        match uv.get_item(&row.id) {
            Ok(Some(item)) => items.push(item),
            Ok(None) => {}
            Err(e) => return store_error(&e).into_response(),
        }
    }
    let found = passkey::lookup(&items, &body.rp_id, &body.allow_credentials);
    Json(found).into_response()
}

#[derive(Deserialize)]
struct PasskeyCreateBody {
    origin: String,
    request: serde_json::Value,
    #[serde(default)]
    user_verified: bool,
}

async fn passkey_create(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasskeyCreateBody>,
) -> impl IntoResponse {
    let options = match passkey::parse_creation(&body.request, &body.origin) {
        Ok(options) => options,
        Err(e) => return passkey_error(e),
    };
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return passkey_locked();
    };
    let rows = match uv.list(false) {
        Ok(rows) => rows,
        Err(e) => return store_error(&e).into_response(),
    };
    for row in rows {
        match uv.get_item(&row.id) {
            Ok(Some(item)) => {
                if let Some(meta) = passkey::metadata(&item) {
                    if meta.rp_id == options.rp_id
                        && options
                            .exclude_credentials
                            .iter()
                            .any(|id| passkey::credential_id_eq(id, &meta.credential_id))
                    {
                        return passkey_error(passkey::PasskeyError::InvalidState(
                            "a matching passkey already exists".into(),
                        ));
                    }
                }
            }
            Ok(None) => {}
            Err(e) => return store_error(&e).into_response(),
        }
    }
    let created = match passkey::create_credential(&options, body.user_verified) {
        Ok(created) => created,
        Err(e) => return passkey_error(e),
    };
    let now = now_ms();
    let name = if created.user_name.is_empty() {
        created.rp_name.clone()
    } else {
        format!("{} ({})", created.rp_name, created.user_name)
    };
    let mut values = BTreeMap::from([
        ("relying_party".to_owned(), created.rp_id.clone()),
        ("rp_name".to_owned(), created.rp_name.clone()),
        ("user_handle".to_owned(), created.user_handle.clone()),
        ("user_name".to_owned(), created.user_name.clone()),
        ("display_name".to_owned(), created.display_name.clone()),
        ("credential_id".to_owned(), created.credential_id.clone()),
        ("private_key".to_owned(), created.private_key.clone()),
        ("algorithm".to_owned(), "ES256".to_owned()),
        ("sign_count".to_owned(), "0".to_owned()),
        ("discoverable".to_owned(), created.discoverable.to_string()),
        ("backup_eligible".to_owned(), "true".to_owned()),
        ("backup_state".to_owned(), "true".to_owned()),
        ("aaguid".to_owned(), created.aaguid.clone()),
        ("created_ms".to_owned(), now.to_string()),
        ("last_used_ms".to_owned(), now.to_string()),
        ("transports".to_owned(), "internal".to_owned()),
    ]);
    if let Some(login) = unique_login_for(uv, &created.rp_id, &created.user_name) {
        values.insert("login_id".to_owned(), login);
    }
    let item = match glyx_store::present::build_new(
        uv,
        glyx_core::ItemType::Passkey,
        name,
        String::new(),
        Vec::new(),
        values,
    ) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let id = item.id;
    if let Err(e) = uv.put_item(&item) {
        return store_error(&e).into_response();
    }
    audit(
        uv,
        "passkey_create",
        Some(id),
        None,
        "success",
        Some(&created.rp_id),
    );
    Json(serde_json::json!({
        "item_id": id,
        "name": item.name,
        "rp_id": created.rp_id,
        "response": created.response,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct PasskeyGetBody {
    origin: String,
    request: serde_json::Value,
    item_id: Option<String>,
    #[serde(default)]
    user_verified: bool,
}

#[allow(clippy::too_many_lines)]
async fn passkey_get(
    State(state): State<Arc<AppState>>,
    Json(body): Json<PasskeyGetBody>,
) -> impl IntoResponse {
    let options = match passkey::parse_assertion(&body.request, &body.origin) {
        Ok(options) => options,
        Err(e) => return passkey_error(e),
    };
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return passkey_locked();
    };
    let mut item = if let Some(id) = body.item_id.as_deref() {
        match uv.resolve(id) {
            Ok(item) => item,
            Err(_) => {
                return passkey_error(passkey::PasskeyError::NotAllowed(
                    "passkey not found".into(),
                ));
            }
        }
    } else {
        let rows = match uv.list(false) {
            Ok(rows) => rows,
            Err(e) => return store_error(&e).into_response(),
        };
        let mut found = Vec::new();
        for row in rows {
            match uv.get_item(&row.id) {
                Ok(Some(candidate)) => {
                    if let Some(meta) = passkey::metadata(&candidate) {
                        let allowed = if options.allow_credentials.is_empty() {
                            meta.discoverable
                        } else {
                            options
                                .allow_credentials
                                .iter()
                                .any(|id| passkey::credential_id_eq(id, &meta.credential_id))
                        };
                        if meta.rp_id == options.rp_id && allowed {
                            found.push(candidate);
                        }
                    }
                }
                Ok(None) => {}
                Err(e) => return store_error(&e).into_response(),
            }
        }
        if found.len() != 1 {
            return passkey_error(passkey::PasskeyError::NotAllowed(if found.is_empty() {
                "no matching passkey".into()
            } else {
                "multiple passkeys match; select one".into()
            }));
        }
        found.remove(0)
    };
    let Some(meta) = passkey::metadata(&item) else {
        return passkey_error(passkey::PasskeyError::NotAllowed(
            "item is not a passkey".into(),
        ));
    };
    if meta.rp_id != options.rp_id {
        return passkey_error(passkey::PasskeyError::NotAllowed(
            "passkey relying party does not match".into(),
        ));
    }
    if options.allow_credentials.is_empty() && !meta.discoverable {
        return passkey_error(passkey::PasskeyError::NotAllowed(
            "passkey is not discoverable".into(),
        ));
    }
    if !options.allow_credentials.is_empty()
        && !options
            .allow_credentials
            .iter()
            .any(|id| passkey::credential_id_eq(id, &meta.credential_id))
    {
        return passkey_error(passkey::PasskeyError::NotAllowed(
            "passkey is not in allowCredentials".into(),
        ));
    }
    let assertion = match passkey::assert_credential(&options, &item, body.user_verified) {
        Ok(assertion) => assertion,
        Err(e) => return passkey_error(e),
    };
    let now = now_ms();
    let mut values = BTreeMap::new();
    values.insert("last_used_ms".to_owned(), now.to_string());
    if let Err(e) = glyx_store::present::apply_fields(uv, &mut item, values) {
        return store_error(&e).into_response();
    }
    if let Err(e) = uv.put_item(&item) {
        return store_error(&e).into_response();
    }
    audit(
        uv,
        "passkey_get",
        Some(item.id),
        None,
        "success",
        Some(&assertion.rp_id),
    );
    Json(serde_json::json!({
        "item_id": item.id,
        "name": item.name,
        "rp_id": assertion.rp_id,
        "response": assertion.response,
    }))
    .into_response()
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
            if let Err(e) = start_ssh_agent(&state, &uv) {
                eprintln!("ssh agent start failed: {e}");
            }
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

fn stop_ssh_agent(state: &AppState) {
    if let Some(agent) = state
        .ssh_agent
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
    {
        agent.stop();
    }
}

fn start_ssh_agent(
    state: &AppState,
    uv: &glyx_store::UnlockedVault,
) -> Result<Arc<glyx_agent::ssh_agent::AgentState>, glyx_agent::ssh_agent::SshAgentError> {
    stop_ssh_agent(state);
    let identities = glyx_agent::ssh_agent::load_identities(uv)?;
    let agent = Arc::new(glyx_agent::ssh_agent::AgentState::new(identities));
    let sock = glyx_agent::ssh_agent::socket_path(&uv.config().vault_id);
    let run = agent.clone();
    std::thread::spawn(move || {
        glyx_agent::ssh_agent::serve_until_state(&sock, &run).ok();
    });
    *state
        .ssh_agent
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(agent.clone());
    Ok(agent)
}

fn reload_ssh_agent(
    state: &AppState,
    uv: &glyx_store::UnlockedVault,
) -> Result<Arc<glyx_agent::ssh_agent::AgentState>, glyx_agent::ssh_agent::SshAgentError> {
    let existing = state
        .ssh_agent
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    if let Some(agent) = existing {
        agent.replace(glyx_agent::ssh_agent::load_identities(uv)?);
        Ok(agent)
    } else {
        start_ssh_agent(state, uv)
    }
}

fn ssh_agent_status(state: &AppState, uv: &glyx_store::UnlockedVault) -> serde_json::Value {
    let socket = glyx_agent::ssh_agent::socket_path(&uv.config().vault_id);
    let handle = state
        .ssh_agent
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    let running = handle.as_ref().is_some_and(|agent| agent.running());
    serde_json::json!({
        "running": running,
        "socket": socket,
        "identities": handle.as_ref().map_or(0, |agent| agent.count()),
    })
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
    stop_ssh_agent(state);
    if let Some(mut uv) = taken {
        audit(&uv, "lock", None, None, "success", None);
        release_vault(&uv);
        if let Err(e) = uv.compact() {
            eprintln!("vault compaction failed: {e}");
        }
    }
}

fn do_shutdown(state: &AppState) {
    let taken = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    stop_ssh_agent(state);
    if let Some(mut uv) = taken {
        let lock_on_exit = glyx_store::config::load().lock_on_exit;
        if let Err(e) = glyx_agent::engine::teardown_for_exit(&uv, lock_on_exit) {
            eprintln!("exit teardown failed: {e}");
        }
        audit(&uv, "lock", None, None, "success", None);
        let vault_id = uv.config().vault_id;
        glyx_agent::ssh_agent::stop(&glyx_agent::ssh_agent::socket_path(&vault_id));
        glyx_store::session::wipe_ticket(&vault_id);
        if let Err(e) = uv.compact() {
            eprintln!("vault compaction failed: {e}");
        }
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
struct MatchLoginBody {
    #[serde(default)]
    origin: String,
    #[serde(default)]
    package: String,
    #[serde(default)]
    username: String,
}

#[derive(Deserialize)]
struct ListLoginsBody {
    #[serde(default)]
    origin: String,
    #[serde(default)]
    package: String,
    #[serde(default)]
    username: String,
    limit: Option<usize>,
}

#[derive(serde::Serialize)]
struct LoginMatch {
    id: String,
    name: String,
    username: String,
    password: String,
    url: String,
    package: String,
    has_totp: bool,
    totp_item_id: Option<String>,
}

fn registrable_host(host: &str) -> String {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost" || host.parse::<std::net::IpAddr>().is_ok() {
        return host;
    }
    psl::domain_str(&host).map_or_else(|| host.clone(), ToOwned::to_owned)
}

fn host_matches(item_host: &str, page_host: &str) -> bool {
    item_host == page_host || registrable_host(item_host) == registrable_host(page_host)
}

fn login_totp_item(
    uv: &glyx_store::UnlockedVault,
    item: &glyx_core::Item,
    rows: &[glyx_store::IndexRow],
) -> Option<String> {
    if item.fields.contains_key("seed") {
        return Some(item.id.to_string());
    }
    let login_id = item.id.to_string();
    for row in rows {
        if row.item_type != "totp" {
            continue;
        }
        let Ok(Some(candidate)) = uv.get_item(&row.id) else {
            continue;
        };
        if item_is_linked_to(&candidate, &login_id) {
            return Some(candidate.id.to_string());
        }
    }
    None
}

fn login_matches(
    uv: &glyx_store::UnlockedVault,
    rows: &[glyx_store::IndexRow],
    origin: &str,
    package: &str,
    username: &str,
    limit: usize,
) -> Vec<LoginMatch> {
    let page_host = url_host(origin);
    let package = package.trim();
    let username = username.trim();
    let mut out: Vec<(u8, LoginMatch)> = Vec::new();
    for row in rows {
        if row.item_type != "login" {
            continue;
        }
        let Ok(Some(item)) = uv.get_item(&row.id) else {
            continue;
        };
        let item_host = item
            .fields
            .get("url")
            .and_then(|field| url_host(field.value.expose()));
        let item_package = item
            .fields
            .get("package")
            .map_or("", |field| field.value.expose())
            .trim();
        let host_hit = page_host.as_ref().is_some_and(|page| {
            item_host
                .as_ref()
                .is_some_and(|host| host_matches(host, page))
        });
        let package_hit = !package.is_empty() && item_package == package;
        if !host_hit && !package_hit {
            continue;
        }
        let item_username = item
            .fields
            .get("username")
            .map_or("", |field| field.value.expose());
        if !username.is_empty() && !item_username.eq_ignore_ascii_case(username) {
            continue;
        }
        let rank = u8::from(
            page_host
                .as_ref()
                .zip(item_host.as_ref())
                .is_some_and(|(page, host)| page == host),
        ) | (u8::from(package_hit) << 1);
        let totp_item_id = login_totp_item(uv, &item, rows);
        out.push((
            rank,
            LoginMatch {
                id: item.id.to_string(),
                name: item.name.clone(),
                username: item_username.to_owned(),
                password: item
                    .fields
                    .get("password")
                    .map_or("", |field| field.value.expose())
                    .to_owned(),
                url: item
                    .fields
                    .get("url")
                    .map_or("", |field| field.value.expose())
                    .to_owned(),
                package: item_package.to_owned(),
                has_totp: totp_item_id.is_some(),
                totp_item_id,
            },
        ));
    }
    out.sort_by(|(left_rank, left), (right_rank, right)| {
        right_rank
            .cmp(left_rank)
            .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            .then_with(|| left.id.cmp(&right.id))
    });
    out.truncate(limit);
    out.into_iter().map(|(_, item)| item).collect()
}

async fn match_login(
    State(state): State<Arc<AppState>>,
    Json(body): Json<MatchLoginBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let rows = match uv.list(false) {
        Ok(rows) => rows,
        Err(e) => return store_error(&e).into_response(),
    };
    let matches = login_matches(uv, &rows, &body.origin, &body.package, &body.username, 1);
    match matches.into_iter().next() {
        Some(found) => Json(serde_json::json!({"match": found})).into_response(),
        None => Json(serde_json::json!({"match": null})).into_response(),
    }
}

async fn list_logins(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ListLoginsBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let rows = match uv.list(false) {
        Ok(rows) => rows,
        Err(e) => return store_error(&e).into_response(),
    };
    let limit = body.limit.unwrap_or(20).clamp(1, 50);
    let matches = login_matches(
        uv,
        &rows,
        &body.origin,
        &body.package,
        &body.username,
        limit,
    );
    Json(serde_json::json!({"matches": matches})).into_response()
}

fn url_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    (!host.is_empty()).then_some(host)
}

fn unique_login_for(uv: &glyx_store::UnlockedVault, rp_id: &str, account: &str) -> Option<String> {
    let rows = uv.list(false).ok()?;
    let mut found = None;
    for row in rows {
        let Ok(Some(item)) = uv.get_item(&row.id) else {
            continue;
        };
        if item.item_type != glyx_core::ItemType::Login {
            continue;
        }
        let username = item
            .fields
            .get("username")
            .map(|f| f.value.expose().trim().to_owned());
        if username.as_deref() != Some(account.trim()) {
            continue;
        }
        let host = item
            .fields
            .get("url")
            .and_then(|f| url_host(f.value.expose()));
        let Some(host) = host else {
            continue;
        };
        if host != rp_id && !host.ends_with(&format!(".{rp_id}")) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(item.id.to_string());
    }
    found
}

fn linked_login(item: &glyx_core::Item) -> Option<String> {
    item.fields
        .get("login_id")
        .map(|f| f.value.expose().trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn item_is_linked_to(item: &glyx_core::Item, login_id: &str) -> bool {
    let Some(linked) = linked_login(item) else {
        return false;
    };
    linked == login_id
        || uuid::Uuid::parse_str(&linked).is_ok_and(|parsed| parsed.to_string() == login_id)
}

async fn item_related(
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
    let login_id = item.id.to_string();
    let rows = match uv.list(false) {
        Ok(rows) => rows,
        Err(e) => return store_error(&e).into_response(),
    };
    let mut children = Vec::new();
    for row in rows {
        match uv.get_item(&row.id) {
            Ok(Some(other)) => {
                if other.id != item.id && item_is_linked_to(&other, &login_id) {
                    children.push(glyx_store::present::item_json(&other, false));
                }
            }
            Ok(None) => {}
            Err(e) => return store_error(&e).into_response(),
        }
    }
    let parent = linked_login(&item).and_then(|linked| {
        uv.resolve(&linked)
            .ok()
            .map(|login| glyx_store::present::item_json(&login, false))
    });
    let mut injected = Vec::new();
    let mut exported = Vec::new();
    if let Ok(conn) = glyx_agent::ledger::open_db() {
        if let Ok(injects) = glyx_agent::ledger::list_injects(&conn) {
            for row in injects {
                let refs: serde_json::Value =
                    serde_json::from_str(&row.refs_json).unwrap_or_else(|_| serde_json::json!([]));
                let hit = refs.as_array().is_some_and(|list| {
                    list.iter().any(|entry| {
                        entry
                            .get("item_id")
                            .and_then(|value| value.as_str())
                            .is_some_and(|value| value == login_id)
                    })
                });
                if hit {
                    injected.push(row.target.to_string_lossy().into_owned());
                }
            }
        }
        if let Ok(exports) = glyx_agent::ledger::list_exports(&conn) {
            for row in exports {
                if row
                    .item_id
                    .is_some_and(|value| value.to_string() == login_id)
                {
                    exported.push(row.target.to_string_lossy().into_owned());
                }
            }
        }
    }
    Json(serde_json::json!({
        "item": glyx_store::present::item_json(&item, false),
        "parent": parent,
        "children": children,
        "used_by": { "injects": injected, "exports": exported },
    }))
    .into_response()
}

#[derive(Deserialize)]
struct LinkBody {
    child: String,
}

async fn item_link(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<LinkBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let parent = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    if parent.item_type != glyx_core::ItemType::Login {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "only login items can own linked children"})),
        )
            .into_response();
    }
    let mut child = match uv.resolve(&body.child) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    if child.item_type != glyx_core::ItemType::Totp
        && child.item_type != glyx_core::ItemType::Passkey
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "only TOTP or passkey items can be linked"})),
        )
            .into_response();
    }
    let login_id = parent.id.to_string();
    let values = BTreeMap::from([("login_id".to_owned(), login_id)]);
    if let Err(e) = glyx_store::present::apply_fields(uv, &mut child, values) {
        return store_error(&e).into_response();
    }
    match uv.put_item(&child) {
        Ok(()) => {
            audit(uv, "item_link", Some(child.id), None, "success", None);
            Json(serde_json::json!({"ok": true, "child": child.id})).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn item_unlink(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<LinkBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let parent = match uv.resolve(&id) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let mut child = match uv.resolve(&body.child) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    if !item_is_linked_to(&child, &parent.id.to_string()) {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "item is not linked to this login"})),
        )
            .into_response();
    }
    child.fields.remove("login_id");
    if let Err(e) = glyx_store::present::apply_fields(uv, &mut child, BTreeMap::new()) {
        return store_error(&e).into_response();
    }
    match uv.put_item(&child) {
        Ok(()) => {
            audit(uv, "item_unlink", Some(child.id), None, "success", None);
            Json(serde_json::json!({"ok": true, "child": child.id})).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn ssh_keys(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let keys = match glyx_agent::ssh_agent::load_key_meta(uv) {
        Ok(keys) => keys,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let exports = glyx_agent::ledger::open_db()
        .ok()
        .and_then(|conn| glyx_agent::ledger::list_exports(&conn).ok())
        .unwrap_or_default();
    let keys = keys
        .into_iter()
        .map(|meta| {
            let targets = exports
                .iter()
                .filter(|row| row.kind == "ssh" && row.item_id.is_some_and(|id| id == meta.item_id))
                .map(|row| {
                    serde_json::json!({
                        "target": row.target,
                        "keep": row.keep_on_lock,
                        "perm": row.perm,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "id": meta.item_id,
                "name": meta.name,
                "algorithm": meta.algorithm,
                "fingerprint": meta.fingerprint,
                "public": meta.public,
                "comment": meta.comment,
                "agent_enabled": meta.agent_enabled,
                "agent_supported": meta.agent_supported,
                "exports": targets,
            })
        })
        .collect::<Vec<_>>();
    Json(serde_json::json!({
        "agent": ssh_agent_status(&state, uv),
        "keys": keys,
    }))
    .into_response()
}

#[derive(Deserialize)]
struct SshToggleBody {
    agent_enabled: bool,
}

async fn ssh_toggle(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<SshToggleBody>,
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
    if item.item_type != glyx_core::ItemType::SshKey {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "item is not an SSH key"})),
        )
            .into_response();
    }
    let Some(meta) = glyx_agent::ssh_agent::key_meta(&item) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "SSH key is unreadable"})),
        )
            .into_response();
    };
    if body.agent_enabled && !meta.agent_supported {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "the SSH agent supports Ed25519 keys only; RSA keys are export-only"
            })),
        )
            .into_response();
    }
    let values = BTreeMap::from([("agent_enabled".to_owned(), body.agent_enabled.to_string())]);
    if let Err(e) = glyx_store::present::apply_fields(uv, &mut item, values) {
        return store_error(&e).into_response();
    }
    if let Err(e) = uv.put_item(&item) {
        return store_error(&e).into_response();
    }
    if let Err(e) = reload_ssh_agent(&state, uv) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    audit(
        uv,
        if body.agent_enabled {
            "ssh_agent_add"
        } else {
            "ssh_agent_revoke"
        },
        Some(item.id),
        None,
        "success",
        None,
    );
    Json(serde_json::json!({
        "ok": true,
        "agent": ssh_agent_status(&state, uv),
        "key": glyx_agent::ssh_agent::key_meta(&item),
    }))
    .into_response()
}

async fn ssh_agent_start(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    if let Err(e) = start_ssh_agent(&state, uv) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    audit(uv, "ssh_agent_start", None, None, "success", None);
    Json(serde_json::json!({"ok": true, "agent": ssh_agent_status(&state, uv)})).into_response()
}

async fn ssh_agent_stop(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    stop_ssh_agent(&state);
    glyx_agent::ssh_agent::stop(&glyx_agent::ssh_agent::socket_path(&uv.config().vault_id));
    audit(uv, "ssh_agent_stop", None, None, "success", None);
    Json(serde_json::json!({"ok": true, "agent": ssh_agent_status(&state, uv)})).into_response()
}

async fn ssh_agent_reload(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    if let Err(e) = reload_ssh_agent(&state, uv) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    Json(serde_json::json!({"ok": true, "agent": ssh_agent_status(&state, uv)})).into_response()
}

#[derive(Deserialize)]
struct SshImportBody {
    private_key: String,
    passphrase: Option<String>,
    name: Option<String>,
    comment: Option<String>,
    folder: Option<String>,
    tags: Option<Vec<String>>,
    add_to_agent: Option<bool>,
}

async fn ssh_import(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SshImportBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let imported = match glyx_crypto::ssh::import(&body.private_key, body.passphrase.as_deref()) {
        Ok(imported) => imported,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    let add_to_agent = body.add_to_agent.unwrap_or(false);
    if add_to_agent && imported.algorithm != "ed25519" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "the SSH agent supports Ed25519 keys only; import this RSA key without adding it to the agent"
            })),
        )
            .into_response();
    }
    let comment = body
        .comment
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(imported.comment);
    let public = normalized_public(&imported.pair.openssh_public, &comment);
    let name = body
        .name
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            if comment.is_empty() {
                "imported ssh key".to_owned()
            } else {
                comment.clone()
            }
        });
    let values = BTreeMap::from([
        ("private".to_owned(), imported.pair.openssh_private),
        ("public".to_owned(), public),
        ("comment".to_owned(), comment),
        ("kind".to_owned(), imported.algorithm),
        ("agent_enabled".to_owned(), add_to_agent.to_string()),
    ]);
    let item = match glyx_store::present::build_new(
        uv,
        glyx_core::ItemType::SshKey,
        name,
        body.folder.unwrap_or_default(),
        body.tags.unwrap_or_default(),
        values,
    ) {
        Ok(item) => item,
        Err(e) => return store_error(&e).into_response(),
    };
    let id = item.id;
    if let Err(e) = uv.put_item(&item) {
        return store_error(&e).into_response();
    }
    if add_to_agent {
        if let Err(e) = reload_ssh_agent(&state, uv) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    }
    audit(uv, "ssh_import", Some(id), None, "success", None);
    Json(serde_json::json!({
        "ok": true,
        "id": id,
        "key": glyx_agent::ssh_agent::key_meta(&item),
        "agent": ssh_agent_status(&state, uv),
    }))
    .into_response()
}

fn normalized_public(public: &str, comment: &str) -> String {
    let mut parts = public.split_whitespace();
    let algorithm = parts.next().unwrap_or_default();
    let key = parts.next().unwrap_or_default();
    if key.is_empty() {
        return public.to_owned();
    }
    if comment.is_empty() {
        format!("{algorithm} {key}")
    } else {
        format!("{algorithm} {key} {comment}")
    }
}

#[derive(Deserialize)]
struct SshGenBody {
    name: String,
    kind: Option<String>,
    comment: Option<String>,
    folder: Option<String>,
    tags: Option<Vec<String>>,
    add_to_agent: Option<bool>,
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
    let add_to_agent = body.add_to_agent.unwrap_or(false);
    if add_to_agent && kind != "ed25519" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({
                "error": "the SSH agent supports Ed25519 keys only; generate this key without adding it to the agent"
            })),
        )
            .into_response();
    }
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
    values.insert("agent_enabled".to_owned(), add_to_agent.to_string());
    match glyx_store::present::build_new(
        uv,
        glyx_core::ItemType::SshKey,
        body.name,
        body.folder.unwrap_or_default(),
        body.tags.unwrap_or_default(),
        values,
    ) {
        Ok(item) => {
            let id = item.id;
            match uv.put_item(&item) {
                Ok(()) => {
                    if add_to_agent {
                        if let Err(e) = reload_ssh_agent(&state, uv) {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(serde_json::json!({"error": e.to_string()})),
                            )
                                .into_response();
                        }
                    }
                    Json(serde_json::json!({
                        "ok": true,
                        "id": id,
                        "public": pair.openssh_public,
                        "key": glyx_agent::ssh_agent::key_meta(&item),
                    }))
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
    let heal = match uv.heal_container_conflicts() {
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
            if let Err(e) = uv.compact() {
                eprintln!("vault compaction failed: {e}");
            }
            Json(serde_json::json!({"ids": ids})).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn upload_blob(State(state): State<Arc<AppState>>, body: Bytes) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
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
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
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
    let tmp = std::env::temp_dir().join(format!("glyx-backup-{}-{stamp}.glyx", std::process::id()));
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
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{name}-{stamp}.glyx\""))
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
    let tmp = std::env::temp_dir().join(format!("glyx-restore-{}.glyx", temp_tag()));
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
                Json(serde_json::json!({"error": "backup file is too large"})),
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
    let mut report = serde_json::json!({
        "format_version": vault.config().format_version,
        "index": "in-memory, rebuilt on unlock",
        "ok": true,
    });
    if let Some(uv) = guard.as_ref() {
        match uv.list(true) {
            Ok(rows) => {
                let live = rows.iter().filter(|row| !row.deleted).count();
                let mut ok = 0;
                for row in &rows {
                    if uv.get_item(&row.id).ok().flatten().is_some() {
                        ok += 1;
                    }
                }
                report["envelopes"] = serde_json::json!(rows.len());
                report["live"] = serde_json::json!(live);
                report["decrypted_items"] = serde_json::json!(ok);
                if params.rebuild_index == Some(true) {
                    report["rebuilt_index"] = serde_json::json!(rows.len());
                }
            }
            Err(e) => return store_error(&e).into_response(),
        }
    } else if params.rebuild_index == Some(true) {
        report["rebuilt_index"] = serde_json::json!("requires unlock");
    }
    if params.with_unlock == Some(true) {
        report["with_unlock"] = serde_json::json!(guard.is_some());
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
            "item_id": e.item_id, "field": e.field, "blob": e.blob_addr,
            "perm": e.perm,
        })).collect::<Vec<_>>(),
        "injects": injects.iter().map(|i| {
            let hash = std::fs::read(&i.target)
                .ok()
                .map(|bytes| glyx_crypto::blake3_hex(&bytes));
            let status = if !i.target.exists() {
                "missing"
            } else if hash.as_deref() == i.locked_hash.as_deref() {
                "locked"
            } else if hash.as_deref() == i.unlocked_hash.as_deref() {
                "unlocked"
            } else {
                "drift"
            };
            let refs: serde_json::Value =
                serde_json::from_str(&i.refs_json).unwrap_or_else(|_| serde_json::json!([]));
            serde_json::json!({
                "target": i.target, "form": i.form, "status": status,
                "template": i.template_text.is_some(), "refs": refs,
                "lock_on_exit": i.lock_on_exit,
            })
        }).collect::<Vec<_>>(),
        "roots": roots.iter().map(|r| serde_json::json!({
            "root": r.root, "glob": r.glob, "form": r.form,
        })).collect::<Vec<_>>(),
    }))
    .into_response()
}

#[derive(Deserialize)]
struct InjectQuery {
    target: PathBuf,
    reveal: Option<bool>,
}

#[derive(Deserialize)]
struct InjectSaveBody {
    target: PathBuf,
    template: String,
    form: String,
    expected_hash: Option<String>,
    materialized: Option<bool>,
    ref_forms: Option<BTreeMap<String, String>>,
}

fn inject_error(e: glyx_agent::ledger::AgentError) -> Response {
    let (status, message) = match e {
        glyx_agent::ledger::AgentError::Tamper(message) => (StatusCode::CONFLICT, message),
        glyx_agent::ledger::AgentError::Io(error) => {
            (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
        }
        other => (StatusCode::UNPROCESSABLE_ENTITY, other.to_string()),
    };
    (status, Json(serde_json::json!({"error": message}))).into_response()
}

async fn inject_content(
    State(state): State<Arc<AppState>>,
    Query(q): Query<InjectQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match glyx_agent::inject_content(uv, &q.target, q.reveal.unwrap_or(false)) {
        Ok(content) => Json(content).into_response(),
        Err(e) => inject_error(e),
    }
}

async fn inject_preview(
    State(state): State<Arc<AppState>>,
    Query(q): Query<InjectQuery>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    match glyx_agent::inject_preview(uv, &q.target, q.reveal.unwrap_or(false)) {
        Ok(preview) => Json(preview).into_response(),
        Err(e) => inject_error(e),
    }
}

async fn inject_save(
    State(state): State<Arc<AppState>>,
    Json(body): Json<InjectSaveBody>,
) -> impl IntoResponse {
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let empty = BTreeMap::new();
    let ref_forms = body.ref_forms.as_ref().unwrap_or(&empty);
    match glyx_agent::inject_save(
        uv,
        &body.target,
        &body.template,
        &body.form,
        body.expected_hash.as_deref(),
        body.materialized.unwrap_or(true),
        ref_forms,
    ) {
        Ok(content) => Json(content).into_response(),
        Err(e) => inject_error(e),
    }
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
    if body.kind != "field" && body.kind != "blob" && body.kind != "ssh" && body.kind != "file" {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "kind must be field, file, blob, or ssh"})),
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
struct UpdateExportBody {
    target: PathBuf,
    keep: Option<bool>,
    perm: Option<u32>,
}

async fn update_export(Json(body): Json<UpdateExportBody>) -> impl IntoResponse {
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
    match glyx_agent::ledger::update_export(&conn, &body.target, body.keep, body.perm) {
        Ok(true) => Json(serde_json::json!({"ok": true})).into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "export not tracked"})),
        )
            .into_response(),
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
    let is_export = glyx_agent::ledger::list_exports(&conn)
        .is_ok_and(|rows| rows.iter().any(|row| row.target.as_path() == q.target));
    let result = if is_export {
        glyx_agent::engine::recall_target(&q.target)
    } else {
        glyx_agent::forget_target(&q.target)
    };
    match result {
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
    lock_on_exit: Option<bool>,
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
    let registered = glyx_agent::ledger::register_inject(
        &conn,
        &body.target,
        &body.form.unwrap_or_else(|| "encrypted-pointer".to_owned()),
        None,
    );
    match registered {
        Ok(()) => {
            if let Some(lock_on_exit) = body.lock_on_exit {
                if let Err(e) = glyx_agent::ledger::set_inject_lock_on_exit(
                    &conn,
                    &body.target,
                    Some(lock_on_exit),
                ) {
                    return (
                        StatusCode::UNPROCESSABLE_ENTITY,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            }
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

#[derive(Deserialize)]
struct SetInjectPolicyBody {
    target: PathBuf,
    lock_on_exit: Option<bool>,
}

async fn set_inject_policy(Json(body): Json<SetInjectPolicyBody>) -> impl IntoResponse {
    let conn = match glyx_agent::ledger::open_db() {
        Ok(conn) => conn,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    if let Err(e) =
        glyx_agent::ledger::set_inject_lock_on_exit(&conn, &body.target, body.lock_on_exit)
    {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response();
    }
    Json(serde_json::json!({"ok": true, "lock_on_exit": body.lock_on_exit})).into_response()
}

#[derive(Deserialize)]
struct PickBody {
    title: Option<String>,
    file_name: Option<String>,
}

async fn pick_file_dialog(Json(body): Json<PickBody>) -> impl IntoResponse {
    pick_dialog(crate::picker::PickKind::File, body).await
}

async fn pick_folder_dialog(Json(body): Json<PickBody>) -> impl IntoResponse {
    pick_dialog(crate::picker::PickKind::Folder, body).await
}

async fn pick_save_dialog(Json(body): Json<PickBody>) -> impl IntoResponse {
    pick_dialog(crate::picker::PickKind::Save, body).await
}

async fn pick_dialog(kind: crate::picker::PickKind, body: PickBody) -> Response {
    let title = body.title.unwrap_or_else(|| "Choose a path".to_owned());
    let result = tokio::task::spawn_blocking(move || {
        crate::picker::pick(kind, &title, body.file_name.as_deref())
    })
    .await;
    match result {
        Ok(Ok(Some(path))) => Json(serde_json::json!({
            "ok": true,
            "path": path,
            "cancelled": false,
        }))
        .into_response(),
        Ok(Ok(None)) => Json(serde_json::json!({
            "ok": true,
            "path": null,
            "cancelled": true,
        }))
        .into_response(),
        Ok(Err(error)) => (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({"error": error})),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": error.to_string()})),
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
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_ref() else {
        return locked_error().into_response();
    };
    let status = ssh_agent_status(&state, uv);
    if status["running"].as_bool() == Some(true) {
        Json(serde_json::json!({
            "sock": status["socket"],
            "running": true,
            "identities": status["identities"],
        }))
        .into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no agent socket", "running": false})),
        )
            .into_response()
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
    lock_on_exit: Option<bool>,
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

#[derive(Deserialize)]
struct BiometricSlotBody {
    keyfile: Option<String>,
}

fn keyfile_for_slot(
    uv: &glyx_store::UnlockedVault,
    path: Option<&str>,
) -> Result<[u8; 32], (StatusCode, Json<serde_json::Value>)> {
    if !uv.config().keyfile_required {
        return Ok(glyx_crypto::ZERO_KEYFILE);
    }
    let Some(path) = path else {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "keyfile required"})),
        ));
    };
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut keyfile = [0u8; 32];
            keyfile.copy_from_slice(&bytes);
            Ok(keyfile)
        }
        Ok(_) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "bad keyfile"})),
        )),
        Err(e) => Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": e.to_string()})),
        )),
    }
}

async fn add_biometric_slot(
    State(state): State<Arc<AppState>>,
    Json(body): Json<BiometricSlotBody>,
) -> impl IntoResponse {
    let mut guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(uv) = guard.as_mut() else {
        return locked_error().into_response();
    };
    let keyfile = match keyfile_for_slot(uv, body.keyfile.as_deref()) {
        Ok(keyfile) => keyfile,
        Err(response) => return response.into_response(),
    };
    let mut bytes = [0u8; 32];
    if glyx_crypto::rand::fill_random(&mut bytes).is_err() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "cannot generate slot secret"})),
        )
            .into_response();
    }
    let secret = bytes.iter().fold(String::with_capacity(64), |mut out, b| {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
        out
    });
    match uv.add_slot(secret.as_bytes(), &keyfile) {
        Ok(id) => {
            audit(uv, "keyslot_add", None, None, "success", Some("biometric"));
            Json(serde_json::json!({"ok": true, "slot_id": id, "secret": secret})).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
}

async fn retire_biometric_slot(
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
    let Ok(id) = uuid::Uuid::parse_str(&id) else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "bad slot id"})),
        )
            .into_response();
    };
    match uv.retire_slot(&id) {
        Ok(()) => {
            audit(
                uv,
                "keyslot_retire",
                None,
                None,
                "success",
                Some("biometric"),
            );
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => store_error(&e).into_response(),
    }
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
        "lock_on_exit": cfg.lock_on_exit,
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
    if let Some(lock) = body.lock_on_exit {
        cfg.lock_on_exit = lock;
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
        "lock_on_exit": cfg.lock_on_exit,
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
    if let Ok(report) = glyx_agent::engine::recover_crash(glyx_store::config::load().lock_on_exit) {
        if report.restored > 0 || report.wiped > 0 || !report.drifted.is_empty() {
            eprintln!(
                "crash recovery: restored {}, wiped {}, drifted {}",
                report.restored,
                report.wiped,
                report.drifted.len()
            );
        }
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let state = Arc::new(AppState {
        active: Mutex::new(config.vault.clone()),
        vault: Mutex::new(None),
        token,
        port: Mutex::new(addr.port()),
        idle_lock_ms: std::sync::atomic::AtomicU64::new(config.idle_lock_ms),
        last_activity_ms: Mutex::new(now_ms()),
        ssh_agent: Mutex::new(None),
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
    let shutdown = state.clone();
    tokio::spawn(async move {
        wait_for_shutdown().await;
        do_shutdown(&shutdown);
        std::process::exit(0);
    });
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap_or_else(|e| {
            eprintln!("daemon serve error: {e}");
        });
    });
    Ok((addr, handle))
}

async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("sigterm handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
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
            ssh_agent: Mutex::new(None),
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
            Some("application/octet-stream")
        );
        assert_eq!(&archive[..8], b"GLYXPK01");
        let dest = cfg.path().join("restored.glyx");
        let (status, _, body) = call_raw(
            state,
            "POST",
            &format!("/v1/vaults/restore?dest={}", dest.display()),
            Body::from(archive),
            Some("application/octet-stream"),
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
    async fn biometric_slot_add_unlock_and_retire() {
        let cfg = tempfile::tempdir().expect("config dir");
        std::env::set_var("GLYX_CONFIG", cfg.path().join("config.toml"));
        let (_d, state) = test_state();
        let kf_path = test_kf();
        let (status, _) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": "pw", "keyfile": kf_path.clone()})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/vaults/slots",
            Some(serde_json::json!({"keyfile": kf_path.clone()})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let secret = body["secret"].as_str().expect("secret").to_owned();
        let slot_id = body["slot_id"].as_str().expect("slot id").to_owned();
        assert_eq!(secret.len(), 64);

        let (status, _) = call(state.clone(), "POST", "/v1/lock", None, "test-token").await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/unlock",
            Some(serde_json::json!({"password": secret, "keyfile": kf_path})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            state.clone(),
            "DELETE",
            &format!("/v1/vaults/slots/{slot_id}"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn passkey_create_lookup_and_get() {
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

        let creation = serde_json::json!({
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": "dXNlcg",
                "name": "alice@example.com",
                "displayName": "Alice"
            },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "excludeCredentials": [],
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "required"
            },
            "extensions": {"credProps": true}
        });
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/passkeys/create",
            Some(serde_json::json!({
                "origin": "https://example.com",
                "request": creation.clone(),
                "user_verified": true
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let item_id = body["item_id"].as_str().expect("item id").to_owned();
        let credential_id = body["response"]["id"]
            .as_str()
            .expect("credential id")
            .to_owned();
        assert_eq!(body["response"]["response"]["publicKeyAlgorithm"], -7);
        assert!(body["response"]["response"]["authenticatorData"]
            .as_str()
            .is_some());
        assert!(body["response"]["response"]["publicKey"].as_str().is_some());

        let (status, body) = call(state.clone(), "GET", "/v1/passkeys", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().expect("array").len(), 1);
        assert_eq!(body[0]["rp_id"], "example.com");
        assert_eq!(body[0]["usable"], true);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/passkeys/lookup",
            Some(serde_json::json!({
                "origin": "https://example.com",
                "rp_id": "example.com",
                "allow_credentials": []
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body.as_array().expect("array").len(), 1);
        assert_eq!(body[0]["item_id"], item_id);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/passkeys/get",
            Some(serde_json::json!({
                "origin": "https://example.com",
                "item_id": item_id,
                "user_verified": true,
                "request": {
                    "rpId": "example.com",
                    "challenge": "b3RoZXItY2hhbGxlbmdl",
                    "userVerification": "required",
                    "allowCredentials": [{"type": "public-key", "id": credential_id}]
                }
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["response"]["id"], credential_id);
        assert!(body["response"]["response"]["signature"].as_str().is_some());

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/passkeys/create",
            Some(serde_json::json!({
                "origin": "https://evil.example",
                "request": creation.clone(),
                "user_verified": true
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["name"], "SecurityError");

        let (status, body) = call(
            state,
            "POST",
            "/v1/passkeys/create",
            Some(serde_json::json!({
                "origin": "https://example.com",
                "request": creation,
                "user_verified": false
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["name"], "NotAllowedError");
    }

    #[tokio::test]
    async fn match_login_by_host_and_username() {
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

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "login",
                "name": "example.com",
                "fields": {
                    "username": "alice",
                    "password": "secret",
                    "url": "https://example.com"
                }
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/logins/match",
            Some(serde_json::json!({
                "origin": "https://login.example.com",
                "username": "alice"
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["match"]["username"], "alice");
        assert_eq!(body["match"]["password"], "secret");

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/logins/match",
            Some(serde_json::json!({
                "origin": "https://example.com",
                "username": "bob"
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["match"].is_null());

        let (status, body) = call(
            state,
            "POST",
            "/v1/logins/match",
            Some(serde_json::json!({
                "origin": "https://other.example",
                "username": "alice"
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["match"].is_null());
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn login_list_matches_domain_package_and_totp() {
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

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "login",
                "name": "example.com",
                "fields": {
                    "username": "alice",
                    "password": "secret",
                    "url": "https://example.com",
                    "package": "com.example.app"
                }
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let login_id = body["id"].as_str().expect("login id").to_owned();

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "totp",
                "name": "example totp",
                "fields": {
                    "seed": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
                    "login_id": login_id
                }
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let totp_id = body["id"].as_str().expect("totp id").to_owned();

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/logins/list",
            Some(serde_json::json!({"origin": "https://login.example.com"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let matches = body["matches"].as_array().expect("matches");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0]["username"], "alice");
        assert_eq!(matches[0]["password"], "secret");
        assert_eq!(matches[0]["has_totp"], true);
        assert_eq!(matches[0]["totp_item_id"], totp_id);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/logins/list",
            Some(serde_json::json!({"package": "com.example.app"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["matches"].as_array().expect("matches").len(), 1);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/logins/list",
            Some(serde_json::json!({"origin": "https://other.example"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["matches"].as_array().expect("matches").is_empty());

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/logins/match",
            Some(serde_json::json!({
                "origin": "https://example.com",
                "username": "ALICE"
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["match"]["username"], "alice");

        let (status, body) = call(
            state,
            "POST",
            "/v1/logins/match",
            Some(serde_json::json!({"package": "com.example.app"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["match"]["username"], "alice");
    }

    #[tokio::test]
    async fn auth_rejects_bad_token() {
        let (_d, state) = test_state();
        let (status, _) = call(state, "GET", "/v1/health", None, "wrong").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn ui_is_public_and_cors_allows_tauri() {
        let (_d, state) = test_state();
        let app = router(state);
        let res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_ne!(res.status(), StatusCode::UNAUTHORIZED);

        let res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/status")
                    .header("origin", "tauri://localhost")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("tauri://localhost")
        );
        assert!(res
            .headers()
            .get("access-control-allow-headers")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.to_ascii_lowercase().contains("authorization")));

        for origin in [
            "http://localhost:4173",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            let res = app
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("OPTIONS")
                        .uri("/v1/status")
                        .header("origin", origin)
                        .header("access-control-request-method", "GET")
                        .header("access-control-request-headers", "authorization")
                        .body(Body::empty())
                        .expect("request"),
                )
                .await
                .expect("oneshot");
            assert_eq!(res.status(), StatusCode::OK);
            assert_eq!(
                res.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok()),
                Some(origin)
            );
        }

        let res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("OPTIONS")
                    .uri("/v1/status")
                    .header("origin", "https://evil.example")
                    .header("access-control-request-method", "GET")
                    .header("access-control-request-headers", "authorization")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert!(res.headers().get("access-control-allow-origin").is_none());

        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/v1/status")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("oneshot");
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
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
    #[allow(clippy::too_many_lines)]
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
        assert_eq!(body["lock_on_exit"], serde_json::json!(true));
        assert_eq!(
            state
                .idle_lock_ms
                .load(std::sync::atomic::Ordering::Relaxed),
            300_000
        );
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/settings",
            Some(serde_json::json!({"lock_on_exit": false})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["lock_on_exit"], serde_json::json!(false));
    }

    #[tokio::test]
    async fn inject_lock_policy_roundtrip() {
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
        let target = dir.path().join("notes.md");
        std::fs::write(&target, "hello\n").expect("write");
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/injects",
            Some(serde_json::json!({
                "target": target,
                "form": "encrypted-pointer",
                "lock_on_exit": true,
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = call(state.clone(), "GET", "/v1/exports", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let injects = body["injects"].as_array().expect("injects");
        assert_eq!(injects.len(), 1);
        assert_eq!(injects[0]["lock_on_exit"], serde_json::json!(true));
        let (status, body) = call(
            state.clone(),
            "PATCH",
            "/v1/injects",
            Some(serde_json::json!({"target": target, "lock_on_exit": false})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = call(state.clone(), "GET", "/v1/exports", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["injects"][0]["lock_on_exit"], serde_json::json!(false));
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
    async fn doctor_rebuilds_in_memory_index_when_unlocked() {
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
            "GET",
            "/v1/doctor?rebuild_index=true",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body.get("rebuilt_index").is_some(), "{body}");
        assert_eq!(
            body["index"],
            serde_json::json!("in-memory, rebuilt on unlock")
        );
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
        assert_eq!(body["rebuilt_index"], serde_json::json!("requires unlock"));
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

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn links_totp_and_passkey_to_login() {
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
            "/v1/items",
            Some(serde_json::json!({
                "type": "login",
                "name": "example login",
                "fields": {
                    "username": "alice@example.com",
                    "password": "hunter2",
                    "url": "https://example.com/login",
                    "seed": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
                }
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let login_id = body["id"].as_str().expect("login id").to_owned();

        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{login_id}/totp"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/items",
            Some(serde_json::json!({
                "type": "totp",
                "name": "standalone totp",
                "fields": {"seed": "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let totp_id = body["id"].as_str().expect("totp id").to_owned();

        let (status, body) = call(
            state.clone(),
            "POST",
            &format!("/v1/items/{login_id}/link"),
            Some(serde_json::json!({"child": totp_id})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{login_id}/related"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["children"].as_array().map(Vec::len), Some(1));
        assert_eq!(body["children"][0]["id"], totp_id);

        let creation = serde_json::json!({
            "rp": {"id": "example.com", "name": "Example"},
            "user": {
                "id": "dXNlcg",
                "name": "alice@example.com",
                "displayName": "Alice"
            },
            "challenge": "Y2hhbGxlbmdl",
            "pubKeyCredParams": [{"type": "public-key", "alg": -7}],
            "excludeCredentials": [],
            "authenticatorSelection": {
                "residentKey": "required",
                "userVerification": "required"
            },
            "extensions": {"credProps": true}
        });
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/passkeys/create",
            Some(serde_json::json!({
                "origin": "https://example.com",
                "request": creation,
                "user_verified": true
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let passkey_id = body["item_id"].as_str().expect("passkey id").to_owned();

        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{login_id}/related"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let children = body["children"].as_array().expect("children");
        assert_eq!(children.len(), 2, "{body}");
        assert!(children.iter().any(|child| child["id"] == passkey_id));

        let (status, body) = call(
            state.clone(),
            "POST",
            &format!("/v1/items/{login_id}/unlink"),
            Some(serde_json::json!({"child": totp_id})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/items/{login_id}/related"),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["children"].as_array().map(Vec::len), Some(1));
    }

    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn inject_editor_saves_and_restores_baseline() {
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
            "/v1/items",
            Some(serde_json::json!({
                "type": "login",
                "name": "inject source",
                "fields": {"username": "alice", "password": "hunter2"}
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let item_id = body["id"].as_str().expect("item id").to_owned();

        let work = tempfile::tempdir().expect("tempdir");
        let target = work.path().join("app.env");
        std::fs::write(&target, "user = alice\npassword = \n").expect("write");
        let target_str = target.to_string_lossy().into_owned();

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/injects",
            Some(serde_json::json!({"target": target_str, "form": "encrypted-pointer"})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(
            state.clone(),
            "GET",
            &format!("/v1/injects/content?target={}", urlencoding(&target_str)),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let hash = body["hash"].as_str().expect("hash").to_owned();

        let (status, body) = call(
            state.clone(),
            "PUT",
            "/v1/injects/content",
            Some(serde_json::json!({
                "target": target_str,
                "template": format!("user = alice\npassword = {{{{glyx:{item_id}/password}}}}\n"),
                "form": "encrypted-pointer",
                "expected_hash": hash,
                "materialized": true,
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["status"], "unlocked");
        assert_eq!(body["refs"].as_array().map(Vec::len), Some(1));
        assert_eq!(
            std::fs::read_to_string(&target).expect("read"),
            "user = alice\npassword = hunter2\n"
        );

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/agent/lock",
            Some(serde_json::json!({"target": target_str})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let locked = std::fs::read_to_string(&target).expect("read");
        assert!(locked.contains("__GLYXENC:V1:"), "{locked}");
        assert!(!locked.contains("hunter2"));

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/agent/unlock",
            Some(serde_json::json!({"target": target_str})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            std::fs::read_to_string(&target).expect("read"),
            "user = alice\npassword = hunter2\n"
        );

        let (status, body) = call(
            state.clone(),
            "DELETE",
            &format!("/v1/exports?target={}", urlencoding(&target_str)),
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(
            target.exists(),
            "forgetting an injection must keep the file"
        );
    }

    #[tokio::test]
    async fn ssh_keys_and_agent_toggle() {
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

        let (status, body) = call(state.clone(), "GET", "/v1/ssh", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["agent"]["running"], true);
        assert_eq!(body["agent"]["identities"], 0);
        assert_eq!(body["keys"].as_array().map(Vec::len), Some(0));

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh-gen",
            Some(serde_json::json!({
                "name": "deploy",
                "comment": "deploy@host",
                "folder": "ops",
                "tags": ["prod"]
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let id = body["id"].as_str().expect("id").to_owned();
        assert_eq!(body["key"]["agent_enabled"], false);
        assert_eq!(body["key"]["agent_supported"], true);
        assert!(body["key"]["fingerprint"]
            .as_str()
            .is_some_and(|value| value.starts_with("SHA256:")));

        let (status, body) = call(
            state.clone(),
            "PATCH",
            &format!("/v1/ssh/keys/{id}"),
            Some(serde_json::json!({"agent_enabled": true})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["agent"]["identities"], 1);
        assert_eq!(body["key"]["agent_enabled"], true);

        let (status, body) = call(
            state.clone(),
            "PATCH",
            &format!("/v1/ssh/keys/{id}"),
            Some(serde_json::json!({"agent_enabled": false})),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["agent"]["identities"], 0);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh/agent/stop",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["agent"]["running"], false);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh/agent/start",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["agent"]["running"], true);

        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh/agent/reload",
            None,
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");

        let (status, body) = call(state.clone(), "GET", "/v1/ssh/env", None, "test-token").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["running"], true);
    }

    #[tokio::test]
    async fn ssh_import_ed25519_and_rsa() {
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

        let pair = glyx_crypto::ssh::generate("ed25519", "imported@host").expect("generate");
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh/import",
            Some(serde_json::json!({
                "private_key": pair.openssh_private,
                "name": "imported",
                "add_to_agent": true
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["key"]["agent_enabled"], true);
        assert_eq!(body["key"]["algorithm"], "ed25519");
        assert_eq!(body["agent"]["identities"], 1);

        let rsa_pem = include_str!("../tests/fixtures/rsa_test_key").to_owned();
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh/import",
            Some(serde_json::json!({
                "private_key": rsa_pem,
                "name": "rsa key",
                "add_to_agent": true
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        let (status, body) = call(
            state.clone(),
            "POST",
            "/v1/ssh/import",
            Some(serde_json::json!({
                "private_key": rsa_pem,
                "name": "rsa key",
                "add_to_agent": false
            })),
            "test-token",
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["key"]["algorithm"], "rsa");
        assert_eq!(body["key"]["agent_supported"], false);
        assert_eq!(body["agent"]["identities"], 1);
    }

    fn urlencoding(path: &str) -> String {
        path.replace('/', "%2F")
    }
}
