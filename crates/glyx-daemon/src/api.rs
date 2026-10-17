use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::{get, post};
use axum::{middleware, Router};
use serde::Deserialize;
pub struct AppState {
    pub active: Mutex<Option<PathBuf>>,
    pub vault: Mutex<Option<glyx_store::UnlockedVault>>,
    pub token: String,
    pub port: Mutex<u16>,
    pub idle_lock_ms: u64,
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
        let _ = glyx_daemon::runtime::write_record(&glyx_daemon::runtime::DaemonRecord {
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
        _ => StatusCode::UNPROCESSABLE_ENTITY,
    };
    (code, Json(serde_json::json!({"error": e.to_string()})))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(ui_index))
        .fallback(ui_fallback)
        .route("/v1/health", get(health))
        .route("/v1/status", get(status))
        .route(
            "/v1/vaults",
            get(list_vaults).post(add_vault).delete(forget_vault),
        )
        .route("/v1/vaults/create", post(create_vault))
        .route("/v1/vaults/select", post(select_vault))
        .route("/v1/settings", get(get_settings).post(set_settings))
        .route("/v1/unlock", post(unlock))
        .route("/v1/lock", post(lock))
        .route("/v1/items", get(list_items).post(create_item))
        .route(
            "/v1/items/:id",
            get(show_item).patch(edit_item).delete(delete_item),
        )
        .route("/v1/items/:id/totp", get(totp_code))
        .route("/v1/items/:id/rendered", get(rendered_item))
        .route("/v1/ssh-gen", post(ssh_gen))
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

async fn status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let active = state.active_path();
    let vault_info = active.as_ref().and_then(|p| {
        glyx_store::Vault::open(p).ok().map(|v| {
            serde_json::json!({
                "path": p,
                "vault_id": v.config().vault_id,
                "keyfile_required": v.keyfile_required(),
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
}

async fn unlock(
    State(state): State<Arc<AppState>>,
    Json(body): Json<UnlockBody>,
) -> impl IntoResponse {
    let vault = match state.active_vault() {
        Ok((_, v)) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    let vault_id = vault.config().vault_id;
    let keyfile_required = vault.keyfile_required();
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
            let agent_report = glyx_agent::enforce_all(&mut uv, false)
                .map(|r| r.skipped)
                .unwrap_or_default();
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
        Ok(Err(e)) => store_error(&e).into_response(),
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
    let out: Vec<_> = rows
        .into_iter()
        .filter(|r| q.item_type.as_ref().is_none_or(|t| &r.item_type == t))
        .filter(|r| {
            q.q.as_ref().is_none_or(|needle| {
                let needle = needle.to_lowercase();
                r.name.to_lowercase().contains(&needle)
            })
        })
        .collect();
    let out: Vec<_> = out
        .into_iter()
        .filter(|r| {
            q.folder.as_ref().is_none_or(|f| {
                uv.get_item(&r.id)
                    .ok()
                    .flatten()
                    .is_some_and(|item| &item.folder == f)
            }) && q.tag.as_ref().is_none_or(|t| {
                uv.get_item(&r.id)
                    .ok()
                    .flatten()
                    .is_some_and(|item| item.tags.iter().any(|x| x == t))
            })
        })
        .map(|r| {
            serde_json::json!({
                "id": r.id,
                "type": r.item_type,
                "name": r.name,
                "rev": r.rev,
                "deleted": r.deleted,
            })
        })
        .collect();
    Json(serde_json::Value::Array(out)).into_response()
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
        Ok(item) => Json(glyx_store::present::item_json(
            &item,
            q.reveal.unwrap_or(false),
        ))
        .into_response(),
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
                Ok(()) => Json(serde_json::json!({"ok": true, "id": id})).into_response(),
                Err(e) => store_error(&e).into_response(),
            }
        }
        Err(e) => store_error(&e).into_response(),
    }
}

#[derive(Deserialize)]
struct EditBody {
    rename: Option<String>,
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
    let values = body.fields.unwrap_or_default();
    let touched = !values.is_empty() || body.delete_fields.is_some() || renamed;
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
        Ok(_) => Json(serde_json::json!({"ok": true, "id": item.id})).into_response(),
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
        Ok(code) => Json(serde_json::json!({"code": code, "period": params.step})).into_response(),
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
        Ok(ids) => Json(serde_json::json!({"ids": ids})).into_response(),
        Err(e) => store_error(&e).into_response(),
    }
}

async fn doctor(State(state): State<Arc<AppState>>) -> impl IntoResponse {
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
    }))
}

async fn set_settings(
    State(_state): State<Arc<AppState>>,
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
    if let Err(e) = glyx_store::config::save(&cfg) {
        return store_error(&e).into_response();
    }
    Json(serde_json::json!({
        "ok": true,
        "daemon_on_exit": cfg.daemon_on_exit,
        "mode": cfg.mode,
        "session_ttl_min": cfg.session_ttl_min,
    }))
    .into_response()
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
        idle_lock_ms: config.idle_lock_ms,
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
            if idle.idle_lock_ms > 0 && idle_for >= idle.idle_lock_ms {
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

pub struct DaemonConfig {
    pub vault: Option<PathBuf>,
    pub idle_lock_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    fn test_state() -> (tempfile::TempDir, Arc<AppState>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        glyx_store::Vault::init(&path, suite, b"pw", Some(&[1u8; 32])).expect("init");
        let state = Arc::new(AppState {
            active: Mutex::new(Some(path)),
            vault: Mutex::new(None),
            token: "test-token".to_owned(),
            port: Mutex::new(0),
            idle_lock_ms: 0,
            last_activity_ms: Mutex::new(now_ms()),
            agent_stop: Mutex::new(None),
            tamper: Mutex::new(Vec::new()),
        });
        (dir, state)
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
    async fn vault_management_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_CONFIG", dir.path().join("config.toml"));
        std::env::set_var("GLYX_RUNTIME_DIR", dir.path().join("run"));
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
}
