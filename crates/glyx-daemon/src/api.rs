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
    pub vault_path: PathBuf,
    pub vault: Mutex<Option<glyx_store::UnlockedVault>>,
    pub token: String,
    pub idle_lock_ms: u64,
    pub last_activity_ms: Mutex<u64>,
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
        .route("/v1/unlock", post(unlock))
        .route("/v1/lock", post(lock))
        .route("/v1/items", get(list_items).post(create_item))
        .route(
            "/v1/items/:id",
            get(show_item).patch(edit_item).delete(delete_item),
        )
        .route("/v1/items/:id/totp", get(totp_code))
        .route("/v1/ssh-gen", post(ssh_gen))
        .route("/v1/sync", post(sync))
        .route("/v1/conflicts", get(list_conflicts))
        .route("/v1/conflicts/:id", get(show_conflict))
        .route("/v1/conflicts/:id/resolve", post(resolve_conflict))
        .route("/v1/gc", post(gc))
        .route("/v1/doctor", get(doctor))
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
    let guard = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match guard.as_ref() {
        None => Json(serde_json::json!({"locked": true})),
        Some(uv) => {
            let headers = uv.list(true).unwrap_or_default();
            let live = headers.iter().filter(|r| !r.deleted).count();
            let conflicts = uv.list_conflicts().map_or(0, |c| c.len());
            let last_merge = uv.last_merge_ms().unwrap_or(None);
            Json(serde_json::json!({
                "locked": false,
                "envelopes": headers.len(),
                "live": live,
                "conflicts": conflicts,
                "last_merge_ms": last_merge,
            }))
        }
    }
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
    let vault = match glyx_store::Vault::open(&state.vault_path) {
        Ok(v) => v,
        Err(e) => return store_error(&e).into_response(),
    };
    let result = tokio::task::spawn_blocking(move || {
        if let Some(pin) = body.pin {
            return vault.open_session(Some(pin.as_bytes())).and_then(|opt| {
                opt.ok_or_else(|| glyx_store::StoreError::Corrupt("bad PIN".into()))
            });
        }
        let kf_path = body.keyfile.ok_or_else(|| {
            glyx_store::StoreError::Corrupt("password and keyfile required".into())
        })?;
        let kf_bytes = std::fs::read(&kf_path).map_err(glyx_store::StoreError::from)?;
        if kf_bytes.len() != 32 {
            return Err(glyx_store::StoreError::Corrupt("bad keyfile".into()));
        }
        let mut kf = [0u8; 32];
        kf.copy_from_slice(&kf_bytes);
        let pw = body.password.unwrap_or_default();
        vault.unlock(pw.as_bytes(), &kf)
    })
    .await;
    match result {
        Ok(Ok(uv)) => {
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

async fn lock(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let taken = state
        .vault
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    drop(taken);
    if let Ok(vault) = glyx_store::Vault::open(&state.vault_path) {
        glyx_store::session::wipe_ticket(&vault.config().vault_id);
    }
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
    let Some(kf_path) = body.other_keyfile else {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "other_keyfile required"})),
        )
            .into_response();
    };
    let kf_bytes = match std::fs::read(&kf_path) {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(serde_json::json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };
    if kf_bytes.len() != 32 {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": "bad keyfile"})),
        )
            .into_response();
    }
    let mut kf = [0u8; 32];
    kf.copy_from_slice(&kf_bytes);
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
    let vault = match glyx_store::Vault::open(&state.vault_path) {
        Ok(v) => v,
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

pub async fn serve(
    config: DaemonConfig,
    token: String,
) -> anyhow::Result<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let state = Arc::new(AppState {
        vault_path: config.vault_path.clone(),
        vault: Mutex::new(None),
        token,
        idle_lock_ms: config.idle_lock_ms,
        last_activity_ms: Mutex::new(now_ms()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
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
                idle.vault
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .take();
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
    pub vault_path: PathBuf,
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
        glyx_store::Vault::init(&path, suite, b"pw", &[1u8; 32]).expect("init");
        let state = Arc::new(AppState {
            vault_path: path,
            vault: Mutex::new(None),
            token: "test-token".to_owned(),
            idle_lock_ms: 0,
            last_activity_ms: Mutex::new(now_ms()),
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
        let kf = state.vault_path.join("..").join("kf");
        let _ = kf;
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
}
