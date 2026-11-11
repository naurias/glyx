use std::sync::Mutex;

use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::{AppHandle, Manager as _, Wry};
use tauri_plugin_deep_link::DeepLinkExt as _;

struct BiometricState(PluginHandle<Wry>);

static PENDING_OTPAUTH: Mutex<Option<String>> = Mutex::new(None);

fn otpauth_script(raw: &str) -> Option<String> {
    if raw.len() > 8192 || !raw.to_ascii_lowercase().starts_with("otpauth://totp/") {
        return None;
    }
    let encoded = serde_json::to_string(raw).ok()?;
    Some(format!(
        "window.__GLYX_OTPAUTH__={encoded};window.dispatchEvent(new CustomEvent('glyx-otpauth',{{detail:{encoded}}}));"
    ))
}

fn remember(raw: &str) {
    if otpauth_script(raw).is_none() {
        return;
    }
    let mut guard = PENDING_OTPAUTH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *guard = Some(raw.to_owned());
}

pub fn take_pending_link() -> Option<String> {
    PENDING_OTPAUTH
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

pub fn install_link_listener(app: &AppHandle) {
    let handle = app.clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            let Some(script) = otpauth_script(url.as_str()) else {
                continue;
            };
            match handle.get_webview_window("main") {
                Some(window) => {
                    let _ = window.eval(&script);
                }
                None => remember(url.as_str()),
            }
        }
    });
}

pub fn capture_initial_link(app: &AppHandle) {
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        for url in urls {
            remember(url.as_str());
        }
    }
}

fn biometric_plugin() -> TauriPlugin<Wry> {
    Builder::new("glyx-biometric")
        .setup(|app, api| {
            let handle = api.register_android_plugin("dev.glyx.app", "BiometricPlugin")?;
            app.manage(BiometricState(handle));
            Ok(())
        })
        .build()
}

pub fn configure(builder: tauri::Builder<Wry>) -> tauri::Builder<Wry> {
    builder
        .plugin(biometric_plugin())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_barcode_scanner::init())
        .invoke_handler(tauri::generate_handler![
            mobile_biometric_status,
            mobile_biometric_enable,
            mobile_biometric_unlock,
            mobile_biometric_disable
        ])
}

#[tauri::command]
async fn mobile_biometric_status(app: AppHandle) -> Result<serde_json::Value, String> {
    let handle = app.state::<BiometricState>().0.clone();
    handle
        .run_mobile_plugin_async("status", ())
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn mobile_biometric_enable(
    app: AppHandle,
    secret: String,
    vault_id: String,
    slot_id: String,
) -> Result<serde_json::Value, String> {
    let handle = app.state::<BiometricState>().0.clone();
    handle
        .run_mobile_plugin_async(
            "enable",
            serde_json::json!({
                "secret": secret,
                "vaultId": vault_id,
                "slotId": slot_id,
            }),
        )
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn mobile_biometric_unlock(
    app: AppHandle,
    vault_id: String,
) -> Result<serde_json::Value, String> {
    let handle = app.state::<BiometricState>().0.clone();
    handle
        .run_mobile_plugin_async("unlock", serde_json::json!({ "vaultId": vault_id }))
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn mobile_biometric_disable(app: AppHandle) -> Result<serde_json::Value, String> {
    let handle = app.state::<BiometricState>().0.clone();
    handle
        .run_mobile_plugin_async("disable", ())
        .await
        .map_err(|e| e.to_string())
}
