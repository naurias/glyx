use tauri::plugin::{Builder, PluginHandle, TauriPlugin};
use tauri::{AppHandle, Manager as _, Wry};

struct BiometricState(PluginHandle<Wry>);

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
