#[cfg(not(mobile))]
mod desktop;

#[cfg(not(mobile))]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(mobile))]
use tauri::Manager as _;

#[cfg(not(mobile))]
static OWNED_DAEMON: AtomicBool = AtomicBool::new(false);
#[cfg(not(mobile))]
static EMBEDDED_DAEMON: AtomicBool = AtomicBool::new(false);

#[cfg(target_os = "linux")]
fn configure_linux_backend() {
    if std::env::var_os("GDK_BACKEND").is_some()
        || std::env::var_os("WAYLAND_DISPLAY").is_none()
        || std::env::var_os("DISPLAY").is_none()
        || std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none()
    {
        return;
    }
    std::env::set_var("GDK_BACKEND", "x11");
}

#[cfg(not(mobile))]
#[derive(Debug, Clone, serde::Serialize)]
pub struct BootstrapInfo {
    pub url: String,
    pub token: String,
    pub error: Option<String>,
}

fn bootstrap_script(url: &str, token: &str) -> String {
    format!(
        "window.__GLYX__={{url:{},token:{}}};",
        serde_json::to_string(url).unwrap_or_else(|_| "''".into()),
        serde_json::to_string(token).unwrap_or_else(|_| "''".into())
    )
}

#[cfg(not(mobile))]
fn bootstrap_error_script(error: &str) -> String {
    format!(
        "window.__GLYX_BOOT__={};",
        serde_json::to_string(error).unwrap_or_else(|_| "\"bootstrap failed\"".into())
    )
}

pub(crate) fn current_vault() -> Option<std::path::PathBuf> {
    glyx_store::config::load()
        .current_vault
        .filter(|p| glyx_store::Vault::open(p).is_ok())
}

#[cfg(not(mobile))]
fn random_token() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 32];
    let _ = glyx_crypto::fill_random(&mut bytes);
    let mut token = String::with_capacity(64);
    for b in bytes {
        let _ = write!(token, "{b:02x}");
    }
    token
}

#[cfg(not(mobile))]
fn embedded_daemon() -> Result<BootstrapInfo, String> {
    let token = random_token();
    let idle_lock_ms = glyx_store::config::load()
        .idle_lock_min
        .unwrap_or(15)
        .saturating_mul(60_000);
    let config = glyx_daemon::api::DaemonConfig {
        vault: current_vault(),
        idle_lock_ms,
    };
    let token_for_server = token.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("glyx embedded daemon runtime failed: {e}");
                return;
            }
        };
        runtime.block_on(async move {
            match glyx_daemon::api::serve(config, token_for_server).await {
                Ok((addr, handle)) => {
                    let _ = tx.send(addr.port());
                    if let Err(e) = handle.await {
                        eprintln!("glyx embedded daemon stopped: {e}");
                    }
                }
                Err(e) => eprintln!("glyx embedded daemon failed: {e}"),
            }
        });
    });
    let port = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .map_err(|_| "daemon did not start within 10s".to_owned())?;
    EMBEDDED_DAEMON.store(true, Ordering::Relaxed);
    Ok(BootstrapInfo {
        url: format!("http://127.0.0.1:{port}"),
        token,
        error: None,
    })
}

#[cfg(not(mobile))]
pub fn desktop_bootstrap_info() -> BootstrapInfo {
    if let Some(rec) = glyx_daemon::runtime::live_record() {
        return BootstrapInfo {
            url: format!("http://127.0.0.1:{}", rec.port),
            token: rec.token,
            error: None,
        };
    }
    match glyx_daemon::runtime::ensure_running(current_vault().as_deref(), None) {
        Ok(rec) => {
            OWNED_DAEMON.store(true, Ordering::Relaxed);
            BootstrapInfo {
                url: format!("http://127.0.0.1:{}", rec.port),
                token: rec.token,
                error: None,
            }
        }
        Err(e) => {
            eprintln!("glyx daemon autostart failed: {e}; using embedded daemon");
            embedded_daemon().unwrap_or_else(|embedded| BootstrapInfo {
                url: String::new(),
                token: String::new(),
                error: Some(format!("{e}; embedded daemon: {embedded}")),
            })
        }
    }
}

#[cfg(not(mobile))]
fn desktop_script() -> String {
    let info = desktop_bootstrap_info();
    match info.error {
        Some(error) => bootstrap_error_script(&error),
        None => bootstrap_script(&info.url, &info.token),
    }
}

#[cfg(not(mobile))]
#[tauri::command]
async fn desktop_bootstrap() -> BootstrapInfo {
    tokio::task::spawn_blocking(desktop_bootstrap_info)
        .await
        .unwrap_or_else(|e| BootstrapInfo {
            url: String::new(),
            token: String::new(),
            error: Some(e.to_string()),
        })
}

#[cfg(mobile)]
fn mobile_script() -> String {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 32];
    let _ = glyx_crypto::fill_random(&mut bytes);
    let token: String = bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    });
    let config = glyx_daemon::api::DaemonConfig {
        vault: current_vault(),
        idle_lock_ms: 15 * 60_000,
    };
    let token_for_server = token.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("glyx mobile runtime failed: {e}");
                return;
            }
        };
        runtime.block_on(async move {
            match glyx_daemon::api::serve(config, token_for_server).await {
                Ok((addr, handle)) => {
                    let _ = tx.send(addr.port());
                    if let Err(e) = handle.await {
                        eprintln!("glyx mobile daemon stopped: {e}");
                    }
                }
                Err(e) => eprintln!("glyx mobile daemon failed: {e}"),
            }
        });
    });
    let port = rx
        .recv_timeout(std::time::Duration::from_secs(10))
        .unwrap_or(0);
    bootstrap_script(&format!("http://127.0.0.1:{port}"), &token)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(target_os = "linux")]
    configure_linux_backend();
    #[cfg(not(mobile))]
    let mut builder = desktop::configure(tauri::Builder::default());
    #[cfg(mobile)]
    let builder = tauri::Builder::default();
    #[cfg(not(mobile))]
    {
        builder = builder.on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if desktop::settings(window.app_handle()).close_to_tray {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        });
    }
    builder
        .setup(move |app| {
            #[cfg(not(mobile))]
            {
                let script = desktop_script();
                tauri::WebviewWindowBuilder::new(
                    app,
                    "main",
                    tauri::WebviewUrl::App("index.html".into()),
                )
                .title("glyx")
                .inner_size(1100.0, 750.0)
                .initialization_script(&script)
                .build()?;
                desktop::setup(app)?;
                if OWNED_DAEMON.load(Ordering::Relaxed) {
                    desktop::notify(
                        app.handle(),
                        "glyx daemon",
                        "Daemon started for the selected vault.",
                    );
                }
            }
            #[cfg(mobile)]
            {
                let _ = app;
                let script = mobile_script();
                tauri::WebviewWindowBuilder::new(
                    app,
                    "main",
                    tauri::WebviewUrl::App("index.html".into()),
                )
                .title("glyx")
                .initialization_script(&script)
                .build()?;
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("tauri runtime failed")
        .run(|app, event| {
            #[cfg(not(mobile))]
            if let tauri::RunEvent::Exit = event {
                let stop = glyx_store::config::load().daemon_on_exit
                    == glyx_store::config::DaemonExit::Stop;
                if EMBEDDED_DAEMON.load(Ordering::Relaxed) {
                    glyx_daemon::runtime::remove_record();
                } else if stop && OWNED_DAEMON.load(Ordering::Relaxed) {
                    desktop::notify(app, "glyx daemon", "Daemon stopped.");
                    let _ = glyx_daemon::runtime::stop();
                }
            }
            #[cfg(mobile)]
            let _ = (app, event);
        });
}
