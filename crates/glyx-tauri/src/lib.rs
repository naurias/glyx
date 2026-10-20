#[cfg(not(mobile))]
mod desktop;

#[cfg(not(mobile))]
use std::sync::atomic::{AtomicBool, Ordering};

#[cfg(not(mobile))]
use tauri::Manager as _;

#[cfg(not(mobile))]
static OWNED_DAEMON: AtomicBool = AtomicBool::new(false);

fn bootstrap_script(port: u16, token: &str) -> String {
    format!("window.__GLYX__={{url:'http://127.0.0.1:{port}',token:'{token}'}};")
}

fn current_vault() -> Option<std::path::PathBuf> {
    glyx_store::config::load()
        .current_vault
        .filter(|p| glyx_store::Vault::open(p).is_ok())
}

#[cfg(not(mobile))]
fn desktop_script() -> String {
    if let Some(rec) = glyx_daemon::runtime::live_record() {
        return bootstrap_script(rec.port, &rec.token);
    }
    match glyx_daemon::runtime::ensure_running(current_vault().as_deref(), None) {
        Ok(rec) => {
            OWNED_DAEMON.store(true, Ordering::Relaxed);
            bootstrap_script(rec.port, &rec.token)
        }
        Err(e) => {
            eprintln!("glyx daemon autostart failed: {e}");
            String::new()
        }
    }
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
    bootstrap_script(port, &token)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
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
                if stop && OWNED_DAEMON.load(Ordering::Relaxed) {
                    desktop::notify(app, "glyx daemon", "Daemon stopped.");
                    let _ = glyx_daemon::runtime::stop();
                }
            }
            #[cfg(mobile)]
            let _ = (app, event);
        });
}
