#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::atomic::{AtomicBool, Ordering};

use tauri::Manager as _;
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut};

static OWNED_DAEMON: AtomicBool = AtomicBool::new(false);

fn bootstrap_script(port: u16, token: &str) -> String {
    format!("window.__GLYX__={{url:'http://127.0.0.1:{port}',token:'{token}'}};")
}

fn main() {
    let shortcut = Shortcut::new(Some(Modifiers::CONTROL | Modifiers::SHIFT), Code::KeyG);
    tauri::Builder::default()
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(move |app, _shortcut, event| {
                    if matches!(
                        event.state(),
                        tauri_plugin_global_shortcut::ShortcutState::Pressed
                    ) {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(),
        )
        .setup(move |app| {
            app.global_shortcut().register(shortcut)?;
            let script = if let Some(rec) = glyx_daemon::runtime::live_record() {
                bootstrap_script(rec.port, &rec.token)
            } else {
                let vault = glyx_store::config::load().current_vault;
                match glyx_daemon::runtime::ensure_running(vault.as_deref(), None) {
                    Ok(rec) => {
                        OWNED_DAEMON.store(true, Ordering::Relaxed);
                        bootstrap_script(rec.port, &rec.token)
                    }
                    Err(e) => {
                        eprintln!("glyx daemon autostart failed: {e}");
                        String::new()
                    }
                }
            };
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("glyx")
            .inner_size(1100.0, 750.0)
            .initialization_script(&script)
            .build()?;
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("tauri runtime failed")
        .run(|_app, event| {
            if let tauri::RunEvent::Exit = event {
                let stop = glyx_store::config::load().daemon_on_exit
                    == glyx_store::config::DaemonExit::Stop;
                if stop && OWNED_DAEMON.load(Ordering::Relaxed) {
                    let _ = glyx_daemon::runtime::stop();
                }
            }
        });
}
