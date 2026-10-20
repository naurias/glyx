use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::str::FromStr as _;
use std::sync::Mutex;
use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{App, AppHandle, Manager as _};

use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_deep_link::DeepLinkExt as _;
use tauri_plugin_global_shortcut::{GlobalShortcutExt as _, Shortcut};
use tauri_plugin_notification::NotificationExt as _;

const DEFAULT_SHORTCUT: &str = "Ctrl+Shift+G";

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct DesktopSettings {
    pub close_to_tray: bool,
    pub autostart: bool,
    pub notifications: bool,
    pub shortcut: String,
}

impl Default for DesktopSettings {
    fn default() -> Self {
        Self {
            close_to_tray: true,
            autostart: false,
            notifications: true,
            shortcut: DEFAULT_SHORTCUT.to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct DesktopState {
    settings: Mutex<DesktopSettings>,
}

#[must_use]
pub fn settings(app: &AppHandle) -> DesktopSettings {
    app.try_state::<DesktopState>()
        .map(|state| {
            state
                .settings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
        .unwrap_or_default()
}

fn settings_path() -> PathBuf {
    glyx_store::config::config_path().with_file_name("desktop.json")
}

fn load_settings() -> DesktopSettings {
    std::fs::read(settings_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_settings(settings: &DesktopSettings) -> Result<(), String> {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let bytes = serde_json::to_vec_pretty(settings).map_err(|e| e.to_string())?;
    glyx_store::vault::atomic_write(&path, &bytes).map_err(|e| e.to_string())
}

pub fn configure(builder: tauri::Builder<tauri::Wry>) -> tauri::Builder<tauri::Wry> {
    builder
        .plugin(tauri_plugin_single_instance::init(|app, argv, _cwd| {
            show_main(app);
            for arg in argv.iter().filter(|arg| arg.starts_with("glyx://")) {
                handle_url(app, arg);
            }
        }))
        .plugin(tauri_plugin_window_state::Builder::default().build())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, _shortcut, event| {
                    if matches!(
                        event.state(),
                        tauri_plugin_global_shortcut::ShortcutState::Pressed
                    ) {
                        show_main(app);
                        eval(app, "window.dispatchEvent(new Event('glyx-quick'))");
                    }
                })
                .build(),
        )
        .invoke_handler(tauri::generate_handler![
            desktop_settings_get,
            desktop_settings_set
        ])
}

pub fn setup(app: &mut App) -> tauri::Result<()> {
    let loaded = load_settings();
    app.manage(DesktopState {
        settings: Mutex::new(loaded.clone()),
    });
    apply_autostart(app.handle(), &loaded);
    if let Err(e) = register_shortcut(app.handle(), &loaded.shortcut) {
        eprintln!("glyx shortcut: {e}");
    }
    setup_tray(app)?;
    let handle = app.handle().clone();
    app.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            handle_url(&handle, url.as_str());
        }
    });
    if let Ok(Some(urls)) = app.deep_link().get_current() {
        for url in urls {
            handle_url(app.handle(), url.as_str());
        }
    }
    if let Err(e) = app.deep_link().register_all() {
        eprintln!("glyx deep-link registration: {e}");
    }
    if loaded.autostart && std::env::args().any(|arg| arg == "--minimized") {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.hide();
        }
    }
    spawn_notifier(app.handle().clone());
    Ok(())
}

pub fn notify(app: &AppHandle, title: &str, body: &str) {
    if !settings(app).notifications {
        return;
    }
    if let Err(e) = app.notification().builder().title(title).body(body).show() {
        eprintln!("glyx notification: {e}");
    }
}

fn setup_tray(app: &App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show glyx", true, None::<&str>)?;
    let quick = MenuItem::with_id(app, "quick", "Quick search", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quick, &lock, &quit])?;
    let icon = tauri::include_image!("icons/128x128.png");
    TrayIconBuilder::with_id("glyx-tray")
        .menu(&menu)
        .icon(icon)
        .show_menu_on_left_click(false)
        .tooltip("glyx")
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => show_main(app),
            "quick" => {
                show_main(app);
                eval(app, "window.dispatchEvent(new Event('glyx-quick'))");
            }
            "lock" => eval(app, "window.dispatchEvent(new Event('glyx-lock'))"),
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)?;
    Ok(())
}

fn register_shortcut(app: &AppHandle, value: &str) -> Result<(), String> {
    let shortcut = Shortcut::from_str(value).map_err(|e| e.to_string())?;
    let manager = app.global_shortcut();
    let _ = manager.unregister_all();
    manager.register(shortcut).map_err(|e| e.to_string())
}

fn apply_autostart(app: &AppHandle, settings: &DesktopSettings) {
    let manager = app.autolaunch();
    let result = if settings.autostart {
        manager.enable()
    } else {
        manager.disable()
    };
    if let Err(e) = result {
        eprintln!("glyx autostart: {e}");
    }
}

fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

fn eval(app: &AppHandle, script: &str) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.eval(script);
    }
}

fn deep_link_script(raw: &str) -> Option<String> {
    let path = raw.strip_prefix("glyx://")?.trim_matches('/');
    match path {
        "" | "unlock" => Some("window.location.href='/';".to_owned()),
        "items" => Some("window.location.href='/items';".to_owned()),
        "settings" => Some("window.location.href='/settings';".to_owned()),
        "lock" => Some("window.dispatchEvent(new Event('glyx-lock'));".to_owned()),
        "quick" => Some("window.dispatchEvent(new Event('glyx-quick'));".to_owned()),
        other if other.starts_with("items/") => {
            let id = &other["items/".len()..];
            if !id.is_empty() && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                Some(format!("window.location.href='/items/{id}';"))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn handle_url(app: &AppHandle, raw: &str) {
    show_main(app);
    if let Some(script) = deep_link_script(raw) {
        eval(app, &script);
    }
}

fn spawn_notifier(app: AppHandle) {
    std::thread::spawn(move || {
        let mut last_locked = None;
        let mut last_tamper: Option<String> = None;
        loop {
            std::thread::sleep(Duration::from_secs(30));
            if !settings(&app).notifications {
                continue;
            }
            let Some(rec) = glyx_daemon::runtime::live_record() else {
                continue;
            };
            let Some(status) = daemon_get(rec.port, &rec.token, "/v1/status") else {
                continue;
            };
            let locked = status.get("locked").and_then(serde_json::Value::as_bool) == Some(true);
            if last_locked == Some(false) && locked {
                notify(
                    &app,
                    "glyx locked",
                    "The vault was locked after inactivity.",
                );
            }
            last_locked = Some(locked);
            if locked {
                last_tamper = None;
                continue;
            }
            if let Some(tamper) = daemon_get(rec.port, &rec.token, "/v1/agent/tamper") {
                let current = serde_json::to_string(&tamper).unwrap_or_default();
                if last_tamper.as_ref().is_some_and(|prev| prev != &current) {
                    notify(
                        &app,
                        "glyx tamper detected",
                        "Tracked files changed outside glyx.",
                    );
                }
                last_tamper = Some(current);
            }
        }
    });
}

fn daemon_get(port: u16, token: &str, path: &str) -> Option<serde_json::Value> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    )
    .ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    let body = response.split_once("\r\n\r\n")?.1;
    serde_json::from_str(body).ok()
}

fn consume<T>(_value: T) {}

#[tauri::command]
fn desktop_settings_get(state: tauri::State<'_, DesktopState>) -> DesktopSettings {
    let settings = state
        .settings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone();
    consume(state);
    settings
}

#[tauri::command]
fn desktop_settings_set(
    app: AppHandle,
    state: tauri::State<'_, DesktopState>,
    settings: DesktopSettings,
) -> Result<DesktopSettings, String> {
    Shortcut::from_str(&settings.shortcut).map_err(|e| e.to_string())?;
    save_settings(&settings)?;
    *state
        .settings
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = settings.clone();
    apply_autostart(&app, &settings);
    register_shortcut(&app, &settings.shortcut)?;
    consume(state);
    drop(app);
    Ok(settings)
}

#[cfg(test)]
mod tests {
    use super::deep_link_script;

    #[test]
    fn parses_deep_links() {
        assert_eq!(
            deep_link_script("glyx://unlock").as_deref(),
            Some("window.location.href='/';")
        );
        assert_eq!(
            deep_link_script("glyx://items/0199abc-1").as_deref(),
            Some("window.location.href='/items/0199abc-1';")
        );
        assert_eq!(
            deep_link_script("glyx://lock").as_deref(),
            Some("window.dispatchEvent(new Event('glyx-lock'));")
        );
        assert!(deep_link_script("glyx://items/../../etc").is_none());
        assert!(deep_link_script("https://example.com").is_none());
    }
}
