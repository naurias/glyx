use std::path::PathBuf;

use anyhow::{Context, Result};

pub const HOST_NAME: &str = "dev.glyx.bridge";
pub const EXTENSION_ID: &str = "glyx@local";

pub fn bridge_config_write(vault: &PathBuf) -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(
        |_| {
            std::env::var("HOME")
                .map_or_else(|_| PathBuf::from("."), |h| PathBuf::from(h).join(".config"))
        },
        PathBuf::from,
    );
    let dir = base.join("glyx");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("bridge.json");
    std::fs::write(&path, serde_json::json!({"vault": vault}).to_string())?;
    Ok(path)
}

pub fn host_binary() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let next = dir.join("glyx-native-host");
            if next.exists() {
                return next;
            }
        }
    }
    PathBuf::from("glyx-native-host")
}

pub fn chrome_dir() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(
        |_| {
            std::env::var("HOME")
                .map_or_else(|_| PathBuf::from("."), |h| PathBuf::from(h).join(".config"))
        },
        PathBuf::from,
    );
    base.join("google-chrome").join("NativeMessagingHosts")
}

pub fn firefox_dir() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from("."),
        |h| {
            PathBuf::from(h)
                .join(".mozilla")
                .join("native-messaging-hosts")
        },
    )
}

pub fn cmd_install(vault: &PathBuf, chrome: bool, firefox: bool, as_json: bool) -> Result<()> {
    let cfg = bridge_config_write(vault)?;
    let bin = host_binary();
    let mut written = Vec::new();
    let want_chrome = chrome || !firefox;
    if want_chrome {
        let dir = chrome_dir();
        std::fs::create_dir_all(&dir)?;
        let manifest = serde_json::json!({
            "name": HOST_NAME,
            "description": "glyx native bridge",
            "path": bin,
            "type": "stdio",
            "allowed_origins": [],
        });
        let path = dir.join(format!("{HOST_NAME}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
        written.push(path);
    }
    if firefox {
        let dir = firefox_dir();
        std::fs::create_dir_all(&dir)?;
        let manifest = serde_json::json!({
            "name": HOST_NAME,
            "description": "glyx native bridge",
            "path": bin,
            "type": "stdio",
            "allowed_extensions": [EXTENSION_ID],
        });
        let path = dir.join(format!("{HOST_NAME}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
        written.push(path);
    }
    if as_json {
        println!(
            "{}",
            serde_json::json!({"ok": true, "config": cfg, "manifests": written})
        );
    } else {
        println!("bridge config: {}", cfg.display());
        for path in &written {
            println!("manifest: {}", path.display());
        }
        println!("for Chrome: load apps/extension, then run: glyx extension allow <id>");
    }
    Ok(())
}

pub fn cmd_allow(id: &str, as_json: bool) -> Result<()> {
    let path = chrome_dir().join(format!("{HOST_NAME}.json"));
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "no Chrome manifest at {}; run install first",
            path.display()
        )
    })?;
    let mut manifest: serde_json::Value = serde_json::from_str(&text)?;
    let origin = format!("chrome-extension://{id}/");
    let origins = manifest
        .get_mut("allowed_origins")
        .and_then(|v| v.as_array_mut())
        .context("bad manifest")?;
    if !origins.iter().any(|v| v.as_str() == Some(&origin)) {
        origins.push(serde_json::Value::String(origin));
    }
    std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
    if as_json {
        println!("{}", serde_json::json!({"ok": true, "path": path}));
    } else {
        println!("allowed {id} in {}", path.display());
    }
    Ok(())
}

pub fn cmd_status(vault: &PathBuf, as_json: bool) {
    let cfg_ok = std::env::var("GLYX_BRIDGE_CONFIG").map_or_else(
        |_| {
            let base =
                std::env::var("XDG_CONFIG_HOME").map_or_else(|_| PathBuf::from("."), PathBuf::from);
            base.join("glyx").join("bridge.json")
        },
        PathBuf::from,
    );
    let chrome = chrome_dir().join(format!("{HOST_NAME}.json")).exists();
    let firefox = firefox_dir().join(format!("{HOST_NAME}.json")).exists();
    let bin = host_binary();
    let report = serde_json::json!({
        "vault": vault,
        "bridge_config": cfg_ok.exists(),
        "binary": bin.exists() || bin.as_os_str() == "glyx-native-host",
        "chrome_manifest": chrome,
        "firefox_manifest": firefox,
    });
    if as_json {
        println!("{report}");
    } else {
        println!("vault: {}", vault.display());
        println!("bridge config: {}", cfg_ok.exists());
        println!("chrome manifest: {chrome}, firefox manifest: {firefox}");
    }
}
