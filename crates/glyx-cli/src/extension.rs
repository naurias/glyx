use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use serde_json::{json, Value};

pub const HOST_NAME: &str = "dev.glyx.bridge";
pub const FIREFOX_EXTENSION_ID: &str = "glyx@local";

/// Public half of the key that pins the unpacked Chromium extension id. Only
/// the public key is stored here; it is not a secret.
pub const EXTENSION_KEY: &str = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpo36+vi93LtsO0/fdp1gqnbYI2ChhrS0OsH1Z+rYcaC2X8+sZg8YlFLF9BeydaSK9RLqdYABAAi+QFhW0CO12w==";
/// Derived from [`EXTENSION_KEY`] with Chrome's extension id algorithm.
pub const EXTENSION_ID: &str = "pghflpdollfefhhgbpmdpakgmemflmpn";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Browser {
    Chrome,
    Chromium,
    Brave,
    Edge,
    Vivaldi,
    Opera,
    Firefox,
}

impl Browser {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Chrome => "chrome",
            Self::Chromium => "chromium",
            Self::Brave => "brave",
            Self::Edge => "edge",
            Self::Vivaldi => "vivaldi",
            Self::Opera => "opera",
            Self::Firefox => "firefox",
        }
    }

    #[must_use]
    pub fn is_firefox(self) -> bool {
        matches!(self, Self::Firefox)
    }
}

pub const ALL_BROWSERS: [Browser; 7] = [
    Browser::Chrome,
    Browser::Chromium,
    Browser::Brave,
    Browser::Edge,
    Browser::Vivaldi,
    Browser::Opera,
    Browser::Firefox,
];

fn home_dir() -> PathBuf {
    std::env::var("HOME").map_or_else(|_| PathBuf::from("."), PathBuf::from)
}

fn config_base() -> PathBuf {
    std::env::var("XDG_CONFIG_HOME").map_or_else(|_| home_dir().join(".config"), PathBuf::from)
}

#[must_use]
pub fn config_root(browser: Browser) -> PathBuf {
    let base = config_base();
    match browser {
        Browser::Chrome => base.join("google-chrome"),
        Browser::Chromium => base.join("chromium"),
        Browser::Brave => base.join("BraveSoftware").join("Brave-Browser"),
        Browser::Edge => base.join("microsoft-edge"),
        Browser::Vivaldi => base.join("vivaldi"),
        Browser::Opera => base.join("opera"),
        Browser::Firefox => home_dir().join(".mozilla"),
    }
}

#[must_use]
pub fn manifest_dir(browser: Browser) -> PathBuf {
    if browser.is_firefox() {
        home_dir().join(".mozilla").join("native-messaging-hosts")
    } else {
        config_root(browser).join("NativeMessagingHosts")
    }
}

#[must_use]
pub fn detected_browsers() -> Vec<Browser> {
    let mut found: Vec<Browser> = ALL_BROWSERS
        .into_iter()
        .filter(|browser| config_root(*browser).exists())
        .collect();
    if found.is_empty() {
        found.push(Browser::Chrome);
    }
    found
}

fn flatpak_manifest_dirs(browser: Browser) -> Vec<PathBuf> {
    let home = home_dir();
    let mut dirs = Vec::new();
    let flatpak = home.join(".var").join("app");
    let apps: &[(&str, &str)] = match browser {
        Browser::Chrome => &[("com.google.Chrome", "google-chrome")],
        Browser::Chromium => &[("org.chromium.Chromium", "chromium")],
        Browser::Brave => &[("com.brave.Browser", "BraveSoftware/Brave-Browser")],
        Browser::Edge => &[("com.microsoft.Edge", "microsoft-edge")],
        Browser::Vivaldi | Browser::Opera | Browser::Firefox => &[],
    };
    for (app, sub) in apps {
        let root = flatpak.join(app).join("config").join(sub);
        if root.exists() {
            dirs.push(root.join("NativeMessagingHosts"));
        }
    }
    if browser == Browser::Chromium {
        let snap = home
            .join("snap")
            .join("chromium")
            .join("current")
            .join(".config")
            .join("chromium");
        if snap.exists() {
            dirs.push(snap.join("NativeMessagingHosts"));
        }
    }
    dirs
}

#[must_use]
pub fn install_dirs(browser: Browser) -> Vec<PathBuf> {
    let mut dirs = vec![manifest_dir(browser)];
    dirs.extend(flatpak_manifest_dirs(browser));
    dirs
}

pub fn bridge_config_write(vault: &Path) -> Result<PathBuf> {
    let dir = config_base().join("glyx");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("bridge.json");
    std::fs::write(&path, json!({"vault": vault}).to_string())?;
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

fn manifest_json(browser: Browser, bin: &Path) -> Value {
    if browser.is_firefox() {
        json!({
            "name": HOST_NAME,
            "description": "glyx native bridge",
            "path": bin,
            "type": "stdio",
            "allowed_extensions": [FIREFOX_EXTENSION_ID],
        })
    } else {
        json!({
            "name": HOST_NAME,
            "description": "glyx native bridge",
            "path": bin,
            "type": "stdio",
            "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
        })
    }
}

fn write_manifest(browser: Browser, dir: &Path, bin: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(format!("{HOST_NAME}.json"));
    let mut manifest = manifest_json(browser, bin);
    if !browser.is_firefox() {
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(existing) = serde_json::from_str::<Value>(&text) {
                let known = manifest["allowed_origins"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default();
                let merged = manifest["allowed_origins"]
                    .as_array_mut()
                    .context("manifest origins")?;
                for origin in existing
                    .get("allowed_origins")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if !known.contains(origin) && !merged.contains(origin) {
                        merged.push(origin.clone());
                    }
                }
            }
        }
    }
    std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
    Ok(path)
}

#[cfg(test)]
pub fn extension_id_from_key(key: &str) -> Result<String> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};
    let der = base64::engine::general_purpose::STANDARD
        .decode(key)
        .context("decode extension key")?;
    let hash = Sha256::digest(&der);
    let mut id = String::with_capacity(32);
    for byte in &hash[..16] {
        id.push(char::from(b'a' + (byte >> 4)));
        id.push(char::from(b'a' + (byte & 0x0f)));
    }
    Ok(id)
}

pub fn cmd_install(vault: &Path, browsers: &[Browser], as_json: bool) -> Result<()> {
    let cfg = bridge_config_write(vault)?;
    let bin = host_binary();
    let selected = if browsers.is_empty() {
        detected_browsers()
    } else {
        browsers.to_vec()
    };
    let mut written = Vec::new();
    let mut seen = Vec::new();
    for browser in selected {
        if seen.contains(&browser) {
            continue;
        }
        seen.push(browser);
        for dir in install_dirs(browser) {
            written.push(write_manifest(browser, &dir, &bin)?);
        }
    }
    if as_json {
        println!(
            "{}",
            json!({
                "ok": true,
                "config": cfg,
                "extension_id": EXTENSION_ID,
                "manifests": written,
            })
        );
    } else {
        println!("bridge config: {}", cfg.display());
        for path in &written {
            println!("manifest: {}", path.display());
        }
        println!("extension id: {EXTENSION_ID}");
        println!("load apps/extension/dist/chromium or apps/extension/dist/firefox");
        println!("build them with: node apps/extension/build.mjs all");
    }
    Ok(())
}

pub fn cmd_allow(id: &str, browsers: &[Browser], as_json: bool) -> Result<()> {
    let origin = format!("chrome-extension://{id}/");
    let selected: Vec<Browser> = if browsers.is_empty() {
        detected_browsers()
    } else {
        browsers.to_vec()
    };
    let mut written = Vec::new();
    for browser in selected.into_iter().filter(|b| !b.is_firefox()) {
        for dir in install_dirs(browser) {
            let path = dir.join(format!("{HOST_NAME}.json"));
            if !path.exists() {
                continue;
            }
            let text = std::fs::read_to_string(&path)?;
            let mut manifest: Value = serde_json::from_str(&text)?;
            let origins = manifest
                .get_mut("allowed_origins")
                .and_then(Value::as_array_mut)
                .context("bad manifest")?;
            if !origins.iter().any(|value| value.as_str() == Some(&origin)) {
                origins.push(Value::String(origin.clone()));
            }
            std::fs::write(&path, serde_json::to_string_pretty(&manifest)?)?;
            written.push(path);
        }
    }
    if written.is_empty() {
        bail!("no Chromium native host manifest found; run glyx extension install first");
    }
    if as_json {
        println!(
            "{}",
            json!({"ok": true, "origin": origin, "manifests": written})
        );
    } else {
        for path in &written {
            println!("allowed {id} in {}", path.display());
        }
    }
    Ok(())
}

pub fn cmd_id(as_json: bool) {
    if as_json {
        println!(
            "{}",
            json!({"ok": true, "id": EXTENSION_ID, "key": EXTENSION_KEY})
        );
    } else {
        println!("{EXTENSION_ID}");
    }
}

pub fn cmd_status(vault: &Path, as_json: bool) {
    let bridge = config_base().join("glyx").join("bridge.json");
    let bin = host_binary();
    let mut manifests = Vec::new();
    for browser in ALL_BROWSERS {
        for dir in install_dirs(browser) {
            let path = dir.join(format!("{HOST_NAME}.json"));
            let exists = path.exists();
            let mut origins = Vec::new();
            if exists {
                if let Ok(text) = std::fs::read_to_string(&path) {
                    if let Ok(value) = serde_json::from_str::<Value>(&text) {
                        for key in ["allowed_origins", "allowed_extensions"] {
                            for item in value
                                .get(key)
                                .and_then(Value::as_array)
                                .into_iter()
                                .flatten()
                            {
                                if let Some(text) = item.as_str() {
                                    origins.push(text.to_owned());
                                }
                            }
                        }
                    }
                }
            }
            manifests.push(json!({
                "browser": browser.label(),
                "path": path,
                "exists": exists,
                "allowed": origins,
            }));
        }
    }
    let report = json!({
        "vault": vault,
        "bridge_config": bridge.exists(),
        "binary": bin.exists() || bin.as_os_str() == "glyx-native-host",
        "extension_id": EXTENSION_ID,
        "manifests": manifests,
    });
    if as_json {
        println!("{report}");
    } else {
        println!("vault: {}", vault.display());
        println!("bridge config: {}", bridge.exists());
        println!("extension id: {EXTENSION_ID}");
        for manifest in report["manifests"].as_array().into_iter().flatten() {
            let browser = manifest["browser"].as_str().unwrap_or("?");
            let path = manifest["path"].as_str().unwrap_or("?");
            if manifest["exists"].as_bool().unwrap_or(false) {
                println!("{browser}: {path}");
            } else {
                println!("{browser}: not installed ({path})");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_id_is_derived_from_the_manifest_key() {
        assert_eq!(
            extension_id_from_key(EXTENSION_KEY).expect("derive id"),
            EXTENSION_ID
        );
    }

    #[test]
    fn chromium_manifest_preauthorizes_the_stable_id() {
        let manifest = manifest_json(Browser::Chrome, Path::new("/bin/glyx-native-host"));
        assert_eq!(
            manifest["allowed_origins"][0],
            format!("chrome-extension://{EXTENSION_ID}/")
        );
    }

    #[test]
    fn firefox_manifest_uses_allowed_extensions() {
        let manifest = manifest_json(Browser::Firefox, Path::new("/bin/glyx-native-host"));
        assert_eq!(
            manifest["allowed_extensions"][0].as_str(),
            Some(FIREFOX_EXTENSION_ID)
        );
        assert!(manifest.get("allowed_origins").is_none());
    }

    #[test]
    fn browser_labels_are_stable() {
        assert_eq!(Browser::Chrome.label(), "chrome");
        assert_eq!(Browser::Firefox.label(), "firefox");
        assert!(Browser::Firefox.is_firefox());
    }
}
