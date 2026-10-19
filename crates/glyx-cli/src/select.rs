use std::io::IsTerminal as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use inquire::{Confirm, Password, PasswordDisplayMode, Select, Text};

use crate::auth;

enum Action {
    Use(PathBuf),
    AddCustom,
    CreateNew,
    RemovePicker,
}

struct Item {
    label: String,
    action: Action,
}

impl std::fmt::Display for Item {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.label)
    }
}

fn preset_from(name: &str) -> glyx_core::KdfParams {
    match name {
        "hardened" => glyx_core::KdfParams::hardened(),
        "mobile" => glyx_core::KdfParams::mobile(),
        _ => glyx_core::KdfParams::balanced(),
    }
}

fn cipher_from(name: &str) -> glyx_core::Cipher {
    match name {
        "aesgcm" => glyx_core::Cipher::Aes256gcm,
        _ => glyx_core::Cipher::Xchacha20poly1305,
    }
}

pub fn cmd_select(as_json: bool) -> Result<()> {
    let cfg = auth::load_config();
    if as_json || !std::io::stdin().is_terminal() {
        let current = cfg.current_vault.clone();
        let vaults: Vec<_> = cfg
            .vaults
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path,
                    "label": e.label(),
                    "name": e.name,
                    "keyfile": e.keyfile,
                    "current": current.as_deref().is_some_and(|c| {
                        glyx_store::config::normalize(c) == glyx_store::config::normalize(&e.path)
                    }),
                })
            })
            .collect();
        if as_json {
            println!(
                "{}",
                serde_json::json!({"current": current, "vaults": vaults})
            );
            return Ok(());
        }
        for e in &cfg.vaults {
            let mark = if current.as_deref().is_some_and(|c| {
                glyx_store::config::normalize(c) == glyx_store::config::normalize(&e.path)
            }) {
                "* "
            } else {
                "  "
            };
            println!("{mark}{}  {}", e.label(), e.path.display());
        }
        if cfg.vaults.is_empty() {
            println!("no vaults registered");
        }
        bail!("interactive selection needs a terminal")
    }
    wizard()
}

fn wizard() -> Result<()> {
    let cfg = auth::load_config();
    let current = cfg.current_vault.clone();
    let mut items: Vec<Item> = cfg
        .vaults
        .iter()
        .map(|e| {
            let mark = if current.as_deref().is_some_and(|c| {
                glyx_store::config::normalize(c) == glyx_store::config::normalize(&e.path)
            }) {
                " (current)"
            } else {
                ""
            };
            let kf = e
                .keyfile
                .as_ref()
                .map_or(String::new(), |_| " [keyfile]".to_owned());
            Item {
                label: format!("{}{mark}{kf}  {}", e.label(), e.path.display()),
                action: Action::Use(e.path.clone()),
            }
        })
        .collect();
    items.push(Item {
        label: "Add vault from custom location".to_owned(),
        action: Action::AddCustom,
    });
    items.push(Item {
        label: "Create and configure new vault".to_owned(),
        action: Action::CreateNew,
    });
    items.push(Item {
        label: "Remove a vault from the list".to_owned(),
        action: Action::RemovePicker,
    });
    let choice = Select::new("Select a vault:", items).prompt()?;
    match choice.action {
        Action::Use(path) => {
            let mut cfg = auth::load_config();
            cfg.select(&path);
            auth::save_config(&cfg)?;
            println!("selected {}", path.display());
        }
        Action::AddCustom => add_custom()?,
        Action::CreateNew => create_new()?,
        Action::RemovePicker => remove_vault()?,
    }
    Ok(())
}

fn remove_vault() -> Result<()> {
    let cfg = auth::load_config();
    if cfg.vaults.is_empty() {
        println!("no vaults registered");
        return Ok(());
    }
    let items: Vec<Item> = cfg
        .vaults
        .iter()
        .map(|e| Item {
            label: format!("{}  {}", e.label(), e.path.display()),
            action: Action::Use(e.path.clone()),
        })
        .collect();
    let choice = Select::new("Remove which vault (files untouched):", items).prompt()?;
    let Action::Use(path) = choice.action else {
        return Ok(());
    };
    let mut cfg = auth::load_config();
    let entry = cfg.find(&path).cloned();
    cfg.remove(&path);
    auth::save_config(&cfg)?;
    if let Some(id) = entry.and_then(|e| e.vault_id) {
        glyx_store::session::wipe_ticket(&id);
    }
    println!("removed {} from the list (files untouched)", path.display());
    Ok(())
}

fn optional_text(prompt: &str) -> Result<Option<String>> {
    let value = Text::new(prompt).prompt()?;
    let trimmed = value.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_owned()))
}

fn add_custom() -> Result<()> {
    let path = PathBuf::from(Text::new("Vault directory:").prompt()?);
    let vault = glyx_store::Vault::open(&path)
        .with_context(|| format!("not a glyx vault: {}", path.display()))?;
    let name = optional_text("Display name (optional):")?;
    let keyfile = if vault.keyfile_required() {
        optional_text("Keyfile path (optional, stored for convenience):")?.map(PathBuf::from)
    } else {
        None
    };
    let mut cfg = auth::load_config();
    cfg.register(glyx_store::config::VaultEntry {
        path: path.clone(),
        name,
        vault_id: Some(vault.config().vault_id),
        keyfile,
        last_used_ms: 0,
    });
    cfg.select(&path);
    auth::save_config(&cfg)?;
    println!("added and selected {}", path.display());
    Ok(())
}

fn create_new() -> Result<()> {
    let path = PathBuf::from(Text::new("New vault directory:").prompt()?);
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let name = optional_text("Display name (optional):")?;
    let preset = Select::new("KDF preset:", vec!["balanced", "hardened", "mobile"]).prompt()?;
    let cipher = Select::new("Cipher:", vec!["xchacha", "aesgcm"]).prompt()?;
    let password = Password::new("Password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()?;
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let confirm = Password::new("Confirm password:")
        .with_display_mode(PasswordDisplayMode::Masked)
        .prompt()?;
    if password != confirm {
        bail!("passwords do not match");
    }
    let use_keyfile = Confirm::new("Use a keyfile (recommended)?")
        .with_default(true)
        .prompt()?;
    let (keyfile_bytes, keyfile_path) = if use_keyfile {
        let default = default_keyfile_path(&path);
        let input = Text::new("Keyfile path:").with_default(&default).prompt()?;
        let kf_path = PathBuf::from(input);
        (Some(auth::load_or_create_keyfile(&kf_path)?), Some(kf_path))
    } else {
        (None, None)
    };
    let suite = glyx_core::CipherSuiteConfig {
        kdf: glyx_core::KdfId::Argon2id,
        cipher: cipher_from(cipher),
        params: preset_from(preset),
    };
    let vault = glyx_store::Vault::init(&path, suite, password.as_bytes(), keyfile_bytes.as_ref())?;
    let mut cfg = auth::load_config();
    cfg.register(glyx_store::config::VaultEntry {
        path: path.clone(),
        name,
        vault_id: Some(vault.config().vault_id),
        keyfile: keyfile_path,
        last_used_ms: 0,
    });
    cfg.select(&path);
    auth::save_config(&cfg)?;
    println!("created and selected {}", path.display());
    Ok(())
}

fn default_keyfile_path(vault: &Path) -> String {
    let mut p = vault.to_path_buf();
    let stem = p
        .file_name()
        .map_or_else(|| "vault".to_owned(), |n| n.to_string_lossy().into_owned());
    p.set_file_name(format!("{stem}.kf"));
    p.to_string_lossy().into_owned()
}
