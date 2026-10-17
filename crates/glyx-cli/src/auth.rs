use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

use glyx_store::config::{self, AppConfig, SessionMode};

pub fn load_config() -> AppConfig {
    config::load()
}

pub fn save_config(cfg: &AppConfig) -> Result<()> {
    config::save(cfg).map_err(|e| anyhow::anyhow!(e))
}

pub struct AuthFlags {
    pub vault: PathBuf,
    pub keyfile: Option<PathBuf>,
    pub password_env: Option<String>,
    pub no_session: bool,
}

pub fn resolve_vault_path(explicit: Option<&PathBuf>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.clone());
    }
    if let Ok(p) = std::env::var("GLYX_VAULT") {
        return Ok(PathBuf::from(p));
    }
    if let Some(p) = config::load().current_vault {
        return Ok(p);
    }
    bail!("no vault selected: run `glyx` to pick one, or pass --vault / set GLYX_VAULT")
}

pub fn read_password(env_var: Option<&str>) -> Result<Vec<u8>> {
    if let Some(var) = env_var {
        return std::env::var(var)
            .map(String::into_bytes)
            .with_context(|| format!("cannot read password from env {var}"));
    }
    let pw = rpassword::prompt_password("vault password: ").context("cannot read password")?;
    if pw.is_empty() {
        bail!("password must not be empty");
    }
    Ok(pw.into_bytes())
}

pub fn read_keyfile(path: &Path) -> Result<[u8; 32]> {
    glyx_store::keyfile::read(path).map_err(|e| anyhow::anyhow!(e))
}

pub fn load_or_create_keyfile(path: &Path) -> Result<[u8; 32]> {
    let existed = path.exists();
    let kf = glyx_store::keyfile::load_or_create(path).map_err(|e| anyhow::anyhow!(e))?;
    if !existed {
        eprintln!(
            "keyfile created: {} (keep it apart from the vault)",
            path.display()
        );
    }
    Ok(kf)
}

pub fn resolve_keyfile(vault: &glyx_store::Vault, keyfile: Option<&Path>) -> Result<[u8; 32]> {
    if vault.keyfile_required() {
        let path = keyfile.context("this vault requires a keyfile: pass --keyfile")?;
        read_keyfile(path)
    } else {
        Ok(glyx_crypto::ZERO_KEYFILE)
    }
}

pub fn full_unlock(
    vault: &glyx_store::Vault,
    keyfile: Option<&Path>,
    password_env: Option<&str>,
) -> Result<glyx_store::UnlockedVault> {
    let kf = resolve_keyfile(vault, keyfile)?;
    let password = read_password(password_env)?;
    Ok(vault.unlock(&password, &kf)?)
}

pub fn resolve_unlocked(auth: &AuthFlags) -> Result<glyx_store::UnlockedVault> {
    let vault = glyx_store::Vault::open(&auth.vault)?;
    if !auth.no_session {
        if let Some(uv) = vault.open_session(None)? {
            return Ok(uv);
        }
        if vault_has_pin_session(&vault) {
            let pin = rpassword::prompt_password("vault PIN: ").context("cannot read PIN")?;
            if !pin.is_empty() {
                if let Some(uv) = vault.open_session(Some(pin.as_bytes()))? {
                    return Ok(uv);
                }
                eprintln!("PIN rejected, falling back to full unlock");
            }
        }
    }
    let uv = full_unlock(
        &vault,
        auth.keyfile.as_deref(),
        auth.password_env.as_deref(),
    )?;
    if !auth.no_session && load_config().mode == SessionMode::Session {
        let ttl = load_config().session_ttl_min;
        uv.write_plain_session(ttl)?;
    }
    Ok(uv)
}

fn vault_has_pin_session(vault: &glyx_store::Vault) -> bool {
    let path = glyx_store::session::session_path(&vault.config().vault_id);
    if !path.exists() {
        return false;
    }
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v.get("mode").and_then(|m| m.as_str()).map(str::to_owned))
        .is_some_and(|m| m == "pin")
}
