use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SessionMode {
    Oneshot,
    Session,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub mode: SessionMode,
    pub session_ttl_min: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mode: SessionMode::Oneshot,
            session_ttl_min: glyx_store::SESSION_TTL_DEFAULT_MIN,
        }
    }
}

pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("GLYX_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(
        |_| {
            std::env::var("HOME")
                .map_or_else(|_| PathBuf::from("."), |h| PathBuf::from(h).join(".config"))
        },
        PathBuf::from,
    );
    base.join("glyx").join("config.toml")
}

pub fn load_config() -> Config {
    let path = config_path();
    let Ok(text) = std::fs::read_to_string(path) else {
        return Config::default();
    };
    toml::from_str(&text).unwrap_or_default()
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
    std::env::var("GLYX_VAULT")
        .map(PathBuf::from)
        .context("no vault given: pass --vault or set GLYX_VAULT")
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

pub fn read_keyfile(path: &std::path::Path) -> Result<[u8; 32]> {
    let bytes = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    if bytes.len() != 32 {
        bail!("keyfile {} must hold exactly 32 bytes", path.display());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn load_or_create_keyfile(path: &std::path::Path) -> Result<[u8; 32]> {
    if path.exists() {
        return read_keyfile(path);
    }
    let kf = glyx_crypto::generate_keyfile()?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("cannot create {}", parent.display()))?;
        }
    }
    std::fs::write(path, kf).with_context(|| format!("cannot write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    eprintln!(
        "keyfile created: {} (keep it apart from the vault)",
        path.display()
    );
    Ok(kf)
}

pub fn full_unlock(
    vault: &glyx_store::Vault,
    keyfile: Option<&std::path::Path>,
    password_env: Option<&str>,
) -> Result<glyx_store::UnlockedVault> {
    let kf_path = keyfile.context("--keyfile is required for full unlock")?;
    let kf = read_keyfile(kf_path)?;
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
