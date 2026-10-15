use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(name = "glyx", version, about = "Local-first password manager")]
struct Cli {
    #[arg(long, global = true, help = "Output machine-readable JSON")]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    #[command(about = "Vault lifecycle")]
    Vault {
        #[command(subcommand)]
        cmd: VaultCmd,
    },
    #[command(about = "Check vault health")]
    Doctor {
        #[arg(help = "Vault directory")]
        path: PathBuf,
        #[arg(long, help = "Keyfile path (required with --with-unlock)")]
        keyfile: Option<PathBuf>,
        #[arg(long, help = "Rebuild the SQLite index from envelope headers")]
        rebuild_index: bool,
        #[arg(long, help = "Also unlock and decrypt every item and blob")]
        with_unlock: bool,
        #[arg(long, help = "Read password from this env var instead of prompting")]
        password_env: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
enum VaultCmd {
    #[command(about = "Create a fresh vault directory")]
    Init {
        #[arg(help = "New vault directory (must not exist)")]
        path: PathBuf,
        #[arg(long, value_enum, default_value = "balanced", help = "Cost preset")]
        preset: Preset,
        #[arg(long, value_enum, default_value = "xchacha", help = "Payload cipher")]
        cipher: CipherOpt,
        #[arg(long, help = "Keyfile path; generated when missing")]
        keyfile: PathBuf,
        #[arg(long, help = "Read password from this env var instead of prompting")]
        password_env: Option<String>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Preset {
    #[value(help = "Balanced desktop defaults")]
    Balanced,
    #[value(help = "Hardened defaults")]
    Hardened,
    #[value(help = "Low-RAM mobile defaults")]
    Mobile,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum CipherOpt {
    #[value(help = "XChaCha20-Poly1305")]
    Xchacha,
    #[value(help = "AES-256-GCM")]
    Aesgcm,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Vault { cmd } => match cmd {
            VaultCmd::Init {
                path,
                preset,
                cipher,
                keyfile,
                password_env,
            } => {
                let password = read_password(password_env.as_deref())?;
                let kf = load_or_create_keyfile(&keyfile)?;
                let params = match preset {
                    Preset::Balanced => glyx_core::KdfParams::balanced(),
                    Preset::Hardened => glyx_core::KdfParams::hardened(),
                    Preset::Mobile => glyx_core::KdfParams::mobile(),
                };
                let suite = glyx_core::CipherSuiteConfig {
                    kdf: glyx_core::KdfId::Argon2id,
                    cipher: match cipher {
                        CipherOpt::Xchacha => glyx_core::Cipher::Xchacha20poly1305,
                        CipherOpt::Aesgcm => glyx_core::Cipher::Aes256gcm,
                    },
                    params,
                };
                let vault = glyx_store::Vault::init(&path, suite, &password, &kf)?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "ok": true,
                            "vault_id": vault.config().vault_id,
                            "path": path,
                        })
                    );
                } else {
                    println!("vault created: {}", path.display());
                    println!("vault id: {}", vault.config().vault_id);
                }
                Ok(())
            }
        },
        Cmd::Doctor {
            path,
            keyfile,
            rebuild_index,
            with_unlock,
            password_env,
        } => doctor(
            &path,
            keyfile.as_deref(),
            rebuild_index,
            with_unlock,
            password_env.as_deref(),
            cli.json,
        ),
    }
}

fn read_password(env_var: Option<&str>) -> Result<Vec<u8>> {
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

fn load_or_create_keyfile(path: &PathBuf) -> Result<[u8; 32]> {
    if path.exists() {
        let bytes =
            std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        if bytes.len() != 32 {
            bail!("keyfile {} must hold exactly 32 bytes", path.display());
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
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

fn doctor(
    path: &PathBuf,
    keyfile: Option<&std::path::Path>,
    rebuild_index: bool,
    with_unlock: bool,
    password_env: Option<&str>,
    as_json: bool,
) -> Result<()> {
    let mut report = serde_json::json!({"path": path});
    let vault = glyx_store::Vault::open(path)?;
    report["format_version"] = serde_json::json!(vault.config().format_version);
    report["keyslots"] = serde_json::json!(vault.keyslot_count()?);
    let headers = vault.scan_headers()?;
    report["envelopes"] = serde_json::json!(headers.len());
    if rebuild_index {
        let n = vault.rebuild_index()?;
        report["rebuilt_index"] = serde_json::json!(n);
    }
    if with_unlock {
        let kf_path = keyfile.context("--keyfile is required with --with-unlock")?;
        let kf_bytes = std::fs::read(kf_path)?;
        if kf_bytes.len() != 32 {
            bail!("keyfile must hold exactly 32 bytes");
        }
        let mut kf = [0u8; 32];
        kf.copy_from_slice(&kf_bytes);
        let password = read_password(password_env)?;
        let unlocked = vault.unlock(&password, &kf)?;
        let mut items_ok = 0;
        for h in &headers {
            if unlocked.get_item(&h.id)?.is_some() {
                items_ok += 1;
            }
        }
        report["decrypted_items"] = serde_json::json!(items_ok);
    }
    report["ok"] = serde_json::json!(true);
    if as_json {
        println!("{report}");
    } else {
        println!("vault ok: {}", path.display());
        println!("format: v{}", vault.config().format_version);
        println!("keyslots: {}", report["keyslots"]);
        println!("envelopes: {}", headers.len());
        if let Some(n) = report.get("rebuilt_index") {
            println!("index rebuilt: {n}");
        }
        if let Some(n) = report.get("decrypted_items") {
            println!("decrypted: {n}");
        }
    }
    Ok(())
}
