mod api;

use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "glyx-daemon", version, about = "glyx localhost daemon")]
struct Args {
    #[arg(long, help = "Vault directory")]
    vault: PathBuf,
    #[arg(
        long,
        default_value = "15",
        help = "Idle auto-lock minutes, 0 disables"
    )]
    idle_lock_min: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let vault = glyx_store::Vault::open(&args.vault)?;
    let vault_id = vault.config().vault_id;
    let mut token_bytes = [0u8; 32];
    glyx_crypto::fill_random(&mut token_bytes)?;
    let mut token = String::with_capacity(64);
    for b in token_bytes {
        use std::fmt::Write as _;
        write!(token, "{b:02x}").expect("hex formatting");
    }
    let config = api::DaemonConfig {
        vault_path: args.vault.clone(),
        idle_lock_ms: args.idle_lock_min.saturating_mul(60_000),
    };
    let (addr, handle) = api::serve(config, token.clone()).await?;
    let record = serde_json::json!({
        "port": addr.port(),
        "pid": std::process::id(),
        "vault_id": vault_id,
        "token": token,
    });
    let dir = glyx_store::session::session_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("daemon-{}.json", vault_id.as_simple()));
    std::fs::write(&path, serde_json::to_vec(&record)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("glyx-daemon on 127.0.0.1:{} vault {vault_id}", addr.port());
    handle.await?;
    Ok(())
}
