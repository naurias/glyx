use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "glyx-daemon", version, about = "glyx localhost daemon")]
struct Args {
    #[arg(long, help = "Vault directory; omit to use the selected vault")]
    vault: Option<PathBuf>,
    #[arg(long, help = "Idle auto-lock minutes, 0 disables")]
    idle_lock_min: Option<u64>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let vault = match args.vault {
        Some(path) => {
            let opened = glyx_store::Vault::open(&path)?;
            let mut cfg = glyx_store::config::load();
            cfg.register(glyx_store::config::VaultEntry {
                path: path.clone(),
                name: None,
                vault_id: Some(opened.config().vault_id),
                keyfile: None,
                last_used_ms: 0,
            });
            cfg.select(&path);
            glyx_store::config::save(&cfg)?;
            Some(path)
        }
        None => glyx_store::config::load()
            .current_vault
            .filter(|p| glyx_store::Vault::open(p).is_ok()),
    };
    let mut token_bytes = [0u8; 32];
    glyx_crypto::fill_random(&mut token_bytes)?;
    let mut token = String::with_capacity(64);
    for b in token_bytes {
        use std::fmt::Write as _;
        write!(token, "{b:02x}").expect("hex formatting");
    }
    let idle_lock_min = args
        .idle_lock_min
        .or_else(|| glyx_store::config::load().idle_lock_min)
        .unwrap_or(15);
    let config = glyx_daemon::api::DaemonConfig {
        vault,
        idle_lock_ms: idle_lock_min.saturating_mul(60_000),
    };
    let (addr, handle) = glyx_daemon::api::serve(config, token).await?;
    println!("glyx-daemon on 127.0.0.1:{}", addr.port());
    handle.await?;
    Ok(())
}
