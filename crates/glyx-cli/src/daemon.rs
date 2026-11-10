use std::path::Path;

use anyhow::{bail, Result};

use glyx_daemon::runtime::{DaemonRecord, TokenSource};

pub fn cmd_start(
    vault: Option<&Path>,
    idle_lock_min: Option<u64>,
    token: &TokenSource,
    as_json: bool,
) -> Result<()> {
    let requested = token.resolve_warn()?;
    if let Some(rec) = glyx_daemon::runtime::live_record() {
        if let Some(token) = &requested {
            if rec.token != *token {
                bail!(
                    "daemon already running with a different token (pid {})\nrunning token: {}\nrun `glyx daemon stop` before starting with a custom token",
                    rec.pid,
                    rec.token
                );
            }
        }
        print_record(&rec, as_json);
        return Ok(());
    }
    let rec = glyx_daemon::runtime::ensure_running(vault, idle_lock_min, requested.as_deref())?;
    print_record(&rec, as_json);
    Ok(())
}

fn print_record(rec: &DaemonRecord, as_json: bool) {
    let url = format!("http://127.0.0.1:{}/", rec.port);
    let record = glyx_daemon::runtime::record_path();
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "url": url,
                "port": rec.port,
                "pid": rec.pid,
                "token": rec.token,
                "record": record,
            })
        );
    } else {
        println!("daemon on {url} (pid {})", rec.pid);
        println!("token: {}", rec.token);
        println!("token file: {}", record.display());
    }
}

pub fn cmd_stop(as_json: bool) -> Result<()> {
    match glyx_daemon::runtime::stop()? {
        Some(pid) => {
            if as_json {
                println!("{}", serde_json::json!({"ok": true, "pid": pid}));
            } else {
                println!("stopped daemon (was pid {pid})");
            }
        }
        None => {
            if as_json {
                println!("{}", serde_json::json!({"ok": true, "wiped": 0}));
            } else {
                println!("no daemon recorded");
            }
        }
    }
    Ok(())
}

pub fn cmd_status(as_json: bool) {
    let rec = glyx_daemon::runtime::live_record();
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "running": rec.is_some(),
                "port": rec.as_ref().map(|r| r.port),
                "pid": rec.as_ref().map(|r| r.pid),
                "vault_path": rec.as_ref().and_then(|r| r.vault_path.clone()),
            })
        );
    } else {
        match rec {
            Some(rec) => println!("daemon on 127.0.0.1:{} (pid {})", rec.port, rec.pid),
            None => println!("daemon not running"),
        }
    }
}
