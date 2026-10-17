use std::path::Path;

use anyhow::Result;

pub fn cmd_start(vault: Option<&Path>, idle_lock_min: Option<u64>, as_json: bool) -> Result<()> {
    if let Some(rec) = glyx_daemon::runtime::live_record() {
        if as_json {
            println!(
                "{}",
                serde_json::json!({"ok": true, "port": rec.port, "pid": rec.pid})
            );
        } else {
            println!("daemon already on 127.0.0.1:{} (pid {})", rec.port, rec.pid);
        }
        return Ok(());
    }
    let rec = glyx_daemon::runtime::ensure_running(vault, idle_lock_min)?;
    if as_json {
        println!(
            "{}",
            serde_json::json!({"ok": true, "port": rec.port, "pid": rec.pid})
        );
    } else {
        println!("daemon on 127.0.0.1:{} (pid {})", rec.port, rec.pid);
    }
    Ok(())
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
