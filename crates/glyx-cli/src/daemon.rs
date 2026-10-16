use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonRecord {
    pub port: u16,
    pub pid: u32,
    pub vault_id: Uuid,
    pub token: String,
}

pub fn record_path(vault_id: &Uuid) -> PathBuf {
    glyx_store::session::session_dir().join(format!("daemon-{}.json", vault_id.as_simple()))
}

pub fn read_record(vault_id: &Uuid) -> Option<DaemonRecord> {
    let bytes = std::fs::read(record_path(vault_id)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().expect("loopback"),
        Duration::from_millis(500),
    )
    .is_ok()
}

pub fn pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new(&format!("/proc/{pid}")).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}

pub fn find_daemon_bin() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let next = dir.join("glyx-daemon");
            if next.exists() {
                return next;
            }
        }
    }
    PathBuf::from("glyx-daemon")
}

pub fn cmd_start(
    vault_path: &std::path::Path,
    idle_lock_min: Option<u64>,
    as_json: bool,
) -> Result<()> {
    let vault = glyx_store::Vault::open(vault_path)?;
    let vault_id = vault.config().vault_id;
    if let Some(rec) = read_record(&vault_id) {
        if port_open(rec.port) && pid_alive(rec.pid) {
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
    }
    let bin = find_daemon_bin();
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("--vault")
        .arg(vault_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(min) = idle_lock_min {
        cmd.arg("--idle-lock-min").arg(min.to_string());
    }
    cmd.spawn().context("cannot spawn glyx-daemon")?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(rec) = read_record(&vault_id) {
            if port_open(rec.port) {
                if as_json {
                    println!(
                        "{}",
                        serde_json::json!({"ok": true, "port": rec.port, "pid": rec.pid})
                    );
                } else {
                    println!("daemon on 127.0.0.1:{} (pid {})", rec.port, rec.pid);
                }
                return Ok(());
            }
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("daemon did not come up within 10s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn cmd_stop(vault_path: &std::path::Path, as_json: bool) -> Result<()> {
    let vault = glyx_store::Vault::open(vault_path)?;
    let vault_id = vault.config().vault_id;
    let Some(rec) = read_record(&vault_id) else {
        if as_json {
            println!("{}", serde_json::json!({"ok": true, "wiped": 0}));
        } else {
            println!("no daemon recorded");
        }
        return Ok(());
    };
    terminate(rec.pid);
    std::fs::remove_file(record_path(&vault_id)).ok();
    if as_json {
        println!("{}", serde_json::json!({"ok": true, "pid": rec.pid}));
    } else {
        println!("stopped daemon (was pid {})", rec.pid);
    }
    Ok(())
}

pub fn cmd_status(vault_path: &std::path::Path, as_json: bool) -> Result<()> {
    let vault = glyx_store::Vault::open(vault_path)?;
    let vault_id = vault.config().vault_id;
    let running =
        read_record(&vault_id).is_some_and(|rec| port_open(rec.port) && pid_alive(rec.pid));
    let rec = read_record(&vault_id);
    if as_json {
        println!(
            "{}",
            serde_json::json!({
                "running": running,
                "port": rec.as_ref().map(|r| r.port),
                "pid": rec.as_ref().map(|r| r.pid),
            })
        );
    } else {
        match (running, rec) {
            (true, Some(rec)) => {
                println!("daemon on 127.0.0.1:{} (pid {})", rec.port, rec.pid);
            }
            _ => println!("daemon not running"),
        }
    }
    Ok(())
}

fn terminate(pid: u32) {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output();
    }
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .output();
    }
}
