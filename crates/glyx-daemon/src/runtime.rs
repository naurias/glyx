use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonRecord {
    pub port: u16,
    pub pid: u32,
    pub token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_path: Option<PathBuf>,
}

#[must_use]
pub fn record_path() -> PathBuf {
    glyx_store::session::session_dir().join("daemon.json")
}

#[must_use]
pub fn read_record() -> Option<DaemonRecord> {
    let bytes = std::fs::read(record_path()).ok()?;
    serde_json::from_slice(&bytes).ok()
}

pub fn write_record(record: &DaemonRecord) -> std::io::Result<()> {
    let path = record_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    std::fs::write(&path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn remove_record() {
    std::fs::remove_file(record_path()).ok();
}

#[must_use]
pub fn port_open(port: u16) -> bool {
    std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().expect("loopback"),
        Duration::from_millis(500),
    )
    .is_ok()
}

#[must_use]
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

#[must_use]
pub fn is_live(record: &DaemonRecord) -> bool {
    port_open(record.port) && pid_alive(record.pid)
}

#[must_use]
pub fn find_daemon_bin() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let next = dir.join("glyx-daemon");
            if next.exists() {
                return next;
            }
            #[cfg(windows)]
            {
                let exe_next = dir.join("glyx-daemon.exe");
                if exe_next.exists() {
                    return exe_next;
                }
            }
        }
    }
    PathBuf::from("glyx-daemon")
}

#[must_use]
pub fn live_record() -> Option<DaemonRecord> {
    read_record().filter(is_live)
}

pub fn ensure_running(
    vault_path: Option<&std::path::Path>,
    idle_lock_min: Option<u64>,
) -> anyhow::Result<DaemonRecord> {
    if let Some(record) = live_record() {
        return Ok(record);
    }
    let bin = find_daemon_bin();
    let mut cmd = std::process::Command::new(bin);
    if let Some(path) = vault_path {
        cmd.arg("--vault").arg(path);
    }
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if let Some(min) = idle_lock_min {
        cmd.arg("--idle-lock-min").arg(min.to_string());
    }
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("cannot spawn glyx-daemon: {e}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(record) = read_record() {
            if is_live(&record) {
                return Ok(record);
            }
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("daemon did not come up within 10s");
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn stop() -> anyhow::Result<Option<u32>> {
    let Some(record) = read_record() else {
        return Ok(None);
    };
    terminate(record.pid);
    remove_record();
    Ok(Some(record.pid))
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
