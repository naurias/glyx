use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    Random,
    Literal(String),
    Env(String),
    File(PathBuf),
}

impl TokenSource {
    #[must_use]
    pub fn new(token: Option<String>, env: Option<String>, file: Option<PathBuf>) -> Self {
        match (token, env, file) {
            (Some(token), _, _) => Self::Literal(token),
            (_, Some(env), _) => Self::Env(env),
            (_, _, Some(file)) => Self::File(file),
            _ => Self::Random,
        }
    }

    pub fn resolve(&self) -> anyhow::Result<Option<String>> {
        let raw = match self {
            Self::Random => return Ok(None),
            Self::Literal(token) => token.clone(),
            Self::Env(name) => std::env::var(name)
                .map_err(|_| anyhow::anyhow!("token environment variable {name} is not set"))?,
            Self::File(path) => std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("cannot read token file {}: {e}", path.display()))?,
        };
        normalize_token(&raw).map(Some)
    }

    pub fn resolve_warn(&self) -> anyhow::Result<Option<String>> {
        let token = self.resolve()?;
        if let Some(token) = &token {
            warn_if_short(token);
        }
        Ok(token)
    }
}

pub fn normalize_token(raw: &str) -> anyhow::Result<String> {
    let token = raw.trim();
    if token.is_empty() {
        anyhow::bail!("token must not be empty");
    }
    if token.chars().any(char::is_control) {
        anyhow::bail!("token must not contain control characters");
    }
    Ok(token.to_owned())
}

pub fn token_from_spawn_env() -> anyhow::Result<Option<String>> {
    match std::env::var("GLYX_DAEMON_TOKEN") {
        Ok(raw) => {
            let token = normalize_token(&raw)?;
            warn_if_short(&token);
            Ok(Some(token))
        }
        Err(_) => Ok(None),
    }
}

pub fn warn_if_short(token: &str) {
    if token.chars().count() < 16 {
        eprintln!("warning: daemon token is shorter than 16 characters; use a longer random value");
    }
}

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
    token: Option<&str>,
) -> anyhow::Result<DaemonRecord> {
    if let Some(record) = live_record() {
        if let Some(token) = token {
            if record.token != token {
                anyhow::bail!(
                    "daemon already running with a different token (pid {})",
                    record.pid
                );
            }
        }
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
    cmd.env_remove("GLYX_DAEMON_TOKEN");
    if let Some(token) = token {
        cmd.env("GLYX_DAEMON_TOKEN", token);
    }
    cmd.spawn()
        .map_err(|e| anyhow::anyhow!("cannot spawn glyx-daemon: {e}"))?;
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(record) = read_record() {
            if is_live(&record) {
                if let Some(token) = token {
                    if record.token != token {
                        anyhow::bail!("daemon started with an unexpected token");
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_and_rejects_tokens() {
        assert_eq!(normalize_token("  abc  ").expect("trim"), "abc");
        assert!(normalize_token("").is_err());
        assert!(normalize_token("   ").is_err());
        assert!(normalize_token("bad\ntoken").is_err());
        assert!(normalize_token("bad\ttoken").is_err());
    }

    #[test]
    fn resolves_literal_and_random_sources() {
        assert_eq!(
            TokenSource::new(Some("  custom-token  ".to_owned()), None, None)
                .resolve()
                .expect("literal"),
            Some("custom-token".to_owned())
        );
        assert_eq!(
            TokenSource::new(None, None, None)
                .resolve()
                .expect("random"),
            None
        );
    }

    #[test]
    fn resolves_env_and_file_sources() {
        let name = format!("GLYX_TEST_TOKEN_{}", std::process::id());
        std::env::set_var(&name, "env-token\n");
        assert_eq!(
            TokenSource::new(None, Some(name.clone()), None)
                .resolve()
                .expect("env"),
            Some("env-token".to_owned())
        );
        std::env::remove_var(&name);

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("token");
        std::fs::write(&path, "file-token\n").expect("write");
        assert_eq!(
            TokenSource::new(None, None, Some(path.clone()))
                .resolve()
                .expect("file"),
            Some("file-token".to_owned())
        );

        assert!(TokenSource::new(None, Some(name), None).resolve().is_err());
        assert!(
            TokenSource::new(None, None, Some(dir.path().join("missing")))
                .resolve()
                .is_err()
        );
    }

    #[test]
    fn spawn_env_token_is_normalized() {
        std::env::set_var("GLYX_DAEMON_TOKEN", "  spawn-token  ");
        assert_eq!(
            token_from_spawn_env().expect("spawn env"),
            Some("spawn-token".to_owned())
        );
        std::env::remove_var("GLYX_DAEMON_TOKEN");
        assert_eq!(token_from_spawn_env().expect("unset"), None);
    }
}
