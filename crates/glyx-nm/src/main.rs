use std::fmt::Write as FmtWrite;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct Call {
    op: String,
    request_id: Option<u64>,
    #[serde(default)]
    args: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct Response {
    ok: bool,
    request_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DaemonRecord {
    pub port: u16,
    pub token: String,
}

pub fn bridge_config_path() -> PathBuf {
    if let Ok(p) = std::env::var("GLYX_BRIDGE_CONFIG") {
        return PathBuf::from(p);
    }
    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(
        |_| {
            std::env::var("HOME")
                .map_or_else(|_| PathBuf::from("."), |h| PathBuf::from(h).join(".config"))
        },
        PathBuf::from,
    );
    base.join("glyx").join("bridge.json")
}

pub fn resolve_vault() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("GLYX_VAULT") {
        let path = PathBuf::from(&p);
        if path.exists() {
            return Ok(path);
        }
    }
    if let Ok(current) = std::env::var("GLYX_CONFIG") {
        if let Some(path) = vault_from_config(std::path::Path::new(&current)) {
            return Ok(path);
        }
    }
    if let Some(path) = vault_from_config(&default_config_path()) {
        return Ok(path);
    }
    let path = bridge_config_path();
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "no selected vault; run glyx extension install or select a vault (bridge config {} missing)",
            path.display()
        )
    })?;
    let cfg: serde_json::Value = serde_json::from_str(&text)?;
    cfg.get("vault")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .context("bridge config has no vault path")
}

fn default_config_path() -> PathBuf {
    let base = std::env::var("XDG_CONFIG_HOME").map_or_else(
        |_| {
            std::env::var("HOME")
                .map_or_else(|_| PathBuf::from("."), |h| PathBuf::from(h).join(".config"))
        },
        PathBuf::from,
    );
    base.join("glyx").join("config.toml")
}

fn vault_from_config(path: &std::path::Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(path).ok()?;
    let cfg: toml::Value = toml::from_str(&text).ok()?;
    let current = cfg.get("current_vault")?.as_str()?;
    let vault = PathBuf::from(current);
    vault.exists().then_some(vault)
}

pub fn daemon_record(_vault_path: &std::path::Path) -> Result<DaemonRecord> {
    let path = glyx_store::session::session_dir().join("daemon.json");
    let bytes = std::fs::read(&path).context("daemon offline: run glyx daemon start")?;
    serde_json::from_slice(&bytes).context("bad daemon record")
}

pub fn http(
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<(u16, serde_json::Value)> {
    use std::io::BufRead as _;
    let mut stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().expect("loopback"),
        std::time::Duration::from_secs(5),
    )?;
    let body_bytes = body.map(serde_json::to_vec).transpose()?;
    let len = body_bytes.as_ref().map_or(0, Vec::len);
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n"
    );
    if body_bytes.is_some() {
        req.push_str("Content-Type: application/json\r\n");
    }
    FmtWrite::write_fmt(&mut req, format_args!("Content-Length: {len}\r\n\r\n")).expect("header");
    stream.write_all(req.as_bytes())?;
    if let Some(body) = body_bytes {
        stream.write_all(&body)?;
    }
    let mut reader = std::io::BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end().to_owned();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.trim().parse().unwrap_or(0);
            }
        }
    }
    let mut buf = Vec::new();
    if content_length == 0 {
        reader.read_to_end(&mut buf)?;
    } else {
        buf.resize(content_length, 0);
        reader.read_exact(&mut buf)?;
    }
    let json = if buf.is_empty() {
        serde_json::Value::Null
    } else {
        serde_json::from_slice(&buf)?
    };
    Ok((status, json))
}

#[allow(clippy::too_many_lines)]
fn handle(req: &Call) -> Response {
    let rid = req.request_id;
    let fail = |e: anyhow::Error| Response {
        ok: false,
        request_id: rid,
        data: None,
        error: Some(e.to_string()),
    };
    let vault_path = match resolve_vault() {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let record = match daemon_record(&vault_path) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let out = match req.op.as_str() {
        "status" => http(record.port, &record.token, "GET", "/v1/status", None),
        "search" => {
            let q = req.args.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let path = format!("/v1/items?{}", url_query(&[("q", q)]));
            http(record.port, &record.token, "GET", &path, None)
        }
        "fill" => {
            let id = req.args.get("id").and_then(|v| v.as_str()).unwrap_or("");
            http(
                record.port,
                &record.token,
                "GET",
                &format!("/v1/items/{id}?reveal=true"),
                None,
            )
        }
        "totp" => {
            let id = req.args.get("id").and_then(|v| v.as_str()).unwrap_or("");
            http(
                record.port,
                &record.token,
                "GET",
                &format!("/v1/items/{id}/totp"),
                None,
            )
        }
        "lock" => http(record.port, &record.token, "POST", "/v1/lock", None),
        "passkey_lookup" => http(
            record.port,
            &record.token,
            "POST",
            "/v1/passkeys/lookup",
            Some(&req.args),
        ),
        "passkey_create" => http(
            record.port,
            &record.token,
            "POST",
            "/v1/passkeys/create",
            Some(&req.args),
        ),
        "passkey_get" => http(
            record.port,
            &record.token,
            "POST",
            "/v1/passkeys/get",
            Some(&req.args),
        ),
        "login_match" => http(
            record.port,
            &record.token,
            "POST",
            "/v1/logins/match",
            Some(&req.args),
        ),
        "login_save" | "totp_save" => http(
            record.port,
            &record.token,
            "POST",
            "/v1/items",
            Some(&req.args),
        ),
        "login_update" => {
            let id = req.args.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let fields = req
                .args
                .get("fields")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            http(
                record.port,
                &record.token,
                "PATCH",
                &format!("/v1/items/{}", percent_encode(id)),
                Some(&serde_json::json!({"fields": fields})),
            )
        }
        other => return fail(anyhow::anyhow!("unknown op {other}")),
    };
    match out {
        Ok((status, data)) if status < 400 => Response {
            ok: true,
            request_id: rid,
            data: Some(data),
            error: None,
        },
        Ok((status, data)) => fail(anyhow::anyhow!("daemon {status}: {data}")),
        Err(e) => fail(e),
    }
}

fn url_query(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            FmtWrite::write_fmt(&mut out, format_args!("%{b:02X}")).expect("hex");
        }
    }
    out
}

fn read_frame(reader: &mut impl Read) -> Result<Option<serde_json::Value>> {
    let mut len = [0u8; 4];
    match reader.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_le_bytes(len) as usize;
    if len > 1024 * 1024 {
        anyhow::bail!("frame too large");
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(serde_json::from_slice(&buf)?))
}

fn write_frame(writer: &mut impl Write, value: &serde_json::Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    let len = u32::try_from(bytes.len()).context("frame too large")?;
    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&bytes)?;
    writer.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = stdin.lock();
    let mut writer = stdout.lock();
    loop {
        let Some(value) = read_frame(&mut reader)? else {
            break;
        };
        let response = match serde_json::from_value::<Call>(value) {
            Ok(req) => handle(&req),
            Err(e) => Response {
                ok: false,
                request_id: None,
                data: None,
                error: Some(e.to_string()),
            },
        };
        write_frame(&mut writer, &serde_json::to_value(response)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_roundtrip() {
        let value = serde_json::json!({"op": "status", "request_id": 7});
        let mut buf = Vec::new();
        write_frame(&mut buf, &value).expect("write");
        let len = u32::from_le_bytes(buf[..4].try_into().expect("prefix")) as usize;
        assert_eq!(len, buf.len() - 4);
        let back = read_frame(&mut Cursor::new(buf))
            .expect("read")
            .expect("frame");
        assert_eq!(back, value);
    }

    #[test]
    fn frame_eof_ends_cleanly() {
        assert!(read_frame(&mut Cursor::new(Vec::new()))
            .expect("eof")
            .is_none());
    }

    #[test]
    fn frame_rejects_oversize() {
        let mut buf = (10u32 * 1024 * 1024).to_le_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 16]);
        assert!(read_frame(&mut Cursor::new(buf)).is_err());
    }

    #[test]
    fn http_reads_lowercase_content_length() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\n{\"ok\":1}")
                .expect("write");
        });
        let (status, data) = http(port, "token", "GET", "/v1/status", None).expect("http");
        assert_eq!(status, 200);
        assert_eq!(data["ok"], 1);
    }

    #[test]
    fn unknown_op_fails_closed() {
        let res = handle(&Call {
            op: "nope".to_owned(),
            request_id: Some(1),
            args: serde_json::Value::Null,
        });
        assert!(!res.ok);
        assert_eq!(res.request_id, Some(1));
    }

    #[test]
    fn percent_encoding_safe() {
        assert_eq!(percent_encode("example.com"), "example.com");
        assert_eq!(percent_encode("a b+c"), "a%20b%2Bc");
    }
}
