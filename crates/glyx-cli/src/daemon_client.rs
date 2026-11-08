use std::fmt::Write as _;
use std::io::{BufRead as _, Read as _, Write as _};
use std::net::TcpStream;
use std::time::Duration;

use anyhow::{Context, Result};

pub fn http(
    method: &str,
    path: &str,
    body: Option<&serde_json::Value>,
) -> Result<(u16, serde_json::Value)> {
    let record =
        glyx_daemon::runtime::live_record().context("daemon offline: run `glyx daemon start`")?;
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", record.port)
            .parse()
            .expect("loopback"),
        Duration::from_secs(5),
    )?;
    let body_bytes = body.map(serde_json::to_vec).transpose()?;
    let len = body_bytes.as_ref().map_or(0, Vec::len);
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n",
        record.port, record.token
    );
    if body_bytes.is_some() {
        req.push_str("Content-Type: application/json\r\n");
    }
    write!(req, "Content-Length: {len}\r\n\r\n")?;
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
        let line = line.trim_end();
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

pub fn agent_action(action: &str) -> Result<Option<serde_json::Value>> {
    if glyx_daemon::runtime::live_record().is_none() {
        return Ok(None);
    }
    let (status, body) = http("POST", &format!("/v1/ssh/agent/{action}"), None)?;
    require_ok(status, &body)?;
    Ok(Some(body))
}

pub fn agent_status() -> Result<Option<serde_json::Value>> {
    if glyx_daemon::runtime::live_record().is_none() {
        return Ok(None);
    }
    let (status, body) = http("GET", "/v1/ssh", None)?;
    require_ok(status, &body)?;
    Ok(Some(body))
}

pub fn require_ok(status: u16, body: &serde_json::Value) -> Result<()> {
    if (200..300).contains(&status) {
        return Ok(());
    }
    let message = body
        .get("error")
        .and_then(|value| value.as_str())
        .unwrap_or("daemon request failed");
    anyhow::bail!("{message}")
}
