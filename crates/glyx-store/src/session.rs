use std::path::PathBuf;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::StoreError;

pub const SESSION_PREFIX: &str = "session-";
pub const SESSION_TTL_DEFAULT_MIN: u64 = 15;
pub const SESSION_TTL_MAX_MIN: u64 = 480;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TicketFile {
    vault_id: Uuid,
    expiry_ms: u64,
    mode: String,
    salt_b64: String,
    nonce_b64: String,
    wrapped_b64: String,
}

#[must_use]
pub fn session_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("GLYX_RUNTIME_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("glyx");
    }
    std::env::temp_dir().join("glyx-sessions")
}

#[must_use]
pub fn session_path(vault_id: &Uuid) -> PathBuf {
    session_dir().join(format!("{SESSION_PREFIX}{}.json", vault_id.as_simple()))
}

fn write_file(ticket: &TicketFile) -> Result<(), StoreError> {
    let dir = session_dir();
    std::fs::create_dir_all(&dir)?;
    let path = session_path(&ticket.vault_id);
    std::fs::write(
        &path,
        serde_json::to_vec(ticket).map_err(|e| StoreError::Corrupt(e.to_string()))?,
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn expiry(ttl_min: u64) -> u64 {
    let ttl = ttl_min.clamp(1, SESSION_TTL_MAX_MIN);
    glyx_core::ids::wall_ms_now().saturating_add(ttl.saturating_mul(60_000))
}

pub fn seal_pin_ticket(
    vault_id: Uuid,
    data_key: &[u8; 32],
    pin: &[u8],
    ttl_min: u64,
) -> Result<(), StoreError> {
    let salt = glyx_crypto::generate_salt()?;
    let kek = glyx_crypto::derive_kek(pin, &[0u8; 32], &salt, glyx_core::KdfParams::mobile())?;
    let ct = glyx_crypto::encrypt(
        glyx_core::Cipher::Xchacha20poly1305,
        &kek,
        data_key,
        b"glyx-session-v1",
    )?;
    write_file(&TicketFile {
        vault_id,
        expiry_ms: expiry(ttl_min),
        mode: "pin".to_owned(),
        salt_b64: STANDARD.encode(salt),
        nonce_b64: STANDARD.encode(&ct.nonce),
        wrapped_b64: STANDARD.encode(&ct.ct),
    })
}

pub fn write_plain_ticket(
    vault_id: Uuid,
    data_key: &[u8; 32],
    ttl_min: u64,
) -> Result<(), StoreError> {
    write_file(&TicketFile {
        vault_id,
        expiry_ms: expiry(ttl_min),
        mode: "plain".to_owned(),
        salt_b64: String::new(),
        nonce_b64: String::new(),
        wrapped_b64: STANDARD.encode(data_key),
    })
}

pub fn open_ticket(
    vault_id: &Uuid,
    pin: Option<&[u8]>,
) -> Result<Option<Zeroizing<[u8; 32]>>, StoreError> {
    let path = session_path(vault_id);
    if !path.exists() {
        return Ok(None);
    }
    let ticket: TicketFile = serde_json::from_slice(&std::fs::read(&path)?)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    if ticket.vault_id != *vault_id || ticket.expiry_ms <= glyx_core::ids::wall_ms_now() {
        std::fs::remove_file(&path).ok();
        return Ok(None);
    }
    if ticket.mode == "plain" && pin.is_none() {
        let raw = STANDARD
            .decode(&ticket.wrapped_b64)
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        if raw.len() != 32 {
            return Ok(None);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&raw);
        return Ok(Some(Zeroizing::new(key)));
    }
    let Some(pin) = pin else {
        return Ok(None);
    };
    let salt: [u8; 16] = STANDARD
        .decode(&ticket.salt_b64)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?
        .try_into()
        .map_err(|_| StoreError::Corrupt("bad session salt".into()))?;
    let nonce = STANDARD
        .decode(&ticket.nonce_b64)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let wrapped = STANDARD
        .decode(&ticket.wrapped_b64)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let kek = glyx_crypto::derive_kek(pin, &[0u8; 32], &salt, glyx_core::KdfParams::mobile())?;
    match glyx_crypto::decrypt(
        glyx_core::Cipher::Xchacha20poly1305,
        &kek,
        &nonce,
        &wrapped,
        b"glyx-session-v1",
    ) {
        Ok(pt) => {
            if pt.len() != 32 {
                return Ok(None);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&pt);
            Ok(Some(Zeroizing::new(key)))
        }
        Err(_) => Ok(None),
    }
}

pub fn wipe_ticket(vault_id: &Uuid) {
    std::fs::remove_file(session_path(vault_id)).ok();
}

#[must_use]
pub fn wipe_all() -> usize {
    let dir = session_dir();
    let mut n = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let is_ticket = entry.path().extension().is_some_and(|e| e == "json")
                && entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(SESSION_PREFIX)
                && std::fs::remove_file(entry.path()).is_ok();
            if is_ticket {
                n += 1;
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guard() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::env::set_var("GLYX_RUNTIME_DIR", dir.path());
        dir
    }

    #[test]
    fn ticket_roundtrips_wipe_and_reject() {
        let _g = guard();
        let plain = Uuid::now_v7();
        write_plain_ticket(plain, &[7u8; 32], 30).expect("write");
        let back = open_ticket(&plain, None).expect("open").expect("found");
        assert_eq!(&*back, &[7u8; 32]);
        let pinned = Uuid::now_v7();
        seal_pin_ticket(pinned, &[8u8; 32], b"1234", 30).expect("seal");
        assert!(open_ticket(&pinned, None).expect("open").is_none());
        let back = open_ticket(&pinned, Some(b"1234"))
            .expect("open")
            .expect("found");
        assert_eq!(&*back, &[8u8; 32]);
        assert!(open_ticket(&pinned, Some(b"wrong"))
            .expect("open")
            .is_none());
        wipe_ticket(&plain);
        assert!(open_ticket(&plain, None).expect("open").is_none());
        assert_eq!(wipe_all(), 1);
        assert!(open_ticket(&pinned, Some(b"1234")).expect("open").is_none());
    }
}
