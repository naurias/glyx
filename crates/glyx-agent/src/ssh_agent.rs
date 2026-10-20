use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use ed25519_dalek::Signer as _;
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum SshAgentError {
    #[error("vault: {0}")]
    Store(#[from] glyx_store::StoreError),
    #[error("key: {0}")]
    Key(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub struct AgentIdentity {
    pub name: String,
    pub public_blob: Vec<u8>,
    pub signing_key: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for AgentIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentIdentity")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn socket_path(vault_id: &Uuid) -> PathBuf {
    glyx_store::session::session_dir().join(format!("glyx-ssh-{}.sock", vault_id.as_simple()))
}

pub fn load_identities(
    uv: &glyx_store::UnlockedVault,
) -> Result<Vec<AgentIdentity>, SshAgentError> {
    let mut out = Vec::new();
    for row in uv.list(false)? {
        if row.item_type != "ssh_key" {
            continue;
        }
        let Some(item) = uv.get_item(&row.id)? else {
            continue;
        };
        let Some(private) = item
            .fields
            .get("private")
            .map(|f| f.value.expose().to_owned())
        else {
            continue;
        };
        let Ok(key) = ssh_key::PrivateKey::from_openssh(&private) else {
            continue;
        };
        let ssh_key::private::KeypairData::Ed25519(pair) = key.key_data() else {
            continue;
        };
        let seed = pair.private.to_bytes();
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let public_blob = key
            .public_key()
            .to_bytes()
            .map_err(|e| SshAgentError::Key(e.to_string()))?;
        out.push(AgentIdentity {
            name: format!("glyx:{}", item.name),
            public_blob,
            signing_key,
        });
    }
    Ok(out)
}

fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(*pos..*pos + 4)?.try_into().ok()?;
    *pos += 4;
    Some(u32::from_be_bytes(bytes))
}

fn read_string(data: &[u8], pos: &mut usize) -> Option<Vec<u8>> {
    let len = read_u32(data, pos)? as usize;
    let out = data.get(*pos..*pos + len)?.to_vec();
    *pos += len;
    Some(out)
}

fn u32len(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32len(bytes.len()).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 5);
    out.extend_from_slice(&u32len(payload.len() + 1).to_be_bytes());
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

fn failure() -> Vec<u8> {
    frame(5, &[])
}

fn handle(identities: &[AgentIdentity], msg: &[u8]) -> Vec<u8> {
    let Some(kind) = msg.first().copied() else {
        return failure();
    };
    match kind {
        11 => {
            let mut payload = Vec::new();
            payload.extend_from_slice(&u32len(identities.len()).to_be_bytes());
            for id in identities {
                put_string(&mut payload, &id.public_blob);
                put_string(&mut payload, id.name.as_bytes());
            }
            frame(12, &payload)
        }
        13 => {
            let mut pos = 1;
            let (Some(blob), Some(data)) = (read_string(msg, &mut pos), read_string(msg, &mut pos))
            else {
                return failure();
            };
            let Some(id) = identities.iter().find(|id| id.public_blob == blob) else {
                return failure();
            };
            let sig = id.signing_key.sign(&data);
            let mut inner = Vec::new();
            put_string(&mut inner, b"ssh-ed25519");
            put_string(&mut inner, &sig.to_bytes());
            let mut payload = Vec::new();
            put_string(&mut payload, &inner);
            frame(14, &payload)
        }
        _ => failure(),
    }
}

fn serve_conn(identities: &[AgentIdentity], stream: &mut UnixStream) {
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            break;
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > 1024 * 1024 {
            break;
        }
        let mut msg = vec![0u8; len];
        if stream.read_exact(&mut msg).is_err() {
            break;
        }
        let reply = handle(identities, &msg);
        if stream.write_all(&reply).is_err() {
            break;
        }
    }
}

pub fn serve(path: &Path, identities: &[AgentIdentity]) -> Result<(), SshAgentError> {
    if path.exists() {
        std::fs::remove_file(path).ok();
    }
    let listener = UnixListener::bind(path)?;
    for stream in listener.incoming().flatten() {
        let mut stream = stream;
        serve_conn(identities, &mut stream);
    }
    Ok(())
}

pub fn serve_until(
    path: &Path,
    identities: &[AgentIdentity],
    stop: &std::sync::atomic::AtomicBool,
) -> Result<(), SshAgentError> {
    if path.exists() {
        std::fs::remove_file(path).ok();
    }
    let listener = UnixListener::bind(path)?;
    listener.set_nonblocking(true)?;
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream.set_nonblocking(false).ok();
                serve_conn(identities, &mut stream);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => return Err(SshAgentError::Io(e)),
        }
    }
    std::fs::remove_file(path).ok();
    Ok(())
}

pub fn stop(path: &Path) {
    std::fs::remove_file(path).ok();
}

#[must_use]
pub fn live_socket() -> Option<PathBuf> {
    let dir = glyx_store::session::session_dir();
    let entries = std::fs::read_dir(dir).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_sock = path.extension().is_some_and(|x| x == "sock")
            && entry.file_name().to_string_lossy().starts_with("glyx-ssh-");
        if !is_sock {
            continue;
        }
        match std::os::unix::net::UnixStream::connect(&path) {
            Ok(_) => return Some(path),
            Err(_) => {
                std::fs::remove_file(&path).ok();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier as _;

    fn framed(kind: u8, payload: &[u8]) -> Vec<u8> {
        frame(kind, payload)
    }

    #[test]
    fn list_and_sign_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vpath = dir.path().join("v.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        glyx_store::Vault::init(&vpath, suite, b"pw", Some(&[2u8; 32])).expect("init");
        let vault = glyx_store::Vault::open(&vpath).expect("open");
        let mut uv = vault.unlock(b"pw", &[2u8; 32]).expect("unlock");
        let pair = glyx_crypto::ssh::generate("ed25519", "test").expect("gen");
        let hlc = uv.next_hlc().expect("tick");
        let node = uv.device_node();
        let mut fields = std::collections::BTreeMap::new();
        for (k, v) in [
            ("private", pair.openssh_private),
            ("public", pair.openssh_public),
        ] {
            fields.insert(
                k.to_owned(),
                glyx_core::Field {
                    value: glyx_core::SecretString::new(v),
                    field_hlc: hlc,
                },
            );
        }
        uv.put_item(&glyx_core::Item {
            id: Uuid::now_v7(),
            item_type: glyx_core::ItemType::SshKey,
            name: "deploy".to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            favorite: false,
            fields,
            hlc,
            rev: 1,
            deleted: false,
            updated_by: node,
        })
        .expect("put");
        let identities = load_identities(&uv).expect("load");
        assert_eq!(identities.len(), 1);
        assert_eq!(identities[0].name, "glyx:deploy");
        let sock = dir.path().join("agent.sock");
        let thread_ids = load_identities(&uv).expect("reload");
        let thread_sock = sock.clone();
        let server = std::thread::spawn(move || {
            let listener = UnixListener::bind(&thread_sock).expect("bind");
            let (mut stream, _) = listener.accept().expect("accept");
            serve_conn(&thread_ids, &mut stream);
        });
        let mut client = UnixStream::connect(&sock).ok();
        for _ in 0..50 {
            if client.is_none() {
                std::thread::sleep(std::time::Duration::from_millis(20));
                client = UnixStream::connect(&sock).ok();
            }
        }
        let mut client = client.expect("connect");
        client.write_all(&framed(11, &[])).expect("list");
        let mut len = [0u8; 4];
        client.read_exact(&mut len).expect("len");
        let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
        client.read_exact(&mut msg).expect("msg");
        assert_eq!(msg[0], 12);
        let mut pos = 1;
        let n = read_u32(&msg, &mut pos).expect("n");
        assert_eq!(n, 1);
        let blob = read_string(&msg, &mut pos).expect("blob");
        assert_eq!(blob, identities[0].public_blob);
        let mut payload = Vec::new();
        put_string(&mut payload, &blob);
        put_string(&mut payload, b"session-data");
        payload.extend_from_slice(&0u32.to_be_bytes());
        client.write_all(&framed(13, &payload)).expect("sign");
        client.read_exact(&mut len).expect("len");
        let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
        client.read_exact(&mut msg).expect("msg");
        assert_eq!(msg[0], 14);
        let mut pos = 1;
        let inner = read_string(&msg, &mut pos).expect("inner");
        let mut ipos = 0;
        let alg = read_string(&inner, &mut ipos).expect("alg");
        let sig = read_string(&inner, &mut ipos).expect("sig");
        assert_eq!(alg, b"ssh-ed25519");
        let verifying = identities[0].signing_key.verifying_key();
        verifying
            .verify(
                b"session-data",
                &ed25519_dalek::Signature::from_slice(&sig).expect("sig"),
            )
            .expect("verify");
        drop(client);
        server.join().expect("server");
    }

    #[test]
    fn unknown_key_fails() {
        let reply = handle(&[], &[13, 0]);
        assert_eq!(reply[4], 5);
        let reply = handle(&[], &[11]);
        assert_eq!(reply[4], 12);
    }
}
