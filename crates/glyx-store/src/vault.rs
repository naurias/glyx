use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use fs2::FileExt as _;
use rusqlite::Connection;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{blob, index, layout, Envelope, EnvelopeHeader, IndexRow, StoreError};

#[derive(Debug, Clone)]
pub struct Vault {
    path: PathBuf,
    config: glyx_core::VaultConfig,
}

impl Vault {
    pub fn init(
        path: &Path,
        suite: glyx_core::CipherSuiteConfig,
        password: &[u8],
        keyfile: &[u8; 32],
    ) -> Result<Self, StoreError> {
        if path.exists() {
            return Err(StoreError::AlreadyExists(path.display().to_string()));
        }
        fs::create_dir_all(path.join(layout::KEYSLOTS_DIR))?;
        fs::create_dir_all(path.join(layout::ITEMS_DIR))?;
        fs::create_dir_all(path.join(layout::BLOBS_DIR))?;
        fs::create_dir_all(path.join(layout::HISTORY_DIR))?;
        let _session = lock_file(path)?;
        let config = glyx_core::VaultConfig::new(Uuid::now_v7(), suite);
        config.validate()?;
        atomic_write(&path.join(layout::VAULT_TOML), config.to_toml()?.as_bytes())?;
        let (key, slot) = glyx_crypto::seal_fresh_vault(password, keyfile, suite.params)?;
        drop(key);
        atomic_write(
            &path.join(layout::KEYSLOTS_DIR).join(slot.filename()),
            serde_json::to_string_pretty(&slot)
                .map_err(|e| StoreError::Corrupt(e.to_string()))?
                .as_bytes(),
        )?;
        let conn = Connection::open(path.join(layout::INDEX_DB))?;
        index::init_schema(&conn)?;
        conn.execute(
            "INSERT INTO meta(key, value) VALUES ('vault_id', ?1)",
            [config.vault_id.as_simple().to_string()],
        )?;
        drop(conn);
        Ok(Self {
            path: path.to_owned(),
            config,
        })
    }
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        let text = fs::read_to_string(path.join(layout::VAULT_TOML))
            .map_err(|e| StoreError::Corrupt(format!("cannot read VAULT.toml: {e}")))?;
        let config = glyx_core::VaultConfig::parse_toml(&text)?;
        for dir in [layout::KEYSLOTS_DIR, layout::ITEMS_DIR, layout::BLOBS_DIR] {
            if !path.join(dir).is_dir() {
                return Err(StoreError::Corrupt(format!("missing dir {dir}")));
            }
        }
        Ok(Self {
            path: path.to_owned(),
            config,
        })
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
    #[must_use]
    pub fn config(&self) -> &glyx_core::VaultConfig {
        &self.config
    }
    pub fn unlock(&self, password: &[u8], keyfile: &[u8; 32]) -> Result<UnlockedVault, StoreError> {
        let dir = fs::read_dir(self.path.join(layout::KEYSLOTS_DIR))?;
        let mut last_err = StoreError::Corrupt("no keyslots found".into());
        for entry in dir.flatten() {
            let bytes = match fs::read(entry.path()) {
                Ok(b) => b,
                Err(e) => {
                    last_err = e.into();
                    continue;
                }
            };
            let slot: glyx_crypto::Keyslot = match serde_json::from_slice(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    last_err = StoreError::Corrupt(e.to_string());
                    continue;
                }
            };
            match slot.unseal(password, keyfile) {
                Ok(key) => {
                    let session = lock_file(&self.path)?;
                    let conn = Connection::open(self.path.join(layout::INDEX_DB))?;
                    index::init_schema(&conn)?;
                    return Ok(UnlockedVault {
                        path: self.path.clone(),
                        config: self.config.clone(),
                        key,
                        conn,
                        _session: session,
                    });
                }
                Err(e) => last_err = e.into(),
            }
        }
        Err(last_err)
    }
    pub fn scan_headers(&self) -> Result<Vec<EnvelopeHeader>, StoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.path.join(layout::ITEMS_DIR))?.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".envelope.json")
            {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let env: Envelope =
                serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            out.push(env.header());
        }
        Ok(out)
    }
    pub fn rebuild_index(&self) -> Result<usize, StoreError> {
        let _session = lock_file(&self.path)?;
        let conn = Connection::open(self.path.join(layout::INDEX_DB))?;
        index::init_schema(&conn)?;
        conn.execute("DELETE FROM items", [])?;
        let mut n = 0;
        for entry in fs::read_dir(self.path.join(layout::ITEMS_DIR))?.flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .ends_with(".envelope.json")
            {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let env: Envelope =
                serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            conn.execute(
                "INSERT INTO items(id, hlc_ms, hlc_seq, node, rev, deleted, item_type, name, updated_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, '', '', 0)",
                rusqlite::params![
                    env.id.as_simple().to_string(),
                    env.hlc.wall_ms.cast_signed(),
                    i64::from(env.hlc.seq),
                    env.hlc.node.0.to_vec(),
                    env.rev.cast_signed(),
                    i64::from(env.deleted),
                ],
            )?;
            n += 1;
        }
        Ok(n)
    }
    pub fn keyslot_count(&self) -> Result<usize, StoreError> {
        Ok(fs::read_dir(self.path.join(layout::KEYSLOTS_DIR))?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
            .count())
    }
}

pub struct UnlockedVault {
    path: PathBuf,
    config: glyx_core::VaultConfig,
    key: Zeroizing<[u8; 32]>,
    conn: Connection,
    _session: fs::File,
}

impl UnlockedVault {
    #[must_use]
    pub fn cipher(&self) -> glyx_core::Cipher {
        self.config.cipher_suite.cipher
    }
    #[must_use]
    pub fn vault_path(&self) -> PathBuf {
        self.path.clone()
    }
    pub fn put_item(&mut self, item: &glyx_core::Item) -> Result<(), StoreError> {
        item.validate()?;
        let env = Envelope::seal(item, &self.key, self.cipher())?;
        atomic_write(
            &self.path.join(layout::ITEMS_DIR).join(env.filename()),
            serde_json::to_string_pretty(&env)
                .map_err(|e| StoreError::Corrupt(e.to_string()))?
                .as_bytes(),
        )?;
        index::upsert(&self.conn, item)?;
        Ok(())
    }
    pub fn get_item(&self, id: &Uuid) -> Result<Option<glyx_core::Item>, StoreError> {
        let file = self
            .path
            .join(layout::ITEMS_DIR)
            .join(format!("{}.envelope.json", id.as_simple()));
        if !file.exists() {
            return Ok(None);
        }
        let env: Envelope = serde_json::from_slice(&fs::read(file)?)
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        Ok(Some(env.open(&self.key)?))
    }
    pub fn list(&self) -> Result<Vec<IndexRow>, StoreError> {
        index::list(&self.conn)
    }
    pub fn put_blob(&self, data: &[u8]) -> Result<String, StoreError> {
        let (addr, bytes) = blob::seal(data, &self.key, self.cipher(), b"glyx-blob-v1")?;
        atomic_write(
            &self
                .path
                .join(layout::BLOBS_DIR)
                .join(format!("{addr}.enc")),
            &bytes,
        )?;
        Ok(addr)
    }
    pub fn get_blob(&self, addr: &str) -> Result<Zeroizing<Vec<u8>>, StoreError> {
        let bytes = fs::read(
            self.path
                .join(layout::BLOBS_DIR)
                .join(format!("{addr}.enc")),
        )?;
        blob::open(&bytes, &self.key, b"glyx-blob-v1")
    }
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("path", &self.path)
            .field("vault_id", &self.config.vault_id)
            .finish_non_exhaustive()
    }
}

pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::File::create(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    fs::rename(&tmp, path)?;
    Ok(())
}

fn lock_file(vault_path: &Path) -> Result<fs::File, StoreError> {
    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(vault_path.join(layout::LOCK_FILE))
        .map_err(|e| StoreError::Corrupt(format!("cannot open lock file: {e}")))?;
    file.lock_exclusive()
        .map_err(|e| StoreError::Corrupt(format!("vault is locked by another process: {e}")))?;
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_item(node: glyx_core::DeviceId) -> glyx_core::Item {
        let mut fields = BTreeMap::new();
        fields.insert(
            "password".to_owned(),
            glyx_core::Field {
                value: glyx_core::SecretString::new("s3cret".to_owned()),
                field_hlc: glyx_core::Hlc {
                    wall_ms: 1,
                    seq: 0,
                    node,
                },
            },
        );
        glyx_core::Item {
            id: Uuid::now_v7(),
            item_type: glyx_core::ItemType::Login,
            name: "example".to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            fields,
            hlc: glyx_core::Hlc {
                wall_ms: 1,
                seq: 0,
                node,
            },
            rev: 1,
            deleted: false,
            updated_by: node,
        }
    }

    fn suite(cipher: glyx_core::Cipher) -> glyx_core::CipherSuiteConfig {
        glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher,
            params: glyx_core::KdfParams::mobile(),
        }
    }

    #[test]
    fn vault_lifecycle_both_ciphers() {
        for cipher in [
            glyx_core::Cipher::Xchacha20poly1305,
            glyx_core::Cipher::Aes256gcm,
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("test.glyx");
            let keyfile = [9u8; 32];
            Vault::init(&path, suite(cipher), b"password", &keyfile).expect("init");
            let vault = Vault::open(&path).expect("open");
            assert!(vault.unlock(b"wrong", &keyfile).is_err());
            let mut unlocked = vault.unlock(b"password", &keyfile).expect("unlock");
            let item = test_item(glyx_core::DeviceId::zero());
            unlocked.put_item(&item).expect("put");
            let back = unlocked.get_item(&item.id).expect("get").expect("found");
            assert_eq!(back.name, "example");
            assert_eq!(back.fields["password"].value.expose(), "s3cret");
            assert_eq!(unlocked.list().expect("list").len(), 1);
            let addr = unlocked.put_blob(b"attachment").expect("put blob");
            assert_eq!(&*unlocked.get_blob(&addr).expect("get blob"), b"attachment");
            drop(unlocked);
            let reopened = Vault::open(&path).expect("reopen");
            assert_eq!(reopened.scan_headers().expect("scan").len(), 1);
            assert_eq!(reopened.rebuild_index().expect("rebuild"), 1);
        }
    }
}
