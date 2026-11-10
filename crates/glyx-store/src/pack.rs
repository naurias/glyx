use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::StoreError;

pub const CONTAINER_VERSION: u32 = 1;
pub const SLOT_SIZE: usize = 32 * 1024;
pub const DATA_START: u64 = (SLOT_SIZE as u64) * 2;
const DATA_START_USIZE: usize = SLOT_SIZE * 2;
const MAGIC: &[u8; 8] = b"GLYXPK01";
const SLOT_HEADER_LEN: usize = 84;
const MAX_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;
const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub container_version: u32,
    pub config: glyx_core::VaultConfig,
    pub keyslots: Vec<glyx_crypto::Keyslot>,
    pub manifest: ManifestRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRef {
    pub offset: u64,
    pub len: u64,
    pub nonce_b64: String,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub v: u32,
    pub generation: u64,
    pub entries: BTreeMap<String, EntryRef>,
    #[serde(default)]
    pub meta: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryRef {
    pub offset: u64,
    pub len: u64,
}

pub struct Pack {
    path: PathBuf,
    file: Mutex<File>,
    header: Header,
    manifest: Manifest,
    key: Zeroizing<[u8; 32]>,
    slot_generation: u64,
}

impl std::fmt::Debug for Pack {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Pack")
            .field("path", &self.path)
            .field("entries", &self.manifest.entries.len())
            .field("generation", &self.manifest.generation)
            .finish_non_exhaustive()
    }
}

impl Pack {
    pub fn create(
        path: &Path,
        config: glyx_core::VaultConfig,
        keyslots: Vec<glyx_crypto::Keyslot>,
        key: &[u8; 32],
    ) -> Result<Self, StoreError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&vec![0u8; DATA_START_USIZE])?;
        let manifest = Manifest {
            v: MANIFEST_VERSION,
            generation: 1,
            entries: BTreeMap::new(),
            meta: BTreeMap::new(),
        };
        let cipher = config.cipher_suite.cipher;
        let aad = manifest_aad(&config, 1);
        let ct = glyx_crypto::encrypt(cipher, key, &manifest_bytes(&manifest)?, &aad)?;
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&ct.ct)?;
        let manifest_ref = ManifestRef {
            offset,
            len: u64::try_from(ct.ct.len()).unwrap_or(u64::MAX),
            nonce_b64: STANDARD.encode(&ct.nonce),
            generation: 1,
        };
        let header = Header {
            container_version: CONTAINER_VERSION,
            config,
            keyslots,
            manifest: manifest_ref,
        };
        write_slot(&mut file, 0, 1, &header)?;
        file.sync_all()?;
        sync_parent(path);
        Ok(Self {
            path: path.to_owned(),
            file: Mutex::new(file),
            header,
            manifest,
            key: Zeroizing::new(*key),
            slot_generation: 1,
        })
    }

    pub fn open(path: &Path, header: Header, key: &[u8; 32]) -> Result<Self, StoreError> {
        let mut options = OpenOptions::new();
        options.read(true).write(true);
        let file = options.open(path)?;
        let manifest = decrypt_manifest(&file, &header, key)?;
        if manifest.v != MANIFEST_VERSION {
            return Err(StoreError::Corrupt(format!(
                "pack manifest v{}, max supported is {MANIFEST_VERSION}",
                manifest.v
            )));
        }
        if manifest.generation != header.manifest.generation {
            return Err(StoreError::Corrupt(
                "pack manifest generation mismatch".into(),
            ));
        }
        let slot_generation = newest_slot_generation(&file)?.unwrap_or(1);
        Ok(Self {
            path: path.to_owned(),
            file: Mutex::new(file),
            header,
            manifest,
            key: Zeroizing::new(*key),
            slot_generation,
        })
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn header(&self) -> &Header {
        &self.header
    }

    #[must_use]
    pub fn config(&self) -> &glyx_core::VaultConfig {
        &self.header.config
    }

    pub fn set_config(&mut self, config: glyx_core::VaultConfig) {
        self.header.config = config;
    }

    #[must_use]
    pub fn keyslots(&self) -> &[glyx_crypto::Keyslot] {
        &self.header.keyslots
    }

    pub fn set_keyslots(&mut self, keyslots: Vec<glyx_crypto::Keyslot>) {
        self.header.keyslots = keyslots;
    }

    pub fn read_entry(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        let entry = self
            .manifest
            .entries
            .get(key)
            .ok_or_else(|| StoreError::NotFound(key.to_owned()))?;
        if entry.len > MAX_ENTRY_BYTES {
            return Err(StoreError::Limit(format!("pack entry {key} is too large")));
        }
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        file.seek(SeekFrom::Start(entry.offset))?;
        let mut out = vec![0u8; usize::try_from(entry.len).unwrap_or(0)];
        file.read_exact(&mut out)?;
        Ok(out)
    }

    #[must_use]
    pub fn has_entry(&self, key: &str) -> bool {
        self.manifest.entries.contains_key(key)
    }

    #[must_use]
    pub fn entry_len(&self, key: &str) -> Option<u64> {
        self.manifest.entries.get(key).map(|entry| entry.len)
    }

    #[must_use]
    pub fn list_entries(&self, prefix: &str) -> Vec<String> {
        self.manifest
            .entries
            .keys()
            .filter(|key| key.starts_with(prefix))
            .cloned()
            .collect()
    }

    pub fn append_entry(&mut self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len > MAX_ENTRY_BYTES {
            return Err(StoreError::Limit(format!("pack entry {key} is too large")));
        }
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(bytes)?;
        self.manifest
            .entries
            .insert(key.to_owned(), EntryRef { offset, len });
        Ok(())
    }

    pub fn remove_entry(&mut self, key: &str) {
        self.manifest.entries.remove(key);
    }

    pub fn set_meta(&mut self, key: &str, value: &str) {
        self.manifest.meta.insert(key.to_owned(), value.to_owned());
    }

    #[must_use]
    pub fn meta(&self, key: &str) -> Option<&str> {
        self.manifest.meta.get(key).map(String::as_str)
    }

    pub fn commit(&mut self) -> Result<(), StoreError> {
        let generation = self.manifest.generation.saturating_add(1);
        self.manifest.generation = generation;
        let cipher = self.header.config.cipher_suite.cipher;
        let aad = manifest_aad(&self.header.config, generation);
        let ct = glyx_crypto::encrypt(cipher, &self.key, &manifest_bytes(&self.manifest)?, &aad)?;
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let offset = file.seek(SeekFrom::End(0))?;
        file.write_all(&ct.ct)?;
        self.header.manifest = ManifestRef {
            offset,
            len: u64::try_from(ct.ct.len()).unwrap_or(u64::MAX),
            nonce_b64: STANDARD.encode(&ct.nonce),
            generation,
        };
        self.slot_generation = self.slot_generation.saturating_add(1);
        let slot = usize::from(self.slot_generation.is_multiple_of(2));
        write_slot(&mut file, slot, self.slot_generation, &self.header)?;
        file.sync_all()?;
        sync_parent(&self.path);
        Ok(())
    }

    pub fn write_header(&mut self) -> Result<(), StoreError> {
        self.slot_generation = self.slot_generation.saturating_add(1);
        let slot = usize::from(self.slot_generation.is_multiple_of(2));
        let mut file = self
            .file
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        write_slot(&mut file, slot, self.slot_generation, &self.header)?;
        file.sync_all()?;
        sync_parent(&self.path);
        Ok(())
    }

    pub fn compact(&mut self) -> Result<(), StoreError> {
        let parent = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("vault.glyx");
        let tmp = parent.join(format!(".{name}.compact-{}", std::process::id()));
        let result = (|| {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt as _;
                options.mode(0o600);
            }
            let mut new_file = options.open(&tmp)?;
            new_file.write_all(&vec![0u8; DATA_START_USIZE])?;
            let mut entries = BTreeMap::new();
            for key in self.manifest.entries.keys().cloned().collect::<Vec<_>>() {
                let bytes = self.read_entry(&key)?;
                let offset = new_file.seek(SeekFrom::End(0))?;
                new_file.write_all(&bytes)?;
                entries.insert(
                    key,
                    EntryRef {
                        offset,
                        len: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                    },
                );
            }
            let mut manifest = self.manifest.clone();
            manifest.entries = entries;
            manifest.generation = manifest.generation.saturating_add(1);
            let cipher = self.header.config.cipher_suite.cipher;
            let aad = manifest_aad(&self.header.config, manifest.generation);
            let ct = glyx_crypto::encrypt(cipher, &self.key, &manifest_bytes(&manifest)?, &aad)?;
            let offset = new_file.seek(SeekFrom::End(0))?;
            new_file.write_all(&ct.ct)?;
            let manifest_ref = ManifestRef {
                offset,
                len: u64::try_from(ct.ct.len()).unwrap_or(u64::MAX),
                nonce_b64: STANDARD.encode(&ct.nonce),
                generation: manifest.generation,
            };
            let header = Header {
                container_version: self.header.container_version,
                config: self.header.config.clone(),
                keyslots: self.header.keyslots.clone(),
                manifest: manifest_ref,
            };
            let new_generation = self.slot_generation.saturating_add(1);
            write_slot(&mut new_file, 0, new_generation, &header)?;
            write_slot(&mut new_file, 1, new_generation, &header)?;
            new_file.sync_all()?;
            drop(new_file);
            fs::rename(&tmp, &self.path)?;
            sync_parent(&self.path);
            crate::vault::harden_file(&self.path);
            let reopened = OpenOptions::new().read(true).write(true).open(&self.path)?;
            self.file = Mutex::new(reopened);
            self.header = header;
            self.manifest = manifest;
            self.slot_generation = new_generation;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result
    }
}

pub fn read_header(path: &Path) -> Result<Header, StoreError> {
    let mut file = File::open(path)?;
    if file.metadata()?.len() < DATA_START {
        return Err(StoreError::Corrupt(
            "not a glyx single-file vault; directory vaults are no longer supported".into(),
        ));
    }
    let mut best: Option<(u64, Header)> = None;
    for slot in 0..2 {
        if let Some((generation, header)) = read_slot(&mut file, slot)? {
            if best
                .as_ref()
                .is_none_or(|(best_generation, _)| generation > *best_generation)
            {
                best = Some((generation, header));
            }
        }
    }
    best.map(|(_, header)| header).ok_or_else(|| {
        StoreError::Corrupt(
            "not a glyx single-file vault; directory vaults are no longer supported".into(),
        )
    })
}

fn newest_slot_generation(file: &File) -> Result<Option<u64>, StoreError> {
    let mut file = file.try_clone()?;
    let mut newest = None;
    for slot in 0..2 {
        if let Some((generation, _)) = read_slot(&mut file, slot)? {
            newest = Some(newest.map_or(generation, |value: u64| value.max(generation)));
        }
    }
    Ok(newest)
}

fn read_slot(file: &mut File, slot: usize) -> Result<Option<(u64, Header)>, StoreError> {
    file.seek(SeekFrom::Start((slot * SLOT_SIZE) as u64))?;
    let mut raw = vec![0u8; SLOT_SIZE];
    file.read_exact(&mut raw)?;
    if &raw[..8] != MAGIC {
        return Ok(None);
    }
    let len = u32::from_le_bytes(raw[8..12].try_into().unwrap_or([0; 4])) as usize;
    let generation = u64::from_le_bytes(raw[12..20].try_into().unwrap_or([0; 8]));
    if len == 0 || generation == 0 || SLOT_HEADER_LEN.saturating_add(len) > SLOT_SIZE {
        return Ok(None);
    }
    let checksum = String::from_utf8_lossy(&raw[20..84]);
    let json = &raw[SLOT_HEADER_LEN..SLOT_HEADER_LEN + len];
    if glyx_crypto::blake3_hex(json) != checksum {
        return Ok(None);
    }
    let header: Header = match serde_json::from_slice(json) {
        Ok(header) => header,
        Err(_) => return Ok(None),
    };
    if header.container_version != CONTAINER_VERSION {
        return Err(StoreError::Corrupt(format!(
            "pack container v{}, max supported is {CONTAINER_VERSION}",
            header.container_version
        )));
    }
    header.config.validate()?;
    Ok(Some((generation, header)))
}

fn write_slot(
    file: &mut File,
    slot: usize,
    generation: u64,
    header: &Header,
) -> Result<(), StoreError> {
    let json = serde_json::to_vec(header).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    if SLOT_HEADER_LEN.saturating_add(json.len()) > SLOT_SIZE {
        return Err(StoreError::Corrupt("vault header is too large".into()));
    }
    let mut raw = vec![0u8; SLOT_SIZE];
    raw[..8].copy_from_slice(MAGIC);
    raw[8..12].copy_from_slice(&u32::try_from(json.len()).unwrap_or(0).to_le_bytes());
    raw[12..20].copy_from_slice(&generation.to_le_bytes());
    raw[20..84].copy_from_slice(glyx_crypto::blake3_hex(&json).as_bytes());
    raw[SLOT_HEADER_LEN..SLOT_HEADER_LEN + json.len()].copy_from_slice(&json);
    file.seek(SeekFrom::Start((slot * SLOT_SIZE) as u64))?;
    file.write_all(&raw)?;
    Ok(())
}

fn decrypt_manifest(file: &File, header: &Header, key: &[u8; 32]) -> Result<Manifest, StoreError> {
    let mut file = file.try_clone()?;
    file.seek(SeekFrom::Start(header.manifest.offset))?;
    let len = usize::try_from(header.manifest.len)
        .map_err(|_| StoreError::Corrupt("pack manifest is too large".into()))?;
    if len == 0 || len > 64 * 1024 * 1024 {
        return Err(StoreError::Corrupt(
            "pack manifest length is invalid".into(),
        ));
    }
    let mut ct = vec![0u8; len];
    file.read_exact(&mut ct)?;
    let nonce = STANDARD
        .decode(&header.manifest.nonce_b64)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let aad = manifest_aad(&header.config, header.manifest.generation);
    let plain = glyx_crypto::decrypt(header.config.cipher_suite.cipher, key, &nonce, &ct, &aad)?;
    serde_json::from_slice(&plain).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn manifest_bytes(manifest: &Manifest) -> Result<Vec<u8>, StoreError> {
    serde_json::to_vec(manifest).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn manifest_aad(config: &glyx_core::VaultConfig, generation: u64) -> Vec<u8> {
    let cipher = match config.cipher_suite.cipher {
        glyx_core::Cipher::Xchacha20poly1305 => "xchacha20poly1305",
        glyx_core::Cipher::Aes256gcm => "aes256gcm",
    };
    format!(
        "glyx-manifest-v1:{}:{}:{cipher}",
        config.vault_id, generation
    )
    .into_bytes()
}

fn sync_parent(path: &Path) {
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite() -> glyx_core::CipherSuiteConfig {
        glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        }
    }

    fn create_pack(dir: &Path) -> (PathBuf, [u8; 32], Header) {
        let path = dir.join("v.glyx");
        let (key, slot) =
            glyx_crypto::seal_fresh_vault(b"pw", &[0u8; 32], suite().params).expect("seal");
        let config = glyx_core::VaultConfig::new(uuid::Uuid::now_v7(), suite(), false);
        let pack = Pack::create(&path, config, vec![slot], &key).expect("create");
        let header = pack.header().clone();
        (path, *key, header)
    }

    #[test]
    fn roundtrips_entries_and_meta() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, key, header) = create_pack(dir.path());
        {
            let mut pack = Pack::open(&path, header.clone(), &key).expect("open");
            pack.append_entry("items/a.envelope.json", b"alpha")
                .expect("a");
            pack.append_entry("blobs/b.enc", b"beta").expect("b");
            pack.set_meta("last_merge_ms", "123");
            pack.commit().expect("commit");
        }
        let pack = Pack::open(&path, read_header(&path).expect("header"), &key).expect("reopen");
        assert_eq!(
            pack.read_entry("items/a.envelope.json").expect("a"),
            b"alpha"
        );
        assert_eq!(pack.read_entry("blobs/b.enc").expect("b"), b"beta");
        assert_eq!(pack.meta("last_merge_ms"), Some("123"));
        assert_eq!(pack.list_entries("items/"), vec!["items/a.envelope.json"]);
        assert!(pack.has_entry("blobs/b.enc"));
        assert_eq!(pack.entry_len("blobs/b.enc"), Some(4));
        assert!(pack.read_entry("missing").is_err());
    }

    #[test]
    fn overwrite_append_keeps_latest_value() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, key, header) = create_pack(dir.path());
        let mut pack = Pack::open(&path, header, &key).expect("open");
        pack.append_entry("k", b"old").expect("old");
        pack.commit().expect("commit old");
        pack.append_entry("k", b"new").expect("new");
        pack.commit().expect("commit new");
        let mut pack =
            Pack::open(&path, read_header(&path).expect("header"), &key).expect("reopen");
        assert_eq!(pack.read_entry("k").expect("k"), b"new");
        pack.compact().expect("compact");
        let pack = Pack::open(&path, read_header(&path).expect("header"), &key).expect("reopen");
        assert_eq!(pack.read_entry("k").expect("k"), b"new");
    }

    #[test]
    fn wrong_key_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _key, header) = create_pack(dir.path());
        let other = [9u8; 32];
        let err = Pack::open(&path, header, &other).expect_err("wrong key");
        assert!(matches!(err, StoreError::Crypto(_)), "{err:?}");
    }

    #[test]
    fn tampered_manifest_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, key, header) = create_pack(dir.path());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open raw");
        file.seek(SeekFrom::Start(header.manifest.offset))
            .expect("seek");
        let mut byte = [0u8; 1];
        file.read_exact(&mut byte).expect("read");
        byte[0] ^= 0xff;
        file.seek(SeekFrom::Start(header.manifest.offset))
            .expect("seek");
        file.write_all(&byte).expect("write");
        file.sync_all().expect("sync");
        let err = Pack::open(&path, read_header(&path).expect("header"), &key).expect_err("tamper");
        assert!(matches!(err, StoreError::Crypto(_)), "{err:?}");
    }

    #[test]
    fn torn_header_write_falls_back_to_older_slot() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, key, header) = create_pack(dir.path());
        let mut pack = Pack::open(&path, header, &key).expect("open");
        pack.append_entry("k", b"v1").expect("v1");
        pack.commit().expect("commit 1");
        pack.append_entry("k", b"v2").expect("v2");
        pack.commit().expect("commit 2");
        let newest = read_header(&path).expect("header").manifest.generation;
        // Corrupt the newest slot: find which slot holds it.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open raw");
        for slot in 0..2 {
            file.seek(SeekFrom::Start((slot * SLOT_SIZE) as u64 + 12))
                .expect("seek");
            let mut generation = [0u8; 8];
            file.read_exact(&mut generation).expect("read");
            if u64::from_le_bytes(generation) == newest {
                file.seek(SeekFrom::Start((slot * SLOT_SIZE) as u64 + 20))
                    .expect("seek checksum");
                file.write_all(b"0000000000000000000000000000000000000000000000000000000000000000")
                    .expect("corrupt checksum");
            }
        }
        file.sync_all().expect("sync");
        let recovered = read_header(&path).expect("recover older slot");
        assert!(recovered.manifest.generation < newest);
        let pack = Pack::open(&path, recovered, &key).expect("open older");
        assert_eq!(pack.read_entry("k").expect("k"), b"v1");
    }

    #[test]
    fn compact_mirrors_the_header_into_both_slots() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, key, header) = create_pack(dir.path());
        let mut pack = Pack::open(&path, header, &key).expect("open");
        pack.append_entry("k", b"v").expect("entry");
        pack.commit().expect("commit");
        pack.compact().expect("compact");
        // Corrupt slot 0; slot 1 must still hold the same header.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .expect("open raw");
        file.seek(SeekFrom::Start(20)).expect("seek checksum");
        file.write_all(b"0000000000000000000000000000000000000000000000000000000000000000")
            .expect("corrupt checksum");
        file.sync_all().expect("sync");
        let recovered = read_header(&path).expect("mirror header");
        let pack = Pack::open(&path, recovered, &key).expect("reopen");
        assert_eq!(pack.read_entry("k").expect("k"), b"v");
    }

    #[test]
    fn rejects_non_container_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.glyx");
        fs::write(&path, b"not a vault").expect("write");
        let err = read_header(&path).expect_err("bad file");
        assert!(err.to_string().contains("single-file"), "{err}");
    }

    #[test]
    fn compact_preserves_meta_and_drops_dead_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, key, header) = create_pack(dir.path());
        let mut pack = Pack::open(&path, header, &key).expect("open");
        pack.append_entry("keep", b"keep").expect("keep");
        pack.append_entry("drop", b"drop").expect("drop");
        pack.set_meta("m", "v");
        pack.commit().expect("commit");
        pack.remove_entry("drop");
        pack.commit().expect("commit remove");
        let before = fs::metadata(&path).expect("meta").len();
        pack.compact().expect("compact");
        let after = fs::metadata(&path).expect("meta").len();
        assert!(after < before, "compaction should shrink the file");
        let pack = Pack::open(&path, read_header(&path).expect("header"), &key).expect("reopen");
        assert_eq!(pack.read_entry("keep").expect("keep"), b"keep");
        assert!(!pack.has_entry("drop"));
        assert_eq!(pack.meta("m"), Some("v"));
    }
}
