use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use fs2::FileExt as _;
use rusqlite::{Connection, OptionalExtension as _};
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
        fs::create_dir_all(path.join(layout::CONFLICTS_DIR))?;
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
                Ok(key) => return self.finish_unlock(key),
                Err(e) => last_err = e.into(),
            }
        }
        Err(last_err)
    }
    pub fn scan_headers(&self) -> Result<Vec<EnvelopeHeader>, StoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.path.join(layout::ITEMS_DIR))?.flatten() {
            if !is_envelope_file(&entry.path()) {
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
            if !is_envelope_file(&entry.path()) {
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
            .filter(|e| has_extension(&e.path(), "json"))
            .count())
    }
    pub fn device_id(&self) -> Result<glyx_core::DeviceId, StoreError> {
        let file = self.path.join("device.id");
        if file.exists() {
            let raw = fs::read(&file)?;
            if let Ok(bytes) = <[u8; 16]>::try_from(raw) {
                return Ok(glyx_core::DeviceId(bytes));
            }
        }
        let id = glyx_core::DeviceId::generate();
        atomic_write(&file, &id.0)?;
        Ok(id)
    }
    pub fn verify_slot(
        &self,
        id: &Uuid,
        password: &[u8],
        keyfile: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let bytes = fs::read(
            self.path
                .join(layout::KEYSLOTS_DIR)
                .join(format!("slot-{}.json", id.as_simple())),
        )?;
        let slot: glyx_crypto::Keyslot =
            serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        match slot.unseal(password, keyfile) {
            Ok(_) => Ok(true),
            Err(glyx_crypto::CryptoError::Decrypt) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
    pub fn open_session(&self, pin: Option<&[u8]>) -> Result<Option<UnlockedVault>, StoreError> {
        match crate::session::open_ticket(&self.config.vault_id, pin)? {
            Some(key) => Ok(Some(self.finish_unlock(key)?)),
            None => Ok(None),
        }
    }
    fn finish_unlock(&self, key: Zeroizing<[u8; 32]>) -> Result<UnlockedVault, StoreError> {
        let node = self.device_id()?;
        let session = lock_file(&self.path)?;
        let conn = Connection::open(self.path.join(layout::INDEX_DB))?;
        index::init_schema(&conn)?;
        let mut uv = UnlockedVault {
            path: self.path.clone(),
            config: self.config.clone(),
            key,
            conn,
            node,
            _session: session,
        };
        let healed = uv.heal_conflict_files()?;
        if healed.healed > 0 {
            uv.stamp_merge()?;
        }
        Ok(uv)
    }
}

pub struct UnlockedVault {
    path: PathBuf,
    config: glyx_core::VaultConfig,
    key: Zeroizing<[u8; 32]>,
    conn: Connection,
    node: glyx_core::DeviceId,
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
    #[must_use]
    pub fn device_node(&self) -> glyx_core::DeviceId {
        self.node
    }
    pub fn put_item(&mut self, item: &glyx_core::Item) -> Result<(), StoreError> {
        item.validate()?;
        if has_conflict_files(&self.path) {
            self.heal_conflict_files()?;
            self.stamp_merge()?;
        }
        let env = Envelope::seal(item, &self.key, self.cipher())?;
        let target = self.path.join(layout::ITEMS_DIR).join(env.filename());
        if target.exists() {
            let old = fs::read(&target)?;
            let dir = self
                .path
                .join(layout::HISTORY_DIR)
                .join(item.id.as_simple().to_string());
            fs::create_dir_all(&dir)?;
            atomic_write(
                &dir.join(format!("{}-{}.json", item.hlc.wall_ms, item.hlc.seq)),
                &old,
            )?;
        }
        atomic_write(
            &target,
            serde_json::to_string_pretty(&env)
                .map_err(|e| StoreError::Corrupt(e.to_string()))?
                .as_bytes(),
        )?;
        index::upsert(&self.conn, item)?;
        Ok(())
    }
    pub fn resolve(&self, query: &str) -> Result<glyx_core::Item, StoreError> {
        if let Ok(id) = query.parse::<Uuid>() {
            return self
                .get_item(&id)?
                .ok_or_else(|| StoreError::NotFound(query.to_owned()));
        }
        let rows = self.list(true)?;
        let live: Vec<_> = rows.iter().filter(|r| !r.deleted).collect();
        let mut hits = Vec::new();
        for row in &live {
            if row.id.as_simple().to_string().starts_with(query) {
                hits.push(row.id);
            }
        }
        if hits.len() == 1 {
            return self
                .get_item(&hits[0])?
                .ok_or_else(|| StoreError::NotFound(query.to_owned()));
        }
        if hits.len() > 1 {
            return Err(StoreError::Ambiguous(query.to_owned(), hits.len()));
        }
        let mut named = Vec::new();
        for row in &live {
            if row.name == query {
                named.push(row.id);
            }
        }
        if named.len() == 1 {
            return self
                .get_item(&named[0])?
                .ok_or_else(|| StoreError::NotFound(query.to_owned()));
        }
        if named.is_empty() {
            let dead = rows.len() - live.len();
            if dead > 0 {
                return Err(StoreError::NotFound(format!("{query} ({dead} deleted)")));
            }
            return Err(StoreError::NotFound(query.to_owned()));
        }
        Err(StoreError::Ambiguous(query.to_owned(), named.len()))
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
    pub fn list(&self, include_deleted: bool) -> Result<Vec<IndexRow>, StoreError> {
        index::list(&self.conn, include_deleted)
    }
    pub fn next_hlc(&mut self) -> Result<glyx_core::Hlc, StoreError> {
        let last_ms: i64 = self.meta_get("hlc_ms")?.unwrap_or(0);
        let last_seq: i64 = self.meta_get("hlc_seq")?.unwrap_or(0);
        let now = glyx_core::ids::wall_ms_now().cast_signed();
        let (wall, seq) = if now <= last_ms {
            (last_ms, last_seq.saturating_add(1))
        } else {
            (now, 0)
        };
        self.meta_set("hlc_ms", wall)?;
        self.meta_set("hlc_seq", seq)?;
        Ok(glyx_core::Hlc {
            wall_ms: u64::try_from(wall).unwrap_or(0),
            seq: u16::try_from(seq).unwrap_or(u16::MAX),
            node: self.node,
        })
    }
    pub fn delete_item(&mut self, id: &Uuid) -> Result<bool, StoreError> {
        let Some(mut item) = self.get_item(id)? else {
            return Ok(false);
        };
        if item.deleted {
            return Ok(true);
        }
        item.deleted = true;
        item.hlc = self.next_hlc()?;
        item.rev = item.rev.saturating_add(1);
        item.updated_by = self.node;
        self.put_item(&item)?;
        Ok(true)
    }
    fn meta_get(&self, key: &str) -> Result<Option<i64>, StoreError> {
        let v: Option<String> = self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
            .optional()
            .map_err(StoreError::from)?;
        v.map(|s| {
            s.parse::<i64>()
                .map_err(|_| StoreError::Corrupt(format!("bad meta {key}")))
        })
        .transpose()
    }
    fn meta_set(&self, key: &str, value: i64) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            rusqlite::params![key, value.to_string()],
        )?;
        Ok(())
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
    pub fn write_plain_session(&self, ttl_min: u64) -> Result<(), StoreError> {
        crate::session::write_plain_ticket(self.config.vault_id, &self.key, ttl_min)
    }
    pub fn seal_pin_session(&self, pin: &[u8], ttl_min: u64) -> Result<(), StoreError> {
        crate::session::seal_pin_ticket(self.config.vault_id, &self.key, pin, ttl_min)
    }
    pub fn add_slot(&self, password: &[u8], keyfile: &[u8; 32]) -> Result<Uuid, StoreError> {
        self.add_slot_with_params(password, keyfile, self.config.cipher_suite.params)
    }
    pub fn add_slot_with_params(
        &self,
        password: &[u8],
        keyfile: &[u8; 32],
        params: glyx_core::KdfParams,
    ) -> Result<Uuid, StoreError> {
        let slot = glyx_crypto::Keyslot::seal(password, keyfile, &self.key, params)?;
        let id = slot.id;
        atomic_write(
            &self.path.join(layout::KEYSLOTS_DIR).join(slot.filename()),
            serde_json::to_string_pretty(&slot)
                .map_err(|e| StoreError::Corrupt(e.to_string()))?
                .as_bytes(),
        )?;
        Ok(id)
    }
    pub fn list_slots(&self) -> Result<Vec<(Uuid, glyx_core::KdfParams)>, StoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.path.join(layout::KEYSLOTS_DIR))?.flatten() {
            if !has_extension(&entry.path(), "json") {
                continue;
            }
            let slot: glyx_crypto::Keyslot = serde_json::from_slice(&fs::read(entry.path())?)
                .map_err(|e| StoreError::Corrupt(e.to_string()))?;
            out.push((slot.id, slot.params));
        }
        Ok(out)
    }
    pub fn retire_slot(&self, id: &Uuid) -> Result<(), StoreError> {
        let slots = self.list_slots()?;
        if slots.len() <= 1 {
            return Err(StoreError::Corrupt("cannot retire the last keyslot".into()));
        }
        if !slots.iter().any(|(s, _)| s == id) {
            return Err(StoreError::Corrupt("keyslot not found".into()));
        }
        fs::remove_file(
            self.path
                .join(layout::KEYSLOTS_DIR)
                .join(format!("slot-{}.json", id.as_simple())),
        )?;
        Ok(())
    }
    fn scan_headers_unlocked(&self) -> Result<Vec<EnvelopeHeader>, StoreError> {
        let mut out = Vec::new();
        for entry in fs::read_dir(self.path.join(layout::ITEMS_DIR))?.flatten() {
            if !is_envelope_file(&entry.path()) {
                continue;
            }
            let bytes = fs::read(entry.path())?;
            let env: Envelope =
                serde_json::from_slice(&bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
            out.push(env.header());
        }
        Ok(out)
    }
    pub fn reencrypt(&mut self, cipher: glyx_core::Cipher) -> Result<usize, StoreError> {
        let mut addr_map = std::collections::HashMap::new();
        for entry in fs::read_dir(self.path.join(layout::BLOBS_DIR))?.flatten() {
            if !has_extension(&entry.path(), "enc") {
                continue;
            }
            let old_addr = entry
                .path()
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let bytes = fs::read(entry.path())?;
            let data = blob::open(&bytes, &self.key, b"glyx-blob-v1")?;
            let (new_addr, sealed) = blob::seal(&data, &self.key, cipher, b"glyx-blob-v1")?;
            if new_addr != old_addr {
                atomic_write(
                    &self
                        .path
                        .join(layout::BLOBS_DIR)
                        .join(format!("{new_addr}.enc")),
                    &sealed,
                )?;
                fs::remove_file(entry.path())?;
                addr_map.insert(old_addr, new_addr);
            }
        }
        let mut n = 0;
        let headers = self.scan_headers_unlocked()?;
        for header in headers {
            let Some(mut item) = self.get_item(&header.id)? else {
                continue;
            };
            let mut touched = false;
            for field in item.fields.values_mut() {
                if let Some(new_addr) = addr_map.get(field.value.expose()) {
                    field.value = glyx_core::SecretString::new(new_addr.clone());
                    touched = true;
                }
            }
            if touched {
                item.hlc = self.next_hlc()?;
                item.rev = item.rev.saturating_add(1);
                item.updated_by = self.node;
            }
            let env = Envelope::seal(&item, &self.key, cipher)?;
            atomic_write(
                &self.path.join(layout::ITEMS_DIR).join(env.filename()),
                serde_json::to_string_pretty(&env)
                    .map_err(|e| StoreError::Corrupt(e.to_string()))?
                    .as_bytes(),
            )?;
            index::upsert(&self.conn, &item)?;
            n += 1;
        }
        self.config.cipher_suite.cipher = cipher;
        atomic_write(
            &self.path.join(layout::VAULT_TOML),
            self.config.to_toml()?.as_bytes(),
        )?;
        Ok(n)
    }

    pub fn last_merge_ms(&self) -> Result<Option<u64>, StoreError> {
        Ok(self
            .meta_get("last_merge_ms")?
            .and_then(|v| u64::try_from(v).ok()))
    }

    pub fn stamp_merge(&self) -> Result<(), StoreError> {
        self.meta_set("last_merge_ms", glyx_core::ids::wall_ms_now().cast_signed())
    }

    fn read_envelope(&self, id: &Uuid) -> Result<Option<Envelope>, StoreError> {
        let file = self
            .path
            .join(layout::ITEMS_DIR)
            .join(format!("{}.envelope.json", id.as_simple()));
        if !file.exists() {
            return Ok(None);
        }
        serde_json::from_slice(&fs::read(file)?)
            .map_err(|e| StoreError::Corrupt(e.to_string()))
            .map(Some)
    }

    pub fn merge_envelope(
        &mut self,
        remote: &Envelope,
    ) -> Result<crate::conflicts::MergeReport, StoreError> {
        use crate::conflicts::{MergeOutcome, MergeReport};
        let local_env = self.read_envelope(&remote.id)?;
        let Some(local_env) = local_env else {
            let item = remote.open(&self.key)?;
            self.put_item(&item)?;
            return Ok(MergeReport {
                outcome: MergeOutcome::Adopted,
                races: 0,
            });
        };
        let local_item = local_env.open(&self.key)?;
        let remote_item = remote.open(&self.key)?;
        if local_item == remote_item {
            return Ok(MergeReport {
                outcome: MergeOutcome::Stale,
                races: 0,
            });
        }
        if local_item.deleted != remote_item.deleted {
            if local_item.deleted {
                return Ok(MergeReport {
                    outcome: MergeOutcome::Tombstoned,
                    races: 0,
                });
            }
            self.put_item(&remote_item)?;
            return Ok(MergeReport {
                outcome: MergeOutcome::Tombstoned,
                races: 0,
            });
        }
        if glyx_sync::remote_dominates(&local_item, &remote_item) {
            self.put_item(&remote_item)?;
            return Ok(MergeReport {
                outcome: MergeOutcome::FastForwarded,
                races: 0,
            });
        }
        let tick = self.next_hlc()?;
        let (winner, races) = glyx_sync::merge_items(
            &local_item,
            &remote_item,
            tick,
            self.node,
            local_item.hlc.node,
            remote_item.hlc.node,
        );
        self.put_item(&winner)?;
        let n = races.len();
        if n > 0 {
            let winner_env = Envelope::seal(&winner, &self.key, self.cipher())?;
            let file = crate::conflicts::ConflictFile {
                v: crate::conflicts::CONFLICT_VERSION,
                item_id: winner.id,
                created_ms: tick.wall_ms,
                winner: winner_env,
                local: local_env,
                remote: remote.clone(),
                race_targets: races
                    .iter()
                    .map(|r| crate::conflicts::target_label(&r.target))
                    .collect(),
            };
            crate::conflicts::write_conflict(
                &self.path.join(layout::CONFLICTS_DIR),
                &file,
                tick.wall_ms,
                tick.seq,
            )?;
        }
        Ok(MergeReport {
            outcome: MergeOutcome::Merged,
            races: n,
        })
    }
}

impl UnlockedVault {
    pub fn heal_conflict_files(&mut self) -> Result<crate::conflicts::HealReport, StoreError> {
        use crate::conflicts::{HealReport, MergeOutcome};
        let mut report = HealReport::default();
        let mut copies = Vec::new();
        for entry in fs::read_dir(self.path.join(layout::ITEMS_DIR))?.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if is_sync_conflict_copy(&name) {
                copies.push(entry.path());
            }
        }
        let mut pending = Vec::new();
        for copy in copies {
            let Some(original) = original_envelope_name(&copy) else {
                continue;
            };
            let bytes = fs::read(&copy)?;
            let remote: Envelope = match serde_json::from_slice(&bytes) {
                Ok(env) => env,
                Err(_) => continue,
            };
            if remote.id.as_simple().to_string() + ".envelope.json" != original {
                continue;
            }
            fs::remove_file(&copy)?;
            pending.push(remote);
        }
        for remote in &pending {
            let rep = self.merge_envelope(remote)?;
            report.healed += 1;
            match rep.outcome {
                MergeOutcome::Merged => {
                    report.merged += 1;
                    report.conflicts += usize::from(rep.races > 0);
                }
                MergeOutcome::Adopted | MergeOutcome::FastForwarded | MergeOutcome::Tombstoned => {
                    report.merged += 1;
                }
                MergeOutcome::Stale => {}
            }
        }
        Ok(report)
    }

    pub fn sync_from(
        &mut self,
        other: &UnlockedVault,
    ) -> Result<crate::conflicts::SyncReport, StoreError> {
        use crate::conflicts::{MergeOutcome, SyncReport};
        let mut report = SyncReport::default();
        let headers = other.scan_headers_unlocked()?;
        for header in headers {
            let Some(other_env) = other.read_envelope(&header.id)? else {
                continue;
            };
            let Ok(remote_item) = other_env.open(&other.key) else {
                continue;
            };
            let mut adopted = Envelope::seal(&remote_item, &self.key, self.cipher())?;
            adopted.hlc = other_env.hlc;
            adopted.rev = other_env.rev;
            adopted.deleted = other_env.deleted;
            let rep = self.merge_envelope(&adopted)?;
            match rep.outcome {
                MergeOutcome::Adopted | MergeOutcome::FastForwarded | MergeOutcome::Tombstoned => {
                    report.merged += 1;
                }
                MergeOutcome::Merged => {
                    report.merged += 1;
                    report.conflicts += usize::from(rep.races > 0);
                }
                MergeOutcome::Stale => {}
            }
            if rep.outcome != MergeOutcome::Stale {
                report.blobs += usize::from(self.ensure_file_blob(other, &header.id)?);
            }
        }
        self.stamp_merge()?;
        Ok(report)
    }

    fn ensure_file_blob(&mut self, other: &UnlockedVault, id: &Uuid) -> Result<bool, StoreError> {
        let Some(mut item) = self.get_item(id)? else {
            return Ok(false);
        };
        if item.item_type != glyx_core::ItemType::File {
            return Ok(false);
        }
        let Some(addr) = item.fields.get("blob").map(|f| f.value.expose().to_owned()) else {
            return Ok(false);
        };
        if self
            .path
            .join(layout::BLOBS_DIR)
            .join(format!("{addr}.enc"))
            .exists()
        {
            return Ok(false);
        }
        let data = other.get_blob(&addr)?;
        let (new_addr, sealed) = blob::seal(&data, &self.key, self.cipher(), b"glyx-blob-v1")?;
        atomic_write(
            &self
                .path
                .join(layout::BLOBS_DIR)
                .join(format!("{new_addr}.enc")),
            &sealed,
        )?;
        if new_addr != addr {
            let hlc = self.next_hlc()?;
            if let Some(field) = item.fields.get_mut("blob") {
                field.value = glyx_core::SecretString::new(new_addr);
                field.field_hlc = hlc;
            }
            item.hlc = hlc;
            item.rev = item.rev.saturating_add(1);
            item.updated_by = self.node;
            self.put_item(&item)?;
        }
        Ok(true)
    }

    pub fn list_conflicts(&self) -> Result<Vec<crate::conflicts::ConflictMeta>, StoreError> {
        let dir = self.path.join(layout::CONFLICTS_DIR);
        let mut out = Vec::new();
        if !dir.exists() {
            return Ok(out);
        }
        for entry in fs::read_dir(dir)?.flatten() {
            let path = entry.path();
            if !has_extension(&path, "json") {
                continue;
            }
            if let Ok(file) = crate::conflicts::read_conflict(&path) {
                out.push(crate::conflicts::ConflictMeta {
                    item_id: file.item_id,
                    path,
                    created_ms: file.created_ms,
                    race_targets: file.race_targets,
                });
            }
        }
        out.sort_by_key(|m| (m.item_id.as_bytes().to_vec(), m.created_ms));
        Ok(out)
    }

    pub fn read_conflict(
        &self,
        item_id: &Uuid,
    ) -> Result<Option<crate::conflicts::ConflictTriple>, StoreError> {
        let mut metas = self.list_conflicts()?;
        metas.retain(|m| &m.item_id == item_id);
        let Some(meta) = metas.into_iter().next() else {
            return Ok(None);
        };
        let file = crate::conflicts::read_conflict(&meta.path)?;
        Ok(Some((
            file.winner.open(&self.key)?,
            file.local.open(&self.key)?,
            file.remote.open(&self.key)?,
            file.race_targets,
        )))
    }

    pub fn resolve_conflict(
        &mut self,
        item_id: &Uuid,
        resolution: crate::conflicts::Resolution,
    ) -> Result<bool, StoreError> {
        use crate::conflicts::Resolution;
        let Some((winner, local, remote, _)) = self.read_conflict(item_id)? else {
            return Ok(false);
        };
        let mut item = match resolution {
            Resolution::Mine => local,
            Resolution::Theirs => remote,
            Resolution::Fields(map) => {
                let mut item = winner;
                let hlc = self.next_hlc()?;
                for (k, v) in &map {
                    if k == "name" {
                        item.name.clone_from(v);
                    } else if k == "folder" {
                        item.folder.clone_from(v);
                    } else {
                        item.fields.insert(
                            k.clone(),
                            glyx_core::Field {
                                value: glyx_core::SecretString::new(v.clone()),
                                field_hlc: hlc,
                            },
                        );
                    }
                }
                item.hlc = hlc;
                item
            }
        };
        item.hlc = self.next_hlc()?;
        item.rev = item.rev.saturating_add(1);
        item.deleted = false;
        item.updated_by = self.node;
        self.put_item(&item)?;
        for meta in self.list_conflicts()? {
            if &meta.item_id == item_id {
                fs::remove_file(meta.path)?;
            }
        }
        Ok(true)
    }

    pub fn gc_tombstones(&mut self, older_than_ms: u64) -> Result<Vec<Uuid>, StoreError> {
        let now = glyx_core::ids::wall_ms_now();
        let cutoff = now.saturating_sub(older_than_ms);
        let mut purged = Vec::new();
        for header in self.scan_headers_unlocked()? {
            if !header.deleted || header.hlc.wall_ms >= cutoff {
                continue;
            }
            fs::remove_file(
                self.path
                    .join(layout::ITEMS_DIR)
                    .join(format!("{}.envelope.json", header.id.as_simple())),
            )?;
            index::remove(&self.conn, &header.id)?;
            purged.push(header.id);
        }
        Ok(purged)
    }
}

fn has_conflict_files(vault_path: &Path) -> bool {
    fs::read_dir(vault_path.join(layout::ITEMS_DIR)).is_ok_and(|entries| {
        entries
            .flatten()
            .any(|e| is_sync_conflict_copy(&e.file_name().to_string_lossy()))
    })
}

fn is_sync_conflict_copy(name: &str) -> bool {
    name.contains(".sync-conflict-") || name.contains("conflicted copy")
}

fn original_envelope_name(copy_path: &Path) -> Option<String> {
    let name = copy_path.file_name()?.to_string_lossy().into_owned();
    if let Some((head, _)) = name.split_once(".sync-conflict-") {
        let ext = copy_path.extension()?.to_string_lossy().into_owned();
        return Some(format!("{head}.{ext}"));
    }
    if let Some((head, _)) = name.split_once(" (conflicted copy") {
        let ext = copy_path.extension()?.to_string_lossy().into_owned();
        return Some(format!("{head}.{ext}"));
    }
    None
}

impl std::fmt::Debug for UnlockedVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVault")
            .field("path", &self.path)
            .field("vault_id", &self.config.vault_id)
            .finish_non_exhaustive()
    }
}

fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension().is_some_and(|e| e == ext)
}

fn is_envelope_file(path: &Path) -> bool {
    if !has_extension(path, "json") {
        return false;
    }
    path.file_stem()
        .and_then(|s| s.to_str())
        .is_some_and(|stem| stem.rsplit('.').next() == Some("envelope"))
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
            assert_eq!(unlocked.list(false).expect("list").len(), 1);
            let addr = unlocked.put_blob(b"attachment").expect("put blob");
            assert_eq!(&*unlocked.get_blob(&addr).expect("get blob"), b"attachment");
            drop(unlocked);
            let reopened = Vault::open(&path).expect("reopen");
            assert_eq!(reopened.scan_headers().expect("scan").len(), 1);
            assert_eq!(reopened.rebuild_index().expect("rebuild"), 1);
        }
    }
}

#[cfg(test)]
mod m1_tests {
    use super::*;

    fn mobile_suite() -> glyx_core::CipherSuiteConfig {
        glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        }
    }

    fn login_item(node: glyx_core::DeviceId, hlc: glyx_core::Hlc) -> glyx_core::Item {
        let mut fields = std::collections::BTreeMap::new();
        fields.insert(
            "password".to_owned(),
            glyx_core::Field {
                value: glyx_core::SecretString::new("pw".to_owned()),
                field_hlc: hlc,
            },
        );
        glyx_core::Item {
            id: Uuid::now_v7(),
            item_type: glyx_core::ItemType::Login,
            name: "web".to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            fields,
            hlc,
            rev: 1,
            deleted: false,
            updated_by: node,
        }
    }

    #[test]
    fn tombstone_and_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("t.glyx");
        let kf = [1u8; 32];
        Vault::init(&path, mobile_suite(), b"pw", &kf).expect("init");
        let vault = Vault::open(&path).expect("open");
        let mut uv = vault.unlock(b"pw", &kf).expect("unlock");
        let hlc = uv.next_hlc().expect("tick");
        let item = login_item(uv.device_node(), hlc);
        let id = item.id;
        uv.put_item(&item).expect("put");
        let hlc2 = uv.next_hlc().expect("tick");
        assert!(hlc2 > hlc);
        let mut v2 = uv.get_item(&id).expect("get").expect("found");
        v2.name = "renamed".to_owned();
        v2.hlc = uv.next_hlc().expect("tick");
        v2.rev = 2;
        uv.put_item(&v2).expect("overwrite");
        let hist = path
            .join(layout::HISTORY_DIR)
            .join(id.as_simple().to_string());
        assert!(fs::read_dir(&hist).expect("history").count() >= 1);
        assert!(uv.delete_item(&id).expect("delete"));
        assert!(uv.get_item(&id).expect("get").expect("found").deleted);
        assert!(uv.list(false).expect("list").is_empty());
        assert_eq!(uv.list(true).expect("all").len(), 1);
        assert!(!uv.delete_item(&Uuid::now_v7()).expect("missing"));
    }

    #[test]
    fn hlc_persists_across_sessions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("h.glyx");
        let kf = [2u8; 32];
        Vault::init(&path, mobile_suite(), b"pw", &kf).expect("init");
        let first = {
            let vault = Vault::open(&path).expect("open");
            let mut uv = vault.unlock(b"pw", &kf).expect("unlock");
            uv.next_hlc().expect("tick")
        };
        let vault = Vault::open(&path).expect("open");
        let mut uv = vault.unlock(b"pw", &kf).expect("unlock");
        assert!(uv.next_hlc().expect("tick") > first);
    }

    #[test]
    fn slot_rotation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("s.glyx");
        Vault::init(&path, mobile_suite(), b"pw", &[3u8; 32]).expect("init");
        let vault = Vault::open(&path).expect("open");
        let uv = vault.unlock(b"pw", &[3u8; 32]).expect("unlock");
        let id = uv.add_slot(b"new", &[4u8; 32]).expect("add");
        assert!(vault.verify_slot(&id, b"new", &[4u8; 32]).expect("verify"));
        assert!(!vault
            .verify_slot(&id, b"wrong", &[4u8; 32])
            .expect("reject"));
        assert_eq!(uv.list_slots().expect("slots").len(), 2);
        let first = uv.list_slots().expect("slots")[0].0;
        uv.retire_slot(&first).expect("retire");
        assert!(uv.retire_slot(&id).is_err());
    }

    #[test]
    fn reencrypt_switch() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("r.glyx");
        let kf = [5u8; 32];
        Vault::init(&path, mobile_suite(), b"pw", &kf).expect("init");
        let vault = Vault::open(&path).expect("open");
        let mut uv = vault.unlock(b"pw", &kf).expect("unlock");
        let hlc = uv.next_hlc().expect("tick");
        uv.put_item(&login_item(uv.device_node(), hlc))
            .expect("put");
        uv.put_blob(b"data").expect("blob");
        let n = uv
            .reencrypt(glyx_core::Cipher::Aes256gcm)
            .expect("reencrypt");
        assert_eq!(n, 1);
        drop(uv);
        let vault = Vault::open(&path).expect("reopen");
        assert_eq!(
            vault.config().cipher_suite.cipher,
            glyx_core::Cipher::Aes256gcm
        );
        let uv = vault.unlock(b"pw", &kf).expect("unlock");
        assert_eq!(uv.list(false).expect("list").len(), 1);
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    pub fn copy_dir(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).expect("mkdir");
        for entry in fs::read_dir(src).expect("read").flatten() {
            let to = dst.join(entry.file_name());
            if entry.file_type().expect("type").is_dir() {
                copy_dir(&entry.path(), &to);
            } else {
                fs::copy(entry.path(), to).expect("copy");
            }
        }
    }

    pub fn m1_item(uv: &mut UnlockedVault, name: &str, fields: &[(&str, &str)]) -> glyx_core::Item {
        let hlc = uv.next_hlc().expect("tick");
        let node = uv.device_node();
        let map = fields
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_owned(),
                    glyx_core::Field {
                        value: glyx_core::SecretString::new((*v).to_owned()),
                        field_hlc: hlc,
                    },
                )
            })
            .collect();
        glyx_core::Item {
            id: Uuid::now_v7(),
            item_type: glyx_core::ItemType::Login,
            name: name.to_owned(),
            folder: String::new(),
            tags: Vec::new(),
            fields: map,
            hlc,
            rev: 1,
            deleted: false,
            updated_by: node,
        }
    }

    pub fn two_vaults() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("a.glyx");
        let b = dir.path().join("b.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        Vault::init(&a, suite, b"pw", &[9u8; 32]).expect("init");
        copy_dir(&a, &b);
        fs::remove_file(b.join("device.id")).ok();
        (dir, a, b)
    }

    pub fn seed_b_from_a(a: &Path, b: &Path) {
        let vault_a = Vault::open(a).expect("open");
        let uv_a = vault_a.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let vault_b = Vault::open(b).expect("open");
        let mut uv_b = vault_b.unlock(b"pw", &[9u8; 32]).expect("unlock");
        uv_b.sync_from(&uv_a).expect("seed");
    }

    pub fn race_pair(a: &Path, b: &Path, id: &Uuid, field: &str, left: &str, right: &str) {
        for (path, val) in [(a, left), (b, right)] {
            let vault = Vault::open(path).expect("open");
            let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
            let mut item = uv.get_item(id).expect("get").expect("found");
            let hlc = glyx_core::Hlc {
                wall_ms: 60_000,
                seq: 0,
                node: uv.device_node(),
            };
            item.fields.insert(
                field.to_owned(),
                glyx_core::Field {
                    value: glyx_core::SecretString::new(val.to_owned()),
                    field_hlc: hlc,
                },
            );
            item.hlc = hlc;
            item.rev += 1;
            uv.put_item(&item).expect("put");
        }
    }
}

#[cfg(test)]
mod m2_tests {
    use super::test_helpers::*;
    use super::*;

    #[test]
    fn pairwise_disjoint_edits_union() {
        let (_d, a, b) = two_vaults();
        let id = {
            let vault = Vault::open(&a).expect("open");
            let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
            let item = m1_item(&mut uv, "x", &[("password", "p0"), ("username", "u0")]);
            let id = item.id;
            uv.put_item(&item).expect("put");
            id
        };
        seed_b_from_a(&a, &b);
        {
            let vault = Vault::open(&a).expect("open");
            let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
            let mut item = uv.get_item(&id).expect("get").expect("found");
            let hlc = uv.next_hlc().expect("tick");
            item.fields.insert(
                "password".to_owned(),
                glyx_core::Field {
                    value: glyx_core::SecretString::new("pA".to_owned()),
                    field_hlc: hlc,
                },
            );
            item.hlc = hlc;
            item.rev += 1;
            uv.put_item(&item).expect("put");
        }
        {
            let vault = Vault::open(&b).expect("open");
            let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
            let mut item = uv.get_item(&id).expect("get").expect("found");
            let hlc = uv.next_hlc().expect("tick");
            item.fields.insert(
                "username".to_owned(),
                glyx_core::Field {
                    value: glyx_core::SecretString::new("uB".to_owned()),
                    field_hlc: hlc,
                },
            );
            item.hlc = hlc;
            item.rev += 1;
            uv.put_item(&item).expect("put");
        }
        let vault_a = Vault::open(&a).expect("open");
        let mut uv_a = vault_a.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let vault_b = Vault::open(&b).expect("open");
        let uv_b = vault_b.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let rep = uv_a.sync_from(&uv_b).expect("sync");
        assert_eq!(rep.conflicts, 0);
        let merged = uv_a.get_item(&id).expect("get").expect("found");
        assert_eq!(merged.fields["password"].value.expose(), "pA");
        assert_eq!(merged.fields["username"].value.expose(), "uB");
    }

    #[test]
    fn same_field_race_records_and_resolves() {
        let (_d, a, b) = two_vaults();
        let id = {
            let vault = Vault::open(&a).expect("open");
            let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
            let item = m1_item(&mut uv, "x", &[("nickname", "base")]);
            let id = item.id;
            uv.put_item(&item).expect("put");
            id
        };
        seed_b_from_a(&a, &b);
        for (path, val) in [(&a, "alpha"), (&b, "beta")] {
            let vault = Vault::open(path).expect("open");
            let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
            let mut item = uv.get_item(&id).expect("get").expect("found");
            let hlc = glyx_core::Hlc {
                wall_ms: 50_000,
                seq: 0,
                node: uv.device_node(),
            };
            item.fields.insert(
                "nickname".to_owned(),
                glyx_core::Field {
                    value: glyx_core::SecretString::new(val.to_owned()),
                    field_hlc: hlc,
                },
            );
            item.hlc = hlc;
            item.rev += 1;
            uv.put_item(&item).expect("put");
        }
        let vault_a = Vault::open(&a).expect("open");
        let mut uv_a = vault_a.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let vault_b = Vault::open(&b).expect("open");
        let uv_b = vault_b.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let rep = uv_a.sync_from(&uv_b).expect("sync");
        assert_eq!(rep.conflicts, 1);
        assert_eq!(uv_a.list_conflicts().expect("list").len(), 1);
        let val = uv_a.get_item(&id).expect("get").expect("found").fields["nickname"]
            .value
            .expose()
            .to_owned();
        assert!(val == "alpha" || val == "beta");
        assert!(uv_a
            .resolve_conflict(&id, crate::conflicts::Resolution::Theirs)
            .expect("resolve"));
        assert!(uv_a.list_conflicts().expect("list").is_empty());
    }

    #[test]
    fn conflict_copy_heals_on_unlock() {
        let (_d, a, _) = two_vaults();
        let vault = Vault::open(&a).expect("open");
        let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let item = m1_item(&mut uv, "x", &[("password", "p")]);
        uv.put_item(&item).expect("put");
        drop(uv);
        let hex = item.id.as_simple().to_string();
        let src = a
            .join(layout::ITEMS_DIR)
            .join(format!("{hex}.envelope.json"));
        let copy = a.join(layout::ITEMS_DIR).join(format!(
            "{hex}.envelope.sync-conflict-20240101-101010-ABCDEF1.json"
        ));
        fs::copy(&src, &copy).expect("craft copy");
        let vault = Vault::open(&a).expect("open");
        let _uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
        assert!(!copy.exists());
    }

    #[test]
    fn gc_purges_only_old_tombstones() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("g.glyx");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        Vault::init(&path, suite, b"pw", &[9u8; 32]).expect("init");
        let vault = Vault::open(&path).expect("open");
        let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let item = m1_item(&mut uv, "gone", &[("password", "p")]);
        let id = item.id;
        uv.put_item(&item).expect("put");
        assert!(uv.delete_item(&id).expect("delete"));
        assert!(uv.gc_tombstones(u64::MAX).expect("gc").is_empty());
        assert_eq!(uv.gc_tombstones(0).expect("gc"), vec![id]);
        assert!(uv.get_item(&id).expect("get").is_none());
    }
}

#[cfg(test)]
mod m2_resolve_tests {
    use super::test_helpers::*;
    use super::*;

    fn raced_id(a: &std::path::Path, b: &std::path::Path) -> Uuid {
        let id = {
            let vault = Vault::open(a).expect("open");
            let mut uv = vault.unlock(b"pw", &[9u8; 32]).expect("unlock");
            let item = m1_item(&mut uv, "x", &[("city", "base"), ("zip", "1")]);
            let id = item.id;
            uv.put_item(&item).expect("put");
            id
        };
        seed_b_from_a(a, b);
        race_pair(a, b, &id, "city", "alpha", "beta");
        id
    }

    fn synced_a(a: &std::path::Path, b: &std::path::Path) -> UnlockedVault {
        let vault_a = Vault::open(a).expect("open");
        let mut uv_a = vault_a.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let vault_b = Vault::open(b).expect("open");
        let uv_b = vault_b.unlock(b"pw", &[9u8; 32]).expect("unlock");
        let rep = uv_a.sync_from(&uv_b).expect("sync");
        assert_eq!(rep.conflicts, 1);
        uv_a
    }

    #[test]
    fn resolve_mine_keeps_local_side() {
        let (_d, a, b) = two_vaults();
        let id = raced_id(&a, &b);
        let mut uv_a = synced_a(&a, &b);
        assert!(uv_a
            .resolve_conflict(&id, crate::conflicts::Resolution::Mine)
            .expect("resolve"));
        let after = uv_a.get_item(&id).expect("get").expect("found");
        assert!(!after.deleted);
        assert!(uv_a.list_conflicts().expect("list").is_empty());
    }

    #[test]
    fn resolve_fields_overrides() {
        let (_d, a, b) = two_vaults();
        let id = raced_id(&a, &b);
        let mut uv_a = synced_a(&a, &b);
        let mut map = std::collections::BTreeMap::new();
        map.insert("city".to_owned(), "chosen".to_owned());
        map.insert("name".to_owned(), "renamed".to_owned());
        assert!(uv_a
            .resolve_conflict(&id, crate::conflicts::Resolution::Fields(map))
            .expect("resolve"));
        let after = uv_a.get_item(&id).expect("get").expect("found");
        assert_eq!(after.fields["city"].value.expose(), "chosen");
        assert_eq!(after.name, "renamed");
        assert_eq!(after.fields["zip"].value.expose(), "1");
        assert!(!uv_a
            .resolve_conflict(&id, crate::conflicts::Resolution::Mine)
            .expect("again"));
    }

    #[test]
    fn read_conflict_triple() {
        let (_d, a, b) = two_vaults();
        let id = raced_id(&a, &b);
        let uv_a = synced_a(&a, &b);
        let Some((winner, local, remote, targets)) = uv_a.read_conflict(&id).expect("read") else {
            panic!("expected conflict");
        };
        assert_eq!(targets, vec!["field:city".to_owned()]);
        assert_ne!(
            local.fields["city"].value.expose(),
            remote.fields["city"].value.expose()
        );
        assert!(winner.fields.contains_key("city"));
        assert!(uv_a.read_conflict(&Uuid::now_v7()).expect("read").is_none());
    }
}
