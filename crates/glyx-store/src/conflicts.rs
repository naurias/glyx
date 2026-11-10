use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{Envelope, StoreError};

pub const CONFLICT_VERSION: u32 = 1;

pub type ConflictTriple = (
    glyx_core::Item,
    glyx_core::Item,
    glyx_core::Item,
    Vec<String>,
);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictFile {
    pub v: u32,
    pub item_id: Uuid,
    pub created_ms: u64,
    pub winner: Envelope,
    pub local: Envelope,
    pub remote: Envelope,
    pub race_targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ConflictMeta {
    pub item_id: Uuid,
    pub key: String,
    pub created_ms: u64,
    pub race_targets: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum Resolution {
    Mine,
    Theirs,
    Fields(BTreeMap<String, String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MergeOutcome {
    Adopted,
    FastForwarded,
    Merged,
    Stale,
    Tombstoned,
}

#[derive(Debug, Clone)]
pub struct MergeReport {
    pub outcome: MergeOutcome,
    pub races: usize,
}

#[derive(Debug, Clone, Default)]
pub struct HealReport {
    pub healed: usize,
    pub merged: usize,
    pub conflicts: usize,
}

#[derive(Debug, Clone, Default)]
pub struct SyncReport {
    pub adopted: usize,
    pub merged: usize,
    pub conflicts: usize,
    pub blobs: usize,
}

#[must_use]
pub fn target_label(target: &glyx_sync::RaceTarget) -> String {
    match target {
        glyx_sync::RaceTarget::Field(k) => format!("field:{k}"),
        glyx_sync::RaceTarget::Name => "name".to_owned(),
        glyx_sync::RaceTarget::Folder => "folder".to_owned(),
        glyx_sync::RaceTarget::Tags => "tags".to_owned(),
        glyx_sync::RaceTarget::Favorite => "favorite".to_owned(),
        glyx_sync::RaceTarget::ItemType => "type".to_owned(),
    }
}

#[must_use]
pub fn conflict_filename(item_id: &Uuid, stamp_ms: u64, stamp_seq: u16) -> String {
    format!("{}-{stamp_ms}-{stamp_seq}.json", item_id.as_simple())
}

pub fn read_conflict_bytes(bytes: &[u8]) -> Result<ConflictFile, StoreError> {
    let file: ConflictFile =
        serde_json::from_slice(bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    if file.v != CONFLICT_VERSION {
        return Err(StoreError::Corrupt("unsupported conflict version".into()));
    }
    Ok(file)
}
