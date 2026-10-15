use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlaceholderMode {
    Ref,
    EncryptedPointer,
    MaskedShape,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportRecord {
    pub target: PathBuf,
    pub item_id: Uuid,
    pub locked_hash: String,
    pub mode: PlaceholderMode,
}

pub trait ExportLedger {
    type Error: std::error::Error;
    fn record(&mut self, entry: ExportRecord) -> Result<(), Self::Error>;
    fn remove(&mut self, target: &Path) -> Result<(), Self::Error>;
    fn get(&self, target: &Path) -> Result<Option<ExportRecord>, Self::Error>;
    fn list(&self) -> Result<Vec<ExportRecord>, Self::Error>;
}

#[must_use]
pub fn locked_placeholder(mode: PlaceholderMode, item_id: &Uuid, field: &str) -> String {
    match mode {
        PlaceholderMode::Ref => format!("{{{{glyx:{item_id}/{field}}}}}"),
        PlaceholderMode::EncryptedPointer => format!("__GLYXENC:V1:{item_id}:{field}__"),
        PlaceholderMode::MaskedShape => format!("__GLYXSEC:{field}__"),
    }
}
