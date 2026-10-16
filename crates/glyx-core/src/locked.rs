use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LockedForm {
    Ref,
    EncryptedPointer,
    MaskedShape,
}

#[must_use]
pub fn ref_placeholder(item_id: &Uuid, field: &str) -> String {
    format!("{{{{glyx:{item_id}/{field}}}}}")
}

#[must_use]
pub fn masked_fallback(field: &str) -> String {
    format!("__GLYXSEC:{field}__")
}
