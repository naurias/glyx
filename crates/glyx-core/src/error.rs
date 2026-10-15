use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid value for {field}: {reason}")]
    Validation { field: &'static str, reason: String },
    #[error("unknown item type: {0}")]
    UnknownItemType(String),
    #[error("unsupported vault format {found}, max supported is {max_supported}")]
    UnsupportedVersion { found: u32, max_supported: u32 },
}
