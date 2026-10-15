use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("storage I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault data: {0}")]
    Core(#[from] glyx_core::CoreError),
    #[error("crypto: {0}")]
    Crypto(#[from] glyx_crypto::CryptoError),
    #[error("index: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("corrupt vault: {0}")]
    Corrupt(String),
    #[error("vault already exists at {0}")]
    AlreadyExists(String),
}
