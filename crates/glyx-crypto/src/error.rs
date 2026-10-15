use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("decryption failed")]
    Decrypt,
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("invalid crypto parameter: {0}")]
    Param(String),
}
