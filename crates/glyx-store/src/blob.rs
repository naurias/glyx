use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::StoreError;

pub const BLOB_VERSION: u32 = 1;
pub const MAX_BLOB_BYTES: usize = 25 * 1024 * 1024;

#[must_use]
pub fn valid_address(addr: &str) -> bool {
    addr.strip_prefix("blake3-").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

#[derive(Debug, Serialize, Deserialize)]
struct BlobFile {
    v: u32,
    cipher: glyx_core::Cipher,
    nonce_b64: String,
    blob_b64: String,
}

pub fn seal(
    data: &[u8],
    key: &[u8; 32],
    cipher: glyx_core::Cipher,
    aad: &[u8],
) -> Result<(String, Vec<u8>), StoreError> {
    let ct = glyx_crypto::encrypt(cipher, key, data, aad)?;
    let file = BlobFile {
        v: BLOB_VERSION,
        cipher,
        nonce_b64: STANDARD.encode(&ct.nonce),
        blob_b64: STANDARD.encode(&ct.ct),
    };
    let bytes = serde_json::to_vec(&file).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    Ok((format!("blake3-{}", glyx_crypto::blake3_hex(&bytes)), bytes))
}

pub fn open(bytes: &[u8], key: &[u8; 32], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>, StoreError> {
    let file: BlobFile =
        serde_json::from_slice(bytes).map_err(|e| StoreError::Corrupt(e.to_string()))?;
    if file.v != BLOB_VERSION {
        return Err(StoreError::Corrupt(format!(
            "blob v{}, max supported is {BLOB_VERSION}",
            file.v
        )));
    }
    let nonce = STANDARD
        .decode(&file.nonce_b64)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    let blob = STANDARD
        .decode(&file.blob_b64)
        .map_err(|e| StoreError::Corrupt(e.to_string()))?;
    Ok(glyx_crypto::decrypt(file.cipher, key, &nonce, &blob, aad)?)
}
