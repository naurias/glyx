use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::StoreError;

pub const ENVELOPE_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub id: Uuid,
    pub hlc: glyx_core::Hlc,
    pub rev: u64,
    pub deleted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    pub id: Uuid,
    pub hlc: glyx_core::Hlc,
    pub rev: u64,
    pub deleted: bool,
    pub cipher: glyx_core::Cipher,
    pub nonce_b64: String,
    pub blob_b64: String,
}

impl Envelope {
    pub fn seal(
        item: &glyx_core::Item,
        key: &[u8; 32],
        cipher: glyx_core::Cipher,
    ) -> Result<Self, StoreError> {
        let plain = item.canonical_json()?;
        let ct = glyx_crypto::encrypt(cipher, key, plain.as_bytes(), item.id.as_bytes())?;
        Ok(Self {
            v: ENVELOPE_VERSION,
            id: item.id,
            hlc: item.hlc,
            rev: item.rev,
            deleted: item.deleted,
            cipher,
            nonce_b64: STANDARD.encode(&ct.nonce),
            blob_b64: STANDARD.encode(&ct.ct),
        })
    }
    pub fn open(&self, key: &[u8; 32]) -> Result<glyx_core::Item, StoreError> {
        if self.v != ENVELOPE_VERSION {
            return Err(StoreError::Corrupt(format!(
                "envelope v{}, max supported is {ENVELOPE_VERSION}",
                self.v
            )));
        }
        let nonce = STANDARD
            .decode(&self.nonce_b64)
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let blob = STANDARD
            .decode(&self.blob_b64)
            .map_err(|e| StoreError::Corrupt(e.to_string()))?;
        let pt = glyx_crypto::decrypt(self.cipher, key, &nonce, &blob, self.id.as_bytes())?;
        let item: glyx_core::Item =
            serde_json::from_slice(&pt).map_err(|e| StoreError::Corrupt(e.to_string()))?;
        if item.id != self.id {
            return Err(StoreError::Corrupt("envelope id mismatch".into()));
        }
        Ok(item)
    }
    #[must_use]
    pub fn header(&self) -> EnvelopeHeader {
        EnvelopeHeader {
            id: self.id,
            hlc: self.hlc,
            rev: self.rev,
            deleted: self.deleted,
        }
    }
    #[must_use]
    pub fn filename(&self) -> String {
        format!("{}.envelope.json", self.id.as_simple())
    }
}
