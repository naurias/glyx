use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{aead, kdf, rand, CryptoError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Keyslot {
    pub id: Uuid,
    pub kdf: glyx_core::KdfId,
    #[serde(flatten)]
    pub params: glyx_core::KdfParams,
    #[serde(with = "b64_16")]
    pub salt: [u8; 16],
    #[serde(with = "b64_vec")]
    pub wrap_nonce: Vec<u8>,
    #[serde(with = "b64_vec")]
    pub wrapped_key: Vec<u8>,
}

impl Keyslot {
    pub fn seal(
        password: &[u8],
        keyfile: &[u8; 32],
        data_key: &[u8; 32],
        params: glyx_core::KdfParams,
    ) -> Result<Self, CryptoError> {
        let (kek, salt) = kdf::derive_kek_fresh_salt(password, keyfile, params)?;
        let ct = aead::encrypt(
            glyx_core::Cipher::Xchacha20poly1305,
            &kek,
            data_key,
            b"glyx-keyslot-v1",
        )?;
        Ok(Self {
            id: Uuid::now_v7(),
            kdf: glyx_core::KdfId::Argon2id,
            params,
            salt,
            wrap_nonce: ct.nonce,
            wrapped_key: ct.ct,
        })
    }
    pub fn unseal(
        &self,
        password: &[u8],
        keyfile: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        let kek = kdf::derive_kek(password, keyfile, &self.salt, self.params)?;
        let pt = aead::decrypt(
            glyx_core::Cipher::Xchacha20poly1305,
            &kek,
            &self.wrap_nonce,
            &self.wrapped_key,
            b"glyx-keyslot-v1",
        )?;
        if pt.len() != 32 {
            return Err(CryptoError::Decrypt);
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&pt);
        Ok(Zeroizing::new(key))
    }
    #[must_use]
    pub fn filename(&self) -> String {
        format!("slot-{}.json", self.id.as_simple())
    }
}

pub fn seal_fresh_vault(
    password: &[u8],
    keyfile: &[u8; 32],
    params: glyx_core::KdfParams,
) -> Result<(Zeroizing<[u8; 32]>, Keyslot), CryptoError> {
    let key = rand::generate_data_key()?;
    let slot = Keyslot::seal(password, keyfile, &key, params)?;
    Ok((Zeroizing::new(key), slot))
}

mod b64_16 {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        let raw = STANDARD
            .decode(String::deserialize(d)?)
            .map_err(D::Error::custom)?;
        raw.try_into()
            .map_err(|_| D::Error::custom("expected 16 bytes"))
    }
}

mod b64_vec {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(d)?)
            .map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyslot_roundtrip() {
        let params = glyx_core::KdfParams::mobile();
        let keyfile = [3u8; 32];
        let (key, slot) = seal_fresh_vault(b"correct horse", &keyfile, params).expect("seals");
        let back = slot.unseal(b"correct horse", &keyfile).expect("unseals");
        assert_eq!(&*back, &*key);
        assert!(slot.unseal(b"wrong password", &keyfile).is_err());
        assert!(slot.unseal(b"correct horse", &[4u8; 32]).is_err());
    }
}
