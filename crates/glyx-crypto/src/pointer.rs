use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use uuid::Uuid;

use crate::CryptoError;

pub const POINTER_VERSION: u32 = 1;

pub fn seal_pointer(
    key: &[u8; 32],
    item_id: &Uuid,
    field: &str,
    target: &str,
) -> Result<String, CryptoError> {
    let mut plain = Vec::new();
    plain.extend_from_slice(item_id.as_bytes());
    plain.push(0x00);
    plain.extend_from_slice(field.as_bytes());
    plain.push(0x00);
    plain.extend_from_slice(blake3::hash(format!("{item_id}/{field}").as_bytes()).as_bytes());
    let ct = crate::encrypt(
        glyx_core::Cipher::Xchacha20poly1305,
        key,
        &plain,
        format!("glyx-pointer-v1:{target}").as_bytes(),
    )?;
    let mut packed = Vec::with_capacity(ct.nonce.len() + ct.ct.len());
    packed.extend_from_slice(&ct.nonce);
    packed.extend_from_slice(&ct.ct);
    Ok(format!("__GLYXENC:V1:{}__", URL_SAFE_NO_PAD.encode(packed)))
}

pub fn open_pointer(
    key: &[u8; 32],
    placeholder: &str,
    target: &str,
) -> Result<(Uuid, String), CryptoError> {
    let body = placeholder
        .strip_prefix("__GLYXENC:V1:")
        .and_then(|s| s.strip_suffix("__"))
        .ok_or_else(|| CryptoError::Param("not a glyx pointer".into()))?;
    let packed = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|e| CryptoError::Param(e.to_string()))?;
    if packed.len() < 24 + 16 + 16 {
        return Err(CryptoError::Param("pointer too short".into()));
    }
    let (nonce, ct) = packed.split_at(24);
    let pt = crate::decrypt(
        glyx_core::Cipher::Xchacha20poly1305,
        key,
        nonce,
        ct,
        format!("glyx-pointer-v1:{target}").as_bytes(),
    )?;
    if pt.len() < 16 + 1 + 1 + 32 {
        return Err(CryptoError::Decrypt);
    }
    let mut id_bytes = [0u8; 16];
    id_bytes.copy_from_slice(&pt[..16]);
    let id = Uuid::from_bytes(id_bytes);
    if pt[16] != 0x00 || pt[pt.len() - 33] != 0x00 {
        return Err(CryptoError::Decrypt);
    }
    let rest = &pt[17..pt.len() - 33];
    let field = String::from_utf8(rest.to_vec()).map_err(|_| CryptoError::Decrypt)?;
    let expect = blake3::hash(format!("{id}/{field}").as_bytes());
    if expect.as_bytes() != &pt[pt.len() - 32..] {
        return Err(CryptoError::Decrypt);
    }
    Ok((id, field))
}

#[must_use]
pub fn masked_tag(key: &[u8; 32], item_id: &Uuid, field: &str, target: &str) -> String {
    let mut hasher = blake3::Hasher::new_keyed(key);
    hasher.update(format!("glyx-mask-v1:{target}:{item_id}/{field}").as_bytes());
    format!("ENC[{}]", &hasher.finalize().to_hex()[..12])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pointer_roundtrip_and_binding() {
        let key = [9u8; 32];
        let id = Uuid::now_v7();
        let s = seal_pointer(&key, &id, "password", "/home/u/.env").expect("seal");
        assert!(s.starts_with("__GLYXENC:V1:") && s.ends_with("__"));
        let (back_id, back_field) = open_pointer(&key, &s, "/home/u/.env").expect("open");
        assert_eq!(back_id, id);
        assert_eq!(back_field, "password");
        assert!(open_pointer(&key, &s, "/other/path").is_err());
        assert!(open_pointer(&[1u8; 32], &s, "/home/u/.env").is_err());
        assert!(open_pointer(&key, "{{glyx:abc/def}}", "/home/u/.env").is_err());
    }

    #[test]
    fn masked_tag_stable() {
        let key = [9u8; 32];
        let id = Uuid::now_v7();
        let a = masked_tag(&key, &id, "password", "/x");
        let b = masked_tag(&key, &id, "password", "/x");
        assert_eq!(a, b);
        assert_ne!(a, masked_tag(&key, &id, "password", "/y"));
    }
}
