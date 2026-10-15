use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::{Zeroize, Zeroizing};

use crate::{rand, CryptoError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfPreset {
    Balanced,
    Hardened,
    Mobile,
    Custom(glyx_core::KdfParams),
}

impl KdfPreset {
    pub fn params(self) -> Result<glyx_core::KdfParams, CryptoError> {
        let p = match self {
            Self::Balanced => glyx_core::KdfParams::balanced(),
            Self::Hardened => glyx_core::KdfParams::hardened(),
            Self::Mobile => glyx_core::KdfParams::mobile(),
            Self::Custom(p) => p,
        };
        p.validate()
            .map_err(|e| CryptoError::Param(e.to_string()))?;
        Ok(p)
    }
}

pub fn derive_kek(
    password: &[u8],
    keyfile: &[u8; 32],
    salt: &[u8; 16],
    params: glyx_core::KdfParams,
) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    params
        .validate()
        .map_err(|e| CryptoError::Param(e.to_string()))?;
    let argon = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| CryptoError::Param(e.to_string()))?,
    );
    let mut secret = Vec::with_capacity(password.len() + 1 + keyfile.len());
    secret.extend_from_slice(password);
    secret.push(0x00);
    secret.extend_from_slice(keyfile);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(&secret, salt, &mut out)
        .map_err(|e| CryptoError::Kdf(e.to_string()))?;
    secret.zeroize();
    Ok(Zeroizing::new(out))
}

pub fn derive_kek_fresh_salt(
    password: &[u8],
    keyfile: &[u8; 32],
    params: glyx_core::KdfParams,
) -> Result<(Zeroizing<[u8; 32]>, [u8; 16]), CryptoError> {
    let salt = rand::generate_salt()?;
    Ok((derive_kek(password, keyfile, &salt, params)?, salt))
}
