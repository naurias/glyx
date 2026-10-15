use crate::CryptoError;

pub fn fill_random(buf: &mut [u8]) -> Result<(), CryptoError> {
    getrandom::getrandom(buf).map_err(|e| CryptoError::Param(e.to_string()))?;
    Ok(())
}

pub fn generate_keyfile() -> Result<[u8; 32], CryptoError> {
    let mut out = [0u8; 32];
    fill_random(&mut out)?;
    Ok(out)
}

pub fn generate_data_key() -> Result<[u8; 32], CryptoError> {
    let mut out = [0u8; 32];
    fill_random(&mut out)?;
    Ok(out)
}

pub fn generate_salt() -> Result<[u8; 16], CryptoError> {
    let mut out = [0u8; 16];
    fill_random(&mut out)?;
    Ok(out)
}

pub fn generate_x_nonce() -> Result<[u8; 24], CryptoError> {
    let mut out = [0u8; 24];
    fill_random(&mut out)?;
    Ok(out)
}

pub fn generate_aes_nonce() -> Result<[u8; 12], CryptoError> {
    let mut out = [0u8; 12];
    fill_random(&mut out)?;
    Ok(out)
}
