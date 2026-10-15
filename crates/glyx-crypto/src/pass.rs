use crate::CryptoError;

pub const PASSWORD_ALPHABET: &str =
    "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$%^&*-_+=";

pub fn generate_password(len: usize) -> Result<String, CryptoError> {
    if len == 0 || len > 1024 {
        return Err(CryptoError::Param(
            "password length must be 1..=1024".into(),
        ));
    }
    let alpha = PASSWORD_ALPHABET.as_bytes();
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 64];
    let mut i = 0;
    while i < len {
        crate::rand::fill_random(&mut buf)?;
        for b in buf {
            if i >= len {
                break;
            }
            if (b as usize) < 256 - (256 % alpha.len()) {
                out.push(alpha[(b as usize) % alpha.len()] as char);
                i += 1;
            }
        }
    }
    Ok(out)
}
