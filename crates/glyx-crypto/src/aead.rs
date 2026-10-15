use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes256Gcm;
use aes_gcm::KeyInit;
use chacha20poly1305::aead::Payload as ChachaPayload;
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::{rand, CryptoError};

#[derive(Debug, Clone)]
pub struct Ciphertext {
    pub nonce: Vec<u8>,
    pub ct: Vec<u8>,
}

pub fn encrypt(
    cipher: glyx_core::Cipher,
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Ciphertext, CryptoError> {
    match cipher {
        glyx_core::Cipher::Xchacha20poly1305 => {
            let nonce = rand::generate_x_nonce()?;
            let c = XChaCha20Poly1305::new(key.into());
            let ct = c
                .encrypt(
                    &XNonce::from(nonce),
                    ChachaPayload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Decrypt)?;
            Ok(Ciphertext {
                nonce: nonce.to_vec(),
                ct,
            })
        }
        glyx_core::Cipher::Aes256gcm => {
            let nonce = rand::generate_aes_nonce()?;
            let c = Aes256Gcm::new(key.into());
            let ct = c
                .encrypt(
                    nonce.as_ref().into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| CryptoError::Decrypt)?;
            Ok(Ciphertext {
                nonce: nonce.to_vec(),
                ct,
            })
        }
    }
}

pub fn decrypt(
    cipher: glyx_core::Cipher,
    key: &[u8; 32],
    nonce: &[u8],
    ct: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    match cipher {
        glyx_core::Cipher::Xchacha20poly1305 => {
            let nonce: &[u8; 24] = nonce
                .try_into()
                .map_err(|_| CryptoError::Param("xchacha nonce must be 24 bytes".into()))?;
            let c = XChaCha20Poly1305::new(key.into());
            let pt = c
                .decrypt(&XNonce::from(*nonce), ChachaPayload { msg: ct, aad })
                .map_err(|_| CryptoError::Decrypt)?;
            Ok(Zeroizing::new(pt))
        }
        glyx_core::Cipher::Aes256gcm => {
            let nonce: &[u8; 12] = nonce
                .try_into()
                .map_err(|_| CryptoError::Param("aes-gcm nonce must be 12 bytes".into()))?;
            let c = Aes256Gcm::new(key.into());
            let pt = c
                .decrypt(nonce.as_ref().into(), Payload { msg: ct, aad })
                .map_err(|_| CryptoError::Decrypt)?;
            Ok(Zeroizing::new(pt))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_both_ciphers() {
        for cipher in [
            glyx_core::Cipher::Xchacha20poly1305,
            glyx_core::Cipher::Aes256gcm,
        ] {
            let key = [7u8; 32];
            let ct = encrypt(cipher, &key, b"hello glyx", b"aad").expect("encrypts");
            let pt = decrypt(cipher, &key, &ct.nonce, &ct.ct, b"aad").expect("decrypts");
            assert_eq!(&*pt, b"hello glyx");
        }
    }

    #[test]
    fn tamper_fails() {
        let key = [7u8; 32];
        let mut ct =
            encrypt(glyx_core::Cipher::Xchacha20poly1305, &key, b"data", b"aad").expect("encrypts");
        ct.ct[0] ^= 1;
        assert!(decrypt(
            glyx_core::Cipher::Xchacha20poly1305,
            &key,
            &ct.nonce,
            &ct.ct,
            b"aad"
        )
        .is_err());
        let ct = encrypt(glyx_core::Cipher::Aes256gcm, &key, b"data", b"aad").expect("encrypts");
        assert!(decrypt(
            glyx_core::Cipher::Aes256gcm,
            &key,
            &ct.nonce,
            &ct.ct,
            b"other"
        )
        .is_err());
    }
}
