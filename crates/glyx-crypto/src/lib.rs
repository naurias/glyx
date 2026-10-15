pub mod aead;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod keyslot;
pub mod pass;
pub mod rand;
pub mod ssh;
pub mod totp;

pub use aead::{decrypt, encrypt, Ciphertext};
pub use error::CryptoError;
pub use hash::blake3_hex;
pub use kdf::{derive_kek, derive_kek_fresh_salt, KdfPreset};
pub use keyslot::{seal_fresh_vault, Keyslot};
pub use rand::{
    fill_random, generate_aes_nonce, generate_data_key, generate_keyfile, generate_salt,
    generate_x_nonce,
};
pub use totp::TotpParams;
