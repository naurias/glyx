use ssh_key::{Algorithm, PrivateKey};

use crate::CryptoError;

pub struct SshPair {
    pub openssh_private: String,
    pub openssh_public: String,
}

impl std::fmt::Debug for SshPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshPair")
            .field("openssh_private", &"[redacted]")
            .field("openssh_public", &self.openssh_public)
            .finish()
    }
}

pub fn generate(kind: &str, comment: &str) -> Result<SshPair, CryptoError> {
    let algo = match kind {
        "ed25519" => Algorithm::Ed25519,
        "rsa4096" => Algorithm::Rsa { hash: None },
        _ => return Err(CryptoError::Param("kind must be ed25519 or rsa4096".into())),
    };
    let mut rng = ssh_key::rand_core::OsRng;
    let private =
        PrivateKey::random(&mut rng, algo).map_err(|e| CryptoError::Param(e.to_string()))?;
    let openssh_private = private
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| CryptoError::Param(e.to_string()))?
        .to_string();
    let mut public = private
        .public_key()
        .to_openssh()
        .map_err(|e| CryptoError::Param(e.to_string()))?;
    if !comment.is_empty() {
        public.push(' ');
        public.push_str(comment);
    }
    Ok(SshPair {
        openssh_private,
        openssh_public: public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_roundtrip() {
        let pair = generate("ed25519", "test").expect("generates");
        assert!(pair.openssh_private.contains("OPENSSH PRIVATE KEY"));
        let parsed = ssh_key::PublicKey::from_openssh(&pair.openssh_public).expect("parses");
        assert_eq!(parsed.algorithm(), Algorithm::Ed25519);
        assert!(generate("dsa", "").is_err());
    }
}
