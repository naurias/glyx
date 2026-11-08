use ssh_key::{Algorithm, PrivateKey};

use crate::CryptoError;

pub struct SshPair {
    pub openssh_private: String,
    pub openssh_public: String,
}

#[derive(Debug)]
pub struct ImportedSshKey {
    pub pair: SshPair,
    pub algorithm: String,
    pub comment: String,
}

impl std::fmt::Debug for SshPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshPair")
            .field("openssh_private", &"[redacted]")
            .field("openssh_public", &self.openssh_public)
            .finish()
    }
}

pub fn import(
    private_openssh: &str,
    passphrase: Option<&str>,
) -> Result<ImportedSshKey, CryptoError> {
    let parsed = PrivateKey::from_openssh(private_openssh)
        .map_err(|e| CryptoError::Param(format!("invalid OpenSSH private key: {e}")))?;
    let key = if parsed.is_encrypted() {
        let passphrase = passphrase.ok_or_else(|| {
            CryptoError::Param("private key is encrypted; a passphrase is required".into())
        })?;
        parsed
            .decrypt(passphrase)
            .map_err(|_| CryptoError::Param("wrong passphrase for private key".into()))?
    } else {
        parsed
    };
    let algorithm = match key.algorithm() {
        Algorithm::Ed25519 => "ed25519",
        Algorithm::Rsa { .. } => "rsa",
        other => {
            return Err(CryptoError::Param(format!(
                "unsupported SSH key algorithm: {}",
                other.as_str()
            )));
        }
    };
    let openssh_private = key
        .to_openssh(ssh_key::LineEnding::LF)
        .map_err(|e| CryptoError::Param(e.to_string()))?
        .to_string();
    let public_key = key.public_key();
    let comment = public_key.comment().to_owned();
    let openssh_public = public_key
        .to_openssh()
        .map_err(|e| CryptoError::Param(e.to_string()))?;
    Ok(ImportedSshKey {
        pair: SshPair {
            openssh_private,
            openssh_public,
        },
        algorithm: algorithm.to_owned(),
        comment,
    })
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

    #[test]
    fn import_plain_and_encrypted_keys() {
        let pair = generate("ed25519", "me@host").expect("generates");
        let imported = import(&pair.openssh_private, None).expect("import");
        assert_eq!(imported.algorithm, "ed25519");
        assert!(imported.comment.is_empty());

        let key =
            PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).expect("random");
        let encrypted = key
            .encrypt(&mut ssh_key::rand_core::OsRng, "pw")
            .expect("encrypt");
        let pem = encrypted
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .to_string();
        assert!(import(&pem, None).is_err());
        let imported = import(&pem, Some("pw")).expect("decrypt");
        assert_eq!(imported.algorithm, "ed25519");
        assert!(import(&pem, Some("wrong")).is_err());
    }
}
