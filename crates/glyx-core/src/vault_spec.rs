use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CoreError;

pub const MAX_FORMAT_VERSION: u32 = 2;
pub const KDF_M_KIB_MIN: u32 = 65_536;
pub const KDF_T_COST_MIN: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cipher {
    Xchacha20poly1305,
    Aes256gcm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    #[must_use]
    pub fn balanced() -> Self {
        Self {
            m_kib: 262_144,
            t_cost: 3,
            p_cost: 4,
        }
    }
    #[must_use]
    pub fn hardened() -> Self {
        Self {
            m_kib: 1_048_576,
            t_cost: 4,
            p_cost: 4,
        }
    }
    #[must_use]
    pub fn mobile() -> Self {
        Self {
            m_kib: 65536,
            t_cost: 3,
            p_cost: 2,
        }
    }
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.m_kib < KDF_M_KIB_MIN {
            return Err(CoreError::Validation {
                field: "m_kib",
                reason: format!("minimum is {KDF_M_KIB_MIN} KiB"),
            });
        }
        if self.t_cost < KDF_T_COST_MIN {
            return Err(CoreError::Validation {
                field: "t_cost",
                reason: format!("minimum is {KDF_T_COST_MIN}"),
            });
        }
        if self.p_cost == 0 {
            return Err(CoreError::Validation {
                field: "p_cost",
                reason: "must be at least 1".to_owned(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CipherSuiteConfig {
    pub kdf: KdfId,
    pub cipher: Cipher,
    #[serde(flatten)]
    pub params: KdfParams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KdfId {
    Argon2id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultConfig {
    pub format_version: u32,
    pub vault_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub keyfile_required: bool,
    pub cipher_suite: CipherSuiteConfig,
}

impl VaultConfig {
    #[must_use]
    pub fn new(vault_id: Uuid, suite: CipherSuiteConfig, keyfile_required: bool) -> Self {
        Self {
            format_version: MAX_FORMAT_VERSION,
            vault_id,
            created_at: Utc::now(),
            keyfile_required,
            cipher_suite: suite,
        }
    }
    pub fn parse_toml(text: &str) -> Result<Self, CoreError> {
        let cfg: Self = toml::from_str(text).map_err(|e| CoreError::Validation {
            field: "VAULT.toml",
            reason: e.to_string(),
        })?;
        cfg.validate()?;
        Ok(cfg)
    }
    pub fn to_toml(&self) -> Result<String, CoreError> {
        toml::to_string_pretty(self).map_err(|e| CoreError::Validation {
            field: "VAULT.toml",
            reason: e.to_string(),
        })
    }
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.format_version > MAX_FORMAT_VERSION {
            return Err(CoreError::UnsupportedVersion {
                found: self.format_version,
                max_supported: MAX_FORMAT_VERSION,
            });
        }
        if self.format_version < MAX_FORMAT_VERSION {
            return Err(CoreError::Validation {
                field: "format_version",
                reason: format!(
                    "format {} is no longer supported; recreate the vault (format {MAX_FORMAT_VERSION} required)",
                    self.format_version
                ),
            });
        }
        self.cipher_suite.params.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_toml_roundtrip() {
        let text = "format_version = 2\nvault_id = \"0191a2b3-c4d5-7e6f-8901-234567890abc\"\ncreated_at = \"2026-10-15T00:00:00Z\"\nkeyfile_required = true\n[cipher_suite]\nkdf = \"argon2id\"\ncipher = \"xchacha20poly1305\"\nm_kib = 262144\nt_cost = 3\np_cost = 4\n";
        let cfg = VaultConfig::parse_toml(text).expect("golden parses");
        assert_eq!(cfg.format_version, 2);
        assert!(cfg.keyfile_required);
        assert_eq!(cfg.cipher_suite.cipher, Cipher::Xchacha20poly1305);
        let _ = cfg.to_toml().expect("renders");
    }

    #[test]
    fn rejects_old_version() {
        let text = "format_version = 1\nvault_id = \"0191a2b3-c4d5-7e6f-8901-234567890abc\"\ncreated_at = \"2026-10-15T00:00:00Z\"\nkeyfile_required = true\n[cipher_suite]\nkdf = \"argon2id\"\ncipher = \"xchacha20poly1305\"\nm_kib = 262144\nt_cost = 3\np_cost = 4\n";
        assert!(matches!(
            VaultConfig::parse_toml(text),
            Err(CoreError::Validation {
                field: "format_version",
                ..
            })
        ));
    }

    #[test]
    fn rejects_future_version() {
        let text = "format_version = 99\nvault_id = \"0191a2b3-c4d5-7e6f-8901-234567890abc\"\ncreated_at = \"2026-10-15T00:00:00Z\"\nkeyfile_required = true\n[cipher_suite]\nkdf = \"argon2id\"\ncipher = \"aes256gcm\"\nm_kib = 65536\nt_cost = 3\np_cost = 2\n";
        assert!(matches!(
            VaultConfig::parse_toml(text),
            Err(CoreError::UnsupportedVersion { found: 99, .. })
        ));
    }

    #[test]
    fn rejects_weak_kdf() {
        let weak = KdfParams {
            m_kib: 8192,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(weak.validate().is_err());
        assert!(KdfParams::mobile().validate().is_ok());
    }
}
