pub mod error;
pub mod hlc;
pub mod ids;
pub mod item;
pub mod secret;
pub mod template;
pub mod vault_spec;

pub use error::CoreError;
pub use hlc::Hlc;
pub use ids::DeviceId;
pub use item::{Field, Item, ItemType};
pub use secret::SecretString;
pub use template::{parse_type, FieldSpec};
pub use vault_spec::{Cipher, CipherSuiteConfig, KdfId, KdfParams, VaultConfig};

#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
