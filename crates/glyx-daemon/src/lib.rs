use std::path::PathBuf;

pub mod api;
pub mod passkey;
pub mod picker;
pub mod runtime;

#[derive(Debug)]
pub enum DaemonState {
    Locked { path: PathBuf },
    Unlocked(glyx_store::UnlockedVault),
}

impl DaemonState {
    pub fn locked(path: PathBuf) -> Result<Self, glyx_store::StoreError> {
        glyx_store::Vault::open(&path)?;
        Ok(Self::Locked { path })
    }
    #[must_use = "use the returned unlocked state"]
    pub fn unlock(
        self,
        password: &[u8],
        keyfile: &[u8; 32],
    ) -> Result<Self, glyx_store::StoreError> {
        match self {
            Self::Locked { path } => {
                let vault = glyx_store::Vault::open(&path)?;
                Ok(Self::Unlocked(vault.unlock(password, keyfile)?))
            }
            already @ Self::Unlocked(_) => Ok(already),
        }
    }
    #[must_use = "use the returned locked state"]
    pub fn lock(self) -> Self {
        match self {
            Self::Unlocked(v) => {
                let path = v.vault_path();
                Self::Locked { path }
            }
            locked @ Self::Locked { .. } => locked,
        }
    }
    #[must_use]
    pub fn is_unlocked(&self) -> bool {
        matches!(self, Self::Unlocked(_))
    }
}
