use std::path::Path;

use crate::StoreError;

pub fn read(path: &Path) -> Result<[u8; 32], StoreError> {
    let bytes = std::fs::read(path)?;
    if bytes.len() != 32 {
        return Err(StoreError::Corrupt(format!(
            "keyfile {} must hold exactly 32 bytes",
            path.display()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn load_or_create(path: &Path) -> Result<[u8; 32], StoreError> {
    if path.exists() {
        return read(path);
    }
    let kf = glyx_crypto::generate_keyfile()?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, kf)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(kf)
}
