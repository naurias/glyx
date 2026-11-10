use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{StoreError, Vault};

pub const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    pub bytes: u64,
}

pub fn create(
    vault: &Vault,
    out: &Path,
    _keyfile: Option<&Path>,
) -> Result<BackupReport, StoreError> {
    let out = ensure_outside_vault(vault, out)?;
    let _lock = vault.try_lock()?;
    let source = vault.path();
    let bytes = fs::metadata(source)?.len();
    if bytes > MAX_ARCHIVE_BYTES {
        return Err(StoreError::Limit("vault file is too large".into()));
    }
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut destination = options.open(&out)?;
        let mut input = fs::File::open(source)?;
        std::io::copy(&mut input, &mut destination)?;
        destination.sync_all()?;
        Ok(BackupReport { bytes })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&out);
    } else {
        crate::vault::harden_file(&out);
    }
    result
}

pub fn restore(archive: &Path, dest: &Path) -> Result<(), StoreError> {
    if fs::symlink_metadata(dest).is_ok() {
        return Err(StoreError::AlreadyExists(dest.display().to_string()));
    }
    let bytes = archive.metadata()?.len();
    if bytes > MAX_ARCHIVE_BYTES {
        return Err(StoreError::Limit("vault backup is too large".into()));
    }
    Vault::open(archive)?;
    let parent = parent_of(dest);
    if !parent.is_dir() {
        return Err(StoreError::Corrupt(
            "restore destination parent is missing".into(),
        ));
    }
    let name = dest
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| StoreError::Corrupt("restore destination has no name".into()))?;
    let tmp = parent.join(format!(".{name}-restore-{}", random_suffix()?));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut output = options.open(&tmp)?;
        let mut input = fs::File::open(archive)?;
        std::io::copy(&mut input, &mut output)?;
        output.sync_all()?;
        crate::vault::harden_file(&tmp);
        fs::rename(&tmp, dest)?;
        crate::vault::harden_file(dest);
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn parent_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_outside_vault(vault: &Vault, out: &Path) -> Result<PathBuf, StoreError> {
    let parent = parent_of(out);
    if !parent.is_dir() {
        return Err(StoreError::Corrupt(
            "backup output directory is missing".into(),
        ));
    }
    let name = out
        .file_name()
        .ok_or_else(|| StoreError::Corrupt("backup output has no file name".into()))?;
    let out = fs::canonicalize(parent)?.join(name);
    let root = fs::canonicalize(vault.path())?;
    if out == root {
        return Err(StoreError::Corrupt(
            "backup output must not be the vault file".into(),
        ));
    }
    Ok(out)
}

fn random_suffix() -> Result<String, StoreError> {
    let mut bytes = [0u8; 8];
    glyx_crypto::fill_random(&mut bytes)?;
    let mut out = String::with_capacity(16);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suite() -> glyx_core::CipherSuiteConfig {
        glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        }
    }

    #[test]
    fn backup_copies_the_single_vault_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.glyx");
        let backup = dir.path().join("v.backup.glyx");
        Vault::init(&path, suite(), b"pw", None).expect("init");
        let vault = Vault::open(&path).expect("open");
        let report = create(&vault, &backup, None).expect("backup");
        assert_eq!(report.bytes, fs::metadata(&path).expect("meta").len());
        assert_eq!(
            fs::read(&backup).expect("backup bytes"),
            fs::read(&path).expect("vault bytes")
        );
    }

    #[test]
    fn restore_copies_and_validates() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.glyx");
        let backup = dir.path().join("v.backup.glyx");
        let restored = dir.path().join("restored.glyx");
        Vault::init(&path, suite(), b"pw", None).expect("init");
        let vault = Vault::open(&path).expect("open");
        create(&vault, &backup, None).expect("backup");
        restore(&backup, &restored).expect("restore");
        let opened = Vault::open(&restored).expect("open restored");
        assert_eq!(opened.config().vault_id, vault.config().vault_id);
        assert!(restore(&backup, &restored).is_err());
    }

    #[test]
    fn rejects_non_vault_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bad = dir.path().join("bad.glyx");
        fs::write(&bad, b"not a vault").expect("write");
        let dest = dir.path().join("restored.glyx");
        assert!(restore(&bad, &dest).is_err());
    }
}
