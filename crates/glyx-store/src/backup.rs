use std::fs;
use std::path::{Component, Path, PathBuf};

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;

use crate::{layout, StoreError, Vault};

const ALLOWED_TOP: [&str; 6] = [
    layout::VAULT_TOML,
    layout::KEYSLOTS_DIR,
    layout::ITEMS_DIR,
    layout::BLOBS_DIR,
    layout::HISTORY_DIR,
    layout::CONFLICTS_DIR,
];
const MAX_ENTRIES: usize = 100_000;
pub const MAX_ARCHIVE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct BackupReport {
    pub bytes: u64,
}

pub fn create(
    vault: &Vault,
    out: &Path,
    keyfile: Option<&Path>,
) -> Result<BackupReport, StoreError> {
    let out = ensure_outside_vault(vault, out)?;
    let keyfile = keyfile.and_then(|p| fs::canonicalize(p).ok());
    let result = (|| {
        let _lock = vault.try_lock()?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&out)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);
        builder.follow_symlinks(false);
        let root = vault.path();
        for name in [layout::KEYSLOTS_DIR, layout::ITEMS_DIR, layout::BLOBS_DIR] {
            append_tree(&mut builder, root, Path::new(name), keyfile.as_deref())?;
        }
        for name in [layout::HISTORY_DIR, layout::CONFLICTS_DIR] {
            if root.join(name).is_dir() {
                append_tree(&mut builder, root, Path::new(name), keyfile.as_deref())?;
            }
        }
        let vault_toml = root.join(layout::VAULT_TOML);
        builder.append_path_with_name(&vault_toml, layout::VAULT_TOML)?;
        let encoder = builder.into_inner()?;
        let file = encoder.finish()?;
        file.sync_all()?;
        let bytes = file.metadata()?.len();
        Ok(BackupReport { bytes })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&out);
    }
    result
}

pub fn restore(archive: &Path, dest: &Path) -> Result<(), StoreError> {
    if fs::symlink_metadata(dest).is_ok() {
        return Err(StoreError::AlreadyExists(dest.display().to_string()));
    }
    if archive.metadata()?.len() > MAX_ARCHIVE_BYTES {
        return Err(StoreError::Limit("backup archive is too large".into()));
    }
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
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(&tmp)?;
    let result = extract(archive, &tmp);
    if result.is_err() {
        let _ = fs::remove_dir_all(&tmp);
        return result;
    }
    if let Err(e) = Vault::open(&tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e);
    }
    harden_tree(&tmp)?;
    if let Err(e) = fs::rename(&tmp, dest) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e.into());
    }
    Ok(())
}

fn extract(archive: &Path, tmp: &Path) -> Result<(), StoreError> {
    let file = fs::File::open(archive)?;
    let mut tar = tar::Archive::new(GzDecoder::new(file));
    let mut entries = 0usize;
    let mut total = 0u64;
    for entry in tar.entries()? {
        let mut entry = entry?;
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err(StoreError::Limit("backup has too many entries".into()));
        }
        let rel = entry.path()?.into_owned();
        if !safe_path(&rel) {
            return Err(StoreError::Corrupt(format!(
                "unsafe backup path: {}",
                rel.display()
            )));
        }
        let kind = entry.header().entry_type();
        if kind.is_dir() {
            fs::create_dir_all(tmp.join(&rel))?;
            continue;
        }
        if !kind.is_file() {
            return Err(StoreError::Corrupt(format!(
                "unsupported backup entry: {}",
                rel.display()
            )));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_ARCHIVE_BYTES {
            return Err(StoreError::Limit("backup expands too large".into()));
        }
        entry.unpack(tmp.join(&rel))?;
    }
    if !tmp.join(layout::VAULT_TOML).is_file() {
        return Err(StoreError::Corrupt("backup is missing VAULT.toml".into()));
    }
    for dir in [
        layout::KEYSLOTS_DIR,
        layout::ITEMS_DIR,
        layout::BLOBS_DIR,
        layout::HISTORY_DIR,
        layout::CONFLICTS_DIR,
    ] {
        fs::create_dir_all(tmp.join(dir))?;
    }
    Ok(())
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
    if out.starts_with(&root) {
        return Err(StoreError::Corrupt(
            "backup output must be outside the vault".into(),
        ));
    }
    Ok(out)
}

fn append_tree(
    builder: &mut tar::Builder<GzEncoder<fs::File>>,
    root: &Path,
    rel: &Path,
    keyfile: Option<&Path>,
) -> Result<(), StoreError> {
    let path = root.join(rel);
    let meta = fs::symlink_metadata(&path)?;
    if meta.file_type().is_symlink() {
        return Err(StoreError::Corrupt(format!(
            "refusing to back up symlink: {}",
            rel.display()
        )));
    }
    if meta.is_dir() {
        builder.append_dir(rel, &path)?;
        let mut entries: Vec<_> = fs::read_dir(&path)?.flatten().collect();
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            append_tree(builder, root, &rel.join(entry.file_name()), keyfile)?;
        }
        return Ok(());
    }
    if !meta.is_file() {
        return Err(StoreError::Corrupt(format!(
            "unsupported vault entry: {}",
            rel.display()
        )));
    }
    if rel.extension().is_some_and(|ext| ext == "tmp") {
        return Ok(());
    }
    if keyfile.is_some_and(|kf| fs::canonicalize(&path).is_ok_and(|p| p == kf)) {
        return Ok(());
    }
    builder.append_path_with_name(&path, rel)?;
    Ok(())
}

fn safe_path(path: &Path) -> bool {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return false;
    }
    let mut components = path.components();
    let Some(Component::Normal(first)) = components.next() else {
        return false;
    };
    let first = first.to_string_lossy();
    if !ALLOWED_TOP.iter().any(|allowed| *allowed == first) {
        return false;
    }
    if first == layout::VAULT_TOML {
        return components.next().is_none();
    }
    for component in components {
        let Component::Normal(name) = component else {
            return false;
        };
        if name.to_string_lossy().contains('\\') {
            return false;
        }
    }
    true
}

fn harden_tree(path: &Path) -> Result<(), StoreError> {
    let meta = fs::symlink_metadata(path)?;
    if meta.file_type().is_symlink() {
        return Err(StoreError::Corrupt(
            "refusing symlink in restored vault".into(),
        ));
    }
    if meta.is_dir() {
        crate::vault::harden_dir(path);
        for entry in fs::read_dir(path)?.flatten() {
            harden_tree(&entry.path())?;
        }
    } else if meta.is_file() {
        crate::vault::harden_file(path);
    } else {
        return Err(StoreError::Corrupt(
            "unsupported file type in restored vault".into(),
        ));
    }
    Ok(())
}

fn random_suffix() -> Result<String, StoreError> {
    use std::fmt::Write as _;
    let mut bytes = [0u8; 8];
    glyx_crypto::rand::fill_random(&mut bytes)?;
    let mut out = String::with_capacity(16);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_excludes_index_and_device_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v.glyx");
        let archive = dir.path().join("v.tar.gz");
        let suite = glyx_core::CipherSuiteConfig {
            kdf: glyx_core::KdfId::Argon2id,
            cipher: glyx_core::Cipher::Xchacha20poly1305,
            params: glyx_core::KdfParams::mobile(),
        };
        Vault::init(&path, suite, b"pw", None).expect("init");
        let vault = Vault::open(&path).expect("open");
        vault.device_id().expect("device");
        create(&vault, &archive, None).expect("backup");
        let file = fs::File::open(&archive).expect("archive");
        let mut tar = tar::Archive::new(GzDecoder::new(file));
        let names: Vec<String> = tar
            .entries()
            .expect("entries")
            .flatten()
            .map(|e| e.path().expect("path").to_string_lossy().into_owned())
            .collect();
        assert!(names.iter().any(|n| n == "VAULT.toml"), "{names:?}");
        assert!(names.iter().any(|n| n == "keyslots"), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("glyx.db")), "{names:?}");
        assert!(!names.iter().any(|n| n == "device.id"), "{names:?}");
    }

    #[test]
    fn unsafe_restore_paths_rejected() {
        assert!(safe_path(Path::new("VAULT.toml")));
        assert!(safe_path(Path::new("items/abc.envelope.json")));
        assert!(safe_path(Path::new("history/abc/1-0.json")));
        assert!(!safe_path(Path::new("../evil")));
        assert!(!safe_path(Path::new("/etc/passwd")));
        assert!(!safe_path(Path::new("glyx.db")));
        assert!(!safe_path(Path::new("device.id")));
        assert!(!safe_path(Path::new("VAULT.toml/evil")));
        assert!(!safe_path(Path::new("items/../evil")));
        assert!(!safe_path(Path::new("items\\evil")));
    }
}
