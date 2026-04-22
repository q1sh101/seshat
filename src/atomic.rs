//! Atomic root file installer: temp-in-target + fsync + rename + parent fsync.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::error::Error;

pub fn install_root_file(destination: &Path, payload: &[u8], mode: u32) -> Result<(), Error> {
    let parent = destination.parent().ok_or_else(|| Error::Validation {
        field: "destination".to_string(),
        reason: format!(
            "cannot install to a path with no parent directory: {}",
            destination.display()
        ),
    })?;

    // Staging next to the destination keeps rename(2) atomic (same filesystem).
    let mut tmp = tempfile::Builder::new()
        .prefix(".seshat-install.")
        .tempfile_in(parent)?;

    tmp.as_file_mut().write_all(payload)?;

    // chmod before promotion so the new inode never shows default-umask mode.
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(mode))?;
    tmp.as_file_mut().sync_all()?;

    tmp.persist(destination).map_err(|e| e.error)?;

    // fsync parent so the new directory entry is durable.
    fs::File::open(parent)?.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::tempdir;

    fn read_file(path: &Path) -> Vec<u8> {
        let mut f = fs::File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    fn file_mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn install_root_file_writes_payload_with_mode_to_fresh_destination() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("99-kernel-hardening.conf");
        install_root_file(&dst, b"kernel.kptr_restrict = 2\n", 0o644).unwrap();
        assert_eq!(read_file(&dst), b"kernel.kptr_restrict = 2\n");
        assert_eq!(file_mode(&dst), 0o644);
    }

    #[test]
    fn install_root_file_overwrites_existing_destination() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("99-kernel-hardening.conf");
        fs::write(&dst, b"old payload").unwrap();
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o600)).unwrap();

        install_root_file(&dst, b"new payload", 0o644).unwrap();
        assert_eq!(read_file(&dst), b"new payload");
        assert_eq!(file_mode(&dst), 0o644);
    }

    #[test]
    fn install_root_file_sets_requested_mode_on_destination() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("99-kernel-hardening.conf");
        install_root_file(&dst, b"payload", 0o600).unwrap();
        assert_eq!(file_mode(&dst), 0o600);
    }

    #[test]
    fn install_root_file_rejects_destination_without_parent() {
        let err = install_root_file(Path::new("/"), b"x", 0o644).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn install_root_file_fails_when_parent_dir_missing() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("no-such-subdir").join("99.conf");
        let err = install_root_file(&dst, b"x", 0o644).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn install_root_file_leaves_no_temp_files_on_success() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("99.conf");
        install_root_file(&dst, b"payload", 0o644).unwrap();

        let mut leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        leftovers.sort();
        assert_eq!(leftovers, vec![std::ffi::OsString::from("99.conf")]);
    }

    #[test]
    fn install_root_file_writes_large_payload_intact() {
        let dir = tempdir().unwrap();
        let dst = dir.path().join("99.conf");
        let payload = vec![b'x'; 64 * 1024 + 7];
        install_root_file(&dst, &payload, 0o644).unwrap();
        assert_eq!(read_file(&dst), payload);
    }
}
