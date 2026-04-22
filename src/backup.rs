
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Error;

pub const BACKUP_SUFFIX: &str = "bak";

fn format_backup_name(basename: &OsStr, secs: u64, nanos: u32, pid: u32) -> OsString {
    let mut out = OsString::from(basename);
    out.push(format!(".{secs}.{nanos:09}.{pid}.{BACKUP_SUFFIX}"));
    out
}

fn backup_path_in(
    backup_dir: &Path,
    destination: &Path,
    secs: u64,
    nanos: u32,
    pid: u32,
) -> PathBuf {
    let basename = destination
        .file_name()
        .unwrap_or_else(|| OsStr::new("unnamed"));
    backup_dir.join(format_backup_name(basename, secs, nanos, pid))
}

fn now_components() -> Result<(u64, u32), Error> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Validation {
            field: "system_time".to_string(),
            reason: format!("system clock is before UNIX_EPOCH: {e}"),
        })?;
    Ok((d.as_secs(), d.subsec_nanos()))
}

fn create_backup_with_clock(
    destination: &Path,
    backup_dir: &Path,
    secs: u64,
    nanos: u32,
    pid: u32,
) -> Result<Option<PathBuf>, Error> {
    // symlink_metadata does not follow; a symlink source is rejected.
    let metadata = match fs::symlink_metadata(destination) {
        Ok(m) => m,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };
    if !metadata.file_type().is_file() {
        return Err(Error::UnsafePath {
            path: destination.to_path_buf(),
            reason: "backup source is not a regular file".to_string(),
        });
    }

    let backup = backup_path_in(backup_dir, destination, secs, nanos, pid);

    // Stage under `.seshat-backup.*` so a crash before promotion cannot
    // be mistaken for a real rollback `.bak`.
    let mut tmp = tempfile::Builder::new()
        .prefix(".seshat-backup.")
        .tempfile_in(backup_dir)?;

    let mut src = fs::File::open(destination)?;
    io::copy(&mut src, tmp.as_file_mut())?;

    fs::set_permissions(tmp.path(), metadata.permissions())?;
    tmp.as_file_mut().sync_all()?;

    // persist_noclobber: link(2) semantics keep "rejected, not overwritten".
    tmp.persist_noclobber(&backup).map_err(|e| e.error)?;

    // fsync parent so the new dir entry survives a crash after rename.
    fs::File::open(backup_dir)?.sync_all()?;

    Ok(Some(backup))
}

pub fn create_backup(destination: &Path, backup_dir: &Path) -> Result<Option<PathBuf>, Error> {
    let (secs, nanos) = now_components()?;
    create_backup_with_clock(destination, backup_dir, secs, nanos, std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use tempfile::tempdir;

    #[test]
    fn format_backup_name_is_stable() {
        let out = format_backup_name(
            OsStr::new("99-kernel-hardening.conf"),
            1_700_000_000,
            123,
            42,
        );
        assert_eq!(
            out,
            OsString::from("99-kernel-hardening.conf.1700000000.000000123.42.bak")
        );
    }

    #[test]
    fn format_backup_name_pads_nanos_to_nine_digits() {
        let out = format_backup_name(OsStr::new("x"), 1, 5, 2);
        assert_eq!(out, OsString::from("x.1.000000005.2.bak"));
    }

    #[test]
    fn format_backup_name_handles_zero_nanos() {
        let out = format_backup_name(OsStr::new("x"), 0, 0, 1);
        assert_eq!(out, OsString::from("x.0.000000000.1.bak"));
    }

    #[test]
    fn backup_path_is_placed_under_backup_dir_not_beside_destination() {
        let path = backup_path_in(
            Path::new("/var/lib/seshat/backups/sysctl"),
            Path::new("/etc/sysctl.d/99.conf"),
            10,
            20,
            30,
        );
        assert_eq!(
            path,
            PathBuf::from("/var/lib/seshat/backups/sysctl/99.conf.10.000000020.30.bak")
        );
    }

    #[test]
    fn backup_path_keeps_basename_when_destination_is_bare_filename() {
        let path = backup_path_in(
            Path::new("/srv/seshat/backups/modules"),
            Path::new("99.conf"),
            10,
            20,
            30,
        );
        assert_eq!(
            path,
            PathBuf::from("/srv/seshat/backups/modules/99.conf.10.000000020.30.bak")
        );
    }

    fn write_file(path: &Path, body: &[u8]) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(body).unwrap();
    }

    fn read_file(path: &Path) -> Vec<u8> {
        let mut f = fs::File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn create_backup_returns_none_when_destination_missing() {
        let state = tempdir().unwrap();
        let backup_dir = state.path().join("backups/sysctl");
        fs::create_dir_all(&backup_dir).unwrap();

        let dst = tempdir().unwrap().path().join("missing.conf");
        let out = create_backup_with_clock(&dst, &backup_dir, 1, 2, 3).unwrap();
        assert!(out.is_none());
    }

    #[test]
    fn create_backup_writes_into_backup_dir_not_beside_destination() {
        let state = tempdir().unwrap();
        let backup_dir = state.path().join("backups/sysctl");
        fs::create_dir_all(&backup_dir).unwrap();

        let etc = tempdir().unwrap();
        let dst = etc.path().join("99.conf");
        write_file(&dst, b"payload");

        let out = create_backup_with_clock(&dst, &backup_dir, 1_700_000_000, 123, 42)
            .unwrap()
            .expect("backup path");
        assert_eq!(out, backup_dir.join("99.conf.1700000000.000000123.42.bak"));
        assert_eq!(out.parent().unwrap(), backup_dir);
        assert_ne!(out.parent().unwrap(), dst.parent().unwrap());
        assert_eq!(read_file(&out), b"payload");
        assert_eq!(read_file(&dst), b"payload");
    }

    #[test]
    fn create_backup_rejects_same_timestamp_collision() {
        let state = tempdir().unwrap();
        let backup_dir = state.path().join("backups/sysctl");
        fs::create_dir_all(&backup_dir).unwrap();

        let etc = tempdir().unwrap();
        let dst = etc.path().join("99.conf");
        write_file(&dst, b"payload");

        let first = create_backup_with_clock(&dst, &backup_dir, 1, 2, 3)
            .unwrap()
            .unwrap();
        assert!(first.exists());

        let err = create_backup_with_clock(&dst, &backup_dir, 1, 2, 3).unwrap_err();
        match err {
            Error::Io(e) => assert_eq!(e.kind(), io::ErrorKind::AlreadyExists),
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
    }

    #[test]
    fn create_backup_rejects_symlink_destination() {
        use std::os::unix::fs::symlink;
        let state = tempdir().unwrap();
        let backup_dir = state.path().join("backups/sysctl");
        fs::create_dir_all(&backup_dir).unwrap();

        let etc = tempdir().unwrap();
        let real = etc.path().join("real.conf");
        let link = etc.path().join("link.conf");
        write_file(&real, b"payload");
        symlink(&real, &link).unwrap();

        let err = create_backup_with_clock(&link, &backup_dir, 1, 2, 3).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn create_backup_preserves_source_mode() {
        use std::os::unix::fs::PermissionsExt;
        let state = tempdir().unwrap();
        let backup_dir = state.path().join("backups/sysctl");
        fs::create_dir_all(&backup_dir).unwrap();

        let etc = tempdir().unwrap();
        let dst = etc.path().join("99.conf");
        write_file(&dst, b"payload");
        fs::set_permissions(&dst, fs::Permissions::from_mode(0o600)).unwrap();

        let backup = create_backup_with_clock(&dst, &backup_dir, 1, 2, 3)
            .unwrap()
            .unwrap();
        let mode = fs::metadata(&backup).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn public_create_backup_writes_sibling_file_in_backup_dir() {
        let state = tempdir().unwrap();
        let backup_dir = state.path().join("backups/sysctl");
        fs::create_dir_all(&backup_dir).unwrap();

        let etc = tempdir().unwrap();
        let dst = etc.path().join("99.conf");
        write_file(&dst, b"payload");

        let backup = create_backup(&dst, &backup_dir)
            .unwrap()
            .expect("backup path");
        assert!(backup.exists());
        assert_eq!(read_file(&backup), b"payload");
        assert_eq!(backup.parent().unwrap(), backup_dir);
        assert_eq!(backup.extension().and_then(|e| e.to_str()), Some("bak"));
    }
}
