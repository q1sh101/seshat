use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::deploy::ReloadStatus;
use crate::atomic::install_root_file;
use crate::backup::BACKUP_SUFFIX;
use crate::error::Error;

const SYSCTL_DROPIN_MODE: u32 = 0o644;

#[derive(Debug, PartialEq, Eq)]
pub struct SysctlRestore {
    pub restored_from: PathBuf,
    pub reload: ReloadStatus,
}

pub fn restore_sysctl_from_backup<F>(
    target: &Path,
    backup_dir: &Path,
    reload: F,
) -> Result<SysctlRestore, Error>
where
    F: FnOnce() -> ReloadStatus,
{
    let basename = target.file_name().ok_or_else(|| Error::Validation {
        field: "sysctl.target".to_string(),
        reason: format!("restore target has no file name: {}", target.display()),
    })?;

    let backup = latest_backup_for(basename, backup_dir)?.ok_or_else(|| Error::Validation {
        field: "sysctl.backup".to_string(),
        reason: format!(
            "no backup available in {} to restore {}",
            backup_dir.display(),
            target.display()
        ),
    })?;

    // symlink_metadata does not follow; a symlink backup entry is rejected.
    let metadata = fs::symlink_metadata(&backup)?;
    if !metadata.file_type().is_file() {
        return Err(Error::UnsafePath {
            path: backup.clone(),
            reason: "backup source is not a regular file".to_string(),
        });
    }
    let payload = fs::read(&backup)?;

    install_root_file(target, &payload, SYSCTL_DROPIN_MODE)?;

    // Only after a successful install do we touch the kernel.
    let reload_status = reload();

    Ok(SysctlRestore {
        restored_from: backup,
        reload: reload_status,
    })
}

fn latest_backup_for(basename: &OsStr, backup_dir: &Path) -> Result<Option<PathBuf>, Error> {
    let entries = match fs::read_dir(backup_dir) {
        Ok(it) => it,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(Error::Io(e)),
    };

    let mut best: Option<((u64, u32, u32), PathBuf)> = None;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(ts) = parse_backup_suffix(basename, &name) else {
            continue;
        };
        let candidate = entry.path();
        let better = best.as_ref().is_none_or(|(bts, _)| ts > *bts);
        if better {
            best = Some((ts, candidate));
        }
    }
    Ok(best.map(|(_, path)| path))
}

// Canonical layout from backup::create_backup: "<basename>.<secs>.<nanos9>.<pid>.bak".
fn parse_backup_suffix(basename: &OsStr, name: &OsStr) -> Option<(u64, u32, u32)> {
    let full = name.to_str()?;
    let base = basename.to_str()?;
    let tail = full.strip_prefix(base)?.strip_prefix('.')?;
    let core = tail.strip_suffix(BACKUP_SUFFIX)?.strip_suffix('.')?;
    let mut parts = core.rsplitn(3, '.');
    let pid = parts.next()?.parse::<u32>().ok()?;
    let nanos = parts.next()?.parse::<u32>().ok()?;
    let secs = parts.next()?.parse::<u64>().ok()?;
    Some((secs, nanos, pid))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::create_backup;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn env() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let target = dir.path().join("sysctl.d/99-test.conf");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        (dir, target, backup_dir)
    }

    fn seed_backup(
        backup_dir: &Path,
        basename: &str,
        secs: u64,
        nanos: u32,
        pid: u32,
        body: &[u8],
    ) -> PathBuf {
        let name = format!("{basename}.{secs}.{nanos:09}.{pid}.bak");
        let path = backup_dir.join(name);
        fs::write(&path, body).unwrap();
        path
    }

    fn applied() -> ReloadStatus {
        ReloadStatus::Applied
    }

    fn never_reload() -> ReloadStatus {
        panic!("reload must not run in this scenario")
    }

    #[test]
    fn restore_returns_err_when_no_backup_exists() {
        let (_d, target, backup_dir) = env();
        let err = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
        match err {
            Error::Validation { field, reason } => {
                assert_eq!(field, "sysctl.backup");
                assert!(reason.contains("no backup available"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert!(!target.exists());
    }

    #[test]
    fn restore_returns_err_when_backup_dir_missing() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("sysctl.d/99-test.conf");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let backup_dir = dir.path().join("never_created");
        let err = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn restore_copies_single_backup_onto_target() {
        let (_d, target, backup_dir) = env();
        let backup = seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload-A\n");
        let outcome = restore_sysctl_from_backup(&target, &backup_dir, applied).unwrap();
        assert_eq!(outcome.restored_from, backup);
        assert_eq!(outcome.reload, ReloadStatus::Applied);
        assert_eq!(fs::read(&target).unwrap(), b"payload-A\n");
    }

    #[test]
    fn restore_picks_latest_backup_by_timestamp_tuple() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 1, 1, b"older-secs\n");
        seed_backup(&backup_dir, "99-test.conf", 20, 0, 1, b"middle\n");
        let latest = seed_backup(&backup_dir, "99-test.conf", 20, 500, 1, b"newest-nanos\n");
        let outcome = restore_sysctl_from_backup(&target, &backup_dir, applied).unwrap();
        assert_eq!(outcome.restored_from, latest);
        assert_eq!(fs::read(&target).unwrap(), b"newest-nanos\n");
    }

    #[test]
    fn restore_tie_broken_by_higher_pid() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 20, 100, b"pid-100\n");
        let winner = seed_backup(&backup_dir, "99-test.conf", 10, 20, 999, b"pid-999\n");
        let outcome = restore_sysctl_from_backup(&target, &backup_dir, applied).unwrap();
        assert_eq!(outcome.restored_from, winner);
    }

    #[test]
    fn restore_ignores_backups_for_other_basenames() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "other.conf", 99, 99, 99, b"wrong-file\n");
        let err = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn restore_ignores_files_without_canonical_suffix() {
        let (_d, target, backup_dir) = env();
        fs::write(backup_dir.join("99-test.conf.bak"), b"no-timestamp\n").unwrap();
        fs::write(
            backup_dir.join("99-test.conf.10.20.30.notbak"),
            b"wrong-ext\n",
        )
        .unwrap();
        fs::write(backup_dir.join("README"), b"unrelated\n").unwrap();
        let err = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn restore_rejects_when_backup_entry_is_a_symlink() {
        let (_d, target, backup_dir) = env();
        let real = backup_dir.join("real.data");
        fs::write(&real, b"payload\n").unwrap();
        let link = backup_dir.join("99-test.conf.10.000000020.30.bak");
        symlink(&real, &link).unwrap();
        let err = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert!(!target.exists());
    }

    #[test]
    fn restore_rejects_when_target_is_a_symlink() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        let elsewhere = backup_dir.join("unrelated.conf");
        fs::write(&elsewhere, b"elsewhere\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&elsewhere, &target).unwrap();
        let err = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert_eq!(fs::read(&elsewhere).unwrap(), b"elsewhere\n");
    }

    #[test]
    fn restore_forces_target_mode_to_0o644_regardless_of_backup_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, target, backup_dir) = env();
        let backup = seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
        restore_sysctl_from_backup(&target, &backup_dir, applied).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn restore_round_trip_after_create_backup_matches_payload() {
        let (_d, target, backup_dir) = env();
        fs::write(&target, b"original-payload\n").unwrap();
        let backup = create_backup(&target, &backup_dir).unwrap().unwrap();
        fs::write(&target, b"post-deploy-payload\n").unwrap();
        let outcome = restore_sysctl_from_backup(&target, &backup_dir, applied).unwrap();
        assert_eq!(outcome.restored_from, backup);
        assert_eq!(fs::read(&target).unwrap(), b"original-payload\n");
    }

    #[test]
    fn restore_does_not_touch_target_when_backup_missing() {
        let (_d, target, backup_dir) = env();
        fs::write(&target, b"live\n").unwrap();
        let _ = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
        assert_eq!(fs::read(&target).unwrap(), b"live\n");
    }

    #[test]
    fn restore_invokes_reload_exactly_once_after_successful_install() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        let mut count = 0;
        let reload = || {
            count += 1;
            ReloadStatus::Applied
        };
        let outcome = restore_sysctl_from_backup(&target, &backup_dir, reload).unwrap();
        assert_eq!(count, 1);
        assert_eq!(outcome.reload, ReloadStatus::Applied);
    }

    #[test]
    fn restore_reports_reload_unavailable_verbatim() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        let outcome =
            restore_sysctl_from_backup(&target, &backup_dir, || ReloadStatus::Unavailable).unwrap();
        assert_eq!(outcome.reload, ReloadStatus::Unavailable);
    }

    #[test]
    fn restore_reports_reload_failed_verbatim() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        let outcome = restore_sysctl_from_backup(&target, &backup_dir, || {
            ReloadStatus::Failed("exit 1".to_string())
        })
        .unwrap();
        match outcome.reload {
            ReloadStatus::Failed(reason) => assert_eq!(reason, "exit 1"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn restore_does_not_invoke_reload_when_no_backup_available() {
        let (_d, target, backup_dir) = env();
        let _ = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
    }

    #[test]
    fn restore_does_not_invoke_reload_when_backup_is_symlink() {
        let (_d, target, backup_dir) = env();
        let real = backup_dir.join("real.data");
        fs::write(&real, b"payload\n").unwrap();
        let link = backup_dir.join("99-test.conf.10.000000020.30.bak");
        symlink(&real, &link).unwrap();
        let _ = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
    }

    #[test]
    fn restore_does_not_invoke_reload_when_target_preflight_rejects() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        let elsewhere = backup_dir.join("unrelated.conf");
        fs::write(&elsewhere, b"elsewhere\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&elsewhere, &target).unwrap();
        let _ = restore_sysctl_from_backup(&target, &backup_dir, never_reload).unwrap_err();
    }

    #[test]
    fn parse_backup_suffix_rejects_nonnumeric_components() {
        let ts = parse_backup_suffix(OsStr::new("99.conf"), OsStr::new("99.conf.abc.def.ghi.bak"));
        assert!(ts.is_none());
    }

    #[test]
    fn parse_backup_suffix_rejects_wrong_extension() {
        let ts = parse_backup_suffix(OsStr::new("99.conf"), OsStr::new("99.conf.10.20.30.tar"));
        assert!(ts.is_none());
    }

    #[test]
    fn parse_backup_suffix_rejects_basename_mismatch() {
        let ts = parse_backup_suffix(OsStr::new("99.conf"), OsStr::new("other.conf.10.20.30.bak"));
        assert!(ts.is_none());
    }

    #[test]
    fn parse_backup_suffix_accepts_canonical_format() {
        let ts = parse_backup_suffix(
            OsStr::new("99-test.conf"),
            OsStr::new("99-test.conf.1700000000.000000123.42.bak"),
        );
        assert_eq!(ts, Some((1_700_000_000u64, 123u32, 42u32)));
    }
}
