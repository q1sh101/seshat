use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::atomic::install_root_file;
use crate::backup::latest_backup_for;
use crate::error::Error;

const MODPROBE_DROPIN_MODE: u32 = 0o644;

#[derive(Debug, PartialEq, Eq)]
pub enum ModulesRestore {
    Restored { from: PathBuf },
    Removed { target: PathBuf },
    NothingToRollback,
}

impl ModulesRestore {
    // Drop-in change takes effect on next modprobe; already-loaded banned modules persist until reboot.
    pub fn reboot_required(&self) -> bool {
        matches!(
            self,
            ModulesRestore::Restored { .. } | ModulesRestore::Removed { .. }
        )
    }
}

pub fn restore_modules_from_backup(
    target: &Path,
    backup_dir: &Path,
) -> Result<ModulesRestore, Error> {
    let basename = target.file_name().ok_or_else(|| Error::Validation {
        field: "modules.target".to_string(),
        reason: format!("restore target has no file name: {}", target.display()),
    })?;

    if let Some(backup) = latest_backup_for(basename, backup_dir)? {
        return restore_from_backup(target, &backup);
    }

    remove_target_if_present(target)
}

fn restore_from_backup(target: &Path, backup: &Path) -> Result<ModulesRestore, Error> {
    // symlink_metadata does not follow; a symlink backup entry is rejected.
    let metadata = fs::symlink_metadata(backup)?;
    if !metadata.file_type().is_file() {
        return Err(Error::UnsafePath {
            path: backup.to_path_buf(),
            reason: "backup source is not a regular file".to_string(),
        });
    }
    let payload = fs::read(backup)?;
    install_root_file(target, &payload, MODPROBE_DROPIN_MODE)?;
    Ok(ModulesRestore::Restored {
        from: backup.to_path_buf(),
    })
}

fn remove_target_if_present(target: &Path) -> Result<ModulesRestore, Error> {
    match fs::symlink_metadata(target) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ModulesRestore::NothingToRollback),
        Err(e) => Err(Error::Io(e)),
        Ok(metadata) => {
            let ft = metadata.file_type();
            if ft.is_symlink() {
                return Err(Error::UnsafePath {
                    path: target.to_path_buf(),
                    reason: "managed modprobe target is a symlink; refusing to remove".to_string(),
                });
            }
            if !ft.is_file() {
                return Err(Error::UnsafePath {
                    path: target.to_path_buf(),
                    reason: "managed modprobe target is not a regular file".to_string(),
                });
            }
            fs::remove_file(target)?;
            Ok(ModulesRestore::Removed {
                target: target.to_path_buf(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::create_backup;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn env() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let target = dir.path().join("modprobe.d/99-test.conf");
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

    #[test]
    fn backup_present_restores_payload_and_flags_reboot_required() {
        let (_d, target, backup_dir) = env();
        let backup = seed_backup(
            &backup_dir,
            "99-test.conf",
            10,
            20,
            30,
            b"install ext4 /bin/false\n",
        );
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert_eq!(outcome, ModulesRestore::Restored { from: backup });
        assert!(outcome.reboot_required());
        assert_eq!(fs::read(&target).unwrap(), b"install ext4 /bin/false\n");
    }

    #[test]
    fn backup_present_picks_latest_by_timestamp_tuple() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 1, 1, b"older\n");
        seed_backup(&backup_dir, "99-test.conf", 20, 0, 1, b"middle\n");
        let latest = seed_backup(&backup_dir, "99-test.conf", 20, 500, 1, b"newest\n");
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert_eq!(outcome, ModulesRestore::Restored { from: latest });
        assert_eq!(fs::read(&target).unwrap(), b"newest\n");
    }

    #[test]
    fn backup_entry_as_symlink_is_rejected() {
        let (_d, target, backup_dir) = env();
        let real = backup_dir.join("real.data");
        fs::write(&real, b"payload\n").unwrap();
        let link = backup_dir.join("99-test.conf.10.000000020.30.bak");
        symlink(&real, &link).unwrap();
        let err = restore_modules_from_backup(&target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert!(!target.exists());
    }

    #[test]
    fn restore_path_refuses_when_target_is_symlink() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        let elsewhere = backup_dir.join("unrelated.conf");
        fs::write(&elsewhere, b"elsewhere\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&elsewhere, &target).unwrap();
        let err = restore_modules_from_backup(&target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert_eq!(fs::read(&elsewhere).unwrap(), b"elsewhere\n");
    }

    #[test]
    fn restore_path_forces_target_mode_to_0o644_regardless_of_backup_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, target, backup_dir) = env();
        let backup = seed_backup(&backup_dir, "99-test.conf", 10, 20, 30, b"payload\n");
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
        restore_modules_from_backup(&target, &backup_dir).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn round_trip_create_backup_then_restore_matches_payload() {
        let (_d, target, backup_dir) = env();
        fs::write(&target, b"install vfat /bin/false\n").unwrap();
        let backup = create_backup(&target, &backup_dir).unwrap().unwrap();
        fs::write(&target, b"install vfat /sbin/modprobe\n").unwrap();
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert_eq!(outcome, ModulesRestore::Restored { from: backup });
        assert_eq!(fs::read(&target).unwrap(), b"install vfat /bin/false\n");
    }

    #[test]
    fn no_backup_with_regular_target_removes_it_and_flags_reboot_required() {
        let (_d, target, backup_dir) = env();
        fs::write(&target, b"managed drop-in\n").unwrap();
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert_eq!(
            outcome,
            ModulesRestore::Removed {
                target: target.clone(),
            }
        );
        assert!(outcome.reboot_required());
        assert!(!target.exists());
    }

    #[test]
    fn no_backup_dir_with_regular_target_still_removes_it() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("modprobe.d/99-test.conf");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"managed\n").unwrap();
        let backup_dir = dir.path().join("never_created");
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert!(matches!(outcome, ModulesRestore::Removed { .. }));
        assert!(!target.exists());
    }

    #[test]
    fn no_backup_refuses_to_remove_when_target_is_symlink() {
        let (_d, target, backup_dir) = env();
        let elsewhere = backup_dir.join("unrelated.conf");
        fs::write(&elsewhere, b"elsewhere\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&elsewhere, &target).unwrap();
        let err = restore_modules_from_backup(&target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert!(
            fs::symlink_metadata(&target)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&elsewhere).unwrap(), b"elsewhere\n");
    }

    #[test]
    fn no_backup_refuses_to_remove_when_target_is_directory() {
        let (_d, target, backup_dir) = env();
        fs::remove_file(&target).ok();
        fs::create_dir_all(&target).unwrap();
        let err = restore_modules_from_backup(&target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert!(fs::metadata(&target).unwrap().is_dir());
    }

    #[test]
    fn no_backup_with_basename_mismatch_also_falls_through_to_remove_branch() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "other.conf", 99, 99, 99, b"wrong-file\n");
        fs::write(&target, b"managed\n").unwrap();
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert!(matches!(outcome, ModulesRestore::Removed { .. }));
        assert!(!target.exists());
    }

    #[test]
    fn no_backup_and_no_target_returns_nothing_to_rollback() {
        let (_d, target, backup_dir) = env();
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert_eq!(outcome, ModulesRestore::NothingToRollback);
        assert!(!outcome.reboot_required());
        assert!(!target.exists());
    }

    #[test]
    fn no_backup_dir_and_no_target_returns_nothing_to_rollback() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("modprobe.d/99-test.conf");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        let backup_dir = dir.path().join("never_created");
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert_eq!(outcome, ModulesRestore::NothingToRollback);
        assert!(!outcome.reboot_required());
    }

    #[test]
    fn basename_mismatch_and_no_target_returns_nothing_to_rollback() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "other.conf", 99, 99, 99, b"wrong\n");
        let outcome = restore_modules_from_backup(&target, &backup_dir).unwrap();
        assert_eq!(outcome, ModulesRestore::NothingToRollback);
    }

    #[test]
    fn reboot_required_true_for_restored() {
        let r = ModulesRestore::Restored {
            from: PathBuf::from("/x"),
        };
        assert!(r.reboot_required());
    }

    #[test]
    fn reboot_required_true_for_removed() {
        let r = ModulesRestore::Removed {
            target: PathBuf::from("/x"),
        };
        assert!(r.reboot_required());
    }

    #[test]
    fn reboot_required_false_for_nothing_to_rollback() {
        assert!(!ModulesRestore::NothingToRollback.reboot_required());
    }
}
