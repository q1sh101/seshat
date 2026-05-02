use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::atomic::install_root_file;
use crate::backup::latest_backup_for;
use crate::error::Error;

const GRUB_RESTORE_MODE: u32 = 0o644;

#[derive(Debug, PartialEq, Eq)]
pub enum BootRestore {
    Restored { from: PathBuf },
    Removed { target: PathBuf },
    NothingToRollback,
}

impl BootRestore {
    // Grub source config change only reaches the boot loader after a grub regenerate + reboot.
    pub fn reboot_required(&self) -> bool {
        matches!(self, Self::Restored { .. } | Self::Removed { .. })
    }
}

// `allow_remove_on_no_backup` is true for drop-in mode (we created the file) and false for main-file mode (operator-owned; never remove).
pub fn restore_boot_from_backup(
    target: &Path,
    backup_dir: &Path,
    allow_remove_on_no_backup: bool,
) -> Result<BootRestore, Error> {
    let basename = target.file_name().ok_or_else(|| Error::Validation {
        field: "boot.target".to_string(),
        reason: format!("restore target has no file name: {}", target.display()),
    })?;

    if let Some(backup) = latest_backup_for(basename, backup_dir)? {
        return restore_from_backup(target, &backup);
    }

    if allow_remove_on_no_backup {
        remove_target_if_present(target)
    } else {
        Ok(BootRestore::NothingToRollback)
    }
}

fn restore_from_backup(target: &Path, backup: &Path) -> Result<BootRestore, Error> {
    // symlink_metadata does not follow; a symlinked backup entry is rejected.
    let metadata = fs::symlink_metadata(backup)?;
    if !metadata.file_type().is_file() {
        return Err(Error::UnsafePath {
            path: backup.to_path_buf(),
            reason: "backup source is not a regular file".to_string(),
        });
    }
    let payload = fs::read(backup)?;
    install_root_file(target, &payload, GRUB_RESTORE_MODE)?;
    Ok(BootRestore::Restored {
        from: backup.to_path_buf(),
    })
}

fn remove_target_if_present(target: &Path) -> Result<BootRestore, Error> {
    match fs::symlink_metadata(target) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(BootRestore::NothingToRollback),
        Err(e) => Err(Error::Io(e)),
        Ok(metadata) => {
            let ft = metadata.file_type();
            if ft.is_symlink() {
                return Err(Error::UnsafePath {
                    path: target.to_path_buf(),
                    reason: "managed grub target is a symlink; refusing to remove".to_string(),
                });
            }
            if !ft.is_file() {
                return Err(Error::UnsafePath {
                    path: target.to_path_buf(),
                    reason: "managed grub target is not a regular file".to_string(),
                });
            }
            fs::remove_file(target)?;
            Ok(BootRestore::Removed {
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
        let target = dir.path().join("etc/default/grub.d/99-test.cfg");
        let backup_dir = dir.path().join("backups/boot");
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
    fn restore_returns_nothing_to_rollback_when_no_backup_and_no_target_and_remove_allowed() {
        let (_d, target, backup_dir) = env();
        let outcome = restore_boot_from_backup(&target, &backup_dir, true).unwrap();
        assert_eq!(outcome, BootRestore::NothingToRollback);
        assert!(!target.exists());
    }

    #[test]
    fn restore_returns_nothing_to_rollback_when_no_backup_and_remove_disallowed() {
        let (_d, target, backup_dir) = env();
        fs::write(&target, b"live content\n").unwrap();
        let outcome = restore_boot_from_backup(&target, &backup_dir, false).unwrap();
        assert_eq!(outcome, BootRestore::NothingToRollback);
        // Operator file must not be touched when remove is disallowed.
        assert_eq!(fs::read(&target).unwrap(), b"live content\n");
    }

    #[test]
    fn restore_removes_target_when_no_backup_and_remove_allowed() {
        let (_d, target, backup_dir) = env();
        fs::write(&target, b"managed-dropin\n").unwrap();
        let outcome = restore_boot_from_backup(&target, &backup_dir, true).unwrap();
        assert_eq!(
            outcome,
            BootRestore::Removed {
                target: target.clone()
            }
        );
        assert!(!target.exists());
    }

    #[test]
    fn restore_copies_single_backup_onto_target() {
        let (_d, target, backup_dir) = env();
        let backup = seed_backup(&backup_dir, "99-test.cfg", 10, 20, 30, b"payload-A\n");
        let outcome = restore_boot_from_backup(&target, &backup_dir, true).unwrap();
        assert_eq!(outcome, BootRestore::Restored { from: backup });
        assert_eq!(fs::read(&target).unwrap(), b"payload-A\n");
    }

    #[test]
    fn restore_picks_latest_backup_by_timestamp() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.cfg", 10, 1, 1, b"older\n");
        let latest = seed_backup(&backup_dir, "99-test.cfg", 20, 500, 1, b"newest\n");
        let outcome = restore_boot_from_backup(&target, &backup_dir, true).unwrap();
        assert_eq!(outcome, BootRestore::Restored { from: latest });
        assert_eq!(fs::read(&target).unwrap(), b"newest\n");
    }

    #[test]
    fn restore_ignores_backups_for_other_basenames() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "other.cfg", 99, 99, 99, b"wrong-file\n");
        fs::write(&target, b"managed\n").unwrap();
        let outcome = restore_boot_from_backup(&target, &backup_dir, true).unwrap();
        // No backup for our basename → allow_remove triggers Removed path.
        assert_eq!(
            outcome,
            BootRestore::Removed {
                target: target.clone()
            }
        );
    }

    #[test]
    fn restore_rejects_when_backup_entry_is_a_symlink() {
        let (_d, target, backup_dir) = env();
        let real = backup_dir.join("real.data");
        fs::write(&real, b"payload\n").unwrap();
        let link = backup_dir.join("99-test.cfg.10.000000020.30.bak");
        symlink(&real, &link).unwrap();
        let err = restore_boot_from_backup(&target, &backup_dir, true).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert!(!target.exists());
    }

    #[test]
    fn restore_rejects_when_target_is_a_symlink_during_backup_install() {
        let (_d, target, backup_dir) = env();
        seed_backup(&backup_dir, "99-test.cfg", 10, 20, 30, b"payload\n");
        let elsewhere = backup_dir.join("unrelated.data");
        fs::write(&elsewhere, b"elsewhere\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&elsewhere, &target).unwrap();
        let err = restore_boot_from_backup(&target, &backup_dir, true).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert_eq!(fs::read(&elsewhere).unwrap(), b"elsewhere\n");
    }

    #[test]
    fn restore_rejects_symlink_when_remove_branch_would_fire() {
        let (_d, target, backup_dir) = env();
        let elsewhere = backup_dir.join("unrelated.data");
        fs::write(&elsewhere, b"elsewhere\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&elsewhere, &target).unwrap();
        let err = restore_boot_from_backup(&target, &backup_dir, true).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        // Symlink target must remain untouched.
        assert_eq!(fs::read(&elsewhere).unwrap(), b"elsewhere\n");
    }

    #[test]
    fn restore_forces_target_mode_to_0o644_regardless_of_backup_mode() {
        use std::os::unix::fs::PermissionsExt;
        let (_d, target, backup_dir) = env();
        let backup = seed_backup(&backup_dir, "99-test.cfg", 10, 20, 30, b"payload\n");
        fs::set_permissions(&backup, fs::Permissions::from_mode(0o600)).unwrap();
        restore_boot_from_backup(&target, &backup_dir, true).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn restore_round_trip_after_create_backup_matches_payload() {
        let (_d, target, backup_dir) = env();
        fs::write(&target, b"original\n").unwrap();
        let backup = create_backup(&target, &backup_dir).unwrap().unwrap();
        fs::write(&target, b"post-deploy\n").unwrap();
        let outcome = restore_boot_from_backup(&target, &backup_dir, false).unwrap();
        assert_eq!(outcome, BootRestore::Restored { from: backup });
        assert_eq!(fs::read(&target).unwrap(), b"original\n");
    }

    #[test]
    fn reboot_required_true_on_restored_and_removed() {
        let r = BootRestore::Restored {
            from: PathBuf::from("/x"),
        };
        assert!(r.reboot_required());
        let r = BootRestore::Removed {
            target: PathBuf::from("/y"),
        };
        assert!(r.reboot_required());
    }

    #[test]
    fn reboot_required_false_on_nothing_to_rollback() {
        assert!(!BootRestore::NothingToRollback.reboot_required());
    }
}
