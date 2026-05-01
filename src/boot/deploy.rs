use std::io;
use std::path::{Path, PathBuf};

use super::dropin::generate_grub_dropin;
use super::mainconfig::merge_grub_main_config;
use crate::atomic::install_root_file;
use crate::backup::create_backup;
use crate::error::Error;

const GRUB_DEPLOY_MODE: u32 = 0o644;

#[derive(Debug, PartialEq, Eq)]
pub struct DeploySummary {
    pub target: PathBuf,
    pub backup: Option<PathBuf>,
}

// install_root_file refuses symlink/non-regular destinations; post-write re-read catches silent corruption before the later refresh step runs.
pub fn deploy_grub_dropin(
    merged_cmdline: &str,
    profile_name: &str,
    target: &Path,
    backup_dir: &Path,
) -> Result<DeploySummary, Error> {
    let payload = generate_grub_dropin(merged_cmdline, profile_name);
    let backup = create_backup(target, backup_dir)?;
    install_root_file(target, payload.as_bytes(), GRUB_DEPLOY_MODE)?;
    verify_on_disk(target, &payload)?;
    Ok(DeploySummary {
        target: target.to_path_buf(),
        backup,
    })
}

// Refuse symlink/non-file/missing BEFORE reading so we never follow a link to unrelated state; §16.7 restricts main-file deploy to existing /etc/default/grub.
pub fn deploy_grub_main_config(
    merged_cmdline: &str,
    target: &Path,
    backup_dir: &Path,
) -> Result<DeploySummary, Error> {
    preflight_main_target(target)?;
    let content = std::fs::read_to_string(target)?;
    let updated = merge_grub_main_config(&content, merged_cmdline)?;
    let backup = create_backup(target, backup_dir)?;
    install_root_file(target, updated.as_bytes(), GRUB_DEPLOY_MODE)?;
    verify_on_disk(target, &updated)?;
    Ok(DeploySummary {
        target: target.to_path_buf(),
        backup,
    })
}

fn preflight_main_target(target: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(target) {
        Ok(m) => {
            let ft = m.file_type();
            if ft.is_symlink() {
                return Err(Error::UnsafePath {
                    path: target.to_path_buf(),
                    reason: "main grub config target is a symlink".to_string(),
                });
            }
            if !ft.is_file() {
                return Err(Error::UnsafePath {
                    path: target.to_path_buf(),
                    reason: "main grub config target is not a regular file".to_string(),
                });
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(Error::PreflightRefused {
            path: target.to_path_buf(),
            reason: "main grub config file does not exist".to_string(),
        }),
        Err(e) => Err(Error::Io(e)),
    }
}

fn verify_on_disk(target: &Path, expected: &str) -> Result<(), Error> {
    let live = std::fs::read_to_string(target)?;
    if live != expected {
        return Err(Error::Validation {
            field: "post_write_verify".to_string(),
            reason: format!(
                "grub config at {} diverges from intended payload",
                target.display()
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    fn env_dropin() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let target = dir.path().join("etc/default/grub.d/99-test.cfg");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        (dir, target, backup_dir)
    }

    fn env_main() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let target = dir.path().join("etc/default/grub");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        (dir, target, backup_dir)
    }

    #[test]
    fn dropin_refuses_symlinked_target() {
        let (_dir, target, backup_dir) = env_dropin();
        let real = backup_dir.join("real.cfg");
        fs::write(&real, b"seed\n").unwrap();
        symlink(&real, &target).unwrap();
        let err = deploy_grub_dropin("quiet", "baseline", &target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        // Symlink target must remain untouched.
        assert_eq!(fs::read_to_string(&real).unwrap(), "seed\n");
    }

    #[test]
    fn dropin_refuses_directory_target() {
        let (_dir, target, backup_dir) = env_dropin();
        fs::create_dir(&target).unwrap();
        let err = deploy_grub_dropin("quiet", "baseline", &target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn main_refuses_missing_target() {
        let (_dir, target, backup_dir) = env_main();
        // Target never created.
        let err = deploy_grub_main_config("quiet", &target, &backup_dir).unwrap_err();
        match err {
            Error::PreflightRefused { reason, .. } => {
                assert!(reason.contains("does not exist"), "reason: {reason}");
            }
            other => panic!("expected PreflightRefused, got {other:?}"),
        }
        // No file should have been created.
        assert!(!target.exists());
    }

    #[test]
    fn main_refuses_symlinked_target_without_reading_through_link() {
        let (_dir, target, backup_dir) = env_main();
        let real = backup_dir.join("real.conf");
        fs::write(&real, b"GRUB_CMDLINE_LINUX_DEFAULT=\"leak\"\n").unwrap();
        symlink(&real, &target).unwrap();
        let err = deploy_grub_main_config("quiet", &target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        // Symlink target must remain untouched.
        assert_eq!(
            fs::read_to_string(&real).unwrap(),
            "GRUB_CMDLINE_LINUX_DEFAULT=\"leak\"\n"
        );
    }

    #[test]
    fn main_refuses_directory_target() {
        let (_dir, target, backup_dir) = env_main();
        fs::create_dir(&target).unwrap();
        let err = deploy_grub_main_config("quiet", &target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn main_propagates_parse_error_on_malformed_existing() {
        let (_dir, target, backup_dir) = env_main();
        fs::write(&target, b"GRUB_CMDLINE_LINUX_DEFAULT=\"unterminated\n").unwrap();
        let err = deploy_grub_main_config("quiet", &target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
        // Pre-merge parse must fail before we touch the file; original stays intact.
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "GRUB_CMDLINE_LINUX_DEFAULT=\"unterminated\n"
        );
    }

    #[test]
    fn dropin_writes_expected_payload_with_mode_0644() {
        let (_dir, target, backup_dir) = env_dropin();
        let summary =
            deploy_grub_dropin("quiet init_on_alloc=1", "baseline", &target, &backup_dir).unwrap();
        assert_eq!(summary.target, target);
        assert_eq!(summary.backup, None);
        let body = fs::read_to_string(&target).unwrap();
        assert_eq!(
            body,
            "# managed by seshat\n# profile: baseline\n# mode: grub-dropin\n\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet init_on_alloc=1\"\n"
        );
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn dropin_backs_up_existing_file() {
        let (_dir, target, backup_dir) = env_dropin();
        fs::write(&target, b"prior\n").unwrap();
        let summary = deploy_grub_dropin("quiet", "baseline", &target, &backup_dir).unwrap();
        let backup = summary.backup.expect("existing file must be backed up");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "prior\n");
    }

    #[test]
    fn dropin_is_idempotent_on_rerun_and_backs_up_each_time() {
        let (_dir, target, backup_dir) = env_dropin();
        deploy_grub_dropin("quiet", "baseline", &target, &backup_dir).unwrap();
        let first = fs::read_to_string(&target).unwrap();
        let second = deploy_grub_dropin("quiet", "baseline", &target, &backup_dir).unwrap();
        assert_eq!(first, fs::read_to_string(&target).unwrap());
        assert!(second.backup.is_some(), "rerun must back up existing file");
    }

    #[test]
    fn main_merges_and_writes_preserving_quote_style() {
        let (_dir, target, backup_dir) = env_main();
        fs::write(
            &target,
            b"GRUB_CMDLINE_LINUX_DEFAULT='old'\nGRUB_TIMEOUT=5\n",
        )
        .unwrap();
        let summary =
            deploy_grub_main_config("quiet init_on_alloc=1", &target, &backup_dir).unwrap();
        assert_eq!(summary.target, target);
        assert!(summary.backup.is_some());
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "GRUB_CMDLINE_LINUX_DEFAULT='quiet init_on_alloc=1'\nGRUB_TIMEOUT=5\n"
        );
    }

    #[test]
    fn main_sets_mode_0644() {
        let (_dir, target, backup_dir) = env_main();
        fs::write(&target, b"GRUB_CMDLINE_LINUX_DEFAULT=\"old\"\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        deploy_grub_main_config("quiet", &target, &backup_dir).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn main_backs_up_existing_file_with_original_content() {
        let (_dir, target, backup_dir) = env_main();
        let before = "GRUB_CMDLINE_LINUX_DEFAULT=\"old\"\nGRUB_TIMEOUT=5\n";
        fs::write(&target, before).unwrap();
        let summary = deploy_grub_main_config("quiet", &target, &backup_dir).unwrap();
        let backup = summary.backup.expect("existing main must be backed up");
        assert_eq!(fs::read_to_string(&backup).unwrap(), before);
    }

    #[test]
    fn main_appends_assignment_when_none_present() {
        let (_dir, target, backup_dir) = env_main();
        fs::write(&target, b"GRUB_TIMEOUT=5\n").unwrap();
        deploy_grub_main_config("quiet", &target, &backup_dir).unwrap();
        assert_eq!(
            fs::read_to_string(&target).unwrap(),
            "GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n"
        );
    }
}
