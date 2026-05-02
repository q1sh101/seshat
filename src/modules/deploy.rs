use std::collections::HashSet;
use std::path::{Path, PathBuf};

use super::dropin::{generate_modprobe_dropin, payload_signature};
use crate::atomic::install_root_file;
use crate::backup::create_backup;
use crate::error::Error;
use crate::policy::{ModuleName, normalize_module};

#[derive(Debug, PartialEq, Eq)]
pub struct DeploySummary {
    pub target: PathBuf,
    pub backup: Option<PathBuf>,
    pub allow_count: usize,
    pub block_count: usize,
}

pub fn deploy_enforcement(
    effective: &[ModuleName],
    installed: &[String],
    profile_name: &str,
    target: &Path,
    backup_dir: &Path,
) -> Result<DeploySummary, Error> {
    let payload = generate_modprobe_dropin(effective, installed, profile_name);
    let backup = create_backup(target, backup_dir)?;
    install_root_file(target, payload.as_bytes(), 0o644)?;

    // Re-read and compare signatures to catch post-rename corruption.
    let live = std::fs::read_to_string(target).map_err(|e| Error::Validation {
        field: "post_write_verify_read".to_string(),
        reason: format!("cannot re-read {} after install: {e}", target.display()),
    })?;
    if payload_signature(&live) != payload_signature(&payload) {
        return Err(Error::Validation {
            field: "post_write_verify".to_string(),
            reason: format!(
                "drop-in at {} diverges from intended payload",
                target.display()
            ),
        });
    }

    let allowed: HashSet<String> = effective
        .iter()
        .map(|m| normalize_module(m.as_str()))
        .collect();
    let block_count = installed
        .iter()
        .filter(|raw| !allowed.contains(&normalize_module(raw)))
        .count();

    Ok(DeploySummary {
        target: target.to_path_buf(),
        backup,
        allow_count: effective.len(),
        block_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn deploy_env() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let target = dir.path().join("modprobe.d/99-test.conf");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        (dir, target, backup_dir)
    }

    #[test]
    fn deploy_enforcement_writes_expected_payload() {
        let (_dir, target, backup_dir) = deploy_env();
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let summary =
            deploy_enforcement(&effective, &installed, "baseline", &target, &backup_dir).unwrap();
        assert_eq!(summary.target, target);
        assert_eq!(summary.allow_count, 1);
        assert_eq!(summary.block_count, 1);
        assert_eq!(summary.backup, None);
        let live = fs::read_to_string(&target).unwrap();
        assert!(live.starts_with("# managed by seshat\n"));
        assert!(live.contains("install vfat /bin/false\n"));
    }

    #[test]
    fn deploy_enforcement_backs_up_existing_file() {
        let (_dir, target, backup_dir) = deploy_env();
        fs::write(&target, "prior content\n").unwrap();
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string()];
        let summary =
            deploy_enforcement(&effective, &installed, "baseline", &target, &backup_dir).unwrap();
        let backup = summary.backup.expect("existing file must be backed up");
        let backup_content = fs::read_to_string(&backup).unwrap();
        assert_eq!(backup_content, "prior content\n");
    }

    #[test]
    fn deploy_enforcement_sets_mode_0o644() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, target, backup_dir) = deploy_env();
        let effective = vec![ModuleName::new("ext4").unwrap()];
        deploy_enforcement(&effective, &[], "baseline", &target, &backup_dir).unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn deploy_enforcement_counts_blocked_modules() {
        let (_dir, target, backup_dir) = deploy_env();
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec![
            "ext4".to_string(),
            "vfat".to_string(),
            "usb-storage".to_string(),
            "nouveau".to_string(),
        ];
        let summary =
            deploy_enforcement(&effective, &installed, "baseline", &target, &backup_dir).unwrap();
        assert_eq!(summary.allow_count, 1);
        assert_eq!(summary.block_count, 3);
    }

    #[test]
    fn deploy_enforcement_is_idempotent_on_rerun() {
        let (_dir, target, backup_dir) = deploy_env();
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        deploy_enforcement(&effective, &installed, "baseline", &target, &backup_dir).unwrap();
        let first = fs::read_to_string(&target).unwrap();
        let second_summary =
            deploy_enforcement(&effective, &installed, "baseline", &target, &backup_dir).unwrap();
        let second = fs::read_to_string(&target).unwrap();
        assert_eq!(first, second);
        assert!(second_summary.backup.is_some());
    }

    #[test]
    fn deploy_enforcement_refuses_symlink_target() {
        use std::os::unix::fs::symlink;
        let (_dir, target, backup_dir) = deploy_env();
        let real = backup_dir.join("real.conf");
        fs::write(&real, "seed\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&real, &target).unwrap();
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let err =
            deploy_enforcement(&effective, &[], "baseline", &target, &backup_dir).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }
}
