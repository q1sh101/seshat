use std::io;
use std::path::{Path, PathBuf};

use super::dropin::generate_sysctl_dropin;
use super::plan::LiveRead;
use super::setting::SysctlSetting;
use super::verify::{SysctlVerify, verify_sysctl};
use crate::atomic::install_root_file;
use crate::backup::create_backup;
use crate::error::Error;
use crate::policy::SysctlKey;
use crate::runtime::{CommandOutput, run_sanitized};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ReloadStatus {
    Applied,
    Unavailable,
    Failed(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct DeploySummary {
    pub target: PathBuf,
    pub backup: Option<PathBuf>,
    pub count: usize,
    pub reload: ReloadStatus,
    pub verify: Option<SysctlVerify>,
}

fn classify_reload_result(result: Result<CommandOutput, Error>) -> ReloadStatus {
    match result {
        Ok(output) if output.success() => ReloadStatus::Applied,
        Ok(output) => ReloadStatus::Failed(output.stderr_summary()),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => ReloadStatus::Unavailable,
        Err(e) => ReloadStatus::Failed(e.to_string()),
    }
}

pub fn reload_sysctl() -> ReloadStatus {
    classify_reload_result(run_sanitized("sysctl", ["--system"]))
}

pub fn deploy_sysctl<F, G>(
    settings: &[SysctlSetting],
    profile_name: &str,
    target: &Path,
    backup_dir: &Path,
    reload: F,
    read_live: G,
) -> Result<DeploySummary, Error>
where
    F: FnOnce() -> ReloadStatus,
    G: FnMut(&SysctlKey) -> LiveRead,
{
    let payload = generate_sysctl_dropin(settings, profile_name);
    let backup = create_backup(target, backup_dir)?;
    install_root_file(target, payload.as_bytes(), 0o644)?;

    // Re-read to catch post-rename corruption before triggering a kernel reload.
    let live = std::fs::read_to_string(target)?;
    if live != payload {
        return Err(Error::Validation {
            field: "post_write_verify".to_string(),
            reason: format!(
                "drop-in at {} diverges from intended payload",
                target.display()
            ),
        });
    }

    let reload_status = reload();
    let verify = if matches!(reload_status, ReloadStatus::Applied) {
        Some(verify_sysctl(settings, read_live))
    } else {
        None
    };

    Ok(DeploySummary {
        target: target.to_path_buf(),
        backup,
        count: settings.len(),
        reload: reload_status,
        verify,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::CheckState;
    use std::fs;
    use tempfile::tempdir;

    fn setting(key: &str, value: &str) -> SysctlSetting {
        SysctlSetting::new(key, value).unwrap()
    }

    fn env() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempdir().unwrap();
        let target = dir.path().join("sysctl.d/99-test.conf");
        let backup_dir = dir.path().join("backups");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::create_dir_all(&backup_dir).unwrap();
        (dir, target, backup_dir)
    }

    fn missing_reader() -> impl FnMut(&SysctlKey) -> LiveRead {
        |_| LiveRead::Missing
    }

    fn matching_reader() -> impl FnMut(&SysctlKey) -> LiveRead {
        |k| {
            LiveRead::Value(match k.as_str() {
                "kernel.kptr_restrict" => "2".to_string(),
                "kernel.dmesg_restrict" => "1".to_string(),
                "net.core.bpf_jit_harden" => "2".to_string(),
                _ => String::new(),
            })
        }
    }

    fn cmd(exit: Option<i32>, stderr: &[u8]) -> CommandOutput {
        CommandOutput {
            exit_code: exit,
            stdout: vec![],
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn classify_reload_maps_zero_exit_to_applied() {
        assert_eq!(
            classify_reload_result(Ok(cmd(Some(0), b""))),
            ReloadStatus::Applied
        );
    }

    #[test]
    fn classify_reload_maps_nonzero_exit_to_failed_with_stderr() {
        let r = classify_reload_result(Ok(cmd(Some(1), b"permission denied")));
        match r {
            ReloadStatus::Failed(reason) => assert_eq!(reason, "permission denied"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn classify_reload_maps_signal_terminated_to_failed() {
        // exit_code = None indicates signal termination in runtime::CommandOutput.
        let r = classify_reload_result(Ok(cmd(None, b"")));
        assert!(matches!(r, ReloadStatus::Failed(_)));
    }

    #[test]
    fn classify_reload_maps_not_found_to_unavailable() {
        let err = Error::Io(io::Error::from(io::ErrorKind::NotFound));
        assert_eq!(classify_reload_result(Err(err)), ReloadStatus::Unavailable);
    }

    #[test]
    fn classify_reload_maps_other_io_error_to_failed() {
        let err = Error::Io(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(matches!(
            classify_reload_result(Err(err)),
            ReloadStatus::Failed(_)
        ));
    }

    #[test]
    fn writes_expected_payload() {
        let (_dir, target, backup_dir) = env();
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let summary = deploy_sysctl(
            &settings,
            "baseline",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert_eq!(summary.target, target);
        assert_eq!(summary.count, 1);
        assert_eq!(summary.backup, None);
        let live = fs::read_to_string(&target).unwrap();
        assert_eq!(
            live,
            "# managed by seshat\n# profile: baseline\n\nkernel.kptr_restrict = 2\n"
        );
    }

    #[test]
    fn backs_up_existing_file() {
        let (_dir, target, backup_dir) = env();
        fs::write(&target, "prior content\n").unwrap();
        let summary = deploy_sysctl(
            &[setting("kernel.kptr_restrict", "2")],
            "baseline",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        let backup = summary.backup.expect("existing file must be backed up");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "prior content\n");
    }

    #[test]
    fn sets_mode_0o644() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, target, backup_dir) = env();
        deploy_sysctl(
            &[],
            "baseline",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            missing_reader(),
        )
        .unwrap();
        let mode = fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn invokes_reload_closure_after_install() {
        let (_dir, target, backup_dir) = env();
        let mut called = false;
        let summary = deploy_sysctl(
            &[setting("kernel.kptr_restrict", "2")],
            "x",
            &target,
            &backup_dir,
            || {
                called = true;
                ReloadStatus::Applied
            },
            matching_reader(),
        )
        .unwrap();
        assert!(called, "reload closure must run after install");
        assert_eq!(summary.reload, ReloadStatus::Applied);
    }

    #[test]
    fn reports_reload_unavailable() {
        let (_dir, target, backup_dir) = env();
        let summary = deploy_sysctl(
            &[],
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Unavailable,
            missing_reader(),
        )
        .unwrap();
        assert_eq!(summary.reload, ReloadStatus::Unavailable);
    }

    #[test]
    fn reports_reload_failed_with_reason() {
        let (_dir, target, backup_dir) = env();
        let summary = deploy_sysctl(
            &[],
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Failed("exit 1".to_string()),
            missing_reader(),
        )
        .unwrap();
        match summary.reload {
            ReloadStatus::Failed(reason) => assert_eq!(reason, "exit 1"),
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn runs_live_verify_after_successful_reload() {
        let (_dir, target, backup_dir) = env();
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let summary = deploy_sysctl(
            &settings,
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        let verify = summary.verify.expect("live verify must run on Applied");
        assert_eq!(verify.rows.len(), 1);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
    }

    #[test]
    fn live_verify_surfaces_drift_after_reload() {
        let (_dir, target, backup_dir) = env();
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let drift = |_: &SysctlKey| LiveRead::Value("0".to_string());
        let summary = deploy_sysctl(
            &settings,
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            drift,
        )
        .unwrap();
        let verify = summary.verify.unwrap();
        assert_eq!(verify.rows[0].state, CheckState::Warn);
    }

    #[test]
    fn skips_live_verify_when_reload_unavailable() {
        let (_dir, target, backup_dir) = env();
        let summary = deploy_sysctl(
            &[setting("kernel.kptr_restrict", "2")],
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Unavailable,
            matching_reader(),
        )
        .unwrap();
        assert!(
            summary.verify.is_none(),
            "verify must be skipped when reload is unavailable"
        );
    }

    #[test]
    fn skips_live_verify_when_reload_failed() {
        let (_dir, target, backup_dir) = env();
        let summary = deploy_sysctl(
            &[setting("kernel.kptr_restrict", "2")],
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Failed("exit 1".to_string()),
            matching_reader(),
        )
        .unwrap();
        assert!(
            summary.verify.is_none(),
            "verify must be skipped when reload failed"
        );
    }

    #[test]
    fn count_matches_settings_length() {
        let (_dir, target, backup_dir) = env();
        let settings = vec![
            setting("kernel.kptr_restrict", "2"),
            setting("kernel.dmesg_restrict", "1"),
            setting("net.core.bpf_jit_harden", "2"),
        ];
        let summary = deploy_sysctl(
            &settings,
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert_eq!(summary.count, 3);
    }

    #[test]
    fn is_idempotent_on_rerun() {
        let (_dir, target, backup_dir) = env();
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        deploy_sysctl(
            &settings,
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        let first = fs::read_to_string(&target).unwrap();
        let second = deploy_sysctl(
            &settings,
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert_eq!(first, fs::read_to_string(&target).unwrap());
        assert!(second.backup.is_some(), "rerun must back up existing file");
    }

    #[test]
    fn refuses_symlink_target() {
        use std::os::unix::fs::symlink;
        let (_dir, target, backup_dir) = env();
        let real = backup_dir.join("real.conf");
        fs::write(&real, "seed\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&real, &target).unwrap();
        let err = deploy_sysctl(
            &[],
            "x",
            &target,
            &backup_dir,
            || ReloadStatus::Applied,
            missing_reader(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn reload_not_invoked_when_install_fails() {
        use std::os::unix::fs::symlink;
        let (_dir, target, backup_dir) = env();
        let real = backup_dir.join("real.conf");
        fs::write(&real, "seed\n").unwrap();
        fs::remove_file(&target).ok();
        symlink(&real, &target).unwrap();
        let mut called = false;
        let _ = deploy_sysctl(
            &[],
            "x",
            &target,
            &backup_dir,
            || {
                called = true;
                ReloadStatus::Applied
            },
            missing_reader(),
        );
        assert!(!called, "reload must not run when install refuses target");
    }
}
