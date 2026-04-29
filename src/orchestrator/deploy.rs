use std::io;
use std::path::Path;

use crate::error::Error;
use crate::lock;
use crate::modules::{self, DeploySummary as ModulesDeploy};
use crate::policy::{ModuleName, Profile, SysctlKey};
use crate::result::CheckState;
use crate::sysctl::{self, DeploySummary as SysctlDeploy, LiveRead, ReloadStatus, SysctlSetting};

const DEPLOY_LOCK_NAME: &str = "deploy";

pub const BOOT_DEPLOY_REFUSED: &str =
    "boot deploy not implemented in this build; Milestone 2 covers GRUB deploy";

#[derive(Debug, PartialEq, Eq)]
pub struct BootDeployStatus {
    pub reason: &'static str,
}

#[derive(Debug)]
pub struct DeployReport {
    pub sysctl: Result<SysctlDeploy, Error>,
    pub modules: Result<ModulesDeploy, Error>,
    pub boot: BootDeployStatus,
}

impl DeployReport {
    pub fn exit_code(&self) -> i32 {
        let sysctl_code = match &self.sysctl {
            Err(e) => classify_deploy_error(e),
            Ok(summary) => classify_sysctl_summary(summary),
        };
        let modules_code = self
            .modules
            .as_ref()
            .err()
            .map(classify_deploy_error)
            .unwrap_or(0);
        sysctl_code.max(modules_code)
    }
}

pub fn classify_deploy_error(err: &Error) -> i32 {
    match err {
        Error::UnsafePath { .. }
        | Error::PreflightRefused { .. }
        | Error::Lock { .. } => 3,
        _ => 1,
    }
}

fn classify_sysctl_summary(summary: &SysctlDeploy) -> i32 {
    match &summary.reload {
        ReloadStatus::Unavailable | ReloadStatus::Failed(_) => 1,
        ReloadStatus::Applied => match &summary.verify {
            None => 0,
            Some(verify) => {
                for row in &verify.rows {
                    if matches!(row.state, CheckState::Warn | CheckState::Fail) {
                        return 1;
                    }
                }
                0
            }
        },
    }
}

pub struct DeployInputs<'a> {
    pub profile: &'a Profile,
    pub modules_dir: &'a Path,
    pub snapshot_path: &'a Path,
    pub allow_path: &'a Path,
    pub block_path: &'a Path,
    pub sysctl_target: &'a Path,
    pub sysctl_backup_dir: &'a Path,
    pub modprobe_target: &'a Path,
    pub modprobe_backup_dir: &'a Path,
    pub lock_root: &'a Path,
}

pub fn orchestrate_deploy<F, G>(
    inputs: &DeployInputs<'_>,
    sysctl_reload: F,
    sysctl_read_live: G,
) -> Result<DeployReport, Error>
where
    F: FnOnce() -> ReloadStatus,
    G: FnMut(&SysctlKey) -> LiveRead,
{
    let _guard = lock::acquire(inputs.lock_root, DEPLOY_LOCK_NAME)?;
    Ok(DeployReport {
        sysctl: deploy_sysctl_domain(inputs, sysctl_reload, sysctl_read_live),
        modules: deploy_modules_domain(inputs),
        boot: BootDeployStatus {
            reason: BOOT_DEPLOY_REFUSED,
        },
    })
}

fn deploy_sysctl_domain<F, G>(
    inputs: &DeployInputs<'_>,
    reload: F,
    read_live: G,
) -> Result<SysctlDeploy, Error>
where
    F: FnOnce() -> ReloadStatus,
    G: FnMut(&SysctlKey) -> LiveRead,
{
    let settings: Vec<SysctlSetting> = inputs
        .profile
        .sysctl
        .iter()
        .map(SysctlSetting::from_entry)
        .collect::<Result<_, _>>()?;
    sysctl::deploy_sysctl(
        &settings,
        inputs.profile.profile_name.as_str(),
        inputs.sysctl_target,
        inputs.sysctl_backup_dir,
        reload,
        read_live,
    )
}

fn deploy_modules_domain(inputs: &DeployInputs<'_>) -> Result<ModulesDeploy, Error> {
    let snapshot = read_optional_allowlist(inputs.snapshot_path)?;
    let Some(snapshot) = snapshot else {
        return Err(Error::Validation {
            field: "modules.snapshot".to_string(),
            reason: "snapshot required before deploy; run: seshat snapshot".to_string(),
        });
    };
    let allow = read_optional_allowlist(inputs.allow_path)?;
    let file_block = read_optional_allowlist(inputs.block_path)?.unwrap_or_default();
    let profile_block: Vec<ModuleName> = inputs
        .profile
        .modules
        .block
        .iter()
        .map(|s| ModuleName::new(s))
        .collect::<Result<_, _>>()?;
    let mut combined_block = file_block;
    combined_block.extend(profile_block);

    let effective =
        modules::effective_allowlist(&snapshot, allow.as_deref().unwrap_or(&[]), &combined_block);
    let installed = modules::scan_installed_modules(inputs.modules_dir)?;

    modules::deploy_enforcement(
        &effective,
        &installed,
        inputs.profile.profile_name.as_str(),
        inputs.modprobe_target,
        inputs.modprobe_backup_dir,
    )
}

fn read_optional_allowlist(path: &Path) -> Result<Option<Vec<ModuleName>>, Error> {
    match modules::parse_allowlist(path) {
        Ok(v) => Ok(Some(v)),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BootEntry, LockdownSection, ModulesSection, SysctlEntry};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tempfile::tempdir;

    struct Env {
        _root: tempfile::TempDir,
        modules_dir: PathBuf,
        snapshot_path: PathBuf,
        allow_path: PathBuf,
        block_path: PathBuf,
        sysctl_target: PathBuf,
        sysctl_backup_dir: PathBuf,
        modprobe_target: PathBuf,
        modprobe_backup_dir: PathBuf,
        lock_root: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let modules_dir = root.path().join("lib_modules");
        let snapshot_path = root.path().join("snapshot.conf");
        let allow_path = root.path().join("allow.conf");
        let block_path = root.path().join("block.conf");
        let sysctl_target = root.path().join("sysctl.d/99-test.conf");
        let sysctl_backup_dir = root.path().join("backups/sysctl");
        let modprobe_target = root.path().join("modprobe.d/99-test.conf");
        let modprobe_backup_dir = root.path().join("backups/modules");
        let lock_root = root.path().join("locks");
        fs::create_dir_all(&modules_dir).unwrap();
        fs::create_dir_all(sysctl_target.parent().unwrap()).unwrap();
        fs::create_dir_all(&sysctl_backup_dir).unwrap();
        fs::create_dir_all(modprobe_target.parent().unwrap()).unwrap();
        fs::create_dir_all(&modprobe_backup_dir).unwrap();
        fs::create_dir_all(&lock_root).unwrap();
        fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700)).unwrap();
        Env {
            _root: root,
            modules_dir,
            snapshot_path,
            allow_path,
            block_path,
            sysctl_target,
            sysctl_backup_dir,
            modprobe_target,
            modprobe_backup_dir,
            lock_root,
        }
    }

    fn inputs<'a>(env: &'a Env, profile: &'a Profile) -> DeployInputs<'a> {
        DeployInputs {
            profile,
            modules_dir: &env.modules_dir,
            snapshot_path: &env.snapshot_path,
            allow_path: &env.allow_path,
            block_path: &env.block_path,
            sysctl_target: &env.sysctl_target,
            sysctl_backup_dir: &env.sysctl_backup_dir,
            modprobe_target: &env.modprobe_target,
            modprobe_backup_dir: &env.modprobe_backup_dir,
            lock_root: &env.lock_root,
        }
    }

    fn profile(sysctl: Vec<(&str, &str)>, boot: Vec<&str>, modules_block: Vec<&str>) -> Profile {
        Profile {
            schema_version: 1,
            profile_name: "test".to_string(),
            modules: ModulesSection {
                mode: Some("allowlist".to_string()),
                block: modules_block.iter().map(|s| s.to_string()).collect(),
            },
            sysctl: sysctl
                .into_iter()
                .map(|(k, v)| SysctlEntry {
                    key: k.to_string(),
                    value: v.to_string(),
                })
                .collect(),
            boot: boot
                .into_iter()
                .map(|a| BootEntry { arg: a.to_string() })
                .collect(),
            lockdown: LockdownSection::default(),
        }
    }

    fn write_mode_0o600(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn seed_installed_modules(env: &Env, names: &[&str]) {
        let kernel_dir = env.modules_dir.join("kernel");
        fs::create_dir_all(&kernel_dir).unwrap();
        for n in names {
            fs::write(kernel_dir.join(format!("{n}.ko")), "").unwrap();
        }
    }

    fn matching_reader() -> impl FnMut(&SysctlKey) -> LiveRead + use<> {
        |k| {
            LiveRead::Value(match k.as_str() {
                "kernel.kptr_restrict" => "2".to_string(),
                "kernel.dmesg_restrict" => "1".to_string(),
                _ => String::new(),
            })
        }
    }

    #[test]
    fn boot_deploy_is_always_refused_with_message() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert_eq!(report.boot.reason, BOOT_DEPLOY_REFUSED);
        assert!(report.boot.reason.contains("not implemented"));
    }

    #[test]
    fn modules_deploy_requires_snapshot() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        match report.modules {
            Err(Error::Validation { field, reason }) => {
                assert_eq!(field, "modules.snapshot");
                assert!(reason.contains("seshat snapshot"));
            }
            other => panic!("expected Validation(modules.snapshot), got {other:?}"),
        }
    }

    #[test]
    fn sysctl_deploy_writes_drop_in_and_invokes_reload() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let mut called = false;
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || {
                called = true;
                ReloadStatus::Applied
            },
            matching_reader(),
        )
        .unwrap();
        assert!(called);
        let summary = report.sysctl.unwrap();
        assert_eq!(summary.count, 1);
        assert_eq!(summary.reload, ReloadStatus::Applied);
        assert!(
            fs::read_to_string(&env.sysctl_target)
                .unwrap()
                .contains("kernel.kptr_restrict = 2")
        );
    }

    #[test]
    fn modules_deploy_writes_drop_in_when_snapshot_present() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4", "vfat"]);
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        let summary = report.modules.unwrap();
        assert_eq!(summary.allow_count, 1);
        assert_eq!(summary.block_count, 1);
        assert!(
            fs::read_to_string(&env.modprobe_target)
                .unwrap()
                .contains("install vfat /bin/false")
        );
    }

    #[test]
    fn modules_deploy_applies_profile_block_alongside_snapshot() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\nvfat\n");
        seed_installed_modules(&env, &["ext4", "vfat"]);
        let prof = profile(vec![], vec![], vec!["vfat"]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        let summary = report.modules.unwrap();
        assert_eq!(summary.allow_count, 1);
        assert_eq!(summary.block_count, 1);
    }

    #[test]
    fn exit_code_zero_when_both_domains_ok_and_boot_refused() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert!(report.sysctl.is_ok());
        assert!(report.modules.is_ok());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_one_when_sysctl_domain_errors() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let prof = profile(vec![("Invalid.Uppercase", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert!(report.sysctl.is_err());
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_one_when_modules_snapshot_missing() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert!(report.modules.is_err());
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn reload_closure_invoked_exactly_once_regardless_of_modules_outcome() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let mut count = 0;
        let _ = orchestrate_deploy(
            &inputs(&env, &prof),
            || {
                count += 1;
                ReloadStatus::Applied
            },
            matching_reader(),
        )
        .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn deploy_fails_when_another_deploy_holds_the_lock() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let _holder = lock::acquire(&env.lock_root, DEPLOY_LOCK_NAME).unwrap();
        let result = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        );
        assert!(matches!(result, Err(Error::Lock { .. })));
        assert!(!env.sysctl_target.exists());
        assert!(!env.modprobe_target.exists());
    }

    #[test]
    fn deploy_releases_lock_so_next_deploy_can_proceed() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
    }

    #[test]
    fn exit_code_three_when_sysctl_target_is_symlink() {
        use std::os::unix::fs::symlink;
        let env = env();
        let real = env.sysctl_backup_dir.join("real.conf");
        fs::write(&real, "seed\n").unwrap();
        fs::remove_file(&env.sysctl_target).ok();
        symlink(&real, &env.sysctl_target).unwrap();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert!(matches!(report.sysctl, Err(Error::UnsafePath { .. })));
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn exit_code_three_when_modprobe_target_is_symlink() {
        use std::os::unix::fs::symlink;
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let real = env.modprobe_backup_dir.join("real.conf");
        fs::write(&real, "seed\n").unwrap();
        fs::remove_file(&env.modprobe_target).ok();
        symlink(&real, &env.modprobe_target).unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert!(matches!(report.modules, Err(Error::UnsafePath { .. })));
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn exit_code_three_on_top_level_lock_contention() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let _holder = lock::acquire(&env.lock_root, DEPLOY_LOCK_NAME).unwrap();
        let err = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap_err();
        assert_eq!(classify_deploy_error(&err), 3);
    }

    #[test]
    fn exit_code_one_stays_for_non_security_domain_errors() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert_eq!(report.exit_code(), 1);
    }

    fn env_with_modules_ready() -> Env {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        env
    }

    #[test]
    fn exit_code_one_when_sysctl_reload_failed() {
        let env = env_with_modules_ready();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Failed("exit 1".to_string()),
            matching_reader(),
        )
        .unwrap();
        assert!(report.sysctl.is_ok());
        assert!(report.modules.is_ok());
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_one_when_sysctl_reload_unavailable() {
        let env = env_with_modules_ready();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Unavailable,
            matching_reader(),
        )
        .unwrap();
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_one_when_reload_applied_but_live_verify_warns() {
        let env = env_with_modules_ready();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let drift_reader = |_: &SysctlKey| LiveRead::Value("0".to_string());
        let report =
            orchestrate_deploy(&inputs(&env, &prof), || ReloadStatus::Applied, drift_reader)
                .unwrap();
        assert!(report.sysctl.is_ok());
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_zero_when_reload_applied_and_live_verify_ok() {
        let env = env_with_modules_ready();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert!(report.sysctl.is_ok());
        assert!(report.modules.is_ok());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_three_wins_over_sysctl_summary_warnings() {
        use std::os::unix::fs::symlink;
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let real = env.modprobe_backup_dir.join("real.conf");
        fs::write(&real, "seed\n").unwrap();
        fs::remove_file(&env.modprobe_target).ok();
        symlink(&real, &env.modprobe_target).unwrap();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Unavailable,
            matching_reader(),
        )
        .unwrap();
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn classify_deploy_error_maps_security_variants_to_three() {
        use std::path::PathBuf;
        assert_eq!(
            classify_deploy_error(&Error::UnsafePath {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_deploy_error(&Error::PreflightRefused {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_deploy_error(&Error::Lock {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_deploy_error(&Error::Validation {
                field: "x".into(),
                reason: "".into(),
            }),
            1
        );
    }

    #[test]
    fn modules_deploy_propagates_modules_dir_error_when_snapshot_present() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        fs::remove_dir(&env.modules_dir).unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
        )
        .unwrap();
        assert!(matches!(report.modules.unwrap_err(), Error::Io(_)));
    }
}
