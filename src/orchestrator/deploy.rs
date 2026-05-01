use std::ffi::OsStr;
use std::io;
use std::path::{Path, PathBuf};

use crate::boot::{
    self, Backend, RefreshStatus, deploy_grub_dropin, deploy_grub_main_config,
    parse_grub_cmdline_default, plan_boot_params, refresh_grub_configuration,
};
use crate::error::Error;
use crate::lock;
use crate::modules::{self, DeploySummary as ModulesDeploy};
use crate::policy::{BootArg, ModuleName, Profile, SysctlKey};
use crate::result::CheckState;
use crate::runtime::CommandOutput;
use crate::sysctl::{self, DeploySummary as SysctlDeploy, LiveRead, ReloadStatus, SysctlSetting};

use super::OPERATION_LOCK_NAME;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BootDeployMode {
    GrubDropIn,
    GrubMainFile,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BootSkipReason {
    NoProfileBootArgs,
    BackendSystemdBoot,
    BackendUnknown,
    GrubFilesMissing,
}

impl BootSkipReason {
    pub fn message(&self) -> &'static str {
        match self {
            Self::NoProfileBootArgs => "boot deploy: profile has no boot args",
            Self::BackendSystemdBoot => "boot deploy: systemd-boot backend not supported",
            Self::BackendUnknown => "boot deploy: no known bootloader detected",
            Self::GrubFilesMissing => "boot deploy: /etc/default/grub(.d) not present",
        }
    }
}

#[derive(Debug)]
pub struct BootDeploySummary {
    pub mode: BootDeployMode,
    pub target: PathBuf,
    pub refresh: RefreshStatus,
}

#[derive(Debug)]
pub enum BootDeployStatus {
    Applied(BootDeploySummary),
    Skipped(BootSkipReason),
    DomainError(Error),
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
        let boot_code = classify_boot_status(&self.boot);
        sysctl_code.max(modules_code).max(boot_code)
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

fn classify_boot_status(status: &BootDeployStatus) -> i32 {
    match status {
        BootDeployStatus::Skipped(_) => 0,
        BootDeployStatus::DomainError(e) => classify_deploy_error(e),
        BootDeployStatus::Applied(summary) => match &summary.refresh {
            RefreshStatus::Applied { .. } => 0,
            RefreshStatus::Unavailable | RefreshStatus::Failed { .. } => 1,
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
    pub grub_config: &'a Path,
    pub grub_config_d: &'a Path,
    pub grub_cfg: &'a Path,
    pub grub_dropin_target: &'a Path,
    pub kernel_cmdline: &'a Path,
    pub boot_backup_dir: &'a Path,
}

pub fn orchestrate_deploy<F, G, H, R>(
    inputs: &DeployInputs<'_>,
    sysctl_reload: F,
    sysctl_read_live: G,
    boot_has_command: H,
    boot_runner: R,
) -> Result<DeployReport, Error>
where
    F: FnOnce() -> ReloadStatus,
    G: FnMut(&SysctlKey) -> LiveRead,
    H: Fn(&str) -> bool,
    R: FnOnce(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let _guard = lock::acquire(inputs.lock_root, OPERATION_LOCK_NAME)?;
    Ok(DeployReport {
        sysctl: deploy_sysctl_domain(inputs, sysctl_reload, sysctl_read_live),
        modules: deploy_modules_domain(inputs),
        boot: deploy_boot_domain(inputs, boot_has_command, boot_runner),
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

// Skip reasons (empty profile, non-grub backend, missing grub files) exit cleanly; domain errors keep the existing exit-3 / exit-1 mapping.
pub(crate) fn deploy_boot_domain<H, R>(
    inputs: &DeployInputs<'_>,
    has_command: H,
    runner: R,
) -> BootDeployStatus
where
    H: Fn(&str) -> bool,
    R: FnOnce(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    if inputs.profile.boot.is_empty() {
        return BootDeployStatus::Skipped(BootSkipReason::NoProfileBootArgs);
    }

    let backend = boot::detect_backend(
        inputs.grub_config,
        inputs.grub_config_d,
        inputs.grub_cfg,
        inputs.kernel_cmdline,
        &has_command,
    );
    match backend {
        Backend::SystemdBoot => {
            return BootDeployStatus::Skipped(BootSkipReason::BackendSystemdBoot);
        }
        Backend::Unknown => return BootDeployStatus::Skipped(BootSkipReason::BackendUnknown),
        Backend::Grub => {}
    }

    let has_dropin_parent = inputs.grub_config_d.is_dir();
    let has_main = inputs.grub_config.is_file();
    if !has_dropin_parent && !has_main {
        return BootDeployStatus::Skipped(BootSkipReason::GrubFilesMissing);
    }

    let expected_args: Vec<BootArg> = match inputs
        .profile
        .boot
        .iter()
        .map(|e| BootArg::new(&e.arg))
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(e) => return BootDeployStatus::DomainError(e),
    };

    // Empty content on missing /etc/default/grub keeps plan sane; drop-in path still benefits from that current view.
    let current_content = match std::fs::read_to_string(inputs.grub_config) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => String::new(),
        Err(e) => return BootDeployStatus::DomainError(Error::Io(e)),
    };
    let current_default = match parse_grub_cmdline_default(&current_content) {
        Ok(d) => d,
        Err(e) => return BootDeployStatus::DomainError(e),
    };
    let current_cmdline = current_default.as_ref().map(|d| d.value.as_str());
    let plan = plan_boot_params(current_cmdline, &expected_args);

    let (deploy_result, mode) = if has_dropin_parent {
        (
            deploy_grub_dropin(
                &plan.merged_cmdline,
                inputs.profile.profile_name.as_str(),
                inputs.grub_dropin_target,
                inputs.boot_backup_dir,
            ),
            BootDeployMode::GrubDropIn,
        )
    } else {
        (
            deploy_grub_main_config(
                &plan.merged_cmdline,
                inputs.grub_config,
                inputs.boot_backup_dir,
            ),
            BootDeployMode::GrubMainFile,
        )
    };
    let summary = match deploy_result {
        Ok(s) => s,
        Err(e) => return BootDeployStatus::DomainError(e),
    };

    let refresh = refresh_grub_configuration(inputs.grub_cfg, &has_command, runner);

    BootDeployStatus::Applied(BootDeploySummary {
        mode,
        target: summary.target,
        refresh,
    })
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
    use crate::boot::RefreshBackend;
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
        grub_config: PathBuf,
        grub_config_d: PathBuf,
        grub_cfg: PathBuf,
        grub_dropin_target: PathBuf,
        kernel_cmdline: PathBuf,
        boot_backup_dir: PathBuf,
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
        let grub_config = root.path().join("etc/default/grub");
        let grub_config_d = root.path().join("etc/default/grub.d");
        let grub_cfg = root.path().join("boot/grub/grub.cfg");
        let grub_dropin_target = grub_config_d.join("99-test.cfg");
        let kernel_cmdline = root.path().join("etc/kernel/cmdline");
        let boot_backup_dir = root.path().join("backups/boot");
        fs::create_dir_all(&modules_dir).unwrap();
        fs::create_dir_all(sysctl_target.parent().unwrap()).unwrap();
        fs::create_dir_all(&sysctl_backup_dir).unwrap();
        fs::create_dir_all(modprobe_target.parent().unwrap()).unwrap();
        fs::create_dir_all(&modprobe_backup_dir).unwrap();
        fs::create_dir_all(&lock_root).unwrap();
        fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir_all(grub_config.parent().unwrap()).unwrap();
        fs::create_dir_all(grub_cfg.parent().unwrap()).unwrap();
        fs::create_dir_all(&boot_backup_dir).unwrap();
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
            grub_config,
            grub_config_d,
            grub_cfg,
            grub_dropin_target,
            kernel_cmdline,
            boot_backup_dir,
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
            grub_config: &env.grub_config,
            grub_config_d: &env.grub_config_d,
            grub_cfg: &env.grub_cfg,
            grub_dropin_target: &env.grub_dropin_target,
            kernel_cmdline: &env.kernel_cmdline,
            boot_backup_dir: &env.boot_backup_dir,
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

    fn has_none(_: &str) -> bool {
        false
    }

    fn runner_never(_: &str, _: Vec<&OsStr>) -> Result<CommandOutput, Error> {
        panic!("runner must not be invoked when no backend is selected");
    }

    fn applied_runner(_: &str, _: Vec<&OsStr>) -> Result<CommandOutput, Error> {
        Ok(CommandOutput {
            exit_code: Some(0),
            stdout: vec![],
            stderr: vec![],
        })
    }

    fn seed_grub_tree(env: &Env, main_content: &str) {
        fs::write(&env.grub_config, main_content).unwrap();
        fs::create_dir_all(&env.grub_config_d).unwrap();
        fs::write(&env.grub_cfg, b"# managed\n").unwrap();
    }

    #[test]
    fn boot_deploy_skipped_when_profile_has_no_boot_args() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
        )
        .unwrap();
        assert!(matches!(
            report.boot,
            BootDeployStatus::Skipped(BootSkipReason::NoProfileBootArgs)
        ));
    }

    #[test]
    fn boot_deploy_skipped_when_backend_is_unknown() {
        let env = env();
        let prof = profile(vec![], vec!["quiet"], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
        )
        .unwrap();
        assert!(matches!(
            report.boot,
            BootDeployStatus::Skipped(BootSkipReason::BackendUnknown)
        ));
    }

    #[test]
    fn boot_deploy_skipped_when_backend_is_systemd_boot() {
        let env = env();
        fs::create_dir_all(env.kernel_cmdline.parent().unwrap()).unwrap();
        fs::write(&env.kernel_cmdline, b"quiet\n").unwrap();
        let prof = profile(vec![], vec!["debugfs=off"], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
        )
        .unwrap();
        assert!(matches!(
            report.boot,
            BootDeployStatus::Skipped(BootSkipReason::BackendSystemdBoot)
        ));
    }

    #[test]
    fn boot_deploy_skipped_when_grub_detected_but_files_missing() {
        // Only grub_cfg present triggers Grub backend; main config + dropin dir absent means nothing to deploy to.
        let env = env();
        fs::write(&env.grub_cfg, b"# managed\n").unwrap();
        let has_grub_tool = |name: &str| name == "update-grub";
        let prof = profile(vec![], vec!["quiet"], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_grub_tool,
            runner_never,
        )
        .unwrap();
        assert!(matches!(
            report.boot,
            BootDeployStatus::Skipped(BootSkipReason::GrubFilesMissing)
        ));
    }

    #[test]
    fn boot_deploy_via_dropin_when_grub_config_d_exists() {
        let env = env();
        seed_grub_tree(&env, "GRUB_CMDLINE_LINUX_DEFAULT=\"ro\"\n");
        let has_grub_tool = |name: &str| name == "update-grub";
        let prof = profile(vec![], vec!["quiet", "debugfs=off"], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_grub_tool,
            applied_runner,
        )
        .unwrap();
        match report.boot {
            BootDeployStatus::Applied(summary) => {
                assert_eq!(summary.mode, BootDeployMode::GrubDropIn);
                assert_eq!(summary.target, env.grub_dropin_target);
                assert!(summary.backup.is_none(), "fresh dropin has no prior file");
                assert!(matches!(
                    summary.refresh,
                    RefreshStatus::Applied {
                        backend: RefreshBackend::UpdateGrub
                    }
                ));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        let body = fs::read_to_string(&env.grub_dropin_target).unwrap();
        assert!(body.contains("GRUB_CMDLINE_LINUX_DEFAULT=\"ro quiet debugfs=off\""));
    }

    #[test]
    fn boot_deploy_via_main_file_when_only_grub_config_exists() {
        let env = env();
        fs::write(&env.grub_config, "GRUB_CMDLINE_LINUX_DEFAULT=\"ro\"\n").unwrap();
        fs::write(&env.grub_cfg, b"# managed\n").unwrap();
        // grub_config_d NOT created → drop-in path unavailable, main-file path taken.
        let has_grub_tool = |name: &str| name == "grub-mkconfig";
        let prof = profile(vec![], vec!["quiet"], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_grub_tool,
            applied_runner,
        )
        .unwrap();
        match report.boot {
            BootDeployStatus::Applied(summary) => {
                assert_eq!(summary.mode, BootDeployMode::GrubMainFile);
                assert_eq!(summary.target, env.grub_config);
                assert!(summary.backup.is_some(), "existing main must be backed up");
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        let body = fs::read_to_string(&env.grub_config).unwrap();
        assert!(body.contains("GRUB_CMDLINE_LINUX_DEFAULT=\"ro quiet\""));
    }

    #[test]
    fn boot_deploy_propagates_invalid_profile_boot_arg_as_domain_error() {
        let env = env();
        seed_grub_tree(&env, "GRUB_CMDLINE_LINUX_DEFAULT=\"\"\n");
        let prof = profile(vec![], vec!["bad arg with space"], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            |name| name == "update-grub",
            runner_never,
        )
        .unwrap();
        assert!(matches!(report.boot, BootDeployStatus::DomainError(_)));
    }

    #[test]
    fn boot_deploy_propagates_main_parse_error_as_domain_error() {
        let env = env();
        // Malformed main config; no drop-in dir so main-file path is chosen and fails at parse time.
        fs::write(
            &env.grub_config,
            b"GRUB_CMDLINE_LINUX_DEFAULT=\"unterminated\n",
        )
        .unwrap();
        fs::write(&env.grub_cfg, b"# managed\n").unwrap();
        let prof = profile(vec![], vec!["quiet"], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            |name| name == "update-grub",
            runner_never,
        )
        .unwrap();
        assert!(matches!(
            report.boot,
            BootDeployStatus::DomainError(Error::Parse { .. })
        ));
    }

    #[test]
    fn modules_deploy_requires_snapshot() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
        )
        .unwrap();
        let summary = report.modules.unwrap();
        assert_eq!(summary.allow_count, 1);
        assert_eq!(summary.block_count, 1);
    }

    #[test]
    fn exit_code_zero_when_domains_ok_and_boot_skipped() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
        )
        .unwrap();
        assert_eq!(count, 1);
    }

    #[test]
    fn deploy_fails_when_another_deploy_holds_the_lock() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let result = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
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
            has_none,
            runner_never,
        )
        .unwrap();
        orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
        )
        .unwrap();
        assert!(matches!(report.modules, Err(Error::UnsafePath { .. })));
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn exit_code_three_on_top_level_lock_contention() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let err = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            matching_reader(),
            has_none,
            runner_never,
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
        )
        .unwrap();
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_one_when_reload_applied_but_live_verify_warns() {
        let env = env_with_modules_ready();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let drift_reader = |_: &SysctlKey| LiveRead::Value("0".to_string());
        let report = orchestrate_deploy(
            &inputs(&env, &prof),
            || ReloadStatus::Applied,
            drift_reader,
            has_none,
            runner_never,
        )
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
            has_none,
            runner_never,
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
            has_none,
            runner_never,
        )
        .unwrap();
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn classify_deploy_error_maps_security_variants_to_three() {
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
            has_none,
            runner_never,
        )
        .unwrap();
        assert!(matches!(report.modules.unwrap_err(), Error::Io(_)));
    }
}
