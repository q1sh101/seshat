use std::io;
use std::path::Path;

use crate::boot::{self, BootPlan};
use crate::error::Error;
use crate::modules::{self, EnforcementPlan};
use crate::policy::{BootArg, ModuleName, Profile, SysctlKey};
use crate::sysctl::{self, SysctlPlan, SysctlSetting};

#[derive(Debug)]
pub struct PlanReport {
    pub sysctl: Result<SysctlPlan, Error>,
    pub modules: Result<EnforcementPlan, Error>,
    pub boot: Result<BootPlan, Error>,
}

pub struct PlanInputs<'a> {
    pub profile: &'a Profile,
    pub proc_sys_root: &'a Path,
    pub modules_dir: &'a Path,
    pub snapshot_path: &'a Path,
    pub allow_path: &'a Path,
    pub block_path: &'a Path,
    pub grub_config_path: &'a Path,
}

pub fn orchestrate_plan(inputs: &PlanInputs<'_>) -> PlanReport {
    PlanReport {
        sysctl: plan_sysctl_domain(inputs),
        modules: plan_modules_domain(inputs),
        boot: plan_boot_domain(inputs),
    }
}

fn plan_sysctl_domain(inputs: &PlanInputs<'_>) -> Result<SysctlPlan, Error> {
    let settings: Vec<SysctlSetting> = inputs
        .profile
        .sysctl
        .iter()
        .map(SysctlSetting::from_entry)
        .collect::<Result<_, _>>()?;
    let proc_sys_root = inputs.proc_sys_root;
    let read_live = |key: &SysctlKey| sysctl::read_live_sysctl(proc_sys_root, key);
    Ok(sysctl::plan_sysctl(&settings, read_live))
}

fn plan_modules_domain(inputs: &PlanInputs<'_>) -> Result<EnforcementPlan, Error> {
    let snapshot = read_optional_allowlist(inputs.snapshot_path)?;
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

    let effective: Option<Vec<ModuleName>> = snapshot
        .as_ref()
        .map(|s| modules::effective_allowlist(s, allow.as_deref().unwrap_or(&[]), &combined_block));

    let installed = match &effective {
        Some(_) => modules::scan_installed_modules(inputs.modules_dir)?,
        None => Vec::new(),
    };

    Ok(modules::plan_enforcement(effective.as_deref(), &installed))
}

fn plan_boot_domain(inputs: &PlanInputs<'_>) -> Result<BootPlan, Error> {
    let current = read_grub_default(inputs.grub_config_path)?;
    let expected: Vec<BootArg> = inputs
        .profile
        .boot
        .iter()
        .map(|entry| BootArg::new(&entry.arg))
        .collect::<Result<_, _>>()?;
    Ok(boot::plan_boot_params(current.as_deref(), &expected))
}

fn read_optional_allowlist(path: &Path) -> Result<Option<Vec<ModuleName>>, Error> {
    match modules::parse_allowlist(path) {
        Ok(v) => Ok(Some(v)),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn read_grub_default(path: &Path) -> Result<Option<String>, Error> {
    match std::fs::read_to_string(path) {
        Ok(content) => Ok(boot::parse_grub_cmdline_default(&content)?.map(|g| g.value)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
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
        proc_sys_root: PathBuf,
        modules_dir: PathBuf,
        snapshot_path: PathBuf,
        allow_path: PathBuf,
        block_path: PathBuf,
        grub_config_path: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let proc_sys_root = root.path().join("proc_sys");
        let modules_dir = root.path().join("lib_modules");
        let snapshot_path = root.path().join("snapshot.conf");
        let allow_path = root.path().join("allow.conf");
        let block_path = root.path().join("block.conf");
        let grub_config_path = root.path().join("grub_config");
        fs::create_dir_all(&proc_sys_root).unwrap();
        fs::create_dir_all(&modules_dir).unwrap();
        Env {
            _root: root,
            proc_sys_root,
            modules_dir,
            snapshot_path,
            allow_path,
            block_path,
            grub_config_path,
        }
    }

    fn inputs<'a>(env: &'a Env, profile: &'a Profile) -> PlanInputs<'a> {
        PlanInputs {
            profile,
            proc_sys_root: &env.proc_sys_root,
            modules_dir: &env.modules_dir,
            snapshot_path: &env.snapshot_path,
            allow_path: &env.allow_path,
            block_path: &env.block_path,
            grub_config_path: &env.grub_config_path,
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

    fn seed_proc_sys(env: &Env, key_path: &str, value: &str) {
        let full = env.proc_sys_root.join(key_path);
        fs::create_dir_all(full.parent().unwrap()).unwrap();
        fs::write(full, value).unwrap();
    }

    fn seed_installed_modules(env: &Env, names: &[&str]) {
        let kernel_dir = env.modules_dir.join("kernel");
        fs::create_dir_all(&kernel_dir).unwrap();
        for n in names {
            fs::write(kernel_dir.join(format!("{n}.ko")), "").unwrap();
        }
    }

    #[test]
    fn aggregates_three_domain_plans_in_single_report() {
        let env = env();
        seed_proc_sys(&env, "kernel/kptr_restrict", "2");
        fs::write(
            &env.grub_config_path,
            "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n",
        )
        .unwrap();
        write_mode_0o600(&env.snapshot_path, "ext4\nvfat\n");

        let prof = profile(
            vec![("kernel.kptr_restrict", "2")],
            vec!["debugfs=off"],
            vec![],
        );
        let report = orchestrate_plan(&inputs(&env, &prof));
        assert!(report.sysctl.is_ok());
        assert!(report.modules.is_ok());
        assert!(report.boot.is_ok());
    }

    #[test]
    fn sysctl_domain_returns_plan_rows_matching_live_state() {
        let env = env();
        seed_proc_sys(&env, "kernel/kptr_restrict", "0");

        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let sysctl = report.sysctl.unwrap();
        assert_eq!(sysctl.rows.len(), 1);
        assert_eq!(sysctl.rows[0].state, sysctl::PlanState::Change);
    }

    #[test]
    fn modules_domain_skips_when_snapshot_missing() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let modules_plan = report.modules.unwrap();
        assert_eq!(modules_plan.rows[0].state, modules::PlanState::Skip);
    }

    #[test]
    fn modules_domain_reports_allow_count_from_effective_set() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\nvfat\nusb_storage\n");
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let plan = report.modules.unwrap();
        assert!(plan.rows[0].detail.contains("3 modules"));
    }

    #[test]
    fn boot_domain_returns_plan_when_grub_config_absent() {
        let env = env();
        let prof = profile(vec![], vec!["debugfs=off"], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let plan = report.boot.unwrap();
        assert_eq!(plan.merged_cmdline, "debugfs=off");
        assert_eq!(plan.changes, 1);
    }

    #[test]
    fn boot_domain_merges_against_existing_grub_cmdline() {
        let env = env();
        fs::write(
            &env.grub_config_path,
            "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet debugfs=on\"\n",
        )
        .unwrap();
        let prof = profile(vec![], vec!["debugfs=off"], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let plan = report.boot.unwrap();
        assert_eq!(plan.merged_cmdline, "quiet debugfs=off");
    }

    #[test]
    fn boot_domain_propagates_grub_parse_error() {
        let env = env();
        fs::write(
            &env.grub_config_path,
            "GRUB_CMDLINE_LINUX_DEFAULT=\"unterminated\n",
        )
        .unwrap();
        let prof = profile(vec![], vec!["debugfs=off"], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        assert!(matches!(report.boot.unwrap_err(), Error::Parse { .. }));
    }

    #[test]
    fn one_domain_failure_does_not_abort_other_domains() {
        let env = env();
        fs::write(&env.grub_config_path, "GRUB_CMDLINE_LINUX_DEFAULT=\"bad\n").unwrap();
        seed_proc_sys(&env, "kernel/kptr_restrict", "2");
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        assert!(report.boot.is_err());
        assert!(report.sysctl.is_ok());
        assert!(report.modules.is_ok());
    }

    #[test]
    fn modules_domain_skips_when_snapshot_missing_even_if_modules_dir_missing() {
        let env = env();
        fs::remove_dir(&env.modules_dir).unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let plan = report.modules.unwrap();
        assert_eq!(plan.rows[0].state, modules::PlanState::Skip);
    }

    #[test]
    fn modules_domain_errors_when_modules_dir_missing_and_snapshot_present() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\n");
        fs::remove_dir(&env.modules_dir).unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        assert!(matches!(report.modules.unwrap_err(), Error::Io(_)));
    }

    #[test]
    fn sysctl_domain_rejects_invalid_profile_entry() {
        let env = env();
        let prof = profile(vec![("Invalid.Key.With.Uppercase", "2")], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        assert!(matches!(
            report.sysctl.unwrap_err(),
            Error::Validation { .. }
        ));
    }

    #[test]
    fn profile_block_excludes_module_from_effective_allowlist() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\nvfat\n");
        seed_installed_modules(&env, &["ext4", "vfat"]);
        let prof = profile(vec![], vec![], vec!["vfat"]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let plan = report.modules.unwrap();
        assert_eq!(plan.rows[0].detail, "1 modules allowed");
        assert_eq!(plan.rows[1].state, modules::PlanState::Change);
        assert!(plan.rows[1].detail.contains("1 modules to block"));
    }

    #[test]
    fn profile_block_and_file_block_both_apply() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "ext4\nvfat\nusb_storage\n");
        write_mode_0o600(&env.block_path, "vfat\n");
        seed_installed_modules(&env, &["ext4", "vfat", "usb-storage"]);
        let prof = profile(vec![], vec![], vec!["usb_storage"]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        let plan = report.modules.unwrap();
        assert_eq!(plan.rows[0].detail, "1 modules allowed");
        assert!(plan.rows[1].detail.contains("2 modules to block"));
    }

    #[test]
    fn profile_block_rejected_when_entry_is_invalid_module_name() {
        let env = env();
        let prof = profile(vec![], vec![], vec!["bad name"]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        assert!(matches!(
            report.modules.unwrap_err(),
            Error::Validation { .. }
        ));
    }

    #[test]
    fn empty_profile_yields_empty_plans_across_all_domains() {
        let env = env();
        write_mode_0o600(&env.snapshot_path, "");
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_plan(&inputs(&env, &prof));
        assert_eq!(report.sysctl.unwrap().rows.len(), 0);
        let modules_plan = report.modules.unwrap();
        assert_eq!(modules_plan.rows[0].detail, "0 modules allowed");
        assert_eq!(report.boot.unwrap().rows.len(), 0);
    }
}
