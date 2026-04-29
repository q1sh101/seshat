use std::io;
use std::path::Path;

use crate::boot::{self, BootVerify};
use crate::error::Error;
use crate::modules::{self, VerifyReport as ModulesVerify};
use crate::policy::{BootArg, ModuleName, Profile, SysctlKey};
use crate::result::CheckState;
use crate::sysctl::{self, SysctlSetting, SysctlVerify};

#[derive(Debug, PartialEq, Eq)]
pub struct LockdownRow {
    pub state: CheckState,
    pub detail: String,
    pub hint: &'static str,
}

#[derive(Debug)]
pub struct VerifyReport {
    pub sysctl: Result<SysctlVerify, Error>,
    pub modules: Result<ModulesVerify, Error>,
    pub boot: Result<BootVerify, Error>,
    pub lockdown: LockdownRow,
}

pub struct VerifyInputs<'a> {
    pub profile: &'a Profile,
    pub proc_sys_root: &'a Path,
    pub modules_dir: &'a Path,
    pub snapshot_path: &'a Path,
    pub allow_path: &'a Path,
    pub block_path: &'a Path,
    pub proc_cmdline_path: &'a Path,
    pub modprobe_dropin_path: &'a Path,
    pub sys_lockdown_path: &'a Path,
    pub modprobe_show_config: Option<String>,
}

pub fn orchestrate_verify(inputs: &VerifyInputs<'_>) -> VerifyReport {
    VerifyReport {
        sysctl: verify_sysctl_domain(inputs),
        modules: verify_modules_domain(inputs),
        boot: verify_boot_domain(inputs),
        lockdown: verify_lockdown_domain(inputs),
    }
}

fn verify_sysctl_domain(inputs: &VerifyInputs<'_>) -> Result<SysctlVerify, Error> {
    let settings: Vec<SysctlSetting> = inputs
        .profile
        .sysctl
        .iter()
        .map(SysctlSetting::from_entry)
        .collect::<Result<_, _>>()?;
    let proc_sys_root = inputs.proc_sys_root;
    let read_live = |key: &SysctlKey| sysctl::read_live_sysctl(proc_sys_root, key);
    Ok(sysctl::verify_sysctl(&settings, read_live))
}

fn verify_modules_domain(inputs: &VerifyInputs<'_>) -> Result<ModulesVerify, Error> {
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

    let cfg = inputs.modprobe_show_config.clone();
    modules::verify_enforcement(
        effective.as_deref(),
        &installed,
        inputs.profile.profile_name.as_str(),
        inputs.modprobe_dropin_path,
        move || cfg,
    )
}

fn verify_boot_domain(inputs: &VerifyInputs<'_>) -> Result<BootVerify, Error> {
    let live = boot::read_live_cmdline(inputs.proc_cmdline_path)?;
    let expected: Vec<BootArg> = inputs
        .profile
        .boot
        .iter()
        .map(|e| BootArg::new(&e.arg))
        .collect::<Result<_, _>>()?;
    Ok(boot::verify_boot_params(live.as_deref(), &expected))
}

fn verify_lockdown_domain(inputs: &VerifyInputs<'_>) -> LockdownRow {
    let expected = inputs.profile.lockdown.expect.as_deref();
    let live = read_lockdown_file(inputs.sys_lockdown_path);
    verify_lockdown(expected, live.as_deref())
}

fn verify_lockdown(expected: Option<&str>, live: Option<&str>) -> LockdownRow {
    match (expected, live) {
        (None, _) => LockdownRow {
            state: CheckState::Skip,
            detail: "lockdown expectation not configured".to_string(),
            hint: "",
        },
        (Some(_), None) => LockdownRow {
            state: CheckState::Warn,
            detail: "cannot read /sys/kernel/security/lockdown".to_string(),
            hint: "kernel without lockdown support",
        },
        (Some(exp), Some(content)) => match parse_lockdown(content) {
            None => LockdownRow {
                state: CheckState::Warn,
                detail: "unrecognized lockdown format".to_string(),
                hint: "",
            },
            Some(live_mode) => {
                if live_mode == exp {
                    LockdownRow {
                        state: CheckState::Ok,
                        detail: format!("lockdown: {exp}"),
                        hint: "",
                    }
                } else {
                    LockdownRow {
                        state: CheckState::Warn,
                        detail: format!("live {live_mode}, expected {exp}"),
                        hint: "reboot with kernel lockdown= to apply",
                    }
                }
            }
        },
    }
}

fn parse_lockdown(content: &str) -> Option<String> {
    for token in content.split_whitespace() {
        if let Some(inner) = token.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            return Some(inner.to_string());
        }
    }
    None
}

fn read_lockdown_file(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
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
        proc_sys_root: PathBuf,
        modules_dir: PathBuf,
        snapshot_path: PathBuf,
        allow_path: PathBuf,
        block_path: PathBuf,
        proc_cmdline_path: PathBuf,
        modprobe_dropin_path: PathBuf,
        sys_lockdown_path: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let proc_sys_root = root.path().join("proc_sys");
        let modules_dir = root.path().join("lib_modules");
        let snapshot_path = root.path().join("snapshot.conf");
        let allow_path = root.path().join("allow.conf");
        let block_path = root.path().join("block.conf");
        let proc_cmdline_path = root.path().join("proc_cmdline");
        let modprobe_dropin_path = root.path().join("modprobe.conf");
        let sys_lockdown_path = root.path().join("lockdown");
        fs::create_dir_all(&proc_sys_root).unwrap();
        fs::create_dir_all(&modules_dir).unwrap();
        Env {
            _root: root,
            proc_sys_root,
            modules_dir,
            snapshot_path,
            allow_path,
            block_path,
            proc_cmdline_path,
            modprobe_dropin_path,
            sys_lockdown_path,
        }
    }

    fn inputs<'a>(
        env: &'a Env,
        profile: &'a Profile,
        modprobe_show_config: Option<String>,
    ) -> VerifyInputs<'a> {
        VerifyInputs {
            profile,
            proc_sys_root: &env.proc_sys_root,
            modules_dir: &env.modules_dir,
            snapshot_path: &env.snapshot_path,
            allow_path: &env.allow_path,
            block_path: &env.block_path,
            proc_cmdline_path: &env.proc_cmdline_path,
            modprobe_dropin_path: &env.modprobe_dropin_path,
            sys_lockdown_path: &env.sys_lockdown_path,
            modprobe_show_config,
        }
    }

    fn profile(
        sysctl: Vec<(&str, &str)>,
        boot: Vec<&str>,
        modules_block: Vec<&str>,
        lockdown: Option<&str>,
    ) -> Profile {
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
            lockdown: LockdownSection {
                expect: lockdown.map(String::from),
            },
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
    fn parse_lockdown_extracts_bracketed_mode() {
        assert_eq!(
            parse_lockdown("none [integrity] confidentiality\n").as_deref(),
            Some("integrity")
        );
        assert_eq!(
            parse_lockdown("[none] integrity confidentiality\n").as_deref(),
            Some("none")
        );
    }

    #[test]
    fn parse_lockdown_returns_none_for_unrecognized_format() {
        assert!(parse_lockdown("").is_none());
        assert!(parse_lockdown("none integrity confidentiality").is_none());
    }

    #[test]
    fn lockdown_skip_when_expectation_not_configured() {
        let row = verify_lockdown(None, Some("[none] integrity"));
        assert_eq!(row.state, CheckState::Skip);
    }

    #[test]
    fn lockdown_skip_when_expectation_not_configured_regardless_of_live_state() {
        assert_eq!(verify_lockdown(None, None).state, CheckState::Skip);
        assert_eq!(
            verify_lockdown(None, Some("garbage")).state,
            CheckState::Skip
        );
    }

    #[test]
    fn lockdown_warn_when_live_unavailable_with_configured_expectation() {
        let row = verify_lockdown(Some("integrity"), None);
        assert_eq!(row.state, CheckState::Warn);
        assert!(row.detail.contains("/sys/kernel/security/lockdown"));
    }

    #[test]
    fn lockdown_warn_when_live_unrecognized_with_configured_expectation() {
        let row = verify_lockdown(Some("integrity"), Some("no brackets here"));
        assert_eq!(row.state, CheckState::Warn);
        assert!(row.detail.contains("unrecognized"));
    }

    #[test]
    fn lockdown_ok_when_live_matches_expected() {
        let row = verify_lockdown(
            Some("integrity"),
            Some("none [integrity] confidentiality\n"),
        );
        assert_eq!(row.state, CheckState::Ok);
    }

    #[test]
    fn lockdown_warn_when_live_differs_with_reboot_hint() {
        let row = verify_lockdown(
            Some("confidentiality"),
            Some("none [integrity] confidentiality\n"),
        );
        assert_eq!(row.state, CheckState::Warn);
        assert!(row.detail.contains("integrity"));
        assert!(row.detail.contains("confidentiality"));
        assert!(!row.hint.is_empty());
    }

    #[test]
    fn lockdown_warn_when_configured_but_file_missing() {
        let env = env();
        let prof = profile(vec![], vec![], vec![], Some("integrity"));
        let report = orchestrate_verify(&inputs(&env, &prof, None));
        assert_eq!(report.lockdown.state, CheckState::Warn);
    }

    #[test]
    fn lockdown_skip_when_not_configured() {
        let env = env();
        let prof = profile(vec![], vec![], vec![], None);
        let report = orchestrate_verify(&inputs(&env, &prof, None));
        assert_eq!(report.lockdown.state, CheckState::Skip);
    }

    #[test]
    fn aggregates_four_domain_outcomes_in_single_report() {
        let env = env();
        seed_proc_sys(&env, "kernel/kptr_restrict", "2");
        fs::write(&env.proc_cmdline_path, "quiet debugfs=off\n").unwrap();
        fs::write(&env.sys_lockdown_path, "[integrity] none\n").unwrap();
        let prof = profile(
            vec![("kernel.kptr_restrict", "2")],
            vec!["debugfs=off"],
            vec![],
            Some("integrity"),
        );
        let report = orchestrate_verify(&inputs(&env, &prof, None));
        assert!(report.sysctl.is_ok());
        assert!(report.modules.is_ok());
        assert!(report.boot.is_ok());
        assert_eq!(report.lockdown.state, CheckState::Ok);
    }

    #[test]
    fn modules_domain_skips_when_snapshot_missing_even_if_modules_dir_missing() {
        let env = env();
        fs::remove_dir(&env.modules_dir).unwrap();
        let prof = profile(vec![], vec![], vec![], None);
        let report = orchestrate_verify(&inputs(&env, &prof, None));
        assert!(report.modules.is_ok());
    }
}
