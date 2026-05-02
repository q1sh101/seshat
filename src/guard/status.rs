//! Query installed-state and live-state of the boot-time lock unit.

use std::ffi::OsStr;
use std::path::Path;

use super::install::{GuardInputs, service_unit_name};
use crate::error::Error;
use crate::runtime::CommandOutput;

#[derive(Debug, PartialEq, Eq)]
pub struct GuardStatus {
    pub service_installed: bool,
    pub service_enabled: bool,
    pub modules_disabled: Option<u8>,
}

pub fn query_guard_status<R>(
    inputs: &GuardInputs<'_>,
    modules_disabled_path: &Path,
    mut runner: R,
) -> GuardStatus
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let service_installed = inputs.service_unit.exists();
    let service_enabled = if service_installed {
        is_enabled(&mut runner, &service_unit_name())
    } else {
        false
    };
    let modules_disabled = read_modules_disabled(modules_disabled_path);
    GuardStatus {
        service_installed,
        service_enabled,
        modules_disabled,
    }
}

fn is_enabled<R>(runner: &mut R, unit: &str) -> bool
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let argv: Vec<&OsStr> = [OsStr::new("is-enabled"), OsStr::new(unit)].into();
    match runner("systemctl", argv) {
        Ok(out) => out.success(),
        Err(_) => false,
    }
}

fn read_modules_disabled(path: &Path) -> Option<u8> {
    let text = std::fs::read_to_string(path).ok()?;
    match text.trim() {
        "0" => Some(0),
        "1" => Some(1),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn enabled() -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: b"enabled\n".to_vec(),
            stderr: vec![],
        }
    }

    fn disabled() -> CommandOutput {
        CommandOutput {
            exit_code: Some(1),
            stdout: b"disabled\n".to_vec(),
            stderr: vec![],
        }
    }

    struct Env {
        _root: tempfile::TempDir,
        unit_dir: PathBuf,
        service_unit: PathBuf,
        binary_path: PathBuf,
        state_root: PathBuf,
        modules_disabled: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let unit_dir = root.path().join("etc/systemd/system");
        std::fs::create_dir_all(&unit_dir).unwrap();
        Env {
            service_unit: unit_dir.join("kernel-hardening-guard.service"),
            binary_path: root.path().join("seshat"),
            state_root: root.path().join("var/lib/seshat"),
            modules_disabled: root.path().join("proc/sys/kernel/modules_disabled"),
            _root: root,
            unit_dir,
        }
    }

    fn inputs(env: &Env) -> GuardInputs<'_> {
        GuardInputs {
            binary_path: &env.binary_path,
            state_root: &env.state_root,
            unit_dir: &env.unit_dir,
            service_unit: &env.service_unit,
        }
    }

    #[test]
    fn status_pre_install_reports_absent_and_no_systemctl_call() {
        use std::cell::RefCell;
        let env = env();
        let calls: RefCell<u32> = RefCell::new(0);
        let status = query_guard_status(&inputs(&env), &env.modules_disabled, |_, _| {
            *calls.borrow_mut() += 1;
            Ok(disabled())
        });
        assert!(!status.service_installed);
        assert!(!status.service_enabled);
        assert_eq!(
            *calls.borrow(),
            0,
            "runner must not be consulted when service is absent"
        );
    }

    #[test]
    fn status_post_install_reports_installed_and_enabled() {
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let status = query_guard_status(&inputs(&env), &env.modules_disabled, |_, _| Ok(enabled()));
        assert!(status.service_installed);
        assert!(status.service_enabled);
    }

    #[test]
    fn status_installed_but_not_enabled_maps_is_enabled_failure_to_false() {
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let status =
            query_guard_status(&inputs(&env), &env.modules_disabled, |_, _| Ok(disabled()));
        assert!(status.service_installed);
        assert!(!status.service_enabled);
    }

    #[test]
    fn status_modules_disabled_parses_zero_one_and_none_on_missing() {
        let env = env();
        std::fs::create_dir_all(env.modules_disabled.parent().unwrap()).unwrap();
        std::fs::write(&env.modules_disabled, "0\n").unwrap();
        let s0 = query_guard_status(&inputs(&env), &env.modules_disabled, |_, _| Ok(disabled()));
        assert_eq!(s0.modules_disabled, Some(0));

        std::fs::write(&env.modules_disabled, "1\n").unwrap();
        let s1 = query_guard_status(&inputs(&env), &env.modules_disabled, |_, _| Ok(disabled()));
        assert_eq!(s1.modules_disabled, Some(1));

        std::fs::remove_file(&env.modules_disabled).unwrap();
        let s_missing =
            query_guard_status(&inputs(&env), &env.modules_disabled, |_, _| Ok(disabled()));
        assert!(s_missing.modules_disabled.is_none());
    }
}
