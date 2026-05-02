//! Install the boot-time auto-lock systemd service unit.

use std::ffi::OsStr;
use std::path::Path;

use super::units::generate_service_unit;
use crate::atomic::install_root_file;
use crate::error::Error;
use crate::paths::{GUARD_UNIT_STEM, ensure_dir};
use crate::runtime::CommandOutput;

const UNIT_MODE: u32 = 0o644;

pub(crate) fn service_unit_name() -> String {
    format!("{GUARD_UNIT_STEM}.service")
}

pub struct GuardInputs<'a> {
    pub binary_path: &'a Path,
    pub state_root: &'a Path,
    pub unit_dir: &'a Path,
    pub service_unit: &'a Path,
}

pub fn install_guard<R>(inputs: &GuardInputs<'_>, mut runner: R) -> Result<(), Error>
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    ensure_dir(inputs.unit_dir)?;

    let body = generate_service_unit(inputs.binary_path, inputs.state_root)?;
    install_root_file(inputs.service_unit, body.as_bytes(), UNIT_MODE)?;

    // enable (not --now): the lock fires on next boot, not at install time.
    let unit = service_unit_name();
    systemctl(&mut runner, &["daemon-reload"])?;
    systemctl(&mut runner, &["enable", &unit])?;
    Ok(())
}

fn systemctl<R>(runner: &mut R, args: &[&str]) -> Result<(), Error>
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let argv: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    let out = runner("systemctl", argv)?;
    if out.success() {
        return Ok(());
    }
    Err(Error::Validation {
        field: "systemctl".to_string(),
        reason: format!(
            "systemctl {} failed: {}",
            args.join(" "),
            out.stderr_summary()
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn ok_output() -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: vec![],
            stderr: vec![],
        }
    }

    fn fail_output(reason: &[u8]) -> CommandOutput {
        CommandOutput {
            exit_code: Some(1),
            stdout: vec![],
            stderr: reason.to_vec(),
        }
    }

    struct Env {
        _root: tempfile::TempDir,
        unit_dir: PathBuf,
        service_unit: PathBuf,
        binary_path: PathBuf,
        state_root: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let unit_dir = root.path().join("etc/systemd/system");
        let state_root = root.path().join("var/lib/seshat");
        std::fs::create_dir_all(&unit_dir).unwrap();
        std::fs::create_dir_all(&state_root).unwrap();
        Env {
            service_unit: unit_dir.join("kernel-hardening-guard.service"),
            binary_path: root.path().join("usr/local/bin/seshat"),
            _root: root,
            unit_dir,
            state_root,
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
    fn install_writes_service_unit_and_runs_systemctl_in_order() {
        let env = env();
        let calls: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());
        install_guard(&inputs(&env), |program, args| {
            let mut rec = vec![program.to_string()];
            for a in args {
                rec.push(a.to_string_lossy().into_owned());
            }
            calls.borrow_mut().push(rec);
            Ok(ok_output())
        })
        .unwrap();

        assert!(env.service_unit.exists());
        let recorded = calls.borrow();
        assert_eq!(recorded.len(), 2);
        assert_eq!(recorded[0], vec!["systemctl", "daemon-reload"]);
        assert_eq!(
            recorded[1],
            vec!["systemctl", "enable", "kernel-hardening-guard.service"]
        );
    }

    #[test]
    fn install_does_not_pass_now_flag_to_enable() {
        let env = env();
        let calls: RefCell<Vec<String>> = RefCell::new(Vec::new());
        install_guard(&inputs(&env), |_, args| {
            let rec: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            calls.borrow_mut().push(rec.join(" "));
            Ok(ok_output())
        })
        .unwrap();
        for call in calls.borrow().iter() {
            assert!(
                !call.contains("--now"),
                "install must not trigger the unit at install time: {call}"
            );
        }
    }

    #[test]
    fn install_writes_unit_at_mode_0o644() {
        use std::os::unix::fs::PermissionsExt;
        let env = env();
        install_guard(&inputs(&env), |_, _| Ok(ok_output())).unwrap();
        let mode = std::fs::metadata(&env.service_unit)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }

    #[test]
    fn install_is_idempotent_and_overwrites() {
        let env = env();
        install_guard(&inputs(&env), |_, _| Ok(ok_output())).unwrap();
        let first = std::fs::read_to_string(&env.service_unit).unwrap();
        install_guard(&inputs(&env), |_, _| Ok(ok_output())).unwrap();
        let second = std::fs::read_to_string(&env.service_unit).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn install_refuses_symlinked_unit_dir() {
        use std::os::unix::fs::symlink;
        let root = tempdir().unwrap();
        let real = root.path().join("real_units");
        std::fs::create_dir_all(&real).unwrap();
        let unit_dir = root.path().join("etc/systemd/system");
        std::fs::create_dir_all(unit_dir.parent().unwrap()).unwrap();
        symlink(&real, &unit_dir).unwrap();

        let bin = root.path().join("seshat");
        let state = root.path().join("state");
        std::fs::create_dir_all(&state).unwrap();
        let inputs = GuardInputs {
            binary_path: &bin,
            state_root: &state,
            unit_dir: &unit_dir,
            service_unit: &unit_dir.join("kernel-hardening-guard.service"),
        };
        let err = install_guard(&inputs, |_, _| Ok(ok_output())).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn install_aborts_when_systemctl_enable_fails() {
        let env = env();
        let err = install_guard(&inputs(&env), |_, args| {
            let joined: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            if joined.contains(&"enable".to_string()) {
                Ok(fail_output(b"unit not found"))
            } else {
                Ok(ok_output())
            }
        })
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }
}
