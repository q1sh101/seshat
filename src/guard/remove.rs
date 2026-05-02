//! Remove the boot-time auto-lock service unit.

use std::ffi::OsStr;
use std::io;

use super::install::{GuardInputs, service_unit_name};
use crate::error::Error;
use crate::runtime::CommandOutput;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RemoveSummary {
    pub service_removed: bool,
}

pub fn remove_guard<R>(inputs: &GuardInputs<'_>, mut runner: R) -> Result<RemoveSummary, Error>
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    // disable is tolerant: the unit may never have been enabled.
    let unit = service_unit_name();
    disable_tolerant(&mut runner, &unit);

    let service_removed = remove_if_present(inputs.service_unit)?;

    reload_tolerant(&mut runner);

    Ok(RemoveSummary { service_removed })
}

fn disable_tolerant<R>(runner: &mut R, unit: &str)
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let argv: Vec<&OsStr> = [OsStr::new("disable"), OsStr::new(unit)].into();
    let _ = runner("systemctl", argv);
}

fn reload_tolerant<R>(runner: &mut R)
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let argv: Vec<&OsStr> = [OsStr::new("daemon-reload")].into();
    let _ = runner("systemctl", argv);
}

fn remove_if_present(path: &std::path::Path) -> Result<bool, Error> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::Io(e)),
    }
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

    fn fail_output() -> CommandOutput {
        CommandOutput {
            exit_code: Some(1),
            stdout: vec![],
            stderr: b"unit not loaded".to_vec(),
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
        std::fs::create_dir_all(&unit_dir).unwrap();
        Env {
            service_unit: unit_dir.join("kernel-hardening-guard.service"),
            binary_path: root.path().join("seshat"),
            state_root: root.path().join("var/lib/seshat"),
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
    fn remove_from_empty_state_returns_service_removed_false() {
        let env = env();
        let summary = remove_guard(&inputs(&env), |_, _| Ok(ok_output())).unwrap();
        assert_eq!(summary, RemoveSummary::default());
    }

    #[test]
    fn remove_from_installed_state_deletes_unit_and_reports_true() {
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let summary = remove_guard(&inputs(&env), |_, _| Ok(ok_output())).unwrap();
        assert_eq!(
            summary,
            RemoveSummary {
                service_removed: true
            }
        );
        assert!(!env.service_unit.exists());
    }

    #[test]
    fn remove_tolerates_systemctl_disable_failure() {
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let summary = remove_guard(&inputs(&env), |_, _| Ok(fail_output())).unwrap();
        assert!(summary.service_removed);
        assert!(!env.service_unit.exists());
    }

    #[test]
    fn remove_calls_daemon_reload_after_file_deletion() {
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let calls: RefCell<Vec<String>> = RefCell::new(Vec::new());
        remove_guard(&inputs(&env), |_, args| {
            let rec: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            calls.borrow_mut().push(rec.join(" "));
            Ok(ok_output())
        })
        .unwrap();
        let recorded = calls.borrow();
        assert!(recorded.iter().any(|c| c == "daemon-reload"));
        assert_eq!(
            recorded.last().map(String::as_str),
            Some("daemon-reload"),
            "daemon-reload must be the final systemctl call"
        );
    }
}
