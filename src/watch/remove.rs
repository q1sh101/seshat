//! Remove the drift-detector systemd units.

use std::ffi::OsStr;
use std::io;

use super::install::{WatchInputs, unit_name};
use crate::error::Error;
use crate::runtime::CommandOutput;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct RemoveSummary {
    pub service_removed: bool,
    pub path_removed: bool,
    pub timer_removed: bool,
}

pub fn remove_watch<R>(inputs: &WatchInputs<'_>, mut runner: R) -> Result<RemoveSummary, Error>
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    // disable --now is allowed to fail when the unit was never enabled.
    disable_tolerant(&mut runner, &unit_name("path"));
    disable_tolerant(&mut runner, &unit_name("timer"));

    let service_removed = remove_if_present(inputs.service_unit)?;
    let path_removed = remove_if_present(inputs.path_unit)?;
    let timer_removed = remove_if_present(inputs.timer_unit)?;

    reload_tolerant(&mut runner);

    Ok(RemoveSummary {
        service_removed,
        path_removed,
        timer_removed,
    })
}

fn disable_tolerant<R>(runner: &mut R, unit: &str)
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let argv: Vec<&OsStr> = [OsStr::new("disable"), OsStr::new("--now"), OsStr::new(unit)].into();
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
    use crate::policy::ProfileName;
    use std::cell::RefCell;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn profile() -> ProfileName {
        ProfileName::new("baseline").unwrap()
    }

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
        path_unit: PathBuf,
        timer_unit: PathBuf,
        sysctl_dropin: PathBuf,
        modprobe_dropin: PathBuf,
        binary_path: PathBuf,
        state_root: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let unit_dir = root.path().join("etc/systemd/system");
        std::fs::create_dir_all(&unit_dir).unwrap();
        Env {
            service_unit: unit_dir.join("kernel-hardening-watch.service"),
            path_unit: unit_dir.join("kernel-hardening-watch.path"),
            timer_unit: unit_dir.join("kernel-hardening-watch.timer"),
            sysctl_dropin: root.path().join("sysctl.conf"),
            modprobe_dropin: root.path().join("modprobe.conf"),
            binary_path: root.path().join("seshat"),
            state_root: root.path().join("var/lib/seshat"),
            _root: root,
            unit_dir,
        }
    }

    fn inputs<'a>(env: &'a Env, profile: &'a ProfileName) -> WatchInputs<'a> {
        WatchInputs {
            binary_path: &env.binary_path,
            profile,
            state_root: &env.state_root,
            unit_dir: &env.unit_dir,
            service_unit: &env.service_unit,
            path_unit: &env.path_unit,
            timer_unit: &env.timer_unit,
            sysctl_dropin: &env.sysctl_dropin,
            modprobe_dropin: &env.modprobe_dropin,
        }
    }

    #[test]
    fn remove_from_empty_state_returns_zero_removed_and_no_error() {
        let env = env();
        let prof = profile();
        let summary = remove_watch(&inputs(&env, &prof), |_, _| Ok(ok_output())).unwrap();
        assert_eq!(summary, RemoveSummary::default());
    }

    #[test]
    fn remove_from_fully_installed_state_removes_all_three() {
        let env = env();
        for p in [&env.service_unit, &env.path_unit, &env.timer_unit] {
            std::fs::write(p, "managed by seshat\n").unwrap();
        }
        let prof = profile();
        let summary = remove_watch(&inputs(&env, &prof), |_, _| Ok(ok_output())).unwrap();
        assert_eq!(
            summary,
            RemoveSummary {
                service_removed: true,
                path_removed: true,
                timer_removed: true
            }
        );
        for p in [&env.service_unit, &env.path_unit, &env.timer_unit] {
            assert!(!p.exists(), "leftover: {}", p.display());
        }
    }

    #[test]
    fn remove_tolerates_systemctl_disable_failure() {
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let prof = profile();
        let summary = remove_watch(&inputs(&env, &prof), |_, _| Ok(fail_output())).unwrap();
        assert!(summary.service_removed);
        assert!(!env.service_unit.exists());
    }

    #[test]
    fn remove_invokes_daemon_reload_after_file_deletion() {
        let env = env();
        std::fs::write(&env.path_unit, "x").unwrap();
        let calls: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let prof = profile();
        remove_watch(&inputs(&env, &prof), |_, args| {
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

    #[test]
    fn remove_surfaces_non_not_found_io_error() {
        use std::os::unix::fs::PermissionsExt;
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let parent = env.unit_dir.clone();
        let prev = std::fs::metadata(&parent).unwrap().permissions().mode();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o500)).unwrap();
        let prof = profile();
        let res = remove_watch(&inputs(&env, &prof), |_, _| Ok(ok_output()));
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(prev)).unwrap();
        assert!(matches!(res, Err(Error::Io(_))));
    }
}
