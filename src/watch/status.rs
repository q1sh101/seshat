//! Query installed-state and live-state of the drift-detector units.

use std::ffi::OsStr;

use super::install::{WatchInputs, unit_name};
use crate::error::Error;
use crate::runtime::CommandOutput;

#[derive(Debug, PartialEq, Eq)]
pub struct WatchStatus {
    pub service_installed: bool,
    pub path_installed: bool,
    pub path_active: bool,
    pub timer_installed: bool,
    pub timer_active: bool,
    pub next_elapse: Option<String>,
    pub journal_tail: Vec<String>,
}

pub fn query_watch_status<R>(inputs: &WatchInputs<'_>, mut runner: R) -> WatchStatus
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let service_installed = inputs.service_unit.exists();
    let path_installed = inputs.path_unit.exists();
    let timer_installed = inputs.timer_unit.exists();

    let path_active = is_active(&mut runner, &unit_name("path"));
    let timer_active = is_active(&mut runner, &unit_name("timer"));

    let next_elapse = if timer_installed {
        query_next_elapse(&mut runner, &unit_name("timer"))
    } else {
        None
    };

    let journal_tail = if service_installed {
        query_journal_tail(&mut runner, &unit_name("service"), 5)
    } else {
        Vec::new()
    };

    WatchStatus {
        service_installed,
        path_installed,
        path_active,
        timer_installed,
        timer_active,
        next_elapse,
        journal_tail,
    }
}

fn is_active<R>(runner: &mut R, unit: &str) -> bool
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let argv: Vec<&OsStr> = [OsStr::new("is-active"), OsStr::new(unit)].into();
    match runner("systemctl", argv) {
        Ok(out) => out.success(),
        Err(_) => false,
    }
}

fn query_next_elapse<R>(runner: &mut R, unit: &str) -> Option<String>
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let argv: Vec<&OsStr> = [
        OsStr::new("show"),
        OsStr::new(unit),
        OsStr::new("--property=NextElapseUSecRealtime"),
    ]
    .into();
    let out = runner("systemctl", argv).ok()?;
    if !out.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let value = text.trim().strip_prefix("NextElapseUSecRealtime=")?;
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn query_journal_tail<R>(runner: &mut R, unit: &str, lines: u32) -> Vec<String>
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    let n = lines.to_string();
    let argv: Vec<&OsStr> = [
        OsStr::new("-u"),
        OsStr::new(unit),
        OsStr::new("-n"),
        OsStr::new(&n),
        OsStr::new("--no-pager"),
    ]
    .into();
    let out = match runner("journalctl", argv) {
        Ok(o) if o.success() => o,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with("-- No entries"))
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ProfileName;
    use std::io;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn profile() -> ProfileName {
        ProfileName::new("baseline").unwrap()
    }

    fn ok(stdout: &[u8]) -> CommandOutput {
        CommandOutput {
            exit_code: Some(0),
            stdout: stdout.to_vec(),
            stderr: vec![],
        }
    }

    fn inactive() -> CommandOutput {
        CommandOutput {
            exit_code: Some(3),
            stdout: b"inactive\n".to_vec(),
            stderr: vec![],
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
    fn status_reports_all_absent_before_install() {
        let env = env();
        let prof = profile();
        let status = query_watch_status(&inputs(&env, &prof), |_, _| Ok(inactive()));
        assert!(!status.service_installed);
        assert!(!status.path_installed);
        assert!(!status.timer_installed);
        assert!(!status.path_active);
        assert!(!status.timer_active);
        assert!(status.next_elapse.is_none());
        assert!(status.journal_tail.is_empty());
    }

    #[test]
    fn status_reports_installed_and_active_after_install() {
        let env = env();
        for p in [&env.service_unit, &env.path_unit, &env.timer_unit] {
            std::fs::write(p, "x").unwrap();
        }
        let prof = profile();
        let status = query_watch_status(&inputs(&env, &prof), |program, args| {
            match (
            program,
            args.first().and_then(|a| a.to_str()),
        ) {
            ("systemctl", Some("is-active")) => Ok(ok(b"active\n")),
            ("systemctl", Some("show")) => Ok(ok(b"NextElapseUSecRealtime=Tue 2026-04-20 01:30:00 UTC\n")),
            ("journalctl", _) => Ok(ok(b"Apr 20 01:00:00 host seshat[1234]: verify sysctl: OK\nApr 20 01:01:00 host seshat[1235]: verify modules: OK\n")),
            _ => Ok(inactive()),
        }
        });
        assert!(status.service_installed);
        assert!(status.path_installed);
        assert!(status.timer_installed);
        assert!(status.path_active);
        assert!(status.timer_active);
        assert_eq!(
            status.next_elapse.as_deref(),
            Some("Tue 2026-04-20 01:30:00 UTC")
        );
        assert_eq!(status.journal_tail.len(), 2);
    }

    #[test]
    fn status_with_missing_journalctl_reports_empty_tail_not_error() {
        let env = env();
        std::fs::write(&env.service_unit, "x").unwrap();
        let prof = profile();
        let status = query_watch_status(&inputs(&env, &prof), |program, _| {
            if program == "journalctl" {
                Err(Error::Io(io::Error::from(io::ErrorKind::NotFound)))
            } else {
                Ok(inactive())
            }
        });
        assert!(status.journal_tail.is_empty());
        assert!(status.service_installed);
    }

    #[test]
    fn status_skips_next_elapse_and_journal_when_units_absent() {
        use std::cell::RefCell;
        let env = env();
        let prof = profile();
        let programs: RefCell<Vec<String>> = RefCell::new(Vec::new());
        query_watch_status(&inputs(&env, &prof), |program, args| {
            programs.borrow_mut().push(format!(
                "{} {}",
                program,
                args.iter()
                    .map(|a| a.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" "),
            ));
            Ok(inactive())
        });
        let called = programs.borrow();
        assert!(
            called.iter().all(|c| c.starts_with("systemctl is-active")),
            "only is-active is permitted when units absent, got: {called:?}"
        );
        assert_eq!(called.len(), 2);
    }
}
