//! Install the drift-detector systemd units: service, path, timer.

use std::ffi::OsStr;
use std::path::Path;

use super::units::{generate_path_unit, generate_service_unit, generate_timer_unit};
use crate::atomic::install_root_file;
use crate::error::Error;
use crate::paths::{WATCH_UNIT_STEM, ensure_dir};
use crate::policy::ProfileName;
use crate::runtime::CommandOutput;

const UNIT_MODE: u32 = 0o644;

pub(crate) fn unit_name(suffix: &str) -> String {
    format!("{WATCH_UNIT_STEM}.{suffix}")
}

pub struct WatchInputs<'a> {
    pub binary_path: &'a Path,
    pub profile: &'a ProfileName,
    pub state_root: &'a Path,
    pub unit_dir: &'a Path,
    pub service_unit: &'a Path,
    pub path_unit: &'a Path,
    pub timer_unit: &'a Path,
    pub sysctl_dropin: &'a Path,
    pub modprobe_dropin: &'a Path,
}

pub fn install_watch<R>(inputs: &WatchInputs<'_>, mut runner: R) -> Result<(), Error>
where
    R: FnMut(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    ensure_dir(inputs.unit_dir)?;

    let service_body =
        generate_service_unit(inputs.binary_path, inputs.profile, inputs.state_root)?;
    let path_body = generate_path_unit(inputs.sysctl_dropin, inputs.modprobe_dropin)?;
    let timer_body = generate_timer_unit();

    install_root_file(inputs.service_unit, service_body.as_bytes(), UNIT_MODE)?;
    install_root_file(inputs.path_unit, path_body.as_bytes(), UNIT_MODE)?;
    install_root_file(inputs.timer_unit, timer_body.as_bytes(), UNIT_MODE)?;

    let path = unit_name("path");
    let timer = unit_name("timer");
    systemctl(&mut runner, &["daemon-reload"])?;
    systemctl(&mut runner, &["enable", "--now", &path])?;
    systemctl(&mut runner, &["enable", "--now", &timer])?;

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

    fn profile(name: &str) -> ProfileName {
        ProfileName::new(name).unwrap()
    }

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
        let sysctl = root.path().join("etc/sysctl.d/99-kernel-hardening.conf");
        let modprobe = root.path().join("etc/modprobe.d/99-kernel-hardening.conf");
        let state_root = root.path().join("var/lib/seshat");
        std::fs::create_dir_all(&unit_dir).unwrap();
        std::fs::create_dir_all(sysctl.parent().unwrap()).unwrap();
        std::fs::create_dir_all(modprobe.parent().unwrap()).unwrap();
        std::fs::create_dir_all(&state_root).unwrap();
        Env {
            service_unit: unit_dir.join("kernel-hardening-watch.service"),
            path_unit: unit_dir.join("kernel-hardening-watch.path"),
            timer_unit: unit_dir.join("kernel-hardening-watch.timer"),
            binary_path: root.path().join("usr/local/bin/seshat"),
            _root: root,
            unit_dir,
            sysctl_dropin: sysctl,
            modprobe_dropin: modprobe,
            state_root,
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
    fn install_writes_three_unit_files_and_runs_systemctl_in_order() {
        let env = env();
        let prof = profile("baseline");
        let calls: RefCell<Vec<Vec<String>>> = RefCell::new(Vec::new());

        install_watch(&inputs(&env, &prof), |program, args| {
            let mut rec = vec![program.to_string()];
            for a in args {
                rec.push(a.to_string_lossy().into_owned());
            }
            calls.borrow_mut().push(rec);
            Ok(ok_output())
        })
        .unwrap();

        assert!(env.service_unit.exists());
        assert!(env.path_unit.exists());
        assert!(env.timer_unit.exists());

        let recorded = calls.borrow();
        assert_eq!(recorded.len(), 3);
        assert_eq!(recorded[0], vec!["systemctl", "daemon-reload"]);
        assert_eq!(
            recorded[1],
            vec![
                "systemctl",
                "enable",
                "--now",
                "kernel-hardening-watch.path",
            ]
        );
        assert_eq!(
            recorded[2],
            vec![
                "systemctl",
                "enable",
                "--now",
                "kernel-hardening-watch.timer",
            ]
        );
    }

    #[test]
    fn install_writes_unit_files_at_mode_0o644() {
        use std::os::unix::fs::PermissionsExt;
        let env = env();
        let prof = profile("baseline");
        install_watch(&inputs(&env, &prof), |_, _| Ok(ok_output())).unwrap();
        for p in [&env.service_unit, &env.path_unit, &env.timer_unit] {
            let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "wrong mode on {}", p.display());
        }
    }

    #[test]
    fn install_is_idempotent_and_overwrites_stale_unit() {
        let env = env();
        let prof_a = profile("alpha");
        let prof_b = profile("beta");

        install_watch(&inputs(&env, &prof_a), |_, _| Ok(ok_output())).unwrap();
        let first = std::fs::read_to_string(&env.service_unit).unwrap();
        assert!(first.contains("--profile \"alpha\""));

        install_watch(&inputs(&env, &prof_b), |_, _| Ok(ok_output())).unwrap();
        let second = std::fs::read_to_string(&env.service_unit).unwrap();
        assert!(second.contains("--profile \"beta\""));
        assert!(!second.contains("--profile \"alpha\""));
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

        let sysctl = root.path().join("sysctl.conf");
        let modprobe = root.path().join("modprobe.conf");
        std::fs::write(&sysctl, "").unwrap();
        std::fs::write(&modprobe, "").unwrap();

        let prof = profile("baseline");
        let bin = root.path().join("seshat");
        let state_root = root.path().join("state");
        std::fs::create_dir_all(&state_root).unwrap();
        let inputs = WatchInputs {
            binary_path: &bin,
            profile: &prof,
            state_root: &state_root,
            unit_dir: &unit_dir,
            service_unit: &unit_dir.join("kernel-hardening-watch.service"),
            path_unit: &unit_dir.join("kernel-hardening-watch.path"),
            timer_unit: &unit_dir.join("kernel-hardening-watch.timer"),
            sysctl_dropin: &sysctl,
            modprobe_dropin: &modprobe,
        };

        let err = install_watch(&inputs, |_, _| Ok(ok_output())).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn install_aborts_when_daemon_reload_fails() {
        let env = env();
        let prof = profile("baseline");
        let err = install_watch(&inputs(&env, &prof), |_, args| {
            let first = args.first().and_then(|a| a.to_str()).unwrap_or("");
            if first == "daemon-reload" {
                Ok(fail_output(b"reload failed"))
            } else {
                Ok(ok_output())
            }
        })
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn install_aborts_when_enable_fails_for_timer() {
        let env = env();
        let prof = profile("baseline");
        let err = install_watch(&inputs(&env, &prof), |_, args| {
            let joined: Vec<String> = args
                .iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect();
            if joined.last().map(String::as_str) == Some("kernel-hardening-watch.timer") {
                Ok(fail_output(b"unit not found"))
            } else {
                Ok(ok_output())
            }
        })
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }
}
