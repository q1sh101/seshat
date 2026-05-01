use std::ffi::OsStr;
use std::io;
use std::path::Path;

use crate::error::Error;
use crate::runtime::CommandOutput;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RefreshBackend {
    UpdateGrub,
    GrubMkconfig,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RefreshStatus {
    Applied {
        backend: RefreshBackend,
    },
    Unavailable,
    Failed {
        backend: RefreshBackend,
        reason: String,
    },
}

impl RefreshStatus {
    // Any successful refresh rewrites /boot/grub/grub.cfg; the kernel still runs the old cmdline until reboot.
    pub fn reboot_required(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

// §16.7: update-grub preferred; fall back to grub-mkconfig -o <grub.cfg>; neither present = Unavailable.
pub fn refresh_grub_configuration<H, R>(
    grub_cfg_path: &Path,
    has_command: H,
    runner: R,
) -> RefreshStatus
where
    H: Fn(&str) -> bool,
    R: FnOnce(&str, Vec<&OsStr>) -> Result<CommandOutput, Error>,
{
    if has_command("update-grub") {
        classify(
            RefreshBackend::UpdateGrub,
            runner("update-grub", Vec::new()),
        )
    } else if has_command("grub-mkconfig") {
        let args = vec![OsStr::new("-o"), grub_cfg_path.as_os_str()];
        classify(RefreshBackend::GrubMkconfig, runner("grub-mkconfig", args))
    } else {
        RefreshStatus::Unavailable
    }
}

fn classify(backend: RefreshBackend, result: Result<CommandOutput, Error>) -> RefreshStatus {
    match result {
        Ok(output) if output.success() => RefreshStatus::Applied { backend },
        Ok(output) => RefreshStatus::Failed {
            backend,
            reason: output.stderr_summary(),
        },
        // Race: has_command probed present, then exec saw NotFound between probe and spawn.
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => RefreshStatus::Unavailable,
        Err(e) => RefreshStatus::Failed {
            backend,
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn cmd(exit: Option<i32>, stderr: &[u8]) -> CommandOutput {
        CommandOutput {
            exit_code: exit,
            stdout: vec![],
            stderr: stderr.to_vec(),
        }
    }

    fn never_runs(_: &str, _: Vec<&OsStr>) -> Result<CommandOutput, Error> {
        panic!("runner must not be invoked when no backend is available");
    }

    #[test]
    fn unavailable_when_neither_command_present() {
        let out =
            refresh_grub_configuration(Path::new("/boot/grub/grub.cfg"), |_| false, never_runs);
        assert_eq!(out, RefreshStatus::Unavailable);
    }

    #[test]
    fn prefers_update_grub_when_both_present() {
        let picked = std::cell::Cell::new(None);
        let runner = |program: &str, _: Vec<&OsStr>| {
            picked.set(Some(program.to_string()));
            Ok(cmd(Some(0), b""))
        };
        let _ = refresh_grub_configuration(Path::new("/boot/grub/grub.cfg"), |_| true, runner);
        assert_eq!(picked.take().as_deref(), Some("update-grub"));
    }

    #[test]
    fn falls_back_to_grub_mkconfig_when_update_grub_absent() {
        let picked = std::cell::Cell::new(None);
        let runner = |program: &str, _: Vec<&OsStr>| {
            picked.set(Some(program.to_string()));
            Ok(cmd(Some(0), b""))
        };
        let _ = refresh_grub_configuration(
            Path::new("/boot/grub/grub.cfg"),
            |name| name == "grub-mkconfig",
            runner,
        );
        assert_eq!(picked.take().as_deref(), Some("grub-mkconfig"));
    }

    #[test]
    fn grub_mkconfig_receives_cfg_path_after_minus_o_flag() {
        let captured: std::cell::RefCell<Vec<String>> = std::cell::RefCell::new(Vec::new());
        let runner = |program: &str, args: Vec<&OsStr>| {
            let all: Vec<String> = std::iter::once(program.to_string())
                .chain(args.iter().map(|a| a.to_string_lossy().into_owned()))
                .collect();
            *captured.borrow_mut() = all;
            Ok(cmd(Some(0), b""))
        };
        let cfg = PathBuf::from("/boot/grub/grub.cfg");
        let _ = refresh_grub_configuration(&cfg, |name| name == "grub-mkconfig", runner);
        let argv = captured.borrow();
        assert_eq!(
            &argv[..],
            &["grub-mkconfig", "-o", "/boot/grub/grub.cfg"][..]
        );
    }

    #[test]
    fn classify_zero_exit_maps_to_applied_with_backend() {
        let status = classify(RefreshBackend::UpdateGrub, Ok(cmd(Some(0), b"")));
        assert_eq!(
            status,
            RefreshStatus::Applied {
                backend: RefreshBackend::UpdateGrub
            }
        );
    }

    #[test]
    fn classify_nonzero_exit_maps_to_failed_with_stderr_reason() {
        let status = classify(
            RefreshBackend::UpdateGrub,
            Ok(cmd(Some(1), b"permission denied")),
        );
        match status {
            RefreshStatus::Failed { backend, reason } => {
                assert_eq!(backend, RefreshBackend::UpdateGrub);
                assert_eq!(reason, "permission denied");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }

    #[test]
    fn classify_signal_termination_maps_to_failed() {
        let status = classify(RefreshBackend::GrubMkconfig, Ok(cmd(None, b"")));
        assert!(matches!(status, RefreshStatus::Failed { .. }));
    }

    #[test]
    fn classify_not_found_error_maps_to_unavailable() {
        let err = Error::Io(io::Error::from(io::ErrorKind::NotFound));
        let status = classify(RefreshBackend::UpdateGrub, Err(err));
        assert_eq!(status, RefreshStatus::Unavailable);
    }

    #[test]
    fn classify_other_io_error_maps_to_failed() {
        let err = Error::Io(io::Error::from(io::ErrorKind::PermissionDenied));
        let status = classify(RefreshBackend::UpdateGrub, Err(err));
        assert!(matches!(status, RefreshStatus::Failed { .. }));
    }

    #[test]
    fn reboot_required_is_true_only_on_applied() {
        assert!(
            RefreshStatus::Applied {
                backend: RefreshBackend::UpdateGrub,
            }
            .reboot_required()
        );
    }

    #[test]
    fn reboot_required_is_false_on_unavailable() {
        assert!(!RefreshStatus::Unavailable.reboot_required());
    }

    #[test]
    fn reboot_required_is_false_on_failed() {
        assert!(
            !RefreshStatus::Failed {
                backend: RefreshBackend::GrubMkconfig,
                reason: "boom".to_string(),
            }
            .reboot_required()
        );
    }
}
