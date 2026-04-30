use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::lock;

use super::OPERATION_LOCK_NAME;

pub const BOOT_ROLLBACK_REFUSED: &str =
    "boot rollback not implemented in this build; Milestone 2 covers GRUB rollback";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum RollbackDomain {
    All,
    Sysctl,
    Modules,
    Boot,
}

#[derive(Debug, PartialEq, Eq)]
pub struct RollbackOutcome {
    pub restored_from: Option<PathBuf>,
}

#[derive(Debug)]
pub struct RollbackReport {
    pub aborted: bool,
    pub sysctl: Option<Result<RollbackOutcome, Error>>,
    pub modules: Option<Result<RollbackOutcome, Error>>,
}

impl RollbackReport {
    pub fn exit_code(&self) -> i32 {
        if self.aborted {
            return 0;
        }
        let sysctl_code = self
            .sysctl
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .map(classify_rollback_error)
            .unwrap_or(0);
        let modules_code = self
            .modules
            .as_ref()
            .and_then(|r| r.as_ref().err())
            .map(classify_rollback_error)
            .unwrap_or(0);
        sysctl_code.max(modules_code)
    }
}

pub fn classify_rollback_error(err: &Error) -> i32 {
    match err {
        Error::UnsafePath { .. }
        | Error::PreflightRefused { .. }
        | Error::Lock { .. } => 3,
        _ => 1,
    }
}

pub struct RollbackInputs<'a> {
    pub domain: RollbackDomain,
    pub yes: bool,
    pub interactive: bool,
    pub lock_root: &'a Path,
}

pub fn orchestrate_rollback<F, R, M>(
    inputs: &RollbackInputs<'_>,
    confirm_prompt: F,
    restore_sysctl: R,
    restore_modules: M,
) -> Result<RollbackReport, Error>
where
    F: FnOnce() -> bool,
    R: FnOnce() -> Result<RollbackOutcome, Error>,
    M: FnOnce() -> Result<RollbackOutcome, Error>,
{
    // Interactive decline is a clean abort (exit 0), not a domain failure.
    if let Authorization::Declined = authorize(inputs, confirm_prompt)? {
        return Ok(RollbackReport {
            aborted: true,
            sysctl: None,
            modules: None,
        });
    }
    // Boot rollback is Milestone 2 territory: refuse before lock/restore.
    if matches!(inputs.domain, RollbackDomain::Boot) {
        return Err(Error::PreflightRefused {
            path: PathBuf::from("boot"),
            reason: BOOT_ROLLBACK_REFUSED.to_string(),
        });
    }
    let _guard = lock::acquire(inputs.lock_root, OPERATION_LOCK_NAME)?;
    pause_watcher();
    let report = dispatch(inputs.domain, restore_sysctl, restore_modules);
    resume_watcher();
    Ok(report)
}

enum Authorization {
    Authorized,
    Declined,
}

fn authorize<F>(inputs: &RollbackInputs<'_>, confirm_prompt: F) -> Result<Authorization, Error>
where
    F: FnOnce() -> bool,
{
    if inputs.yes {
        return Ok(Authorization::Authorized);
    }
    if !inputs.interactive {
        return Err(Error::Validation {
            field: "rollback".to_string(),
            reason: "noninteractive session: pass --yes to confirm".to_string(),
        });
    }
    if confirm_prompt() {
        Ok(Authorization::Authorized)
    } else {
        Ok(Authorization::Declined)
    }
}

fn dispatch<R, M>(domain: RollbackDomain, restore_sysctl: R, restore_modules: M) -> RollbackReport
where
    R: FnOnce() -> Result<RollbackOutcome, Error>,
    M: FnOnce() -> Result<RollbackOutcome, Error>,
{
    match domain {
        RollbackDomain::All => RollbackReport {
            aborted: false,
            sysctl: Some(restore_sysctl()),
            modules: Some(restore_modules()),
        },
        RollbackDomain::Sysctl => RollbackReport {
            aborted: false,
            sysctl: Some(restore_sysctl()),
            modules: None,
        },
        RollbackDomain::Modules => RollbackReport {
            aborted: false,
            sysctl: None,
            modules: Some(restore_modules()),
        },
        RollbackDomain::Boot => unreachable!("RollbackDomain::Boot is refused before dispatch"),
    }
}

// No-op until the watch milestone lands; kept so callers do not inline the contract.
fn pause_watcher() {}
fn resume_watcher() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    struct Env {
        _root: tempfile::TempDir,
        lock_root: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let lock_root = root.path().join("locks");
        fs::create_dir_all(&lock_root).unwrap();
        fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700)).unwrap();
        Env {
            _root: root,
            lock_root,
        }
    }

    fn inputs<'a>(
        env: &'a Env,
        domain: RollbackDomain,
        yes: bool,
        interactive: bool,
    ) -> RollbackInputs<'a> {
        RollbackInputs {
            domain,
            yes,
            interactive,
            lock_root: &env.lock_root,
        }
    }

    fn never_called() -> bool {
        panic!("confirm_prompt must not run in this scenario");
    }

    fn sysctl_ok() -> Result<RollbackOutcome, Error> {
        Ok(RollbackOutcome {
            restored_from: Some(PathBuf::from("/backups/sysctl/latest")),
        })
    }

    fn modules_ok() -> Result<RollbackOutcome, Error> {
        Ok(RollbackOutcome {
            restored_from: Some(PathBuf::from("/backups/modules/latest")),
        })
    }

    fn domain_err(field: &str) -> Result<RollbackOutcome, Error> {
        Err(Error::Validation {
            field: field.to_string(),
            reason: "fake".to_string(),
        })
    }

    #[test]
    fn yes_flag_skips_prompt_and_authorizes() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        )
        .unwrap();
        assert!(report.sysctl.is_some());
        assert!(report.modules.is_none());
    }

    #[test]
    fn noninteractive_without_yes_refuses() {
        let env = env();
        let err = orchestrate_rollback(
            &inputs(&env, RollbackDomain::All, false, false),
            never_called,
            sysctl_ok,
            modules_ok,
        )
        .unwrap_err();
        match err {
            Error::Validation { field, reason } => {
                assert_eq!(field, "rollback");
                assert!(reason.contains("noninteractive"));
                assert!(reason.contains("--yes"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn interactive_prompt_accept_authorizes() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, false, true),
            || true,
            sysctl_ok,
            modules_ok,
        )
        .unwrap();
        assert!(report.sysctl.is_some());
    }

    #[test]
    fn interactive_prompt_decline_is_clean_abort() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, false, true),
            || false,
            sysctl_ok,
            modules_ok,
        )
        .unwrap();
        assert!(report.aborted);
        assert!(report.sysctl.is_none());
        assert!(report.modules.is_none());
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn interactive_decline_does_not_invoke_restore_or_take_lock() {
        let env = env();
        // If decline reached lock acquisition, holder below would make this Err(Lock).
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::All, false, true),
            || false,
            || panic!("sysctl restore must not run when operator declines"),
            || panic!("modules restore must not run when operator declines"),
        )
        .unwrap();
        assert!(report.aborted);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn all_domain_dispatches_only_sysctl_and_modules_in_milestone_one() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::All, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        )
        .unwrap();
        assert!(report.sysctl.is_some());
        assert!(report.modules.is_some());
        assert!(report.sysctl.as_ref().unwrap().is_ok());
        assert!(report.modules.as_ref().unwrap().is_ok());
    }

    #[test]
    fn sysctl_domain_dispatches_only_sysctl() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        )
        .unwrap();
        assert!(report.sysctl.is_some());
        assert!(report.modules.is_none());
    }

    #[test]
    fn modules_domain_dispatches_only_modules() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Modules, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        )
        .unwrap();
        assert!(report.sysctl.is_none());
        assert!(report.modules.is_some());
    }

    #[test]
    fn boot_domain_refuses_with_preflight_and_exit_three() {
        let env = env();
        let result = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Boot, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        );
        let err = match result {
            Err(ref e @ Error::PreflightRefused { ref reason, .. }) => {
                assert_eq!(reason, BOOT_ROLLBACK_REFUSED);
                e
            }
            other => panic!("expected PreflightRefused, got {other:?}"),
        };
        assert_eq!(classify_rollback_error(err), 3);
    }

    #[test]
    fn boot_domain_refuses_before_taking_lock_or_running_restore() {
        let env = env();
        // Holder would turn a lock-acquiring path into Err(Lock); refusal must beat that.
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let result = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Boot, true, false),
            never_called,
            || panic!("sysctl restore must not run for boot refusal"),
            || panic!("modules restore must not run for boot refusal"),
        );
        assert!(matches!(result, Err(Error::PreflightRefused { .. })));
    }

    #[test]
    fn rollback_fails_when_lock_contended() {
        let env = env();
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let result = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        );
        assert!(matches!(result, Err(Error::Lock { .. })));
    }

    #[test]
    fn rollback_does_not_invoke_restore_when_lock_contended() {
        let env = env();
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let _ = orchestrate_rollback(
            &inputs(&env, RollbackDomain::All, true, false),
            never_called,
            || {
                panic!("sysctl restore must not run when lock is contended");
            },
            || {
                panic!("modules restore must not run when lock is contended");
            },
        );
    }

    #[test]
    fn exit_code_zero_when_restores_succeed() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::All, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        )
        .unwrap();
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn exit_code_one_when_domain_restore_errors() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, true, false),
            never_called,
            || domain_err("rollback.sysctl"),
            modules_ok,
        )
        .unwrap();
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn exit_code_three_when_unsafe_path_in_restore() {
        let env = env();
        let report = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, true, false),
            never_called,
            || {
                Err(Error::UnsafePath {
                    path: PathBuf::from("/x"),
                    reason: "symlink".to_string(),
                })
            },
            modules_ok,
        )
        .unwrap();
        assert_eq!(report.exit_code(), 3);
    }

    #[test]
    fn exit_code_three_on_top_level_lock_contention() {
        let env = env();
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let err = orchestrate_rollback(
            &inputs(&env, RollbackDomain::Sysctl, true, false),
            never_called,
            sysctl_ok,
            modules_ok,
        )
        .unwrap_err();
        assert_eq!(classify_rollback_error(&err), 3);
    }

    #[test]
    fn classify_rollback_error_maps_security_variants_to_three() {
        assert_eq!(
            classify_rollback_error(&Error::UnsafePath {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_rollback_error(&Error::Lock {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_rollback_error(&Error::Validation {
                field: "x".into(),
                reason: "".into(),
            }),
            1
        );
    }
}
