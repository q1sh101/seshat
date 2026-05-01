use std::path::Path;

use crate::error::Error;
use crate::modules::{ModulesLockOutcome, lock_modules_runtime, read_modules_lock_state};

pub struct LockInputs<'a> {
    pub proc_file: &'a Path,
    pub yes: bool,
    pub interactive: bool,
}

#[derive(Debug)]
pub enum LockReport {
    Aborted,
    Completed(Result<ModulesLockOutcome, Error>),
}

pub fn classify_lock_error(err: &Error) -> i32 {
    match err {
        Error::UnsafePath { .. }
        | Error::PreflightRefused { .. }
        | Error::Lock { .. } => 3,
        _ => 1,
    }
}

pub fn orchestrate_lock<C, E>(
    inputs: &LockInputs<'_>,
    confirm_prompt: C,
    is_root: E,
) -> Result<LockReport, Error>
where
    C: FnOnce() -> bool,
    E: FnOnce() -> bool,
{
    // Read state first: already-locked path needs no prompt, no root, no write.
    if read_modules_lock_state(inputs.proc_file)? {
        return Ok(LockReport::Completed(Ok(ModulesLockOutcome::AlreadyLocked)));
    }

    // Interactive decline is a clean abort (exit 0), not a domain failure.
    if let Authorization::Declined = authorize(inputs, confirm_prompt)? {
        return Ok(LockReport::Aborted);
    }

    // Write path requires euid 0; refuse with a sudo hint before the kernel does.
    if !is_root() {
        return Err(Error::PreflightRefused {
            path: inputs.proc_file.to_path_buf(),
            reason: "runtime module lock requires root; try: sudo seshat lock".to_string(),
        });
    }

    Ok(LockReport::Completed(lock_modules_runtime(
        inputs.proc_file,
    )))
}

enum Authorization {
    Authorized,
    Declined,
}

fn authorize<C>(inputs: &LockInputs<'_>, confirm_prompt: C) -> Result<Authorization, Error>
where
    C: FnOnce() -> bool,
{
    if inputs.yes {
        return Ok(Authorization::Authorized);
    }
    if !inputs.interactive {
        return Err(Error::Validation {
            field: "lock".to_string(),
            reason: "noninteractive session: pass --yes to confirm".to_string(),
        });
    }
    if confirm_prompt() {
        Ok(Authorization::Authorized)
    } else {
        Ok(Authorization::Declined)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use tempfile::tempdir;

    struct Env {
        _root: tempfile::TempDir,
        proc_file: PathBuf,
    }

    fn env_with(body: &str) -> Env {
        let dir = tempdir().unwrap();
        let proc_file = dir.path().join("modules_disabled");
        fs::write(&proc_file, body).unwrap();
        Env {
            _root: dir,
            proc_file,
        }
    }

    fn inputs<'a>(env: &'a Env, yes: bool, interactive: bool) -> LockInputs<'a> {
        LockInputs {
            proc_file: &env.proc_file,
            yes,
            interactive,
        }
    }

    fn never_prompt() -> bool {
        panic!("confirm_prompt must not run in this scenario");
    }

    fn never_root() -> bool {
        panic!("is_root probe must not run in this scenario");
    }

    fn as_root() -> bool {
        true
    }

    fn not_root() -> bool {
        false
    }

    #[test]
    fn yes_writes_when_state_is_zero_and_running_as_root() {
        let env = env_with("0\n");
        let report = orchestrate_lock(&inputs(&env, true, false), never_prompt, as_root).unwrap();
        assert!(matches!(
            report,
            LockReport::Completed(Ok(ModulesLockOutcome::LockedNow))
        ));
        assert_eq!(fs::read_to_string(&env.proc_file).unwrap().trim(), "1");
    }

    #[test]
    fn already_locked_short_circuits_before_prompt_and_root_probe() {
        // yes=false + interactive=true would normally prompt; never_prompt/never_root
        // panic if invoked. AlreadyLocked path must return before either runs.
        let env = env_with("1\n");
        let report =
            orchestrate_lock(&inputs(&env, false, true), never_prompt, never_root).unwrap();
        assert!(matches!(
            report,
            LockReport::Completed(Ok(ModulesLockOutcome::AlreadyLocked))
        ));
        assert_eq!(fs::read_to_string(&env.proc_file).unwrap().trim(), "1");
    }

    #[test]
    fn already_locked_noninteractive_without_yes_still_returns_alreadylocked() {
        let env = env_with("1\n");
        let report =
            orchestrate_lock(&inputs(&env, false, false), never_prompt, never_root).unwrap();
        assert!(matches!(
            report,
            LockReport::Completed(Ok(ModulesLockOutcome::AlreadyLocked))
        ));
    }

    #[test]
    fn unlocked_noninteractive_without_yes_refuses_with_validation_and_no_write() {
        let env = env_with("0\n");
        let err =
            orchestrate_lock(&inputs(&env, false, false), never_prompt, never_root).unwrap_err();
        match err {
            Error::Validation { field, reason } => {
                assert_eq!(field, "lock");
                assert!(reason.contains("noninteractive"));
                assert!(reason.contains("--yes"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&env.proc_file).unwrap().trim(), "0");
    }

    #[test]
    fn interactive_decline_is_clean_abort_and_no_write() {
        let env = env_with("0\n");
        let report = orchestrate_lock(&inputs(&env, false, true), || false, never_root).unwrap();
        assert!(matches!(report, LockReport::Aborted));
        assert_eq!(fs::read_to_string(&env.proc_file).unwrap().trim(), "0");
    }

    #[test]
    fn interactive_accept_writes_when_state_is_zero_and_running_as_root() {
        let env = env_with("0\n");
        let report = orchestrate_lock(&inputs(&env, false, true), || true, as_root).unwrap();
        assert!(matches!(
            report,
            LockReport::Completed(Ok(ModulesLockOutcome::LockedNow))
        ));
        assert_eq!(fs::read_to_string(&env.proc_file).unwrap().trim(), "1");
    }

    #[test]
    fn non_root_refuses_with_preflight_before_mutation() {
        let env = env_with("0\n");
        let err = orchestrate_lock(&inputs(&env, true, false), never_prompt, not_root).unwrap_err();
        match err {
            Error::PreflightRefused { path, reason } => {
                assert_eq!(path, env.proc_file);
                assert!(reason.contains("root"));
                assert!(reason.contains("sudo"));
            }
            other => panic!("expected PreflightRefused, got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&env.proc_file).unwrap().trim(), "0");
    }

    #[test]
    fn symlink_proc_file_returns_unsafepath_before_prompt_or_root_check() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "0\n").unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let lock_inputs = LockInputs {
            proc_file: &link,
            yes: false,
            interactive: true,
        };
        let err = orchestrate_lock(&lock_inputs, never_prompt, never_root).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert_eq!(fs::read_to_string(&real).unwrap().trim(), "0");
    }

    #[test]
    fn classify_lock_error_maps_security_variants_to_three() {
        assert_eq!(
            classify_lock_error(&Error::UnsafePath {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_lock_error(&Error::PreflightRefused {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_lock_error(&Error::Lock {
                path: PathBuf::from("/x"),
                reason: "".into(),
            }),
            3
        );
        assert_eq!(
            classify_lock_error(&Error::Validation {
                field: "x".into(),
                reason: "".into(),
            }),
            1
        );
    }
}
