use std::fs;
use std::path::Path;

use crate::error::Error;

#[derive(Debug, PartialEq, Eq)]
pub enum ModulesLockOutcome {
    LockedNow,
    AlreadyLocked,
}

pub fn lock_modules_runtime(proc_file: &Path) -> Result<ModulesLockOutcome, Error> {
    preflight_symlink(proc_file)?;

    if read_flag(proc_file)? {
        return Ok(ModulesLockOutcome::AlreadyLocked);
    }

    fs::write(proc_file, "1\n")?;

    // Post-write verify: kernel may accept the write syscall but reject the value.
    if !read_flag(proc_file)? {
        return Err(Error::Validation {
            field: "modules.runtime_lock".to_string(),
            reason: format!(
                "write succeeded but {} still reports unlocked",
                proc_file.display()
            ),
        });
    }

    Ok(ModulesLockOutcome::LockedNow)
}

pub fn read_modules_lock_state(proc_file: &Path) -> Result<bool, Error> {
    preflight_symlink(proc_file)?;
    read_flag(proc_file)
}

fn preflight_symlink(proc_file: &Path) -> Result<(), Error> {
    // symlink_metadata does not follow; a symlinked proc entry could redirect a privileged write.
    let meta = fs::symlink_metadata(proc_file)?;
    if meta.file_type().is_symlink() {
        return Err(Error::UnsafePath {
            path: proc_file.to_path_buf(),
            reason: "runtime module lock target is a symlink".to_string(),
        });
    }
    Ok(())
}

fn read_flag(path: &Path) -> Result<bool, Error> {
    let raw = fs::read_to_string(path)?;
    match raw.trim() {
        "0" => Ok(false),
        "1" => Ok(true),
        other => Err(Error::Validation {
            field: "modules.runtime_lock".to_string(),
            reason: format!("unexpected value at {}: {:?}", path.display(), other),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use tempfile::tempdir;

    fn proc_file(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("modules_disabled");
        fs::write(&path, body).unwrap();
        (dir, path)
    }

    #[test]
    fn lock_flips_zero_to_one_and_reports_locked_now() {
        let (_d, path) = proc_file("0\n");
        let outcome = lock_modules_runtime(&path).unwrap();
        assert_eq!(outcome, ModulesLockOutcome::LockedNow);
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "1");
    }

    #[test]
    fn lock_is_idempotent_when_already_one() {
        let (_d, path) = proc_file("1\n");
        let outcome = lock_modules_runtime(&path).unwrap();
        assert_eq!(outcome, ModulesLockOutcome::AlreadyLocked);
        assert_eq!(fs::read_to_string(&path).unwrap().trim(), "1");
    }

    #[test]
    fn lock_accepts_value_without_trailing_newline() {
        let (_d, path) = proc_file("0");
        let outcome = lock_modules_runtime(&path).unwrap();
        assert_eq!(outcome, ModulesLockOutcome::LockedNow);
    }

    #[test]
    fn lock_idempotent_accepts_value_without_trailing_newline() {
        let (_d, path) = proc_file("1");
        let outcome = lock_modules_runtime(&path).unwrap();
        assert_eq!(outcome, ModulesLockOutcome::AlreadyLocked);
    }

    #[test]
    fn lock_tolerates_surrounding_whitespace_in_kernel_output() {
        let (_d, path) = proc_file("  1  \n");
        let outcome = lock_modules_runtime(&path).unwrap();
        assert_eq!(outcome, ModulesLockOutcome::AlreadyLocked);
    }

    #[test]
    fn lock_errors_when_proc_file_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("never_created");
        let err = lock_modules_runtime(&path).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn lock_rejects_when_proc_file_is_symlink() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "0\n").unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let err = lock_modules_runtime(&link).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
        assert_eq!(fs::read_to_string(&real).unwrap().trim(), "0");
    }

    #[test]
    fn lock_errors_when_value_is_neither_zero_nor_one() {
        let (_d, path) = proc_file("2\n");
        let err = lock_modules_runtime(&path).unwrap_err();
        match err {
            Error::Validation { field, reason } => {
                assert_eq!(field, "modules.runtime_lock");
                assert!(reason.contains("unexpected value"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn lock_errors_when_value_is_empty() {
        let (_d, path) = proc_file("");
        let err = lock_modules_runtime(&path).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn lock_errors_when_value_is_non_numeric_garbage() {
        let (_d, path) = proc_file("enabled\n");
        let err = lock_modules_runtime(&path).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn lock_does_not_write_when_already_locked() {
        let (_d, path) = proc_file("1\n");
        let before = fs::metadata(&path).unwrap().modified().unwrap();
        // Spin briefly so a real write would produce a measurable mtime bump.
        std::thread::sleep(std::time::Duration::from_millis(10));
        lock_modules_runtime(&path).unwrap();
        let after = fs::metadata(&path).unwrap().modified().unwrap();
        assert_eq!(before, after, "already-locked path must not touch the file");
    }

    #[test]
    fn lock_does_not_write_when_preflight_rejects_symlink() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "0\n").unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let _ = lock_modules_runtime(&link).unwrap_err();
        assert_eq!(fs::read_to_string(&real).unwrap().trim(), "0");
    }

    #[test]
    fn read_state_reports_locked_for_one() {
        let (_d, path) = proc_file("1\n");
        assert!(read_modules_lock_state(&path).unwrap());
    }

    #[test]
    fn read_state_reports_unlocked_for_zero() {
        let (_d, path) = proc_file("0\n");
        assert!(!read_modules_lock_state(&path).unwrap());
    }

    #[test]
    fn read_state_rejects_symlink() {
        let dir = tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "1\n").unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let err = read_modules_lock_state(&link).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn read_state_errors_on_unexpected_value() {
        let (_d, path) = proc_file("2\n");
        let err = read_modules_lock_state(&path).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }
}
