
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::Error;

const LOCK_DIR_MODE: u32 = 0o700;

#[derive(Debug)]
pub struct LockGuard {
    _file: File,
}

fn parse_uid_from_status(text: &str) -> Result<u32, Error> {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Uid:")
            && let Some(tok) = rest.split_whitespace().next()
        {
            return tok.parse::<u32>().map_err(|_| Error::Validation {
                field: "/proc/self/status".to_string(),
                reason: format!("unparseable Uid line: {line}"),
            });
        }
    }
    Err(Error::Validation {
        field: "/proc/self/status".to_string(),
        reason: "missing Uid line".to_string(),
    })
}

// `/proc/self/status` stands in for `libc::getuid` because the crate forbids `unsafe_code`.
pub(crate) fn current_uid() -> Result<u32, Error> {
    parse_uid_from_status(&fs::read_to_string("/proc/self/status")?)
}

fn sudo_uid() -> Option<u32> {
    std::env::var("SUDO_UID").ok()?.parse().ok()
}

fn uid_is_acceptable(file_uid: u32, current: u32, sudo: Option<u32>) -> bool {
    if file_uid == 0 || file_uid == current {
        return true;
    }
    matches!(sudo, Some(s) if s == file_uid)
}

fn validate_lock_root(lock_root: &Path) -> Result<(), Error> {
    let metadata = fs::symlink_metadata(lock_root).map_err(|e| Error::Lock {
        path: lock_root.to_path_buf(),
        reason: format!("cannot stat lock root: {e}"),
    })?;
    let ft = metadata.file_type();
    if ft.is_symlink() {
        return Err(Error::Lock {
            path: lock_root.to_path_buf(),
            reason: "lock root is a symlink".to_string(),
        });
    }
    if !ft.is_dir() {
        return Err(Error::Lock {
            path: lock_root.to_path_buf(),
            reason: "lock root is not a directory".to_string(),
        });
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != LOCK_DIR_MODE {
        return Err(Error::Lock {
            path: lock_root.to_path_buf(),
            reason: format!("lock root mode must be {LOCK_DIR_MODE:o}, got {mode:o}"),
        });
    }
    let current = current_uid()?;
    if !uid_is_acceptable(metadata.uid(), current, sudo_uid()) {
        return Err(Error::Lock {
            path: lock_root.to_path_buf(),
            reason: format!(
                "lock root owner uid {} is not current/sudo/root",
                metadata.uid()
            ),
        });
    }
    Ok(())
}

// Enforced BEFORE join() so `../x` or `/tmp/x` cannot escape the lock root.
fn validate_lock_name(name: &str) -> Result<(), Error> {
    let reason = if name.is_empty() {
        Some("lock name is empty")
    } else if name == "." || name == ".." {
        Some("lock name must not be '.' or '..'")
    } else if name.contains('/') || name.contains('\\') {
        Some("lock name must not contain path separators")
    } else if Path::new(name).is_absolute() {
        Some("lock name must not be an absolute path")
    } else {
        None
    };
    match reason {
        Some(r) => Err(Error::Lock {
            path: PathBuf::from(name),
            reason: r.to_string(),
        }),
        None => Ok(()),
    }
}

// Reject non-regular existing lock files: opening a FIFO could block.
fn validate_lock_file(lock_path: &Path) -> Result<(), Error> {
    match fs::symlink_metadata(lock_path) {
        Ok(m) => {
            let ft = m.file_type();
            if ft.is_symlink() {
                return Err(Error::Lock {
                    path: lock_path.to_path_buf(),
                    reason: "lock file is a symlink".to_string(),
                });
            }
            if !ft.is_file() {
                return Err(Error::Lock {
                    path: lock_path.to_path_buf(),
                    reason: "lock file exists and is not a regular file".to_string(),
                });
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(Error::Lock {
            path: lock_path.to_path_buf(),
            reason: format!("cannot stat lock file: {e}"),
        }),
    }
}

pub fn acquire(lock_root: &Path, name: &str) -> Result<LockGuard, Error> {
    validate_lock_name(name)?;
    validate_lock_root(lock_root)?;
    let lock_path = lock_root.join(name);
    validate_lock_file(&lock_path)?;

    // create_new on first use gives racing operators a fresh inode to lock on.
    let file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            OpenOptions::new().write(true).open(&lock_path)?
        }
        Err(e) => return Err(e.into()),
    };

    match file.try_lock() {
        Ok(()) => Ok(LockGuard { _file: file }),
        Err(TryLockError::WouldBlock) => Err(Error::Lock {
            path: lock_path,
            reason: "another seshat operation is in progress".to_string(),
        }),
        Err(TryLockError::Error(e)) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn fresh_lock_root() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        // Force 0o700: tempdir's default mode varies by platform.
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(LOCK_DIR_MODE)).unwrap();
        dir
    }

    #[test]
    fn uid_matches_current_is_accepted() {
        assert!(uid_is_acceptable(1000, 1000, None));
    }

    #[test]
    fn uid_zero_root_is_accepted() {
        assert!(uid_is_acceptable(0, 1000, None));
    }

    #[test]
    fn uid_matches_sudo_is_accepted() {
        assert!(uid_is_acceptable(1000, 0, Some(1000)));
    }

    #[test]
    fn uid_unrelated_is_rejected() {
        assert!(!uid_is_acceptable(2000, 1000, None));
        assert!(!uid_is_acceptable(2000, 1000, Some(1500)));
    }

    #[test]
    fn validate_lock_root_accepts_proper_directory() {
        let dir = fresh_lock_root();
        validate_lock_root(dir.path()).unwrap();
    }

    #[test]
    fn validate_lock_root_rejects_wrong_mode() {
        let dir = fresh_lock_root();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let err = validate_lock_root(dir.path()).unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn validate_lock_root_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let real = fresh_lock_root();
        let parent = tempdir().unwrap();
        let link = parent.path().join("locks");
        symlink(real.path(), &link).unwrap();
        let err = validate_lock_root(&link).unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn validate_lock_root_rejects_non_directory() {
        let dir = tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        fs::write(&file, b"").unwrap();
        fs::set_permissions(&file, fs::Permissions::from_mode(LOCK_DIR_MODE)).unwrap();
        let err = validate_lock_root(&file).unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn acquire_creates_lock_file_on_first_use() {
        let dir = fresh_lock_root();
        let _guard = acquire(dir.path(), "deploy").unwrap();
        assert!(dir.path().join("deploy").exists());
    }

    #[test]
    fn acquire_fails_fast_when_another_holder_has_the_lock() {
        let dir = fresh_lock_root();
        let _g1 = acquire(dir.path(), "deploy").unwrap();
        let err = acquire(dir.path(), "deploy").unwrap_err();
        match err {
            Error::Lock { reason, .. } => {
                assert!(reason.contains("another seshat operation"));
            }
            other => panic!("expected Error::Lock, got {other:?}"),
        }
    }

    #[test]
    fn dropping_guard_releases_lock() {
        let dir = fresh_lock_root();
        {
            let _g1 = acquire(dir.path(), "deploy").unwrap();
        }
        let _g2 = acquire(dir.path(), "deploy").unwrap();
    }

    #[test]
    fn acquire_independent_names_do_not_contend() {
        let dir = fresh_lock_root();
        let _g1 = acquire(dir.path(), "deploy").unwrap();
        let _g2 = acquire(dir.path(), "rollback").unwrap();
    }

    #[test]
    fn acquire_rejects_symlinked_lock_file() {
        use std::os::unix::fs::symlink;
        let dir = fresh_lock_root();
        let real = tempdir().unwrap();
        let real_file = real.path().join("real.lock");
        fs::write(&real_file, b"").unwrap();
        symlink(&real_file, dir.path().join("deploy")).unwrap();

        let err = acquire(dir.path(), "deploy").unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn parse_uid_extracts_effective_uid_from_normal_line() {
        let status = "Name:\tseshat\nUid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_uid_from_status(status).unwrap(), 1000);
    }

    #[test]
    fn parse_uid_returns_validation_when_uid_line_missing() {
        let err = parse_uid_from_status("Name:\tseshat\n").unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn parse_uid_returns_validation_when_token_is_unparseable() {
        let err = parse_uid_from_status("Uid:\txyz\n").unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn parse_uid_returns_validation_on_empty_text() {
        let err = parse_uid_from_status("").unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn validate_lock_name_rejects_empty() {
        assert!(matches!(
            validate_lock_name("").unwrap_err(),
            Error::Lock { .. }
        ));
    }

    #[test]
    fn validate_lock_name_rejects_dot_and_dotdot() {
        assert!(matches!(
            validate_lock_name(".").unwrap_err(),
            Error::Lock { .. }
        ));
        assert!(matches!(
            validate_lock_name("..").unwrap_err(),
            Error::Lock { .. }
        ));
    }

    #[test]
    fn validate_lock_name_rejects_parent_traversal() {
        assert!(matches!(
            validate_lock_name("../deploy").unwrap_err(),
            Error::Lock { .. }
        ));
    }

    #[test]
    fn validate_lock_name_rejects_absolute_path() {
        assert!(matches!(
            validate_lock_name("/tmp/deploy").unwrap_err(),
            Error::Lock { .. }
        ));
    }

    #[test]
    fn validate_lock_name_rejects_nested_subpath() {
        assert!(matches!(
            validate_lock_name("sub/lock").unwrap_err(),
            Error::Lock { .. }
        ));
    }

    #[test]
    fn validate_lock_name_rejects_backslash() {
        assert!(matches!(
            validate_lock_name("foo\\bar").unwrap_err(),
            Error::Lock { .. }
        ));
    }

    #[test]
    fn validate_lock_name_accepts_plain_filename() {
        validate_lock_name("deploy").unwrap();
        validate_lock_name("rollback").unwrap();
        validate_lock_name("deploy.lock").unwrap();
    }

    #[test]
    fn acquire_rejects_parent_traversal_name() {
        let dir = fresh_lock_root();
        let err = acquire(dir.path(), "../deploy").unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn acquire_rejects_absolute_name() {
        let dir = fresh_lock_root();
        let err = acquire(dir.path(), "/tmp/deploy").unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn acquire_rejects_nested_name() {
        let dir = fresh_lock_root();
        let err = acquire(dir.path(), "sub/lock").unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn acquire_rejects_empty_name() {
        let dir = fresh_lock_root();
        let err = acquire(dir.path(), "").unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn validate_lock_file_accepts_missing_path() {
        let dir = fresh_lock_root();
        validate_lock_file(&dir.path().join("does-not-exist")).unwrap();
    }

    #[test]
    fn validate_lock_file_accepts_regular_file() {
        let dir = fresh_lock_root();
        let path = dir.path().join("deploy");
        fs::write(&path, b"").unwrap();
        validate_lock_file(&path).unwrap();
    }

    #[test]
    fn validate_lock_file_rejects_directory() {
        let dir = fresh_lock_root();
        let path = dir.path().join("deploy");
        fs::create_dir(&path).unwrap();
        let err = validate_lock_file(&path).unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }

    #[test]
    fn acquire_rejects_existing_directory_at_lock_path() {
        let dir = fresh_lock_root();
        fs::create_dir(dir.path().join("deploy")).unwrap();
        let err = acquire(dir.path(), "deploy").unwrap_err();
        assert!(matches!(err, Error::Lock { .. }));
    }
}
