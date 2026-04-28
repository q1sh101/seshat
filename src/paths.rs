use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use crate::error::Error;

// Symlinked write dirs leak primitive writes outside `<root>` (tempfile_in follows the symlink).
pub fn ensure_dir(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(Error::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "directory target is a symlink".to_string(),
                });
            }
            if !ft.is_dir() {
                return Err(Error::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "path exists and is not a directory".to_string(),
                });
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir_all(path).map_err(Error::Io)
        }
        Err(e) => Err(Error::Io(e)),
    }
}

const SESHAT_SUBDIR: &str = "seshat";
const LOCK_SUBDIR: &str = "seshat-locks";

pub const ENV_STATE_ROOT: &str = "SESHAT_STATE_ROOT";
pub const ENV_LOCK_ROOT: &str = "SESHAT_LOCK_ROOT";

pub const ALLOWLIST_SNAPSHOT: &str = "allowlist.snapshot.conf";
pub const ALLOWLIST_ALLOW: &str = "allowlist.allow.conf";
pub const ALLOWLIST_BLOCK: &str = "allowlist.block.conf";

pub const SYSCTL_DROPIN: &str = "/etc/sysctl.d/99-kernel-hardening.conf";
pub const MODPROBE_DROPIN: &str = "/etc/modprobe.d/99-kernel-hardening.conf";
pub const GRUB_DROPIN: &str = "/etc/default/grub.d/99-kernel-hardening.cfg";
pub const GRUB_CONFIG: &str = "/etc/default/grub";
pub const GRUB_CFG: &str = "/boot/grub/grub.cfg";
pub const KERNEL_CMDLINE: &str = "/etc/kernel/cmdline";

pub const PROC_SYS: &str = "/proc/sys";
pub const PROC_CMDLINE: &str = "/proc/cmdline";
pub const PROC_MODULES_DISABLED: &str = "/proc/sys/kernel/modules_disabled";
pub const SYS_LOCKDOWN: &str = "/sys/kernel/security/lockdown";
pub const LIB_MODULES: &str = "/lib/modules";

pub fn modules_dir(kernel_release: &str) -> PathBuf {
    PathBuf::from(LIB_MODULES).join(kernel_release)
}

fn non_empty_env(name: &str) -> Option<OsString> {
    std::env::var_os(name).filter(|v| !v.is_empty())
}

// No /tmp fallback: relocating backups under /tmp would be unsafe.
fn resolve_state_root(
    explicit: Option<&OsStr>,
    sudo_home: Option<&OsStr>,
    xdg_state_home: Option<&OsStr>,
    home: Option<&OsStr>,
) -> Option<PathBuf> {
    if let Some(v) = explicit {
        return Some(PathBuf::from(v));
    }
    // Under sudo, HOME flips to /root; prefer the invoker's home so the
    // state dir resolves to the same path the user would see unprivileged.
    if let Some(v) = sudo_home {
        return Some(PathBuf::from(v).join(".local/state").join(SESHAT_SUBDIR));
    }
    if let Some(v) = xdg_state_home {
        return Some(PathBuf::from(v).join(SESHAT_SUBDIR));
    }
    if let Some(v) = home {
        return Some(PathBuf::from(v).join(".local/state").join(SESHAT_SUBDIR));
    }
    None
}

// /tmp/seshat-locks fallback is allowed only because the lockfile is process-local.
fn resolve_lock_root(explicit: Option<&OsStr>, runtime_dir: Option<&OsStr>) -> PathBuf {
    if let Some(v) = explicit {
        return PathBuf::from(v);
    }
    if let Some(v) = runtime_dir {
        return PathBuf::from(v).join(LOCK_SUBDIR);
    }
    PathBuf::from("/tmp").join(LOCK_SUBDIR)
}

fn parse_getent_line(line: &str) -> Option<PathBuf> {
    let home = line.split(':').nth(5)?;
    if home.is_empty() {
        return None;
    }
    Some(PathBuf::from(home))
}

fn lookup_home_for_user(user: &str) -> Option<PathBuf> {
    let out = std::process::Command::new("/usr/bin/getent")
        .args(["passwd", user])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let line = std::str::from_utf8(&out.stdout).ok()?;
    parse_getent_line(line.trim_end_matches('\n'))
}

// Ignores SUDO_USER=root so a root-to-root sudo does not redirect state.
pub fn sudo_user_home() -> Option<PathBuf> {
    let user = non_empty_env("SUDO_USER")?;
    let user_str = user.to_str()?;
    if user_str == "root" {
        return None;
    }
    lookup_home_for_user(user_str)
}

pub fn state_root() -> Result<PathBuf, Error> {
    let sudo_home = sudo_user_home();
    resolve_state_root(
        non_empty_env(ENV_STATE_ROOT).as_deref(),
        sudo_home.as_deref().map(|p| p.as_os_str()),
        non_empty_env("XDG_STATE_HOME").as_deref(),
        non_empty_env("HOME").as_deref(),
    )
    .ok_or_else(|| Error::Validation {
        field: "state_root".to_string(),
        reason: "no state root discoverable; set SESHAT_STATE_ROOT, XDG_STATE_HOME, or HOME"
            .to_string(),
    })
}

pub fn lock_root() -> PathBuf {
    resolve_lock_root(
        non_empty_env(ENV_LOCK_ROOT).as_deref(),
        non_empty_env("XDG_RUNTIME_DIR").as_deref(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;
    use std::path::Path;

    fn s(v: &str) -> &OsStr {
        OsStr::new(v)
    }

    #[test]
    fn resolve_state_root_prefers_explicit() {
        assert_eq!(
            resolve_state_root(
                Some(s("/srv/seshat-test")),
                Some(s("/home/invoker")),
                Some(s("/xdg")),
                Some(s("/home/op"))
            )
            .unwrap(),
            Path::new("/srv/seshat-test")
        );
    }

    #[test]
    fn resolve_state_root_prefers_sudo_user_over_xdg_and_home() {
        assert_eq!(
            resolve_state_root(
                None,
                Some(s("/home/invoker")),
                Some(s("/xdg/state")),
                Some(s("/root"))
            )
            .unwrap(),
            Path::new("/home/invoker/.local/state/seshat")
        );
    }

    #[test]
    fn resolve_state_root_falls_back_to_xdg_state_home() {
        assert_eq!(
            resolve_state_root(None, None, Some(s("/xdg/state")), Some(s("/home/ignored")))
                .unwrap(),
            Path::new("/xdg/state/seshat")
        );
    }

    #[test]
    fn resolve_state_root_falls_back_to_home_local_state() {
        assert_eq!(
            resolve_state_root(None, None, None, Some(s("/home/operator"))).unwrap(),
            Path::new("/home/operator/.local/state/seshat")
        );
    }

    #[test]
    fn resolve_state_root_returns_none_when_no_env_available() {
        assert!(resolve_state_root(None, None, None, None).is_none());
    }

    #[test]
    fn parse_getent_line_extracts_home_for_alice() {
        assert_eq!(
            parse_getent_line("alice:x:1000:1000::/home/alice:/bin/bash").unwrap(),
            Path::new("/home/alice")
        );
    }

    #[test]
    fn parse_getent_line_extracts_home_for_operator() {
        assert_eq!(
            parse_getent_line("operator:x:1001:1001::/home/operator:/bin/zsh").unwrap(),
            Path::new("/home/operator")
        );
    }

    #[test]
    fn parse_getent_line_returns_none_when_home_empty() {
        assert!(parse_getent_line("svc:x:999:999:::/bin/false").is_none());
    }

    #[test]
    fn parse_getent_line_returns_none_when_too_few_fields() {
        assert!(parse_getent_line("bad:line").is_none());
    }

    #[test]
    fn resolve_lock_root_prefers_explicit() {
        assert_eq!(
            resolve_lock_root(Some(s("/run/seshat-locks-test")), Some(s("/run/user/1000"))),
            Path::new("/run/seshat-locks-test")
        );
    }

    #[test]
    fn resolve_lock_root_falls_back_to_xdg_runtime_dir() {
        assert_eq!(
            resolve_lock_root(None, Some(s("/run/user/1000"))),
            Path::new("/run/user/1000/seshat-locks")
        );
    }

    #[test]
    fn resolve_lock_root_last_resort_is_tmp_seshat_locks() {
        assert_eq!(
            resolve_lock_root(None, None),
            Path::new("/tmp/seshat-locks")
        );
    }

    #[test]
    fn every_managed_target_is_absolute() {
        for p in [
            SYSCTL_DROPIN,
            MODPROBE_DROPIN,
            GRUB_DROPIN,
            GRUB_CONFIG,
            GRUB_CFG,
            KERNEL_CMDLINE,
        ] {
            assert!(
                Path::new(p).is_absolute(),
                "managed target must be absolute: {p}"
            );
        }
    }

    #[test]
    fn modules_dir_joins_release_under_lib_modules() {
        assert_eq!(
            modules_dir("6.8.0-test"),
            Path::new("/lib/modules/6.8.0-test")
        );
    }
}
