//! Pure systemd unit file content generators for the drift detector.

use std::path::Path;

use crate::error::Error;
use crate::policy::ProfileName;

// ProfileName::new rejects whitespace/quotes/metacharacters, so `--profile "name"` embeds safely.
// state_root must be baked in: systemd runs services with an empty env, so HOME/XDG fallbacks never fire.
pub fn generate_service_unit(
    binary_path: &Path,
    profile: &ProfileName,
    state_root: &Path,
) -> Result<String, Error> {
    let binary = validated_absolute(binary_path, "binary_path")?;
    let root = validated_absolute(state_root, "state_root")?;
    Ok(format!(
        "# managed by seshat\n\
         [Unit]\n\
         Description=Kernel hardening drift check\n\
         After=network.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         Environment=\"SESHAT_STATE_ROOT={root}\"\n\
         ExecStartPre=/bin/sleep 5\n\
         ExecStart=\"{binary}\" verify --profile \"{profile_name}\"\n\
         StandardOutput=journal\n\
         StandardError=journal\n",
        binary = binary,
        profile_name = profile.as_str(),
        root = root,
    ))
}

fn validated_absolute<'a>(path: &'a Path, field: &str) -> Result<&'a str, Error> {
    let s = path.to_str().ok_or_else(|| Error::Validation {
        field: field.to_string(),
        reason: format!("{field} is not valid UTF-8: {}", path.display()),
    })?;
    if !path.is_absolute() {
        return Err(Error::Validation {
            field: field.to_string(),
            reason: format!("{field} must be absolute: {s}"),
        });
    }
    if s.contains('"') || s.contains('\n') {
        return Err(Error::Validation {
            field: field.to_string(),
            reason: format!("{field} contains quote or newline"),
        });
    }
    Ok(s)
}

pub fn generate_path_unit(
    sysctl_dropin: &Path,
    modprobe_dropin: &Path,
) -> Result<String, Error> {
    let sysctl = path_str(sysctl_dropin, "sysctl_dropin")?;
    let modprobe = path_str(modprobe_dropin, "modprobe_dropin")?;
    Ok(format!(
        "# managed by seshat\n\
         [Unit]\n\
         Description=Watch kernel hardening config files for drift\n\
         \n\
         [Path]\n\
         PathChanged={sysctl}\n\
         PathChanged={modprobe}\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
    ))
}

// OnBootSec waits past early boot so /proc and /sys have settled.
pub fn generate_timer_unit() -> String {
    "# managed by seshat\n\
     [Unit]\n\
     Description=Periodic kernel hardening verify\n\
     \n\
     [Timer]\n\
     OnBootSec=5min\n\
     OnUnitActiveSec=1h\n\
     Persistent=true\n\
     \n\
     [Install]\n\
     WantedBy=timers.target\n"
        .to_string()
}

fn path_str<'a>(path: &'a Path, field: &str) -> Result<&'a str, Error> {
    let s = path.to_str().ok_or_else(|| Error::Validation {
        field: field.to_string(),
        reason: format!("path is not valid UTF-8: {}", path.display()),
    })?;
    if !path.is_absolute() {
        return Err(Error::Validation {
            field: field.to_string(),
            reason: format!("path must be absolute: {s}"),
        });
    }
    if s.contains('\n') {
        return Err(Error::Validation {
            field: field.to_string(),
            reason: "path contains newline".to_string(),
        });
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn profile(name: &str) -> ProfileName {
        ProfileName::new(name).unwrap()
    }

    #[test]
    fn service_unit_contains_exec_start_with_binary_and_profile() {
        let out = generate_service_unit(
            Path::new("/usr/local/bin/seshat"),
            &profile("baseline"),
            Path::new("/var/lib/seshat"),
        )
        .unwrap();
        assert!(out.contains("Description=Kernel hardening drift check"));
        assert!(out.contains("Type=oneshot"));
        assert!(out.contains("Environment=\"SESHAT_STATE_ROOT=/var/lib/seshat\""));
        assert!(out.contains("ExecStartPre=/bin/sleep 5"));
        assert!(out.contains("ExecStart=\"/usr/local/bin/seshat\" verify --profile \"baseline\""));
        assert!(out.contains("StandardOutput=journal"));
        assert!(out.contains("StandardError=journal"));
    }

    #[test]
    fn service_unit_rejects_relative_binary_path() {
        let err = generate_service_unit(
            Path::new("./seshat"),
            &profile("baseline"),
            Path::new("/var/lib/seshat"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn service_unit_rejects_relative_state_root() {
        let err = generate_service_unit(
            Path::new("/usr/local/bin/seshat"),
            &profile("baseline"),
            Path::new("state"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn service_unit_rejects_newline_in_binary_path() {
        let malicious = PathBuf::from("/tmp/evil\nExecStart=/bin/sh");
        let err = generate_service_unit(
            &malicious,
            &profile("baseline"),
            Path::new("/var/lib/seshat"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn service_unit_rejects_newline_in_state_root() {
        let malicious = PathBuf::from("/var/lib/seshat\nEnvironment=LD_PRELOAD=/evil");
        let err = generate_service_unit(
            Path::new("/usr/local/bin/seshat"),
            &profile("baseline"),
            &malicious,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn path_unit_lists_both_drop_ins() {
        let out = generate_path_unit(
            Path::new("/etc/sysctl.d/99-kernel-hardening.conf"),
            Path::new("/etc/modprobe.d/99-kernel-hardening.conf"),
        )
        .unwrap();
        assert!(out.contains("PathChanged=/etc/sysctl.d/99-kernel-hardening.conf"));
        assert!(out.contains("PathChanged=/etc/modprobe.d/99-kernel-hardening.conf"));
        assert!(out.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn path_unit_rejects_relative_paths() {
        let err = generate_path_unit(
            Path::new("sysctl.conf"),
            Path::new("/etc/modprobe.d/99.conf"),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn timer_unit_has_boot_and_active_intervals() {
        let out = generate_timer_unit();
        assert!(out.contains("OnBootSec=5min"));
        assert!(out.contains("OnUnitActiveSec=1h"));
        assert!(out.contains("Persistent=true"));
        assert!(out.contains("WantedBy=timers.target"));
    }

    #[test]
    fn every_unit_starts_with_managed_by_header() {
        let svc = generate_service_unit(
            Path::new("/usr/bin/seshat"),
            &profile("x"),
            Path::new("/var/lib/seshat"),
        )
        .unwrap();
        let pth = generate_path_unit(
            Path::new("/etc/sysctl.d/a.conf"),
            Path::new("/etc/modprobe.d/b.conf"),
        )
        .unwrap();
        let tim = generate_timer_unit();
        for u in [&svc, &pth, &tim] {
            assert!(
                u.starts_with("# managed by seshat\n"),
                "missing header: {u}"
            );
        }
    }
}
