//! Pure systemd unit file content generator for the boot-time lock service.

use std::path::Path;

use crate::error::Error;

// systemd runs services with an empty env; SESHAT_STATE_ROOT must be baked in.
pub fn generate_service_unit(binary_path: &Path, state_root: &Path) -> Result<String, Error> {
    let binary = validated_absolute(binary_path, "binary_path")?;
    let root = validated_absolute(state_root, "state_root")?;
    Ok(format!(
        "# managed by seshat\n\
         [Unit]\n\
         Description=Lock kernel modules after boot\n\
         After=multi-user.target\n\
         \n\
         [Service]\n\
         Type=oneshot\n\
         Environment=\"SESHAT_STATE_ROOT={root}\"\n\
         ExecStart=\"{binary}\" lock --yes\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        binary = binary,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn service_unit_embeds_binary_and_state_root_and_lock_yes() {
        let out = generate_service_unit(
            Path::new("/usr/local/bin/seshat"),
            Path::new("/var/lib/seshat"),
        )
        .unwrap();
        assert!(out.contains("Description=Lock kernel modules after boot"));
        assert!(out.contains("After=multi-user.target"));
        assert!(out.contains("Type=oneshot"));
        assert!(out.contains("Environment=\"SESHAT_STATE_ROOT=/var/lib/seshat\""));
        assert!(out.contains("ExecStart=\"/usr/local/bin/seshat\" lock --yes"));
        assert!(out.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn service_unit_rejects_relative_binary_path() {
        let err =
            generate_service_unit(Path::new("./seshat"), Path::new("/var/lib/seshat")).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn service_unit_rejects_relative_state_root() {
        let err =
            generate_service_unit(Path::new("/usr/bin/seshat"), Path::new("state")).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn service_unit_rejects_newline_in_binary_path() {
        let malicious = PathBuf::from("/tmp/evil\nExecStart=/bin/sh");
        let err = generate_service_unit(&malicious, Path::new("/var/lib/seshat")).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn service_unit_rejects_newline_in_state_root() {
        let malicious = PathBuf::from("/var/lib/seshat\nEnvironment=LD_PRELOAD=/evil");
        let err = generate_service_unit(Path::new("/usr/bin/seshat"), &malicious).unwrap_err();
        assert!(matches!(err, Error::Validation { .. }));
    }

    #[test]
    fn service_unit_starts_with_managed_by_header() {
        let out = generate_service_unit(Path::new("/usr/bin/seshat"), Path::new("/var/lib/seshat"))
            .unwrap();
        assert!(out.starts_with("# managed by seshat\n"));
    }
}
