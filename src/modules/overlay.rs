use std::io;
use std::path::{Path, PathBuf};

use crate::atomic::install_root_file;
use crate::backup::create_backup;
use crate::error::Error;
use crate::policy::{ModuleName, normalize_module, safe_policy_read};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EditOutcome {
    pub changed: bool,
    pub backup: Option<PathBuf>,
    // Block-wins advisory: target is in the other list. Operation still applied.
    pub overlap: bool,
}

fn read_validated_overlay(path: &Path) -> Result<Option<String>, Error> {
    let text = match safe_policy_read(path) {
        Ok(t) => t,
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        ModuleName::new(line)?;
    }
    Ok(Some(text))
}

fn list_contains(path: &Path, mod_name: &str) -> Result<bool, Error> {
    match read_validated_overlay(path)? {
        None => Ok(false),
        Some(text) => {
            let target = normalize_module(mod_name);
            for raw in text.lines() {
                let line = raw.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if normalize_module(line) == target {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

fn fresh_overlay(kind: &str, mod_name: &str) -> String {
    format!("# seshat manual {kind} list\n\n{mod_name}\n")
}

fn append_overlay(existing: &str, mod_name: &str) -> String {
    let mut out = existing.to_string();
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(mod_name);
    out.push('\n');
    out
}

fn remove_from_overlay(text: &str, mod_name: &str) -> (String, bool) {
    let target = normalize_module(mod_name);
    let mut removed = false;
    let mut out = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') && normalize_module(trimmed) == target {
            removed = true;
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, removed)
}

pub fn allow_module(
    mod_name: &ModuleName,
    allow_path: &Path,
    block_path: &Path,
    backup_dir: &Path,
) -> Result<EditOutcome, Error> {
    if list_contains(block_path, mod_name.as_str())? {
        return Err(Error::Validation {
            field: "modules.allow".to_string(),
            reason: format!("{} is blocked; unblock first", mod_name.as_str()),
        });
    }
    if list_contains(allow_path, mod_name.as_str())? {
        return Ok(EditOutcome {
            changed: false,
            backup: None,
            overlap: false,
        });
    }
    let existing = read_validated_overlay(allow_path)?;
    let backup = if existing.is_some() {
        create_backup(allow_path, backup_dir)?
    } else {
        None
    };
    let new_content = match existing.as_deref() {
        Some(t) => append_overlay(t, mod_name.as_str()),
        None => fresh_overlay("allow", mod_name.as_str()),
    };
    install_root_file(allow_path, new_content.as_bytes(), 0o600)?;
    Ok(EditOutcome {
        changed: true,
        backup,
        overlap: false,
    })
}

pub fn unallow_module(
    mod_name: &ModuleName,
    allow_path: &Path,
    backup_dir: &Path,
) -> Result<EditOutcome, Error> {
    let existing = match read_validated_overlay(allow_path)? {
        Some(t) => t,
        None => {
            return Ok(EditOutcome {
                changed: false,
                backup: None,
                overlap: false,
            });
        }
    };
    let (new_content, removed) = remove_from_overlay(&existing, mod_name.as_str());
    if !removed {
        return Ok(EditOutcome {
            changed: false,
            backup: None,
            overlap: false,
        });
    }
    let backup = create_backup(allow_path, backup_dir)?;
    install_root_file(allow_path, new_content.as_bytes(), 0o600)?;
    Ok(EditOutcome {
        changed: true,
        backup,
        overlap: false,
    })
}

pub fn block_module(
    mod_name: &ModuleName,
    allow_path: &Path,
    block_path: &Path,
    backup_dir: &Path,
) -> Result<EditOutcome, Error> {
    let overlap = list_contains(allow_path, mod_name.as_str())?;
    if list_contains(block_path, mod_name.as_str())? {
        return Ok(EditOutcome {
            changed: false,
            backup: None,
            overlap,
        });
    }
    let existing = read_validated_overlay(block_path)?;
    let backup = if existing.is_some() {
        create_backup(block_path, backup_dir)?
    } else {
        None
    };
    let new_content = match existing.as_deref() {
        Some(t) => append_overlay(t, mod_name.as_str()),
        None => fresh_overlay("block", mod_name.as_str()),
    };
    install_root_file(block_path, new_content.as_bytes(), 0o600)?;
    Ok(EditOutcome {
        changed: true,
        backup,
        overlap,
    })
}

pub fn unblock_module(
    mod_name: &ModuleName,
    block_path: &Path,
    backup_dir: &Path,
) -> Result<EditOutcome, Error> {
    let existing = match read_validated_overlay(block_path)? {
        Some(t) => t,
        None => {
            return Ok(EditOutcome {
                changed: false,
                backup: None,
                overlap: false,
            });
        }
    };
    let (new_content, removed) = remove_from_overlay(&existing, mod_name.as_str());
    if !removed {
        return Ok(EditOutcome {
            changed: false,
            backup: None,
            overlap: false,
        });
    }
    let backup = create_backup(block_path, backup_dir)?;
    install_root_file(block_path, new_content.as_bytes(), 0o600)?;
    Ok(EditOutcome {
        changed: true,
        backup,
        overlap: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::modules::parse_allowlist;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn overlay_env(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let allow = dir.join("allowlist.allow.conf");
        let block = dir.join("allowlist.block.conf");
        let backup_dir = dir.join("backups/modules");
        fs::create_dir_all(&backup_dir).unwrap();
        (allow, block, backup_dir)
    }

    fn mod_name(n: &str) -> ModuleName {
        ModuleName::new(n).unwrap()
    }

    #[test]
    fn allow_creates_file_when_absent() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        let out = allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        assert!(out.changed);
        assert!(out.backup.is_none());
        let text = fs::read_to_string(&allow).unwrap();
        assert!(text.contains("vfat"));
        assert!(text.starts_with("# seshat manual allow list"));
    }

    #[test]
    fn allow_appends_to_existing_with_backup() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        let out = allow_module(&mod_name("ext4"), &allow, &block, &backup_dir).unwrap();
        assert!(out.changed);
        assert!(out.backup.is_some());
        let modules = parse_allowlist(&allow).unwrap();
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, vec!["vfat", "ext4"]);
    }

    #[test]
    fn allow_is_no_op_on_duplicate() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        let out = allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        assert!(!out.changed);
        assert!(out.backup.is_none());
    }

    #[test]
    fn allow_treats_hyphen_underscore_as_same_module() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        allow_module(&mod_name("usb-storage"), &allow, &block, &backup_dir).unwrap();
        let out = allow_module(&mod_name("usb_storage"), &allow, &block, &backup_dir).unwrap();
        assert!(!out.changed);
    }

    #[test]
    fn allow_refuses_when_module_is_blocked() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        block_module(&mod_name("usb-storage"), &allow, &block, &backup_dir).unwrap();
        match allow_module(&mod_name("usb_storage"), &allow, &block, &backup_dir).unwrap_err() {
            Error::Validation { field, reason } => {
                assert_eq!(field, "modules.allow");
                assert!(reason.contains("unblock"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn unallow_removes_line_and_backs_up() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        allow_module(&mod_name("ext4"), &allow, &block, &backup_dir).unwrap();
        let out = unallow_module(&mod_name("vfat"), &allow, &backup_dir).unwrap();
        assert!(out.changed);
        assert!(out.backup.is_some());
        let modules = parse_allowlist(&allow).unwrap();
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, vec!["ext4"]);
    }

    #[test]
    fn unallow_is_no_op_when_file_missing() {
        let dir = tempdir().unwrap();
        let (allow, _block, backup_dir) = overlay_env(dir.path());
        let out = unallow_module(&mod_name("vfat"), &allow, &backup_dir).unwrap();
        assert!(!out.changed);
        assert!(out.backup.is_none());
    }

    #[test]
    fn unallow_is_no_op_when_module_not_present() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        let out = unallow_module(&mod_name("ext4"), &allow, &backup_dir).unwrap();
        assert!(!out.changed);
        assert!(out.backup.is_none());
    }

    #[test]
    fn block_creates_file_when_absent() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        let out = block_module(&mod_name("usb-storage"), &allow, &block, &backup_dir).unwrap();
        assert!(out.changed);
        assert!(!out.overlap);
        let text = fs::read_to_string(&block).unwrap();
        assert!(text.contains("usb-storage"));
        assert!(text.starts_with("# seshat manual block list"));
    }

    #[test]
    fn block_warns_overlap_when_module_also_allowed_but_still_applies() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        let out = block_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        assert!(out.changed);
        assert!(out.overlap);
        assert!(list_contains(&block, "vfat").unwrap());
        assert!(list_contains(&allow, "vfat").unwrap());
    }

    #[test]
    fn block_is_no_op_on_duplicate() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        block_module(&mod_name("usb-storage"), &allow, &block, &backup_dir).unwrap();
        let out = block_module(&mod_name("usb_storage"), &allow, &block, &backup_dir).unwrap();
        assert!(!out.changed);
    }

    #[test]
    fn unblock_removes_and_backs_up() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        block_module(&mod_name("usb-storage"), &allow, &block, &backup_dir).unwrap();
        block_module(&mod_name("firewire_core"), &allow, &block, &backup_dir).unwrap();
        let out = unblock_module(&mod_name("usb_storage"), &block, &backup_dir).unwrap();
        assert!(out.changed);
        assert!(out.backup.is_some());
        let modules = parse_allowlist(&block).unwrap();
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, vec!["firewire_core"]);
    }

    #[test]
    fn overlay_files_have_mode_0o600() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        allow_module(&mod_name("vfat"), &allow, &block, &backup_dir).unwrap();
        block_module(&mod_name("usb-storage"), &allow, &block, &backup_dir).unwrap();
        assert_eq!(
            fs::metadata(&allow).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&block).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn remove_from_overlay_preserves_comments_and_blanks() {
        let text = "# header\n\nvfat\n# mid\next4\n";
        let (out, removed) = remove_from_overlay(text, "vfat");
        assert!(removed);
        assert!(out.contains("# header"));
        assert!(out.contains("# mid"));
        assert!(out.contains("ext4"));
        assert!(!out.lines().any(|l| l.trim() == "vfat"));
    }

    fn write_overlay(path: &Path, body: &str) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    #[test]
    fn allow_rejects_when_existing_allow_has_invalid_line() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        write_overlay(&allow, "vfat\nbad name\n");
        let before = fs::read(&allow).unwrap();
        match allow_module(&mod_name("ext4"), &allow, &block, &backup_dir).unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "module_name"),
            other => panic!("expected Validation, got {other:?}"),
        }
        assert_eq!(fs::read(&allow).unwrap(), before);
    }

    #[test]
    fn allow_rejects_when_existing_block_has_invalid_line() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        write_overlay(&block, "bad name\n");
        assert!(matches!(
            allow_module(&mod_name("ext4"), &allow, &block, &backup_dir).unwrap_err(),
            Error::Validation { .. }
        ));
    }

    #[test]
    fn unallow_rejects_when_existing_allow_has_invalid_line() {
        let dir = tempdir().unwrap();
        let (allow, _block, backup_dir) = overlay_env(dir.path());
        write_overlay(&allow, "vfat\nbad name\n");
        let before = fs::read(&allow).unwrap();
        assert!(matches!(
            unallow_module(&mod_name("vfat"), &allow, &backup_dir).unwrap_err(),
            Error::Validation { .. }
        ));
        assert_eq!(fs::read(&allow).unwrap(), before);
    }

    #[test]
    fn block_rejects_when_existing_block_has_invalid_line() {
        let dir = tempdir().unwrap();
        let (allow, block, backup_dir) = overlay_env(dir.path());
        write_overlay(&block, "bad name\n");
        let before = fs::read(&block).unwrap();
        assert!(matches!(
            block_module(&mod_name("usb-storage"), &allow, &block, &backup_dir).unwrap_err(),
            Error::Validation { .. }
        ));
        assert_eq!(fs::read(&block).unwrap(), before);
    }

    #[test]
    fn unblock_rejects_when_existing_block_has_invalid_line() {
        let dir = tempdir().unwrap();
        let (_allow, block, backup_dir) = overlay_env(dir.path());
        write_overlay(&block, "usb-storage\nbad name\n");
        let before = fs::read(&block).unwrap();
        assert!(matches!(
            unblock_module(&mod_name("usb-storage"), &block, &backup_dir).unwrap_err(),
            Error::Validation { .. }
        ));
        assert_eq!(fs::read(&block).unwrap(), before);
    }
}
