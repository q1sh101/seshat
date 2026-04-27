use std::collections::{BTreeSet, HashSet};
use std::io;
use std::path::Path;

use super::names::strip_module_suffix;
use crate::error::Error;
use crate::policy::{ModuleName, normalize_module};

// Refuse missing root: a header-only drop-in would silently block nothing.
pub fn scan_installed_modules(modules_dir: &Path) -> Result<Vec<String>, Error> {
    let mut out: Vec<String> = Vec::new();
    scan_module_dir(modules_dir, &mut out, true)?;
    out.sort();
    out.dedup();
    Ok(out)
}

fn scan_module_dir(dir: &Path, out: &mut Vec<String>, is_root: bool) -> Result<(), Error> {
    let entries = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) if !is_root && e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    for entry in entries {
        let entry = entry?;
        // file_type() does not follow symlinks; parity with `find -type f`,
        // skip e.g. /lib/modules/<ver>/build -> /usr/src/... dir symlink.
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            scan_module_dir(&entry.path(), out, false)?;
        } else if ft.is_file() {
            let name_os = entry.file_name();
            if let Some(fname) = name_os.to_str()
                && let Some(stripped) = strip_module_suffix(fname)
                && ModuleName::new(stripped).is_ok()
            {
                out.push(stripped.to_string());
            }
        }
    }
    Ok(())
}

// Sort for order independence; keep duplicates so extra lines still drift.
pub(super) fn payload_signature(payload: &str) -> Vec<String> {
    let mut lines: Vec<String> = payload
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();
    lines.sort();
    lines
}

pub fn generate_modprobe_dropin(
    effective: &[ModuleName],
    installed: &[String],
    profile_name: &str,
) -> String {
    let allowed: HashSet<String> = effective
        .iter()
        .map(|m| normalize_module(m.as_str()))
        .collect();
    let mut blocked: BTreeSet<String> = BTreeSet::new();
    for raw in installed {
        let norm = normalize_module(raw);
        if !allowed.contains(&norm) {
            blocked.insert(raw.clone());
        }
    }

    let mut out = String::new();
    out.push_str("# managed by seshat\n");
    out.push_str(&format!("# profile: {profile_name}\n"));
    out.push_str("# mode: allowlist (auto-generated blocklist)\n");
    out.push_str("# source: snapshot ∪ allow − block\n\n");
    for name in &blocked {
        out.push_str("install ");
        out.push_str(name);
        out.push_str(" /bin/false\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::tempdir;

    fn touch(path: &Path, body: &str) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    #[test]
    fn scan_installed_modules_walks_recursively_and_filters() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("kernel/drivers");
        fs::create_dir_all(&root).unwrap();
        touch(&root.join("ext4.ko"), "");
        touch(&root.join("vfat.ko.zst"), "");
        touch(&root.join("README"), "");
        let nested = root.join("usb");
        fs::create_dir(&nested).unwrap();
        touch(&nested.join("usb-storage.ko"), "");

        let modules = scan_installed_modules(dir.path()).unwrap();
        assert_eq!(modules, vec!["ext4", "usb-storage", "vfat"]);
    }

    #[test]
    fn scan_installed_modules_errors_when_root_missing() {
        let dir = tempdir().unwrap();
        let err = scan_installed_modules(&dir.path().join("no-such-kernel")).unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == io::ErrorKind::NotFound));
    }

    #[test]
    fn scan_installed_modules_skips_symlink_dir() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let real = dir.path().join("kernel");
        fs::create_dir_all(&real).unwrap();
        touch(&real.join("ext4.ko"), "");

        let outside = dir.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        touch(&outside.join("leaked.ko"), "");

        symlink(&outside, real.join("build")).unwrap();

        let modules = scan_installed_modules(&real).unwrap();
        assert_eq!(modules, vec!["ext4"]);
    }

    #[test]
    fn scan_installed_modules_skips_symlink_files() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let root = dir.path().join("kernel");
        fs::create_dir_all(&root).unwrap();
        let real = root.join("ext4.ko");
        touch(&real, "");
        symlink(&real, root.join("vfat.ko")).unwrap();

        let modules = scan_installed_modules(&root).unwrap();
        assert_eq!(modules, vec!["ext4"]);
    }

    #[test]
    fn scan_installed_modules_rejects_invalid_filename() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("kernel");
        fs::create_dir_all(&root).unwrap();
        touch(&root.join("ext4.ko"), "");
        touch(&root.join("bad name.ko"), "");
        touch(&root.join("weird$char.ko"), "");

        let modules = scan_installed_modules(&root).unwrap();
        assert_eq!(modules, vec!["ext4"]);
    }

    #[test]
    fn scan_installed_modules_deduplicates() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        fs::create_dir_all(&a).unwrap();
        fs::create_dir_all(&b).unwrap();
        touch(&a.join("ext4.ko"), "");
        touch(&b.join("ext4.ko"), "");

        let modules = scan_installed_modules(dir.path()).unwrap();
        assert_eq!(modules, vec!["ext4"]);
    }

    #[test]
    fn generate_modprobe_dropin_blocks_modules_not_in_effective() {
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec![
            "ext4".to_string(),
            "vfat".to_string(),
            "usb-storage".to_string(),
        ];
        let out = generate_modprobe_dropin(&effective, &installed, "baseline");
        assert!(out.starts_with("# managed by seshat\n"));
        assert!(out.contains("# profile: baseline"));
        assert!(!out.contains("install ext4"));
        assert!(out.contains("install usb-storage /bin/false\n"));
        assert!(out.contains("install vfat /bin/false\n"));
    }

    #[test]
    fn generate_modprobe_dropin_treats_hyphen_and_underscore_as_equivalent() {
        let effective = vec![ModuleName::new("usb_storage").unwrap()];
        let installed = vec!["usb-storage".to_string()];
        let out = generate_modprobe_dropin(&effective, &installed, "x");
        assert!(!out.contains("install usb-storage"));
    }

    #[test]
    fn generate_modprobe_dropin_output_is_sorted() {
        let effective: Vec<ModuleName> = Vec::new();
        let installed = vec!["zram".to_string(), "aes".to_string(), "btrfs".to_string()];
        let out = generate_modprobe_dropin(&effective, &installed, "x");
        let install_lines: Vec<&str> = out.lines().filter(|l| l.starts_with("install ")).collect();
        assert_eq!(
            install_lines,
            vec![
                "install aes /bin/false",
                "install btrfs /bin/false",
                "install zram /bin/false",
            ]
        );
    }

    #[test]
    fn generate_modprobe_dropin_emits_header_only_when_everything_allowed() {
        let effective = vec![
            ModuleName::new("ext4").unwrap(),
            ModuleName::new("vfat").unwrap(),
        ];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let out = generate_modprobe_dropin(&effective, &installed, "x");
        assert!(!out.lines().any(|l| l.starts_with("install ")));
    }

    #[test]
    fn payload_signature_ignores_comments_and_blanks_and_is_order_independent() {
        let a = "# header\n\ninstall vfat /bin/false\ninstall aes /bin/false\n";
        let b = "install aes /bin/false\n\n# other comment\ninstall vfat /bin/false\n";
        assert_eq!(payload_signature(a), payload_signature(b));
    }

    #[test]
    fn payload_signature_preserves_duplicates() {
        let a = "install vfat /bin/false\ninstall vfat /bin/false\n";
        let b = "install vfat /bin/false\n";
        assert_ne!(payload_signature(a), payload_signature(b));
    }
}
