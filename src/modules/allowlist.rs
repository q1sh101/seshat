use std::collections::{BTreeSet, HashSet};
use std::path::Path;

use crate::error::Error;
use crate::policy::{ModuleName, normalize_module, safe_policy_read};

pub fn parse_allowlist(path: &Path) -> Result<Vec<ModuleName>, Error> {
    let text = safe_policy_read(path)?;
    let mut modules = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        modules.push(ModuleName::new(line)?);
    }
    Ok(modules)
}

pub fn effective_allowlist(
    snapshot: &[ModuleName],
    allow: &[ModuleName],
    block: &[ModuleName],
) -> Vec<ModuleName> {
    let blocked: HashSet<String> = block.iter().map(|m| normalize_module(m.as_str())).collect();
    let mut effective: BTreeSet<String> = BTreeSet::new();
    for m in snapshot.iter().chain(allow.iter()) {
        let normal = normalize_module(m.as_str());
        if !blocked.contains(&normal) {
            effective.insert(normal);
        }
    }
    effective
        .into_iter()
        .map(|s| ModuleName::new(&s).expect("normalized module name is always valid"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write_list(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    #[test]
    fn empty_file_produces_empty_vec() {
        let dir = tempdir().unwrap();
        let path = write_list(dir.path(), "empty.conf", "");
        assert!(parse_allowlist(&path).unwrap().is_empty());
    }

    #[test]
    fn parses_one_module_per_line() {
        let dir = tempdir().unwrap();
        let path = write_list(
            dir.path(),
            "allow.conf",
            "usb-storage\nfirewire_core\nvfat\n",
        );
        let modules = parse_allowlist(&path).unwrap();
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, vec!["usb-storage", "firewire_core", "vfat"]);
    }

    #[test]
    fn blank_lines_are_skipped() {
        let dir = tempdir().unwrap();
        let path = write_list(dir.path(), "allow.conf", "\nusb-storage\n\n\nvfat\n\n");
        let modules = parse_allowlist(&path).unwrap();
        assert_eq!(modules.len(), 2);
    }

    #[test]
    fn full_line_comments_are_skipped() {
        let dir = tempdir().unwrap();
        let body = "# header comment\nusb-storage\n# another comment\nvfat\n";
        let path = write_list(dir.path(), "allow.conf", body);
        let modules = parse_allowlist(&path).unwrap();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].as_str(), "usb-storage");
        assert_eq!(modules[1].as_str(), "vfat");
    }

    #[test]
    fn inline_hash_is_rejected_not_stripped() {
        let dir = tempdir().unwrap();
        let path = write_list(dir.path(), "allow.conf", "vfat # reason\n");
        match parse_allowlist(&path).unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "module_name"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn hash_inside_token_is_rejected() {
        let dir = tempdir().unwrap();
        let path = write_list(dir.path(), "allow.conf", "vfat#reason\n");
        match parse_allowlist(&path).unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "module_name"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn indented_full_line_comment_is_skipped() {
        let dir = tempdir().unwrap();
        let body = "   # indented comment\nusb-storage\n";
        let path = write_list(dir.path(), "allow.conf", body);
        let modules = parse_allowlist(&path).unwrap();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].as_str(), "usb-storage");
    }

    #[test]
    fn duplicates_are_tolerated() {
        let dir = tempdir().unwrap();
        let path = write_list(dir.path(), "allow.conf", "usb-storage\nusb-storage\n");
        let modules = parse_allowlist(&path).unwrap();
        assert_eq!(modules.len(), 2);
    }

    #[test]
    fn invalid_module_name_is_rejected() {
        let dir = tempdir().unwrap();
        let path = write_list(dir.path(), "allow.conf", "valid_one\nhas space\n");
        match parse_allowlist(&path).unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "module_name"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn rejects_symlink_source() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let real = write_list(dir.path(), "real.conf", "usb-storage\n");
        let link = dir.path().join("link.conf");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            parse_allowlist(&link).unwrap_err(),
            Error::UnsafePath { .. }
        ));
    }

    #[test]
    fn rejects_group_writable_file() {
        let dir = tempdir().unwrap();
        let path = write_list(dir.path(), "allow.conf", "usb-storage\n");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        assert!(matches!(
            parse_allowlist(&path).unwrap_err(),
            Error::UnsafePath { .. }
        ));
    }

    #[test]
    fn missing_file_maps_to_io_error() {
        let dir = tempdir().unwrap();
        assert!(matches!(
            parse_allowlist(&dir.path().join("missing.conf")).unwrap_err(),
            Error::Io(_)
        ));
    }

    fn mods(names: &[&str]) -> Vec<ModuleName> {
        names.iter().map(|n| ModuleName::new(n).unwrap()).collect()
    }

    fn as_str_vec(v: &[ModuleName]) -> Vec<&str> {
        v.iter().map(|m| m.as_str()).collect()
    }

    #[test]
    fn effective_empty_inputs_produce_empty_output() {
        assert!(effective_allowlist(&[], &[], &[]).is_empty());
    }

    #[test]
    fn effective_snapshot_only_is_returned_sorted() {
        let out = effective_allowlist(&mods(&["vfat", "ext4", "btrfs"]), &[], &[]);
        assert_eq!(as_str_vec(&out), vec!["btrfs", "ext4", "vfat"]);
    }

    #[test]
    fn effective_union_of_snapshot_and_allow() {
        let out = effective_allowlist(&mods(&["ext4"]), &mods(&["vfat"]), &[]);
        assert_eq!(as_str_vec(&out), vec!["ext4", "vfat"]);
    }

    #[test]
    fn effective_block_removes_from_snapshot() {
        let out = effective_allowlist(
            &mods(&["usb_storage", "ext4"]),
            &[],
            &mods(&["usb_storage"]),
        );
        assert_eq!(as_str_vec(&out), vec!["ext4"]);
    }

    #[test]
    fn effective_block_removes_from_allow() {
        let out = effective_allowlist(&[], &mods(&["usb_storage"]), &mods(&["usb_storage"]));
        assert!(out.is_empty());
    }

    #[test]
    fn effective_block_wins_when_allow_and_block_collide() {
        let out = effective_allowlist(
            &mods(&["ext4"]),
            &mods(&["usb_storage"]),
            &mods(&["usb_storage"]),
        );
        assert_eq!(as_str_vec(&out), vec!["ext4"]);
    }

    #[test]
    fn effective_hyphen_underscore_normalization_blocks_match() {
        let out = effective_allowlist(&mods(&["usb-storage"]), &[], &mods(&["usb_storage"]));
        assert!(out.is_empty());
    }

    #[test]
    fn effective_deduplicates_repeated_entries() {
        let out = effective_allowlist(&mods(&["vfat", "vfat", "vfat"]), &mods(&["vfat"]), &[]);
        assert_eq!(as_str_vec(&out), vec!["vfat"]);
    }

    #[test]
    fn effective_output_uses_normalized_form() {
        let out = effective_allowlist(&mods(&["usb-storage"]), &[], &[]);
        assert_eq!(as_str_vec(&out), vec!["usb_storage"]);
    }

    #[test]
    fn effective_output_is_deterministic_across_input_orders() {
        let a = effective_allowlist(&mods(&["a", "c", "b"]), &mods(&["e", "d"]), &mods(&["b"]));
        let b = effective_allowlist(&mods(&["c", "b", "a"]), &mods(&["d", "e"]), &mods(&["b"]));
        assert_eq!(as_str_vec(&a), as_str_vec(&b));
    }
}
