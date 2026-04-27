use std::io;
use std::path::Path;

use super::allowlist::{effective_allowlist, parse_allowlist};
use crate::error::Error;
use crate::policy::ModuleName;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AllowlistReport {
    pub snapshot: Option<Vec<ModuleName>>,
    pub allow: Option<Vec<ModuleName>>,
    pub block: Option<Vec<ModuleName>>,
    pub effective: Vec<ModuleName>,
}

fn read_optional_list(path: &Path) -> Result<Option<Vec<ModuleName>>, Error> {
    match parse_allowlist(path) {
        Ok(v) => Ok(Some(v)),
        Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn list_allowlist(
    snapshot_path: &Path,
    allow_path: &Path,
    block_path: &Path,
) -> Result<AllowlistReport, Error> {
    let snapshot = read_optional_list(snapshot_path)?;
    let allow = read_optional_list(allow_path)?;
    let block = read_optional_list(block_path)?;

    let effective = effective_allowlist(
        snapshot.as_deref().unwrap_or(&[]),
        allow.as_deref().unwrap_or(&[]),
        block.as_deref().unwrap_or(&[]),
    );

    Ok(AllowlistReport {
        snapshot,
        allow,
        block,
        effective,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use tempfile::tempdir;

    fn write_overlay(path: &Path, body: &str) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn three_list_env(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        (
            dir.join("allowlist.snapshot.conf"),
            dir.join("allowlist.allow.conf"),
            dir.join("allowlist.block.conf"),
        )
    }

    fn effective_names(report: &AllowlistReport) -> Vec<&str> {
        report.effective.iter().map(|m| m.as_str()).collect()
    }

    fn opt_len<T>(opt: &Option<Vec<T>>) -> Option<usize> {
        opt.as_ref().map(|v| v.len())
    }

    #[test]
    fn list_with_all_three_files_reports_every_count() {
        let dir = tempdir().unwrap();
        let (snap, allow, block) = three_list_env(dir.path());
        write_overlay(&snap, "ext4\nvfat\nusb_storage\n");
        write_overlay(&allow, "btrfs\n");
        write_overlay(&block, "usb-storage\n");

        let report = list_allowlist(&snap, &allow, &block).unwrap();
        assert_eq!(opt_len(&report.snapshot), Some(3));
        assert_eq!(opt_len(&report.allow), Some(1));
        assert_eq!(opt_len(&report.block), Some(1));
        assert_eq!(effective_names(&report), vec!["btrfs", "ext4", "vfat"]);
        assert_eq!(report.effective.len(), 3);
    }

    #[test]
    fn list_missing_snapshot_reports_none_and_empty_effective() {
        let dir = tempdir().unwrap();
        let (snap, allow, block) = three_list_env(dir.path());
        let report = list_allowlist(&snap, &allow, &block).unwrap();
        assert_eq!(opt_len(&report.snapshot), None);
        assert_eq!(opt_len(&report.allow), None);
        assert_eq!(opt_len(&report.block), None);
        assert_eq!(report.effective.len(), 0);
    }

    #[test]
    fn list_missing_overlays_keeps_snapshot_as_effective() {
        let dir = tempdir().unwrap();
        let (snap, allow, block) = three_list_env(dir.path());
        write_overlay(&snap, "ext4\nvfat\n");
        let report = list_allowlist(&snap, &allow, &block).unwrap();
        assert_eq!(opt_len(&report.snapshot), Some(2));
        assert_eq!(opt_len(&report.allow), None);
        assert_eq!(opt_len(&report.block), None);
        assert_eq!(effective_names(&report), vec!["ext4", "vfat"]);
    }

    #[test]
    fn list_output_is_deterministic_across_runs() {
        let dir = tempdir().unwrap();
        let (snap, allow, block) = three_list_env(dir.path());
        write_overlay(&snap, "vfat\nusb_storage\next4\n");
        write_overlay(&allow, "btrfs\nxfs\n");
        let a = list_allowlist(&snap, &allow, &block).unwrap();
        let b = list_allowlist(&snap, &allow, &block).unwrap();
        assert_eq!(effective_names(&a), effective_names(&b));
    }

    #[test]
    fn list_surfaces_invalid_source_file() {
        let dir = tempdir().unwrap();
        let (snap, allow, block) = three_list_env(dir.path());
        write_overlay(&snap, "bad name\n");
        assert!(matches!(
            list_allowlist(&snap, &allow, &block).unwrap_err(),
            Error::Validation { .. }
        ));
    }
}
