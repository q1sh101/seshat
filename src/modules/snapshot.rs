use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::atomic::install_root_file;
use crate::backup::create_backup;
use crate::error::Error;
use crate::policy::{ModuleName, normalize_module};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SnapshotSummary {
    pub loaded: usize,
    pub builtin: usize,
    pub deps: usize,
    pub total: usize,
}

// Require a kernel-module suffix: arbitrary filenames must not leak into policy.
fn path_to_module_name(path: &str) -> Option<String> {
    let base = std::path::Path::new(path.trim()).file_name()?.to_str()?;
    let stripped = base
        .strip_suffix(".ko.zst")
        .or_else(|| base.strip_suffix(".ko.xz"))
        .or_else(|| base.strip_suffix(".ko.gz"))
        .or_else(|| base.strip_suffix(".ko"))?;
    if stripped.is_empty() {
        return None;
    }
    Some(normalize_module(stripped))
}

fn parse_proc_modules(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let token = line.split_whitespace().next()?;
            if token.is_empty() {
                None
            } else {
                Some(normalize_module(token))
            }
        })
        .collect()
}

fn parse_modules_builtin(text: &str) -> Vec<String> {
    text.lines().filter_map(path_to_module_name).collect()
}

fn render_snapshot(modules: &BTreeSet<String>, kernel_release: &str) -> String {
    let mut out = String::new();
    out.push_str("# seshat snapshot\n");
    out.push_str(&format!("# kernel: {kernel_release}\n"));
    out.push_str(&format!("# modules: {}\n", modules.len()));
    out.push_str("# review before deploy\n\n");
    for m in modules {
        out.push_str(m);
        out.push('\n');
    }
    out
}

// resolve_deps returns None when modinfo is unavailable.
fn gather_snapshot<F>(
    proc_modules_path: &Path,
    modules_dir: &Path,
    kernel_release: &str,
    mut resolve_deps: F,
) -> Result<(String, SnapshotSummary), Error>
where
    F: FnMut(&str) -> Option<Vec<String>>,
{
    use std::fs;
    use std::io;

    let loaded_text = fs::read_to_string(proc_modules_path)?;
    let loaded = parse_proc_modules(&loaded_text);
    let loaded_count = loaded.len();

    let builtin_path = modules_dir.join("modules.builtin");
    let builtin = match fs::read_to_string(&builtin_path) {
        Ok(t) => parse_modules_builtin(&t),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(Error::Io(e)),
    };
    let builtin_count = builtin.len();

    let mut deps: Vec<String> = Vec::new();
    for name in &loaded {
        if let Some(list) = resolve_deps(name) {
            deps.extend(list);
        }
    }
    let dep_count = deps.len();

    // Every source-derived name re-validates before landing in the policy file.
    let mut all: BTreeSet<String> = BTreeSet::new();
    for m in loaded.iter().chain(builtin.iter()).chain(deps.iter()) {
        ModuleName::new(m).map_err(|_| Error::Validation {
            field: "snapshot_source".to_string(),
            reason: format!("malformed module name in source: {m:?}"),
        })?;
        all.insert(m.clone());
    }
    let total = all.len();

    let payload = render_snapshot(&all, kernel_release);
    Ok((
        payload,
        SnapshotSummary {
            loaded: loaded_count,
            builtin: builtin_count,
            deps: dep_count,
            total,
        },
    ))
}

pub fn create_snapshot<F>(
    dest: &Path,
    proc_modules_path: &Path,
    modules_dir: &Path,
    kernel_release: &str,
    resolve_deps: F,
) -> Result<SnapshotSummary, Error>
where
    F: FnMut(&str) -> Option<Vec<String>>,
{
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let (payload, summary) =
        gather_snapshot(proc_modules_path, modules_dir, kernel_release, resolve_deps)?;

    // create_new enforces create-or-fail: exists -> AlreadyExists.
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(dest)?;
    file.write_all(payload.as_bytes())?;
    file.sync_all()?;
    if let Some(parent) = dest.parent() {
        fs::File::open(parent)?.sync_all()?;
    }

    Ok(summary)
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResetSummary {
    pub snapshot: SnapshotSummary,
    pub backup: Option<PathBuf>,
}

// reset overwrites snapshot only; allow/block overlays are never touched.
pub fn reset_snapshot<F>(
    dest: &Path,
    proc_modules_path: &Path,
    modules_dir: &Path,
    kernel_release: &str,
    backup_dir: &Path,
    resolve_deps: F,
) -> Result<ResetSummary, Error>
where
    F: FnMut(&str) -> Option<Vec<String>>,
{
    let backup = create_backup(dest, backup_dir)?;
    let (payload, summary) =
        gather_snapshot(proc_modules_path, modules_dir, kernel_release, resolve_deps)?;
    install_root_file(dest, payload.as_bytes(), 0o600)?;
    Ok(ResetSummary {
        snapshot: summary,
        backup,
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

    #[test]
    fn path_to_module_name_strips_extensions() {
        assert_eq!(
            path_to_module_name("kernel/fs/ext4/ext4.ko"),
            Some("ext4".to_string())
        );
        assert_eq!(
            path_to_module_name("kernel/fs/ext4/ext4.ko.gz"),
            Some("ext4".to_string())
        );
        assert_eq!(
            path_to_module_name("kernel/fs/ext4/ext4.ko.xz"),
            Some("ext4".to_string())
        );
        assert_eq!(
            path_to_module_name("kernel/fs/ext4/ext4.ko.zst"),
            Some("ext4".to_string())
        );
    }

    #[test]
    fn path_to_module_name_normalizes_hyphens() {
        assert_eq!(
            path_to_module_name("kernel/drivers/usb/storage/usb-storage.ko"),
            Some("usb_storage".to_string())
        );
    }

    #[test]
    fn parse_proc_modules_takes_first_token_per_line() {
        let text = "ext4 1048576 3 - Live 0x0\nvfat 65536 0 - Live 0x0\n";
        assert_eq!(parse_proc_modules(text), vec!["ext4", "vfat"]);
    }

    #[test]
    fn parse_proc_modules_normalizes_hyphens() {
        let text = "usb-storage 65536 0 - Live 0x0\n";
        assert_eq!(parse_proc_modules(text), vec!["usb_storage"]);
    }

    #[test]
    fn parse_modules_builtin_extracts_names_from_paths() {
        let text = "kernel/fs/ext4/ext4.ko\nkernel/drivers/net/ethernet/intel/e1000/e1000.ko\n";
        assert_eq!(parse_modules_builtin(text), vec!["ext4", "e1000"]);
    }

    #[test]
    fn path_to_module_name_rejects_non_ko_files() {
        assert_eq!(path_to_module_name("kernel/fs/README"), None);
        assert_eq!(path_to_module_name("some/dir/Makefile"), None);
        assert_eq!(path_to_module_name(""), None);
    }

    #[test]
    fn render_snapshot_has_stable_header_and_sorted_names() {
        let mut set = BTreeSet::new();
        set.insert("vfat".to_string());
        set.insert("ext4".to_string());
        let out = render_snapshot(&set, "6.8.0");
        let expected = "# seshat snapshot\n\
# kernel: 6.8.0\n\
# modules: 2\n\
# review before deploy\n\
\n\
ext4\n\
vfat\n";
        assert_eq!(out, expected);
    }

    fn write(path: &Path, body: &str) {
        let mut f = fs::File::create(path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
    }

    fn deps_map(pairs: &[(&str, &[&str])]) -> impl FnMut(&str) -> Option<Vec<String>> {
        let map: std::collections::HashMap<String, Vec<String>> = pairs
            .iter()
            .map(|(k, v)| {
                (
                    (*k).to_string(),
                    v.iter().map(|s| (*s).to_string()).collect(),
                )
            })
            .collect();
        move |name| Some(map.get(name).cloned().unwrap_or_default())
    }

    #[test]
    fn create_snapshot_writes_union_and_returns_counts() {
        let dir = tempdir().unwrap();
        let proc_modules = dir.path().join("proc_modules");
        write(
            &proc_modules,
            "ext4 0 0 - Live 0x0\nusb-storage 0 0 - Live 0x0\n",
        );

        let mods_dir = dir.path().join("lib/modules/test");
        fs::create_dir_all(&mods_dir).unwrap();
        write(
            &mods_dir.join("modules.builtin"),
            "kernel/crypto/crc32c.ko\n",
        );

        let dest = dir.path().join("allowlist.snapshot.conf");
        let summary = create_snapshot(
            &dest,
            &proc_modules,
            &mods_dir,
            "6.8.0",
            deps_map(&[("ext4", &["jbd2", "crc16"])]),
        )
        .unwrap();

        assert_eq!(summary.loaded, 2);
        assert_eq!(summary.builtin, 1);
        assert_eq!(summary.deps, 2);
        assert_eq!(summary.total, 5);

        let written = fs::read_to_string(&dest).unwrap();
        let modules = parse_allowlist(&dest).unwrap();
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(
            names,
            vec!["crc16", "crc32c", "ext4", "jbd2", "usb_storage"]
        );
        assert!(written.starts_with("# seshat snapshot\n"));
        assert!(written.contains("# kernel: 6.8.0\n"));
    }

    #[test]
    fn create_snapshot_skips_deps_when_resolver_unavailable() {
        let dir = tempdir().unwrap();
        let proc_modules = dir.path().join("proc_modules");
        write(&proc_modules, "ext4 0 0 - Live 0x0\n");
        let mods_dir = dir.path().join("lib/modules/test");
        fs::create_dir_all(&mods_dir).unwrap();

        let dest = dir.path().join("snap.conf");
        let summary = create_snapshot(&dest, &proc_modules, &mods_dir, "6.8.0", |_| None).unwrap();
        assert_eq!(summary.deps, 0);
        assert_eq!(summary.total, 1);
    }

    #[test]
    fn create_snapshot_rejects_malformed_source_module_name() {
        let dir = tempdir().unwrap();
        let proc_modules = dir.path().join("proc_modules");
        write(&proc_modules, "ext4 0 0 - Live 0x0\n");
        let mods_dir = dir.path().join("lib/modules/test");
        fs::create_dir_all(&mods_dir).unwrap();

        let dest = dir.path().join("snap.conf");
        let err = create_snapshot(
            &dest,
            &proc_modules,
            &mods_dir,
            "6.8.0",
            deps_map(&[("ext4", &["bad name"])]),
        )
        .unwrap_err();
        match err {
            Error::Validation { field, .. } => assert_eq!(field, "snapshot_source"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn create_snapshot_fails_when_destination_exists() {
        let dir = tempdir().unwrap();
        let proc_modules = dir.path().join("proc_modules");
        write(&proc_modules, "ext4 0 0 - Live 0x0\n");
        let mods_dir = dir.path().join("lib/modules/test");
        fs::create_dir_all(&mods_dir).unwrap();

        let dest = dir.path().join("snap.conf");
        write(&dest, "pre-existing\n");

        let err = create_snapshot(&dest, &proc_modules, &mods_dir, "6.8.0", |_| Some(vec![]))
            .unwrap_err();
        match err {
            Error::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists),
            other => panic!("expected Io(AlreadyExists), got {other:?}"),
        }
        assert_eq!(fs::read_to_string(&dest).unwrap(), "pre-existing\n");
    }

    #[test]
    fn create_snapshot_tolerates_missing_builtin() {
        let dir = tempdir().unwrap();
        let proc_modules = dir.path().join("proc_modules");
        write(&proc_modules, "ext4 0 0 - Live 0x0\n");
        let mods_dir = dir.path().join("lib/modules/missing");
        fs::create_dir_all(&mods_dir).unwrap();

        let dest = dir.path().join("snap.conf");
        let summary =
            create_snapshot(&dest, &proc_modules, &mods_dir, "6.8.0", |_| Some(vec![])).unwrap();
        assert_eq!(summary.loaded, 1);
        assert_eq!(summary.builtin, 0);
        assert_eq!(summary.deps, 0);
        assert_eq!(summary.total, 1);
    }

    #[test]
    fn create_snapshot_writes_mode_0o600() {
        let dir = tempdir().unwrap();
        let proc_modules = dir.path().join("proc_modules");
        write(&proc_modules, "ext4 0 0 - Live 0x0\n");
        let mods_dir = dir.path().join("lib/modules/test");
        fs::create_dir_all(&mods_dir).unwrap();

        let dest = dir.path().join("snap.conf");
        create_snapshot(&dest, &proc_modules, &mods_dir, "6.8.0", |_| Some(vec![])).unwrap();
        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn scratch_snapshot_env(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
        let proc_modules = dir.join("proc_modules");
        write(&proc_modules, "ext4 0 0 - Live 0x0\n");
        let mods_dir = dir.join("lib/modules/test");
        fs::create_dir_all(&mods_dir).unwrap();
        let backup_dir = dir.join("backups/modules");
        fs::create_dir_all(&backup_dir).unwrap();
        (proc_modules, mods_dir, backup_dir)
    }

    #[test]
    fn reset_snapshot_with_no_prior_snapshot_has_no_backup() {
        let dir = tempdir().unwrap();
        let (proc_modules, mods_dir, backup_dir) = scratch_snapshot_env(dir.path());
        let dest = dir.path().join("snapshot.conf");

        let summary = reset_snapshot(
            &dest,
            &proc_modules,
            &mods_dir,
            "6.8.0",
            &backup_dir,
            |_| Some(vec![]),
        )
        .unwrap();

        assert!(summary.backup.is_none());
        assert_eq!(summary.snapshot.total, 1);
        assert!(dest.exists());
    }

    #[test]
    fn reset_snapshot_backs_up_prior_and_overwrites() {
        let dir = tempdir().unwrap();
        let (proc_modules, mods_dir, backup_dir) = scratch_snapshot_env(dir.path());
        let dest = dir.path().join("snapshot.conf");

        create_snapshot(&dest, &proc_modules, &mods_dir, "6.8.0", |_| Some(vec![])).unwrap();
        let old_bytes = fs::read(&dest).unwrap();

        write(&proc_modules, "ext4 0 0 - Live 0x0\nvfat 0 0 - Live 0x0\n");
        let summary = reset_snapshot(
            &dest,
            &proc_modules,
            &mods_dir,
            "6.8.0",
            &backup_dir,
            |_| Some(vec![]),
        )
        .unwrap();

        let backup_path = summary.backup.expect("backup path returned");
        assert_eq!(backup_path.parent().unwrap(), backup_dir);
        assert_eq!(fs::read(&backup_path).unwrap(), old_bytes);

        let new_bytes = fs::read(&dest).unwrap();
        assert_ne!(new_bytes, old_bytes);
        assert_eq!(summary.snapshot.total, 2);
    }

    #[test]
    fn reset_snapshot_preserves_allow_and_block_overlays() {
        let dir = tempdir().unwrap();
        let (proc_modules, mods_dir, backup_dir) = scratch_snapshot_env(dir.path());
        let snapshot = dir.path().join("allowlist.snapshot.conf");
        let allow = dir.path().join("allowlist.allow.conf");
        let block = dir.path().join("allowlist.block.conf");

        create_snapshot(&snapshot, &proc_modules, &mods_dir, "6.8.0", |_| {
            Some(vec![])
        })
        .unwrap();
        write(&allow, "vfat\n");
        write(&block, "usb_storage\n");
        let allow_before = fs::read(&allow).unwrap();
        let block_before = fs::read(&block).unwrap();

        reset_snapshot(
            &snapshot,
            &proc_modules,
            &mods_dir,
            "6.8.0",
            &backup_dir,
            |_| Some(vec![]),
        )
        .unwrap();

        assert_eq!(fs::read(&allow).unwrap(), allow_before);
        assert_eq!(fs::read(&block).unwrap(), block_before);
    }

    #[test]
    fn reset_snapshot_writes_mode_0o600() {
        let dir = tempdir().unwrap();
        let (proc_modules, mods_dir, backup_dir) = scratch_snapshot_env(dir.path());
        let dest = dir.path().join("snapshot.conf");

        reset_snapshot(
            &dest,
            &proc_modules,
            &mods_dir,
            "6.8.0",
            &backup_dir,
            |_| Some(vec![]),
        )
        .unwrap();
        let mode = fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
