use std::path::{Path, PathBuf};

use crate::boot::{self, Backend};
use crate::error::Error;
use crate::modules;
use crate::policy::{ModuleName, Profile};
use crate::sysctl::{self, SysctlSetting};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DriftState {
    Sync,
    Drift,
    Missing,
    Unknown,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SysctlStatus {
    pub drop_in_path: PathBuf,
    pub drop_in_hash: Option<String>,
    pub drop_in_mode: Option<u32>,
    pub drift: DriftState,
    pub backup_count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ModulesStatus {
    pub drop_in_path: PathBuf,
    pub drop_in_hash: Option<String>,
    pub drop_in_mode: Option<u32>,
    pub drift: DriftState,
    pub backup_count: usize,
    pub snapshot_present: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BootStatus {
    pub backend: Backend,
}

#[derive(Debug, PartialEq, Eq)]
pub struct LockStatus {
    pub modules_disabled: Option<String>,
}

#[derive(Debug)]
pub struct StatusReport {
    pub sysctl: SysctlStatus,
    pub modules: ModulesStatus,
    pub boot: BootStatus,
    pub lock: LockStatus,
}

pub struct StatusInputs<'a> {
    pub profile: &'a Profile,
    pub modules_dir: &'a Path,
    pub snapshot_path: &'a Path,
    pub allow_path: &'a Path,
    pub block_path: &'a Path,
    pub sysctl_drop_in: &'a Path,
    pub sysctl_backup_dir: &'a Path,
    pub modprobe_drop_in: &'a Path,
    pub modprobe_backup_dir: &'a Path,
    pub grub_config: &'a Path,
    pub grub_config_d: &'a Path,
    pub grub_cfg: &'a Path,
    pub kernel_cmdline: &'a Path,
    pub modules_disabled_path: &'a Path,
}

pub fn orchestrate_status<F>(inputs: &StatusInputs<'_>, has_command: F) -> StatusReport
where
    F: Fn(&str) -> bool,
{
    StatusReport {
        sysctl: sysctl_status(inputs),
        modules: modules_status(inputs),
        boot: boot_status(inputs, has_command),
        lock: lock_status(inputs),
    }
}

// FNV-1a 64-bit for short deterministic fingerprints; not a security hash.
fn fnv1a_64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut h = OFFSET;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

pub fn fingerprint(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a_64(bytes))
}

// Refuse symlinks: status must not fingerprint a target substituted for the real drop-in.
fn read_safe_regular_file(path: &Path) -> Option<(Vec<u8>, u32)> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::symlink_metadata(path).ok()?;
    if !meta.file_type().is_file() {
        return None;
    }
    let mode = meta.permissions().mode() & 0o777;
    let bytes = std::fs::read(path).ok()?;
    Some((bytes, mode))
}

fn count_backups(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| {
            let Ok(meta) = e.metadata() else {
                return false;
            };
            if !meta.file_type().is_file() {
                return false;
            }
            e.file_name().to_str().is_some_and(|n| !n.starts_with('.'))
        })
        .count()
}

fn sysctl_status(inputs: &StatusInputs<'_>) -> SysctlStatus {
    let live = read_safe_regular_file(inputs.sysctl_drop_in);
    let drift = compute_sysctl_drift(inputs, live.as_ref().map(|(b, _)| b.as_slice()));
    let (hash, mode) = match live {
        Some((bytes, mode)) => (Some(fingerprint(&bytes)), Some(mode)),
        None => (None, None),
    };
    SysctlStatus {
        drop_in_path: inputs.sysctl_drop_in.to_path_buf(),
        drop_in_hash: hash,
        drop_in_mode: mode,
        drift,
        backup_count: count_backups(inputs.sysctl_backup_dir),
    }
}

fn modules_status(inputs: &StatusInputs<'_>) -> ModulesStatus {
    let live = read_safe_regular_file(inputs.modprobe_drop_in);
    let drift = compute_modules_drift(inputs, live.as_ref().map(|(b, _)| b.as_slice()));
    let (hash, mode) = match live {
        Some((bytes, mode)) => (Some(fingerprint(&bytes)), Some(mode)),
        None => (None, None),
    };
    ModulesStatus {
        drop_in_path: inputs.modprobe_drop_in.to_path_buf(),
        drop_in_hash: hash,
        drop_in_mode: mode,
        drift,
        backup_count: count_backups(inputs.modprobe_backup_dir),
        snapshot_present: inputs.snapshot_path.exists(),
    }
}

fn compute_sysctl_drift(inputs: &StatusInputs<'_>, live: Option<&[u8]>) -> DriftState {
    let Ok(settings): Result<Vec<SysctlSetting>, Error> = inputs
        .profile
        .sysctl
        .iter()
        .map(SysctlSetting::from_entry)
        .collect()
    else {
        return DriftState::Unknown;
    };
    let expected = sysctl::generate_sysctl_dropin(&settings, inputs.profile.profile_name.as_str());
    match live {
        None => drift_when_unreadable(inputs.sysctl_drop_in),
        Some(bytes) => {
            let Ok(live_text) = std::str::from_utf8(bytes) else {
                return DriftState::Unknown;
            };
            if sysctl_payload_lines(&expected) == sysctl_payload_lines(live_text) {
                DriftState::Sync
            } else {
                DriftState::Drift
            }
        }
    }
}

// symlink_metadata does not follow symlinks: a dangling symlink is Unknown, not Missing.
fn drift_when_unreadable(path: &Path) -> DriftState {
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DriftState::Missing,
        _ => DriftState::Unknown,
    }
}

// Profile order is meaningful for sysctl, so preserve order but skip comments/blanks.
fn sysctl_payload_lines(s: &str) -> Vec<&str> {
    s.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect()
}

fn compute_modules_drift(inputs: &StatusInputs<'_>, live: Option<&[u8]>) -> DriftState {
    let Ok(snapshot) = read_optional_allowlist(inputs.snapshot_path) else {
        return DriftState::Unknown;
    };
    let Some(snapshot) = snapshot else {
        return DriftState::Unknown;
    };
    let Ok(allow) = read_optional_allowlist(inputs.allow_path) else {
        return DriftState::Unknown;
    };
    let Ok(file_block) = read_optional_allowlist(inputs.block_path) else {
        return DriftState::Unknown;
    };
    let Ok(profile_block): Result<Vec<ModuleName>, Error> = inputs
        .profile
        .modules
        .block
        .iter()
        .map(|s| ModuleName::new(s))
        .collect()
    else {
        return DriftState::Unknown;
    };
    let mut combined_block = file_block.unwrap_or_default();
    combined_block.extend(profile_block);

    let effective =
        modules::effective_allowlist(&snapshot, allow.as_deref().unwrap_or(&[]), &combined_block);
    let Ok(installed) = modules::scan_installed_modules(inputs.modules_dir) else {
        return DriftState::Unknown;
    };
    let expected = modules::generate_modprobe_dropin(
        &effective,
        &installed,
        inputs.profile.profile_name.as_str(),
    );
    match live {
        None => drift_when_unreadable(inputs.modprobe_drop_in),
        Some(bytes) => {
            let Ok(live_text) = std::str::from_utf8(bytes) else {
                return DriftState::Unknown;
            };
            if modules::payload_signature(&expected) == modules::payload_signature(live_text) {
                DriftState::Sync
            } else {
                DriftState::Drift
            }
        }
    }
}

fn read_optional_allowlist(path: &Path) -> Result<Option<Vec<ModuleName>>, Error> {
    match modules::parse_allowlist(path) {
        Ok(v) => Ok(Some(v)),
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn boot_status<F>(inputs: &StatusInputs<'_>, has_command: F) -> BootStatus
where
    F: Fn(&str) -> bool,
{
    BootStatus {
        backend: boot::detect_backend(
            inputs.grub_config,
            inputs.grub_config_d,
            inputs.grub_cfg,
            inputs.kernel_cmdline,
            has_command,
        ),
    }
}

fn lock_status(inputs: &StatusInputs<'_>) -> LockStatus {
    let modules_disabled = std::fs::read_to_string(inputs.modules_disabled_path)
        .ok()
        .map(|s| s.trim().to_string());
    LockStatus { modules_disabled }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{BootEntry, LockdownSection, ModulesSection, SysctlEntry};
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::tempdir;

    struct Env {
        _root: tempfile::TempDir,
        modules_dir: PathBuf,
        snapshot_path: PathBuf,
        allow_path: PathBuf,
        block_path: PathBuf,
        sysctl_drop_in: PathBuf,
        sysctl_backup_dir: PathBuf,
        modprobe_drop_in: PathBuf,
        modprobe_backup_dir: PathBuf,
        grub_config: PathBuf,
        grub_config_d: PathBuf,
        grub_cfg: PathBuf,
        kernel_cmdline: PathBuf,
        modules_disabled_path: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let modules_dir = root.path().join("lib_modules");
        fs::create_dir_all(&modules_dir).unwrap();
        Env {
            modules_dir,
            snapshot_path: root.path().join("snapshot.conf"),
            allow_path: root.path().join("allow.conf"),
            block_path: root.path().join("block.conf"),
            sysctl_drop_in: root.path().join("etc/sysctl.d/99-test.conf"),
            sysctl_backup_dir: root.path().join("backups/sysctl"),
            modprobe_drop_in: root.path().join("etc/modprobe.d/99-test.conf"),
            modprobe_backup_dir: root.path().join("backups/modules"),
            grub_config: root.path().join("etc/default/grub"),
            grub_config_d: root.path().join("etc/default/grub.d"),
            grub_cfg: root.path().join("boot/grub/grub.cfg"),
            kernel_cmdline: root.path().join("etc/kernel/cmdline"),
            modules_disabled_path: root.path().join("proc/sys/kernel/modules_disabled"),
            _root: root,
        }
    }

    fn inputs<'a>(env: &'a Env, prof: &'a Profile) -> StatusInputs<'a> {
        StatusInputs {
            profile: prof,
            modules_dir: &env.modules_dir,
            snapshot_path: &env.snapshot_path,
            allow_path: &env.allow_path,
            block_path: &env.block_path,
            sysctl_drop_in: &env.sysctl_drop_in,
            sysctl_backup_dir: &env.sysctl_backup_dir,
            modprobe_drop_in: &env.modprobe_drop_in,
            modprobe_backup_dir: &env.modprobe_backup_dir,
            grub_config: &env.grub_config,
            grub_config_d: &env.grub_config_d,
            grub_cfg: &env.grub_cfg,
            kernel_cmdline: &env.kernel_cmdline,
            modules_disabled_path: &env.modules_disabled_path,
        }
    }

    fn profile(sysctl: Vec<(&str, &str)>, boot: Vec<&str>, modules_block: Vec<&str>) -> Profile {
        Profile {
            schema_version: 1,
            profile_name: "test".to_string(),
            modules: ModulesSection {
                mode: Some("allowlist".to_string()),
                block: modules_block.iter().map(|s| s.to_string()).collect(),
            },
            sysctl: sysctl
                .into_iter()
                .map(|(k, v)| SysctlEntry {
                    key: k.to_string(),
                    value: v.to_string(),
                })
                .collect(),
            boot: boot
                .into_iter()
                .map(|a| BootEntry { arg: a.to_string() })
                .collect(),
            lockdown: LockdownSection::default(),
        }
    }

    fn write_with_mode(path: &Path, body: &str, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    fn write_snapshot(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn seed_installed_modules(env: &Env, names: &[&str]) {
        let kernel_dir = env.modules_dir.join("kernel");
        fs::create_dir_all(&kernel_dir).unwrap();
        for n in names {
            fs::write(kernel_dir.join(format!("{n}.ko")), "").unwrap();
        }
    }

    fn no_command(_: &str) -> bool {
        false
    }

    #[test]
    fn fingerprint_is_deterministic_for_same_content() {
        assert_eq!(fingerprint(b"hello"), fingerprint(b"hello"));
    }

    #[test]
    fn fingerprint_differs_between_content_versions() {
        assert_ne!(fingerprint(b"hello"), fingerprint(b"hello "));
    }

    #[test]
    fn fingerprint_output_is_16_hex_chars() {
        let fp = fingerprint(b"content");
        assert_eq!(fp.len(), 16);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn sysctl_status_missing_when_drop_in_absent() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert!(report.sysctl.drop_in_hash.is_none());
        assert!(report.sysctl.drop_in_mode.is_none());
        assert_eq!(report.sysctl.drift, DriftState::Missing);
    }

    #[test]
    fn sysctl_status_sync_when_drop_in_matches_profile() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let expected = sysctl::generate_sysctl_dropin(
            &[SysctlSetting::new("kernel.kptr_restrict", "2").unwrap()],
            "test",
        );
        write_with_mode(&env.sysctl_drop_in, &expected, 0o644);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.drift, DriftState::Sync);
        assert_eq!(report.sysctl.drop_in_mode, Some(0o644));
    }

    #[test]
    fn sysctl_status_drift_when_drop_in_differs_from_profile() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        write_with_mode(&env.sysctl_drop_in, "kernel.kptr_restrict = 0\n", 0o644);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.drift, DriftState::Drift);
    }

    #[test]
    fn sysctl_status_refuses_symlink_drop_in() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let real = env.sysctl_backup_dir.join("real.conf");
        fs::create_dir_all(&env.sysctl_backup_dir).unwrap();
        fs::write(&real, "malicious content\n").unwrap();
        fs::create_dir_all(env.sysctl_drop_in.parent().unwrap()).unwrap();
        symlink(&real, &env.sysctl_drop_in).unwrap();
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert!(report.sysctl.drop_in_hash.is_none());
        assert!(report.sysctl.drop_in_mode.is_none());
        assert_eq!(report.sysctl.drift, DriftState::Unknown);
    }

    #[test]
    fn modules_status_missing_when_drop_in_absent() {
        let env = env();
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.modules.drift, DriftState::Missing);
    }

    #[test]
    fn modules_status_sync_when_drop_in_matches_effective_policy() {
        let env = env();
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4", "vfat"]);
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let expected = modules::generate_modprobe_dropin(
            &effective,
            &["ext4".to_string(), "vfat".to_string()],
            "test",
        );
        write_with_mode(&env.modprobe_drop_in, &expected, 0o644);
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.modules.drift, DriftState::Sync);
    }

    #[test]
    fn modules_status_drift_when_drop_in_differs() {
        let env = env();
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4", "vfat"]);
        write_with_mode(&env.modprobe_drop_in, "# stale\n", 0o644);
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.modules.drift, DriftState::Drift);
    }

    #[test]
    fn modules_status_drift_unknown_without_snapshot() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.modules.drift, DriftState::Unknown);
        assert!(!report.modules.snapshot_present);
    }

    #[test]
    fn modules_status_refuses_symlink_drop_in() {
        let env = env();
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let real = env.modprobe_backup_dir.join("real.conf");
        fs::create_dir_all(&env.modprobe_backup_dir).unwrap();
        fs::write(&real, "malicious\n").unwrap();
        fs::create_dir_all(env.modprobe_drop_in.parent().unwrap()).unwrap();
        symlink(&real, &env.modprobe_drop_in).unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert!(report.modules.drop_in_hash.is_none());
        assert_eq!(report.modules.drift, DriftState::Unknown);
    }

    #[test]
    fn backup_count_returns_zero_when_dir_missing() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.backup_count, 0);
    }

    #[test]
    fn backup_count_only_counts_regular_files_not_dirs_or_dotfiles() {
        let env = env();
        fs::create_dir_all(&env.sysctl_backup_dir).unwrap();
        fs::write(env.sysctl_backup_dir.join("backup.1"), "").unwrap();
        fs::write(env.sysctl_backup_dir.join("backup.2"), "").unwrap();
        fs::create_dir(env.sysctl_backup_dir.join("subdir")).unwrap();
        fs::write(env.sysctl_backup_dir.join(".seshat-backup.tmp"), "").unwrap();
        fs::write(env.sysctl_backup_dir.join(".hidden"), "").unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.backup_count, 2);
    }

    #[test]
    fn backup_count_skips_symlinks_in_backup_dir() {
        let env = env();
        fs::create_dir_all(&env.sysctl_backup_dir).unwrap();
        let real = env.sysctl_backup_dir.join("real.backup");
        fs::write(&real, "").unwrap();
        symlink(&real, env.sysctl_backup_dir.join("link.backup")).unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.backup_count, 1);
    }

    #[test]
    fn boot_backend_reports_unknown_when_no_markers_present() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.boot.backend, Backend::Unknown);
    }

    #[test]
    fn boot_backend_reports_systemd_boot_when_kernel_cmdline_present() {
        let env = env();
        write_with_mode(&env.kernel_cmdline, "rw\n", 0o644);
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.boot.backend, Backend::SystemdBoot);
    }

    #[test]
    fn lock_status_reports_modules_disabled_value() {
        let env = env();
        fs::create_dir_all(env.modules_disabled_path.parent().unwrap()).unwrap();
        fs::write(&env.modules_disabled_path, "1\n").unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.lock.modules_disabled.as_deref(), Some("1"));
    }

    #[test]
    fn lock_status_returns_none_when_unreadable() {
        let env = env();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert!(report.lock.modules_disabled.is_none());
    }

    #[test]
    fn orchestrator_aggregates_all_four_domains_with_drift() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let expected = sysctl::generate_sysctl_dropin(
            &[SysctlSetting::new("kernel.kptr_restrict", "2").unwrap()],
            "test",
        );
        write_with_mode(&env.sysctl_drop_in, &expected, 0o644);
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let modprobe_expected =
            modules::generate_modprobe_dropin(&effective, &["ext4".to_string()], "test");
        write_with_mode(&env.modprobe_drop_in, &modprobe_expected, 0o644);
        write_with_mode(&env.kernel_cmdline, "rw\n", 0o644);
        fs::create_dir_all(env.modules_disabled_path.parent().unwrap()).unwrap();
        fs::write(&env.modules_disabled_path, "0").unwrap();

        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.drift, DriftState::Sync);
        assert_eq!(report.modules.drift, DriftState::Sync);
        assert_eq!(report.boot.backend, Backend::SystemdBoot);
        assert_eq!(report.lock.modules_disabled.as_deref(), Some("0"));
    }

    #[test]
    fn sysctl_status_sync_when_only_comments_and_blanks_differ() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let tampered = "\
# operator added this header
# another comment line

kernel.kptr_restrict = 2

# trailing comment
";
        write_with_mode(&env.sysctl_drop_in, tampered, 0o644);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.drift, DriftState::Sync);
    }

    #[test]
    fn sysctl_status_drift_when_payload_changes_regardless_of_comments() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let tampered = "\
# looks innocent
kernel.kptr_restrict = 0
";
        write_with_mode(&env.sysctl_drop_in, tampered, 0o644);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.drift, DriftState::Drift);
    }

    #[test]
    fn modules_status_sync_when_only_comments_and_blanks_differ() {
        let env = env();
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4", "vfat"]);
        let prof = profile(vec![], vec![], vec![]);
        let tampered = "\
# operator added this
install vfat /bin/false

# trailing
";
        write_with_mode(&env.modprobe_drop_in, tampered, 0o644);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.modules.drift, DriftState::Sync);
    }

    #[test]
    fn modules_status_drift_when_extra_payload_line_added() {
        let env = env();
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4", "vfat"]);
        let prof = profile(vec![], vec![], vec![]);
        let tampered = "\
# header
install vfat /bin/false
install sneaky_extra /bin/false
";
        write_with_mode(&env.modprobe_drop_in, tampered, 0o644);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.modules.drift, DriftState::Drift);
    }

    #[test]
    fn sysctl_status_unknown_not_missing_for_dangling_symlink() {
        let env = env();
        let prof = profile(vec![("kernel.kptr_restrict", "2")], vec![], vec![]);
        let nonexistent = env.sysctl_backup_dir.join("nowhere.conf");
        fs::create_dir_all(env.sysctl_drop_in.parent().unwrap()).unwrap();
        symlink(&nonexistent, &env.sysctl_drop_in).unwrap();
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.drift, DriftState::Unknown);
        assert!(report.sysctl.drop_in_hash.is_none());
    }

    #[test]
    fn modules_status_unknown_not_missing_for_dangling_symlink() {
        let env = env();
        write_snapshot(&env.snapshot_path, "ext4\n");
        seed_installed_modules(&env, &["ext4"]);
        let nonexistent = env.modprobe_backup_dir.join("nowhere.conf");
        fs::create_dir_all(env.modprobe_drop_in.parent().unwrap()).unwrap();
        symlink(&nonexistent, &env.modprobe_drop_in).unwrap();
        let prof = profile(vec![], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.modules.drift, DriftState::Unknown);
    }

    #[test]
    fn sysctl_drift_unknown_when_profile_has_invalid_entry() {
        let env = env();
        write_with_mode(&env.sysctl_drop_in, "anything\n", 0o644);
        let prof = profile(vec![("Invalid.Uppercase", "2")], vec![], vec![]);
        let report = orchestrate_status(&inputs(&env, &prof), no_command);
        assert_eq!(report.sysctl.drift, DriftState::Unknown);
    }
}
