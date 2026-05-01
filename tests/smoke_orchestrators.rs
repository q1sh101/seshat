use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn run(args: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_seshat"))
        .args(args)
        .output()
        .expect("run seshat binary");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

// Omits etc/sysctl.d, etc/modprobe.d, run/seshat-locks so cross-domain leaks are observable.
fn seed_fake_root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = dir.path();
    for sub in [
        "etc/default/grub.d",
        "etc/kernel",
        "boot/grub",
        "proc/sys/kernel",
        "proc/sys/net/core",
        "sys/kernel/security",
        "lib/modules/seshat-smoke",
        "var/lib/seshat/profiles",
    ] {
        fs::create_dir_all(r.join(sub)).unwrap();
    }
    fs::write(r.join("proc/modules"), "ext4 1 0 - Live 0\n").unwrap();
    fs::write(r.join("lib/modules/seshat-smoke/modules.builtin"), b"").unwrap();
    fs::write(r.join("proc/sys/kernel/kptr_restrict"), "2\n").unwrap();
    fs::write(r.join("proc/sys/net/core/bpf_jit_harden"), "2\n").unwrap();
    fs::write(
        r.join("sys/kernel/security/lockdown"),
        "none [integrity] confidentiality\n",
    )
    .unwrap();
    fs::write(r.join("proc/cmdline"), "rw quiet\n").unwrap();
    fs::write(
        r.join("etc/default/grub"),
        "GRUB_CMDLINE_LINUX_DEFAULT=\"rw quiet\"\n",
    )
    .unwrap();
    fs::write(r.join("etc/kernel/cmdline"), "rw quiet\n").unwrap();
    fs::write(r.join("boot/grub/grub.cfg"), "# managed\n").unwrap();
    fs::write(r.join("proc/sys/kernel/modules_disabled"), "0\n").unwrap();
    seed_baseline_profile(&r.join("var/lib/seshat/profiles/baseline.toml"));
    dir
}

fn seed_baseline_profile(path: &Path) {
    let body = r#"schema_version = 1
profile_name = "smoke-baseline"

[modules]
mode = "allowlist"
block = []

[[sysctl]]
key = "kernel.kptr_restrict"
value = "2"

[[sysctl]]
key = "net.core.bpf_jit_harden"
value = "2"
"#;
    fs::write(path, body).unwrap();
}

fn profiles_dir(root: &Path) -> PathBuf {
    root.join("var/lib/seshat/profiles")
}

#[test]
fn deploy_sysctl_writes_sysctl_tree_only() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "deploy", "sysctl"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("deploy sysctl"), "stdout: {stdout}");
    assert!(
        tmp.path()
            .join("etc/sysctl.d/99-kernel-hardening.conf")
            .exists()
    );
    assert!(
        !tmp.path().join("etc/modprobe.d").exists(),
        "modprobe tree must NOT be created for deploy sysctl"
    );
    assert!(
        !tmp.path()
            .join("var/lib/seshat/profiles/backups-modprobe")
            .exists(),
        "modprobe backup dir must NOT be created for deploy sysctl"
    );
    assert!(
        !tmp.path().join("run/seshat-locks").exists(),
        "lock_root must NOT be created for single-domain deploy"
    );
}

#[test]
fn deploy_modules_writes_modprobe_tree_only() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let (code, stdout, stderr) = run(&["--root", root, "deploy", "modules"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("deploy modules"), "stdout: {stdout}");
    assert!(
        tmp.path()
            .join("etc/modprobe.d/99-kernel-hardening.conf")
            .exists()
    );
    assert!(
        !tmp.path().join("etc/sysctl.d").exists(),
        "sysctl tree must NOT be created for deploy modules"
    );
    assert!(
        !tmp.path()
            .join("var/lib/seshat/profiles/backups-sysctl")
            .exists(),
        "sysctl backup dir must NOT be created for deploy modules"
    );
    assert!(
        !tmp.path().join("run/seshat-locks").exists(),
        "lock_root must NOT be created for single-domain deploy"
    );
}

#[test]
fn deploy_boot_without_profile_args_skips_and_writes_nothing() {
    // Boot-only deploy should skip cleanly when the profile has no boot args.
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "deploy", "boot"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("profile has no boot args"),
        "combined: {combined}"
    );
    assert!(
        !tmp.path()
            .join("etc/sysctl.d/99-kernel-hardening.conf")
            .exists()
    );
    assert!(
        !tmp.path()
            .join("etc/modprobe.d/99-kernel-hardening.conf")
            .exists()
    );
    assert!(fs::read_to_string(tmp.path().join("boot/grub/grub.cfg")).unwrap() == "# managed\n");
}

#[test]
fn deploy_all_covers_sysctl_and_modules_with_boot_reported_refused() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let (code, stdout, stderr) = run(&["--root", root, "deploy", "all"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("deploy sysctl"));
    assert!(stdout.contains("deploy modules"));
    // Baseline profile has no [[boot]] args; orchestrator reports a skip reason.
    assert!(stdout.contains("profile has no boot args"));
    assert!(
        tmp.path()
            .join("etc/sysctl.d/99-kernel-hardening.conf")
            .exists()
    );
    assert!(
        tmp.path()
            .join("etc/modprobe.d/99-kernel-hardening.conf")
            .exists()
    );
    assert!(
        tmp.path().join("run/seshat-locks").exists(),
        "deploy all must create lock_root for the orchestrator lock"
    );
}

#[test]
fn deploy_all_repairs_lock_root_mode_to_0700_under_umask_022() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    // Pre-create lock_root with the wrong mode umask 022 would produce.
    let lock_root = tmp.path().join("run/seshat-locks");
    fs::create_dir_all(&lock_root).unwrap();
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let (code, _, stderr) = run(&["--root", root, "deploy", "all"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let mode = fs::metadata(&lock_root).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "lock_root must be repaired to 0700");
}

#[test]
fn deploy_all_refuses_symlink_as_lock_root() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let real_elsewhere = tempfile::tempdir().unwrap();
    let link = tmp.path().join("run/seshat-locks");
    fs::create_dir_all(tmp.path().join("run")).unwrap();
    std::os::unix::fs::symlink(real_elsewhere.path(), &link).unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let (code, _, stderr) = run(&["--root", root, "deploy", "all"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
}

#[test]
fn plan_sysctl_reports_only_sysctl_section() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "plan", "sysctl"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("plan sysctl:"), "stdout: {stdout}");
    assert!(!stdout.contains("plan modules:"));
    assert!(!stdout.contains("plan boot:"));
}

#[test]
fn plan_all_reports_all_three_domains() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "plan", "all"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("plan sysctl:"));
    assert!(stdout.contains("plan modules:"));
    assert!(stdout.contains("plan boot:"));
}

#[test]
fn verify_modules_reports_only_modules_section() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "verify", "modules"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("verify modules:"), "stdout: {stdout}");
    assert!(!stdout.contains("verify sysctl:"));
    assert!(!stdout.contains("verify boot:"));
}

#[test]
fn status_all_reports_all_domains_with_fingerprints() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "status", "all"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(combined.contains("sysctl:"));
    assert!(combined.contains("modules:"));
    assert!(combined.contains("boot:"));
    assert!(combined.contains("lock:"));
}

#[test]
fn profile_default_loads_baseline_toml() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "plan"]);
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn profile_named_loads_custom_toml() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    seed_baseline_profile(&profiles_dir(tmp.path()).join("custom.toml"));
    let (code, _, stderr) = run(&["--root", root, "plan", "--profile", "custom"]);
    assert_eq!(code, 0, "stderr: {stderr}");
}

#[test]
fn profile_path_traversal_is_refused_before_filesystem_touch() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "plan", "--profile", "../evil"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("profile_name") || stderr.contains("validation"),
        "stderr: {stderr}"
    );
}

#[test]
fn profile_absolute_path_is_refused() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "plan", "--profile", "/tmp/evil"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("profile_name") || stderr.contains("validation"),
        "stderr: {stderr}"
    );
}

#[test]
fn profile_empty_name_is_refused() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "plan", "--profile", ""]);
    assert_eq!(code, 1);
    assert!(stderr.contains("profile_name"), "stderr: {stderr}");
}

#[test]
fn plan_missing_profile_file_exits_one_with_clear_error() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "plan", "--profile", "nonexistent"]);
    assert_eq!(code, 1);
    assert!(
        stderr.contains("nonexistent") || stderr.contains("No such file"),
        "stderr: {stderr}"
    );
}

#[test]
fn verify_sysctl_matching_live_values_exits_zero() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "verify", "sysctl"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("verify sysctl:"), "stdout: {stdout}");
}

#[test]
fn verify_sysctl_with_drift_exits_one() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    fs::write(tmp.path().join("proc/sys/kernel/kptr_restrict"), "0\n").unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "verify", "sysctl"]);
    assert_eq!(code, 1, "stdout: {stdout}, stderr: {stderr}");
}

#[test]
fn verify_modules_snapshot_present_but_dropin_missing_exits_one() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    // Snapshot configured but no deploy yet → managed drop-in missing → Fail row.
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let (code, stdout, stderr) = run(&["--root", root, "verify", "modules"]);
    assert_eq!(code, 1, "stdout: {stdout}, stderr: {stderr}");
}

#[test]
fn status_reports_fake_boot_grub_under_root() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "status", "boot"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("boot:"), "stdout: {stdout}");
}

#[test]
fn plan_refuses_filesystem_root_via_canonical_guard() {
    let (code, _, stderr) = run(&["--root", "/", "plan"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("filesystem-root") || stderr.contains("filesystem root"),
        "stderr: {stderr}"
    );
}

#[test]
fn deploy_refuses_missing_root_and_creates_nothing() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("does_not_exist");
    let (code, _, _) = run(&["--root", missing.to_str().unwrap(), "deploy", "sysctl"]);
    assert_eq!(code, 2);
    assert!(!missing.exists());
}

#[test]
fn deploy_sysctl_refuses_symlinked_backup_dir() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let dir = profiles_dir(tmp.path());
    fs::create_dir_all(&dir).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), dir.join("backups-sysctl")).unwrap();
    let (code, _, stderr) = run(&["--root", root, "deploy", "sysctl"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    // Nothing may have leaked into the symlink target.
    assert_eq!(
        fs::read_dir(elsewhere.path()).unwrap().count(),
        0,
        "backup leaked outside <root> via symlinked backup dir"
    );
}

#[test]
fn deploy_modules_refuses_symlinked_backup_dir() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let elsewhere = tempfile::tempdir().unwrap();
    let dir = profiles_dir(tmp.path());
    std::os::unix::fs::symlink(elsewhere.path(), dir.join("backups-modprobe")).unwrap();
    let (code, _, stderr) = run(&["--root", root, "deploy", "modules"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn deploy_sysctl_refuses_symlinked_target_parent() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("etc")).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join("etc/sysctl.d")).unwrap();
    let (code, _, stderr) = run(&["--root", root, "deploy", "sysctl"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn deploy_modules_refuses_symlinked_target_parent() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let elsewhere = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("etc")).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join("etc/modprobe.d")).unwrap();
    let (code, _, stderr) = run(&["--root", root, "deploy", "modules"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn modules_allow_refuses_symlinked_backup_dir() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    // Seed allow.conf so next allow stages a backup (backups-modprobe is lazy).
    assert_eq!(run(&["--root", root, "modules", "allow", "vfat"]).0, 0);
    let elsewhere = tempfile::tempdir().unwrap();
    let symlink_path = profiles_dir(tmp.path()).join("backups-modprobe");
    fs::remove_dir_all(&symlink_path).ok();
    std::os::unix::fs::symlink(elsewhere.path(), &symlink_path).unwrap();
    let (code, _, stderr) = run(&["--root", root, "modules", "allow", "ext4"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn deploy_all_refuses_symlinked_boot_backup_dir() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    let elsewhere = tempfile::tempdir().unwrap();
    let dir = profiles_dir(tmp.path());
    std::os::unix::fs::symlink(elsewhere.path(), dir.join("backups-boot")).unwrap();
    let (code, _, stderr) = run(&["--root", root, "deploy", "all"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn deploy_all_refuses_symlinked_grub_config_d() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    // Seed seed_fake_root creates etc/default/grub.d as a real dir; replace it with a symlink.
    let grub_d = tmp.path().join("etc/default/grub.d");
    fs::remove_dir_all(&grub_d).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), &grub_d).unwrap();
    let (code, _, stderr) = run(&["--root", root, "deploy", "all"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn deploy_all_refuses_symlinked_grub_config_parent() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    assert_eq!(run(&["--root", root, "snapshot"]).0, 0);
    // Replace <root>/etc/default with a symlink to trigger refuse at grub_config.parent().
    let etc_default = tmp.path().join("etc/default");
    fs::remove_dir_all(&etc_default).unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), &etc_default).unwrap();
    let (code, _, stderr) = run(&["--root", root, "deploy", "all"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}
