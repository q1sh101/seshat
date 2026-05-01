use std::fs;
use std::os::unix::fs::PermissionsExt;
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

fn run_with_env(args: &[&str], key: &str, val: &str) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_seshat"))
        .args(args)
        .env(key, val)
        .output()
        .expect("run seshat binary");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn seed_fake_root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let r = dir.path();
    for sub in [
        "etc/default/grub.d",
        "etc/kernel",
        "boot/grub",
        "proc/sys/kernel",
        "sys/kernel/security",
        "lib/modules/seshat-smoke",
        "var/lib/seshat/profiles",
    ] {
        fs::create_dir_all(r.join(sub)).unwrap();
    }
    fs::write(r.join("proc/modules"), "ext4 1 0 - Live 0\n").unwrap();
    fs::write(r.join("lib/modules/seshat-smoke/modules.builtin"), b"").unwrap();
    fs::write(r.join("proc/sys/kernel/kptr_restrict"), "2\n").unwrap();
    fs::write(r.join("proc/sys/kernel/modules_disabled"), "0\n").unwrap();
    fs::write(r.join("sys/kernel/security/lockdown"), "[none]\n").unwrap();
    fs::write(r.join("proc/cmdline"), "rw\n").unwrap();
    fs::write(r.join("etc/kernel/cmdline"), "rw\n").unwrap();
    fs::write(r.join("boot/grub/grub.cfg"), "# managed\n").unwrap();
    fs::write(
        r.join("etc/default/grub"),
        "GRUB_CMDLINE_LINUX_DEFAULT=\"rw\"\n",
    )
    .unwrap();
    seed_profile(&r.join("var/lib/seshat/profiles/baseline.toml"));
    dir
}

fn seed_profile(path: &Path) {
    fs::write(
        path,
        r#"schema_version = 1
profile_name = "smoke"

[[sysctl]]
key = "kernel.kptr_restrict"
value = "2"
"#,
    )
    .unwrap();
}

fn backup_dir(root: &Path, domain: &str) -> PathBuf {
    root.join(format!("var/lib/seshat/profiles/backups-{domain}"))
}

fn seed_sysctl_backup(root: &Path) -> PathBuf {
    let dir = backup_dir(root, "sysctl");
    fs::create_dir_all(&dir).unwrap();
    let backup = dir.join("99-kernel-hardening.conf.10.000000020.30.bak");
    fs::write(&backup, "kernel.kptr_restrict = 2\n").unwrap();
    backup
}

fn seed_modprobe_backup(root: &Path) -> PathBuf {
    let dir = backup_dir(root, "modprobe");
    fs::create_dir_all(&dir).unwrap();
    let backup = dir.join("99-kernel-hardening.conf.10.000000020.30.bak");
    fs::write(&backup, "# prior managed\ninstall vfat /bin/false\n").unwrap();
    backup
}

#[test]
fn rollback_boot_exits_three_and_writes_nothing() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "rollback", "--yes", "boot"]);
    assert_eq!(code, 3);
    assert!(
        stderr.contains("boot rollback not implemented"),
        "stderr: {stderr}"
    );
    // Boot refusal must not create lock_root or touch any domain tree.
    assert!(!tmp.path().join("run/seshat-locks").exists());
    assert!(!tmp.path().join("etc/sysctl.d").exists());
    assert!(!tmp.path().join("etc/modprobe.d").exists());
}

#[test]
fn rollback_noninteractive_without_yes_is_refused_and_creates_nothing() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "rollback", "all"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("--yes") || stderr.contains("noninteractive"));
    // Refused auth path must not create any dirs.
    assert!(!tmp.path().join("run/seshat-locks").exists());
    assert!(!tmp.path().join("etc/sysctl.d").exists());
    assert!(!tmp.path().join("etc/modprobe.d").exists());
}

#[test]
fn rollback_sysctl_with_backup_restores_drop_in() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let backup = seed_sysctl_backup(tmp.path());
    let (code, stdout, stderr) = run(&["--root", root, "rollback", "--yes", "sysctl"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("rollback sysctl:"), "stdout: {stdout}");
    let dropin = tmp.path().join("etc/sysctl.d/99-kernel-hardening.conf");
    assert!(dropin.exists(), "sysctl drop-in not restored");
    assert_eq!(
        fs::read_to_string(&dropin).unwrap(),
        fs::read_to_string(&backup).unwrap()
    );
}

#[test]
fn rollback_sysctl_no_backup_exits_one() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "rollback", "--yes", "sysctl"]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("no backup") || stderr.contains("sysctl.backup"));
}

#[test]
fn rollback_modules_with_backup_restores_and_warns_about_reboot() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    seed_modprobe_backup(tmp.path());
    let (code, stdout, stderr) = run(&["--root", root, "rollback", "--yes", "modules"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("rollback modules: restored"),
        "stdout: {stdout}"
    );
    assert!(
        stderr.contains("reboot required"),
        "reboot warning missing: {stderr}"
    );
    assert!(
        tmp.path()
            .join("etc/modprobe.d/99-kernel-hardening.conf")
            .exists()
    );
}

#[test]
fn rollback_modules_no_backup_but_target_present_removes_and_warns_about_reboot() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    fs::create_dir_all(tmp.path().join("etc/modprobe.d")).unwrap();
    fs::write(
        tmp.path().join("etc/modprobe.d/99-kernel-hardening.conf"),
        "# stale managed\n",
    )
    .unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "rollback", "--yes", "modules"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("rollback modules: removed"),
        "stdout: {stdout}"
    );
    assert!(stderr.contains("reboot required"));
    assert!(
        !tmp.path()
            .join("etc/modprobe.d/99-kernel-hardening.conf")
            .exists()
    );
}

#[test]
fn rollback_modules_no_backup_no_target_is_nothing_to_rollback_without_reboot_warning() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, _) = run(&["--root", root, "rollback", "--yes", "modules"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("nothing to rollback"), "stdout: {stdout}");
    assert!(!stdout.contains("reboot required"));
    // NothingToRollback path must not pre-create etc/modprobe.d.
    assert!(
        !tmp.path().join("etc/modprobe.d").exists(),
        "NothingToRollback must not pre-create modprobe dir"
    );
}

#[test]
fn rollback_all_with_both_backups_covers_sysctl_and_modules() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    seed_sysctl_backup(tmp.path());
    seed_modprobe_backup(tmp.path());
    let (code, stdout, stderr) = run(&["--root", root, "rollback", "--yes", "all"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("rollback sysctl:"));
    assert!(stdout.contains("rollback modules:"));
}

#[test]
fn rollback_creates_lock_root_at_mode_0700_under_umask_022() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    // Pre-create at wrong mode; rollback must repair.
    let lock_root = tmp.path().join("run/seshat-locks");
    fs::create_dir_all(&lock_root).unwrap();
    fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o755)).unwrap();
    seed_sysctl_backup(tmp.path());
    let (code, _, _) = run(&["--root", root, "rollback", "--yes", "sysctl"]);
    assert_eq!(code, 0);
    let mode = fs::metadata(&lock_root).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
}

#[test]
fn rollback_sysctl_symlink_backup_exits_three_and_leaves_sysctl_dir_absent() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let dir = backup_dir(tmp.path(), "sysctl");
    fs::create_dir_all(&dir).unwrap();
    let real = dir.join("real.data");
    fs::write(&real, b"payload\n").unwrap();
    std::os::unix::fs::symlink(
        &real,
        dir.join("99-kernel-hardening.conf.10.000000020.30.bak"),
    )
    .unwrap();
    let (code, _, stderr) = run(&["--root", root, "rollback", "--yes", "sysctl"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(
        !tmp.path().join("etc/sysctl.d").exists(),
        "symlink backup refusal must not create target parent"
    );
}

#[test]
fn rollback_modules_symlink_backup_exits_three_and_leaves_modprobe_dir_absent() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let dir = backup_dir(tmp.path(), "modprobe");
    fs::create_dir_all(&dir).unwrap();
    let real = dir.join("real.data");
    fs::write(&real, b"payload\n").unwrap();
    std::os::unix::fs::symlink(
        &real,
        dir.join("99-kernel-hardening.conf.10.000000020.30.bak"),
    )
    .unwrap();
    let (code, _, stderr) = run(&["--root", root, "rollback", "--yes", "modules"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(
        !tmp.path().join("etc/modprobe.d").exists(),
        "symlink backup refusal must not create target parent"
    );
}

#[test]
fn rollback_refuses_symlink_lock_root() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    fs::create_dir_all(tmp.path().join("run")).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join("run/seshat-locks")).unwrap();
    let (code, _, stderr) = run(&["--root", root, "rollback", "--yes", "sysctl"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
}

#[test]
fn lock_yes_state_one_reports_already_locked_without_root_probe() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    // state=1 + no SESHAT_SMOKE_AS_ROOT env; already-locked path must short-circuit before root check.
    fs::write(tmp.path().join("proc/sys/kernel/modules_disabled"), "1\n").unwrap();
    let (code, stdout, _) = run(&["--root", root, "lock", "--yes"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("already locked"), "stdout: {stdout}");
}

#[test]
fn lock_yes_state_zero_with_smoke_root_env_writes_one() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, _) = run_with_env(
        &["--root", root, "lock", "--yes"],
        "SESHAT_SMOKE_AS_ROOT",
        "1",
    );
    assert_eq!(code, 0);
    assert!(
        stdout.contains("module loading disabled"),
        "stdout: {stdout}"
    );
    assert_eq!(
        fs::read_to_string(tmp.path().join("proc/sys/kernel/modules_disabled"))
            .unwrap()
            .trim(),
        "1"
    );
}

#[test]
fn lock_yes_state_zero_without_smoke_root_env_exits_three() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "lock", "--yes"]);
    assert_eq!(code, 3);
    assert!(stderr.contains("root"), "stderr: {stderr}");
    assert_eq!(
        fs::read_to_string(tmp.path().join("proc/sys/kernel/modules_disabled"))
            .unwrap()
            .trim(),
        "0"
    );
}

#[test]
fn lock_without_yes_noninteractive_refused() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "lock"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("--yes") || stderr.contains("noninteractive"));
    assert_eq!(
        fs::read_to_string(tmp.path().join("proc/sys/kernel/modules_disabled"))
            .unwrap()
            .trim(),
        "0"
    );
}

#[test]
fn lock_symlink_proc_file_refused_with_exit_three() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let real = tmp.path().join("proc/sys/kernel/real_md");
    fs::write(&real, "0\n").unwrap();
    fs::remove_file(tmp.path().join("proc/sys/kernel/modules_disabled")).unwrap();
    std::os::unix::fs::symlink(&real, tmp.path().join("proc/sys/kernel/modules_disabled")).unwrap();
    let (code, _, stderr) = run_with_env(
        &["--root", root, "lock", "--yes"],
        "SESHAT_SMOKE_AS_ROOT",
        "1",
    );
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
}

#[test]
fn lock_parse_level_root_discipline_still_enforced() {
    let (code, _, stderr) = run(&["--root", "/", "lock", "--yes"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("filesystem root") || stderr.contains("filesystem-root"),
        "stderr: {stderr}"
    );
}
