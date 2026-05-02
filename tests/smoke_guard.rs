use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::Command;

fn run(root: &Path, args: &[&str]) -> (i32, String, String) {
    let full: Vec<&str> = std::iter::once("--root")
        .chain(std::iter::once(root.to_str().unwrap()))
        .chain(args.iter().copied())
        .collect();
    let output = Command::new(env!("CARGO_BIN_EXE_seshat"))
        .args(full)
        .output()
        .expect("run seshat binary");
    let code = output.status.code().unwrap_or(-1);
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (code, stdout, stderr)
}

fn seed(root: &Path) {
    for sub in [
        "etc/systemd/system",
        "proc/sys/kernel",
        "var/lib/seshat/profiles",
    ] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    fs::write(root.join("proc/sys/kernel/modules_disabled"), "0\n").unwrap();
}

fn service_unit(root: &Path) -> std::path::PathBuf {
    root.join("etc/systemd/system/kernel-hardening-guard.service")
}

#[test]
fn guard_install_writes_single_service_unit_at_mode_0644() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, _stdout, stderr) = run(tmp.path(), &["guard", "install"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let unit = service_unit(tmp.path());
    assert!(unit.exists(), "service unit missing");
    let mode = fs::metadata(&unit).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o644);
}

#[test]
fn guard_install_embeds_binary_and_state_root_and_lock_yes_exec() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, _stdout, stderr) = run(tmp.path(), &["guard", "install"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let body = fs::read_to_string(service_unit(tmp.path())).unwrap();
    assert!(
        body.contains("Environment=\"SESHAT_STATE_ROOT="),
        "missing env: {body}"
    );
    assert!(body.contains("lock --yes"), "missing lock --yes: {body}");
    assert!(
        body.contains("WantedBy=multi-user.target"),
        "missing WantedBy: {body}"
    );
}

#[test]
fn guard_install_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (a, _, _) = run(tmp.path(), &["guard", "install"]);
    let (b, _, _) = run(tmp.path(), &["guard", "install"]);
    assert_eq!(a, 0);
    assert_eq!(b, 0);
    assert!(service_unit(tmp.path()).exists());
}

#[test]
fn guard_install_refuses_symlinked_unit_dir() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let elsewhere = tempfile::tempdir().unwrap();
    let unit_dir = tmp.path().join("etc/systemd/system");
    fs::remove_dir_all(&unit_dir).unwrap();
    symlink(elsewhere.path(), &unit_dir).unwrap();
    let (code, _stdout, stderr) = run(tmp.path(), &["guard", "install"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn guard_status_pre_install_reports_absent() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, stdout, stderr) = run(tmp.path(), &["guard", "status"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("service:    installed=false enabled=false"),
        "stdout: {stdout}"
    );
}

#[test]
fn guard_status_post_install_reports_installed() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    run(tmp.path(), &["guard", "install"]);
    let (code, stdout, stderr) = run(tmp.path(), &["guard", "status"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("service:    installed=true"),
        "stdout: {stdout}"
    );
}

#[test]
fn guard_status_reports_modules_disabled_from_proc_file() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    fs::write(tmp.path().join("proc/sys/kernel/modules_disabled"), "1\n").unwrap();
    let (code, stdout, _stderr) = run(tmp.path(), &["guard", "status"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("modules_disabled: 1 (locked)"),
        "stdout: {stdout}"
    );
}

#[test]
fn guard_remove_deletes_service_unit() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    run(tmp.path(), &["guard", "install"]);
    assert!(service_unit(tmp.path()).exists());
    let (code, stdout, stderr) = run(tmp.path(), &["guard", "remove"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("service=true"), "stdout: {stdout}");
    assert!(!service_unit(tmp.path()).exists());
}

#[test]
fn guard_remove_on_empty_state_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, stdout, stderr) = run(tmp.path(), &["guard", "remove"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("service=false"), "stdout: {stdout}");
}
