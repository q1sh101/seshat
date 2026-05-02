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
        "etc/sysctl.d",
        "etc/modprobe.d",
        "var/lib/seshat/profiles",
    ] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    let user_profiles = root.join("var/lib/seshat/profiles");
    let profile = user_profiles.join("baseline.toml");
    fs::write(
        &profile,
        "schema_version = 1\nprofile_name = \"baseline\"\n",
    )
    .unwrap();
    fs::set_permissions(&profile, fs::Permissions::from_mode(0o600)).unwrap();
}

fn unit_dir(root: &Path) -> std::path::PathBuf {
    root.join("etc/systemd/system")
}

fn units(root: &Path) -> [std::path::PathBuf; 3] {
    let d = unit_dir(root);
    [
        d.join("kernel-hardening-watch.service"),
        d.join("kernel-hardening-watch.path"),
        d.join("kernel-hardening-watch.timer"),
    ]
}

#[test]
fn watch_install_writes_three_unit_files_under_root() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, _stdout, stderr) = run(tmp.path(), &["watch", "install"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    for u in units(tmp.path()) {
        assert!(u.exists(), "missing unit: {}", u.display());
        let mode = fs::metadata(&u).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644, "wrong mode on {}", u.display());
    }
}

#[test]
fn watch_install_embeds_profile_in_service_unit() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, _stdout, stderr) = run(tmp.path(), &["watch", "install", "--profile", "baseline"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let service = unit_dir(tmp.path()).join("kernel-hardening-watch.service");
    let body = fs::read_to_string(&service).unwrap();
    assert!(
        body.contains("--profile \"baseline\""),
        "service body: {body}"
    );
}

#[test]
fn watch_install_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code_a, _, _) = run(tmp.path(), &["watch", "install"]);
    let (code_b, _, _) = run(tmp.path(), &["watch", "install"]);
    assert_eq!(code_a, 0);
    assert_eq!(code_b, 0);
    for u in units(tmp.path()) {
        assert!(u.exists());
    }
}

#[test]
fn watch_install_rejects_invalid_profile_name() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, _stdout, _stderr) = run(tmp.path(), &["watch", "install", "--profile", "bad name"]);
    assert_ne!(code, 0);
    for u in units(tmp.path()) {
        assert!(
            !u.exists(),
            "unit should not exist after rejected install: {}",
            u.display()
        );
    }
}

#[test]
fn watch_install_refuses_symlinked_unit_dir() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let elsewhere = tempfile::tempdir().unwrap();
    let unit_dir = unit_dir(tmp.path());
    fs::remove_dir_all(&unit_dir).unwrap();
    symlink(elsewhere.path(), &unit_dir).unwrap();

    let (code, _stdout, stderr) = run(tmp.path(), &["watch", "install"]);
    assert_eq!(code, 3, "stderr: {stderr}");
    assert!(stderr.contains("symlink"), "stderr: {stderr}");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn watch_status_before_install_reports_absent() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, stdout, stderr) = run(tmp.path(), &["watch", "status"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("path unit: not installed"),
        "combined: {combined}"
    );
    assert!(
        combined.contains("timer unit: not installed"),
        "combined: {combined}"
    );
    assert!(
        combined.contains("service: not installed"),
        "combined: {combined}"
    );
}

#[test]
fn watch_status_after_install_reports_present() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    run(tmp.path(), &["watch", "install"]);
    let (code, stdout, stderr) = run(tmp.path(), &["watch", "status"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let combined = format!("{stdout}{stderr}");
    assert!(
        combined.contains("path unit: installed"),
        "combined: {combined}"
    );
    assert!(
        combined.contains("timer unit: installed"),
        "combined: {combined}"
    );
    assert!(
        combined.contains("service: installed"),
        "combined: {combined}"
    );
}

#[test]
fn watch_remove_deletes_all_three_units() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    run(tmp.path(), &["watch", "install"]);
    for u in units(tmp.path()) {
        assert!(u.exists());
    }
    let (code, stdout, stderr) = run(tmp.path(), &["watch", "remove"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("service=true"), "stdout: {stdout}");
    assert!(stdout.contains("path=true"), "stdout: {stdout}");
    assert!(stdout.contains("timer=true"), "stdout: {stdout}");
    for u in units(tmp.path()) {
        assert!(!u.exists(), "unit not removed: {}", u.display());
    }
}

#[test]
fn watch_remove_on_empty_state_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    seed(tmp.path());
    let (code, stdout, stderr) = run(tmp.path(), &["watch", "remove"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("service=false"), "stdout: {stdout}");
}
