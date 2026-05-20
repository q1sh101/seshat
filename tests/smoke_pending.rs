use std::fs;
use std::os::unix::fs::PermissionsExt;
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

fn seed_fake_root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(dir.path().join("lib/modules/seshat-smoke")).unwrap();
    fs::create_dir_all(dir.path().join("var/lib/seshat/profiles")).unwrap();
    dir
}

#[test]
fn boot_pending_under_root_reports_unavailable() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, _) = run(&["--root", root, "boot", "pending"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("pending: unavailable"), "stdout: {stdout}");
}

#[test]
fn sysctl_pending_returns_explicit_skip_by_design() {
    let (code, stdout, _) = run(&["sysctl", "pending"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("N/A by design"), "stdout: {stdout}");
    assert!(stdout.contains("drift covers"), "stdout: {stdout}");
}

#[test]
fn module_deny_helper_writes_tsv_entry_to_env_specified_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("pending.log");
    let status = Command::new(env!("CARGO_BIN_EXE_module-deny"))
        .arg("zram")
        .env("SESHAT_PENDING_LOG", &log)
        .status()
        .expect("run module-deny binary");
    assert_eq!(status.code(), Some(1));
    let content = fs::read_to_string(&log).expect("log file written");
    let parts: Vec<&str> = content.trim_end_matches('\n').split('\t').collect();
    assert_eq!(parts.len(), 3, "expected 3 TSV columns: {content:?}");
    assert!(
        parts[0].len() == 20 && parts[0].ends_with('Z'),
        "timestamp should be RFC3339 UTC: {:?}",
        parts[0]
    );
    assert_eq!(parts[1], "zram");
    assert_eq!(parts[2], "helper");
    let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn module_deny_helper_rejects_dangerous_names() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("pending.log");
    let status = Command::new(env!("CARGO_BIN_EXE_module-deny"))
        .arg("evil;rm -rf /")
        .env("SESHAT_PENDING_LOG", &log)
        .status()
        .expect("run module-deny binary");
    assert_eq!(status.code(), Some(1));
    assert!(!log.exists());
}

#[test]
fn module_deny_helper_no_args_still_exits_one_and_no_log() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("pending.log");
    let status = Command::new(env!("CARGO_BIN_EXE_module-deny"))
        .env("SESHAT_PENDING_LOG", &log)
        .status()
        .expect("run module-deny binary");
    assert_eq!(status.code(), Some(1));
    assert!(!log.exists());
}

#[test]
fn module_deny_helper_appends_multiple_entries() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("pending.log");
    for name in ["mod_a", "mod_b", "mod_c"] {
        Command::new(env!("CARGO_BIN_EXE_module-deny"))
            .arg(name)
            .env("SESHAT_PENDING_LOG", &log)
            .status()
            .expect("run module-deny binary");
    }
    let content = fs::read_to_string(&log).unwrap();
    let lines: Vec<&str> = content.lines().collect();
    assert_eq!(lines.len(), 3);
    let names: Vec<&str> = lines
        .iter()
        .map(|l| l.split('\t').nth(1).unwrap())
        .collect();
    assert_eq!(names, vec!["mod_a", "mod_b", "mod_c"]);
}

#[test]
fn module_deny_helper_creates_missing_parent_dir() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("var/lib/seshat/pending.log");
    let status = Command::new(env!("CARGO_BIN_EXE_module-deny"))
        .arg("zram")
        .env("SESHAT_PENDING_LOG", &log)
        .status()
        .expect("run module-deny binary");
    assert_eq!(status.code(), Some(1));
    assert!(
        fs::read_to_string(&log)
            .unwrap()
            .contains("\tzram\thelper\n")
    );
}

#[test]
fn module_deny_helper_tightens_existing_loose_log_mode() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("pending.log");
    fs::write(&log, "").unwrap();
    fs::set_permissions(&log, fs::Permissions::from_mode(0o644)).unwrap();
    let status = Command::new(env!("CARGO_BIN_EXE_module-deny"))
        .arg("zram")
        .env("SESHAT_PENDING_LOG", &log)
        .status()
        .expect("run module-deny binary");
    assert_eq!(status.code(), Some(1));
    let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}
