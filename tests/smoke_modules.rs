use std::fs;
use std::path::Path;
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

// Smoke-root seeder: every test runs against <tmp>; real /proc, /lib/modules, /etc are never touched.
fn seed_fake_root() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    let release_dir = dir.path().join("lib/modules/seshat-smoke");
    fs::create_dir_all(&release_dir).unwrap();
    fs::create_dir_all(dir.path().join("proc")).unwrap();
    fs::create_dir_all(dir.path().join("var/lib/seshat/profiles")).unwrap();
    // Typical /proc/modules line: "name size refs deps state offset"
    fs::write(
        dir.path().join("proc/modules"),
        "ext4 123456 0 - Live 0x0000000000000000\n",
    )
    .unwrap();
    fs::write(release_dir.join("ext4.ko"), b"").unwrap();
    fs::write(release_dir.join("vfat.ko"), b"").unwrap();
    fs::write(
        release_dir.join("modules.builtin"),
        "kernel/builtin/fakebuiltin.ko\n",
    )
    .unwrap();
    dir
}

fn profiles_dir(root: &Path) -> std::path::PathBuf {
    root.join("var/lib/seshat/profiles")
}

#[test]
fn root_filesystem_is_refused_with_exit_two() {
    let (code, _, stderr) = run(&["--root", "/", "modules", "list"]);
    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(
        stderr.contains("may not be the filesystem root"),
        "stderr: {stderr}"
    );
}

#[test]
fn root_must_be_absolute() {
    let (code, _, stderr) = run(&["--root", "relative/path", "modules", "list"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("absolute"), "stderr: {stderr}");
}

#[test]
fn root_without_value_is_refused() {
    let (code, _, stderr) = run(&["--root"]);
    assert_eq!(code, 2);
    assert!(
        stderr.contains("--root requires a value"),
        "stderr: {stderr}"
    );
}

#[test]
fn root_is_refused_when_not_first_position() {
    // parse_globals only looks at args[0]; per-command parser rejects stray --root.
    let (code, _, stderr) = run(&["modules", "list", "--root", "/tmp"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--root"), "stderr: {stderr}");
}

#[test]
fn root_missing_path_is_refused_and_no_tree_created() {
    let parent = tempfile::tempdir().unwrap();
    let missing = parent.path().join("does_not_exist");
    assert!(!missing.exists());
    let (code, _, stderr) = run(&[
        "--root",
        missing.to_str().unwrap(),
        "modules",
        "allow",
        "ext4",
    ]);
    assert_eq!(code, 2);
    assert!(stderr.contains("existing directory"), "stderr: {stderr}");
    assert!(
        !missing.exists(),
        "missing root path was silently created: {}",
        missing.display()
    );
}

#[test]
fn root_pointing_to_regular_file_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("regular");
    fs::write(&file, b"").unwrap();
    let (code, _, stderr) = run(&["--root", file.to_str().unwrap(), "modules", "list"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("directory"), "stderr: {stderr}");
    assert!(fs::metadata(&file).unwrap().is_file());
}

#[test]
fn root_symlink_to_filesystem_root_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("to-root");
    std::os::unix::fs::symlink("/", &link).unwrap();
    let (code, _, stderr) = run(&["--root", link.to_str().unwrap(), "help"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("canonicalizes to /"), "stderr: {stderr}");
}

#[test]
fn root_parent_traversal_that_canonicalizes_to_root_is_refused() {
    let (code, _, stderr) = run(&["--root", "/tmp/..", "help"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("canonicalizes to /"), "stderr: {stderr}");
}

#[test]
fn root_symlink_to_regular_directory_is_accepted_and_uses_canonical_target() {
    let real = tempfile::tempdir().unwrap();
    let link_host = tempfile::tempdir().unwrap();
    let link = link_host.path().join("to-real");
    std::os::unix::fs::symlink(real.path(), &link).unwrap();
    let (code, stdout, stderr) = run(&["--root", link.to_str().unwrap(), "modules", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("effective"), "stdout: {stdout}");
}

#[test]
fn invalid_module_name_exits_one_without_creating_state_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, _, _) = run(&[
        "--root",
        tmp.path().to_str().unwrap(),
        "modules",
        "allow",
        "bad name with spaces",
    ]);
    assert_eq!(code, 1);
    let state = tmp.path().join("var/lib/seshat");
    assert!(
        !state.exists(),
        "state dir must not be created before name validation: {}",
        state.display()
    );
}

#[test]
fn empty_module_name_exits_one_without_filesystem_touch() {
    let tmp = tempfile::tempdir().unwrap();
    let (code, _, _) = run(&[
        "--root",
        tmp.path().to_str().unwrap(),
        "modules",
        "block",
        "",
    ]);
    assert_eq!(code, 1);
    assert!(!tmp.path().join("var/lib/seshat").exists());
}

#[test]
fn modules_allow_creates_allow_file_under_root() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "modules", "allow", "ext4"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("allow: ext4"), "stdout: {stdout}");
    let allow_file = profiles_dir(tmp.path()).join("allowlist.allow.conf");
    assert!(allow_file.exists());
    let body = fs::read_to_string(&allow_file).unwrap();
    assert!(body.contains("ext4"), "allow.conf: {body}");
}

#[test]
fn modules_unallow_after_allow_removes_entry() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let _ = run(&["--root", root, "modules", "allow", "ext4"]);
    let (code, stdout, _) = run(&["--root", root, "modules", "unallow", "ext4"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("unallow: ext4"));
    let allow_file = profiles_dir(tmp.path()).join("allowlist.allow.conf");
    let body = fs::read_to_string(&allow_file).unwrap_or_default();
    assert!(!body.contains("ext4"), "allow.conf still has ext4: {body}");
}

#[test]
fn modules_block_creates_block_file() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, _) = run(&["--root", root, "modules", "block", "vfat"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("block: vfat"));
    let block_file = profiles_dir(tmp.path()).join("allowlist.block.conf");
    assert!(block_file.exists());
    let body = fs::read_to_string(&block_file).unwrap();
    assert!(body.contains("vfat"), "block.conf: {body}");
}

#[test]
fn modules_unblock_after_block_removes_entry() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let _ = run(&["--root", root, "modules", "block", "vfat"]);
    let (code, _, _) = run(&["--root", root, "modules", "unblock", "vfat"]);
    assert_eq!(code, 0);
    let block_file = profiles_dir(tmp.path()).join("allowlist.block.conf");
    let body = fs::read_to_string(&block_file).unwrap_or_default();
    assert!(!body.contains("vfat"), "block.conf still has vfat: {body}");
}

#[test]
fn modules_list_reports_empty_state_cleanly() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, _) = run(&["--root", root, "modules", "list"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("effective: 0 module(s)"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("allow: none"));
    assert!(stdout.contains("block: none"));
}

#[test]
fn modules_list_reflects_prior_allow_edit() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let _ = run(&["--root", root, "modules", "allow", "ext4"]);
    let (code, stdout, _) = run(&["--root", root, "modules", "list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("allow: 1 module(s)"), "stdout: {stdout}");
}

#[test]
fn snapshot_run_writes_snapshot_from_fake_tree() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "snapshot"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("snapshot: wrote"), "stdout: {stdout}");
    let snapshot_file = profiles_dir(tmp.path()).join("allowlist.snapshot.conf");
    assert!(snapshot_file.exists(), "snapshot file missing");
}

#[test]
fn snapshot_reset_without_yes_is_refused_by_parser() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, _, stderr) = run(&["--root", root, "snapshot", "reset"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("requires --yes"), "stderr: {stderr}");
}

#[test]
fn snapshot_reset_with_yes_succeeds_even_with_no_prior_snapshot() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, stderr) = run(&["--root", root, "snapshot", "reset", "--yes"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("snapshot: reset"), "stdout: {stdout}");
}

#[test]
fn modules_pending_reports_unavailable_without_journal() {
    let tmp = seed_fake_root();
    let root = tmp.path().to_str().unwrap();
    let (code, stdout, _) = run(&["--root", root, "modules", "pending"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("pending: unavailable"), "stdout: {stdout}");
}

#[test]
fn modules_allow_under_root_does_not_touch_host_state_locations() {
    // Seed a dummy HOME so the binary would write there if --root leaked.
    let tmp = seed_fake_root();
    let home_probe = tempfile::tempdir().unwrap();
    let root = tmp.path().to_str().unwrap();
    let (code, _, _) = Command::new(env!("CARGO_BIN_EXE_seshat"))
        .args(["--root", root, "modules", "allow", "ext4"])
        .env("HOME", home_probe.path())
        .env_remove("XDG_STATE_HOME")
        .env_remove("SESHAT_STATE_ROOT")
        .output()
        .map(|o| (o.status.code().unwrap_or(-1), o.stdout, o.stderr))
        .expect("run seshat");
    assert_eq!(code, 0);
    assert!(
        profiles_dir(tmp.path())
            .join("allowlist.allow.conf")
            .exists()
    );
    // HOME-anchored state tree must remain empty - --root takes precedence.
    assert!(!home_probe.path().join(".local/state/seshat").exists());
}
