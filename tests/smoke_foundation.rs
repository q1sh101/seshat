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

#[test]
fn empty_argv_prints_help_on_stdout_and_exits_zero() {
    let (code, stdout, stderr) = run(&[]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Usage:"), "stdout: {stdout}");
    assert!(stdout.contains("seshat"));
}

#[test]
fn help_word_prints_usage_and_exits_zero() {
    let (code, stdout, _) = run(&["help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage:"));
}

#[test]
fn long_help_flag_exits_zero() {
    let (code, stdout, _) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage:"));
}

#[test]
fn short_help_flag_exits_zero() {
    let (code, stdout, _) = run(&["-h"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Usage:"));
}

#[test]
fn help_with_extra_argument_exits_two_with_usage_on_stderr() {
    let (code, _, stderr) = run(&["help", "extra"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("extra argument"));
    assert!(stderr.contains("Usage:"));
}

#[test]
fn unknown_top_level_command_exits_two_with_usage_on_stderr() {
    let (code, _, stderr) = run(&["does-not-exist"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown command"));
    assert!(stderr.contains("Usage:"));
}

#[test]
fn unwired_parsed_command_exits_one_with_not_implemented_on_stderr() {
    // `plan` parses cleanly but the domain wiring into main does not exist
    // at the foundation boundary; main dispatches unwired variants to exit 1.
    let (code, _, stderr) = run(&["plan"]);
    assert_eq!(code, 1);
    assert!(stderr.contains("not implemented"));
}

#[test]
fn unknown_flag_exits_two() {
    let (code, _, stderr) = run(&["plan", "--not-a-flag"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown option"));
}

#[test]
fn profile_flag_without_value_exits_two() {
    let (code, _, stderr) = run(&["plan", "--profile"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("--profile requires a value"));
}

#[test]
fn unknown_domain_token_exits_two() {
    let (code, _, stderr) = run(&["plan", "nonsense-domain"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("unknown domain"));
}

#[test]
fn deploy_without_domain_exits_two() {
    let (code, _, stderr) = run(&["deploy"]);
    assert_eq!(code, 2);
    assert!(stderr.contains("requires a domain"));
}
