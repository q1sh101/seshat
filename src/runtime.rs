//! External command runner. Argv arrays only; env sanitized to prevent injection.

use std::ffi::OsStr;
use std::process::{Command, Stdio};

use crate::error::Error;

const STDERR_SUMMARY_MAX: usize = 200;

// No /usr/local/* so a local shim cannot shadow real coreutils.
pub const SANITIZED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
pub const SANITIZED_LC_ALL: &str = "C";

#[derive(Debug, Clone)]
pub struct CommandOutput {
    // None indicates signal-terminated (POSIX WIFSIGNALED).
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    pub fn stderr_summary(&self) -> String {
        let text = String::from_utf8_lossy(&self.stderr);
        let trimmed = text.trim();
        if trimmed.len() <= STDERR_SUMMARY_MAX {
            return trimmed.to_string();
        }
        let mut out = String::with_capacity(STDERR_SUMMARY_MAX + 1);
        for c in trimmed.chars() {
            if out.len() + c.len_utf8() > STDERR_SUMMARY_MAX {
                break;
            }
            out.push(c);
        }
        out.push('…');
        out
    }
}

pub fn run_sanitized<P, I, S>(program: P, args: I) -> Result<CommandOutput, Error>
where
    P: AsRef<OsStr>,
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(program.as_ref());
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear()
        .env("PATH", SANITIZED_PATH)
        .env("LC_ALL", SANITIZED_LC_ALL);

    for arg in args {
        cmd.arg(arg.as_ref());
    }

    let output = cmd.output()?;

    Ok(CommandOutput {
        exit_code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample(exit_code: Option<i32>, stdout: &[u8], stderr: &[u8]) -> CommandOutput {
        CommandOutput {
            exit_code,
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn success_true_only_when_exit_code_is_zero() {
        assert!(sample(Some(0), b"", b"").success());
        assert!(!sample(Some(1), b"", b"").success());
        assert!(!sample(None, b"", b"").success());
    }

    #[test]
    fn stderr_summary_trims_whitespace() {
        let o = sample(Some(0), b"", b"  hello \n");
        assert_eq!(o.stderr_summary(), "hello");
    }

    #[test]
    fn stderr_summary_returns_short_text_unchanged() {
        let o = sample(Some(1), b"", b"boom");
        assert_eq!(o.stderr_summary(), "boom");
    }

    #[test]
    fn stderr_summary_truncates_long_text_with_ellipsis() {
        let long = "x".repeat(STDERR_SUMMARY_MAX * 2);
        let o = sample(Some(1), b"", long.as_bytes());
        let s = o.stderr_summary();
        assert!(s.ends_with('…'));
        assert!(s.len() <= STDERR_SUMMARY_MAX + '…'.len_utf8());
    }

    #[test]
    fn stderr_summary_respects_utf8_char_boundary() {
        let s = "é".repeat(STDERR_SUMMARY_MAX);
        let o = sample(Some(1), b"", s.as_bytes());
        let summary = o.stderr_summary();
        assert!(summary.is_char_boundary(summary.len()));
    }

    fn selected_exactly(name: &str) -> bool {
        let args: Vec<String> = std::env::args().collect();
        if !args.iter().any(|a| a == "--exact") {
            return false;
        }
        args.iter()
            .skip(1)
            .any(|a| !a.starts_with('-') && a == name)
    }

    #[test]
    #[ignore = "helper for run_sanitized tests; prints env when selected exactly"]
    fn child_env_probe() {
        if !selected_exactly("runtime::tests::child_env_probe") {
            return;
        }
        use std::io::Write;
        let names = [
            "PATH",
            "LC_ALL",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "IFS",
            "BASH_ENV",
            "ENV",
            "MODPROBE_OPTIONS",
            "HOME",
            "USER",
        ];
        let mut stdout = std::io::stdout().lock();
        for name in names {
            let value = std::env::var(name).unwrap_or_else(|_| "<unset>".to_string());
            let _ = writeln!(stdout, "{name}={value}");
        }
        let _ = stdout.flush();
    }

    fn test_exe() -> PathBuf {
        std::env::current_exe().expect("current_exe in test")
    }

    fn run_env_probe() -> std::collections::HashMap<String, String> {
        let out = run_sanitized(
            test_exe(),
            [
                "--exact",
                "runtime::tests::child_env_probe",
                "--include-ignored",
                "--nocapture",
            ],
        )
        .expect("spawn env probe child");
        assert!(out.success(), "env probe must exit 0, got {:?}", out);

        let text = String::from_utf8_lossy(&out.stdout);
        let mut map = std::collections::HashMap::new();
        for line in text.lines() {
            if let Some((k, v)) = line.split_once('=')
                && matches!(
                    k,
                    "PATH"
                        | "LC_ALL"
                        | "LD_PRELOAD"
                        | "LD_LIBRARY_PATH"
                        | "LD_AUDIT"
                        | "IFS"
                        | "BASH_ENV"
                        | "ENV"
                        | "MODPROBE_OPTIONS"
                        | "HOME"
                        | "USER"
                )
            {
                map.insert(k.to_string(), v.to_string());
            }
        }
        map
    }

    #[test]
    fn run_sanitized_installs_path_and_lc_all_baseline() {
        let env = run_env_probe();
        assert_eq!(env.get("PATH").map(String::as_str), Some(SANITIZED_PATH));
        assert_eq!(
            env.get("LC_ALL").map(String::as_str),
            Some(SANITIZED_LC_ALL)
        );
    }

    #[test]
    fn run_sanitized_clears_dangerous_injection_vars() {
        let env = run_env_probe();
        for name in [
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "IFS",
            "BASH_ENV",
            "ENV",
            "MODPROBE_OPTIONS",
        ] {
            assert_eq!(
                env.get(name).map(String::as_str),
                Some("<unset>"),
                "sanitized child still saw {name} from the caller's env"
            );
        }
    }

    #[test]
    fn run_sanitized_drops_unrelated_caller_env() {
        let env = run_env_probe();
        assert_eq!(env.get("HOME").map(String::as_str), Some("<unset>"));
        assert_eq!(env.get("USER").map(String::as_str), Some("<unset>"));
    }
}
