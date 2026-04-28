#![forbid(unsafe_code)]

mod atomic;
mod backup;
mod cli;
mod error;
mod lock;
mod modules;
mod output;
mod paths;
mod policy;
mod result;
mod runtime;

use std::path::{Path, PathBuf};

use cli::{Command, ModulesCmd, SnapshotCmd};
use error::Error;
use modules::PendingReport;
use policy::ModuleName;

// Fixed kernel release under --root keeps smoke deterministic and avoids any uname call.
const SMOKE_FAKE_RELEASE: &str = "seshat-smoke";
const BACKUPS_SUBDIR: &str = "backups";
const PROFILES_SUBDIR: &str = "profiles";

fn main() {
    let mut args: Vec<String> = Vec::new();
    for raw in std::env::args_os().skip(1) {
        match raw.into_string() {
            Ok(s) => args.push(s),
            Err(bad) => {
                eprintln!("error: non-UTF-8 argument: {}", bad.to_string_lossy());
                eprintln!();
                eprintln!("{}", cli::USAGE);
                std::process::exit(2);
            }
        }
    }

    // --root stripped before command parse so cli::parse stays unaware of globals.
    let (root, rest) = match cli::parse_globals(&args) {
        Ok(pair) => pair,
        Err(msg) => usage_error_exit(&msg),
    };

    let command = match cli::parse(&rest) {
        Ok(cmd) => cmd,
        Err(msg) => usage_error_exit(&msg),
    };

    std::process::exit(dispatch(command, root.as_deref()));
}

fn usage_error_exit(msg: &str) -> ! {
    eprintln!("error: {msg}");
    eprintln!();
    eprintln!("{}", cli::USAGE);
    std::process::exit(2);
}

fn dispatch(command: Command, root: Option<&Path>) -> i32 {
    match command {
        Command::Help => {
            println!("{}", cli::USAGE);
            0
        }
        Command::Snapshot(SnapshotCmd::Run) => dispatch_snapshot_run(root),
        Command::Snapshot(SnapshotCmd::Reset) => dispatch_snapshot_reset(root),
        Command::Modules(sub) => dispatch_modules(sub, root),
        other => {
            eprintln!("{other:?}: not implemented");
            1
        }
    }
}

enum ModulesEdit {
    Allow,
    Unallow,
    Block,
    Unblock,
}

fn dispatch_modules(sub: ModulesCmd, root: Option<&Path>) -> i32 {
    match sub {
        ModulesCmd::Allow(name) => dispatch_modules_edit(name, root, ModulesEdit::Allow),
        ModulesCmd::Unallow(name) => dispatch_modules_edit(name, root, ModulesEdit::Unallow),
        ModulesCmd::Block(name) => dispatch_modules_edit(name, root, ModulesEdit::Block),
        ModulesCmd::Unblock(name) => dispatch_modules_edit(name, root, ModulesEdit::Unblock),
        ModulesCmd::List { profile: _ } => dispatch_modules_list(root),
        ModulesCmd::Pending => dispatch_modules_pending(root),
    }
}

fn dispatch_modules_edit(raw_name: String, root: Option<&Path>, op: ModulesEdit) -> i32 {
    // Name validation runs BEFORE path resolution or any filesystem touch.
    let validated = match ModuleName::new(&raw_name) {
        Ok(v) => v,
        Err(e) => return print_error_exit(&e, 1),
    };

    let paths = match module_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };

    let result = match op {
        ModulesEdit::Allow => modules::allow_module(
            &validated,
            &paths.allow_path,
            &paths.block_path,
            &paths.backup_dir,
        ),
        ModulesEdit::Unallow => {
            modules::unallow_module(&validated, &paths.allow_path, &paths.backup_dir)
        }
        ModulesEdit::Block => modules::block_module(
            &validated,
            &paths.allow_path,
            &paths.block_path,
            &paths.backup_dir,
        ),
        ModulesEdit::Unblock => {
            modules::unblock_module(&validated, &paths.block_path, &paths.backup_dir)
        }
    };

    match result {
        Ok(outcome) => {
            let verb = match op {
                ModulesEdit::Allow => "allow",
                ModulesEdit::Unallow => "unallow",
                ModulesEdit::Block => "block",
                ModulesEdit::Unblock => "unblock",
            };
            let state = if outcome.changed {
                "changed"
            } else {
                "unchanged"
            };
            output::ok(&format!("{verb}: {}: {state}", validated.as_str()));
            if outcome.overlap {
                output::log("note: overlap with other list");
            }
            0
        }
        Err(e) => print_error_exit(&e, 1),
    }
}

fn dispatch_modules_list(root: Option<&Path>) -> i32 {
    let paths = match module_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    match modules::list_allowlist(&paths.snapshot_path, &paths.allow_path, &paths.block_path) {
        Ok(report) => {
            output::ok(&format!(
                "effective: {} module(s) (snapshot ∪ allow \\ block)",
                report.effective.len()
            ));
            for name in &report.effective {
                output::log(name.as_str());
            }
            let allow_n = report.allow.as_ref().map(|v| v.len()).unwrap_or(0);
            let block_n = report.block.as_ref().map(|v| v.len()).unwrap_or(0);
            if allow_n == 0 {
                output::skip("allow: none");
            } else {
                output::ok(&format!("allow: {allow_n} module(s)"));
            }
            if block_n == 0 {
                output::skip("block: none");
            } else {
                output::ok(&format!("block: {block_n} module(s)"));
            }
            0
        }
        Err(e) => print_error_exit(&e, 1),
    }
}

fn dispatch_modules_pending(root: Option<&Path>) -> i32 {
    // Under --root the real journal is off-limits; force Unavailable so smoke tests stay hermetic.
    let report = modules::check_pending_modules(|| {
        if root.is_some() {
            return None;
        }
        runtime::run_sanitized("journalctl", ["-b", "-k", "--no-pager"])
            .ok()
            .filter(|out| out.success())
            .map(|out| String::from_utf8_lossy(&out.stdout).into_owned())
    });
    match report {
        PendingReport::Unavailable => {
            output::skip("pending: unavailable (no journal)");
            0
        }
        PendingReport::Checked(mods) if mods.is_empty() => {
            output::ok("pending: no blocked module requests found");
            0
        }
        PendingReport::Checked(mods) => {
            output::log(&format!("pending: {} blocked request(s)", mods.len()));
            for m in &mods {
                output::warn(m.as_str());
            }
            output::log("use: seshat modules allow <module> to allow");
            0
        }
    }
}

fn dispatch_snapshot_run(root: Option<&Path>) -> i32 {
    let paths = match module_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };

    match modules::create_snapshot(
        &paths.snapshot_path,
        &paths.proc_modules_path,
        &paths.modules_dir,
        &paths.kernel_release,
        |_name| None,
    ) {
        Ok(summary) => {
            output::ok(&format!(
                "snapshot: wrote {} ({} loaded, {} builtin, {} total)",
                paths.snapshot_path.display(),
                summary.loaded,
                summary.builtin,
                summary.total,
            ));
            0
        }
        // Replace the raw "File exists (os error 17)" from create-or-fail with an operator-facing hint.
        Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            output::fail("snapshot already exists; run: seshat snapshot reset --yes");
            1
        }
        Err(e) => print_error_exit(&e, 1),
    }
}

fn dispatch_snapshot_reset(root: Option<&Path>) -> i32 {
    let paths = match module_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };

    match modules::reset_snapshot(
        &paths.snapshot_path,
        &paths.proc_modules_path,
        &paths.modules_dir,
        &paths.kernel_release,
        &paths.backup_dir,
        |_| None,
    ) {
        Ok(summary) => {
            match summary.backup {
                Some(backup) => output::ok(&format!(
                    "snapshot: reset (previous at {})",
                    backup.display()
                )),
                None => output::log("snapshot: reset (no previous snapshot)"),
            }
            output::log(&format!(
                "new snapshot: {} module(s)",
                summary.snapshot.total
            ));
            0
        }
        Err(e) => print_error_exit(&e, 1),
    }
}

struct ModulePaths {
    snapshot_path: PathBuf,
    allow_path: PathBuf,
    block_path: PathBuf,
    backup_dir: PathBuf,
    proc_modules_path: PathBuf,
    modules_dir: PathBuf,
    kernel_release: String,
}

fn module_paths(root: Option<&Path>) -> Result<ModulePaths, Error> {
    let state_root = match root {
        Some(r) => r.join("var/lib/seshat"),
        None => paths::state_root()?,
    };
    let profiles_dir = state_root.join(PROFILES_SUBDIR);
    let backup_dir = profiles_dir.join(BACKUPS_SUBDIR);

    let (kernel_release, modules_dir, proc_modules_path) = match root {
        Some(r) => (
            SMOKE_FAKE_RELEASE.to_string(),
            r.join("lib/modules").join(SMOKE_FAKE_RELEASE),
            r.join("proc/modules"),
        ),
        None => {
            let release = read_uname_release()?;
            let mdir = paths::modules_dir(&release);
            (release, mdir, PathBuf::from("/proc/modules"))
        }
    };

    Ok(ModulePaths {
        snapshot_path: profiles_dir.join(paths::ALLOWLIST_SNAPSHOT),
        allow_path: profiles_dir.join(paths::ALLOWLIST_ALLOW),
        block_path: profiles_dir.join(paths::ALLOWLIST_BLOCK),
        backup_dir,
        proc_modules_path,
        modules_dir,
        kernel_release,
    })
}

// Production-only path. Smoke never reaches this branch because --root is always Some.
fn read_uname_release() -> Result<String, Error> {
    let out = std::process::Command::new("uname")
        .arg("-r")
        .output()
        .map_err(Error::Io)?;
    if !out.status.success() {
        return Err(Error::Validation {
            field: "uname".to_string(),
            reason: "uname -r exited non-zero".to_string(),
        });
    }
    let rel = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if rel.is_empty() {
        return Err(Error::Validation {
            field: "uname".to_string(),
            reason: "uname -r returned empty".to_string(),
        });
    }
    Ok(rel)
}

fn print_error_exit(err: &Error, default_code: i32) -> i32 {
    eprintln!("error: {err}");
    match err {
        Error::UnsafePath { .. }
        | Error::PreflightRefused { .. }
        | Error::Lock { .. } => 3,
        _ => default_code,
    }
}
