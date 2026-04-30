#![forbid(unsafe_code)]

mod atomic;
mod backup;
mod boot;
mod cli;
mod error;
mod lock;
mod modules;
mod orchestrator;
mod output;
mod paths;
mod policy;
mod result;
mod runtime;
mod sysctl;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use cli::{Command, Domain, ModulesCmd, SnapshotCmd};
use error::Error;
use modules::PendingReport;
use orchestrator::{
    BOOT_DEPLOY_REFUSED, DeployInputs, PlanInputs, StatusInputs, VerifyInputs,
    classify_deploy_error, orchestrate_deploy, orchestrate_plan, orchestrate_status,
    orchestrate_verify,
};
use paths::ensure_dir;
use policy::{ModuleName, Profile, ProfileName};
use result::CheckState;
use sysctl::ReloadStatus;

// Fixed kernel release under --root keeps smoke deterministic and avoids any uname call.
const SMOKE_FAKE_RELEASE: &str = "seshat-smoke";
const BACKUPS_SUBDIR: &str = "backups";
const PROFILES_SUBDIR: &str = "profiles";
const DEFAULT_PROFILE: &str = "baseline";

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
        Command::Plan { profile, domain } => dispatch_plan(profile, domain, root),
        Command::Verify { profile, domain } => dispatch_verify(profile, domain, root),
        Command::Status { profile, domain } => dispatch_status(profile, domain, root),
        Command::Deploy { profile, domain } => dispatch_deploy(profile, domain, root),
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

    let paths = match cli_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };

    let result = match op {
        ModulesEdit::Allow => modules::allow_module(
            &validated,
            &paths.allow_path,
            &paths.block_path,
            &paths.modules_backup_dir,
        ),
        ModulesEdit::Unallow => {
            modules::unallow_module(&validated, &paths.allow_path, &paths.modules_backup_dir)
        }
        ModulesEdit::Block => modules::block_module(
            &validated,
            &paths.allow_path,
            &paths.block_path,
            &paths.modules_backup_dir,
        ),
        ModulesEdit::Unblock => {
            modules::unblock_module(&validated, &paths.block_path, &paths.modules_backup_dir)
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
    let paths = match cli_paths(root) {
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
    let paths = match cli_paths(root) {
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
    let paths = match cli_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };

    match modules::reset_snapshot(
        &paths.snapshot_path,
        &paths.proc_modules_path,
        &paths.modules_dir,
        &paths.kernel_release,
        &paths.modules_backup_dir,
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

fn dispatch_plan(profile: Option<String>, domain: Domain, root: Option<&Path>) -> i32 {
    let prof = match load_profile(root, profile.as_deref()) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    let paths = match cli_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    let inputs = PlanInputs {
        profile: &prof,
        proc_sys_root: &paths.proc_sys_root,
        modules_dir: &paths.modules_dir,
        snapshot_path: &paths.snapshot_path,
        allow_path: &paths.allow_path,
        block_path: &paths.block_path,
        grub_config_path: &paths.grub_config,
    };
    let report = orchestrate_plan(&inputs);
    render_plan_report(&report, domain)
}

fn dispatch_verify(profile: Option<String>, domain: Domain, root: Option<&Path>) -> i32 {
    let prof = match load_profile(root, profile.as_deref()) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    let paths = match cli_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    let modprobe_show_config: Option<String> = if root.is_some() {
        None
    } else {
        fetch_modprobe_show_config()
    };
    let inputs = VerifyInputs {
        profile: &prof,
        proc_sys_root: &paths.proc_sys_root,
        modules_dir: &paths.modules_dir,
        snapshot_path: &paths.snapshot_path,
        allow_path: &paths.allow_path,
        block_path: &paths.block_path,
        proc_cmdline_path: &paths.proc_cmdline,
        modprobe_dropin_path: &paths.modprobe_target,
        sys_lockdown_path: &paths.sys_lockdown,
        modprobe_show_config,
    };
    let report = orchestrate_verify(&inputs);
    render_verify_report(&report, domain)
}

fn dispatch_status(profile: Option<String>, domain: Domain, root: Option<&Path>) -> i32 {
    let prof = match load_profile(root, profile.as_deref()) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    let paths = match cli_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    let inputs = StatusInputs {
        profile: &prof,
        modules_dir: &paths.modules_dir,
        snapshot_path: &paths.snapshot_path,
        allow_path: &paths.allow_path,
        block_path: &paths.block_path,
        sysctl_drop_in: &paths.sysctl_target,
        sysctl_backup_dir: &paths.sysctl_backup_dir,
        modprobe_drop_in: &paths.modprobe_target,
        modprobe_backup_dir: &paths.modules_backup_dir,
        grub_config: &paths.grub_config,
        grub_config_d: &paths.grub_config_d,
        grub_cfg: &paths.grub_cfg,
        kernel_cmdline: &paths.kernel_cmdline,
        modules_disabled_path: &paths.modules_disabled,
    };
    let has_command = has_command_probe(root);
    let report = orchestrate_status(&inputs, has_command);
    render_status_report(&report, domain)
}

fn dispatch_deploy(profile: Option<String>, domain: Domain, root: Option<&Path>) -> i32 {
    if matches!(domain, Domain::Boot) {
        output::fail(BOOT_DEPLOY_REFUSED);
        return 3;
    }
    let prof = match load_profile(root, profile.as_deref()) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };
    let paths = match cli_paths(root) {
        Ok(p) => p,
        Err(e) => return print_error_exit(&e, 1),
    };

    match domain {
        Domain::Sysctl => deploy_sysctl_only(&prof, &paths, root),
        Domain::Modules => deploy_modules_only(&prof, &paths),
        Domain::All => deploy_all(&prof, &paths, root),
        Domain::Boot => unreachable!("handled above"),
    }
}

fn deploy_sysctl_only(profile: &Profile, paths: &CliPaths, root: Option<&Path>) -> i32 {
    // Per-domain dir setup: only sysctl tree is created; modprobe/lock untouched.
    if let Err(e) = ensure_dir(&paths.sysctl_backup_dir) {
        return print_error_exit(&e, 1);
    }
    if let Some(parent) = paths.sysctl_target.parent()
        && let Err(e) = ensure_dir(parent)
    {
        return print_error_exit(&e, 1);
    }
    let settings: Vec<sysctl::SysctlSetting> = match profile
        .sysctl
        .iter()
        .map(sysctl::SysctlSetting::from_entry)
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(e) => return print_error_exit(&e, 1),
    };
    let reload = sysctl_reload_closure(root);
    let read_live = sysctl_read_live_closure(&paths.proc_sys_root);
    match sysctl::deploy_sysctl(
        &settings,
        profile.profile_name.as_str(),
        &paths.sysctl_target,
        &paths.sysctl_backup_dir,
        reload,
        read_live,
    ) {
        Ok(summary) => {
            output::ok(&format!(
                "deploy sysctl: {} key(s), reload={:?}",
                summary.count, summary.reload
            ));
            0
        }
        Err(e) => print_error_exit(&e, 1),
    }
}

fn deploy_modules_only(profile: &Profile, paths: &CliPaths) -> i32 {
    // Per-domain dir setup: only modprobe tree is created; sysctl/lock untouched.
    if let Err(e) = ensure_dir(&paths.modules_backup_dir) {
        return print_error_exit(&e, 1);
    }
    if let Some(parent) = paths.modprobe_target.parent()
        && let Err(e) = ensure_dir(parent)
    {
        return print_error_exit(&e, 1);
    }
    let snapshot = match modules::parse_allowlist(&paths.snapshot_path) {
        Ok(v) => v,
        Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
            output::fail("snapshot required before deploy; run: seshat snapshot");
            return 1;
        }
        Err(e) => return print_error_exit(&e, 1),
    };
    let allow = match modules::parse_allowlist(&paths.allow_path) {
        Ok(v) => v,
        Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return print_error_exit(&e, 1),
    };
    let file_block = match modules::parse_allowlist(&paths.block_path) {
        Ok(v) => v,
        Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return print_error_exit(&e, 1),
    };
    let profile_block: Vec<ModuleName> = match profile
        .modules
        .block
        .iter()
        .map(|s| ModuleName::new(s))
        .collect::<Result<_, _>>()
    {
        Ok(v) => v,
        Err(e) => return print_error_exit(&e, 1),
    };
    let mut combined_block = file_block;
    combined_block.extend(profile_block);
    let effective = modules::effective_allowlist(&snapshot, &allow, &combined_block);
    let installed = match modules::scan_installed_modules(&paths.modules_dir) {
        Ok(v) => v,
        Err(e) => return print_error_exit(&e, 1),
    };
    match modules::deploy_enforcement(
        &effective,
        &installed,
        profile.profile_name.as_str(),
        &paths.modprobe_target,
        &paths.modules_backup_dir,
    ) {
        Ok(summary) => {
            output::ok(&format!(
                "deploy modules: allow={} block={}",
                summary.allow_count, summary.block_count
            ));
            0
        }
        Err(e) => print_error_exit(&e, 1),
    }
}

fn deploy_all(profile: &Profile, paths: &CliPaths, root: Option<&Path>) -> i32 {
    // All-domain setup: orchestrator takes lock::acquire so lock_root must exist at exactly 0700.
    for dir in [&paths.sysctl_backup_dir, &paths.modules_backup_dir] {
        if let Err(e) = ensure_dir(dir) {
            return print_error_exit(&e, 1);
        }
    }
    if let Err(e) = ensure_lock_root(&paths.lock_root) {
        return print_error_exit(&e, 1);
    }
    if let Some(parent) = paths.sysctl_target.parent()
        && let Err(e) = ensure_dir(parent)
    {
        return print_error_exit(&e, 1);
    }
    if let Some(parent) = paths.modprobe_target.parent()
        && let Err(e) = ensure_dir(parent)
    {
        return print_error_exit(&e, 1);
    }
    let inputs = DeployInputs {
        profile,
        modules_dir: &paths.modules_dir,
        snapshot_path: &paths.snapshot_path,
        allow_path: &paths.allow_path,
        block_path: &paths.block_path,
        sysctl_target: &paths.sysctl_target,
        sysctl_backup_dir: &paths.sysctl_backup_dir,
        modprobe_target: &paths.modprobe_target,
        modprobe_backup_dir: &paths.modules_backup_dir,
        lock_root: &paths.lock_root,
    };
    let reload = sysctl_reload_closure(root);
    let read_live = sysctl_read_live_closure(&paths.proc_sys_root);
    let result = orchestrate_deploy(&inputs, reload, read_live);
    render_deploy_report(&result)
}

// Commands are stubbed under --root; only real hosts call sysctl --system.
fn sysctl_reload_closure(root: Option<&Path>) -> Box<dyn FnOnce() -> ReloadStatus> {
    if root.is_some() {
        Box::new(|| ReloadStatus::Applied)
    } else {
        Box::new(sysctl::reload_sysctl)
    }
}

// File reads use the remapped /proc/sys root; same primitive serves smoke and production.
fn sysctl_read_live_closure(
    proc_sys_root: &Path,
) -> impl FnMut(&policy::SysctlKey) -> sysctl::LiveRead + use<> {
    let proc_sys_root = proc_sys_root.to_path_buf();
    move |key| sysctl::read_live_sysctl(&proc_sys_root, key)
}

// Nonzero exit or missing binary yields None so verify reports WARN rather than fake OK.
fn fetch_modprobe_show_config() -> Option<String> {
    match runtime::run_sanitized("modprobe", ["--show-config"]) {
        Ok(out) if out.success() => Some(String::from_utf8_lossy(&out.stdout).to_string()),
        _ => None,
    }
}

// Under --root: stub commands as absent. Production walks SANITIZED_PATH so caller env cannot shadow tools.
fn has_command_probe(root: Option<&Path>) -> impl Fn(&str) -> bool + use<> {
    let under_root = root.is_some();
    move |cmd: &str| {
        if under_root {
            false
        } else {
            boot::default_has_command(cmd)
        }
    }
}

fn sysctl_plan_state(s: &sysctl::PlanState) -> CheckState {
    match s {
        sysctl::PlanState::Ok => CheckState::Ok,
        sysctl::PlanState::Change => CheckState::Warn,
        sysctl::PlanState::Skip => CheckState::Skip,
    }
}

fn modules_plan_state(s: &modules::PlanState) -> CheckState {
    match s {
        modules::PlanState::Ok => CheckState::Ok,
        modules::PlanState::Change => CheckState::Warn,
        modules::PlanState::Skip => CheckState::Skip,
    }
}

fn boot_plan_state(s: &boot::PlanState) -> CheckState {
    match s {
        boot::PlanState::Ok => CheckState::Ok,
        boot::PlanState::Change => CheckState::Warn,
    }
}

fn emit_hint(hint: &str) {
    if !hint.is_empty() {
        output::log(hint);
    }
}

fn render_plan_report(report: &orchestrator::PlanReport, domain: Domain) -> i32 {
    let mut code = 0;
    if matches_domain(domain, Domain::Sysctl) {
        match &report.sysctl {
            Ok(plan) => {
                output::log(&format!("plan sysctl: {} row(s)", plan.rows.len()));
                for row in &plan.rows {
                    output::state(
                        sysctl_plan_state(&row.state),
                        &format!("{} {}", row.key.as_str(), row.detail),
                    );
                    emit_hint(row.hint);
                }
            }
            Err(e) => {
                output::fail(&format!("plan sysctl: {e}"));
                code = code.max(1);
            }
        }
    }
    if matches_domain(domain, Domain::Modules) {
        match &report.modules {
            Ok(plan) => {
                output::log(&format!("plan modules: {} row(s)", plan.rows.len()));
                for row in &plan.rows {
                    output::state(
                        modules_plan_state(&row.state),
                        &format!("{} {}", row.key, row.detail),
                    );
                    emit_hint(row.hint);
                }
            }
            Err(e) => {
                output::fail(&format!("plan modules: {e}"));
                code = code.max(1);
            }
        }
    }
    if matches_domain(domain, Domain::Boot) {
        match &report.boot {
            Ok(plan) => {
                output::log(&format!("plan boot: {} row(s)", plan.rows.len()));
                for row in &plan.rows {
                    output::state(
                        boot_plan_state(&row.state),
                        &format!("{} {}", row.arg.as_str(), row.detail),
                    );
                }
            }
            Err(e) => {
                output::fail(&format!("plan boot: {e}"));
                code = code.max(1);
            }
        }
    }
    code
}

fn render_verify_report(report: &orchestrator::VerifyReport, domain: Domain) -> i32 {
    let mut code = 0;
    if matches_domain(domain, Domain::Sysctl) {
        match &report.sysctl {
            Ok(verify) => {
                output::log(&format!("verify sysctl: {} row(s)", verify.rows.len()));
                for row in &verify.rows {
                    output::state(row.state, &format!("{} {}", row.key.as_str(), row.detail));
                    emit_hint(row.hint);
                }
                if verify.rows.iter().any(row_has_issue) {
                    code = code.max(1);
                }
            }
            Err(e) => {
                output::fail(&format!("verify sysctl: {e}"));
                code = code.max(1);
            }
        }
    }
    if matches_domain(domain, Domain::Modules) {
        match &report.modules {
            Ok(verify) => {
                output::log(&format!("verify modules: {} row(s)", verify.rows.len()));
                for row in &verify.rows {
                    output::state(row.state, &format!("{} {}", row.key, row.detail));
                    emit_hint(row.hint);
                }
                if verify.rows.iter().any(row_has_issue) {
                    code = code.max(1);
                }
            }
            Err(e) => {
                output::fail(&format!("verify modules: {e}"));
                code = code.max(1);
            }
        }
    }
    if matches_domain(domain, Domain::Boot) {
        match &report.boot {
            Ok(verify) => {
                output::log(&format!("verify boot: {} row(s)", verify.rows.len()));
                for row in &verify.rows {
                    output::state(row.state, &format!("{} {}", row.arg.as_str(), row.detail));
                    emit_hint(row.hint);
                }
                if verify.rows.iter().any(row_has_issue) {
                    code = code.max(1);
                }
            }
            Err(e) => {
                output::fail(&format!("verify boot: {e}"));
                code = code.max(1);
            }
        }
    }
    if matches!(domain, Domain::All) {
        output::state(
            report.lockdown.state,
            &format!("lockdown: {}", report.lockdown.detail),
        );
        emit_hint(report.lockdown.hint);
        if matches!(report.lockdown.state, CheckState::Warn | CheckState::Fail) {
            code = code.max(1);
        }
    }
    code
}

fn row_has_issue<R: HasCheckState>(row: &R) -> bool {
    matches!(row.state(), CheckState::Warn | CheckState::Fail)
}

trait HasCheckState {
    fn state(&self) -> CheckState;
}

impl HasCheckState for sysctl::VerifyRow {
    fn state(&self) -> CheckState {
        self.state
    }
}

impl HasCheckState for modules::VerifyRow {
    fn state(&self) -> CheckState {
        self.state
    }
}

impl HasCheckState for boot::VerifyRow {
    fn state(&self) -> CheckState {
        self.state
    }
}

fn drift_state(d: orchestrator::DriftState) -> CheckState {
    match d {
        orchestrator::DriftState::Sync => CheckState::Ok,
        orchestrator::DriftState::Drift | orchestrator::DriftState::Missing => CheckState::Warn,
        orchestrator::DriftState::Unknown => CheckState::Skip,
    }
}

fn drift_label(d: orchestrator::DriftState) -> &'static str {
    match d {
        orchestrator::DriftState::Sync => "SYNC",
        orchestrator::DriftState::Drift => "DRIFT",
        orchestrator::DriftState::Missing => "MISSING",
        orchestrator::DriftState::Unknown => "UNKNOWN",
    }
}

fn mode_str(m: Option<u32>) -> String {
    m.map(|x| format!("{x:04o}"))
        .unwrap_or_else(|| "-".to_string())
}

fn hash_str(h: &Option<String>) -> &str {
    h.as_deref().unwrap_or("-")
}

fn render_status_report(report: &orchestrator::StatusReport, domain: Domain) -> i32 {
    if matches_domain(domain, Domain::Sysctl) {
        let s = &report.sysctl;
        output::state(
            drift_state(s.drift),
            &format!(
                "sysctl: {} {}",
                s.drop_in_path.display(),
                drift_label(s.drift)
            ),
        );
        output::log(&format!(
            "  hash={} mode={}",
            hash_str(&s.drop_in_hash),
            mode_str(s.drop_in_mode)
        ));
        if s.backup_count == 0 {
            output::skip("  backups: none");
        } else {
            output::ok(&format!("  backups: {} file(s)", s.backup_count));
        }
    }
    if matches_domain(domain, Domain::Modules) {
        let m = &report.modules;
        output::state(
            drift_state(m.drift),
            &format!(
                "modules: {} {}",
                m.drop_in_path.display(),
                drift_label(m.drift)
            ),
        );
        output::log(&format!(
            "  hash={} mode={}",
            hash_str(&m.drop_in_hash),
            mode_str(m.drop_in_mode)
        ));
        if m.snapshot_present {
            output::ok("  snapshot: present");
        } else {
            output::warn("  snapshot: missing (run: seshat snapshot)");
        }
        if m.backup_count == 0 {
            output::skip("  backups: none");
        } else {
            output::ok(&format!("  backups: {} file(s)", m.backup_count));
        }
    }
    if matches_domain(domain, Domain::Boot) {
        output::ok(&format!("boot: backend={:?}", report.boot.backend));
    }
    if matches!(domain, Domain::All) {
        let locked = report.lock.modules_disabled.as_deref() == Some("1");
        let cs = if locked {
            CheckState::Ok
        } else {
            CheckState::Warn
        };
        output::state(
            cs,
            &format!(
                "lock: modules_disabled={}",
                report.lock.modules_disabled.as_deref().unwrap_or("unknown")
            ),
        );
        if !locked {
            output::log("run: seshat lock (requires root)");
        }
    }
    0
}

fn render_deploy_report(result: &Result<orchestrator::DeployReport, Error>) -> i32 {
    match result {
        Ok(report) => {
            match &report.sysctl {
                Ok(s) => output::ok(&format!(
                    "deploy sysctl: {} key(s), reload={:?}",
                    s.count, s.reload
                )),
                Err(e) => output::fail(&format!("deploy sysctl: {e}")),
            }
            match &report.modules {
                Ok(m) => output::ok(&format!(
                    "deploy modules: allow={} block={}",
                    m.allow_count, m.block_count
                )),
                Err(e) => output::fail(&format!("deploy modules: {e}")),
            }
            output::log(&format!("deploy boot: {}", report.boot.reason));
            report.exit_code()
        }
        Err(e) => {
            output::fail(&format!("{e}"));
            classify_deploy_error(e)
        }
    }
}

fn matches_domain(selected: Domain, target: Domain) -> bool {
    matches!(selected, Domain::All) || selected == target
}

fn load_profile(root: Option<&Path>, raw_name: Option<&str>) -> Result<Profile, Error> {
    // Validate profile name BEFORE any path join or filesystem access.
    let name_str = raw_name.unwrap_or(DEFAULT_PROFILE);
    let validated = ProfileName::new(name_str)?;
    let paths = cli_paths(root)?;
    let file = paths
        .profiles_dir
        .join(format!("{}.toml", validated.as_str()));
    policy::load_profile(&file)
}

struct CliPaths {
    profiles_dir: PathBuf,
    snapshot_path: PathBuf,
    allow_path: PathBuf,
    block_path: PathBuf,
    modules_backup_dir: PathBuf,
    sysctl_target: PathBuf,
    sysctl_backup_dir: PathBuf,
    modprobe_target: PathBuf,
    proc_modules_path: PathBuf,
    proc_sys_root: PathBuf,
    proc_cmdline: PathBuf,
    grub_config: PathBuf,
    grub_config_d: PathBuf,
    grub_cfg: PathBuf,
    kernel_cmdline: PathBuf,
    sys_lockdown: PathBuf,
    modules_dir: PathBuf,
    kernel_release: String,
    modules_disabled: PathBuf,
    lock_root: PathBuf,
}

fn cli_paths(root: Option<&Path>) -> Result<CliPaths, Error> {
    let state_root = match root {
        Some(r) => r.join("var/lib/seshat"),
        None => paths::state_root()?,
    };
    let profiles_dir = state_root.join(PROFILES_SUBDIR);
    let modules_backup_dir = profiles_dir.join(format!("{BACKUPS_SUBDIR}-modprobe"));
    let sysctl_backup_dir = profiles_dir.join(format!("{BACKUPS_SUBDIR}-sysctl"));

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

    let (
        sysctl_target,
        modprobe_target,
        proc_sys_root,
        proc_cmdline,
        grub_config,
        grub_config_d,
        grub_cfg,
        kernel_cmdline,
        sys_lockdown,
        modules_disabled,
        lock_root,
    ) = match root {
        Some(r) => (
            r.join("etc/sysctl.d/99-kernel-hardening.conf"),
            r.join("etc/modprobe.d/99-kernel-hardening.conf"),
            r.join("proc/sys"),
            r.join("proc/cmdline"),
            r.join("etc/default/grub"),
            r.join("etc/default/grub.d"),
            r.join("boot/grub/grub.cfg"),
            r.join("etc/kernel/cmdline"),
            r.join("sys/kernel/security/lockdown"),
            r.join("proc/sys/kernel/modules_disabled"),
            r.join("run/seshat-locks"),
        ),
        None => (
            PathBuf::from(paths::SYSCTL_DROPIN),
            PathBuf::from(paths::MODPROBE_DROPIN),
            PathBuf::from(paths::PROC_SYS),
            PathBuf::from(paths::PROC_CMDLINE),
            PathBuf::from(paths::GRUB_CONFIG),
            PathBuf::from("/etc/default/grub.d"),
            PathBuf::from(paths::GRUB_CFG),
            PathBuf::from(paths::KERNEL_CMDLINE),
            PathBuf::from(paths::SYS_LOCKDOWN),
            PathBuf::from(paths::PROC_MODULES_DISABLED),
            paths::lock_root(),
        ),
    };

    Ok(CliPaths {
        profiles_dir,
        snapshot_path: state_root
            .join(PROFILES_SUBDIR)
            .join(paths::ALLOWLIST_SNAPSHOT),
        allow_path: state_root
            .join(PROFILES_SUBDIR)
            .join(paths::ALLOWLIST_ALLOW),
        block_path: state_root
            .join(PROFILES_SUBDIR)
            .join(paths::ALLOWLIST_BLOCK),
        modules_backup_dir,
        sysctl_target,
        sysctl_backup_dir,
        modprobe_target,
        proc_modules_path,
        proc_sys_root,
        proc_cmdline,
        grub_config,
        grub_config_d,
        grub_cfg,
        kernel_cmdline,
        sys_lockdown,
        modules_dir,
        kernel_release,
        modules_disabled,
        lock_root,
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

// lock::acquire requires exact mode 0o700; umask 022 would default to 0o755.
fn ensure_lock_root(path: &Path) -> Result<(), Error> {
    const LOCK_DIR_MODE: u32 = 0o700;
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_symlink() {
                return Err(Error::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "lock root is a symlink".to_string(),
                });
            }
            if !ft.is_dir() {
                return Err(Error::UnsafePath {
                    path: path.to_path_buf(),
                    reason: "lock root is not a directory".to_string(),
                });
            }
            if meta.permissions().mode() & 0o777 != LOCK_DIR_MODE {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(LOCK_DIR_MODE))
                    .map_err(Error::Io)?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent() {
                paths::ensure_dir(parent)?;
            }
            std::fs::create_dir(path).map_err(Error::Io)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(LOCK_DIR_MODE))
                .map_err(Error::Io)?;
        }
        Err(e) => return Err(Error::Io(e)),
    }
    Ok(())
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
