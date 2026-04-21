
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Domain {
    All,
    Sysctl,
    Modules,
    Boot,
}

impl Domain {
    fn from_token(s: &str) -> Option<Self> {
        match s {
            "all" => Some(Domain::All),
            "sysctl" => Some(Domain::Sysctl),
            "modules" => Some(Domain::Modules),
            "boot" => Some(Domain::Boot),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SnapshotCmd {
    Run,
    Reset,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ModulesCmd {
    Allow(String),
    Unallow(String),
    Block(String),
    Unblock(String),
    Pending,
    List { profile: Option<String> },
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum WatchCmd {
    Install,
    Remove,
    Status,
    Run,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum GuardCmd {
    Install,
    Remove,
    Status,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Command {
    Help,
    Plan {
        profile: Option<String>,
        domain: Domain,
    },
    Deploy {
        profile: Option<String>,
        domain: Domain,
    },
    Verify {
        profile: Option<String>,
        domain: Domain,
    },
    Status {
        profile: Option<String>,
        domain: Domain,
    },
    Rollback {
        yes: bool,
        domain: Domain,
    },
    Snapshot(SnapshotCmd),
    Lock {
        yes: bool,
    },
    Modules(ModulesCmd),
    Watch(WatchCmd),
    Guard(GuardCmd),
}

pub const USAGE: &str = "\
seshat - deterministic kernel hardening CLI

Usage:
  seshat <command> [options]

Read-only:
  plan     [--profile NAME] [all|sysctl|modules|boot]
  verify   [--profile NAME] [all|sysctl|modules|boot]
  status   [--profile NAME] [all|sysctl|modules|boot]

Mutating (domain required):
  deploy   [--profile NAME] <all|sysctl|modules|boot>
  rollback [--yes]          <all|sysctl|modules|boot>

Snapshot:
  snapshot
  snapshot reset --yes

Runtime lock:
  lock [--yes]

Modules:
  modules allow    <module>
  modules unallow  <module>
  modules block    <module>
  modules unblock  <module>
  modules pending
  modules list     [--profile NAME]

Service units:
  watch install | remove | status | run
  guard install | remove | status

Help:
  help  |  --help  |  -h
";

pub fn parse(args: &[String]) -> Result<Command, String> {
    let (head, rest) = match args.split_first() {
        Some((h, r)) => (h.as_str(), r),
        None => return Ok(Command::Help),
    };

    match head {
        "help" | "-h" | "--help" => {
            refuse_extras(rest, "help")?;
            Ok(Command::Help)
        }
        "plan" => parse_domain_cmd(rest, false).map(|(p, d)| Command::Plan {
            profile: p,
            domain: d,
        }),
        "deploy" => parse_domain_cmd(rest, true).map(|(p, d)| Command::Deploy {
            profile: p,
            domain: d,
        }),
        "verify" => parse_domain_cmd(rest, false).map(|(p, d)| Command::Verify {
            profile: p,
            domain: d,
        }),
        "status" => parse_domain_cmd(rest, false).map(|(p, d)| Command::Status {
            profile: p,
            domain: d,
        }),
        "rollback" => parse_rollback(rest),
        "snapshot" => parse_snapshot(rest),
        "lock" => parse_lock(rest),
        "modules" => parse_modules(rest),
        "watch" => parse_watch(rest),
        "guard" => parse_guard(rest),
        other => Err(format!("unknown command: {other}")),
    }
}

fn parse_domain_cmd(
    args: &[String],
    domain_required: bool,
) -> Result<(Option<String>, Domain), String> {
    let mut profile: Option<String> = None;
    let mut domain: Option<Domain> = None;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--profile" {
            profile = Some(take_value(args, i, "--profile")?);
            i += 2;
        } else if let Some(rest) = arg.strip_prefix("--") {
            return Err(format!("unknown option: --{rest}"));
        } else if domain.is_some() {
            return Err(format!("extra argument: {arg}"));
        } else {
            domain = Some(Domain::from_token(arg).ok_or_else(|| format!("unknown domain: {arg}"))?);
            i += 1;
        }
    }
    let d = match domain {
        Some(d) => d,
        None if !domain_required => Domain::All,
        None => return Err("this command requires a domain: all|sysctl|modules|boot".to_string()),
    };
    Ok((profile, d))
}

fn parse_rollback(args: &[String]) -> Result<Command, String> {
    let mut yes = false;
    let mut domain: Option<Domain> = None;
    for arg in args {
        match arg.as_str() {
            "--yes" => yes = true,
            other if other.starts_with("--") => return Err(format!("unknown option: {other}")),
            other => {
                if domain.is_some() {
                    return Err(format!("extra argument: {other}"));
                }
                domain = Some(
                    Domain::from_token(other).ok_or_else(|| format!("unknown domain: {other}"))?,
                );
            }
        }
    }
    let d =
        domain.ok_or_else(|| "rollback requires a domain: all|sysctl|modules|boot".to_string())?;
    Ok(Command::Rollback { yes, domain: d })
}

fn parse_snapshot(args: &[String]) -> Result<Command, String> {
    match args.split_first() {
        None => Ok(Command::Snapshot(SnapshotCmd::Run)),
        Some((sub, rest)) if sub == "reset" => {
            let mut yes = false;
            for arg in rest {
                match arg.as_str() {
                    "--yes" => yes = true,
                    other => return Err(format!("unknown argument: {other}")),
                }
            }
            if !yes {
                return Err("snapshot reset requires --yes".to_string());
            }
            Ok(Command::Snapshot(SnapshotCmd::Reset))
        }
        Some((other, _)) => Err(format!("unknown snapshot subcommand: {other}")),
    }
}

fn parse_lock(args: &[String]) -> Result<Command, String> {
    let mut yes = false;
    for arg in args {
        match arg.as_str() {
            "--yes" => yes = true,
            other => return Err(format!("unknown argument: {other}")),
        }
    }
    Ok(Command::Lock { yes })
}

fn parse_modules(args: &[String]) -> Result<Command, String> {
    let (sub, rest) = args
        .split_first()
        .ok_or_else(|| "modules requires a subcommand".to_string())?;
    match sub.as_str() {
        "allow" => parse_single_module(rest, ModulesCmd::Allow),
        "unallow" => parse_single_module(rest, ModulesCmd::Unallow),
        "block" => parse_single_module(rest, ModulesCmd::Block),
        "unblock" => parse_single_module(rest, ModulesCmd::Unblock),
        "pending" => {
            refuse_extras(rest, "modules pending")?;
            Ok(Command::Modules(ModulesCmd::Pending))
        }
        "list" => {
            let mut profile: Option<String> = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--profile" => {
                        profile = Some(take_value(rest, i, "--profile")?);
                        i += 2;
                    }
                    other => return Err(format!("unknown argument: {other}")),
                }
            }
            Ok(Command::Modules(ModulesCmd::List { profile }))
        }
        other => Err(format!("unknown modules subcommand: {other}")),
    }
}

fn parse_single_module<F>(args: &[String], ctor: F) -> Result<Command, String>
where
    F: Fn(String) -> ModulesCmd,
{
    match args {
        [name] => Ok(Command::Modules(ctor(name.clone()))),
        [] => Err("missing module name".to_string()),
        [_, extra, ..] => Err(format!("extra argument: {extra}")),
    }
}

fn parse_watch(args: &[String]) -> Result<Command, String> {
    let sub = args
        .first()
        .ok_or_else(|| "watch requires a subcommand: install|remove|status|run".to_string())?;
    refuse_extras(&args[1..], "watch")?;
    let cmd = match sub.as_str() {
        "install" => WatchCmd::Install,
        "remove" => WatchCmd::Remove,
        "status" => WatchCmd::Status,
        "run" => WatchCmd::Run,
        other => return Err(format!("unknown watch subcommand: {other}")),
    };
    Ok(Command::Watch(cmd))
}

fn parse_guard(args: &[String]) -> Result<Command, String> {
    let sub = args
        .first()
        .ok_or_else(|| "guard requires a subcommand: install|remove|status".to_string())?;
    refuse_extras(&args[1..], "guard")?;
    let cmd = match sub.as_str() {
        "install" => GuardCmd::Install,
        "remove" => GuardCmd::Remove,
        "status" => GuardCmd::Status,
        other => return Err(format!("unknown guard subcommand: {other}")),
    };
    Ok(Command::Guard(cmd))
}

fn take_value(args: &[String], i: usize, flag: &str) -> Result<String, String> {
    args.get(i + 1)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn refuse_extras(rest: &[String], label: &str) -> Result<(), String> {
    if let Some(first) = rest.first() {
        Err(format!("extra argument after {label}: {first}"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn empty_argv_yields_help() {
        assert_eq!(parse(&argv(&[])).unwrap(), Command::Help);
    }

    #[test]
    fn help_long_and_short_and_word_all_yield_help() {
        assert_eq!(parse(&argv(&["help"])).unwrap(), Command::Help);
        assert_eq!(parse(&argv(&["--help"])).unwrap(), Command::Help);
        assert_eq!(parse(&argv(&["-h"])).unwrap(), Command::Help);
    }

    #[test]
    fn help_refuses_extra_arguments() {
        assert!(parse(&argv(&["help", "extra"])).is_err());
    }

    #[test]
    fn plan_defaults_to_all_when_no_domain() {
        assert_eq!(
            parse(&argv(&["plan"])).unwrap(),
            Command::Plan {
                profile: None,
                domain: Domain::All
            }
        );
    }

    #[test]
    fn plan_accepts_explicit_domain_and_profile() {
        assert_eq!(
            parse(&argv(&["plan", "--profile", "baseline", "sysctl"])).unwrap(),
            Command::Plan {
                profile: Some("baseline".to_string()),
                domain: Domain::Sysctl
            }
        );
    }

    #[test]
    fn verify_and_status_default_to_all() {
        assert!(matches!(
            parse(&argv(&["verify"])).unwrap(),
            Command::Verify {
                domain: Domain::All,
                ..
            }
        ));
        assert!(matches!(
            parse(&argv(&["status"])).unwrap(),
            Command::Status {
                domain: Domain::All,
                ..
            }
        ));
    }

    #[test]
    fn deploy_without_domain_is_rejected() {
        assert!(parse(&argv(&["deploy"])).is_err());
    }

    #[test]
    fn deploy_accepts_domain_tokens() {
        assert_eq!(
            parse(&argv(&["deploy", "modules"])).unwrap(),
            Command::Deploy {
                profile: None,
                domain: Domain::Modules
            }
        );
    }

    #[test]
    fn rollback_without_domain_is_rejected() {
        assert!(parse(&argv(&["rollback"])).is_err());
    }

    #[test]
    fn rollback_parses_yes_and_domain_in_any_order() {
        assert_eq!(
            parse(&argv(&["rollback", "--yes", "boot"])).unwrap(),
            Command::Rollback {
                yes: true,
                domain: Domain::Boot,
            }
        );
        assert_eq!(
            parse(&argv(&["rollback", "boot", "--yes"])).unwrap(),
            Command::Rollback {
                yes: true,
                domain: Domain::Boot,
            }
        );
    }

    #[test]
    fn snapshot_bare_runs_snapshot() {
        assert_eq!(
            parse(&argv(&["snapshot"])).unwrap(),
            Command::Snapshot(SnapshotCmd::Run)
        );
    }

    #[test]
    fn snapshot_reset_requires_yes() {
        assert!(parse(&argv(&["snapshot", "reset"])).is_err());
        assert_eq!(
            parse(&argv(&["snapshot", "reset", "--yes"])).unwrap(),
            Command::Snapshot(SnapshotCmd::Reset)
        );
    }

    #[test]
    fn lock_optional_yes_flag() {
        assert_eq!(
            parse(&argv(&["lock"])).unwrap(),
            Command::Lock { yes: false }
        );
        assert_eq!(
            parse(&argv(&["lock", "--yes"])).unwrap(),
            Command::Lock { yes: true }
        );
    }

    #[test]
    fn modules_allow_accepts_a_module_name() {
        assert_eq!(
            parse(&argv(&["modules", "allow", "usb-storage"])).unwrap(),
            Command::Modules(ModulesCmd::Allow("usb-storage".to_string()))
        );
    }

    #[test]
    fn modules_list_defaults_profile_to_none() {
        assert_eq!(
            parse(&argv(&["modules", "list"])).unwrap(),
            Command::Modules(ModulesCmd::List { profile: None })
        );
    }

    #[test]
    fn modules_list_accepts_profile() {
        assert_eq!(
            parse(&argv(&["modules", "list", "--profile", "baseline"])).unwrap(),
            Command::Modules(ModulesCmd::List {
                profile: Some("baseline".to_string())
            })
        );
    }

    #[test]
    fn modules_pending_refuses_extras() {
        assert_eq!(
            parse(&argv(&["modules", "pending"])).unwrap(),
            Command::Modules(ModulesCmd::Pending)
        );
        assert!(parse(&argv(&["modules", "pending", "x"])).is_err());
    }

    #[test]
    fn modules_without_subcommand_is_rejected() {
        assert!(parse(&argv(&["modules"])).is_err());
    }

    #[test]
    fn watch_subcommands_parse() {
        assert_eq!(
            parse(&argv(&["watch", "install"])).unwrap(),
            Command::Watch(WatchCmd::Install)
        );
        assert_eq!(
            parse(&argv(&["watch", "run"])).unwrap(),
            Command::Watch(WatchCmd::Run)
        );
    }

    #[test]
    fn guard_subcommands_parse() {
        assert_eq!(
            parse(&argv(&["guard", "status"])).unwrap(),
            Command::Guard(GuardCmd::Status)
        );
    }

    #[test]
    fn watch_and_guard_reject_unknown_subcommand() {
        assert!(parse(&argv(&["watch", "explode"])).is_err());
        assert!(parse(&argv(&["guard", "explode"])).is_err());
    }

    #[test]
    fn unknown_top_level_command_is_rejected() {
        assert!(parse(&argv(&["explode"])).is_err());
    }

    #[test]
    fn unknown_option_is_rejected() {
        assert!(parse(&argv(&["plan", "--foo"])).is_err());
    }

    #[test]
    fn unknown_domain_token_is_rejected() {
        assert!(parse(&argv(&["plan", "nonsense"])).is_err());
    }

    #[test]
    fn extra_positional_after_domain_is_rejected() {
        assert!(parse(&argv(&["plan", "sysctl", "extra"])).is_err());
    }

    #[test]
    fn profile_flag_without_value_is_rejected() {
        assert!(parse(&argv(&["plan", "--profile"])).is_err());
    }
}
