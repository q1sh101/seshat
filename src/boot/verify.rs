use std::collections::HashMap;
use std::io;
use std::path::Path;

use crate::error::Error;
use crate::policy::BootArg;
use crate::result::CheckState;

#[derive(Debug, PartialEq, Eq)]
pub struct VerifyRow {
    pub state: CheckState,
    pub arg: String,
    pub detail: String,
    pub hint: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BootVerify {
    pub rows: Vec<VerifyRow>,
}

pub fn verify_boot_params(live_cmdline: Option<&str>, expected: &[BootArg]) -> BootVerify {
    verify_against_source(live_cmdline, expected, "/proc/cmdline", "reboot required")
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrubCfgResolution {
    Resolved(String),
    Unresolved,
}

pub fn verify_grub_cfg(resolution: Option<&GrubCfgResolution>, expected: &[BootArg]) -> BootVerify {
    match resolution {
        None => verify_against_source(None, expected, "grub.cfg", "run: sudo seshat deploy boot"),
        Some(GrubCfgResolution::Resolved(cmdline)) => verify_against_source(
            Some(cmdline),
            expected,
            "grub.cfg",
            "run: sudo seshat deploy boot",
        ),
        Some(GrubCfgResolution::Unresolved) => BootVerify {
            rows: vec![VerifyRow {
                state: CheckState::Skip,
                arg: String::new(),
                detail: "default entry unresolved".to_string(),
                hint: "inspect /etc/default/grub or grubenv",
            }],
        },
    }
}

fn verify_against_source(
    source_cmdline: Option<&str>,
    expected: &[BootArg],
    source_label: &str,
    missing_hint: &'static str,
) -> BootVerify {
    let Some(live) = source_cmdline else {
        let rows = expected
            .iter()
            .map(|arg| VerifyRow {
                state: CheckState::Skip,
                arg: arg.as_str().to_string(),
                detail: format!("cannot read {source_label}"),
                hint: "",
            })
            .collect();
        return BootVerify { rows };
    };

    let tokens: Vec<&str> = live.split_whitespace().collect();
    let mut live_by_key: HashMap<&str, Vec<&str>> = HashMap::new();
    for tok in &tokens {
        live_by_key.entry(token_key(tok)).or_default().push(tok);
    }

    let mut rows = Vec::with_capacity(expected.len());
    for arg in expected {
        let expected_tok = arg.as_str();
        let ekey = token_key(expected_tok);
        let row = match live_by_key.get(ekey) {
            None => VerifyRow {
                state: CheckState::Warn,
                arg: expected_tok.to_string(),
                detail: format!("missing from {source_label}"),
                hint: missing_hint,
            },
            Some(occurrences) if occurrences.len() > 1 => VerifyRow {
                state: CheckState::Warn,
                arg: expected_tok.to_string(),
                detail: format!(
                    "ambiguous: {} occurrences of {ekey} in {source_label}",
                    occurrences.len()
                ),
                hint: missing_hint,
            },
            Some(occurrences) => {
                let live_tok = occurrences[0];
                if live_tok == expected_tok {
                    VerifyRow {
                        state: CheckState::Ok,
                        arg: expected_tok.to_string(),
                        detail: format!("present: {expected_tok}"),
                        hint: "",
                    }
                } else {
                    VerifyRow {
                        state: CheckState::Warn,
                        arg: expected_tok.to_string(),
                        detail: format!("live {live_tok}, expected {expected_tok}"),
                        hint: missing_hint,
                    }
                }
            }
        };
        rows.push(row);
    }
    BootVerify { rows }
}

pub fn read_live_cmdline(path: &Path) -> Result<Option<String>, Error> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn read_grubenv(path: &Path) -> Result<HashMap<String, String>, Error> {
    let content = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(HashMap::new()),
        Err(e) => return Err(e.into()),
    };
    let mut env = HashMap::new();
    for line in content.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            env.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    Ok(env)
}

pub fn read_grub_cfg_resolution(
    cfg_path: &Path,
    env: &HashMap<String, String>,
) -> Result<Option<GrubCfgResolution>, Error> {
    let content = match std::fs::read_to_string(cfg_path) {
        Ok(s) => s,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(Some(resolve_grub_cfg_default(&content, env)))
}

enum TopLevel {
    Menu(Option<String>),
    Sub {
        entries: Vec<Option<String>>,
        unknown_inner_positions: Vec<usize>,
    },
}

fn resolve_grub_cfg_default(content: &str, env: &HashMap<String, String>) -> GrubCfgResolution {
    let parsed = match parse_grub_cfg(content, env) {
        Ok(t) => t,
        Err(()) => return GrubCfgResolution::Unresolved,
    };
    let sel = match parsed.selectors.last() {
        None => "0".to_string(),
        Some(s) if s.is_empty() => "0".to_string(),
        Some(s) => s.clone(),
    };
    let parts: Vec<&str> = sel.split('>').collect();
    if parts.is_empty() || parts.len() > 2 {
        return GrubCfgResolution::Unresolved;
    }
    let Ok(outer) = parts[0].parse::<usize>() else {
        return GrubCfgResolution::Unresolved;
    };
    if parsed.unknown_entry_positions.iter().any(|&p| p <= outer) {
        return GrubCfgResolution::Unresolved;
    }
    let Some(entry) = parsed.top_level.get(outer) else {
        return GrubCfgResolution::Unresolved;
    };
    if parts.len() == 1 {
        return match entry {
            TopLevel::Menu(Some(cmdline)) => GrubCfgResolution::Resolved(cmdline.clone()),
            _ => GrubCfgResolution::Unresolved,
        };
    }
    let Ok(inner) = parts[1].parse::<usize>() else {
        return GrubCfgResolution::Unresolved;
    };
    match entry {
        TopLevel::Sub {
            entries,
            unknown_inner_positions,
        } => {
            if unknown_inner_positions.iter().any(|&p| p <= inner) {
                return GrubCfgResolution::Unresolved;
            }
            match entries.get(inner) {
                Some(Some(cmdline)) => GrubCfgResolution::Resolved(cmdline.clone()),
                _ => GrubCfgResolution::Unresolved,
            }
        }
        _ => GrubCfgResolution::Unresolved,
    }
}

#[derive(Clone, Copy)]
enum BranchActive {
    Yes,
    No,
    Unknown,
}

fn branch_resolved(stack: &[BranchActive]) -> Option<bool> {
    let mut active = true;
    for s in stack {
        match s {
            BranchActive::Yes => continue,
            BranchActive::No => active = false,
            BranchActive::Unknown => return None,
        }
    }
    Some(active)
}

struct ParsedGrubCfg {
    selectors: Vec<String>,
    top_level: Vec<TopLevel>,
    unknown_entry_positions: Vec<usize>,
}

fn parse_grub_cfg(content: &str, env: &HashMap<String, String>) -> Result<ParsedGrubCfg, ()> {
    let mut default_selectors: Vec<String> = Vec::new();
    let mut top_level: Vec<TopLevel> = Vec::new();
    let mut unknown_entry_positions: Vec<usize> = Vec::new();
    let mut depth: i32 = 0;
    let mut current_top_is_sub = false;
    let mut outer_if_stack: Vec<BranchActive> = Vec::new();
    let mut inner_if_stack: Vec<BranchActive> = Vec::new();
    let mut function_depth: i32 = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        if function_depth > 0 {
            for c in trimmed.chars() {
                if c == '{' {
                    function_depth += 1;
                } else if c == '}' {
                    function_depth -= 1;
                }
            }
            continue;
        }

        if depth == 0 && is_function_open(trimmed) {
            function_depth = 1;
            continue;
        }

        let in_submenu_interior = depth == 1 && current_top_is_sub;
        let in_if_scope = depth == 0 || in_submenu_interior;

        if in_if_scope {
            let stack = if depth == 0 {
                &mut outer_if_stack
            } else {
                &mut inner_if_stack
            };
            if trimmed.starts_with("if ") && trimmed.ends_with("then") {
                stack.push(match parse_if_condition(trimmed, env) {
                    Some(true) => BranchActive::Yes,
                    Some(false) => BranchActive::No,
                    None => BranchActive::Unknown,
                });
                continue;
            }
            if trimmed == "else" {
                if let Some(s) = stack.last_mut() {
                    *s = match s {
                        BranchActive::Yes => BranchActive::No,
                        BranchActive::No => BranchActive::Yes,
                        BranchActive::Unknown => BranchActive::Unknown,
                    };
                }
                continue;
            }
            if trimmed == "fi" {
                stack.pop();
                continue;
            }
        }

        let active = if depth == 0 {
            branch_resolved(&outer_if_stack)
        } else if in_submenu_interior {
            match (
                branch_resolved(&outer_if_stack),
                branch_resolved(&inner_if_stack),
            ) {
                (Some(true), Some(true)) => Some(true),
                (Some(false), _) | (_, Some(false)) => Some(false),
                _ => None,
            }
        } else {
            Some(true)
        };

        if depth == 0
            && let Some(val) = parse_set_default(trimmed)
        {
            match active {
                Some(true) => default_selectors.push(substitute_to_string(&val, env)),
                Some(false) => {}
                None => return Err(()),
            }
            continue;
        }

        if active == Some(false) {
            continue;
        }
        if active.is_none() {
            if depth == 0
                && (is_block_open(trimmed, "menuentry") || is_block_open(trimmed, "submenu"))
            {
                unknown_entry_positions.push(top_level.len());
            } else if in_submenu_interior
                && is_block_open(trimmed, "menuentry")
                && let Some(TopLevel::Sub {
                    entries,
                    unknown_inner_positions,
                }) = top_level.last_mut()
            {
                unknown_inner_positions.push(entries.len());
            }
            continue;
        }

        if depth == 0 {
            if is_block_open(trimmed, "menuentry") {
                top_level.push(TopLevel::Menu(None));
                current_top_is_sub = false;
                depth = 1;
                continue;
            }
            if is_block_open(trimmed, "submenu") {
                top_level.push(TopLevel::Sub {
                    entries: Vec::new(),
                    unknown_inner_positions: Vec::new(),
                });
                current_top_is_sub = true;
                depth = 1;
                continue;
            }
        } else {
            if trimmed == "}" {
                depth -= 1;
                if depth == 0 {
                    inner_if_stack.clear();
                }
                continue;
            }
            if is_block_open(trimmed, "menuentry") {
                if in_submenu_interior
                    && let Some(TopLevel::Sub { entries, .. }) = top_level.last_mut()
                {
                    entries.push(None);
                }
                depth += 1;
                continue;
            }
            if let Some(cmdline) = parse_linux_line(trimmed) {
                if depth == 1 && !current_top_is_sub {
                    if let Some(TopLevel::Menu(slot)) = top_level.last_mut()
                        && slot.is_none()
                    {
                        *slot = Some(cmdline);
                    }
                } else if depth == 2
                    && current_top_is_sub
                    && let Some(TopLevel::Sub { entries, .. }) = top_level.last_mut()
                    && let Some(slot @ None) = entries.last_mut()
                {
                    *slot = Some(cmdline);
                }
            }
        }
    }
    Ok(ParsedGrubCfg {
        selectors: default_selectors,
        top_level,
        unknown_entry_positions,
    })
}

fn substitute_to_string(value: &str, env: &HashMap<String, String>) -> String {
    if !value.contains('$') {
        return value.to_string();
    }
    if let Some(inner) = value.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
        return env.get(inner).cloned().unwrap_or_default();
    }
    value.to_string()
}

fn parse_if_condition(line: &str, env: &HashMap<String, String>) -> Option<bool> {
    let rest = line.strip_prefix("if ")?.strip_suffix("then")?.trim();
    let rest = rest.trim_end_matches(';').trim();
    let inside = rest.strip_prefix('[')?.strip_suffix(']')?.trim();
    if let Some(var) = parse_quoted_var_ref(inside) {
        return Some(env.get(&var).is_some_and(|v| !v.is_empty()));
    }
    if let Some(rest) = inside.strip_prefix("-n ")
        && let Some(var) = parse_quoted_var_ref(rest.trim())
    {
        return Some(env.get(&var).is_some_and(|v| !v.is_empty()));
    }
    if let Some(rest) = inside.strip_prefix("-z ")
        && let Some(var) = parse_quoted_var_ref(rest.trim())
    {
        return Some(env.get(&var).is_none_or(|v| v.is_empty()));
    }
    None
}

fn is_function_open(line: &str) -> bool {
    line.starts_with("function ") && line.ends_with('{')
}

fn parse_quoted_var_ref(s: &str) -> Option<String> {
    let unquoted = s
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .unwrap_or(s);
    let inner = unquoted
        .strip_prefix("${")
        .and_then(|r| r.strip_suffix('}'))?;
    Some(inner.to_string())
}

fn parse_set_default(line: &str) -> Option<String> {
    let rest = line.strip_prefix("set ")?.trim_start();
    let rest = rest.strip_prefix("default=")?;
    Some(rest.trim_matches(|c| c == '"' || c == '\'').to_string())
}

fn is_block_open(line: &str, kind: &str) -> bool {
    line.starts_with(kind)
        && line
            .as_bytes()
            .get(kind.len())
            .is_some_and(u8::is_ascii_whitespace)
        && line.ends_with('{')
}

fn parse_linux_line(line: &str) -> Option<String> {
    let mut tokens = line.split_whitespace();
    match tokens.next() {
        Some("linux") | Some("linuxefi") | Some("linux16") => {}
        _ => return None,
    }
    tokens.next()?;
    let args: Vec<&str> = tokens.collect();
    Some(args.join(" "))
}

fn token_key(tok: &str) -> &str {
    match tok.split_once('=') {
        Some((k, _)) => k,
        None => tok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn args(list: &[&str]) -> Vec<BootArg> {
        list.iter().map(|s| BootArg::new(s).unwrap()).collect()
    }

    #[test]
    fn all_skip_when_live_cmdline_unavailable() {
        let expected = args(&["debugfs=off", "init_on_alloc=1"]);
        let verify = verify_boot_params(None, &expected);
        assert_eq!(verify.rows.len(), 2);
        assert!(verify.rows.iter().all(|r| r.state == CheckState::Skip));
        assert!(
            verify.rows[0].detail.contains("/proc/cmdline"),
            "skip detail should name /proc/cmdline"
        );
    }

    #[test]
    fn ok_when_expected_present_with_matching_value() {
        let expected = args(&["debugfs=off"]);
        let verify = verify_boot_params(Some("quiet debugfs=off ro"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
        assert_eq!(verify.rows[0].detail, "present: debugfs=off");
        assert_eq!(verify.rows[0].hint, "");
    }

    #[test]
    fn warn_when_expected_value_differs_from_live_with_reboot_hint() {
        let expected = args(&["debugfs=off"]);
        let verify = verify_boot_params(Some("quiet debugfs=on"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Warn);
        assert_eq!(
            verify.rows[0].detail,
            "live debugfs=on, expected debugfs=off"
        );
        assert_eq!(verify.rows[0].hint, "reboot required");
    }

    #[test]
    fn warn_when_expected_missing_from_live_with_reboot_hint() {
        let expected = args(&["init_on_alloc=1"]);
        let verify = verify_boot_params(Some("quiet splash"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Warn);
        assert_eq!(verify.rows[0].detail, "missing from /proc/cmdline");
        assert_eq!(verify.rows[0].hint, "reboot required");
    }

    #[test]
    fn boolean_flag_matches_when_no_value() {
        let expected = args(&["quiet"]);
        let verify = verify_boot_params(Some("ro quiet splash"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
    }

    #[test]
    fn mixed_states_across_expected() {
        let expected = args(&["quiet", "debugfs=off", "init_on_alloc=1"]);
        let verify = verify_boot_params(Some("ro quiet debugfs=on"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
        assert_eq!(verify.rows[1].state, CheckState::Warn);
        assert_eq!(verify.rows[2].state, CheckState::Warn);
    }

    #[test]
    fn preserves_expected_order_in_rows() {
        let expected = args(&["a=1", "b=2", "c=3"]);
        let verify = verify_boot_params(Some("a=1 b=2 c=3"), &expected);
        let keys: Vec<&str> = verify.rows.iter().map(|r| r.arg.as_str()).collect();
        assert_eq!(keys, vec!["a=1", "b=2", "c=3"]);
    }

    #[test]
    fn verify_never_emits_change_or_fail_states() {
        let expected = args(&["quiet", "debugfs=off", "missing_arg=1"]);
        let verify = verify_boot_params(Some("quiet debugfs=on"), &expected);
        for row in &verify.rows {
            assert!(
                matches!(
                    row.state,
                    CheckState::Ok | CheckState::Warn | CheckState::Skip
                ),
                "unexpected state {:?}",
                row.state
            );
        }
    }

    #[test]
    fn duplicate_live_key_warns_even_when_first_occurrence_matches_expected() {
        let expected = args(&["debugfs=off"]);
        let verify = verify_boot_params(Some("debugfs=off debugfs=on"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Warn);
        assert!(verify.rows[0].detail.contains("ambiguous"));
        assert!(verify.rows[0].detail.contains("debugfs"));
        assert_eq!(verify.rows[0].hint, "reboot required");
    }

    #[test]
    fn duplicate_live_key_warns_regardless_of_order() {
        let expected = args(&["debugfs=off"]);
        let verify = verify_boot_params(Some("debugfs=on quiet debugfs=off"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Warn);
        assert!(verify.rows[0].detail.contains("ambiguous"));
    }

    #[test]
    fn duplicate_live_key_reports_occurrence_count() {
        let expected = args(&["debugfs=off"]);
        let verify = verify_boot_params(Some("debugfs=a debugfs=b debugfs=c"), &expected);
        assert!(verify.rows[0].detail.contains('3'));
    }

    #[test]
    fn duplicate_unrelated_key_is_ignored_when_not_in_expected() {
        let expected = args(&["debugfs=off"]);
        let verify = verify_boot_params(Some("ro ro debugfs=off"), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
    }

    #[test]
    fn read_live_cmdline_returns_content_when_file_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, "quiet splash debugfs=off\n").unwrap();
        let got = read_live_cmdline(&path).unwrap();
        assert_eq!(got.as_deref(), Some("quiet splash debugfs=off\n"));
    }

    #[test]
    fn read_live_cmdline_returns_none_when_file_missing() {
        let dir = tempdir().unwrap();
        let got = read_live_cmdline(&dir.path().join("cmdline-absent")).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn read_live_cmdline_preserves_raw_body_for_verify_to_tokenize() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("cmdline");
        std::fs::write(&path, "a  b\tc\n").unwrap();
        let got = read_live_cmdline(&path).unwrap().unwrap();
        assert_eq!(got, "a  b\tc\n");
    }

    #[test]
    fn resolve_default_picks_first_menuentry_when_no_set_default() {
        let body = "\
menuentry 'Linux' {
    linux /boot/vmlinuz-test root=UUID=abc ro quiet debugfs=off
    initrd /boot/initrd-test
}
";
        let got = resolve_grub_cfg_default(body, &HashMap::new());
        assert_eq!(
            got,
            GrubCfgResolution::Resolved("root=UUID=abc ro quiet debugfs=off".to_string())
        );
    }

    #[test]
    fn resolve_default_honors_explicit_top_level_index() {
        let body = "\
set default=\"1\"
menuentry 'First' {
    linux /boot/vmlinuz-test ro debugfs=on
}
menuentry 'Second' {
    linux /boot/vmlinuz-test ro debugfs=off
}
";
        let got = resolve_grub_cfg_default(body, &HashMap::new());
        assert_eq!(
            got,
            GrubCfgResolution::Resolved("ro debugfs=off".to_string())
        );
    }

    #[test]
    fn resolve_default_honors_submenu_index_syntax() {
        let body = "\
set default=\"1>0\"
menuentry 'Top' {
    linux /boot/vmlinuz-test ro top_arg=1
}
submenu 'Advanced' {
    menuentry 'Nested' {
        linux /boot/vmlinuz-test ro nested_arg=1
    }
}
";
        let got = resolve_grub_cfg_default(body, &HashMap::new());
        assert_eq!(
            got,
            GrubCfgResolution::Resolved("ro nested_arg=1".to_string())
        );
    }

    #[test]
    fn resolve_default_sequential_literals_take_last_assignment() {
        let body = "\
set default=\"0\"
set default=\"1\"
menuentry 'First' {
    linux /boot/vmlinuz-test ro first
}
menuentry 'Second' {
    linux /boot/vmlinuz-test ro second
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Resolved("ro second".to_string())
        );
    }

    #[test]
    fn resolve_default_uses_next_entry_from_grubenv_when_present() {
        let body = "\
if [ \"${next_entry}\" ] ; then
    set default=\"${next_entry}\"
else
    set default=\"0\"
fi
menuentry 'First' {
    linux /boot/vmlinuz-test ro first
}
menuentry 'Second' {
    linux /boot/vmlinuz-test ro second
}
";
        let mut env = HashMap::new();
        env.insert("next_entry".to_string(), "1".to_string());
        assert_eq!(
            resolve_grub_cfg_default(body, &env),
            GrubCfgResolution::Resolved("ro second".to_string())
        );
    }

    #[test]
    fn resolve_default_falls_back_to_literal_when_grubenv_lacks_var() {
        let body = "\
if [ \"${next_entry}\" ] ; then
    set default=\"${next_entry}\"
else
    set default=\"0\"
fi
menuentry 'First' {
    linux /boot/vmlinuz-test ro first
}
menuentry 'Second' {
    linux /boot/vmlinuz-test ro second
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Resolved("ro first".to_string())
        );
    }

    #[test]
    fn resolve_default_uses_saved_entry_from_grubenv_when_present() {
        let body = "set default=\"${saved_entry}\"\nmenuentry 'A' {\n  linux /boot/vmlinuz-test ro a\n}\nmenuentry 'B' {\n  linux /boot/vmlinuz-test ro b\n}\n";
        let mut env = HashMap::new();
        env.insert("saved_entry".to_string(), "1".to_string());
        assert_eq!(
            resolve_grub_cfg_default(body, &env),
            GrubCfgResolution::Resolved("ro b".to_string())
        );
    }

    #[test]
    fn read_grubenv_parses_key_value_lines_and_skips_comments_and_padding() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("grubenv");
        std::fs::write(
            &path,
            "# GRUB Environment Block\nsaved_entry=2\nnext_entry=1\n##########\n",
        )
        .unwrap();
        let env = read_grubenv(&path).unwrap();
        assert_eq!(env.get("saved_entry").map(String::as_str), Some("2"));
        assert_eq!(env.get("next_entry").map(String::as_str), Some("1"));
    }

    #[test]
    fn read_grubenv_returns_empty_map_when_file_missing() {
        let dir = tempdir().unwrap();
        let env = read_grubenv(&dir.path().join("absent")).unwrap();
        assert!(env.is_empty());
    }

    #[test]
    fn resolve_default_falls_back_to_entry_zero_when_var_empty_in_env() {
        let body = "\
set default=\"${saved_entry}\"
menuentry 'Linux' {
    linux /boot/vmlinuz-test ro quiet
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Resolved("ro quiet".to_string())
        );
    }

    #[test]
    fn resolve_default_ignores_function_body_with_multi_statement_fi_chain() {
        let body = "\
if [ \"${next_entry}\" ] ; then
    set default=\"${next_entry}\"
else
    set default=\"0\"
fi
function initrdfail {
    if [ -n \"${have_grubenv}\" ]; then if [ -n \"${partuuid}\" ]; then
        save_env initrdfail
    fi; fi
}
menuentry 'First' {
    linux /boot/vmlinuz-test ro first
}
menuentry 'Second' {
    linux /boot/vmlinuz-test ro second
}
";
        let mut env = HashMap::new();
        env.insert("next_entry".to_string(), "1".to_string());
        assert_eq!(
            resolve_grub_cfg_default(body, &env),
            GrubCfgResolution::Resolved("ro second".to_string())
        );
    }

    #[test]
    fn resolve_default_handles_real_world_grub_cfg_header_with_functions_and_unknown_ifs() {
        let body = "\
if [ -s $prefix/grubenv ]; then
   load_env
fi
if [ \"${env_block}\" ] ; then
   set env_block=
fi
if [ \"${initrdfail}\" = 2 ]; then
   set pager=1
   if [ \"${next_entry}\" ]; then
      save_env next_entry
   fi
fi
if [ \"${next_entry}\" ] ; then
   set default=\"${next_entry}\"
   set next_entry=
   if [ \"${env_block}\" ] ; then
      save_env env_block
   else
      save_env env_block
   fi
   set boot_once=true
else
   set default=\"0\"
fi
if [ x\"${feature_menuentry_id}\" = xy ]; then
  menuentry_id_option=\"--id\"
else
  menuentry_id_option=\"\"
fi
function savedefault {
  if [ -z \"${boot_once}\" ]; then
    saved_entry=\"${chosen}\"
    if [ \"${env_block}\" ] ; then
      save_env saved_entry
    else
      save_env saved_entry
    fi
  fi
}
function initrdfail {
    if [ -n \"${have_grubenv}\" ]; then if [ -n \"${partuuid}\" ]; then
      if [ -z \"${initrdfail}\" ]; then
        set initrdfail=1
        if [ -n \"${boot_once}\" ]; then
           set initrdfail=2
        fi
      fi
    fi; fi
}
function recordfail {
  set recordfail=1
  if [ -n \"${have_grubenv}\" ]; then if [ -z \"${boot_once}\" ]; then save_env recordfail; fi; fi
}
function load_video {
  if [ x$grub_platform = xefi ]; then
    insmod efi_gop
    insmod efi_uga
  else
    insmod all_video
  fi
}
if [ x$feature_default_font_path = xy ] ; then
   font=unicode
else
   font=$prefix/fonts/unicode.pf2
fi
if loadfont $font ; then
   set gfxmode=auto
fi
menuentry 'Linux' --class gnu-linux $menuentry_id_option 'gnulinux-simple-uuid' {
   linux /boot/vmlinuz-test root=UUID=test ro quiet splash
   initrd /boot/initrd-test
}
submenu 'Advanced options' $menuentry_id_option 'gnulinux-advanced-uuid' {
   menuentry 'Linux (advanced)' $menuentry_id_option 'gnulinux-test-advanced' {
      linux /boot/vmlinuz-test root=UUID=test ro quiet splash
   }
   menuentry 'Linux (recovery mode)' $menuentry_id_option 'gnulinux-test-recovery' {
      linux /boot/vmlinuz-test root=UUID=test ro recovery nomodeset
   }
}
if [ \"$grub_platform\" = efi -a \"$grub_cpu\" = x86_64 ]; then
   menuentry \"Memory test\" --class memtest $menuentry_id_option \"memtest\" {
      linux /boot/memtest.bin
   }
fi
";
        let result = resolve_grub_cfg_default(body, &HashMap::new());
        assert_eq!(
            result,
            GrubCfgResolution::Resolved("root=UUID=test ro quiet splash".to_string()),
            "real-world grub.cfg header should resolve to first top-level menuentry's cmdline; got {result:?}"
        );
    }

    #[test]
    fn resolve_default_safe_when_unknown_menuentry_appears_after_selected_index() {
        let body = "\
set default=\"0\"
menuentry 'Main' {
    linux /boot/vmlinuz-test ro main
}
if [ \"$grub_platform\" = efi ]; then
    menuentry 'Memtest' {
        linux /boot/memtest ro memtest
    }
fi
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Resolved("ro main".to_string())
        );
    }

    #[test]
    fn resolve_default_returns_unresolved_when_unknown_menuentry_inside_submenu_before_selected_inner()
     {
        let body = "\
set default=\"1>0\"
menuentry 'Top' {
    linux /boot/vmlinuz-test ro top
}
submenu 'Advanced' {
    if [ \"$grub_platform\" = efi ]; then
        menuentry 'Conditional Inner' {
            linux /boot/vmlinuz-test ro conditional
        }
    fi
    menuentry 'Normal Inner 0' {
        linux /boot/vmlinuz-test ro inner0
    }
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Unresolved
        );
    }

    #[test]
    fn resolve_default_resolves_submenu_inner_when_no_conditional_before_selected() {
        let body = "\
set default=\"1>1\"
menuentry 'Top' {
    linux /boot/vmlinuz-test ro top
}
submenu 'Advanced' {
    menuentry 'Inner 0' {
        linux /boot/vmlinuz-test ro inner0
    }
    menuentry 'Inner 1' {
        linux /boot/vmlinuz-test ro inner1
    }
    if [ \"$grub_platform\" = efi ]; then
        menuentry 'Conditional Inner After' {
            linux /boot/vmlinuz-test ro conditional
        }
    fi
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Resolved("ro inner1".to_string())
        );
    }

    #[test]
    fn resolve_default_returns_unresolved_when_unknown_menuentry_before_selected_index() {
        let body = "\
set default=\"0\"
if [ \"$grub_platform\" = efi ]; then
    menuentry 'Conditional First' {
        linux /boot/vmlinuz-test ro conditional
    }
fi
menuentry 'Normal First' {
    linux /boot/vmlinuz-test ro normal
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Unresolved
        );
    }

    #[test]
    fn resolve_default_returns_unresolved_when_if_condition_is_unparseable() {
        let body = "\
if [ -f /etc/grub.cfg ] ; then
    set default=\"0\"
fi
menuentry 'Linux' {
    linux /boot/vmlinuz-test ro quiet
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Unresolved
        );
    }

    #[test]
    fn resolve_default_sequential_overrides_var_with_following_literal() {
        let body = "\
set default=\"${saved_entry}\"
set default=\"0\"
menuentry 'Linux' {
    linux /boot/vmlinuz-test ro quiet
}
";
        let mut env = HashMap::new();
        env.insert("saved_entry".to_string(), "1".to_string());
        assert_eq!(
            resolve_grub_cfg_default(body, &env),
            GrubCfgResolution::Resolved("ro quiet".to_string())
        );
    }

    #[test]
    fn resolve_default_returns_unresolved_when_index_out_of_range() {
        let body = "\
set default=\"5\"
menuentry 'Only' {
    linux /boot/vmlinuz-test ro
}
";
        assert_eq!(
            resolve_grub_cfg_default(body, &HashMap::new()),
            GrubCfgResolution::Unresolved
        );
    }

    #[test]
    fn resolve_default_accepts_linuxefi_variant() {
        let body = "    linuxefi /boot/vmlinuz-test root=UUID=abc ro quiet\n";
        let body = format!("menuentry 'Linux' {{\n{body}}}\n");
        let got = resolve_grub_cfg_default(&body, &HashMap::new());
        assert_eq!(
            got,
            GrubCfgResolution::Resolved("root=UUID=abc ro quiet".to_string())
        );
    }

    #[test]
    fn resolve_default_accepts_linux16_variant() {
        let body = "menuentry 'Linux' {\n    linux16 /boot/vmlinuz-test ro quiet\n}\n";
        let got = resolve_grub_cfg_default(body, &HashMap::new());
        assert_eq!(got, GrubCfgResolution::Resolved("ro quiet".to_string()));
    }

    #[test]
    fn verify_grub_cfg_reports_present_when_resolved_cmdline_has_arg() {
        let expected = args(&["debugfs=off"]);
        let resolution = GrubCfgResolution::Resolved("ro quiet debugfs=off".to_string());
        let verify = verify_grub_cfg(Some(&resolution), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
    }

    #[test]
    fn verify_grub_cfg_warns_with_backend_neutral_hint_when_arg_missing() {
        let expected = args(&["debugfs=off"]);
        let resolution = GrubCfgResolution::Resolved("ro quiet".to_string());
        let verify = verify_grub_cfg(Some(&resolution), &expected);
        assert_eq!(verify.rows[0].state, CheckState::Warn);
        assert_eq!(verify.rows[0].hint, "run: sudo seshat deploy boot");
        assert!(verify.rows[0].detail.contains("grub.cfg"));
    }

    #[test]
    fn verify_grub_cfg_skips_with_inspect_hint_when_default_unresolved() {
        let expected = args(&["debugfs=off", "init_on_alloc=1", "iommu=force"]);
        let verify = verify_grub_cfg(Some(&GrubCfgResolution::Unresolved), &expected);
        assert_eq!(
            verify.rows.len(),
            1,
            "Unresolved must collapse to one section-level row regardless of expected count"
        );
        assert_eq!(verify.rows[0].state, CheckState::Skip);
        assert!(verify.rows[0].arg.is_empty());
        assert!(verify.rows[0].detail.contains("unresolved"));
        assert!(verify.rows[0].hint.contains("grubenv"));
    }

    #[test]
    fn verify_grub_cfg_skips_when_resolution_is_none_file_missing() {
        let expected = args(&["debugfs=off"]);
        let verify = verify_grub_cfg(None, &expected);
        assert_eq!(verify.rows[0].state, CheckState::Skip);
        assert!(verify.rows[0].detail.contains("grub.cfg"));
    }
}
