use std::collections::BTreeSet;

use crate::policy::{ModuleName, normalize_module};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PendingReport {
    Checked(Vec<ModuleName>),
    Unavailable,
}

fn is_blocked_module_log_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("module") && lower.contains("block")
}

fn extract_module_after_blocked(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let start = lower.find("blocked")?;
    let after = &line[start..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

fn parse_pending_modules(text: &str) -> Vec<ModuleName> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut result: Vec<ModuleName> = Vec::new();
    for line in text.lines() {
        if !is_blocked_module_log_line(line) {
            continue;
        }
        let Some(raw) = extract_module_after_blocked(line) else {
            continue;
        };
        let Ok(name) = ModuleName::new(&raw) else {
            continue;
        };
        let normal = normalize_module(name.as_str());
        if seen.insert(normal) {
            result.push(name);
        }
    }
    result
}

pub fn check_pending_modules<F>(fetch_journal: F) -> PendingReport
where
    F: FnOnce() -> Option<String>,
{
    match fetch_journal() {
        Some(text) => PendingReport::Checked(parse_pending_modules(&text)),
        None => PendingReport::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending_names(report: &PendingReport) -> Vec<&str> {
        match report {
            PendingReport::Checked(v) => v.iter().map(|m| m.as_str()).collect(),
            PendingReport::Unavailable => vec![],
        }
    }

    #[test]
    fn extract_module_after_blocked_handles_common_patterns() {
        assert_eq!(
            extract_module_after_blocked("kernel: module: blocked: usb-storage").as_deref(),
            Some("usb-storage")
        );
        assert_eq!(
            extract_module_after_blocked("request_module: blocked: foo_bar (-1)").as_deref(),
            Some("foo_bar")
        );
    }

    #[test]
    fn extract_module_after_blocked_returns_none_when_missing() {
        assert!(extract_module_after_blocked("nothing to see here").is_none());
        assert!(extract_module_after_blocked("blocked but no colon").is_none());
    }

    #[test]
    fn parse_pending_dedupes_by_normalized_name() {
        let text = "\
kernel: module: blocked: usb-storage
kernel: module: blocked: usb_storage
kernel: module: blocked: vfat
kernel: module: blocked: vfat
";
        let modules = parse_pending_modules(text);
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, vec!["usb-storage", "vfat"]);
    }

    #[test]
    fn parse_pending_skips_invalid_tokens() {
        let text = "kernel: module: blocked: !!!\nkernel: module: blocked: ext4\n";
        let modules = parse_pending_modules(text);
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, vec!["ext4"]);
    }

    #[test]
    fn check_pending_returns_checked_when_journal_available() {
        let report = check_pending_modules(|| {
            Some(
                "kernel: module: blocked: usb-storage\nkernel: module: blocked: vfat\n".to_string(),
            )
        });
        assert_eq!(pending_names(&report), vec!["usb-storage", "vfat"]);
    }

    #[test]
    fn check_pending_returns_unavailable_when_journal_missing() {
        let report = check_pending_modules(|| None);
        assert!(matches!(report, PendingReport::Unavailable));
    }

    #[test]
    fn check_pending_returns_empty_checked_when_no_blocked_lines() {
        let report = check_pending_modules(|| Some("clean log\nno blocks here\n".to_string()));
        match report {
            PendingReport::Checked(v) => assert!(v.is_empty()),
            other => panic!("expected Checked, got {other:?}"),
        }
    }

    #[test]
    fn parse_pending_ignores_unrelated_blocked_lines() {
        let text = "\
audit: blocked: root
network: blocked: eth0
kernel: module: blocked: usb-storage
";
        let modules = parse_pending_modules(text);
        let names: Vec<&str> = modules.iter().map(|m| m.as_str()).collect();
        assert_eq!(names, vec!["usb-storage"]);
    }

    #[test]
    fn is_blocked_module_log_line_requires_both_keywords() {
        assert!(is_blocked_module_log_line(
            "kernel: module: blocked: usb-storage"
        ));
        assert!(is_blocked_module_log_line(
            "request_module: foo (-1): blocked"
        ));
        assert!(!is_blocked_module_log_line("audit: blocked: root"));
        assert!(!is_blocked_module_log_line("network: blocked: eth0"));
        assert!(!is_blocked_module_log_line("module loaded fine"));
    }
}
