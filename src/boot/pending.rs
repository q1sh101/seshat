use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum BootPendingKind {
    CmdlineMissing,
    UnknownParam,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BootPendingEntry {
    pub arg: String,
    pub kind: BootPendingKind,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BootPendingReport {
    Checked(Vec<BootPendingEntry>),
    Unavailable,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct BootPendingInputs {
    pub expected: Vec<String>,
    pub actual_cmdline: Option<String>,
    pub dmesg: Option<String>,
}

fn tokenize_cmdline(s: &str) -> Vec<String> {
    s.split_whitespace().map(|t| t.to_string()).collect()
}

fn diff_cmdline(expected: &[String], actual: &[String]) -> Vec<BootPendingEntry> {
    let act: BTreeSet<&str> = actual.iter().map(String::as_str).collect();
    let mut result: Vec<BootPendingEntry> = Vec::new();
    for missing in expected.iter().filter(|a| !act.contains(a.as_str())) {
        result.push(BootPendingEntry {
            arg: missing.clone(),
            kind: BootPendingKind::CmdlineMissing,
        });
    }
    result
}

fn extract_unknown_params(line: &str) -> Vec<String> {
    let lower = line.to_ascii_lowercase();
    if !lower.contains("unknown") || !lower.contains("kernel") {
        return Vec::new();
    }
    let Some(start) = line.find('"') else {
        return Vec::new();
    };
    let after = &line[start + 1..];
    let Some(end_pos) = after.find('"') else {
        return Vec::new();
    };
    tokenize_cmdline(&after[..end_pos])
}

fn parse_unknown_param_lines(text: &str) -> Vec<BootPendingEntry> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut result: Vec<BootPendingEntry> = Vec::new();
    for line in text.lines() {
        for arg in extract_unknown_params(line) {
            if seen.insert(arg.clone()) {
                result.push(BootPendingEntry {
                    arg,
                    kind: BootPendingKind::UnknownParam,
                });
            }
        }
    }
    result
}

pub fn check_boot_pending(inputs: BootPendingInputs) -> BootPendingReport {
    let mut any = false;
    let mut entries: Vec<BootPendingEntry> = Vec::new();

    if let Some(actual) = inputs.actual_cmdline.as_deref() {
        let actual_args = tokenize_cmdline(actual);
        entries.extend(diff_cmdline(&inputs.expected, &actual_args));
        any = true;
    }

    if let Some(dmesg) = inputs.dmesg.as_deref() {
        entries.extend(parse_unknown_param_lines(dmesg));
        any = true;
    }

    if !any {
        return BootPendingReport::Unavailable;
    }
    BootPendingReport::Checked(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    fn entry_pairs(report: &BootPendingReport) -> Vec<(&str, BootPendingKind)> {
        match report {
            BootPendingReport::Checked(v) => v.iter().map(|e| (e.arg.as_str(), e.kind)).collect(),
            BootPendingReport::Unavailable => vec![],
        }
    }

    #[test]
    fn tokenize_cmdline_splits_on_whitespace() {
        assert_eq!(
            tokenize_cmdline("quiet splash iommu=force"),
            vec!["quiet", "splash", "iommu=force"]
        );
        assert_eq!(tokenize_cmdline(""), Vec::<String>::new());
        assert_eq!(tokenize_cmdline("  spaced   out  "), vec!["spaced", "out"]);
    }

    #[test]
    fn diff_cmdline_returns_missing_only() {
        let expected = args(&["iommu=force", "init_on_alloc=1"]);
        let actual = args(&["init_on_alloc=1", "quiet", "splash"]);
        let entries = diff_cmdline(&expected, &actual);
        let pairs: Vec<(&str, BootPendingKind)> =
            entries.iter().map(|e| (e.arg.as_str(), e.kind)).collect();
        assert_eq!(
            pairs,
            vec![("iommu=force", BootPendingKind::CmdlineMissing)]
        );
    }

    #[test]
    fn diff_cmdline_does_not_treat_unmanaged_boot_args_as_pending() {
        let expected = args(&[]);
        let actual = args(&["BOOT_IMAGE=/vmlinuz", "root=UUID=x", "rw", "quiet"]);
        assert!(diff_cmdline(&expected, &actual).is_empty());
    }

    #[test]
    fn diff_cmdline_empty_when_match() {
        let expected = args(&["iommu=force", "quiet"]);
        let actual = args(&["iommu=force", "quiet"]);
        assert!(diff_cmdline(&expected, &actual).is_empty());
    }

    #[test]
    fn extract_unknown_params_pulls_args_from_quoted_phrase() {
        let line = "Unknown kernel command line parameters \"foo=1 bar baz\", will be passed.";
        assert_eq!(extract_unknown_params(line), vec!["foo=1", "bar", "baz"]);
    }

    #[test]
    fn extract_unknown_params_empty_on_unrelated_line() {
        assert!(extract_unknown_params("regular kernel boot message").is_empty());
        assert!(extract_unknown_params("Unknown without keyword").is_empty());
        assert!(extract_unknown_params("Unknown kernel without quotes here").is_empty());
    }

    #[test]
    fn parse_unknown_param_lines_dedupes_repeats() {
        let text = "\
[ 0.000000] Unknown kernel command line parameters \"foo=1 bar\", will be passed.
[ 0.000001] Unknown kernel command line parameters \"foo=1 baz\", will be passed.
";
        let entries = parse_unknown_param_lines(text);
        let args: Vec<&str> = entries.iter().map(|e| e.arg.as_str()).collect();
        assert_eq!(args, vec!["foo=1", "bar", "baz"]);
    }

    #[test]
    fn check_boot_pending_returns_unavailable_when_no_sources() {
        let report = check_boot_pending(BootPendingInputs::default());
        assert!(matches!(report, BootPendingReport::Unavailable));
    }

    #[test]
    fn check_boot_pending_reports_cmdline_diff_only() {
        let report = check_boot_pending(BootPendingInputs {
            expected: args(&["iommu=force", "init_on_alloc=1"]),
            actual_cmdline: Some("init_on_alloc=1 quiet".to_string()),
            dmesg: None,
        });
        assert_eq!(
            entry_pairs(&report),
            vec![("iommu=force", BootPendingKind::CmdlineMissing)]
        );
    }

    #[test]
    fn check_boot_pending_reports_unknown_param_only() {
        let report = check_boot_pending(BootPendingInputs {
            expected: Vec::new(),
            actual_cmdline: None,
            dmesg: Some(
                "Unknown kernel command line parameters \"init_on_alloc=1\", will be passed.\n"
                    .to_string(),
            ),
        });
        assert_eq!(
            entry_pairs(&report),
            vec![("init_on_alloc=1", BootPendingKind::UnknownParam)]
        );
    }

    #[test]
    fn check_boot_pending_merges_cmdline_and_unknown_evidence() {
        let report = check_boot_pending(BootPendingInputs {
            expected: args(&["iommu=force", "init_on_alloc=1"]),
            actual_cmdline: Some("init_on_alloc=1".to_string()),
            dmesg: Some(
                "Unknown kernel command line parameters \"init_on_alloc=1\", will be passed.\n"
                    .to_string(),
            ),
        });
        assert_eq!(
            entry_pairs(&report),
            vec![
                ("iommu=force", BootPendingKind::CmdlineMissing),
                ("init_on_alloc=1", BootPendingKind::UnknownParam),
            ]
        );
    }

    #[test]
    fn check_boot_pending_empty_checked_when_all_applied() {
        let report = check_boot_pending(BootPendingInputs {
            expected: args(&["iommu=force"]),
            actual_cmdline: Some("iommu=force".to_string()),
            dmesg: Some("normal boot messages\n".to_string()),
        });
        assert!(matches!(report, BootPendingReport::Checked(ref v) if v.is_empty()));
    }
}
