use std::collections::BTreeSet;

use crate::paths::MODULE_DENY_HELPER;
use crate::policy::{ModuleName, normalize_module};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum PendingSource {
    Kernel,
    Modprobe,
    Helper,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PendingEntry {
    pub name: ModuleName,
    pub source: PendingSource,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PendingReport {
    Checked(Vec<PendingEntry>),
    Unavailable,
}

#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct PendingSources {
    pub state_file: Option<String>,
    pub kmsg: Option<String>,
    pub journal: Option<String>,
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

fn is_modprobe_install_blocked_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("install command '")
        && lower.contains("for module")
        && (lower.contains("/bin/false")
            || lower.contains("/bin/true")
            || lower.contains("/usr/bin/false")
            || lower.contains("/usr/bin/true")
            || lower.contains("/dev/null")
            || lower.contains(MODULE_DENY_HELPER))
}

fn extract_module_after_install_blocked(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let start = lower.find("for module")?;
    let after = &line[start + "for module".len()..];
    let rest = after.trim_start();
    let token: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect();
    if token.is_empty() { None } else { Some(token) }
}

fn extract_module_from_helper_line(line: &str) -> Option<String> {
    let mut parts = line.splitn(3, '\t');
    let _ts = parts.next()?;
    let raw = parts.next()?;
    let tag = parts.next()?;
    if tag != "helper" {
        return None;
    }
    Some(raw.to_string())
}

fn parse_with<F>(text: &str, mut classify: F) -> Vec<PendingEntry>
where
    F: FnMut(&str) -> Option<(String, PendingSource)>,
{
    let mut seen: BTreeSet<(String, PendingSource)> = BTreeSet::new();
    let mut result: Vec<PendingEntry> = Vec::new();
    for line in text.lines() {
        let Some((raw, source)) = classify(line) else {
            continue;
        };
        let Ok(name) = ModuleName::new(&raw) else {
            continue;
        };
        let normal = normalize_module(name.as_str());
        if seen.insert((normal, source)) {
            result.push(PendingEntry { name, source });
        }
    }
    result
}

pub fn parse_kernel_log(text: &str) -> Vec<PendingEntry> {
    parse_with(text, |line| {
        if is_blocked_module_log_line(line) {
            extract_module_after_blocked(line).map(|raw| (raw, PendingSource::Kernel))
        } else {
            None
        }
    })
}

pub fn parse_modprobe_log(text: &str) -> Vec<PendingEntry> {
    parse_with(text, |line| {
        if is_modprobe_install_blocked_line(line) {
            extract_module_after_install_blocked(line).map(|raw| (raw, PendingSource::Modprobe))
        } else {
            None
        }
    })
}

pub fn parse_helper_log(text: &str) -> Vec<PendingEntry> {
    parse_with(text, |line| {
        extract_module_from_helper_line(line).map(|raw| (raw, PendingSource::Helper))
    })
}

pub fn check_pending_modules(sources: PendingSources) -> PendingReport {
    let mut entries: Vec<PendingEntry> = Vec::new();
    let mut any = false;
    if let Some(t) = sources.state_file.as_deref() {
        entries.extend(parse_helper_log(t));
        any = true;
    }
    if let Some(t) = sources.kmsg.as_deref() {
        entries.extend(parse_kernel_log(t));
        any = true;
    }
    if let Some(t) = sources.journal.as_deref() {
        entries.extend(parse_kernel_log(t));
        entries.extend(parse_modprobe_log(t));
        any = true;
    }
    if !any {
        return PendingReport::Unavailable;
    }
    let mut seen: BTreeSet<(String, PendingSource)> = BTreeSet::new();
    let mut dedup: Vec<PendingEntry> = Vec::new();
    for e in entries {
        let key = (normalize_module(e.name.as_str()), e.source);
        if seen.insert(key) {
            dedup.push(e);
        }
    }
    PendingReport::Checked(dedup)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_pending_modules(text: &str) -> Vec<PendingEntry> {
        let mut entries = parse_kernel_log(text);
        entries.extend(parse_modprobe_log(text));
        let mut seen: BTreeSet<(String, PendingSource)> = BTreeSet::new();
        let mut dedup: Vec<PendingEntry> = Vec::new();
        for e in entries {
            let key = (normalize_module(e.name.as_str()), e.source);
            if seen.insert(key) {
                dedup.push(e);
            }
        }
        dedup
    }

    fn pending_names(report: &PendingReport) -> Vec<&str> {
        match report {
            PendingReport::Checked(v) => v.iter().map(|e| e.name.as_str()).collect(),
            PendingReport::Unavailable => vec![],
        }
    }

    fn pending_pairs(report: &PendingReport) -> Vec<(&str, PendingSource)> {
        match report {
            PendingReport::Checked(v) => v.iter().map(|e| (e.name.as_str(), e.source)).collect(),
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
    fn extract_module_after_install_blocked_handles_common_patterns() {
        assert_eq!(
            extract_module_after_install_blocked(
                "modprobe: ERROR: Error running install command '/bin/false' for module lz4_compress: retcode 1"
            )
            .as_deref(),
            Some("lz4_compress")
        );
        assert_eq!(
            extract_module_after_install_blocked(
                "modprobe: ERROR: Error running install command '/bin/false' for module usb-storage"
            )
            .as_deref(),
            Some("usb-storage")
        );
    }

    #[test]
    fn extract_module_after_install_blocked_returns_none_when_missing() {
        assert!(extract_module_after_install_blocked("modprobe: loading driver ok").is_none());
        assert!(
            extract_module_after_install_blocked("install command '/bin/false' for module")
                .is_none()
        );
    }

    #[test]
    fn extract_module_from_helper_line_parses_tsv() {
        assert_eq!(
            extract_module_from_helper_line("2026-05-19T03:25:33Z\tzram\thelper").as_deref(),
            Some("zram")
        );
        assert_eq!(
            extract_module_from_helper_line("2026-05-19T03:25:33Z\tusb-storage\thelper").as_deref(),
            Some("usb-storage")
        );
    }

    #[test]
    fn extract_module_from_helper_line_rejects_unknown_tag() {
        assert!(extract_module_from_helper_line("2026-05-19T03:25:33Z\tzram\tjournal").is_none());
        assert!(extract_module_from_helper_line("not a tsv line").is_none());
        assert!(extract_module_from_helper_line("\t\t").is_none());
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
        let names: Vec<&str> = modules.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["usb-storage", "vfat"]);
    }

    #[test]
    fn parse_pending_skips_invalid_tokens() {
        let text = "kernel: module: blocked: !!!\nkernel: module: blocked: ext4\n";
        let modules = parse_pending_modules(text);
        let names: Vec<&str> = modules.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["ext4"]);
    }

    #[test]
    fn parse_pending_tags_kernel_and_modprobe_sources() {
        let text = "\
kernel: module: blocked: usb-storage
modprobe: ERROR: Error running install command '/bin/false' for module lz4_compress: retcode 1
modprobe: ERROR: Error running install command '/bin/false' for module zram
";
        let modules = parse_pending_modules(text);
        let pairs: Vec<(&str, PendingSource)> = modules
            .iter()
            .map(|e| (e.name.as_str(), e.source))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("usb-storage", PendingSource::Kernel),
                ("lz4_compress", PendingSource::Modprobe),
                ("zram", PendingSource::Modprobe),
            ]
        );
    }

    #[test]
    fn parse_pending_preserves_same_module_across_sources() {
        let text = "\
kernel: module: blocked: zram
modprobe: ERROR: Error running install command '/bin/false' for module zram: retcode 1
";
        let modules = parse_pending_modules(text);
        let pairs: Vec<(&str, PendingSource)> = modules
            .iter()
            .map(|e| (e.name.as_str(), e.source))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("zram", PendingSource::Kernel),
                ("zram", PendingSource::Modprobe),
            ]
        );
    }

    #[test]
    fn parse_pending_dedupes_per_source() {
        let text = "\
modprobe: ERROR: Error running install command '/bin/false' for module lz4_compress: retcode 1
modprobe: ERROR: Error running install command '/bin/false' for module lz4_compress: retcode 1
modprobe: ERROR: Error running install command '/bin/false' for module lz4-compress
";
        let modules = parse_pending_modules(text);
        let names: Vec<&str> = modules.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["lz4_compress"]);
    }

    #[test]
    fn parse_helper_log_reads_tsv_entries() {
        let text = "\
2026-05-19T03:25:33Z\tzram\thelper
2026-05-19T03:25:34Z\tlz4_compress\thelper
2026-05-19T03:25:35Z\tzram\thelper
";
        let entries = parse_helper_log(text);
        let pairs: Vec<(&str, PendingSource)> = entries
            .iter()
            .map(|e| (e.name.as_str(), e.source))
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("zram", PendingSource::Helper),
                ("lz4_compress", PendingSource::Helper),
            ]
        );
    }

    #[test]
    fn parse_helper_log_skips_unknown_tags_and_garbage() {
        let text = "\
2026-05-19T03:25:33Z\tzram\thelper
garbage line
2026-05-19T03:25:34Z\tfoo\tother
\t\t
";
        let entries = parse_helper_log(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name.as_str(), "zram");
    }

    #[test]
    fn check_pending_returns_unavailable_when_no_sources() {
        let report = check_pending_modules(PendingSources::default());
        assert!(matches!(report, PendingReport::Unavailable));
    }

    #[test]
    fn check_pending_returns_empty_checked_when_sources_have_no_events() {
        let report = check_pending_modules(PendingSources {
            journal: Some("clean log\nno blocks here\n".to_string()),
            ..Default::default()
        });
        match report {
            PendingReport::Checked(v) => assert!(v.is_empty()),
            other => panic!("expected Checked, got {other:?}"),
        }
    }

    #[test]
    fn check_pending_merges_helper_state_file_alone() {
        let report = check_pending_modules(PendingSources {
            state_file: Some(
                "2026-05-19T03:25:33Z\tzram\thelper\n2026-05-19T03:25:34Z\thid_jabra\thelper\n"
                    .to_string(),
            ),
            ..Default::default()
        });
        assert_eq!(
            pending_pairs(&report),
            vec![
                ("zram", PendingSource::Helper),
                ("hid_jabra", PendingSource::Helper),
            ]
        );
    }

    #[test]
    fn check_pending_merges_kmsg_kernel_lines_alone() {
        let report = check_pending_modules(PendingSources {
            kmsg: Some("kernel: module: blocked: usb-storage\n".to_string()),
            ..Default::default()
        });
        assert_eq!(
            pending_pairs(&report),
            vec![("usb-storage", PendingSource::Kernel)]
        );
    }

    #[test]
    fn check_pending_merges_three_sources_with_distinct_evidence() {
        let report = check_pending_modules(PendingSources {
            state_file: Some("2026-05-19T03:25:33Z\tzram\thelper\n".to_string()),
            kmsg: Some("kernel: module: blocked: usb-storage\n".to_string()),
            journal: Some(
                "modprobe: ERROR: Error running install command '/bin/false' for module lz4_compress\n"
                    .to_string(),
            ),
        });
        assert_eq!(
            pending_pairs(&report),
            vec![
                ("zram", PendingSource::Helper),
                ("usb-storage", PendingSource::Kernel),
                ("lz4_compress", PendingSource::Modprobe),
            ]
        );
    }

    #[test]
    fn check_pending_dedupes_overlap_between_sources() {
        let report = check_pending_modules(PendingSources {
            state_file: Some("2026-05-19T03:25:33Z\tzram\thelper\n".to_string()),
            journal: Some(
                "modprobe: ERROR: Error running install command '/bin/false' for module zram\n"
                    .to_string(),
            ),
            ..Default::default()
        });
        assert_eq!(
            pending_pairs(&report),
            vec![
                ("zram", PendingSource::Helper),
                ("zram", PendingSource::Modprobe),
            ]
        );
    }

    #[test]
    fn check_pending_dedupes_same_source_same_name() {
        let report = check_pending_modules(PendingSources {
            kmsg: Some(
                "kernel: module: blocked: usb-storage\nkernel: module: blocked: usb_storage\n"
                    .to_string(),
            ),
            ..Default::default()
        });
        assert_eq!(pending_names(&report), vec!["usb-storage"]);
    }

    #[test]
    fn parse_pending_ignores_unrelated_blocked_lines() {
        let text = "\
audit: blocked: root
network: blocked: eth0
kernel: module: blocked: usb-storage
";
        let modules = parse_pending_modules(text);
        let names: Vec<&str> = modules.iter().map(|e| e.name.as_str()).collect();
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

    #[test]
    fn is_modprobe_install_blocked_line_requires_install_for_module_and_no_op() {
        assert!(is_modprobe_install_blocked_line(
            "modprobe: ERROR: Error running install command '/bin/false' for module zram"
        ));
        assert!(!is_modprobe_install_blocked_line(
            "modprobe: ERROR: install command '/bin/false' missing target"
        ));
        assert!(!is_modprobe_install_blocked_line(
            "modprobe: loading for module zram"
        ));
        assert!(!is_modprobe_install_blocked_line(
            "modprobe: ERROR: Error running install command '/opt/custom/handler' for module zram"
        ));
    }

    #[test]
    fn is_modprobe_install_blocked_line_accepts_helper_command() {
        assert!(is_modprobe_install_blocked_line(
            "modprobe: ERROR: Error running install command '/usr/libexec/seshat/module-deny zram' for module zram"
        ));
    }

    #[test]
    fn is_modprobe_install_blocked_line_accepts_known_no_op_targets() {
        for target in [
            "/bin/false",
            "/bin/true",
            "/usr/bin/false",
            "/usr/bin/true",
            "/dev/null",
        ] {
            let line =
                format!("modprobe: ERROR: Error running install command '{target}' for module foo");
            assert!(
                is_modprobe_install_blocked_line(&line),
                "expected match for target {target}"
            );
        }
    }

    #[test]
    fn parse_pending_captures_all_no_op_variants() {
        let text = "\
modprobe: ERROR: Error running install command '/bin/false' for module mod_a
modprobe: ERROR: Error running install command '/bin/true' for module mod_b
modprobe: ERROR: Error running install command '/usr/bin/false' for module mod_c
modprobe: ERROR: Error running install command '/usr/bin/true' for module mod_d
modprobe: ERROR: Error running install command '/dev/null' for module mod_e
modprobe: ERROR: Error running install command '/usr/libexec/seshat/module-deny mod_f' for module mod_f
";
        let modules = parse_pending_modules(text);
        let names: Vec<&str> = modules.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names,
            vec!["mod_a", "mod_b", "mod_c", "mod_d", "mod_e", "mod_f"]
        );
    }
}
