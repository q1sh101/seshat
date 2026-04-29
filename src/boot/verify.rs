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
    let Some(live) = live_cmdline else {
        let rows = expected
            .iter()
            .map(|arg| VerifyRow {
                state: CheckState::Skip,
                arg: arg.as_str().to_string(),
                detail: "cannot read /proc/cmdline".to_string(),
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
                detail: "missing from /proc/cmdline".to_string(),
                hint: "reboot required",
            },
            Some(occurrences) if occurrences.len() > 1 => VerifyRow {
                state: CheckState::Warn,
                arg: expected_tok.to_string(),
                detail: format!(
                    "ambiguous: {} occurrences of {ekey} in /proc/cmdline",
                    occurrences.len()
                ),
                hint: "reboot required",
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
                        hint: "reboot required",
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
}
