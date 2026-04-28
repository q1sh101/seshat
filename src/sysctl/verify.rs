use super::plan::LiveRead;
use super::setting::{SysctlSetting, normalize_sysctl_value};
use crate::policy::SysctlKey;
use crate::result::CheckState;

#[derive(Debug, PartialEq, Eq)]
pub struct VerifyRow {
    pub state: CheckState,
    pub key: String,
    pub detail: String,
    pub hint: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SysctlVerify {
    pub rows: Vec<VerifyRow>,
}

pub fn verify_sysctl<F>(settings: &[SysctlSetting], mut read_live: F) -> SysctlVerify
where
    F: FnMut(&SysctlKey) -> LiveRead,
{
    let mut rows = Vec::with_capacity(settings.len());
    for s in settings {
        let expected = s.value.as_str();
        let key = s.key.as_str().to_string();
        let row = match read_live(&s.key) {
            LiveRead::Value(raw) => {
                let live = normalize_sysctl_value(&raw);
                if live == expected {
                    VerifyRow {
                        state: CheckState::Ok,
                        key,
                        detail: format!("expected: {expected}"),
                        hint: "",
                    }
                } else {
                    VerifyRow {
                        state: CheckState::Warn,
                        key,
                        detail: format!("expected {expected}, live {live}"),
                        hint: "",
                    }
                }
            }
            LiveRead::Missing => VerifyRow {
                state: CheckState::Skip,
                key,
                detail: "not supported on this kernel".to_string(),
                hint: "",
            },
            LiveRead::Unreadable => VerifyRow {
                state: CheckState::Skip,
                key,
                detail: "unreadable".to_string(),
                hint: "run with root",
            },
        };
        rows.push(row);
    }
    SysctlVerify { rows }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn setting(key: &str, value: &str) -> SysctlSetting {
        SysctlSetting::new(key, value).unwrap()
    }

    fn fixed_map(pairs: &[(&str, LiveRead)]) -> impl FnMut(&SysctlKey) -> LiveRead + use<> {
        let mut map: HashMap<String, LiveRead> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), v.clone()))
            .collect();
        move |key| map.remove(key.as_str()).unwrap_or(LiveRead::Missing)
    }

    #[test]
    fn empty_settings_yield_empty_rows() {
        let verify = verify_sysctl(&[], |_| LiveRead::Missing);
        assert!(verify.rows.is_empty());
    }

    #[test]
    fn ok_when_live_matches_expected() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Value("2".to_string()))]);
        let verify = verify_sysctl(&settings, read);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
        assert_eq!(verify.rows[0].key, "kernel.kptr_restrict");
        assert_eq!(verify.rows[0].detail, "expected: 2");
    }

    #[test]
    fn warn_when_live_differs() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Value("0".to_string()))]);
        let verify = verify_sysctl(&settings, read);
        assert_eq!(verify.rows[0].state, CheckState::Warn);
        assert_eq!(verify.rows[0].detail, "expected 2, live 0");
    }

    #[test]
    fn skip_when_live_missing() {
        let settings = vec![setting("kernel.foo_bar", "1")];
        let read = fixed_map(&[("kernel.foo_bar", LiveRead::Missing)]);
        let verify = verify_sysctl(&settings, read);
        assert_eq!(verify.rows[0].state, CheckState::Skip);
        assert_eq!(verify.rows[0].detail, "not supported on this kernel");
        assert_eq!(verify.rows[0].hint, "");
    }

    #[test]
    fn skip_when_live_unreadable_carries_root_hint() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Unreadable)]);
        let verify = verify_sysctl(&settings, read);
        assert_eq!(verify.rows[0].state, CheckState::Skip);
        assert_eq!(verify.rows[0].detail, "unreadable");
        assert_eq!(verify.rows[0].hint, "run with root");
    }

    #[test]
    fn normalizes_live_value_before_comparison() {
        let settings = vec![setting("kernel.printk", "4 4 1 7")];
        let read = fixed_map(&[("kernel.printk", LiveRead::Value("4\t4\t1\t7".to_string()))]);
        let verify = verify_sysctl(&settings, read);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
    }

    #[test]
    fn preserves_settings_order() {
        let settings = vec![
            setting("kernel.dmesg_restrict", "1"),
            setting("kernel.kptr_restrict", "2"),
            setting("net.core.bpf_jit_harden", "2"),
        ];
        let read = fixed_map(&[
            ("kernel.dmesg_restrict", LiveRead::Value("1".to_string())),
            ("kernel.kptr_restrict", LiveRead::Value("2".to_string())),
            ("net.core.bpf_jit_harden", LiveRead::Value("2".to_string())),
        ]);
        let verify = verify_sysctl(&settings, read);
        let keys: Vec<&str> = verify.rows.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "kernel.dmesg_restrict",
                "kernel.kptr_restrict",
                "net.core.bpf_jit_harden",
            ]
        );
    }

    #[test]
    fn mixed_states_across_settings() {
        let settings = vec![
            setting("kernel.kptr_restrict", "2"),
            setting("kernel.dmesg_restrict", "1"),
            setting("kernel.missing_key", "1"),
            setting("kernel.locked_key", "1"),
        ];
        let read = fixed_map(&[
            ("kernel.kptr_restrict", LiveRead::Value("2".to_string())),
            ("kernel.dmesg_restrict", LiveRead::Value("0".to_string())),
            ("kernel.missing_key", LiveRead::Missing),
            ("kernel.locked_key", LiveRead::Unreadable),
        ]);
        let verify = verify_sysctl(&settings, read);
        assert_eq!(verify.rows[0].state, CheckState::Ok);
        assert_eq!(verify.rows[1].state, CheckState::Warn);
        assert_eq!(verify.rows[2].state, CheckState::Skip);
        assert_eq!(verify.rows[3].state, CheckState::Skip);
    }

    #[test]
    fn warn_detail_shows_both_expected_and_live() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Value("1".to_string()))]);
        let verify = verify_sysctl(&settings, read);
        assert!(verify.rows[0].detail.contains("expected 2"));
        assert!(verify.rows[0].detail.contains("live 1"));
    }

    #[test]
    fn verify_never_emits_change_or_fail_states() {
        let settings = vec![
            setting("a.ok", "1"),
            setting("a.warn", "1"),
            setting("a.missing", "1"),
            setting("a.locked", "1"),
        ];
        let read = fixed_map(&[
            ("a.ok", LiveRead::Value("1".to_string())),
            ("a.warn", LiveRead::Value("0".to_string())),
            ("a.missing", LiveRead::Missing),
            ("a.locked", LiveRead::Unreadable),
        ]);
        let verify = verify_sysctl(&settings, read);
        for row in &verify.rows {
            assert!(
                matches!(
                    row.state,
                    CheckState::Ok | CheckState::Warn | CheckState::Skip
                ),
                "unexpected state {:?} for key {}",
                row.state,
                row.key
            );
        }
    }
}
