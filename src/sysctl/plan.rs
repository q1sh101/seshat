use std::io;
use std::path::{Path, PathBuf};

use super::setting::{SysctlSetting, normalize_sysctl_value};
use crate::policy::SysctlKey;

#[derive(Debug, PartialEq, Eq)]
pub enum PlanState {
    Ok,
    Change,
    Skip,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PlanRow {
    pub state: PlanState,
    pub key: String,
    pub detail: String,
    pub hint: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SysctlPlan {
    pub rows: Vec<PlanRow>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LiveRead {
    Value(String),
    Missing,
    Unreadable,
}

// Sysctl keys use dots; /proc/sys uses slashes.
fn sysctl_path(proc_sys_root: &Path, key: &SysctlKey) -> PathBuf {
    proc_sys_root.join(key.as_str().replace('.', "/"))
}

pub fn read_live_sysctl(proc_sys_root: &Path, key: &SysctlKey) -> LiveRead {
    let path = sysctl_path(proc_sys_root, key);
    match std::fs::read_to_string(&path) {
        Ok(body) => LiveRead::Value(body),
        Err(e) if e.kind() == io::ErrorKind::NotFound => LiveRead::Missing,
        Err(_) => LiveRead::Unreadable,
    }
}

pub fn plan_sysctl<F>(settings: &[SysctlSetting], mut read_live: F) -> SysctlPlan
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
                    PlanRow {
                        state: PlanState::Ok,
                        key,
                        detail: format!("already {expected}"),
                        hint: "",
                    }
                } else {
                    PlanRow {
                        state: PlanState::Change,
                        key,
                        detail: format!("{live} -> {expected}"),
                        hint: "",
                    }
                }
            }
            LiveRead::Missing => PlanRow {
                state: PlanState::Skip,
                key,
                detail: "not supported on this kernel".to_string(),
                hint: "",
            },
            LiveRead::Unreadable => PlanRow {
                state: PlanState::Skip,
                key,
                detail: "unreadable".to_string(),
                hint: "run with root",
            },
        };
        rows.push(row);
    }
    SysctlPlan { rows }
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
        let plan = plan_sysctl(&[], |_| LiveRead::Missing);
        assert!(plan.rows.is_empty());
    }

    #[test]
    fn ok_when_live_matches_expected() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Value("2".to_string()))]);
        let plan = plan_sysctl(&settings, read);
        assert_eq!(plan.rows.len(), 1);
        assert_eq!(plan.rows[0].state, PlanState::Ok);
        assert_eq!(plan.rows[0].key, "kernel.kptr_restrict");
        assert_eq!(plan.rows[0].detail, "already 2");
    }

    #[test]
    fn change_when_live_differs() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Value("0".to_string()))]);
        let plan = plan_sysctl(&settings, read);
        assert_eq!(plan.rows[0].state, PlanState::Change);
        assert_eq!(plan.rows[0].detail, "0 -> 2");
    }

    #[test]
    fn skip_when_live_missing() {
        let settings = vec![setting("kernel.foo_bar", "1")];
        let read = fixed_map(&[("kernel.foo_bar", LiveRead::Missing)]);
        let plan = plan_sysctl(&settings, read);
        assert_eq!(plan.rows[0].state, PlanState::Skip);
        assert_eq!(plan.rows[0].detail, "not supported on this kernel");
        assert_eq!(plan.rows[0].hint, "");
    }

    #[test]
    fn skip_when_live_unreadable_carries_root_hint() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Unreadable)]);
        let plan = plan_sysctl(&settings, read);
        assert_eq!(plan.rows[0].state, PlanState::Skip);
        assert_eq!(plan.rows[0].detail, "unreadable");
        assert_eq!(plan.rows[0].hint, "run with root");
    }

    #[test]
    fn normalizes_live_value_before_comparison() {
        let settings = vec![setting("kernel.printk", "4 4 1 7")];
        // Kernel prints whitespace-separated fields with tabs in some builds.
        let read = fixed_map(&[("kernel.printk", LiveRead::Value("4\t4\t1\t7".to_string()))]);
        let plan = plan_sysctl(&settings, read);
        assert_eq!(plan.rows[0].state, PlanState::Ok);
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
        let plan = plan_sysctl(&settings, read);
        let keys: Vec<&str> = plan.rows.iter().map(|r| r.key.as_str()).collect();
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
        let plan = plan_sysctl(&settings, read);
        assert_eq!(plan.rows[0].state, PlanState::Ok);
        assert_eq!(plan.rows[1].state, PlanState::Change);
        assert_eq!(plan.rows[2].state, PlanState::Skip);
        assert_eq!(plan.rows[3].state, PlanState::Skip);
    }

    #[test]
    fn change_detail_shows_live_then_expected() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let read = fixed_map(&[("kernel.kptr_restrict", LiveRead::Value("1".to_string()))]);
        let plan = plan_sysctl(&settings, read);
        assert_eq!(plan.rows[0].detail, "1 -> 2");
    }

    fn key(s: &str) -> SysctlKey {
        SysctlKey::new(s).unwrap()
    }

    #[test]
    fn read_live_returns_value_when_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("kernel")).unwrap();
        std::fs::write(dir.path().join("kernel").join("kptr_restrict"), "2\n").unwrap();
        assert_eq!(
            read_live_sysctl(dir.path(), &key("kernel.kptr_restrict")),
            LiveRead::Value("2\n".to_string())
        );
    }

    #[test]
    fn read_live_maps_dotted_key_to_slashed_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("net/core")).unwrap();
        std::fs::write(dir.path().join("net/core/bpf_jit_harden"), "2\n").unwrap();
        assert_eq!(
            read_live_sysctl(dir.path(), &key("net.core.bpf_jit_harden")),
            LiveRead::Value("2\n".to_string())
        );
    }

    #[test]
    fn read_live_returns_missing_for_absent_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(
            read_live_sysctl(dir.path(), &key("kernel.kptr_restrict")),
            LiveRead::Missing
        );
    }

    #[test]
    fn read_live_returns_unreadable_for_non_file_path() {
        let dir = tempfile::tempdir().unwrap();
        // Directory at the sysctl path: read_to_string fails with IsADirectory/other.
        let target = dir.path().join("kernel").join("kptr_restrict");
        std::fs::create_dir_all(&target).unwrap();
        assert_eq!(
            read_live_sysctl(dir.path(), &key("kernel.kptr_restrict")),
            LiveRead::Unreadable
        );
    }

    #[test]
    fn read_live_preserves_raw_body_for_plan_to_normalize() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("kernel")).unwrap();
        std::fs::write(dir.path().join("kernel/printk"), "4\t4\t1\t7\n").unwrap();
        assert_eq!(
            read_live_sysctl(dir.path(), &key("kernel.printk")),
            LiveRead::Value("4\t4\t1\t7\n".to_string())
        );
    }
}
