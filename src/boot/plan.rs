use std::collections::{HashMap, HashSet};

use crate::policy::BootArg;

#[derive(Debug, PartialEq, Eq)]
pub enum PlanState {
    Ok,
    Change,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PlanRow {
    pub state: PlanState,
    pub arg: String,
    pub detail: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BootPlan {
    pub rows: Vec<PlanRow>,
    pub merged_cmdline: String,
    pub changes: usize,
}

pub fn plan_boot_params(current: Option<&str>, expected: &[BootArg]) -> BootPlan {
    let cur_tokens: Vec<String> = current
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    let mut current_by_key: HashMap<&str, usize> = HashMap::new();
    for (i, tok) in cur_tokens.iter().enumerate() {
        current_by_key.entry(token_key(tok)).or_insert(i);
    }

    let mut rows = Vec::with_capacity(expected.len());
    let mut changes = 0usize;
    for arg in expected {
        let expected_tok = arg.as_str();
        let ekey = token_key(expected_tok);
        let row = match current_by_key.get(ekey) {
            Some(&i) if cur_tokens[i] == expected_tok => PlanRow {
                state: PlanState::Ok,
                arg: expected_tok.to_string(),
                detail: "already present".to_string(),
            },
            Some(&i) => {
                changes += 1;
                PlanRow {
                    state: PlanState::Change,
                    arg: expected_tok.to_string(),
                    detail: format!("{} -> {}", cur_tokens[i], expected_tok),
                }
            }
            None => {
                changes += 1;
                PlanRow {
                    state: PlanState::Change,
                    arg: expected_tok.to_string(),
                    detail: format!("append: {expected_tok}"),
                }
            }
        };
        rows.push(row);
    }

    let expected_by_key: HashMap<&str, &str> = expected
        .iter()
        .map(|a| (token_key(a.as_str()), a.as_str()))
        .collect();

    let mut merged: Vec<String> = Vec::with_capacity(cur_tokens.len() + expected.len());
    let mut emitted_managed: HashSet<&str> = HashSet::new();
    for tok in &cur_tokens {
        let k = token_key(tok);
        if let Some(&new_tok) = expected_by_key.get(k) {
            if emitted_managed.insert(k) {
                merged.push(new_tok.to_string());
            }
        } else {
            merged.push(tok.clone());
        }
    }
    for arg in expected {
        let s = arg.as_str();
        let k = token_key(s);
        if emitted_managed.insert(k) {
            merged.push(s.to_string());
        }
    }

    BootPlan {
        rows,
        merged_cmdline: merged.join(" "),
        changes,
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

    fn args(list: &[&str]) -> Vec<BootArg> {
        list.iter().map(|s| BootArg::new(s).unwrap()).collect()
    }

    #[test]
    fn empty_current_and_empty_expected_yields_empty_plan() {
        let plan = plan_boot_params(None, &[]);
        assert!(plan.rows.is_empty());
        assert_eq!(plan.merged_cmdline, "");
        assert_eq!(plan.changes, 0);
    }

    #[test]
    fn empty_current_appends_all_expected() {
        let expected = args(&["quiet", "init_on_alloc=1"]);
        let plan = plan_boot_params(None, &expected);
        assert_eq!(plan.rows.len(), 2);
        assert!(plan.rows.iter().all(|r| r.state == PlanState::Change));
        assert_eq!(plan.merged_cmdline, "quiet init_on_alloc=1");
        assert_eq!(plan.changes, 2);
    }

    #[test]
    fn matching_arg_reports_ok_and_no_change() {
        let expected = args(&["debugfs=off"]);
        let plan = plan_boot_params(Some("quiet debugfs=off"), &expected);
        assert_eq!(plan.rows[0].state, PlanState::Ok);
        assert_eq!(plan.rows[0].detail, "already present");
        assert_eq!(plan.merged_cmdline, "quiet debugfs=off");
        assert_eq!(plan.changes, 0);
    }

    #[test]
    fn mismatched_value_reports_change_with_before_and_after() {
        let expected = args(&["debugfs=off"]);
        let plan = plan_boot_params(Some("quiet debugfs=on"), &expected);
        assert_eq!(plan.rows[0].state, PlanState::Change);
        assert_eq!(plan.rows[0].detail, "debugfs=on -> debugfs=off");
        assert_eq!(plan.merged_cmdline, "quiet debugfs=off");
        assert_eq!(plan.changes, 1);
    }

    #[test]
    fn missing_key_reports_change_as_append() {
        let expected = args(&["init_on_alloc=1"]);
        let plan = plan_boot_params(Some("quiet splash"), &expected);
        assert_eq!(plan.rows[0].state, PlanState::Change);
        assert_eq!(plan.rows[0].detail, "append: init_on_alloc=1");
        assert_eq!(plan.merged_cmdline, "quiet splash init_on_alloc=1");
    }

    #[test]
    fn operator_only_args_preserved_in_merge() {
        let expected = args(&["debugfs=off"]);
        let plan = plan_boot_params(Some("quiet splash debugfs=on apparmor=1"), &expected);
        assert_eq!(plan.merged_cmdline, "quiet splash debugfs=off apparmor=1");
    }

    #[test]
    fn boolean_flag_matches_when_no_value() {
        let expected = args(&["quiet"]);
        let plan = plan_boot_params(Some("ro quiet splash"), &expected);
        assert_eq!(plan.rows[0].state, PlanState::Ok);
        assert_eq!(plan.changes, 0);
    }

    #[test]
    fn merge_preserves_order_of_operator_args() {
        let expected = args(&["debugfs=off"]);
        let plan = plan_boot_params(Some("first debugfs=on last"), &expected);
        assert_eq!(plan.merged_cmdline, "first debugfs=off last");
    }

    #[test]
    fn managed_args_appended_at_end_when_not_in_current() {
        let expected = args(&["init_on_alloc=1", "init_on_free=1"]);
        let plan = plan_boot_params(Some("quiet splash"), &expected);
        assert_eq!(
            plan.merged_cmdline,
            "quiet splash init_on_alloc=1 init_on_free=1"
        );
        assert_eq!(plan.changes, 2);
    }

    #[test]
    fn managed_args_mixed_update_and_append() {
        let expected = args(&["debugfs=off", "init_on_alloc=1"]);
        let plan = plan_boot_params(Some("quiet debugfs=on"), &expected);
        assert_eq!(plan.merged_cmdline, "quiet debugfs=off init_on_alloc=1");
        assert_eq!(plan.changes, 2);
    }

    #[test]
    fn changes_counter_matches_change_rows() {
        let expected = args(&["a=1", "b=2", "c=3"]);
        let plan = plan_boot_params(Some("a=1 b=9"), &expected);
        let change_rows = plan
            .rows
            .iter()
            .filter(|r| r.state == PlanState::Change)
            .count();
        assert_eq!(plan.changes, change_rows);
    }

    #[test]
    fn no_changes_when_all_expected_already_present() {
        let expected = args(&["debugfs=off", "init_on_alloc=1"]);
        let plan = plan_boot_params(Some("quiet debugfs=off init_on_alloc=1"), &expected);
        assert_eq!(plan.changes, 0);
        assert!(plan.rows.iter().all(|r| r.state == PlanState::Ok));
    }

    #[test]
    fn duplicate_managed_key_in_current_is_collapsed() {
        let expected = args(&["debugfs=off"]);
        let plan = plan_boot_params(Some("debugfs=on quiet debugfs=maybe"), &expected);
        let count = plan
            .merged_cmdline
            .split_whitespace()
            .filter(|t| t.starts_with("debugfs="))
            .count();
        assert_eq!(count, 1, "managed key should collapse to one occurrence");
    }

    #[test]
    fn duplicate_operator_key_preserved_outside_managed_set() {
        let expected = args(&["debugfs=off"]);
        let plan = plan_boot_params(Some("ro ro splash"), &expected);
        assert_eq!(plan.merged_cmdline, "ro ro splash debugfs=off");
    }
}
