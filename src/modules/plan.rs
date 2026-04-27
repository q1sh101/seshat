use std::collections::HashSet;

use crate::policy::{ModuleName, normalize_module};

#[derive(Debug, PartialEq, Eq)]
pub enum PlanState {
    Ok,
    Change,
    Skip,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PlanRow {
    pub state: PlanState,
    pub key: &'static str,
    pub detail: String,
    pub hint: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct EnforcementPlan {
    pub rows: Vec<PlanRow>,
}

pub fn plan_enforcement(effective: Option<&[ModuleName]>, installed: &[String]) -> EnforcementPlan {
    let Some(effective) = effective else {
        return EnforcementPlan {
            rows: vec![PlanRow {
                state: PlanState::Skip,
                key: "allowlist",
                detail: "not configured".to_string(),
                hint: "run: seshat snapshot",
            }],
        };
    };

    let allowed: HashSet<String> = effective
        .iter()
        .map(|m| normalize_module(m.as_str()))
        .collect();
    let allow_count = effective.len();
    let block_count = installed
        .iter()
        .filter(|raw| !allowed.contains(&normalize_module(raw)))
        .count();

    let mut rows = Vec::with_capacity(2);
    rows.push(PlanRow {
        state: PlanState::Ok,
        key: "allowlist",
        detail: format!("{allow_count} modules allowed"),
        hint: "",
    });
    let blocklist_row = if block_count > 0 {
        PlanRow {
            state: PlanState::Change,
            key: "blocklist",
            detail: format!("{block_count} modules to block (auto-generated)"),
            hint: "",
        }
    } else {
        PlanRow {
            state: PlanState::Ok,
            key: "blocklist",
            detail: "all modules allowed (0 to block)".to_string(),
            hint: "",
        }
    };
    rows.push(blocklist_row);

    EnforcementPlan { rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_enforcement_skip_when_no_snapshot() {
        let plan = plan_enforcement(None, &[]);
        assert_eq!(plan.rows.len(), 1);
        assert_eq!(plan.rows[0].state, PlanState::Skip);
        assert_eq!(plan.rows[0].key, "allowlist");
        assert_eq!(plan.rows[0].detail, "not configured");
        assert_eq!(plan.rows[0].hint, "run: seshat snapshot");
    }

    #[test]
    fn plan_enforcement_reports_allow_count() {
        let effective = vec![
            ModuleName::new("ext4").unwrap(),
            ModuleName::new("vfat").unwrap(),
            ModuleName::new("usb_storage").unwrap(),
        ];
        let plan = plan_enforcement(Some(&effective), &[]);
        assert_eq!(plan.rows[0].state, PlanState::Ok);
        assert_eq!(plan.rows[0].key, "allowlist");
        assert_eq!(plan.rows[0].detail, "3 modules allowed");
    }

    #[test]
    fn plan_enforcement_ok_blocklist_when_all_installed_allowed() {
        let effective = vec![
            ModuleName::new("ext4").unwrap(),
            ModuleName::new("vfat").unwrap(),
        ];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let plan = plan_enforcement(Some(&effective), &installed);
        assert_eq!(plan.rows[1].state, PlanState::Ok);
        assert_eq!(plan.rows[1].key, "blocklist");
        assert_eq!(plan.rows[1].detail, "all modules allowed (0 to block)");
    }

    #[test]
    fn plan_enforcement_change_blocklist_when_installed_exceeds() {
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec![
            "ext4".to_string(),
            "vfat".to_string(),
            "usb-storage".to_string(),
        ];
        let plan = plan_enforcement(Some(&effective), &installed);
        assert_eq!(plan.rows[1].state, PlanState::Change);
        assert_eq!(plan.rows[1].key, "blocklist");
        assert_eq!(plan.rows[1].detail, "2 modules to block (auto-generated)");
    }

    #[test]
    fn plan_enforcement_normalizes_hyphen_underscore() {
        let effective = vec![ModuleName::new("usb_storage").unwrap()];
        let installed = vec!["usb-storage".to_string()];
        let plan = plan_enforcement(Some(&effective), &installed);
        assert_eq!(plan.rows[1].state, PlanState::Ok);
        assert_eq!(plan.rows[1].detail, "all modules allowed (0 to block)");
    }

    #[test]
    fn plan_enforcement_empty_installed_reports_zero_to_block() {
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let plan = plan_enforcement(Some(&effective), &[]);
        assert_eq!(plan.rows[0].detail, "1 modules allowed");
        assert_eq!(plan.rows[1].state, PlanState::Ok);
        assert_eq!(plan.rows[1].detail, "all modules allowed (0 to block)");
    }
}
