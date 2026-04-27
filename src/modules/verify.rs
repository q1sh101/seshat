use std::collections::{BTreeSet, HashMap, HashSet};
use std::io;
use std::path::Path;

use super::dropin::{generate_modprobe_dropin, payload_signature};
use crate::error::Error;
use crate::policy::{ModuleName, normalize_module};
use crate::result::CheckState;

#[derive(Debug, PartialEq, Eq)]
pub struct VerifyRow {
    pub state: CheckState,
    pub key: &'static str,
    pub detail: String,
    pub hint: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
pub struct VerifyReport {
    pub rows: Vec<VerifyRow>,
}

pub fn verify_enforcement<F>(
    effective: Option<&[ModuleName]>,
    installed: &[String],
    profile_name: &str,
    deployed_path: &Path,
    modprobe_show_config: F,
) -> Result<VerifyReport, Error>
where
    F: FnOnce() -> Option<String>,
{
    let mut rows: Vec<VerifyRow> = Vec::new();

    let Some(effective) = effective else {
        rows.push(VerifyRow {
            state: CheckState::Skip,
            key: "enforcement",
            detail: "allowlist not configured".to_string(),
            hint: "run: seshat snapshot",
        });
        return Ok(VerifyReport { rows });
    };

    let expected = generate_modprobe_dropin(effective, installed, profile_name);
    let expected_sig = payload_signature(&expected);

    match std::fs::read_to_string(deployed_path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            rows.push(VerifyRow {
                state: CheckState::Fail,
                key: "enforcement",
                detail: format!("drop-in missing: {}", deployed_path.display()),
                hint: "run: seshat deploy modules",
            });
        }
        Err(e) => return Err(e.into()),
        Ok(live) => {
            let live_sig = payload_signature(&live);
            if live_sig == expected_sig {
                rows.push(VerifyRow {
                    state: CheckState::Ok,
                    key: "enforcement",
                    detail: format!(
                        "drop-in matches effective policy: {}",
                        deployed_path.display()
                    ),
                    hint: "",
                });
            } else {
                rows.push(VerifyRow {
                    state: CheckState::Fail,
                    key: "enforcement",
                    detail: "drop-in drifted from effective policy".to_string(),
                    hint: "run: seshat deploy modules",
                });
            }
        }
    }

    // Missing modprobe inspection is WARN, not fake OK.
    let Some(cfg) = modprobe_show_config() else {
        rows.push(VerifyRow {
            state: CheckState::Warn,
            key: "modprobe-config",
            detail: "cannot inspect effective modprobe config".to_string(),
            hint: "",
        });
        return Ok(VerifyReport { rows });
    };

    let rules = parse_modprobe_install_rules(&cfg);
    let allowed: HashSet<String> = effective
        .iter()
        .map(|m| normalize_module(m.as_str()))
        .collect();

    let mut conflicts: BTreeSet<String> = BTreeSet::new();
    for raw in installed {
        let norm = normalize_module(raw);
        if allowed.contains(&norm) {
            continue;
        }
        match rules.get(&norm) {
            Some(cmd) if cmd == "/bin/false" => {}
            _ => {
                conflicts.insert(raw.clone());
            }
        }
    }

    if conflicts.is_empty() {
        rows.push(VerifyRow {
            state: CheckState::Ok,
            key: "modprobe-config",
            detail: "effective modprobe rules enforce policy".to_string(),
            hint: "",
        });
    } else {
        let first = conflicts.iter().next().cloned().unwrap_or_default();
        let n = conflicts.len();
        let detail = if n == 1 {
            format!("conflicting modprobe rule: {first}")
        } else {
            format!("conflicting modprobe rules: {n} modules (first: {first})")
        };
        rows.push(VerifyRow {
            state: CheckState::Fail,
            key: "modprobe-config",
            detail,
            hint: "",
        });
    }

    Ok(VerifyReport { rows })
}

fn parse_modprobe_install_rules(show_config: &str) -> HashMap<String, String> {
    let mut rules: HashMap<String, String> = HashMap::new();
    for raw in show_config.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        if parts.next() != Some("install") {
            continue;
        }
        let Some(name) = parts.next() else { continue };
        let cmd: Vec<&str> = parts.collect();
        rules.insert(normalize_module(name), cmd.join(" "));
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parse_modprobe_install_rules_extracts_install_lines() {
        let cfg = "\
# comment
install ext4 /bin/false
blacklist vfat
install usb-storage /sbin/modprobe --ignore-install usb-storage
options aes foo=1
";
        let rules = parse_modprobe_install_rules(cfg);
        assert_eq!(rules.get("ext4").map(String::as_str), Some("/bin/false"));
        assert_eq!(
            rules.get("usb_storage").map(String::as_str),
            Some("/sbin/modprobe --ignore-install usb-storage")
        );
        assert!(!rules.contains_key("vfat"));
        assert!(!rules.contains_key("aes"));
    }

    #[test]
    fn verify_enforcement_skip_when_no_snapshot() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let report =
            verify_enforcement(None, &[], "baseline", &deployed, || Some(String::new())).unwrap();
        assert_eq!(report.rows.len(), 1);
        assert_eq!(report.rows[0].state, CheckState::Skip);
        assert_eq!(report.rows[0].key, "enforcement");
        assert_eq!(report.rows[0].hint, "run: seshat snapshot");
    }

    #[test]
    fn verify_enforcement_fails_when_drop_in_missing() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(String::new())
            })
            .unwrap();
        assert_eq!(report.rows[0].state, CheckState::Fail);
        assert!(report.rows[0].detail.starts_with("drop-in missing:"));
        assert_eq!(report.rows[0].hint, "run: seshat deploy modules");
    }

    #[test]
    fn verify_enforcement_ok_when_drop_in_matches() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let expected = generate_modprobe_dropin(&effective, &installed, "baseline");
        fs::write(&deployed, &expected).unwrap();
        let cfg = "install vfat /bin/false\n".to_string();
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(cfg)
            })
            .unwrap();
        assert_eq!(report.rows[0].state, CheckState::Ok);
        assert_eq!(report.rows[0].key, "enforcement");
    }

    #[test]
    fn verify_enforcement_fails_on_hash_drift() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        fs::write(&deployed, "# header\ninstall extra /bin/false\n").unwrap();
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(String::new())
            })
            .unwrap();
        assert_eq!(report.rows[0].state, CheckState::Fail);
        assert_eq!(
            report.rows[0].detail,
            "drop-in drifted from effective policy"
        );
    }

    #[test]
    fn verify_enforcement_fails_when_deployed_file_has_duplicate_line() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let expected = generate_modprobe_dropin(&effective, &installed, "baseline");
        let tampered = format!("{expected}install vfat /bin/false\n");
        fs::write(&deployed, &tampered).unwrap();
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(String::new())
            })
            .unwrap();
        assert_eq!(report.rows[0].state, CheckState::Fail);
        assert_eq!(
            report.rows[0].detail,
            "drop-in drifted from effective policy"
        );
    }

    #[test]
    fn verify_enforcement_warns_when_modprobe_unavailable() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let expected = generate_modprobe_dropin(&effective, &[], "baseline");
        fs::write(&deployed, &expected).unwrap();
        let report =
            verify_enforcement(Some(&effective), &[], "baseline", &deployed, || None).unwrap();
        assert_eq!(report.rows[1].state, CheckState::Warn);
        assert_eq!(report.rows[1].key, "modprobe-config");
        assert!(report.rows[1].detail.contains("cannot inspect"));
    }

    #[test]
    fn verify_enforcement_ok_when_modprobe_rules_enforce_policy() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let expected = generate_modprobe_dropin(&effective, &installed, "baseline");
        fs::write(&deployed, &expected).unwrap();
        let cfg = "install vfat /bin/false\n".to_string();
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(cfg)
            })
            .unwrap();
        assert_eq!(report.rows[1].state, CheckState::Ok);
        assert_eq!(report.rows[1].key, "modprobe-config");
    }

    #[test]
    fn verify_enforcement_fails_on_conflicting_modprobe_rule() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let expected = generate_modprobe_dropin(&effective, &installed, "baseline");
        fs::write(&deployed, &expected).unwrap();
        let cfg = "install vfat /sbin/modprobe --ignore-install vfat\n".to_string();
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(cfg)
            })
            .unwrap();
        assert_eq!(report.rows[1].state, CheckState::Fail);
        assert!(report.rows[1].detail.contains("vfat"));
    }

    #[test]
    fn verify_enforcement_fails_when_drop_in_matches_but_config_missing_rule() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "vfat".to_string()];
        let expected = generate_modprobe_dropin(&effective, &installed, "baseline");
        fs::write(&deployed, &expected).unwrap();
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(String::new())
            })
            .unwrap();
        assert_eq!(report.rows[0].state, CheckState::Ok);
        assert_eq!(report.rows[1].state, CheckState::Fail);
    }

    #[test]
    fn verify_enforcement_normalizes_hyphen_underscore_in_conflict_check() {
        let dir = tempdir().unwrap();
        let deployed = dir.path().join("test-modules.conf");
        let effective = vec![ModuleName::new("ext4").unwrap()];
        let installed = vec!["ext4".to_string(), "usb-storage".to_string()];
        let expected = generate_modprobe_dropin(&effective, &installed, "baseline");
        fs::write(&deployed, &expected).unwrap();
        let cfg = "install usb_storage /bin/false\n".to_string();
        let report =
            verify_enforcement(Some(&effective), &installed, "baseline", &deployed, || {
                Some(cfg)
            })
            .unwrap();
        assert_eq!(report.rows[1].state, CheckState::Ok);
    }
}
