use crate::error::Error;
use crate::policy::{SysctlEntry, SysctlKey, SysctlValue};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SysctlSetting {
    pub key: SysctlKey,
    pub value: SysctlValue,
}

impl SysctlSetting {
    pub fn new(key: &str, value: &str) -> Result<Self, Error> {
        // Validate raw before normalize: tabs/newlines/edge-whitespace would otherwise be hidden.
        SysctlValue::new(value)?;
        let normalized = normalize_sysctl_value(value);
        Ok(Self {
            key: SysctlKey::new(key)?,
            value: SysctlValue::new(&normalized)?,
        })
    }

    pub fn from_entry(entry: &SysctlEntry) -> Result<Self, Error> {
        Self::new(&entry.key, &entry.value)
    }
}

// Match /proc canonical form.
pub fn normalize_sysctl_value(s: &str) -> String {
    s.split_whitespace().collect::<Vec<&str>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_collapses_internal_whitespace_runs() {
        assert_eq!(normalize_sysctl_value("4   4   1   7"), "4 4 1 7");
    }

    #[test]
    fn normalize_trims_leading_and_trailing_whitespace() {
        assert_eq!(normalize_sysctl_value("   2   "), "2");
    }

    #[test]
    fn normalize_preserves_single_space_separated_tokens() {
        assert_eq!(normalize_sysctl_value("a b c"), "a b c");
    }

    #[test]
    fn normalize_empty_and_whitespace_only_inputs_yield_empty() {
        assert_eq!(normalize_sysctl_value(""), "");
        assert_eq!(normalize_sysctl_value("   "), "");
    }

    #[test]
    fn normalize_tabs_and_mixed_whitespace_collapse() {
        assert_eq!(normalize_sysctl_value("a\t\tb  \n c"), "a b c");
    }

    #[test]
    fn new_accepts_valid_key_and_value() {
        let s = SysctlSetting::new("kernel.kptr_restrict", "2").unwrap();
        assert_eq!(s.key.as_str(), "kernel.kptr_restrict");
        assert_eq!(s.value.as_str(), "2");
    }

    #[test]
    fn new_stores_normalized_internal_whitespace() {
        let s = SysctlSetting::new("kernel.printk", "4  4  1  7").unwrap();
        assert_eq!(s.value.as_str(), "4 4 1 7");
    }

    #[test]
    fn new_rejects_invalid_key() {
        match SysctlSetting::new("Kernel.Kptr", "2").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_key"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_leading_whitespace() {
        match SysctlSetting::new("kernel.foo", "  2").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_value"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_trailing_whitespace() {
        match SysctlSetting::new("kernel.foo", "2  ").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_value"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_tab_in_value() {
        match SysctlSetting::new("kernel.foo", "a\tb").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_value"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_newline_in_value() {
        match SysctlSetting::new("kernel.foo", "a\nb").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_value"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_value_with_disallowed_char() {
        match SysctlSetting::new("kernel.foo", "bar*baz").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_value"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn new_rejects_whitespace_only_value() {
        match SysctlSetting::new("kernel.foo", "   ").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_value"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn from_entry_constructs_typed_setting() {
        let entry = SysctlEntry {
            key: "kernel.dmesg_restrict".to_string(),
            value: "1".to_string(),
        };
        let s = SysctlSetting::from_entry(&entry).unwrap();
        assert_eq!(s.key.as_str(), "kernel.dmesg_restrict");
        assert_eq!(s.value.as_str(), "1");
    }

    #[test]
    fn from_entry_normalizes_internal_whitespace() {
        let entry = SysctlEntry {
            key: "kernel.printk".to_string(),
            value: "4  4  1  7".to_string(),
        };
        let s = SysctlSetting::from_entry(&entry).unwrap();
        assert_eq!(s.value.as_str(), "4 4 1 7");
    }

    #[test]
    fn equal_settings_compare_equal() {
        let a = SysctlSetting::new("kernel.kptr_restrict", "2").unwrap();
        let b = SysctlSetting::new("kernel.kptr_restrict", "2").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_values_compare_unequal() {
        let a = SysctlSetting::new("kernel.kptr_restrict", "1").unwrap();
        let b = SysctlSetting::new("kernel.kptr_restrict", "2").unwrap();
        assert_ne!(a, b);
    }
}
