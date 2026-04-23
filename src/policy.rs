use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema_version: u32,
    pub profile_name: String,
    #[serde(default)]
    pub modules: ModulesSection,
    #[serde(default)]
    pub sysctl: Vec<SysctlEntry>,
    #[serde(default)]
    pub boot: Vec<BootEntry>,
    #[serde(default)]
    pub lockdown: LockdownSection,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ModulesSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub block: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SysctlEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootEntry {
    pub arg: String,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockdownSection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<String>,
}

fn reject(field: &'static str, reason: impl Into<String>) -> Error {
    Error::Validation {
        field: field.to_string(),
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ProfileName(String);

impl ProfileName {
    pub fn new(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(reject("profile_name", "empty"));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(reject(
                "profile_name",
                format!("must match ^[A-Za-z0-9_-]+$: {s:?}"),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SysctlKey(String);

impl SysctlKey {
    pub fn new(s: &str) -> Result<Self, Error> {
        if s.len() < 2 {
            return Err(reject("sysctl_key", "must be at least two characters"));
        }
        let mut chars = s.chars();
        let first = chars.next().unwrap();
        if !first.is_ascii_lowercase() {
            return Err(reject(
                "sysctl_key",
                format!("first character must be a-z: {s:?}"),
            ));
        }
        for c in chars {
            let ok =
                c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '.' || c == '-';
            if !ok {
                return Err(reject(
                    "sysctl_key",
                    format!("must match ^[a-z][a-z0-9_.-]+$: {s:?}"),
                ));
            }
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct SysctlValue(String);

impl SysctlValue {
    pub fn new(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(reject("sysctl_value", "empty"));
        }
        if s.starts_with(char::is_whitespace) || s.ends_with(char::is_whitespace) {
            return Err(reject(
                "sysctl_value",
                "leading or trailing whitespace not allowed",
            ));
        }
        for c in s.chars() {
            let ok =
                c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | ',' | '|' | '/' | ' ');
            if !ok {
                return Err(reject(
                    "sysctl_value",
                    format!("disallowed character {c:?} in {s:?}"),
                ));
            }
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct ModuleName(String);

impl ModuleName {
    pub fn new(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(reject("module_name", "empty"));
        }
        if !s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(reject(
                "module_name",
                format!("must match ^[A-Za-z0-9_-]+$: {s:?}"),
            ));
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct BootArg(String);

impl BootArg {
    pub fn new(s: &str) -> Result<Self, Error> {
        if s.is_empty() {
            return Err(reject("boot_arg", "empty"));
        }
        for c in s.chars() {
            let ok = c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '=' | ',' | '-');
            if !ok {
                return Err(reject(
                    "boot_arg",
                    format!("must match ^[A-Za-z0-9_.=,-]+$: {s:?}"),
                ));
            }
        }
        Ok(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(src: &str) -> Result<Profile, toml::de::Error> {
        toml::from_str::<Profile>(src)
    }

    #[test]
    fn baseline_example_parses() {
        let src = r#"
schema_version = 1
profile_name = "baseline"

[modules]
mode = "allowlist"
block = []

[[sysctl]]
key = "kernel.kptr_restrict"
value = "2"

[[boot]]
arg = "lockdown=confidentiality"
"#;
        let p = parse(src).unwrap();
        assert_eq!(p.schema_version, 1);
        assert_eq!(p.profile_name, "baseline");
        assert_eq!(p.modules.mode.as_deref(), Some("allowlist"));
        assert!(p.modules.block.is_empty());
        assert_eq!(p.sysctl.len(), 1);
        assert_eq!(p.sysctl[0].key, "kernel.kptr_restrict");
        assert_eq!(p.sysctl[0].value, "2");
        assert_eq!(p.boot.len(), 1);
        assert_eq!(p.boot[0].arg, "lockdown=confidentiality");
    }

    #[test]
    fn minimal_profile_parses_with_defaults() {
        let src = r#"
schema_version = 1
profile_name = "minimal"
"#;
        let p = parse(src).unwrap();
        assert_eq!(p.profile_name, "minimal");
        assert_eq!(p.modules, ModulesSection::default());
        assert!(p.sysctl.is_empty());
        assert!(p.boot.is_empty());
        assert_eq!(p.lockdown, LockdownSection::default());
    }

    #[test]
    fn lockdown_section_parses() {
        let src = r#"
schema_version = 1
profile_name = "x"

[lockdown]
expect = "confidentiality"
"#;
        let p = parse(src).unwrap();
        assert_eq!(p.lockdown.expect.as_deref(), Some("confidentiality"));
    }

    #[test]
    fn unknown_lockdown_field_is_rejected() {
        let src = r#"
schema_version = 1
profile_name = "x"

[lockdown]
expect = "confidentiality"
hidden = true
"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn missing_schema_version_is_rejected() {
        let src = r#"profile_name = "x""#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn missing_profile_name_is_rejected() {
        let src = r#"schema_version = 1"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn unknown_top_level_field_is_rejected() {
        let src = r#"
schema_version = 1
profile_name = "x"
surprise = true
"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn unknown_modules_field_is_rejected() {
        let src = r#"
schema_version = 1
profile_name = "x"

[modules]
mode = "allowlist"
hidden = 42
"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn unknown_sysctl_field_is_rejected() {
        let src = r#"
schema_version = 1
profile_name = "x"

[[sysctl]]
key = "kernel.kptr_restrict"
value = "2"
extra = "nope"
"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn unknown_boot_field_is_rejected() {
        let src = r#"
schema_version = 1
profile_name = "x"

[[boot]]
arg = "x"
rogue = "y"
"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn sysctl_entry_requires_both_key_and_value() {
        let missing_value = r#"
schema_version = 1
profile_name = "x"

[[sysctl]]
key = "kernel.kptr_restrict"
"#;
        assert!(parse(missing_value).is_err());

        let missing_key = r#"
schema_version = 1
profile_name = "x"

[[sysctl]]
value = "2"
"#;
        assert!(parse(missing_key).is_err());
    }

    #[test]
    fn boot_entry_requires_arg() {
        let src = r#"
schema_version = 1
profile_name = "x"

[[boot]]
"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn schema_version_must_be_a_number() {
        let src = r#"
schema_version = "one"
profile_name = "x"
"#;
        assert!(parse(src).is_err());
    }

    #[test]
    fn round_trip_preserves_structure() {
        let original = Profile {
            schema_version: 1,
            profile_name: "baseline".to_string(),
            modules: ModulesSection {
                mode: Some("allowlist".to_string()),
                block: vec!["usb-storage".to_string()],
            },
            sysctl: vec![SysctlEntry {
                key: "kernel.kptr_restrict".to_string(),
                value: "2".to_string(),
            }],
            boot: vec![BootEntry {
                arg: "lockdown=confidentiality".to_string(),
            }],
            lockdown: LockdownSection {
                expect: Some("confidentiality".to_string()),
            },
        };
        let serialised = toml::to_string(&original).unwrap();
        let parsed: Profile = toml::from_str(&serialised).unwrap();
        assert_eq!(parsed, original);
    }

    #[test]
    fn profile_name_accepts_plan_charset() {
        assert_eq!(ProfileName::new("baseline").unwrap().as_str(), "baseline");
        assert_eq!(ProfileName::new("Mix_42-x").unwrap().as_str(), "Mix_42-x");
    }

    #[test]
    fn profile_name_rejects_empty_and_bad_chars() {
        assert!(ProfileName::new("").is_err());
        assert!(ProfileName::new("has space").is_err());
        assert!(ProfileName::new("dot.is.bad").is_err());
        assert!(ProfileName::new("../escape").is_err());
        assert!(ProfileName::new("shell$ubst").is_err());
    }

    #[test]
    fn sysctl_key_accepts_dotted_lowercase_names() {
        assert_eq!(
            SysctlKey::new("kernel.kptr_restrict").unwrap().as_str(),
            "kernel.kptr_restrict"
        );
        assert_eq!(
            SysctlKey::new("net.ipv4.conf.all.rp_filter")
                .unwrap()
                .as_str(),
            "net.ipv4.conf.all.rp_filter"
        );
    }

    #[test]
    fn sysctl_key_rejects_uppercase_digit_or_empty_start() {
        assert!(SysctlKey::new("").is_err());
        assert!(SysctlKey::new("a").is_err());
        assert!(SysctlKey::new("Kernel.kptr").is_err());
        assert!(SysctlKey::new("1kernel").is_err());
        assert!(SysctlKey::new(".kernel").is_err());
        assert!(SysctlKey::new("kernel kptr").is_err());
    }

    #[test]
    fn sysctl_value_accepts_baseline_forms() {
        assert_eq!(SysctlValue::new("2").unwrap().as_str(), "2");
        assert_eq!(SysctlValue::new("3 3 3 3").unwrap().as_str(), "3 3 3 3");
        assert_eq!(
            SysctlValue::new("|/bin/false").unwrap().as_str(),
            "|/bin/false"
        );
        assert_eq!(
            SysctlValue::new("full,force").unwrap().as_str(),
            "full,force"
        );
    }

    #[test]
    fn sysctl_value_rejects_empty_trim_and_shell_metacharacters() {
        assert!(SysctlValue::new("").is_err());
        assert!(SysctlValue::new(" leading").is_err());
        assert!(SysctlValue::new("trailing ").is_err());
        assert!(SysctlValue::new("bad;semi").is_err());
        assert!(SysctlValue::new("bad`tick").is_err());
        assert!(SysctlValue::new("bad$var").is_err());
        assert!(SysctlValue::new("bad&bg").is_err());
        assert!(SysctlValue::new("bad>redir").is_err());
        assert!(SysctlValue::new("bad\"quote").is_err());
    }

    #[test]
    fn module_name_accepts_plan_charset() {
        assert_eq!(
            ModuleName::new("usb_storage").unwrap().as_str(),
            "usb_storage"
        );
        assert_eq!(ModuleName::new("nf-nat").unwrap().as_str(), "nf-nat");
        assert_eq!(ModuleName::new("vfat").unwrap().as_str(), "vfat");
    }

    #[test]
    fn module_name_rejects_empty_and_bad_chars() {
        assert!(ModuleName::new("").is_err());
        assert!(ModuleName::new("has space").is_err());
        assert!(ModuleName::new("dot.bad").is_err());
        assert!(ModuleName::new("sub/path").is_err());
    }

    #[test]
    fn boot_arg_accepts_plan_charset() {
        assert_eq!(
            BootArg::new("lockdown=confidentiality").unwrap().as_str(),
            "lockdown=confidentiality"
        );
        assert_eq!(
            BootArg::new("mitigations=auto,nosmt").unwrap().as_str(),
            "mitigations=auto,nosmt"
        );
        assert_eq!(BootArg::new("quiet").unwrap().as_str(), "quiet");
    }

    #[test]
    fn boot_arg_rejects_empty_space_and_shell_metacharacters() {
        assert!(BootArg::new("").is_err());
        assert!(BootArg::new("has space").is_err());
        assert!(BootArg::new("with;semi").is_err());
        assert!(BootArg::new("with|pipe").is_err());
        assert!(BootArg::new("with/slash").is_err());
        assert!(BootArg::new("with$var").is_err());
    }

    #[test]
    fn validation_errors_name_the_field() {
        match ProfileName::new("").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "profile_name"),
            other => panic!("expected Validation, got {other:?}"),
        }
        match SysctlKey::new("").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_key"),
            other => panic!("expected Validation, got {other:?}"),
        }
        match SysctlValue::new("").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl_value"),
            other => panic!("expected Validation, got {other:?}"),
        }
        match ModuleName::new("").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "module_name"),
            other => panic!("expected Validation, got {other:?}"),
        }
        match BootArg::new("").unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "boot_arg"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
