use serde::{Deserialize, Serialize};

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
}
