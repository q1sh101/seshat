use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::lock::current_uid;

pub const SCHEMA_VERSION: u32 = 1;

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

// Kernel treats '-' and '_' as equivalent in module names.
fn normalize_module(name: &str) -> String {
    name.replace('-', "_")
}

fn boot_arg_key(arg: &str) -> &str {
    arg.split_once('=').map(|(k, _)| k).unwrap_or(arg)
}

impl Profile {
    pub fn check_schema_version(&self) -> Result<(), Error> {
        if self.schema_version == SCHEMA_VERSION {
            return Ok(());
        }
        Err(reject(
            "schema_version",
            format!(
                "unsupported schema version {} (this build supports {}); upgrade seshat or migrate the profile",
                self.schema_version, SCHEMA_VERSION
            ),
        ))
    }

    pub fn check_duplicates(&self) -> Result<(), Error> {
        let mut sysctl_seen: HashSet<&str> = HashSet::new();
        for entry in &self.sysctl {
            if !sysctl_seen.insert(entry.key.as_str()) {
                return Err(reject("sysctl", format!("duplicate key {:?}", entry.key)));
            }
        }

        let mut module_seen: HashSet<String> = HashSet::new();
        for name in &self.modules.block {
            let normal = normalize_module(name);
            if !module_seen.insert(normal.clone()) {
                return Err(reject(
                    "modules.block",
                    format!("duplicate module {name:?} (normalizes to {normal:?})"),
                ));
            }
        }

        let mut boot_seen: HashSet<&str> = HashSet::new();
        for entry in &self.boot {
            let key = boot_arg_key(&entry.arg);
            if !boot_seen.insert(key) {
                return Err(reject(
                    "boot",
                    format!("conflicting boot args for key {key:?}"),
                ));
            }
        }

        Ok(())
    }
}

// TOCTOU boundary: compare opened-file metadata to preflight.
fn same_inode(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

// SUDO_UID exists only when the kernel raised our euid; accepting it keeps
// `sudo seshat deploy` usable against a profile kept under the invoker's home.
fn sudo_uid() -> Option<u32> {
    std::env::var("SUDO_UID").ok()?.parse().ok()
}

fn uid_is_acceptable(file_uid: u32, current: u32, sudo: Option<u32>) -> bool {
    file_uid == 0 || file_uid == current || sudo.is_some_and(|s| file_uid == s)
}

pub fn load_profile(path: &Path) -> Result<Profile, Error> {
    let preflight = fs::symlink_metadata(path)?;
    let ft = preflight.file_type();
    if ft.is_symlink() {
        return Err(Error::UnsafePath {
            path: path.to_path_buf(),
            reason: "policy file is a symlink".to_string(),
        });
    }
    if !ft.is_file() {
        return Err(Error::UnsafePath {
            path: path.to_path_buf(),
            reason: "policy file is not a regular file".to_string(),
        });
    }
    let mode = preflight.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(Error::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("policy file is group/world-writable (mode {mode:o})"),
        });
    }
    let owner = preflight.uid();
    if !uid_is_acceptable(owner, current_uid()?, sudo_uid()) {
        return Err(Error::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("policy file owner uid {owner} is not current/sudo/root"),
        });
    }

    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    if !same_inode(&preflight, &opened) {
        return Err(Error::UnsafePath {
            path: path.to_path_buf(),
            reason: "policy file changed between preflight and open".to_string(),
        });
    }
    if !opened.file_type().is_file() {
        return Err(Error::UnsafePath {
            path: path.to_path_buf(),
            reason: "opened policy file is not a regular file".to_string(),
        });
    }
    let opened_mode = opened.permissions().mode() & 0o777;
    if opened_mode & 0o022 != 0 {
        return Err(Error::UnsafePath {
            path: path.to_path_buf(),
            reason: format!("opened policy file is group/world-writable (mode {opened_mode:o})"),
        });
    }

    let mut text = String::new();
    use std::io::Read;
    file.read_to_string(&mut text)?;
    let profile: Profile = toml::from_str(&text).map_err(|e| Error::Parse {
        what: path.display().to_string(),
        reason: e.to_string(),
    })?;
    profile.check_schema_version()?;
    profile.check_duplicates()?;
    Ok(profile)
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

    use std::io::Write;
    use tempfile::tempdir;

    fn write_profile(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(body.as_bytes()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    const MIN_PROFILE: &str = r#"
schema_version = 1
profile_name = "baseline"

[[sysctl]]
key = "kernel.kptr_restrict"
value = "2"
"#;

    #[test]
    fn load_profile_returns_parsed_profile() {
        let dir = tempdir().unwrap();
        let path = write_profile(dir.path(), "baseline.toml", MIN_PROFILE);
        let p = load_profile(&path).unwrap();
        assert_eq!(p.profile_name, "baseline");
        assert_eq!(p.sysctl.len(), 1);
    }

    #[test]
    fn load_profile_rejects_symlink() {
        use std::os::unix::fs::symlink;
        let dir = tempdir().unwrap();
        let real = write_profile(dir.path(), "real.toml", MIN_PROFILE);
        let link = dir.path().join("link.toml");
        symlink(&real, &link).unwrap();
        let err = load_profile(&link).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn load_profile_rejects_directory() {
        let dir = tempdir().unwrap();
        let sub = dir.path().join("subdir");
        fs::create_dir(&sub).unwrap();
        let err = load_profile(&sub).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn load_profile_rejects_group_writable() {
        let dir = tempdir().unwrap();
        let path = write_profile(dir.path(), "baseline.toml", MIN_PROFILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        let err = load_profile(&path).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn load_profile_rejects_world_writable() {
        let dir = tempdir().unwrap();
        let path = write_profile(dir.path(), "baseline.toml", MIN_PROFILE);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o646)).unwrap();
        let err = load_profile(&path).unwrap_err();
        assert!(matches!(err, Error::UnsafePath { .. }));
    }

    #[test]
    fn load_profile_maps_parse_failure_to_parse_variant() {
        let dir = tempdir().unwrap();
        let path = write_profile(dir.path(), "bad.toml", "not = valid = toml");
        match load_profile(&path).unwrap_err() {
            Error::Parse { what, .. } => assert!(what.contains("bad.toml")),
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    #[test]
    fn load_profile_maps_missing_file_to_io_error() {
        let dir = tempdir().unwrap();
        let err = load_profile(&dir.path().join("missing.toml")).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn load_profile_rejects_unknown_field_via_deny_unknown() {
        let dir = tempdir().unwrap();
        let body = r#"
schema_version = 1
profile_name = "x"
surprise = true
"#;
        let path = write_profile(dir.path(), "bad.toml", body);
        assert!(matches!(
            load_profile(&path).unwrap_err(),
            Error::Parse { .. }
        ));
    }

    #[test]
    fn same_inode_true_for_same_file() {
        let dir = tempdir().unwrap();
        let path = write_profile(dir.path(), "a.toml", MIN_PROFILE);
        let a = fs::symlink_metadata(&path).unwrap();
        let b = fs::File::open(&path).unwrap().metadata().unwrap();
        assert!(same_inode(&a, &b));
    }

    #[test]
    fn same_inode_false_across_distinct_files() {
        let dir = tempdir().unwrap();
        let a_path = write_profile(dir.path(), "a.toml", MIN_PROFILE);
        let b_path = write_profile(dir.path(), "b.toml", MIN_PROFILE);
        let a = fs::symlink_metadata(&a_path).unwrap();
        let b = fs::symlink_metadata(&b_path).unwrap();
        assert!(!same_inode(&a, &b));
    }

    #[test]
    fn uid_is_acceptable_accepts_root_current_and_sudo() {
        assert!(uid_is_acceptable(0, 1000, Some(1000)));
        assert!(uid_is_acceptable(1000, 1000, None));
        assert!(uid_is_acceptable(1000, 0, Some(1000)));
    }

    #[test]
    fn uid_is_acceptable_rejects_unrelated_uid() {
        assert!(!uid_is_acceptable(1234, 1000, None));
        assert!(!uid_is_acceptable(1234, 0, Some(1000)));
    }

    fn mk_profile(sysctl: Vec<SysctlEntry>, block: Vec<&str>, boot: Vec<&str>) -> Profile {
        Profile {
            schema_version: 1,
            profile_name: "x".to_string(),
            modules: ModulesSection {
                mode: None,
                block: block.into_iter().map(String::from).collect(),
            },
            sysctl,
            boot: boot
                .into_iter()
                .map(|a| BootEntry { arg: a.to_string() })
                .collect(),
            lockdown: LockdownSection::default(),
        }
    }

    #[test]
    fn check_duplicates_accepts_unique_entries() {
        let p = mk_profile(
            vec![
                SysctlEntry {
                    key: "kernel.kptr_restrict".to_string(),
                    value: "2".to_string(),
                },
                SysctlEntry {
                    key: "kernel.dmesg_restrict".to_string(),
                    value: "1".to_string(),
                },
            ],
            vec!["usb-storage", "firewire_core"],
            vec!["lockdown=confidentiality", "quiet"],
        );
        p.check_duplicates().unwrap();
    }

    #[test]
    fn check_duplicates_rejects_duplicate_sysctl_key() {
        let p = mk_profile(
            vec![
                SysctlEntry {
                    key: "kernel.kptr_restrict".to_string(),
                    value: "2".to_string(),
                },
                SysctlEntry {
                    key: "kernel.kptr_restrict".to_string(),
                    value: "3".to_string(),
                },
            ],
            vec![],
            vec![],
        );
        match p.check_duplicates().unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "sysctl"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn check_duplicates_rejects_modules_after_normalization() {
        let p = mk_profile(vec![], vec!["usb-storage", "usb_storage"], vec![]);
        match p.check_duplicates().unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "modules.block"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn check_duplicates_rejects_conflicting_boot_args_same_key() {
        let p = mk_profile(
            vec![],
            vec![],
            vec!["lockdown=confidentiality", "lockdown=integrity"],
        );
        match p.check_duplicates().unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "boot"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn check_duplicates_rejects_repeated_bare_boot_arg() {
        let p = mk_profile(vec![], vec![], vec!["quiet", "quiet"]);
        assert!(matches!(
            p.check_duplicates().unwrap_err(),
            Error::Validation { .. }
        ));
    }

    #[test]
    fn load_profile_surfaces_duplicate_sysctl_key() {
        let dir = tempdir().unwrap();
        let body = r#"
schema_version = 1
profile_name = "x"

[[sysctl]]
key = "kernel.kptr_restrict"
value = "2"

[[sysctl]]
key = "kernel.kptr_restrict"
value = "3"
"#;
        let path = write_profile(dir.path(), "dup.toml", body);
        assert!(matches!(
            load_profile(&path).unwrap_err(),
            Error::Validation { .. }
        ));
    }

    #[test]
    fn normalize_module_is_idempotent_on_underscores() {
        assert_eq!(normalize_module("usb_storage"), "usb_storage");
        assert_eq!(normalize_module("usb-storage"), "usb_storage");
        assert_eq!(normalize_module("nf-nat-ipv4"), "nf_nat_ipv4");
    }

    #[test]
    fn boot_arg_key_splits_on_first_equals() {
        assert_eq!(boot_arg_key("quiet"), "quiet");
        assert_eq!(boot_arg_key("lockdown=confidentiality"), "lockdown");
        assert_eq!(boot_arg_key("mitigations=auto,nosmt"), "mitigations");
    }

    #[test]
    fn check_schema_version_accepts_current() {
        let p = mk_profile(vec![], vec![], vec![]);
        assert_eq!(p.schema_version, SCHEMA_VERSION);
        p.check_schema_version().unwrap();
    }

    #[test]
    fn check_schema_version_rejects_zero() {
        let mut p = mk_profile(vec![], vec![], vec![]);
        p.schema_version = 0;
        match p.check_schema_version().unwrap_err() {
            Error::Validation { field, reason } => {
                assert_eq!(field, "schema_version");
                assert!(reason.contains("unsupported"), "reason: {reason}");
                assert!(reason.contains("upgrade") || reason.contains("migrate"));
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[test]
    fn check_schema_version_rejects_future_versions() {
        let mut p = mk_profile(vec![], vec![], vec![]);
        p.schema_version = 2;
        assert!(matches!(
            p.check_schema_version().unwrap_err(),
            Error::Validation { .. }
        ));
    }

    #[test]
    fn load_profile_surfaces_schema_version_mismatch() {
        let dir = tempdir().unwrap();
        let body = r#"
schema_version = 99
profile_name = "x"
"#;
        let path = write_profile(dir.path(), "future.toml", body);
        match load_profile(&path).unwrap_err() {
            Error::Validation { field, .. } => assert_eq!(field, "schema_version"),
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
