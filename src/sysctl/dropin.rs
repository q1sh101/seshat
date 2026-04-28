use super::setting::SysctlSetting;

pub fn generate_sysctl_dropin(settings: &[SysctlSetting], profile_name: &str) -> String {
    let mut out = String::new();
    out.push_str("# managed by seshat\n");
    out.push_str(&format!("# profile: {profile_name}\n"));
    out.push('\n');
    for s in settings {
        out.push_str(s.key.as_str());
        out.push_str(" = ");
        out.push_str(s.value.as_str());
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setting(key: &str, value: &str) -> SysctlSetting {
        SysctlSetting::new(key, value).unwrap()
    }

    #[test]
    fn header_uses_managed_by_seshat_and_profile_name() {
        let out = generate_sysctl_dropin(&[], "baseline");
        assert!(out.starts_with("# managed by seshat\n"));
        assert!(out.contains("# profile: baseline\n"));
    }

    #[test]
    fn empty_settings_produce_header_only() {
        let out = generate_sysctl_dropin(&[], "baseline");
        assert!(!out.lines().any(|l| l.contains('=')));
    }

    #[test]
    fn emits_one_entry_per_line_with_spaced_equals() {
        let out = generate_sysctl_dropin(&[setting("kernel.kptr_restrict", "2")], "x");
        assert!(out.contains("\nkernel.kptr_restrict = 2\n"));
    }

    #[test]
    fn preserves_profile_order() {
        let settings = vec![
            setting("kernel.dmesg_restrict", "1"),
            setting("kernel.kptr_restrict", "2"),
            setting("net.core.bpf_jit_harden", "2"),
        ];
        let out = generate_sysctl_dropin(&settings, "x");
        let entries: Vec<&str> = out.lines().filter(|l| l.contains('=')).collect();
        assert_eq!(
            entries,
            vec![
                "kernel.dmesg_restrict = 1",
                "kernel.kptr_restrict = 2",
                "net.core.bpf_jit_harden = 2",
            ]
        );
    }

    #[test]
    fn multi_value_entries_render_with_single_spaces() {
        let out = generate_sysctl_dropin(&[setting("kernel.printk", "4  4  1  7")], "x");
        assert!(out.contains("kernel.printk = 4 4 1 7\n"));
    }

    #[test]
    fn output_is_deterministic_across_runs() {
        let settings = vec![setting("kernel.kptr_restrict", "2")];
        let a = generate_sysctl_dropin(&settings, "baseline");
        let b = generate_sysctl_dropin(&settings, "baseline");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_settings_output_is_exact() {
        let out = generate_sysctl_dropin(&[], "baseline");
        assert_eq!(out, "# managed by seshat\n# profile: baseline\n\n");
    }

    #[test]
    fn single_setting_output_is_exact() {
        let out = generate_sysctl_dropin(&[setting("kernel.kptr_restrict", "2")], "baseline");
        assert_eq!(
            out,
            "# managed by seshat\n# profile: baseline\n\nkernel.kptr_restrict = 2\n"
        );
    }

    #[test]
    fn blank_line_separates_header_from_entries() {
        let out = generate_sysctl_dropin(&[setting("kernel.kptr_restrict", "2")], "x");
        let lines: Vec<&str> = out.lines().collect();
        let blank_idx = lines.iter().position(|l| l.is_empty()).unwrap();
        assert!(
            lines[..blank_idx].iter().all(|l| l.starts_with('#')),
            "header must precede blank line"
        );
        assert!(
            lines[blank_idx + 1..]
                .iter()
                .all(|l| l.is_empty() || l.contains('=')),
            "entries must follow blank line"
        );
    }
}
