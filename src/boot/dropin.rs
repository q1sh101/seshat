// Caller must pass pre-merged tokens; this assignment overrides main grub, so managed-only input silently drops operator args.
pub fn generate_grub_dropin(merged_cmdline: &str, profile_name: &str) -> String {
    let mut out = String::new();
    out.push_str("# managed by seshat\n");
    out.push_str(&format!("# profile: {profile_name}\n"));
    out.push_str("# mode: grub-dropin\n");
    out.push('\n');
    out.push_str("GRUB_CMDLINE_LINUX_DEFAULT=\"");
    out.push_str(merged_cmdline);
    out.push_str("\"\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_uses_managed_by_seshat_and_profile_name() {
        let out = generate_grub_dropin("", "baseline");
        assert!(out.starts_with("# managed by seshat\n"));
        assert!(out.contains("# profile: baseline\n"));
    }

    #[test]
    fn header_declares_grub_dropin_mode() {
        let out = generate_grub_dropin("quiet", "baseline");
        assert!(out.contains("# mode: grub-dropin\n"));
    }

    #[test]
    fn empty_cmdline_emits_quoted_empty_value() {
        let out = generate_grub_dropin("", "baseline");
        assert!(out.ends_with("GRUB_CMDLINE_LINUX_DEFAULT=\"\"\n"));
    }

    #[test]
    fn typical_cmdline_is_quoted_verbatim() {
        let out = generate_grub_dropin("quiet init_on_alloc=1 debugfs=off", "baseline");
        assert!(out.contains("GRUB_CMDLINE_LINUX_DEFAULT=\"quiet init_on_alloc=1 debugfs=off\"\n"));
    }

    #[test]
    fn comma_and_hyphen_tokens_preserved() {
        let out = generate_grub_dropin("mitigations=auto,nosmt lockdown=integrity", "x");
        assert!(out.contains("mitigations=auto,nosmt lockdown=integrity"));
    }

    #[test]
    fn blank_line_separates_header_from_assignment() {
        let out = generate_grub_dropin("quiet", "x");
        let lines: Vec<&str> = out.lines().collect();
        let blank_idx = lines.iter().position(|l| l.is_empty()).unwrap();
        assert!(
            lines[..blank_idx].iter().all(|l| l.starts_with('#')),
            "header must precede blank line"
        );
        assert!(
            lines[blank_idx + 1..]
                .iter()
                .all(|l| l.is_empty() || l.starts_with("GRUB_CMDLINE_LINUX_DEFAULT=")),
            "assignment must follow blank line"
        );
    }

    #[test]
    fn output_is_deterministic_across_runs() {
        let a = generate_grub_dropin("quiet init_on_alloc=1", "baseline");
        let b = generate_grub_dropin("quiet init_on_alloc=1", "baseline");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_cmdline_output_is_exact() {
        let out = generate_grub_dropin("", "baseline");
        assert_eq!(
            out,
            "# managed by seshat\n# profile: baseline\n# mode: grub-dropin\n\nGRUB_CMDLINE_LINUX_DEFAULT=\"\"\n"
        );
    }

    #[test]
    fn typical_cmdline_output_is_exact() {
        let out = generate_grub_dropin("quiet init_on_alloc=1", "baseline");
        assert_eq!(
            out,
            "# managed by seshat\n# profile: baseline\n# mode: grub-dropin\n\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet init_on_alloc=1\"\n"
        );
    }

    #[test]
    fn profile_name_with_hyphen_rendered_verbatim() {
        let out = generate_grub_dropin("quiet", "hardened-server");
        assert!(out.contains("# profile: hardened-server\n"));
    }

    #[test]
    fn render_is_pass_through_sanitization_is_upstream() {
        let out = generate_grub_dropin("quiet \"evil$`", "x");
        assert!(out.contains("quiet \"evil$`"));
    }

    #[test]
    fn cmdline_newline_passes_through_upstream_must_reject() {
        let out = generate_grub_dropin("quiet\nGRUB_EVIL=1", "x");
        assert!(out.contains("quiet\nGRUB_EVIL=1"));
    }

    #[test]
    fn profile_name_newline_passes_through_upstream_must_reject() {
        let out = generate_grub_dropin("quiet", "x\n# mode: fake");
        assert!(out.contains("x\n# mode: fake"));
    }
}
