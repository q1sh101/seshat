use crate::error::Error;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum QuoteStyle {
    Unquoted,
    Single,
    Double,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GrubDefaultLine {
    pub value: String,
    pub quote: QuoteStyle,
}

const TARGET_KEY: &str = "GRUB_CMDLINE_LINUX_DEFAULT=";

// Last-assignment-wins (shell); malformed line errors so stale values cannot hide regressions.
pub fn parse_grub_cmdline_default(content: &str) -> Result<Option<GrubDefaultLine>, Error> {
    let mut last: Option<GrubDefaultLine> = None;
    for (idx, raw) in content.lines().enumerate() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some(rest) = line.strip_prefix(TARGET_KEY) else {
            continue;
        };
        let parsed = parse_rhs(rest).map_err(|reason| Error::Parse {
            what: format!("GRUB_CMDLINE_LINUX_DEFAULT at line {}", idx + 1),
            reason,
        })?;
        last = Some(parsed);
    }
    Ok(last)
}

fn parse_rhs(rest: &str) -> Result<GrubDefaultLine, String> {
    if let Some(after) = rest.strip_prefix('"') {
        let close = after
            .find('"')
            .ok_or_else(|| "unterminated double quote".to_string())?;
        let value = after[..close].to_string();
        validate_trailing(&after[close + 1..])?;
        return Ok(GrubDefaultLine {
            value,
            quote: QuoteStyle::Double,
        });
    }
    if let Some(after) = rest.strip_prefix('\'') {
        let close = after
            .find('\'')
            .ok_or_else(|| "unterminated single quote".to_string())?;
        let value = after[..close].to_string();
        validate_trailing(&after[close + 1..])?;
        return Ok(GrubDefaultLine {
            value,
            quote: QuoteStyle::Single,
        });
    }
    let value = strip_unquoted_inline_comment(rest).trim_end().to_string();
    Ok(GrubDefaultLine {
        value,
        quote: QuoteStyle::Unquoted,
    })
}

// Trailing after closing quote: only empty or whitespace-then-# allowed; junk fails.
fn validate_trailing(after_close: &str) -> Result<(), String> {
    let trimmed = after_close.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let starts_with_ws = after_close.starts_with(|c: char| c.is_whitespace());
    if trimmed.starts_with('#') && starts_with_ws {
        return Ok(());
    }
    Err(format!(
        "unexpected content after closing quote: {trimmed:?}"
    ))
}

// Shell rule: unquoted '#' starts a comment only after whitespace; otherwise stays in value.
fn strip_unquoted_inline_comment(s: &str) -> &str {
    let mut prev_is_ws = false;
    for (idx, c) in s.char_indices() {
        if c == '#' && prev_is_ws {
            return &s[..idx];
        }
        prev_is_ws = c.is_whitespace();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_line(content: &str) -> GrubDefaultLine {
        parse_grub_cmdline_default(content)
            .expect("must not error")
            .expect("must have an assignment")
    }

    #[test]
    fn parses_double_quoted_value() {
        let out = ok_line(r#"GRUB_CMDLINE_LINUX_DEFAULT="quiet splash""#);
        assert_eq!(out.value, "quiet splash");
        assert_eq!(out.quote, QuoteStyle::Double);
    }

    #[test]
    fn parses_single_quoted_value() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT='lockdown=integrity'");
        assert_eq!(out.value, "lockdown=integrity");
        assert_eq!(out.quote, QuoteStyle::Single);
    }

    #[test]
    fn parses_unquoted_value() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=quiet");
        assert_eq!(out.value, "quiet");
        assert_eq!(out.quote, QuoteStyle::Unquoted);
    }

    #[test]
    fn parses_empty_double_quoted_value() {
        let out = ok_line(r#"GRUB_CMDLINE_LINUX_DEFAULT="""#);
        assert_eq!(out.value, "");
        assert_eq!(out.quote, QuoteStyle::Double);
    }

    #[test]
    fn parses_empty_single_quoted_value() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=''");
        assert_eq!(out.value, "");
        assert_eq!(out.quote, QuoteStyle::Single);
    }

    #[test]
    fn parses_empty_unquoted_value() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=");
        assert_eq!(out.value, "");
        assert_eq!(out.quote, QuoteStyle::Unquoted);
    }

    #[test]
    fn ignores_commented_assignment() {
        let text = "# GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n";
        assert!(parse_grub_cmdline_default(text).unwrap().is_none());
    }

    #[test]
    fn ignores_indented_comment() {
        let text = "   #GRUB_CMDLINE_LINUX_DEFAULT=\"x\"\n";
        assert!(parse_grub_cmdline_default(text).unwrap().is_none());
    }

    #[test]
    fn returns_none_when_variable_not_present() {
        let text = "GRUB_TIMEOUT=5\nGRUB_DEFAULT=saved\n";
        assert!(parse_grub_cmdline_default(text).unwrap().is_none());
    }

    #[test]
    fn does_not_match_grub_cmdline_linux_without_default() {
        let text = "GRUB_CMDLINE_LINUX=\"debug\"\n";
        assert!(parse_grub_cmdline_default(text).unwrap().is_none());
    }

    #[test]
    fn returns_last_assignment_when_multiple_valid() {
        let text = "\
GRUB_CMDLINE_LINUX_DEFAULT=\"first\"
GRUB_CMDLINE_LINUX_DEFAULT=\"second\"
GRUB_CMDLINE_LINUX_DEFAULT=\"last\"
";
        assert_eq!(ok_line(text).value, "last");
    }

    #[test]
    fn handles_leading_whitespace_before_assignment() {
        let out = ok_line("    GRUB_CMDLINE_LINUX_DEFAULT=\"x\"\n");
        assert_eq!(out.value, "x");
    }

    #[test]
    fn accepts_inline_comment_after_closing_double_quote() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\" # inline comment\n");
        assert_eq!(out.value, "quiet");
        assert_eq!(out.quote, QuoteStyle::Double);
    }

    #[test]
    fn accepts_inline_comment_after_closing_single_quote() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT='x'    # note\n");
        assert_eq!(out.value, "x");
        assert_eq!(out.quote, QuoteStyle::Single);
    }

    #[test]
    fn rejects_unterminated_double_quote() {
        let text = "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\n";
        let err = parse_grub_cmdline_default(text).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn rejects_unterminated_single_quote() {
        let text = "GRUB_CMDLINE_LINUX_DEFAULT='quiet splash\n";
        let err = parse_grub_cmdline_default(text).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn rejects_later_malformed_line_even_after_earlier_valid_line() {
        let text = "\
GRUB_CMDLINE_LINUX_DEFAULT=\"good\"
GRUB_CMDLINE_LINUX_DEFAULT=\"unterminated
";
        let err = parse_grub_cmdline_default(text).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn rejects_trailing_non_comment_junk_after_quoted_value() {
        let text = "GRUB_CMDLINE_LINUX_DEFAULT=\"x\" trailing-word\n";
        let err = parse_grub_cmdline_default(text).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn rejects_hash_immediately_after_closing_quote_without_whitespace() {
        let text = "GRUB_CMDLINE_LINUX_DEFAULT=\"x\"#no-space\n";
        let err = parse_grub_cmdline_default(text).unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn preserves_internal_whitespace_in_quoted_value() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=\"foo  bar   baz\"\n");
        assert_eq!(out.value, "foo  bar   baz");
    }

    #[test]
    fn strips_inline_comment_from_unquoted_value() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=quiet # note\n");
        assert_eq!(out.value, "quiet");
        assert_eq!(out.quote, QuoteStyle::Unquoted);
    }

    #[test]
    fn unquoted_hash_without_preceding_whitespace_stays_in_value() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=quiet#keep\n");
        assert_eq!(out.value, "quiet#keep");
    }

    #[test]
    fn unquoted_value_trims_only_trailing_whitespace() {
        let out = ok_line("GRUB_CMDLINE_LINUX_DEFAULT=quiet   \n");
        assert_eq!(out.value, "quiet");
        assert_eq!(out.quote, QuoteStyle::Unquoted);
    }

    #[test]
    fn handles_comment_and_real_assignment_mixed() {
        let text = "\
# default was empty
# GRUB_CMDLINE_LINUX_DEFAULT=\"old\"
GRUB_CMDLINE_LINUX_DEFAULT=\"quiet splash\"
";
        assert_eq!(ok_line(text).value, "quiet splash");
    }

    #[test]
    fn ignores_unrelated_variable_prefix_suffix_collisions() {
        let text = "\
GRUB_CMDLINE_LINUX=\"x\"
GRUB_CMDLINE_LINUX_DEFAULT_EXTRA=\"y\"
FOO_GRUB_CMDLINE_LINUX_DEFAULT=\"z\"
";
        assert!(parse_grub_cmdline_default(text).unwrap().is_none());
    }

    #[test]
    fn parse_error_reports_line_number() {
        let text = "\
GRUB_TIMEOUT=5
GRUB_CMDLINE_LINUX_DEFAULT=\"unterminated
";
        let err = parse_grub_cmdline_default(text).unwrap_err();
        match err {
            Error::Parse { what, .. } => {
                assert!(what.contains("line 2"), "expected line 2 in {what:?}");
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }
}
