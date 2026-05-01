use super::cmdline::{QuoteStyle, parse_grub_cmdline_default};
use crate::error::Error;

const TARGET_PREFIX: &str = "GRUB_CMDLINE_LINUX_DEFAULT=";

// Parse first so malformed content errors out; replace only the last assignment so shell last-wins semantics match the parser.
pub fn merge_grub_main_config(content: &str, new_value: &str) -> Result<String, Error> {
    let _ = parse_grub_cmdline_default(content)?;

    let mut last_assignment: Option<usize> = None;
    for (idx, raw) in content.lines().enumerate() {
        if is_assignment_line(raw) {
            last_assignment = Some(idx);
        }
    }

    let pieces: Vec<&str> = content.split_inclusive('\n').collect();

    match last_assignment {
        None => Ok(append_new_assignment(content, new_value)),
        Some(target_idx) => {
            let mut out = String::with_capacity(content.len() + new_value.len() + 4);
            for (idx, piece) in pieces.iter().enumerate() {
                if idx == target_idx {
                    out.push_str(&rewrite_assignment_line(piece, new_value));
                } else {
                    out.push_str(piece);
                }
            }
            Ok(out)
        }
    }
}

fn is_assignment_line(raw: &str) -> bool {
    let trimmed = raw.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return false;
    }
    trimmed.strip_prefix(TARGET_PREFIX).is_some()
}

fn append_new_assignment(content: &str, new_value: &str) -> String {
    let mut out = String::with_capacity(content.len() + new_value.len() + TARGET_PREFIX.len() + 4);
    out.push_str(content);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(TARGET_PREFIX);
    out.push('"');
    out.push_str(new_value);
    out.push_str("\"\n");
    out
}

fn rewrite_assignment_line(line: &str, new_value: &str) -> String {
    let (body, newline) = match line.strip_suffix('\n') {
        Some(b) => (b, "\n"),
        None => (line, ""),
    };

    let trimmed = body.trim_start();
    let leading_ws_len = body.len() - trimmed.len();
    let leading_ws = &body[..leading_ws_len];
    // Upstream parse_grub_cmdline_default validated; strip must succeed for any line we picked.
    let rhs = trimmed
        .strip_prefix(TARGET_PREFIX)
        .expect("prefix validated");

    let (old_quote, suffix) = split_rhs(rhs);
    let new_quote = decide_new_quote(&old_quote, new_value);

    let mut out = String::with_capacity(line.len() + new_value.len());
    out.push_str(leading_ws);
    out.push_str(TARGET_PREFIX);
    match new_quote {
        QuoteStyle::Double => {
            out.push('"');
            out.push_str(new_value);
            out.push('"');
        }
        QuoteStyle::Single => {
            out.push('\'');
            out.push_str(new_value);
            out.push('\'');
        }
        QuoteStyle::Unquoted => out.push_str(new_value),
    }
    out.push_str(suffix);
    out.push_str(newline);
    out
}

// Upstream parser already verified closing quote / trailing shape, so indexing here is safe.
fn split_rhs(rhs: &str) -> (QuoteStyle, &str) {
    if let Some(after) = rhs.strip_prefix('"') {
        let close = after.find('"').expect("closing double quote validated");
        return (QuoteStyle::Double, &after[close + 1..]);
    }
    if let Some(after) = rhs.strip_prefix('\'') {
        let close = after.find('\'').expect("closing single quote validated");
        return (QuoteStyle::Single, &after[close + 1..]);
    }
    let value_end = find_unquoted_end(rhs);
    (QuoteStyle::Unquoted, &rhs[value_end..])
}

// Shell rule: '#' starts a comment only after whitespace; otherwise stays in the value.
fn find_unquoted_end(s: &str) -> usize {
    let mut prev_ws = false;
    for (idx, c) in s.char_indices() {
        if c == '#' && prev_ws {
            return s[..idx].trim_end().len();
        }
        prev_ws = c.is_whitespace();
    }
    s.trim_end().len()
}

// Unquoted cannot carry whitespace; promote so shell tokenization stays correct.
fn decide_new_quote(old: &QuoteStyle, new_value: &str) -> QuoteStyle {
    match old {
        QuoteStyle::Unquoted if new_value.contains(char::is_whitespace) => QuoteStyle::Double,
        _ => old.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merges_into_double_quoted_assignment() {
        let out = merge_grub_main_config(
            "GRUB_CMDLINE_LINUX_DEFAULT=\"old val\"\n",
            "quiet init_on_alloc=1",
        )
        .unwrap();
        assert_eq!(
            out,
            "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet init_on_alloc=1\"\n"
        );
    }

    #[test]
    fn merges_into_single_quoted_assignment() {
        let out = merge_grub_main_config(
            "GRUB_CMDLINE_LINUX_DEFAULT='old val'\n",
            "quiet debugfs=off",
        )
        .unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT='quiet debugfs=off'\n");
    }

    #[test]
    fn merges_into_unquoted_assignment_without_whitespace() {
        let out = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=old\n", "quiet").unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=quiet\n");
    }

    #[test]
    fn promotes_unquoted_to_double_when_new_value_has_whitespace() {
        let out = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=old\n", "quiet debugfs=off")
            .unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet debugfs=off\"\n");
    }

    #[test]
    fn preserves_leading_whitespace_on_assignment_line() {
        let out =
            merge_grub_main_config("    GRUB_CMDLINE_LINUX_DEFAULT=\"old\"\n", "quiet").unwrap();
        assert_eq!(out, "    GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n");
    }

    #[test]
    fn preserves_inline_comment_after_double_quoted() {
        let out = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=\"old\" # keep me\n", "quiet")
            .unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\" # keep me\n");
    }

    #[test]
    fn preserves_inline_comment_after_single_quoted() {
        let out =
            merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT='old'   # note\n", "quiet").unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT='quiet'   # note\n");
    }

    #[test]
    fn preserves_inline_comment_after_unquoted() {
        let out =
            merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=old # cmt\n", "quiet").unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=quiet # cmt\n");
    }

    #[test]
    fn preserves_other_variables_and_blank_lines() {
        let input = "\
GRUB_TIMEOUT=5

GRUB_CMDLINE_LINUX_DEFAULT=\"old\"
GRUB_DEFAULT=saved
";
        let out = merge_grub_main_config(input, "quiet").unwrap();
        assert_eq!(
            out,
            "\
GRUB_TIMEOUT=5

GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"
GRUB_DEFAULT=saved
"
        );
    }

    #[test]
    fn preserves_commented_lookalike_lines() {
        let input = "\
# GRUB_CMDLINE_LINUX_DEFAULT=\"do not touch\"
GRUB_CMDLINE_LINUX_DEFAULT=\"old\"
";
        let out = merge_grub_main_config(input, "quiet").unwrap();
        assert!(out.contains("# GRUB_CMDLINE_LINUX_DEFAULT=\"do not touch\""));
        assert!(out.contains("GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\""));
    }

    #[test]
    fn replaces_only_last_assignment_when_duplicates_exist() {
        let input = "\
GRUB_CMDLINE_LINUX_DEFAULT=\"first\"
GRUB_CMDLINE_LINUX_DEFAULT=\"second\"
GRUB_CMDLINE_LINUX_DEFAULT=\"third\"
";
        let out = merge_grub_main_config(input, "NEW").unwrap();
        assert_eq!(
            out,
            "\
GRUB_CMDLINE_LINUX_DEFAULT=\"first\"
GRUB_CMDLINE_LINUX_DEFAULT=\"second\"
GRUB_CMDLINE_LINUX_DEFAULT=\"NEW\"
"
        );
    }

    #[test]
    fn appends_new_assignment_when_no_existing_line() {
        let out = merge_grub_main_config("GRUB_TIMEOUT=5\n", "quiet").unwrap();
        assert_eq!(
            out,
            "GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n"
        );
    }

    #[test]
    fn appends_newline_before_append_if_file_lacks_trailing_newline() {
        let out = merge_grub_main_config("GRUB_TIMEOUT=5", "quiet").unwrap();
        assert_eq!(
            out,
            "GRUB_TIMEOUT=5\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n"
        );
    }

    #[test]
    fn empty_input_yields_just_the_assignment() {
        let out = merge_grub_main_config("", "quiet").unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n");
    }

    #[test]
    fn returns_parse_error_on_malformed_existing_line() {
        let err = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=\"unterminated\n", "quiet")
            .unwrap_err();
        assert!(matches!(err, Error::Parse { .. }));
    }

    #[test]
    fn deterministic_across_runs() {
        let input = "GRUB_CMDLINE_LINUX_DEFAULT=\"old\"\nGRUB_TIMEOUT=5\n";
        let a = merge_grub_main_config(input, "quiet init_on_alloc=1").unwrap();
        let b = merge_grub_main_config(input, "quiet init_on_alloc=1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn preserves_file_without_trailing_newline() {
        let out = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=\"old\"", "quiet").unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"");
    }

    #[test]
    fn empty_double_quoted_old_value_accepts_replacement() {
        let out = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=\"\"\n", "quiet").unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n");
    }

    #[test]
    fn empty_unquoted_old_value_accepts_replacement() {
        let out = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=\n", "quiet").unwrap();
        assert_eq!(out, "GRUB_CMDLINE_LINUX_DEFAULT=quiet\n");
    }

    #[test]
    fn new_value_is_pass_through_sanitization_is_upstream() {
        let out = merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=\"old\"\n", "quiet \"evil$`")
            .unwrap();
        assert!(out.contains("quiet \"evil$`"));
    }

    #[test]
    fn newline_in_new_value_passes_through_upstream_must_reject() {
        let out =
            merge_grub_main_config("GRUB_CMDLINE_LINUX_DEFAULT=\"old\"\n", "quiet\nGRUB_EVIL=1")
                .unwrap();
        assert!(out.contains("quiet\nGRUB_EVIL=1"));
    }
}
