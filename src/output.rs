use std::io::{self, IsTerminal, Write};
use std::sync::OnceLock;

use crate::result::CheckState;

const RESET: &str = "\x1b[0m";
const BLUE: &str = "\x1b[1;34m";
const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const RED: &str = "\x1b[1;31m";
const DIM: &str = "\x1b[1;37m";

pub struct Stylesheet {
    pub color: bool,
}

impl Stylesheet {
    pub fn detect() -> Self {
        Self {
            color: io::stdout().is_terminal() || std::env::var_os("JOURNAL_STREAM").is_some(),
        }
    }
}

fn stylesheet() -> &'static Stylesheet {
    static STYLESHEET: OnceLock<Stylesheet> = OnceLock::new();
    STYLESHEET.get_or_init(Stylesheet::detect)
}

pub fn log(msg: &str) {
    let _ = write_line(&mut io::stdout(), stylesheet(), BLUE, "[seshat] ", msg);
}

pub fn ok(msg: &str) {
    let _ = write_line(&mut io::stdout(), stylesheet(), GREEN, "[  ok] ", msg);
}

pub fn warn(msg: &str) {
    let _ = write_line(&mut io::stderr(), stylesheet(), YELLOW, "[warn] ", msg);
}

pub fn fail(msg: &str) {
    let _ = write_line(&mut io::stderr(), stylesheet(), RED, "[fail] ", msg);
}

pub fn skip(msg: &str) {
    let _ = write_line(&mut io::stdout(), stylesheet(), DIM, "[skip] ", msg);
}

pub fn state(cs: CheckState, msg: &str) {
    match cs {
        CheckState::Ok => ok(msg),
        CheckState::Warn => warn(msg),
        CheckState::Fail => fail(msg),
        CheckState::Skip => skip(msg),
    }
}

fn write_line<W: Write>(
    w: &mut W,
    style: &Stylesheet,
    ansi: &str,
    label: &str,
    msg: &str,
) -> io::Result<()> {
    if style.color {
        writeln!(w, "  {ansi}{label}{RESET}{msg}")
    } else {
        writeln!(w, "  {label}{msg}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(style: &Stylesheet, ansi: &str, label: &str, msg: &str) -> String {
        let mut buf: Vec<u8> = Vec::new();
        write_line(&mut buf, style, ansi, label, msg).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn plain_mode_emits_bracket_and_message_without_escapes() {
        let plain = Stylesheet { color: false };
        assert_eq!(
            render(&plain, GREEN, "[  ok] ", "ready"),
            "  [  ok] ready\n"
        );
    }

    #[test]
    fn color_mode_wraps_label_with_ansi_and_resets_before_message() {
        let color = Stylesheet { color: true };
        assert_eq!(
            render(&color, YELLOW, "[warn] ", "drift"),
            "  \x1b[1;33m[warn] \x1b[0mdrift\n"
        );
    }

    #[test]
    fn state_labels_share_a_four_char_token_width() {
        for label in ["[  ok] ", "[warn] ", "[fail] ", "[skip] "] {
            let open = label.find('[').unwrap();
            let close = label.find(']').unwrap();
            assert_eq!(
                close - open - 1,
                4,
                "label {label:?} must hold a 4-char token"
            );
        }
    }

    #[test]
    fn state_dispatches_to_the_matching_label() {
        for cs in [
            CheckState::Ok,
            CheckState::Warn,
            CheckState::Fail,
            CheckState::Skip,
        ] {
            state(cs, "");
        }
    }
}
