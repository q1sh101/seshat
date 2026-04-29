mod backend;
mod cmdline;

pub use backend::{Backend, default_has_command, detect_backend};
pub use cmdline::{GrubDefaultLine, QuoteStyle, parse_grub_cmdline_default};
