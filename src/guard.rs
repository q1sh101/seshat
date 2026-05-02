//! Boot-time module auto-lock orchestration via a oneshot systemd service.

mod install;
mod remove;
mod status;
mod units;

pub use install::{GuardInputs, install_guard};
pub use remove::remove_guard;
pub use status::query_guard_status;
