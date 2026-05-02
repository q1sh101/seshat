//! Drift detector install / remove / status orchestration over systemd units.

mod install;
mod remove;
mod status;
mod units;

pub use install::{WatchInputs, install_watch};
pub use remove::remove_watch;
pub use status::query_watch_status;
