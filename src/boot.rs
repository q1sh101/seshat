mod backend;
mod cmdline;
mod deploy;
mod dropin;
mod mainconfig;
mod plan;
mod refresh;
mod restore;
mod verify;

pub use backend::{Backend, default_has_command, detect_backend};
pub use cmdline::parse_grub_cmdline_default;
pub use deploy::{deploy_grub_dropin, deploy_grub_main_config};
pub use plan::{BootPlan, PlanState, plan_boot_params};
// RefreshBackend re-exported for orchestrator deploy tests; not used by main.rs.
#[allow(unused_imports)]
pub use refresh::RefreshBackend;
pub use refresh::{RefreshStatus, refresh_grub_configuration};
pub use restore::{BootRestore, restore_boot_from_backup};
pub use verify::{BootVerify, VerifyRow, read_live_cmdline, verify_boot_params};
