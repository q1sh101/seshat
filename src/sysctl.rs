mod deploy;
mod dropin;
mod plan;
mod restore;
mod setting;
mod verify;

pub use deploy::{DeploySummary, ReloadStatus, deploy_sysctl, reload_sysctl};
pub use dropin::generate_sysctl_dropin;
// PlanState re-exported for orchestrator plan tests; not used by main.rs.
#[allow(unused_imports)]
pub use plan::PlanState;
pub use plan::{LiveRead, SysctlPlan, plan_sysctl, read_live_sysctl};
pub use restore::restore_sysctl_from_backup;
pub use setting::SysctlSetting;
pub use verify::{SysctlVerify, VerifyRow, verify_sysctl};
