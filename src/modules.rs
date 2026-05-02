mod allowlist;
mod deploy;
mod dropin;
mod list;
mod names;
mod overlay;
mod pending;
mod plan;
mod restore;
mod runtime_lock;
mod snapshot;
mod verify;

pub use allowlist::{effective_allowlist, parse_allowlist};
pub use deploy::{DeploySummary, deploy_enforcement};
pub use dropin::{generate_modprobe_dropin, payload_signature, scan_installed_modules};
pub use list::list_allowlist;
pub use overlay::{allow_module, block_module, unallow_module, unblock_module};
pub use pending::{PendingReport, check_pending_modules};
// PlanState re-exported for orchestrator plan tests; not used by main.rs.
#[allow(unused_imports)]
pub use plan::PlanState;
pub use plan::{EnforcementPlan, plan_enforcement};
pub use restore::{ModulesRestore, restore_modules_from_backup};
pub use runtime_lock::{ModulesLockOutcome, lock_modules_runtime, read_modules_lock_state};
pub use snapshot::{create_snapshot, reset_snapshot};
pub use verify::{VerifyReport, VerifyRow, verify_enforcement};
