pub const OPERATION_LOCK_NAME: &str = "operation";

mod deploy;
mod lock;
mod plan;
mod rollback;
mod status;
mod verify;

pub use deploy::{
    BOOT_DEPLOY_REFUSED, BootDeployStatus, DeployInputs, DeployReport, classify_deploy_error,
    orchestrate_deploy,
};
pub use lock::{LockInputs, LockReport, classify_lock_error, orchestrate_lock};
pub use plan::{PlanInputs, PlanReport, orchestrate_plan};
pub use rollback::{
    BOOT_ROLLBACK_REFUSED, RollbackDomain, RollbackInputs, RollbackOutcome, RollbackReport,
    classify_rollback_error, orchestrate_rollback,
};
pub use status::{
    BootStatus, DriftState, LockStatus, ModulesStatus, StatusInputs, StatusReport, SysctlStatus,
    fingerprint, orchestrate_status,
};
pub use verify::{LockdownRow, VerifyInputs, VerifyReport, orchestrate_verify};

#[cfg(test)]
mod cross_domain_lock_tests {
    use super::*;
    use crate::error::Error;
    use crate::lock;
    use crate::policy::{
        BootEntry, LockdownSection, ModulesSection, Profile, SysctlEntry, SysctlKey,
    };
    use crate::sysctl::{LiveRead, ReloadStatus};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    struct Env {
        _root: tempfile::TempDir,
        modules_dir: PathBuf,
        snapshot_path: PathBuf,
        allow_path: PathBuf,
        block_path: PathBuf,
        sysctl_target: PathBuf,
        sysctl_backup_dir: PathBuf,
        modprobe_target: PathBuf,
        modprobe_backup_dir: PathBuf,
        lock_root: PathBuf,
    }

    fn env() -> Env {
        let root = tempdir().unwrap();
        let modules_dir = root.path().join("lib_modules");
        let snapshot_path = root.path().join("snapshot.conf");
        let allow_path = root.path().join("allow.conf");
        let block_path = root.path().join("block.conf");
        let sysctl_target = root.path().join("sysctl.d/99-test.conf");
        let sysctl_backup_dir = root.path().join("backups/sysctl");
        let modprobe_target = root.path().join("modprobe.d/99-test.conf");
        let modprobe_backup_dir = root.path().join("backups/modules");
        let lock_root = root.path().join("locks");
        fs::create_dir_all(&modules_dir).unwrap();
        fs::create_dir_all(sysctl_target.parent().unwrap()).unwrap();
        fs::create_dir_all(&sysctl_backup_dir).unwrap();
        fs::create_dir_all(modprobe_target.parent().unwrap()).unwrap();
        fs::create_dir_all(&modprobe_backup_dir).unwrap();
        fs::create_dir_all(&lock_root).unwrap();
        fs::set_permissions(&lock_root, fs::Permissions::from_mode(0o700)).unwrap();
        Env {
            _root: root,
            modules_dir,
            snapshot_path,
            allow_path,
            block_path,
            sysctl_target,
            sysctl_backup_dir,
            modprobe_target,
            modprobe_backup_dir,
            lock_root,
        }
    }

    fn profile() -> Profile {
        Profile {
            schema_version: 1,
            profile_name: "test".to_string(),
            modules: ModulesSection::default(),
            sysctl: vec![SysctlEntry {
                key: "kernel.kptr_restrict".to_string(),
                value: "2".to_string(),
            }],
            boot: Vec::<BootEntry>::new(),
            lockdown: LockdownSection::default(),
        }
    }

    fn deploy_inputs<'a>(env: &'a Env, profile: &'a Profile) -> DeployInputs<'a> {
        DeployInputs {
            profile,
            modules_dir: &env.modules_dir,
            snapshot_path: &env.snapshot_path,
            allow_path: &env.allow_path,
            block_path: &env.block_path,
            sysctl_target: &env.sysctl_target,
            sysctl_backup_dir: &env.sysctl_backup_dir,
            modprobe_target: &env.modprobe_target,
            modprobe_backup_dir: &env.modprobe_backup_dir,
            lock_root: &env.lock_root,
        }
    }

    fn rollback_inputs(lock_root: &Path) -> RollbackInputs<'_> {
        RollbackInputs {
            domain: RollbackDomain::Sysctl,
            yes: true,
            interactive: false,
            lock_root,
        }
    }

    fn ok_outcome() -> Result<RollbackOutcome, Error> {
        Ok(RollbackOutcome {
            restored_from: Some(PathBuf::from("/backups/sysctl/latest")),
        })
    }

    fn noop_reader() -> impl FnMut(&SysctlKey) -> LiveRead + use<> {
        |_| LiveRead::Value("2".to_string())
    }

    #[test]
    fn held_operation_lock_from_rollback_blocks_deploy() {
        let env = env();
        let prof = profile();
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let result = orchestrate_deploy(
            &deploy_inputs(&env, &prof),
            || ReloadStatus::Applied,
            noop_reader(),
        );
        assert!(matches!(result, Err(Error::Lock { .. })));
        assert!(!env.sysctl_target.exists());
        assert!(!env.modprobe_target.exists());
    }

    #[test]
    fn held_operation_lock_from_deploy_blocks_rollback() {
        let env = env();
        let _holder = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let result = orchestrate_rollback(
            &rollback_inputs(&env.lock_root),
            || true,
            ok_outcome,
            ok_outcome,
        );
        assert!(matches!(result, Err(Error::Lock { .. })));
    }

    #[test]
    fn deploy_and_rollback_use_the_same_lock_file_name() {
        let env = env();
        let _a = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME).unwrap();
        let b = lock::acquire(&env.lock_root, OPERATION_LOCK_NAME);
        assert!(matches!(b, Err(Error::Lock { .. })));
    }
}
