use std::path::{Path, PathBuf};

use crate::runtime::SANITIZED_PATH;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Backend {
    Grub,
    SystemdBoot,
    Unknown,
}

pub fn detect_backend<F>(
    grub_config: &Path,
    grub_config_d: &Path,
    grub_cfg: &Path,
    kernel_cmdline: &Path,
    has_command: F,
) -> Backend
where
    F: Fn(&str) -> bool,
{
    let grub_marker_present = grub_config.exists() || grub_config_d.exists() || grub_cfg.exists();
    let grub_tool_present = has_command("update-grub") || has_command("grub-mkconfig");
    if grub_marker_present && grub_tool_present {
        return Backend::Grub;
    }
    if kernel_cmdline.exists() {
        return Backend::SystemdBoot;
    }
    Backend::Unknown
}

// Match POSIX test -x: any of owner/group/other.
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && meta.permissions().mode() & 0o111 != 0,
        Err(_) => false,
    }
}

fn check_command_in_paths<I>(name: &str, dirs: I) -> bool
where
    I: IntoIterator<Item = PathBuf>,
{
    for dir in dirs {
        if is_executable(&dir.join(name)) {
            return true;
        }
    }
    false
}

fn has_command_in_path_string(name: &str, path_str: &str) -> bool {
    check_command_in_paths(name, std::env::split_paths(path_str))
}

// Detect via SANITIZED_PATH so caller $PATH cannot shadow grub tools.
pub fn default_has_command(name: &str) -> bool {
    has_command_in_path_string(name, SANITIZED_PATH)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    struct Layout {
        grub_config: PathBuf,
        grub_config_d: PathBuf,
        grub_cfg: PathBuf,
        kernel_cmdline: PathBuf,
    }

    fn layout(root: &Path) -> Layout {
        Layout {
            grub_config: root.join("etc/default/grub"),
            grub_config_d: root.join("etc/default/grub.d"),
            grub_cfg: root.join("boot/grub/grub.cfg"),
            kernel_cmdline: root.join("etc/kernel/cmdline"),
        }
    }

    fn detect(l: &Layout, has: impl Fn(&str) -> bool) -> Backend {
        detect_backend(
            &l.grub_config,
            &l.grub_config_d,
            &l.grub_cfg,
            &l.kernel_cmdline,
            has,
        )
    }

    fn no_command(_: &str) -> bool {
        false
    }

    fn only(target: &'static str) -> impl Fn(&str) -> bool {
        move |cmd| cmd == target
    }

    fn make_executable(path: &Path) {
        let mut p = fs::metadata(path).unwrap().permissions();
        p.set_mode(0o755);
        fs::set_permissions(path, p).unwrap();
    }

    #[test]
    fn grub_detected_when_grub_config_and_update_grub_present() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        fs::create_dir_all(l.grub_config.parent().unwrap()).unwrap();
        fs::write(&l.grub_config, "GRUB_CMDLINE_LINUX=\"\"\n").unwrap();
        assert_eq!(detect(&l, only("update-grub")), Backend::Grub);
    }

    #[test]
    fn grub_detected_via_grub_config_d_and_grub_mkconfig() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        fs::create_dir_all(&l.grub_config_d).unwrap();
        assert_eq!(detect(&l, only("grub-mkconfig")), Backend::Grub);
    }

    #[test]
    fn grub_detected_via_grub_cfg_and_update_grub() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        fs::create_dir_all(l.grub_cfg.parent().unwrap()).unwrap();
        fs::write(&l.grub_cfg, "set default=0\n").unwrap();
        assert_eq!(detect(&l, only("update-grub")), Backend::Grub);
    }

    #[test]
    fn grub_not_detected_when_file_exists_but_command_missing() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        fs::create_dir_all(l.grub_config.parent().unwrap()).unwrap();
        fs::write(&l.grub_config, "\n").unwrap();
        assert_eq!(detect(&l, no_command), Backend::Unknown);
    }

    #[test]
    fn grub_not_detected_when_command_exists_but_no_file() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        assert_eq!(detect(&l, only("update-grub")), Backend::Unknown);
    }

    #[test]
    fn systemd_boot_detected_when_kernel_cmdline_exists() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        fs::create_dir_all(l.kernel_cmdline.parent().unwrap()).unwrap();
        fs::write(&l.kernel_cmdline, "rw quiet\n").unwrap();
        assert_eq!(detect(&l, no_command), Backend::SystemdBoot);
    }

    #[test]
    fn unknown_when_no_markers_exist() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        assert_eq!(detect(&l, no_command), Backend::Unknown);
    }

    #[test]
    fn grub_wins_over_systemd_boot_when_both_markers_present() {
        let dir = tempdir().unwrap();
        let l = layout(dir.path());
        fs::create_dir_all(l.grub_config.parent().unwrap()).unwrap();
        fs::write(&l.grub_config, "\n").unwrap();
        fs::create_dir_all(l.kernel_cmdline.parent().unwrap()).unwrap();
        fs::write(&l.kernel_cmdline, "rw\n").unwrap();
        assert_eq!(detect(&l, only("update-grub")), Backend::Grub);
    }

    #[test]
    fn check_command_finds_executable_in_provided_dir() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("my-fake-tool");
        fs::write(&bin, "#!/bin/sh\n").unwrap();
        make_executable(&bin);
        assert!(check_command_in_paths(
            "my-fake-tool",
            std::iter::once(dir.path().to_path_buf())
        ));
    }

    #[test]
    fn check_command_rejects_non_executable_file() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("not-exec");
        fs::write(&bin, "text\n").unwrap();
        let mut p = fs::metadata(&bin).unwrap().permissions();
        p.set_mode(0o644);
        fs::set_permissions(&bin, p).unwrap();
        assert!(!check_command_in_paths(
            "not-exec",
            std::iter::once(dir.path().to_path_buf())
        ));
    }

    #[test]
    fn check_command_rejects_missing_binary() {
        let dir = tempdir().unwrap();
        assert!(!check_command_in_paths(
            "nothing-here",
            std::iter::once(dir.path().to_path_buf())
        ));
    }

    #[test]
    fn check_command_rejects_directory_with_matching_name() {
        let dir = tempdir().unwrap();
        let as_dir = dir.path().join("looks-like-bin");
        fs::create_dir(&as_dir).unwrap();
        make_executable(&as_dir);
        assert!(!check_command_in_paths(
            "looks-like-bin",
            std::iter::once(dir.path().to_path_buf())
        ));
    }

    #[test]
    fn default_has_command_returns_false_for_nonexistent_binary() {
        assert!(!default_has_command("definitely-not-a-real-binary-xyz-987"));
    }

    #[test]
    fn has_command_in_path_string_finds_executable_in_single_dir() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("my-tool");
        fs::write(&bin, "").unwrap();
        make_executable(&bin);
        let path_str = dir.path().to_str().unwrap();
        assert!(has_command_in_path_string("my-tool", path_str));
    }

    #[test]
    fn has_command_in_path_string_walks_multiple_colon_separated_dirs() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let bin = dir2.path().join("later-in-path");
        fs::write(&bin, "").unwrap();
        make_executable(&bin);
        let path_str = format!("{}:{}", dir1.path().display(), dir2.path().display());
        assert!(has_command_in_path_string("later-in-path", &path_str));
    }

    #[test]
    fn has_command_in_path_string_returns_false_when_no_dir_contains_binary() {
        let dir1 = tempdir().unwrap();
        let dir2 = tempdir().unwrap();
        let path_str = format!("{}:{}", dir1.path().display(), dir2.path().display());
        assert!(!has_command_in_path_string("nothing-here", &path_str));
    }
}
