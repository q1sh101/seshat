pub(super) fn strip_module_suffix(base: &str) -> Option<&str> {
    let stripped = base
        .strip_suffix(".ko.zst")
        .or_else(|| base.strip_suffix(".ko.xz"))
        .or_else(|| base.strip_suffix(".ko.gz"))
        .or_else(|| base.strip_suffix(".ko"))?;
    if stripped.is_empty() {
        None
    } else {
        Some(stripped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_module_suffix_recognises_every_compression() {
        assert_eq!(strip_module_suffix("ext4.ko"), Some("ext4"));
        assert_eq!(strip_module_suffix("ext4.ko.gz"), Some("ext4"));
        assert_eq!(strip_module_suffix("ext4.ko.xz"), Some("ext4"));
        assert_eq!(strip_module_suffix("ext4.ko.zst"), Some("ext4"));
        assert_eq!(strip_module_suffix("README"), None);
        assert_eq!(strip_module_suffix(".ko"), None);
    }
}
