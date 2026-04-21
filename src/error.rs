use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("parse error in {what}: {reason}")]
    Parse { what: String, reason: String },

    #[error("validation failed for {field}: {reason}")]
    Validation { field: String, reason: String },

    #[error("preflight refused for {}: {reason}", path.display())]
    PreflightRefused { path: PathBuf, reason: String },

    #[error("unsafe path {}: {reason}", path.display())]
    UnsafePath { path: PathBuf, reason: String },

    #[error("lock error on {}: {reason}", path.display())]
    Lock { path: PathBuf, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn io_variant_is_constructible_via_from() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "missing");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn io_variant_display_is_transparent() {
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "denied");
        let err: Error = io_err.into();
        assert_eq!(err.to_string(), "denied");
    }
}
