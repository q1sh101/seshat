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

impl Error {
    pub fn exit_code(&self, default: i32) -> i32 {
        match self {
            Error::UnsafePath { .. } | Error::PreflightRefused { .. } | Error::Lock { .. } => 3,
            _ => default,
        }
    }
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

    #[test]
    fn exit_code_maps_security_errors_to_three() {
        assert_eq!(
            Error::UnsafePath {
                path: PathBuf::from("/x"),
                reason: String::new(),
            }
            .exit_code(1),
            3
        );
        assert_eq!(
            Error::PreflightRefused {
                path: PathBuf::from("/x"),
                reason: String::new(),
            }
            .exit_code(1),
            3
        );
        assert_eq!(
            Error::Lock {
                path: PathBuf::from("/x"),
                reason: String::new(),
            }
            .exit_code(1),
            3
        );
        assert_eq!(
            Error::Validation {
                field: "x".into(),
                reason: String::new(),
            }
            .exit_code(7),
            7
        );
    }
}
