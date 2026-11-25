//! XFS-specific error types.

use std::fmt;

use fs_abstraction::FsError;

/// XFS VFS error type.
#[derive(Debug)]
pub enum XfsVfsError {
    /// Underlying VFS error
    Vfs(FsError),
    /// XFS parsing error
    Xfs(String),
    /// I/O error
    Io(std::io::Error),
    /// Internal error
    Internal(String),
}

impl fmt::Display for XfsVfsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XfsVfsError::Vfs(e) => write!(f, "VFS error: {}", e),
            XfsVfsError::Xfs(s) => write!(f, "XFS error: {}", s),
            XfsVfsError::Io(e) => write!(f, "I/O error: {}", e),
            XfsVfsError::Internal(s) => write!(f, "Internal error: {}", s),
        }
    }
}

impl std::error::Error for XfsVfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            XfsVfsError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<FsError> for XfsVfsError {
    fn from(e: FsError) -> Self {
        XfsVfsError::Vfs(e)
    }
}

impl From<std::io::Error> for XfsVfsError {
    fn from(e: std::io::Error) -> Self {
        XfsVfsError::Io(e)
    }
}

impl From<XfsVfsError> for FsError {
    fn from(e: XfsVfsError) -> Self {
        match e {
            XfsVfsError::Vfs(fe) => fe,
            XfsVfsError::Xfs(_) => FsError::Corrupted,
            XfsVfsError::Io(_) => FsError::DiskError,
            XfsVfsError::Internal(_) => FsError::Corrupted,
        }
    }
}
