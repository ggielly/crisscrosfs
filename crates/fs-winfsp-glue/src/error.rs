//! Error types for xfs-winfsp.

use thiserror::Error;

/// Result type alias for xfs-winfsp operations.
pub type Result<T> = std::result::Result<T, XfsWinfspError>;

/// Errors that can occur in xfs-winfsp.
#[derive(Error, Debug)]
pub enum XfsWinfspError {
    /// Failed to open disk or image file.
    #[error("Failed to open disk: {0}")]
    DiskOpenError(String),

    /// Invalid XFS superblock.
    #[error("Invalid XFS filesystem: {0}")]
    InvalidFilesystem(String),

    /// I/O error reading from disk.
    #[error("Disk I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// XFS parsing error.
    #[error("XFS parse error: {0}")]
    XfsError(String),

    /// WinFsp error.
    #[error("WinFsp error: {0}")]
    WinFspError(String),

    /// Mount point already in use.
    #[error("Mount point {0} is already in use")]
    MountPointInUse(String),

    /// Permission denied.
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// File or directory not found.
    #[error("Not found: {0}")]
    NotFound(String),

    /// Invalid argument.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Disk read/write error.
    #[error("Disk error: {0}")]
    DiskError(String),

    /// Windows API error.
    #[error("Windows error: {0}")]
    WindowsError(#[from] windows::core::Error),

    /// Feature not yet implemented.
    #[error("Not implemented: {0}")]
    NotImplemented(String),

    /// Read-only filesystem.
    #[error("Read-only filesystem")]
    ReadOnly,
}

impl From<fs_abstraction::FsError> for XfsWinfspError {
    fn from(err: fs_abstraction::FsError) -> Self {
        XfsWinfspError::XfsError(format!("{:?}", err))
    }
}
