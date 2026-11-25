//! XFS VFS Implementation
//!
//! This crate provides an implementation of the VFS traits for the XFS
//! filesystem.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────┐
//! │          fs-winfsp-glue             │
//! │     (uses dyn VfsFileSystem)        │
//! └─────────────────────────────────────┘
//!                  │
//!                  ▼
//! ┌─────────────────────────────────────┐
//! │            xfs-vfs                  │  ◄── This crate
//! │   impl VfsFileSystem for XfsVfs     │
//! └─────────────────────────────────────┘
//!                  │
//!                  ▼
//! ┌─────────────────────────────────────┐
//! │             xfs-rs                  │
//! │      (low-level XFS parsing)        │
//! └─────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,no_run
//! use std::sync::Arc;
//!
//! use fs_abstraction::{BlockDevice, VfsFileSystem};
//! use xfs_vfs::XfsVfs;
//!
//! // Create a block device (disk, file, etc.)
//! // let device: Arc<dyn BlockDevice> = ...;
//!
//! // Create a structurally read-only XFS VFS instance
//! // let xfs = XfsVfs::read_only(device)?;
//!
//! // Use through VFS trait
//! // let root = xfs.root_inode();
//! // let entries = xfs.readdir(root)?;
//! ```

mod cache;
mod directory;
mod error;
mod filesystem;
mod inode;
mod io;
mod read_ops;

// allocator, journal and write_ops are intentionally not compiled.  The VFS is
// structurally read-only and must not contain an accidental write path.

pub use error::XfsVfsError;
pub use filesystem::XfsVfs;
// Re-export VFS types for convenience
pub use fs_abstraction::{
    BlockDevice,
    FsCapabilities,
    FsError,
    FsResult,
    VfsDirEntry,
    VfsFileInfo,
    VfsFileSystem,
    VfsFileType,
    VfsTimestamp,
    VfsVolumeInfo,
};

/// XFS filesystem magic number
pub const XFS_MAGIC: &[u8; 4] = b"XFSB";

/// Check if a buffer starts with XFS magic number
pub fn is_xfs_filesystem(buffer: &[u8]) -> bool {
    buffer.len() >= 4 && &buffer[0..4] == XFS_MAGIC
}
