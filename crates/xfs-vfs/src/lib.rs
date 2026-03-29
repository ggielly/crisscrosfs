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
//! // Create XFS VFS instance
//! // let xfs = XfsVfs::new(device)?;
//!
//! // Use through VFS trait
//! // let root = xfs.root_inode();
//! // let entries = xfs.readdir(root)?;
//! ```

mod allocator;
mod cache;
mod directory;
mod error;
mod filesystem;
mod inode;
mod journal;
mod read_ops;
mod write_ops;

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
