//! XFS Filesystem for Windows via WinFsp
//!
//! This crate provides a user-mode filesystem driver for XFS on Windows
//! using WinFsp as the kernel-mode component.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Windows Explorer / Apps                      │
//! └─────────────────────────────────────────────────────────────────┘
//!                                │
//!                                │ Win32 API (CreateFile, ReadFile...)
//!                                ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     Windows I/O Manager                          │
//! └─────────────────────────────────────────────────────────────────┘
//!                                │
//!                                │ IRP
//!                                ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     WinFsp.sys (signed by MS)                    │
//! └─────────────────────────────────────────────────────────────────┘
//!                                │
//!                                │ WinFsp protocol
//!                                ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     xfs-winfsp (THIS CRATE)                      │
//! │  ┌────────────────┐  ┌────────────────┐  ┌────────────────────┐ │
//! │  │ WinFsp Ops     │  │ xfs-rs parser  │  │ Disk I/O           │ │
//! │  │ (callbacks)    │◄─│ (existing code)│◄─│ (raw sector read)  │ │
//! │  └────────────────┘  └────────────────┘  └────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//!                                │
//!                                │ DeviceIoControl / ReadFile
//!                                ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     \\.\PhysicalDriveN                           │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Usage
//!
//! ```bash
//! # Mount a physical disk with XFS (read-only)
//! xfs-mount mount --disk 1 --mount-point X:
//!
//! # Mount an XFS image file (read-only)
//! xfs-mount mount --image /path/to/xfs.img --mount-point X:
//!
//! # Install/start the Windows service (auto-detect XFS disks)
//! xfs-mount service install
//! xfs-mount service start
//! ```

pub mod allocator;
pub mod cache;
pub mod colored_log;
pub mod context;
pub mod disk;
pub mod error;
pub mod factory;
pub mod file_context;
pub mod log_colorizer;
pub mod mount;
pub mod path;
pub mod security;
pub mod service;
pub mod transactional;
pub mod volume;
pub mod winfsp_mount;

pub use error::{Result, XfsWinfspError};
pub use file_context::FileContext;
pub use mount::MountOptions;
pub use path::{PathComponents, WidePathComponents};
pub use transactional::TransactionalWriter;
pub use volume::{MountedVolume, VolumeContext, VolumeStats};
