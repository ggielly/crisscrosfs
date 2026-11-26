//! CrissCrossFS - XFS filesystem for Windows via WinFsp
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
//! │                     crisscrossfs-winfsp (THIS CRATE)                      │
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
//! crisscrossfs mount --disk 1 --mount-point X:
//!
//! # Mount an XFS image file (read-only)
//! crisscrossfs mount --image /path/to/xfs.img --mount-point X:
//!
//! # Install/start the Windows service (auto-detect XFS disks)
//! crisscrossfs service install
//! crisscrossfs service start
//! ```

pub mod colored_log;
pub mod context;
pub mod disk;
pub mod error;
pub mod factory;
#[cfg(windows)]
pub mod gui;
pub mod log_colorizer;
pub mod mount;
pub mod path;
pub mod security;
pub mod service;
pub mod source;
pub mod winfsp_mount;

pub use error::{Result, XfsWinfspError};
pub use mount::MountOptions;
pub use path::{PathComponents, WidePathComponents};
