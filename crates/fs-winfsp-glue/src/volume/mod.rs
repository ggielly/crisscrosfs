//! Volume management for XFS filesystems.
//!
//! This module handles mounting, unmounting, and managing XFS volumes.

mod mount_impl;
mod stats;
mod volume_context;

pub use mount_impl::{mount_volume, MountOptions, MountedVolume};
pub use stats::VolumeStats;
pub use volume_context::VolumeContext;
