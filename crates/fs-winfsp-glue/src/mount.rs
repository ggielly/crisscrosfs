//! Mount options and configuration.

use std::path::PathBuf;

/// Options for mounting an XFS filesystem.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Source: either a disk number, partition, or image file path.
    pub source: MountSource,
    /// Mount point (drive letter like "X:" or path).
    pub mount_point: String,
    /// Read-only mode (always true for now).
    pub read_only: bool,
    /// Debug mode.
    pub debug: bool,
    /// Volume prefix for WinFsp.
    pub volume_prefix: Option<String>,
    /// File system name shown in Explorer.
    pub filesystem_name: String,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            source: MountSource::DiskNumber(0),
            mount_point: "X:".to_string(),
            read_only: true,
            debug: false,
            volume_prefix: None,
            filesystem_name: "XFS".to_string(),
        }
    }
}

/// Source for mounting.
#[derive(Debug, Clone)]
pub enum MountSource {
    /// Physical disk number (0, 1, 2...).
    DiskNumber(u32),
    /// Drive letter for a partition.
    Partition(char),
    /// Path to disk device.
    DiskPath(String),
    /// Path to image file.
    ImageFile(PathBuf),
}

impl MountOptions {
    /// Create mount options for a physical disk.
    pub fn disk(disk_number: u32, mount_point: &str) -> Self {
        Self {
            source: MountSource::DiskNumber(disk_number),
            mount_point: mount_point.to_string(),
            ..Default::default()
        }
    }

    /// Create mount options for an image file.
    pub fn image<P: Into<PathBuf>>(path: P, mount_point: &str) -> Self {
        Self {
            source: MountSource::ImageFile(path.into()),
            mount_point: mount_point.to_string(),
            ..Default::default()
        }
    }

    /// Create mount options for a partition.
    pub fn partition(drive_letter: char, mount_point: &str) -> Self {
        Self {
            source: MountSource::Partition(drive_letter),
            mount_point: mount_point.to_string(),
            ..Default::default()
        }
    }
}
