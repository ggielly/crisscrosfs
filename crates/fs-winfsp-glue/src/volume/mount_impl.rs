//! Volume mounting logic.

use std::sync::Arc;

use tracing::{info, warn};

use super::VolumeContext;
use crate::{
    disk::{DiskReader, ImageFileReader, PhysicalDiskReader},
    error::{Result, XfsWinfspError},
};

/// Options for mounting a volume.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Mount as read-only (default: true).
    pub read_only: bool,
    /// Mount point (drive letter or path).
    pub mount_point: String,
    /// Enable case-sensitive filenames.
    pub case_sensitive: bool,
    /// Inode cache size.
    pub inode_cache_size: usize,
    /// Block cache size.
    pub block_cache_size: usize,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: true,
            mount_point: String::new(),
            case_sensitive: true,
            inode_cache_size: 256,
            block_cache_size: 1024,
        }
    }
}

impl MountOptions {
    /// Creates options with a mount point.
    pub fn with_mount_point(mount_point: &str) -> Self {
        Self {
            mount_point: mount_point.to_string(),
            ..Default::default()
        }
    }
}

/// A mounted XFS volume.
pub struct MountedVolume {
    /// Volume context with all filesystem state.
    pub context: Arc<VolumeContext>,
    /// Mount options used.
    pub options: MountOptions,
}

impl MountedVolume {
    /// Unmounts the volume, cleaning up resources.
    pub fn unmount(self) -> Result<()> {
        info!("Unmounting volume from {}", self.options.mount_point);

        // Log final statistics
        let stats = self.context.get_stats();
        info!("Final volume statistics:\n{}", stats);

        // Clear caches
        self.context.clear_caches();

        // The Arc<VolumeContext> will be dropped when all references are gone
        Ok(())
    }

    /// Gets the volume context.
    pub fn context(&self) -> &VolumeContext {
        &self.context
    }

    /// Gets the mount point.
    pub fn mount_point(&self) -> &str {
        &self.options.mount_point
    }
}

/// Mounts an XFS volume from an image file.
pub fn mount_image(image_path: &str, options: MountOptions) -> Result<MountedVolume> {
    info!("Mounting XFS image: {}", image_path);

    let reader = ImageFileReader::open(image_path)?;
    mount_from_reader(Arc::new(reader), options)
}

/// Mounts an XFS volume from a physical disk.
pub fn mount_disk(disk_number: u32, options: MountOptions) -> Result<MountedVolume> {
    info!("Mounting XFS disk: PhysicalDrive{}", disk_number);

    let reader = PhysicalDiskReader::open(disk_number)?;
    mount_from_reader(Arc::new(reader), options)
}

/// Mounts an XFS volume from a partition (drive letter).
pub fn mount_partition(drive_letter: char, options: MountOptions) -> Result<MountedVolume> {
    info!("Mounting XFS partition: {}:", drive_letter);

    let reader = PhysicalDiskReader::open_partition(drive_letter)?;
    mount_from_reader(Arc::new(reader), options)
}

/// Mounts an XFS volume from any disk reader.
pub fn mount_from_reader(
    reader: Arc<dyn DiskReader>,
    options: MountOptions,
) -> Result<MountedVolume> {
    // Read superblock
    let sb_size = xfs_rs::constants::XFS_SB_SIZE_V5;
    let sb_buffer = reader.read_unaligned(0, sb_size)?;

    // Parse superblock
    let superblock = xfs_rs::Superblock::parse(&sb_buffer)
        .map_err(|e| XfsWinfspError::InvalidFilesystem(format!("{:?}", e)))?;

    // Validate XFS magic
    if superblock.magic != xfs_rs::constants::XFS_SB_MAGIC {
        return Err(XfsWinfspError::InvalidFilesystem(
            "Invalid XFS magic number".to_string(),
        ));
    }

    // Log filesystem info
    let label = {
        let name = &superblock.name;
        let len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        String::from_utf8_lossy(&name[..len]).to_string()
    };

    info!(
        "XFS filesystem: label='{}', version={}, block_size={}, total_blocks={}",
        label, superblock.version, superblock.block_size, superblock.total_blocks,
    );

    if superblock.version < 4 {
        warn!(
            "XFS version {} is very old, some features may not work",
            superblock.version
        );
    }

    // Create volume context
    let context = Arc::new(VolumeContext::new(
        reader,
        superblock,
        options.mount_point.clone(),
    ));

    // Verify we can read the root inode
    match context.root_inode() {
        Ok(root) => {
            if !root.core.is_dir() {
                return Err(XfsWinfspError::InvalidFilesystem(
                    "Root inode is not a directory".to_string(),
                ));
            }
            info!("Root directory inode verified");
        }
        Err(e) => {
            return Err(XfsWinfspError::InvalidFilesystem(format!(
                "Cannot read root inode: {}",
                e
            )));
        }
    }

    Ok(MountedVolume { context, options })
}

/// Convenience function to mount a volume (auto-detects type).
pub fn mount_volume(source: &str, mount_point: &str) -> Result<MountedVolume> {
    let options = MountOptions::with_mount_point(mount_point);

    // Try to detect if it's a disk number, drive letter, or file path
    if let Ok(disk_num) = source.parse::<u32>() {
        // It's a disk number
        mount_disk(disk_num, options)
    } else if source.len() == 1 && source.chars().next().unwrap().is_ascii_alphabetic() {
        // It's a drive letter
        mount_partition(source.chars().next().unwrap(), options)
    } else if source.starts_with("\\\\.\\PhysicalDrive") {
        // It's a physical drive path
        let num_str = source.strip_prefix("\\\\.\\PhysicalDrive").unwrap();
        let disk_num: u32 = num_str
            .parse()
            .map_err(|_| XfsWinfspError::InvalidArgument("Invalid disk number".to_string()))?;
        mount_disk(disk_num, options)
    } else {
        // Assume it's a file path
        mount_image(source, options)
    }
}
