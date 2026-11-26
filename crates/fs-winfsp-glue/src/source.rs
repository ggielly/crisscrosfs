//! Opening a mount source as a block device.
//!
//! Shared by the command line front-end and the graphical front-end so both
//! apply exactly the same access rules.

use std::sync::Arc;

use fs_abstraction::BlockDevice;

use crate::{
    disk::{self, ImageFileReader, PhysicalDiskReader},
    error::Result,
    mount::MountSource,
};

/// Open a validated source with the requested access mode.
///
/// Writable access is intentionally limited to regular image files. Physical
/// disks and partitions always use the read-only, GPT-aware opener.
pub fn open_source(source: &MountSource, read_only: bool) -> Result<Arc<dyn BlockDevice>> {
    source.validate()?;
    match source {
        MountSource::DiskNumber(number) => disk::open_disk_with_partitions(*number),
        MountSource::ImageFile(path) if read_only => Ok(Arc::new(ImageFileReader::open(path)?)),
        MountSource::ImageFile(path) => disk::open_writable_image(path),
        MountSource::Partition(letter) => {
            Ok(Arc::new(PhysicalDiskReader::open_partition(*letter)?))
        }
        MountSource::DiskPath(path) => Ok(Arc::new(PhysicalDiskReader::open_by_path(path)?)),
    }
}

/// Stable identifier for a mount source, used to match list rows with live
/// mounts without needing `PartialEq` on `MountSource`.
pub fn source_key(source: &MountSource) -> String {
    match source {
        MountSource::DiskNumber(n) => format!("disk:{n}"),
        MountSource::Partition(letter) => format!("part:{letter}"),
        MountSource::DiskPath(path) => format!("path:{path}"),
        MountSource::ImageFile(path) => format!("img:{}", path.display()),
    }
}
