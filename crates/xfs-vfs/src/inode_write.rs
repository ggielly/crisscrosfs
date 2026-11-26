//! Lossless inode serialization helpers for the XFS writer.

use fs_abstraction::{FsError, FsResult};
use xfs_rs::{DataFork, Extent, Inode, InodeCore};

/// Serialize the inode core and data fork into a complete inode buffer.
///
/// Attribute-fork bytes are intentionally not synthesized here. Callers patch
/// the serialized prefix into the original inode-cluster block so xattrs and
/// other unmodeled bytes remain untouched.
pub(crate) fn serialize_inode(inode: &Inode, inode_size: usize) -> FsResult<Vec<u8>> {
    let core_size = inode.core.data_fork_offset();
    let fork_size = inode.core.data_fork_size(inode_size);
    if core_size
        .checked_add(fork_size)
        .is_none_or(|end| end > inode_size)
    {
        return Err(FsError::Corrupted);
    }

    let mut buffer = inode.core.to_bytes();
    match &inode.data_fork {
        DataFork::Device { major, minor } => {
            if fork_size < 4 {
                return Err(FsError::Corrupted);
            }
            let dev = ((major & 0xFF) << 8) | (minor & 0xFF);
            buffer.extend_from_slice(&dev.to_be_bytes());
        }
        DataFork::Local(data) => {
            if data.len() > fork_size || inode.core.size != data.len() as u64 {
                return Err(FsError::Corrupted);
            }
            buffer.extend_from_slice(data);
        }
        DataFork::Extents(extents) => {
            if extents.len() > fork_size / Extent::SIZE {
                return Err(FsError::FileTooLarge);
            }
            for extent in extents {
                buffer.extend_from_slice(&extent.to_bytes_checked()?);
            }
        }
        DataFork::Btree {
            level,
            num_recs,
            data,
        } => {
            if *level == 0 || data.len() > fork_size.saturating_sub(4) {
                return Err(FsError::Corrupted);
            }
            buffer.extend_from_slice(&level.to_be_bytes());
            buffer.extend_from_slice(&num_recs.to_be_bytes());
            buffer.extend_from_slice(data);
        }
        DataFork::Empty => {}
    }
    if buffer.len() > core_size + fork_size {
        return Err(FsError::FileTooLarge);
    }
    buffer.resize(inode_size, 0);
    if inode.core.version == 3 {
        xfs_rs::crc::recalculate_crc_le(&mut buffer, 0x64).ok_or(FsError::BufferTooSmall)?;
    }
    Ok(buffer)
}

/// Update selected timestamps to the current wall clock and bump the v3 change
/// counter. Invalid clock values fail closed instead of wrapping on disk.
pub(crate) fn touch_inode(
    core: &mut InodeCore,
    has_bigtime: bool,
    atime: bool,
    mtime: bool,
    ctime: bool,
) -> FsResult<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = i64::try_from(now.as_secs()).map_err(|_| FsError::InvalidArgument)?;
    let nsecs = now.subsec_nanos();
    if atime || mtime || ctime {
        let (sec, nsec) = InodeCore::unix_to_timestamp(secs, nsecs, has_bigtime)?;
        if atime {
            core.atime_sec = sec;
            core.atime_nsec = nsec;
        }
        if mtime {
            core.mtime_sec = sec;
            core.mtime_nsec = nsec;
        }
        if ctime {
            core.ctime_sec = sec;
            core.ctime_nsec = nsec;
        }
    }
    if core.version == 3 {
        core.changecount = core.changecount.wrapping_add(1);
    }
    Ok(())
}

/// Convert a filesystem-block count to `di_nblocks` units (512 bytes).
#[allow(dead_code)]
pub(crate) fn nblocks_from_fs_blocks(blocks: u64, block_size: u32) -> FsResult<u64> {
    if block_size < 512 || block_size % 512 != 0 {
        return Err(FsError::Corrupted);
    }
    blocks
        .checked_mul(u64::from(block_size / 512))
        .ok_or(FsError::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use xfs_rs::InodeFormat;

    use super::*;

    fn inode(has_bigtime: bool) -> Inode {
        let core = xfs_rs::inode_alloc::create_empty_inode_core_at(
            0o100644,
            0,
            0,
            3,
            123,
            &[0xA5; 16],
            has_bigtime,
            1_700_000_000,
            123_456_789,
        )
        .unwrap();
        let mut core = core;
        core.size = 3;
        Inode {
            core,
            data_fork: DataFork::Local(b"abc".to_vec()),
        }
    }

    #[test]
    fn inode_round_trip_preserves_bigtime_and_local_data() {
        for has_bigtime in [false, true] {
            let inode = inode(has_bigtime);
            let raw = serialize_inode(&inode, 512).unwrap();
            let parsed = Inode::parse(&raw, 512).unwrap();
            assert_eq!(parsed.inline_data(), Some(b"abc".as_slice()));
            assert_eq!(parsed.core.mtime(has_bigtime), (1_700_000_000, 123_456_789));
            assert!(parsed.verify_crc(&raw, 512).is_ok());
        }
    }

    #[test]
    fn extent_serialization_rejects_overflow_before_writing() {
        let mut inode = inode(false);
        inode.core.format = InodeFormat::Extents;
        inode.core.nextents = 1;
        inode.data_fork = DataFork::Extents(vec![Extent {
            file_offset: 1 << 54,
            start_block: 1,
            block_count: 1,
            is_unwritten: false,
        }]);
        assert!(matches!(
            serialize_inode(&inode, 512),
            Err(FsError::InvalidArgument)
        ));
    }

    #[test]
    fn nblocks_use_basic_block_units() {
        assert_eq!(nblocks_from_fs_blocks(3, 4096).unwrap(), 24);
        assert!(nblocks_from_fs_blocks(u64::MAX, 4096).is_err());
    }
}
