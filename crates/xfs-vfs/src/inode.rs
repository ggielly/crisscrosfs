//! Inode operations for XFS VFS.

use fs_abstraction::{FsError, FsResult, VfsFileInfo, VfsFileType, VfsTimestamp};
use xfs_rs::Inode;

/// Convert XFS inode to VFS file info.
pub fn inode_to_file_info(
    ino: u64,
    inode: &Inode,
    block_size: u32,
    has_bigtime: bool,
    filesystem_size: u64,
) -> FsResult<VfsFileInfo> {
    // XFS stores di_nblocks in 512-byte units, matching VfsFileInfo::blocks.
    // Validate the corresponding allocation size before exposing metadata.
    let allocation_size = inode
        .core
        .nblocks
        .checked_mul(512)
        .ok_or(FsError::ArithmeticOverflow)?;
    if allocation_size > filesystem_size {
        return Err(FsError::Corrupted);
    }

    let file_type = VfsFileType::from_mode(inode.core.mode as u32);

    let (atime_sec, atime_nsec) = inode.core.atime(has_bigtime);
    let (mtime_sec, mtime_nsec) = inode.core.mtime(has_bigtime);
    let (ctime_sec, ctime_nsec) = inode.core.ctime(has_bigtime);

    Ok(VfsFileInfo {
        ino,
        size: inode.core.size,
        blocks: inode.core.nblocks,
        block_size,
        mode: inode.core.mode as u32,
        file_type,
        nlink: inode.core.nlink,
        uid: inode.core.uid,
        gid: inode.core.gid,
        rdev: 0, // XFS stores this differently
        atime: VfsTimestamp::new(atime_sec, atime_nsec),
        mtime: VfsTimestamp::new(mtime_sec, mtime_nsec),
        ctime: VfsTimestamp::new(ctime_sec, ctime_nsec),
        crtime: if inode.core.version >= 3 {
            let (cr_sec, cr_nsec) = inode.core.crtime(has_bigtime);
            Some(VfsTimestamp::new(cr_sec, cr_nsec))
        } else {
            None
        },
    })
}

/// Check if inode is a directory.
pub fn is_directory(inode: &Inode) -> bool {
    (inode.core.mode & 0o170000) == 0o040000
}

/// Check if inode is a symlink.
pub fn is_symlink(inode: &Inode) -> bool {
    (inode.core.mode & 0o170000) == 0o120000
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inode_with_blocks(nblocks: u64) -> Inode {
        let mut raw = vec![0u8; 256];
        raw[0..2].copy_from_slice(&0x494Eu16.to_be_bytes());
        raw[2..4].copy_from_slice(&0o100644u16.to_be_bytes());
        raw[4] = 2; // v2 inode
        raw[5] = 1; // local data fork
        raw[0x40..0x48].copy_from_slice(&nblocks.to_be_bytes());
        Inode::parse(&raw, raw.len()).unwrap()
    }

    #[test]
    fn file_info_allocation_size_is_checked() {
        assert!(matches!(
            inode_to_file_info(1, &inode_with_blocks(u64::MAX), 4096, false, 4096),
            Err(FsError::ArithmeticOverflow)
        ));
        assert!(matches!(
            inode_to_file_info(1, &inode_with_blocks(9), 4096, false, 4096),
            Err(FsError::Corrupted)
        ));

        let info = inode_to_file_info(1, &inode_with_blocks(8), 4096, false, 4096).unwrap();
        assert_eq!(info.blocks, 8);
    }
}
