//! Inode operations for XFS VFS.

use fs_abstraction::{VfsFileInfo, VfsFileType, VfsTimestamp};
use xfs_rs::Inode;

/// Convert XFS inode to VFS file info.
pub fn inode_to_file_info(
    ino: u64,
    inode: &Inode,
    block_size: u32,
    has_bigtime: bool,
) -> VfsFileInfo {
    let file_type = VfsFileType::from_mode(inode.core.mode as u32);

    let (atime_sec, atime_nsec) = inode.core.atime(has_bigtime);
    let (mtime_sec, mtime_nsec) = inode.core.mtime(has_bigtime);
    let (ctime_sec, ctime_nsec) = inode.core.ctime(has_bigtime);

    VfsFileInfo {
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
    }
}

/// Check if inode is a directory.
pub fn is_directory(inode: &Inode) -> bool {
    (inode.core.mode & 0o170000) == 0o040000
}

/// Check if inode is a regular file.
pub fn is_regular_file(inode: &Inode) -> bool {
    (inode.core.mode & 0o170000) == 0o100000
}

/// Check if inode is a symlink.
pub fn is_symlink(inode: &Inode) -> bool {
    (inode.core.mode & 0o170000) == 0o120000
}

/// Get file type from inode mode.
pub fn get_file_type(mode: u16) -> VfsFileType {
    VfsFileType::from_mode(mode as u32)
}
