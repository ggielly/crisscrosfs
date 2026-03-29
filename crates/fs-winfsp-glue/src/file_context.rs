//! File context for open file handles.
//!
//! Each open file/directory has an associated context that tracks
//! its state, position, and cached metadata.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use xfs_rs::Inode;

/// Context for an open file or directory handle.
pub struct FileContext {
    /// Inode number.
    pub inode_number: u64,
    /// Cached inode data.
    pub inode: Inode,
    /// Current file position (for reads).
    position: AtomicU64,
    /// Reference count for this handle.
    ref_count: AtomicU32,
    /// File access flags.
    pub flags: FileFlags,
    /// Is this a directory?
    pub is_directory: bool,
    /// Directory enumeration state.
    pub enum_state: Option<DirectoryEnumState>,
}

/// File access flags.
#[derive(Debug, Clone, Copy)]
pub struct FileFlags {
    /// Opened for reading.
    pub read: bool,
    /// Opened for writing (always false for XFS - read-only).
    pub write: bool,
    /// Opened for append.
    pub append: bool,
    /// Delete on close.
    pub delete_on_close: bool,
}

impl Default for FileFlags {
    fn default() -> Self {
        Self {
            read: true,
            write: false,
            append: false,
            delete_on_close: false,
        }
    }
}

impl FileFlags {
    /// Create flags for read-only access.
    pub fn read_only() -> Self {
        Self {
            read: true,
            write: false,
            append: false,
            delete_on_close: false,
        }
    }

    /// Parse flags from Windows desired access.
    pub fn from_desired_access(desired_access: u32) -> Self {
        const GENERIC_READ: u32 = 0x80000000;
        // const GENERIC_WRITE: u32 = 0x40000000;
        const FILE_APPEND_DATA: u32 = 0x0004;
        const DELETE: u32 = 0x00010000;

        Self {
            read: (desired_access & GENERIC_READ) != 0,
            write: false, // XFS is read-only
            append: (desired_access & FILE_APPEND_DATA) != 0,
            delete_on_close: (desired_access & DELETE) != 0,
        }
    }
}

/// State for directory enumeration.
pub struct DirectoryEnumState {
    /// Current position in directory listing.
    pub position: usize,
    /// Pattern filter (e.g., "*.txt").
    pub pattern: Option<String>,
    /// Restart enumeration from beginning.
    pub restart: bool,
}

impl DirectoryEnumState {
    /// Create a new enumeration state.
    pub fn new(pattern: Option<String>) -> Self {
        Self {
            position: 0,
            pattern,
            restart: false,
        }
    }

    /// Reset enumeration to beginning.
    pub fn reset(&mut self) {
        self.position = 0;
        self.restart = true;
    }
}

impl FileContext {
    /// Creates a new file context.
    pub fn new(inode_number: u64, inode: Inode, flags: FileFlags) -> Self {
        let is_directory = inode.core.is_dir();

        Self {
            inode_number,
            inode,
            position: AtomicU64::new(0),
            ref_count: AtomicU32::new(1),
            flags,
            is_directory,
            enum_state: if is_directory {
                Some(DirectoryEnumState::new(None))
            } else {
                None
            },
        }
    }

    /// Gets the file size.
    pub fn size(&self) -> u64 {
        self.inode.core.size
    }

    /// Checks if this is a directory.
    pub fn is_dir(&self) -> bool {
        self.is_directory
    }

    /// Checks if this is a regular file.
    pub fn is_file(&self) -> bool {
        self.inode.core.is_file()
    }

    /// Checks if this is a symbolic link.
    pub fn is_symlink(&self) -> bool {
        self.inode.core.is_symlink()
    }

    /// Gets the current file position.
    pub fn position(&self) -> u64 {
        self.position.load(Ordering::Relaxed)
    }

    /// Sets the file position.
    pub fn set_position(&self, pos: u64) {
        self.position.store(pos, Ordering::Relaxed);
    }

    /// Advances the file position by the given amount.
    pub fn advance_position(&self, amount: u64) -> u64 {
        self.position.fetch_add(amount, Ordering::Relaxed)
    }

    /// Seeks to a position, returning the new position.
    pub fn seek(&self, seek_from: SeekFrom) -> std::io::Result<u64> {
        let size = self.size();
        let current = self.position();

        let new_pos = match seek_from {
            SeekFrom::Start(pos) => pos,
            SeekFrom::Current(offset) => {
                if offset >= 0 {
                    current.saturating_add(offset as u64)
                } else {
                    current.saturating_sub((-offset) as u64)
                }
            }
            SeekFrom::End(offset) => {
                if offset >= 0 {
                    size.saturating_add(offset as u64)
                } else {
                    size.saturating_sub((-offset) as u64)
                }
            }
        };

        // Clamp to file size for regular files
        let final_pos = if self.is_directory {
            new_pos
        } else {
            new_pos.min(size)
        };

        self.set_position(final_pos);
        Ok(final_pos)
    }

    /// Increments the reference count.
    pub fn add_ref(&self) -> u32 {
        self.ref_count.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Decrements the reference count, returning the new count.
    pub fn release(&self) -> u32 {
        let prev = self.ref_count.fetch_sub(1, Ordering::Relaxed);
        if prev == 0 {
            // Underflow protection
            self.ref_count.store(0, Ordering::Relaxed);
            0
        } else {
            prev - 1
        }
    }

    /// Gets the current reference count.
    pub fn ref_count(&self) -> u32 {
        self.ref_count.load(Ordering::Relaxed)
    }

    /// Gets the file permissions (Unix-style mode bits).
    pub fn permissions(&self) -> u16 {
        self.inode.core.permissions()
    }

    /// Gets the file type.
    pub fn file_type(&self) -> xfs_rs::inode::FileType {
        self.inode.core.file_type()
    }

    /// Gets the number of hard links.
    pub fn nlink(&self) -> u32 {
        self.inode.core.nlink
    }

    /// Gets the owner UID.
    pub fn uid(&self) -> u32 {
        self.inode.core.uid
    }

    /// Gets the owner GID.
    pub fn gid(&self) -> u32 {
        self.inode.core.gid
    }

    /// Gets the access time (Unix timestamp).
    pub fn atime(&self) -> (u32, u32) {
        (self.inode.core.atime_sec, self.inode.core.atime_nsec)
    }

    /// Gets the modification time (Unix timestamp).
    pub fn mtime(&self) -> (u32, u32) {
        (self.inode.core.mtime_sec, self.inode.core.mtime_nsec)
    }

    /// Gets the change time (Unix timestamp).
    pub fn ctime(&self) -> (u32, u32) {
        (self.inode.core.ctime_sec, self.inode.core.ctime_nsec)
    }

    /// Gets the creation time for v3 inodes.
    pub fn crtime(&self) -> Option<(u32, u32)> {
        if self.inode.core.version >= 3 {
            Some((self.inode.core.crtime_sec, self.inode.core.crtime_nsec))
        } else {
            None
        }
    }
}

/// Seek position specifier.
#[derive(Debug, Clone, Copy)]
pub enum SeekFrom {
    /// Seek from the start of the file.
    Start(u64),
    /// Seek from the current position.
    Current(i64),
    /// Seek from the end of the file.
    End(i64),
}

impl From<std::io::SeekFrom> for SeekFrom {
    fn from(seek: std::io::SeekFrom) -> Self {
        match seek {
            std::io::SeekFrom::Start(pos) => SeekFrom::Start(pos),
            std::io::SeekFrom::Current(offset) => SeekFrom::Current(offset),
            std::io::SeekFrom::End(offset) => SeekFrom::End(offset),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests would require creating mock inodes
}
