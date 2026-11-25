//! Caching layer for XFS VFS.
//!
//! This module provides LRU caches for inodes, directory entries,
//! and path resolution results.

use std::{
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use lru::LruCache;
use parking_lot::RwLock;

use crate::VfsDirEntry;

/// Default cache sizes
pub const DEFAULT_INODE_CACHE_SIZE: usize = 4096;
pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 1024;
pub const DEFAULT_PATH_CACHE_SIZE: usize = 2048;
pub const DEFAULT_DIR_CACHE_SIZE: usize = 512;

/// Cached inode data
#[derive(Clone)]
pub struct CachedInode {
    pub inode: xfs_rs::Inode,
    pub timestamp: Instant,
}

impl CachedInode {
    pub fn new(inode: xfs_rs::Inode) -> Self {
        Self {
            inode,
            timestamp: Instant::now(),
        }
    }
}

/// Cached directory entries
#[derive(Clone)]
pub struct CachedDirectory {
    pub entries: Vec<VfsDirEntry>,
    pub timestamp: Instant,
}

impl CachedDirectory {
    pub fn new(entries: Vec<VfsDirEntry>) -> Self {
        Self {
            entries,
            timestamp: Instant::now(),
        }
    }
}

/// XFS cache manager
pub struct XfsCache {
    /// Inode cache: inode_number -> parsed inode
    pub inode_cache: RwLock<LruCache<u64, CachedInode>>,

    /// Block cache: block_number -> raw block data
    pub block_cache: RwLock<LruCache<u64, Vec<u8>>>,

    /// Path cache: path -> inode_number
    pub path_cache: RwLock<LruCache<String, u64>>,

    /// Directory cache: inode_number -> directory entries
    pub dir_cache: RwLock<LruCache<u64, CachedDirectory>>,

    /// Cache TTL
    pub ttl: Duration,
}

impl XfsCache {
    /// Create a new cache with default sizes.
    pub fn new() -> Self {
        Self::with_sizes(
            DEFAULT_INODE_CACHE_SIZE,
            DEFAULT_BLOCK_CACHE_SIZE,
            DEFAULT_PATH_CACHE_SIZE,
            DEFAULT_DIR_CACHE_SIZE,
        )
    }

    /// Create a new cache with custom sizes.
    pub fn with_sizes(
        inode_size: usize,
        block_size: usize,
        path_size: usize,
        dir_size: usize,
    ) -> Self {
        Self {
            inode_cache: RwLock::new(LruCache::new(NonZeroUsize::new(inode_size).unwrap())),
            block_cache: RwLock::new(LruCache::new(NonZeroUsize::new(block_size).unwrap())),
            path_cache: RwLock::new(LruCache::new(NonZeroUsize::new(path_size).unwrap())),
            dir_cache: RwLock::new(LruCache::new(NonZeroUsize::new(dir_size).unwrap())),
            ttl: Duration::from_secs(60), // 60 second default TTL
        }
    }

    /// Get a cached inode if available and not expired.
    pub fn get_inode(&self, ino: u64) -> Option<xfs_rs::Inode> {
        let mut cache = self.inode_cache.write();
        if let Some(entry) = cache.get(&ino) {
            if !entry.timestamp.elapsed().gt(&self.ttl) {
                return Some(entry.inode.clone());
            }
            // Expired, remove it
            cache.pop(&ino);
        }
        None
    }

    /// Store an inode in the cache.
    pub fn put_inode(&self, ino: u64, inode: xfs_rs::Inode) {
        let mut cache = self.inode_cache.write();
        cache.put(ino, CachedInode::new(inode));
    }

    /// Invalidate a cached inode.
    pub fn invalidate_inode(&self, ino: u64) {
        self.inode_cache.write().pop(&ino);
    }

    /// Get cached path resolution.
    pub fn get_path(&self, path: &str) -> Option<u64> {
        self.path_cache.write().get(path).copied()
    }

    /// Store a path resolution.
    pub fn put_path(&self, path: String, ino: u64) {
        self.path_cache.write().put(path, ino);
    }

    /// Get cached directory entries if available and not expired.
    pub fn get_directory(&self, ino: u64) -> Option<Vec<VfsDirEntry>> {
        let mut cache = self.dir_cache.write();
        if let Some(entry) = cache.get(&ino) {
            if !entry.timestamp.elapsed().gt(&self.ttl) {
                return Some(entry.entries.clone());
            }
            // Expired, remove it
            cache.pop(&ino);
        }
        None
    }

    /// Store directory entries.
    pub fn put_directory(&self, ino: u64, entries: Vec<VfsDirEntry>) {
        let mut cache = self.dir_cache.write();
        cache.put(ino, CachedDirectory::new(entries));
    }

    /// Invalidate all caches.
    pub fn invalidate_all(&self) {
        self.inode_cache.write().clear();
        self.block_cache.write().clear();
        self.path_cache.write().clear();
        self.dir_cache.write().clear();
    }
}

impl Default for XfsCache {
    fn default() -> Self {
        Self::new()
    }
}
