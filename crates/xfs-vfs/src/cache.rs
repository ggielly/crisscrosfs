//! Concurrent, explicitly invalidated caches for the XFS VFS.
//!
//! File data deliberately does not use the block cache: WinFsp already caches
//! file data. The block cache is only for metadata (B+trees, AGF/AGI and
//! directory blocks). No TTL is used because this process is the only writer;
//! mutations invalidate the affected entries explicitly.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use ahash::AHashMap;
use fs_abstraction::{FsError, FsResult};
use moka::sync::Cache;
use parking_lot::RwLock;
use xfs_rs::{Extent, Inode};

use crate::{name_mangling::unmangle, VfsDirEntry};

pub const DEFAULT_INODE_CACHE_SIZE: usize = 4096;
pub const DEFAULT_BLOCK_CACHE_SIZE: usize = 1024;
pub const DEFAULT_PATH_CACHE_SIZE: usize = 2048;
pub const DEFAULT_DIR_CACHE_SIZE: usize = 512;
pub const DEFAULT_INODE_CLUSTER_CACHE_SIZE: usize = 256;
pub const DEFAULT_EXTENT_CACHE_SIZE: usize = 2048;

/// A directory listing plus a name index built once when it is cached.
#[derive(Debug)]
pub struct DirIndex {
    pub entries: Arc<[VfsDirEntry]>,
    by_name: AHashMap<Box<str>, usize>,
    by_wide_name: AHashMap<Box<[u16]>, usize>,
}

impl DirIndex {
    pub fn new(entries: Vec<VfsDirEntry>) -> FsResult<Self> {
        let mut by_name = AHashMap::with_capacity(entries.len());
        let mut by_wide_name = AHashMap::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            // XFS cannot contain duplicate live names. Treat duplicates as
            // corruption instead of making lookup depend on iteration order.
            if by_name.insert(entry.name.as_str().into(), index).is_some() {
                return Err(FsError::Corrupted);
            }
            by_wide_name.insert(entry.name.encode_utf16().collect(), index);

            // A valid original UTF-8 name containing the escape marker is
            // also accepted as an alias. This lets Windows keep using the
            // original name after a create, while readdir exposes the safe
            // encoded spelling.
            if let Ok(original) = unmangle(&entry.name)
                .and_then(|bytes| String::from_utf8(bytes).map_err(|_| FsError::Corrupted))
            {
                if original != entry.name {
                    if let Some(existing) = by_name.insert(original.as_str().into(), index) {
                        if existing != index {
                            return Err(FsError::Corrupted);
                        }
                    }
                    by_wide_name.insert(original.encode_utf16().collect(), index);
                }
            }
        }
        Ok(Self {
            entries: entries.into(),
            by_name,
            by_wide_name,
        })
    }

    pub fn lookup(&self, name: &str) -> Option<&VfsDirEntry> {
        self.by_name.get(name).map(|&index| &self.entries[index])
    }

    pub fn lookup_wide(&self, name: &[u16]) -> Option<&VfsDirEntry> {
        self.by_wide_name
            .get(name)
            .map(|&index| &self.entries[index])
    }

    pub fn lookup_wide_case_insensitive(&self, name: &[u16]) -> FsResult<Option<&VfsDirEntry>> {
        self.lookup_case_insensitive(&String::from_utf16_lossy(name))
    }

    pub fn lookup_case_insensitive(&self, name: &str) -> FsResult<Option<&VfsDirEntry>> {
        let mut found = None;
        for (candidate, &index) in &self.by_name {
            if unicase::eq(candidate.as_ref(), name) {
                if found.is_some_and(|existing| existing != index) {
                    return Err(FsError::AlreadyExists);
                }
                found = Some(index);
            }
        }
        Ok(found.map(|index| &self.entries[index]))
    }
}

/// Shared in-core state. All caches support concurrent readers; moka performs
/// recency updates internally without exposing a global write lock.
pub struct XfsCache {
    /// Monotonic mutation epoch. Readers capture it before disk I/O and only
    /// populate caches if it is still current, preventing stale read-after-
    /// invalidation insertion races.
    pub generation: AtomicU64,
    /// Serializes only the final check-and-insert of concurrently filled
    /// entries against invalidation. Disk I/O never holds this lock.
    insertion_lock: RwLock<()>,
    pub inode_cache: Cache<u64, Arc<Inode>>,
    pub block_cache: Cache<u64, Arc<[u8]>>,
    pub path_cache: Cache<String, u64>,
    pub wide_path_cache: Cache<Box<[u16]>, u64>,
    pub dir_cache: Cache<u64, Arc<DirIndex>>,
    pub inode_cluster_cache: Cache<u64, Arc<[u8]>>,
    pub extent_cache: Cache<u64, Arc<[Extent]>>,
}

impl XfsCache {
    pub fn new() -> Self {
        Self::with_sizes(
            DEFAULT_INODE_CACHE_SIZE,
            DEFAULT_BLOCK_CACHE_SIZE,
            DEFAULT_PATH_CACHE_SIZE,
            DEFAULT_DIR_CACHE_SIZE,
        )
    }

    pub fn with_sizes(
        inode_size: usize,
        block_size: usize,
        path_size: usize,
        dir_size: usize,
    ) -> Self {
        Self {
            generation: AtomicU64::new(0),
            insertion_lock: RwLock::new(()),
            inode_cache: Cache::new(capacity(inode_size)),
            block_cache: Cache::new(capacity(block_size)),
            path_cache: Cache::new(capacity(path_size)),
            wide_path_cache: Cache::new(capacity(path_size)),
            dir_cache: Cache::new(capacity(dir_size)),
            inode_cluster_cache: Cache::new(capacity(DEFAULT_INODE_CLUSTER_CACHE_SIZE)),
            extent_cache: Cache::new(capacity(DEFAULT_EXTENT_CACHE_SIZE)),
        }
    }

    pub fn get_inode(&self, ino: u64) -> Option<Arc<Inode>> {
        self.inode_cache.get(&ino)
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    pub fn advance_generation(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Hold this while advancing the generation and invalidating entries.
    /// Conditional cache fills take the read side for their check-and-insert.
    pub fn invalidation_write(&self) -> parking_lot::RwLockWriteGuard<'_, ()> {
        self.insertion_lock.write()
    }

    pub fn put_inode(&self, ino: u64, inode: Arc<Inode>) {
        self.inode_cache.insert(ino, inode);
    }

    pub fn put_inode_if_current(&self, ino: u64, inode: Arc<Inode>, generation: u64) {
        let _guard = self.insertion_lock.read();
        if self.generation() == generation {
            self.put_inode(ino, inode);
        }
    }

    pub fn put_inode_cluster_if_current(&self, block: u64, raw: Arc<[u8]>, generation: u64) {
        let _guard = self.insertion_lock.read();
        if self.generation() == generation {
            self.inode_cluster_cache.insert(block, raw);
        }
    }

    pub fn put_block_if_current(&self, block: u64, raw: Arc<[u8]>, generation: u64) {
        let _guard = self.insertion_lock.read();
        if self.generation() == generation {
            self.block_cache.insert(block, raw);
        }
    }

    pub fn put_extents_if_current(&self, ino: u64, extents: Arc<[Extent]>, generation: u64) {
        let _guard = self.insertion_lock.read();
        if self.generation() == generation {
            self.extent_cache.insert(ino, extents);
        }
    }

    pub fn invalidate_inode_metadata(&self, ino: u64) {
        self.inode_cache.invalidate(&ino);
        self.extent_cache.invalidate(&ino);
    }

    pub fn invalidate_inode(&self, ino: u64) {
        let _guard = self.invalidation_write();
        self.advance_generation();
        self.invalidate_inode_metadata(ino);
        self.invalidate_directory(ino);
        // Public invalidation may be requested after an external namespace
        // change; path answers cannot be proven safe without a generation.
        // The invalidation write guard is already held, so clear directly
        // rather than re-entering `invalidate_paths`.
        self.path_cache.invalidate_all();
        self.wide_path_cache.invalidate_all();
    }

    pub fn invalidate_inode_buffer(&self, inode_block: u64) {
        self.inode_cluster_cache.invalidate(&inode_block);
    }

    pub fn get_path(&self, path: &str) -> Option<u64> {
        self.path_cache.get(path)
    }

    pub fn put_path(&self, path: String, ino: u64) {
        self.path_cache.insert(path, ino);
    }

    pub fn get_wide_path(&self, path: &[u16]) -> Option<u64> {
        self.wide_path_cache.get(path)
    }

    pub fn put_wide_path(&self, path: Box<[u16]>, ino: u64) {
        self.wide_path_cache.insert(path, ino);
    }

    pub fn get_directory(&self, ino: u64) -> Option<Arc<DirIndex>> {
        self.dir_cache.get(&ino)
    }

    #[cfg(test)]
    pub fn put_directory(&self, ino: u64, entries: Vec<VfsDirEntry>) -> FsResult<Arc<DirIndex>> {
        let index = Arc::new(DirIndex::new(entries)?);
        self.dir_cache.insert(ino, index.clone());
        Ok(index)
    }

    pub fn put_directory_if_current(
        &self,
        ino: u64,
        entries: Vec<VfsDirEntry>,
        generation: u64,
    ) -> FsResult<Arc<DirIndex>> {
        let index = Arc::new(DirIndex::new(entries)?);
        let _guard = self.insertion_lock.read();
        if self.generation() == generation {
            self.dir_cache.insert(ino, index.clone());
        }
        Ok(index)
    }

    pub fn invalidate_directory(&self, ino: u64) {
        self.dir_cache.invalidate(&ino);
    }

    pub fn invalidate_paths(&self) {
        let _guard = self.invalidation_write();
        self.advance_generation();
        self.path_cache.invalidate_all();
        self.wide_path_cache.invalidate_all();
    }

    pub fn invalidate_all(&self) {
        let _guard = self.invalidation_write();
        self.advance_generation();
        self.inode_cache.invalidate_all();
        self.block_cache.invalidate_all();
        self.path_cache.invalidate_all();
        self.wide_path_cache.invalidate_all();
        self.dir_cache.invalidate_all();
        self.inode_cluster_cache.invalidate_all();
        self.extent_cache.invalidate_all();
    }
}

impl Default for XfsCache {
    fn default() -> Self {
        Self::new()
    }
}

fn capacity(value: usize) -> u64 {
    assert!(value > 0, "cache capacities must be non-zero");
    value as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, ino: u64) -> VfsDirEntry {
        VfsDirEntry {
            name: name.into(),
            ino,
            file_type: crate::VfsFileType::RegularFile,
            offset: 0,
        }
    }

    #[test]
    fn directory_lookup_does_not_clone_the_listing() {
        let index = DirIndex::new(vec![entry("alpha", 10), entry("beta", 20)]).unwrap();
        assert_eq!(index.lookup("beta").unwrap().ino, 20);
        assert!(index.lookup("missing").is_none());
        assert_eq!(index.entries.len(), 2);
    }

    #[test]
    fn original_escape_marker_name_remains_addressable() {
        let original = "name\u{F001}suffix";
        let encoded = crate::name_mangling::mangle_str(original).unwrap();
        let index = DirIndex::new(vec![entry(&encoded, 10)]).unwrap();
        assert_eq!(index.lookup(original).unwrap().ino, 10);
        assert_eq!(index.lookup(&encoded).unwrap().ino, 10);
    }

    #[test]
    fn invalidating_an_inode_also_invalidates_its_extent_map_and_cluster() {
        let cache = XfsCache::new();
        cache.inode_cluster_cache.insert(128, Arc::from([1u8]));
        cache.extent_cache.insert(129, Arc::from([]));
        cache.invalidate_inode(129);
        cache.invalidate_inode_buffer(128);
        assert!(cache.inode_cluster_cache.get(&128).is_none());
        assert!(cache.extent_cache.get(&129).is_none());
    }
}
