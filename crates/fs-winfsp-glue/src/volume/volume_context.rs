//! Volume context - holds all state for a mounted XFS volume.

use std::sync::{Arc, RwLock};

use xfs_rs::Superblock;

use super::VolumeStats;
use crate::{
    cache::LruCache,
    disk::DiskReader,
    error::{Result, XfsWinfspError},
};

/// Context for a mounted XFS volume.
///
/// Contains all the state needed to access the filesystem:
/// - Disk reader for raw I/O
/// - Parsed superblock
/// - Caches for inodes and blocks
/// - Statistics
pub struct VolumeContext {
    /// The underlying disk reader.
    reader: Arc<dyn DiskReader>,
    /// Parsed XFS superblock.
    pub superblock: Superblock,
    /// LRU cache for inodes.
    inode_cache: RwLock<LruCache<u64, xfs_rs::Inode>>,
    /// LRU cache for blocks.
    block_cache: RwLock<LruCache<u64, Vec<u8>>>,
    /// Volume statistics.
    pub stats: VolumeStats,
    /// Mount point.
    pub mount_point: String,
    /// Volume label (from superblock).
    pub label: String,
    /// Volume UUID.
    pub uuid: [u8; 16],
}

impl VolumeContext {
    /// Creates a new volume context.
    pub fn new(reader: Arc<dyn DiskReader>, superblock: Superblock, mount_point: String) -> Self {
        // Extract label from superblock
        let label = {
            let name_bytes = &superblock.name;
            let len = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            String::from_utf8_lossy(&name_bytes[..len]).to_string()
        };

        let uuid = superblock.uuid;

        Self {
            reader,
            superblock,
            inode_cache: RwLock::new(LruCache::new(256)),
            block_cache: RwLock::new(LruCache::new(1024)),
            stats: VolumeStats::new(),
            mount_point,
            label,
            uuid,
        }
    }

    /// Gets the block size.
    pub fn block_size(&self) -> u32 {
        self.superblock.block_size
    }

    /// Gets the total size in bytes.
    pub fn total_size(&self) -> u64 {
        self.superblock.total_blocks * self.superblock.block_size as u64
    }

    /// Gets the free space in bytes.
    pub fn free_space(&self) -> u64 {
        self.superblock.free_blocks * self.superblock.block_size as u64
    }

    /// Gets the root inode number.
    pub fn root_inode_number(&self) -> u64 {
        self.superblock.root_inode
    }

    /// Reads an inode by number.
    pub fn read_inode(&self, ino: u64) -> Result<xfs_rs::Inode> {
        // Check cache first
        {
            let mut cache = self.inode_cache.write().unwrap();
            if let Some(inode) = cache.get(&ino) {
                self.stats.record_inode_cache_hit();
                return Ok(inode.clone());
            }
        }

        self.stats.record_inode_cache_miss();

        // Calculate inode location
        let offset = self.calculate_inode_offset(ino)?;

        // Read inode data
        let inode_size = self.superblock.inode_size as usize;
        let buffer = self.reader.read_unaligned(offset, inode_size)?;

        // Parse inode
        let inode = xfs_rs::Inode::parse(&buffer, inode_size)
            .map_err(|e| XfsWinfspError::XfsError(format!("{:?}", e)))?;

        // Cache it
        {
            let mut cache = self.inode_cache.write().unwrap();
            cache.put(ino, inode.clone());
        }

        Ok(inode)
    }

    /// Reads the root inode.
    pub fn root_inode(&self) -> Result<xfs_rs::Inode> {
        self.read_inode(self.superblock.root_inode)
    }

    /// Reads a block by number.
    pub fn read_block(&self, block_num: u64) -> Result<Vec<u8>> {
        // Check cache first
        {
            let mut cache = self.block_cache.write().unwrap();
            if let Some(block) = cache.get(&block_num) {
                self.stats.record_block_cache_hit();
                return Ok(block.clone());
            }
        }

        self.stats.record_block_cache_miss();

        // Read from disk
        let buffer = self
            .reader
            .read_block(block_num, self.superblock.block_size)?;

        self.stats.record_read(self.superblock.block_size as u64);

        // Cache it
        {
            let mut cache = self.block_cache.write().unwrap();
            cache.put(block_num, buffer.clone());
        }

        Ok(buffer)
    }

    /// Reads multiple contiguous blocks.
    pub fn read_blocks(&self, start_block: u64, count: u32) -> Result<Vec<u8>> {
        // For now, read blocks individually (benefits from cache)
        // TODO: Optimize for large contiguous reads
        let mut result =
            Vec::with_capacity((count as usize) * (self.superblock.block_size as usize));

        for i in 0..count {
            let block = self.read_block(start_block + i as u64)?;
            result.extend_from_slice(&block);
        }

        Ok(result)
    }

    /// Maps a file block offset to a physical disk block.
    pub fn map_block(&self, inode: &xfs_rs::Inode, file_block: u64) -> Result<Option<u64>> {
        use xfs_rs::InodeFormat;

        match inode.core.format {
            InodeFormat::Local => {
                // Data is inline in the inode
                Err(XfsWinfspError::XfsError(
                    "Cannot map inline data".to_string(),
                ))
            }
            InodeFormat::Extents => {
                // Simple extent list
                inode
                    .map_block(file_block)
                    .map_err(|e| XfsWinfspError::XfsError(format!("{:?}", e)))
            }
            InodeFormat::Btree => {
                // B+tree - need block reader
                let reader = VolumeBlockReader { volume: self };
                let is_v5 = self.superblock.version >= 5;
                inode
                    .map_block_btree(file_block, &reader, is_v5)
                    .map_err(|e| XfsWinfspError::XfsError(format!("{:?}", e)))
            }
            _ => Err(XfsWinfspError::XfsError(
                "Unsupported inode format".to_string(),
            )),
        }
    }

    /// Reads file data from an inode.
    pub fn read_file_data(
        &self,
        inode: &xfs_rs::Inode,
        offset: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        use xfs_rs::DataFork;

        let file_size = inode.core.size;
        if offset >= file_size {
            return Ok(Vec::new());
        }

        let actual_size = size.min((file_size - offset) as usize);
        let mut result = Vec::with_capacity(actual_size);

        match &inode.data_fork {
            DataFork::Local(data) => {
                // Inline data
                let start = offset as usize;
                let end = (offset as usize + actual_size).min(data.len());
                if start < data.len() {
                    result.extend_from_slice(&data[start..end]);
                }
            }
            DataFork::Extents(extents) => {
                // Read from extents
                let mut remaining = actual_size;
                let mut current_offset = offset;

                for extent in extents {
                    if remaining == 0 {
                        break;
                    }

                    let extent_start = extent.file_offset * self.superblock.block_size as u64;
                    let extent_size =
                        (extent.block_count as u64) * self.superblock.block_size as u64;
                    let extent_end = extent_start + extent_size;

                    // Skip extents before our offset
                    if current_offset >= extent_end {
                        continue;
                    }

                    // Calculate read position within this extent
                    let read_start = if current_offset > extent_start {
                        current_offset - extent_start
                    } else {
                        0
                    };

                    let extent_remaining = extent_size - read_start;
                    let to_read = remaining.min(extent_remaining as usize);

                    // Read from disk
                    let disk_offset =
                        extent.start_block * self.superblock.block_size as u64 + read_start;
                    let buffer = self.reader.read_unaligned(disk_offset, to_read)?;
                    result.extend_from_slice(&buffer);

                    self.stats.record_read(to_read as u64);

                    remaining -= buffer.len();
                    current_offset += buffer.len() as u64;
                }
            }
            DataFork::Btree { .. } => {
                // B+tree - map blocks and read
                let block_size = self.superblock.block_size as u64;
                let start_block = offset / block_size;
                let offset_in_block = (offset % block_size) as usize;

                let mut remaining = actual_size;
                let mut file_block = start_block;
                let mut first_block = true;

                while remaining > 0 {
                    if let Some(disk_block) = self.map_block(inode, file_block)? {
                        let block_data = self.read_block(disk_block)?;

                        let start = if first_block { offset_in_block } else { 0 };
                        let available = block_data.len() - start;
                        let to_copy = remaining.min(available);

                        result.extend_from_slice(&block_data[start..start + to_copy]);
                        remaining -= to_copy;
                    } else {
                        // Sparse block - fill with zeros
                        let to_fill = remaining.min(block_size as usize);
                        result.extend(std::iter::repeat(0).take(to_fill));
                        remaining -= to_fill;
                    }

                    file_block += 1;
                    first_block = false;
                }
            }
            DataFork::Device { .. } | DataFork::Empty => {
                // No data to read
            }
        }

        Ok(result)
    }

    /// Calculate the byte offset of an inode on disk.
    fn calculate_inode_offset(&self, ino: u64) -> Result<u64> {
        // Use xfs-rs address module if available, otherwise manual calculation
        let ag_block_log = self.superblock.ag_block_log;
        let inode_per_block_log = self.superblock.inode_per_block_log;

        // Extract AG number and inode offset within AG
        let ag_num = (ino >> (ag_block_log + inode_per_block_log)) as u32;
        let ag_ino = ino & ((1 << (ag_block_log + inode_per_block_log)) - 1);

        // Calculate AG start offset
        let ag_start =
            ag_num as u64 * self.superblock.ag_blocks as u64 * self.superblock.block_size as u64;

        // Calculate inode offset within AG
        let inode_per_block = self.superblock.block_size / self.superblock.inode_size as u32;
        let block_in_ag = ag_ino / inode_per_block as u64;
        let offset_in_block = (ag_ino % inode_per_block as u64) * self.superblock.inode_size as u64;

        let offset = ag_start + block_in_ag * self.superblock.block_size as u64 + offset_in_block;

        Ok(offset)
    }

    /// Gets a snapshot of current statistics.
    pub fn get_stats(&self) -> super::stats::StatsSnapshot {
        self.stats.snapshot()
    }

    /// Clears all caches.
    pub fn clear_caches(&self) {
        let mut inode_cache = self.inode_cache.write().unwrap();
        inode_cache.clear();
        drop(inode_cache);

        let mut block_cache = self.block_cache.write().unwrap();
        block_cache.clear();
    }
}

/// Block reader implementation for B+tree traversal.
struct VolumeBlockReader<'a> {
    volume: &'a VolumeContext,
}

impl<'a> xfs_rs::BlockReader for VolumeBlockReader<'a> {
    fn read_block(&self, block_num: u64) -> fs_abstraction::FsResult<Vec<u8>> {
        self.volume
            .read_block(block_num)
            .map_err(|_| fs_abstraction::FsError::DiskError)
    }
}
