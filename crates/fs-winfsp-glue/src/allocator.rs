//! Block Allocator for XFS write support.
//!
//! This module provides block allocation and deallocation functionality
//! for XFS filesystems. It tracks free blocks using the AGF (Allocation Group
//! Free space) structures and the BNO/CNT B+trees.
//!
//! ## XFS Free Space Management
//!
//! XFS uses two B+trees per AG to manage free space:
//! - **BNO tree**: Sorted by block number (for finding adjacent free blocks)
//! - **CNT tree**: Sorted by count (for finding blocks of a specific size)

use std::sync::Arc;

use xfs_rs::freespace::{
    find_free_extent_by_size,
    read_leaf_records,
    write_leaf_records,
    AllocBtreeBlock,
    AllocRec,
};

use crate::{
    disk::{DiskReader, DiskWriter},
    error::{Result, XfsWinfspError},
};

/// A free extent (contiguous block of free space).
#[derive(Debug, Clone, Copy)]
pub struct FreeExtent {
    /// AG number.
    pub ag_num: u32,
    /// Block number within AG.
    pub ag_block: u32,
    /// Number of contiguous free blocks.
    pub block_count: u32,
}

impl FreeExtent {
    /// Convert to absolute filesystem block number.
    pub fn to_absolute_block(&self, ag_blocks: u32) -> u64 {
        (self.ag_num as u64) * (ag_blocks as u64) + (self.ag_block as u64)
    }
}

/// Simple block allocator for XFS.
///
/// This allocator uses the AGF headers and free space B+trees (BNO/CNT)
/// to find and allocate free blocks.
pub struct BlockAllocator {
    /// Reference to disk reader.
    reader: Arc<dyn DiskReader>,
    /// Reference to disk writer.
    writer: Arc<dyn DiskWriter>,
    /// Superblock info.
    block_size: u32,
    ag_count: u32,
    ag_blocks: u32,
    sector_size: u16,
    /// Whether this is a v5 filesystem (with CRC).
    is_v5: bool,
    /// Cached AGF headers (per AG).
    agf_cache: Vec<Option<xfs_rs::AgFreeHeader>>,
}

impl BlockAllocator {
    /// Create a new block allocator.
    pub fn new(
        reader: Arc<dyn DiskReader>,
        writer: Arc<dyn DiskWriter>,
        superblock: &xfs_rs::Superblock,
    ) -> Self {
        let ag_count = superblock.ag_count;
        let is_v5 = superblock.version >= 5 || superblock.features_compat != 0;
        Self {
            reader,
            writer,
            block_size: superblock.block_size,
            ag_count,
            ag_blocks: superblock.ag_blocks,
            sector_size: superblock.sector_size,
            is_v5,
            agf_cache: vec![None; ag_count as usize],
        }
    }

    /// Read the AGF for a specific allocation group.
    pub fn read_agf(&mut self, ag_num: u32) -> Result<xfs_rs::AgFreeHeader> {
        if ag_num >= self.ag_count {
            return Err(XfsWinfspError::InvalidArgument(format!(
                "AG number {} out of range (max: {})",
                ag_num,
                self.ag_count - 1
            )));
        }

        // Check cache
        if let Some(ref agf) = self.agf_cache[ag_num as usize] {
            return Ok(agf.clone());
        }

        // Calculate AGF offset
        // AGF is at sector 1 within each AG
        let ag_offset = (ag_num as u64) * (self.ag_blocks as u64) * (self.block_size as u64);
        let agf_offset = ag_offset + (self.sector_size as u64); // Sector 1

        // Read AGF
        let buffer = self.reader.read_unaligned(agf_offset, 512)?;
        let agf = xfs_rs::AgFreeHeader::parse(&buffer)
            .map_err(|e| XfsWinfspError::XfsError(format!("Failed to parse AGF: {:?}", e)))?;

        // Cache it
        self.agf_cache[ag_num as usize] = Some(agf.clone());

        Ok(agf)
    }

    /// Get the total number of free blocks in the filesystem.
    pub fn total_free_blocks(&mut self) -> Result<u64> {
        let mut total = 0u64;
        for ag in 0..self.ag_count {
            let agf = self.read_agf(ag)?;
            total += agf.free_blocks as u64;
        }
        Ok(total)
    }

    /// Find an AG with enough free space.
    pub fn find_ag_with_space(&mut self, blocks_needed: u32) -> Result<Option<u32>> {
        for ag in 0..self.ag_count {
            let agf = self.read_agf(ag)?;
            if agf.free_blocks >= blocks_needed && agf.longest_extent >= blocks_needed {
                return Ok(Some(ag));
            }
        }
        Ok(None)
    }

    /// Allocate blocks from the filesystem.
    ///
    /// This allocator uses the CNT B+tree to find free extents of the
    /// requested size or larger.
    ///
    /// Returns the absolute block number of the first allocated block.
    pub fn allocate_blocks(&mut self, count: u32) -> Result<Option<FreeExtent>> {
        // Find an AG with enough space
        let ag_num = match self.find_ag_with_space(count)? {
            Some(ag) => ag,
            None => return Ok(None), // No space
        };

        let agf = self.read_agf(ag_num)?;

        // Read the CNT tree root block
        let cnt_root_block = agf.cnt_root;
        let cnt_offset = self.ag_block_offset(ag_num, cnt_root_block);
        let cnt_buffer = self
            .reader
            .read_unaligned(cnt_offset, self.block_size as usize)?;

        // Parse the B+tree header
        let cnt_header = AllocBtreeBlock::parse(&cnt_buffer, self.is_v5).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to parse CNT header: {:?}", e))
        })?;

        // Search for free extent using the CNT tree
        match find_free_extent_by_size(&cnt_buffer, &cnt_header, count, self.is_v5) {
            Ok(Some((record, _index))) => {
                // Found a suitable extent
                Ok(Some(FreeExtent {
                    ag_num,
                    ag_block: record.start_block,
                    block_count: record.block_count.min(count), // Take only what we need
                }))
            }
            Ok(None) => {
                // No suitable extent in this AG, this shouldn't happen if AGF is correct
                Ok(None)
            }
            Err(e) => {
                // B+tree parsing error - fall back to error
                Err(XfsWinfspError::XfsError(format!(
                    "Failed to search CNT tree: {:?}",
                    e
                )))
            }
        }
    }

    /// Calculate the disk offset for a block within an AG.
    fn ag_block_offset(&self, ag_num: u32, ag_block: u32) -> u64 {
        let ag_offset = (ag_num as u64) * (self.ag_blocks as u64) * (self.block_size as u64);
        ag_offset + (ag_block as u64) * (self.block_size as u64)
    }

    /// Mark blocks as allocated (update B+trees and AGF).
    ///
    /// This removes the allocated extent from both BNO and CNT trees.
    pub fn mark_allocated(&mut self, extent: &FreeExtent) -> Result<()> {
        let agf = self.read_agf(extent.ag_num)?;

        // Read BNO tree root
        let bno_root_block = agf.bno_root;
        let bno_offset = self.ag_block_offset(extent.ag_num, bno_root_block);
        let bno_buffer = self
            .reader
            .read_unaligned(bno_offset, self.block_size as usize)?;

        // Parse BNO header
        let bno_header = AllocBtreeBlock::parse(&bno_buffer, self.is_v5).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to parse BNO header: {:?}", e))
        })?;

        // Read current leaf records from BNO tree
        let records = read_leaf_records(&bno_buffer, &bno_header, self.is_v5).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to read BNO records: {:?}", e))
        })?;

        // Find and remove/split the record
        let mut found = false;
        let mut new_records = Vec::new();

        for rec in &records {
            if rec.start_block == extent.ag_block && rec.block_count == extent.block_count {
                // Exact match - remove entirely
                found = true;
                continue;
            } else if rec.start_block == extent.ag_block && rec.block_count > extent.block_count {
                // Allocating from start - shrink
                found = true;
                new_records.push(AllocRec {
                    start_block: rec.start_block + extent.block_count,
                    block_count: rec.block_count - extent.block_count,
                });
            } else if rec.start_block < extent.ag_block
                && rec.start_block + rec.block_count > extent.ag_block + extent.block_count
            {
                // Allocating from middle - split
                found = true;
                // Left part
                new_records.push(AllocRec {
                    start_block: rec.start_block,
                    block_count: extent.ag_block - rec.start_block,
                });
                // Right part
                let right_start = extent.ag_block + extent.block_count;
                new_records.push(AllocRec {
                    start_block: right_start,
                    block_count: (rec.start_block + rec.block_count) - right_start,
                });
            } else if rec.start_block < extent.ag_block
                && rec.start_block + rec.block_count == extent.ag_block + extent.block_count
            {
                // Allocating from end - shrink
                found = true;
                new_records.push(AllocRec {
                    start_block: rec.start_block,
                    block_count: extent.ag_block - rec.start_block,
                });
            } else {
                // Unrelated record - keep
                new_records.push(rec.clone());
            }
        }

        if !found {
            return Err(XfsWinfspError::XfsError(
                "Extent not found in free space".to_string(),
            ));
        }

        // Write updated BNO tree
        let mut new_bno_buffer = bno_buffer.clone();
        write_leaf_records(&mut new_bno_buffer, &bno_header, &new_records, self.is_v5).map_err(
            |e| XfsWinfspError::XfsError(format!("Failed to write BNO records: {:?}", e)),
        )?;
        self.writer.write_unaligned(bno_offset, &new_bno_buffer)?;

        // Also need to update CNT tree (records sorted by count)
        let cnt_root_block = agf.cnt_root;
        let cnt_offset = self.ag_block_offset(extent.ag_num, cnt_root_block);
        let cnt_buffer = self
            .reader
            .read_unaligned(cnt_offset, self.block_size as usize)?;

        // Parse CNT header
        let cnt_header = AllocBtreeBlock::parse(&cnt_buffer, self.is_v5).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to parse CNT header: {:?}", e))
        })?;

        // For CNT tree, sort records by count then block
        let mut cnt_records = new_records.clone();
        cnt_records.sort_by(|a, b| {
            a.block_count
                .cmp(&b.block_count)
                .then(a.start_block.cmp(&b.start_block))
        });

        let mut new_cnt_buffer = cnt_buffer.clone();
        write_leaf_records(&mut new_cnt_buffer, &cnt_header, &cnt_records, self.is_v5).map_err(
            |e| XfsWinfspError::XfsError(format!("Failed to write CNT records: {:?}", e)),
        )?;
        self.writer.write_unaligned(cnt_offset, &new_cnt_buffer)?;

        // Update AGF header
        self.update_agf_after_alloc(extent)?;

        Ok(())
    }

    /// Free blocks back to the filesystem.
    pub fn free_blocks(&mut self, extent: FreeExtent) -> Result<()> {
        let agf = self.read_agf(extent.ag_num)?;

        // Read BNO tree root
        let bno_root_block = agf.bno_root;
        let bno_offset = self.ag_block_offset(extent.ag_num, bno_root_block);
        let bno_buffer = self
            .reader
            .read_unaligned(bno_offset, self.block_size as usize)?;

        // Parse BNO header
        let bno_header = AllocBtreeBlock::parse(&bno_buffer, self.is_v5).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to parse BNO header: {:?}", e))
        })?;

        // Read current records
        let mut records = read_leaf_records(&bno_buffer, &bno_header, self.is_v5).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to read BNO records: {:?}", e))
        })?;

        // Add the freed extent
        let new_rec = AllocRec {
            start_block: extent.ag_block,
            block_count: extent.block_count,
        };

        // Insert in sorted order and merge adjacent extents
        let mut merged = false;
        for i in 0..records.len() {
            // Check if we can merge with existing record
            if records[i].start_block + records[i].block_count == extent.ag_block {
                // Merge with previous
                records[i].block_count += extent.block_count;
                merged = true;

                // Check if we can also merge with next
                if i + 1 < records.len()
                    && records[i].start_block + records[i].block_count == records[i + 1].start_block
                {
                    records[i].block_count += records[i + 1].block_count;
                    records.remove(i + 1);
                }
                break;
            } else if extent.ag_block + extent.block_count == records[i].start_block {
                // Merge with next
                records[i].start_block = extent.ag_block;
                records[i].block_count += extent.block_count;
                merged = true;
                break;
            } else if records[i].start_block > extent.ag_block {
                // Insert before this record
                records.insert(i, new_rec);
                merged = true;
                break;
            }
        }

        if !merged {
            records.push(new_rec);
        }

        // Sort by block number
        records.sort_by_key(|r| r.start_block);

        // Write updated BNO tree
        let mut new_bno_buffer = bno_buffer.clone();
        write_leaf_records(&mut new_bno_buffer, &bno_header, &records, self.is_v5).map_err(
            |e| XfsWinfspError::XfsError(format!("Failed to write BNO records: {:?}", e)),
        )?;
        self.writer.write_unaligned(bno_offset, &new_bno_buffer)?;

        // Update CNT tree
        let cnt_root_block = agf.cnt_root;
        let cnt_offset = self.ag_block_offset(extent.ag_num, cnt_root_block);
        let cnt_buffer = self
            .reader
            .read_unaligned(cnt_offset, self.block_size as usize)?;

        // Parse CNT header
        let cnt_header = AllocBtreeBlock::parse(&cnt_buffer, self.is_v5).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to parse CNT header: {:?}", e))
        })?;

        let mut cnt_records = records.clone();
        cnt_records.sort_by(|a, b| {
            a.block_count
                .cmp(&b.block_count)
                .then(a.start_block.cmp(&b.start_block))
        });

        let mut new_cnt_buffer = cnt_buffer.clone();
        write_leaf_records(&mut new_cnt_buffer, &cnt_header, &cnt_records, self.is_v5).map_err(
            |e| XfsWinfspError::XfsError(format!("Failed to write CNT records: {:?}", e)),
        )?;
        self.writer.write_unaligned(cnt_offset, &new_cnt_buffer)?;

        // Update AGF header
        self.update_agf_after_free(&extent)?;

        Ok(())
    }

    /// Update AGF header after allocation.
    fn update_agf_after_alloc(&mut self, extent: &FreeExtent) -> Result<()> {
        let mut agf = self.read_agf(extent.ag_num)?;

        agf.free_blocks = agf.free_blocks.saturating_sub(extent.block_count);
        // Note: longest_extent should be recalculated from trees

        // Write AGF back
        let agf_offset = self.ag_block_offset(extent.ag_num, 0) + (self.sector_size as u64);
        let agf_bytes = agf.to_bytes();
        self.writer.write_unaligned(agf_offset, &agf_bytes)?;

        // Invalidate cache
        self.invalidate_agf(extent.ag_num);

        Ok(())
    }

    /// Update AGF header after freeing blocks.
    fn update_agf_after_free(&mut self, extent: &FreeExtent) -> Result<()> {
        let mut agf = self.read_agf(extent.ag_num)?;

        agf.free_blocks = agf.free_blocks.saturating_add(extent.block_count);
        if extent.block_count > agf.longest_extent {
            agf.longest_extent = extent.block_count;
        }

        // Write AGF back
        let agf_offset = self.ag_block_offset(extent.ag_num, 0) + (self.sector_size as u64);
        let agf_bytes = agf.to_bytes();
        self.writer.write_unaligned(agf_offset, &agf_bytes)?;

        // Invalidate cache
        self.invalidate_agf(extent.ag_num);

        Ok(())
    }

    /// Invalidate the AGF cache for a specific AG.
    pub fn invalidate_agf(&mut self, ag_num: u32) {
        if (ag_num as usize) < self.agf_cache.len() {
            self.agf_cache[ag_num as usize] = None;
        }
    }

    /// Invalidate all AGF caches.
    pub fn invalidate_all(&mut self) {
        for cache in &mut self.agf_cache {
            *cache = None;
        }
    }

    /// Get block size.
    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    /// Get AG blocks count.
    pub fn ag_blocks(&self) -> u32 {
        self.ag_blocks
    }
}

/// Extent allocation helper.
///
/// This helper provides convenience methods for working with extents.
pub struct ExtentHelper;

impl ExtentHelper {
    /// Calculate how many blocks are needed for a given byte count.
    pub fn blocks_for_bytes(bytes: u64, block_size: u32) -> u32 {
        let block_size = block_size as u64;
        ((bytes + block_size - 1) / block_size) as u32
    }

    /// Calculate the byte offset within a block.
    pub fn offset_in_block(byte_offset: u64, block_size: u32) -> u32 {
        (byte_offset % block_size as u64) as u32
    }

    /// Convert a file offset to block number.
    pub fn file_offset_to_block(file_offset: u64, block_size: u32) -> u64 {
        file_offset / block_size as u64
    }

    /// Create a new extent.
    pub fn create_extent(
        file_offset_blocks: u64,
        disk_block: u64,
        block_count: u32,
        is_unwritten: bool,
    ) -> xfs_rs::Extent {
        xfs_rs::Extent {
            file_offset: file_offset_blocks,
            start_block: disk_block,
            block_count,
            is_unwritten,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blocks_for_bytes() {
        assert_eq!(ExtentHelper::blocks_for_bytes(0, 4096), 0);
        assert_eq!(ExtentHelper::blocks_for_bytes(1, 4096), 1);
        assert_eq!(ExtentHelper::blocks_for_bytes(4096, 4096), 1);
        assert_eq!(ExtentHelper::blocks_for_bytes(4097, 4096), 2);
        assert_eq!(ExtentHelper::blocks_for_bytes(8192, 4096), 2);
    }

    #[test]
    fn test_offset_in_block() {
        assert_eq!(ExtentHelper::offset_in_block(0, 4096), 0);
        assert_eq!(ExtentHelper::offset_in_block(100, 4096), 100);
        assert_eq!(ExtentHelper::offset_in_block(4096, 4096), 0);
        assert_eq!(ExtentHelper::offset_in_block(4196, 4096), 100);
    }
}
