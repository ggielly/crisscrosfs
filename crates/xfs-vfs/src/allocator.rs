//! Block Allocator for XFS.
//!
//! This module provides block allocation and deallocation functionality
//! using AGF headers and BNO/CNT B+trees.

use std::sync::Arc;

use fs_abstraction::{BlockDevice, FsError, FsResult};
use tracing::{debug, error, info, warn};
use xfs_rs::{
    freespace::{
        find_free_extent_by_size,
        read_leaf_records,
        write_leaf_records,
        AllocBtreeBlock,
        AllocKey,
        AllocPtr,
        AllocRec,
        NULLAGBLOCK,
    },
    AgFreeHeader,
    Superblock,
};

/// A free extent (contiguous block of free space).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

    /// Convert from absolute filesystem block number.
    pub fn from_absolute_block(abs_block: u64, ag_blocks: u32) -> Self {
        Self {
            ag_num: (abs_block / ag_blocks as u64) as u32,
            ag_block: (abs_block % ag_blocks as u64) as u32,
            block_count: 1, // Default to 1
        }
    }
}

pub struct BlockAllocator {
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
}

impl BlockAllocator {
    pub fn new(device: Arc<dyn BlockDevice>, sb: Superblock) -> Self {
        Self { device, sb }
    }

    /// Read AGF header for an AG
    pub fn read_agf(&self, ag_num: u32) -> FsResult<AgFreeHeader> {
        let block_size = self.sb.block_size as u64;
        let sector_size = self.sb.sector_size as u64;
        let ag_offset = (ag_num as u64) * (self.sb.ag_blocks as u64) * block_size;
        let agf_offset = ag_offset + sector_size; // AGF is at sector 1

        let mut buffer = vec![0u8; 512]; // Standard AGF buffer size
        self.device
            .read_at(agf_offset, &mut buffer)
            .map_err(|_| FsError::DiskError)?;

        AgFreeHeader::parse(&buffer)
    }

    /// Find a free extent of at least `min_blocks` size
    pub fn allocate_blocks(&self, count: u32) -> FsResult<Option<FreeExtent>> {
        for ag in 0..self.sb.ag_count {
            let agf = self.read_agf(ag)?;
            if agf.free_blocks < count || agf.longest_extent < count {
                continue;
            }

            // Search in CNT tree (sorted by size)
            if let Some(extent) = self.search_cnt_tree(ag, &agf, count)? {
                return Ok(Some(FreeExtent {
                    ag_num: ag,
                    ag_block: extent.start_block,
                    block_count: count,
                }));
            }
        }
        Ok(None)
    }

    /// Search the CNT B+tree for an extent of at least `min_blocks`
    fn search_cnt_tree(
        &self,
        ag_num: u32,
        agf: &AgFreeHeader,
        min_blocks: u32,
    ) -> FsResult<Option<AllocRec>> {
        let block_size = self.sb.block_size as u64;
        let ag_offset = (ag_num as u64) * (self.sb.ag_blocks as u64) * block_size;
        let is_v5 = self.sb.version >= 5;

        let mut current_block = agf.cnt_root;
        let mut _current_level = agf.cnt_level;

        while current_block != NULLAGBLOCK {
            let offset = ag_offset + (current_block as u64) * block_size;
            let mut buffer = vec![0u8; self.sb.block_size as usize];
            self.device
                .read_at(offset, &mut buffer)
                .map_err(|_| FsError::DiskError)?;

            let header = AllocBtreeBlock::parse(&buffer, is_v5)?;
            if header.level == 0 {
                // Leaf node
                return find_free_extent_by_size(&buffer, &header, min_blocks, is_v5)
                    .map(|opt| opt.map(|(rec, _)| rec));
            } else {
                // Internal node - find the best child
                // Simplified: take the first child that MIGHT contain a large enough extent
                // In CNT tree, keys are (count, block). We want count >= min_blocks.
                let header_size = header.header_size(is_v5);
                let num_recs = header.num_recs as usize;

                let mut found_ptr = NULLAGBLOCK;
                for i in 0..num_recs {
                    let key_off = header_size + i * AllocKey::SIZE;
                    let key = AllocKey::parse(&buffer[key_off..])?;

                    if key.key1 >= min_blocks {
                        // This child or subsequent ones might have it
                        let ptr_off =
                            header_size + (num_recs * AllocKey::SIZE) + i * AllocPtr::SIZE;
                        let ptr = AllocPtr::parse(&buffer[ptr_off..])?;
                        found_ptr = ptr.block;
                        break;
                    }
                }

                if found_ptr == NULLAGBLOCK && num_recs > 0 {
                    // Fallback to last child if all keys are smaller
                    let ptr_off =
                        header_size + (num_recs * AllocKey::SIZE) + (num_recs - 1) * AllocPtr::SIZE;
                    let ptr = AllocPtr::parse(&buffer[ptr_off..])?;
                    found_ptr = ptr.block;
                }

                current_block = found_ptr;
            }
        }

        Ok(None)
    }

    /// Mark blocks as allocated (update both BNO and CNT trees).
    ///
    /// # Errors
    /// Always returns `FsError::NotImplemented` — the B+tree update logic is
    /// not yet written.  Callers must not proceed with a write operation when
    /// this returns an error; doing so would re-use blocks that appear free in
    /// the on-disk free-space trees, causing silent filesystem corruption.
    pub fn mark_allocated(&self, _extent: &FreeExtent) -> FsResult<()> {
        Err(fs_abstraction::FsError::NotImplemented)
    }

    /// Return blocks to the free pool (update both BNO and CNT trees).
    ///
    /// # Errors
    /// Always returns `FsError::NotImplemented` — the B+tree update logic is
    /// not yet written.  See `mark_allocated` for the corruption risk.
    pub fn free_blocks(&self, _extent: &FreeExtent) -> FsResult<()> {
        Err(fs_abstraction::FsError::NotImplemented)
    }

    /// Convert FreeExtent to absolute block number.
    pub fn to_absolute_block(&self, extent: &FreeExtent) -> u64 {
        (extent.ag_num as u64) * (self.sb.ag_blocks as u64) + (extent.ag_block as u64)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fs_abstraction::{FsError, FsResult};

    use super::*;

    struct NullDevice;

    impl fs_abstraction::BlockDevice for NullDevice {
        fn read_at(&self, _: u64, _: &mut [u8]) -> FsResult<usize> {
            Ok(0)
        }
        fn write_at(&self, _: u64, _: &[u8]) -> FsResult<usize> {
            Err(FsError::ReadOnly)
        }
        fn size(&self) -> u64 {
            0
        }
    }

    /// Minimal valid XFS v4 superblock bytes for use in tests.
    fn minimal_superblock() -> xfs_rs::Superblock {
        let mut buf = vec![0u8; 512];
        buf[0x000..0x004].copy_from_slice(&0x58465342u32.to_be_bytes()); // magic
        buf[0x004..0x008].copy_from_slice(&4096u32.to_be_bytes()); // block_size
        buf[0x008..0x010].copy_from_slice(&100u64.to_be_bytes()); // total_blocks
        buf[0x054..0x058].copy_from_slice(&100u32.to_be_bytes()); // ag_blocks
        buf[0x058..0x05C].copy_from_slice(&1u32.to_be_bytes()); // ag_count
        buf[0x064..0x066].copy_from_slice(&4u16.to_be_bytes()); // version
        buf[0x066..0x068].copy_from_slice(&512u16.to_be_bytes()); // sector_size
        buf[0x068..0x06A].copy_from_slice(&256u16.to_be_bytes()); // inode_size
        buf[0x06A..0x06C].copy_from_slice(&16u16.to_be_bytes()); // inodes_per_block
        buf[0x078] = 12; // block_log = log2(4096)
        buf[0x079] = 9; // sector_log = log2(512)
        buf[0x07A] = 8; // inode_log = log2(256)
        buf[0x07B] = 4; // inode_per_block_log = log2(16)
        buf[0x07C] = 7; // ag_block_log = ceil(log2(100))
        xfs_rs::Superblock::parse(&buf).expect("valid v4 superblock")
    }

    fn make_allocator() -> BlockAllocator {
        BlockAllocator::new(Arc::new(NullDevice), minimal_superblock())
    }

    #[test]
    fn mark_allocated_returns_not_implemented() {
        let a = make_allocator();
        let extent = FreeExtent { ag_num: 0, ag_block: 0, block_count: 1 };
        assert!(
            matches!(a.mark_allocated(&extent), Err(FsError::NotImplemented)),
            "mark_allocated must remain a stub until the B+tree update is written"
        );
    }

    #[test]
    fn free_blocks_returns_not_implemented() {
        let a = make_allocator();
        let extent = FreeExtent { ag_num: 0, ag_block: 0, block_count: 1 };
        assert!(
            matches!(a.free_blocks(&extent), Err(FsError::NotImplemented)),
            "free_blocks must remain a stub until the B+tree update is written"
        );
    }

    #[test]
    fn free_extent_round_trips_absolute_block() {
        let ag_blocks: u32 = 100;
        let fe = FreeExtent { ag_num: 2, ag_block: 15, block_count: 1 };
        let abs = fe.to_absolute_block(ag_blocks);
        assert_eq!(abs, 2 * 100 + 15);
        let back = FreeExtent::from_absolute_block(abs, ag_blocks);
        assert_eq!(back.ag_num, 2);
        assert_eq!(back.ag_block, 15);
    }
}
