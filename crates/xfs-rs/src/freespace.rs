//! Free Space B+Tree operations for XFS write support.
//!
//! XFS uses two B+trees per Allocation Group to manage free space:
//! - BNO tree: Sorted by block number (for adjacency lookups)
//! - CNT tree: Sorted by extent count (for size-based allocation)
//!
//! This module provides read/write operations for these trees.

extern crate alloc;

use alloc::{vec, vec::Vec};

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Free space B+tree record (same for BNO and CNT trees).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocRec {
    /// Starting block number (AG-relative).
    pub start_block: u32,
    /// Number of blocks in this free extent.
    pub block_count: u32,
}

impl AllocRec {
    /// Size of an allocation record (8 bytes).
    pub const SIZE: usize = 8;

    /// Parse an allocation record from bytes.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            start_block: buffer.read_be_u32(0)?,
            block_count: buffer.read_be_u32(4)?,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.start_block.to_be_bytes());
        buf[4..8].copy_from_slice(&self.block_count.to_be_bytes());
        buf
    }

    /// Returns the end block (exclusive).
    pub fn end_block(&self) -> u32 {
        self.start_block.saturating_add(self.block_count)
    }

    /// Check if this record is adjacent to another (can be merged).
    pub fn is_adjacent_to(&self, other: &Self) -> bool {
        self.end_block() == other.start_block || other.end_block() == self.start_block
    }
}

/// Free space B+tree key (for BNO tree: block number, for CNT tree: count then
/// block).
#[derive(Debug, Clone, Copy)]
pub struct AllocKey {
    /// For BNO: start block. For CNT: block count.
    pub key1: u32,
    /// For BNO: block count. For CNT: start block (secondary sort).
    pub key2: u32,
}

impl AllocKey {
    /// Size of an allocation key.
    pub const SIZE: usize = 8;

    /// Parse a key from bytes.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            key1: buffer.read_be_u32(0)?,
            key2: buffer.read_be_u32(4)?,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.key1.to_be_bytes());
        buf[4..8].copy_from_slice(&self.key2.to_be_bytes());
        buf
    }

    /// Create a BNO key from a record.
    pub fn from_bno_rec(rec: &AllocRec) -> Self {
        Self {
            key1: rec.start_block,
            key2: rec.block_count,
        }
    }

    /// Create a CNT key from a record.
    pub fn from_cnt_rec(rec: &AllocRec) -> Self {
        Self {
            key1: rec.block_count,
            key2: rec.start_block,
        }
    }
}

/// Pointer in free space B+tree (AG-relative block number).
#[derive(Debug, Clone, Copy)]
pub struct AllocPtr {
    pub block: u32,
}

impl AllocPtr {
    pub const SIZE: usize = 4;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            block: buffer.read_be_u32(0)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.block.to_be_bytes()
    }
}

/// Result of searching for free space.
#[derive(Debug, Clone)]
pub struct FreeSpaceResult {
    /// The free extent found.
    pub extent: AllocRec,
    /// AG number containing this extent.
    pub ag_num: u32,
    /// Path through the BNO tree to this record (for updates).
    pub bno_path: Vec<TreePathEntry>,
    /// Path through the CNT tree to this record (for updates).
    pub cnt_path: Vec<TreePathEntry>,
}

/// Entry in a tree traversal path (for updates).
#[derive(Debug, Clone)]
pub struct TreePathEntry {
    /// Block number of this node.
    pub block_num: u32,
    /// Index of the key/pointer used.
    pub index: u16,
    /// Level in the tree.
    pub level: u16,
}

/// Header for free space B+tree blocks (short format, AG-local).
#[derive(Debug, Clone)]
pub struct AllocBtreeBlock {
    /// Magic number (XFS_ABTB_MAGIC, XFS_ABTC_MAGIC, or CRC variants).
    pub magic: u32,
    /// Level (0 = leaf).
    pub level: u16,
    /// Number of records/keys.
    pub num_recs: u16,
    /// Left sibling (AG-relative, NULLAGBLOCK if none).
    pub left_sibling: u32,
    /// Right sibling (AG-relative, NULLAGBLOCK if none).
    pub right_sibling: u32,
    /// Block number (v5).
    pub block_no: u64,
    /// LSN (v5).
    pub lsn: u64,
    /// UUID (v5).
    pub uuid: [u8; 16],
    /// Owner AG (v5).
    pub owner: u32,
    /// CRC (v5).
    pub crc: u32,
}

impl AllocBtreeBlock {
    /// Offset of the v5 CRC field.
    pub const CRC_OFFSET_V5: usize = 0x34;
    /// V4 header size.
    pub const SIZE_V4: usize = 16;
    /// V5 header size.
    pub const SIZE_V5: usize = 56;

    /// Parse from bytes.
    pub fn parse(buffer: &[u8], is_v5: bool) -> FsResult<Self> {
        let min_size = if is_v5 { Self::SIZE_V5 } else { Self::SIZE_V4 };
        if buffer.len() < min_size {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;
        let legacy_magic = magic == XFS_ABTB_MAGIC || magic == XFS_ABTC_MAGIC;
        let crc_magic = magic == XFS_ABTB_CRC_MAGIC || magic == XFS_ABTC_CRC_MAGIC;
        if (!legacy_magic && !crc_magic) || is_v5 != crc_magic {
            return Err(FsError::InvalidMagic);
        }

        let level = buffer.read_be_u16(4)?;
        let num_recs = buffer.read_be_u16(6)?;
        let left_sibling = buffer.read_be_u32(8)?;
        let right_sibling = buffer.read_be_u32(12)?;

        let (block_no, lsn, uuid, owner, crc) = if is_v5 {
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[32..48]);
            (
                buffer.read_be_u64(16)?,
                buffer.read_be_u64(24)?,
                uuid,
                buffer.read_be_u32(48)?,
                buffer.read_le_u32(52)?,
            )
        } else {
            (0, 0, [0u8; 16], 0, 0)
        };

        Ok(Self {
            magic,
            level,
            num_recs,
            left_sibling,
            right_sibling,
            block_no,
            lsn,
            uuid,
            owner,
            crc,
        })
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self, is_v5: bool) -> Vec<u8> {
        let size = if is_v5 { Self::SIZE_V5 } else { Self::SIZE_V4 };
        let mut buf = vec![0u8; size];

        buf[0..4].copy_from_slice(&self.magic.to_be_bytes());
        buf[4..6].copy_from_slice(&self.level.to_be_bytes());
        buf[6..8].copy_from_slice(&self.num_recs.to_be_bytes());
        buf[8..12].copy_from_slice(&self.left_sibling.to_be_bytes());
        buf[12..16].copy_from_slice(&self.right_sibling.to_be_bytes());

        if is_v5 {
            buf[16..24].copy_from_slice(&self.block_no.to_be_bytes());
            buf[24..32].copy_from_slice(&self.lsn.to_be_bytes());
            buf[32..48].copy_from_slice(&self.uuid);
            buf[48..52].copy_from_slice(&self.owner.to_be_bytes());
            buf[52..56].copy_from_slice(&self.crc.to_le_bytes());
        }

        buf
    }

    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    pub fn header_size(&self, is_v5: bool) -> usize {
        if is_v5 {
            Self::SIZE_V5
        } else {
            Self::SIZE_V4
        }
    }

    /// Returns `true` if this block uses the v5 CRC header.
    pub fn is_v5(&self) -> bool {
        self.magic == XFS_ABTB_CRC_MAGIC || self.magic == XFS_ABTC_CRC_MAGIC
    }

    /// Verifies a v5 allocation B+tree block CRC over the complete block.
    pub fn verify_crc(&self, raw: &[u8]) -> FsResult<()> {
        if !self.is_v5() {
            return Ok(());
        }
        if raw.len() < Self::SIZE_V5 {
            return Err(FsError::BufferTooSmall);
        }
        if raw.read_be_u32(0)? != self.magic {
            return Err(FsError::InvalidMagic);
        }
        crate::crc::verify_crc32c_field(raw, Self::CRC_OFFSET_V5, self.crc, true)
    }

    /// Validates that all declared leaf records fit in the supplied block.
    pub fn validate_leaf_recs(&self, buffer: &[u8], is_v5: bool) -> FsResult<usize> {
        let header_size = self.header_size(is_v5);
        if buffer.len() < header_size {
            return Err(FsError::BufferTooSmall);
        }
        let max_recs = (buffer.len() - header_size) / AllocRec::SIZE;
        let num_recs = self.num_recs as usize;
        if num_recs > max_recs {
            return Err(FsError::Corrupted);
        }
        Ok(num_recs)
    }

    /// Check if this is a BNO tree block.
    pub fn is_bno_tree(&self) -> bool {
        self.magic == XFS_ABTB_MAGIC || self.magic == XFS_ABTB_CRC_MAGIC
    }

    /// Check if this is a CNT tree block.
    pub fn is_cnt_tree(&self) -> bool {
        self.magic == XFS_ABTC_MAGIC || self.magic == XFS_ABTC_CRC_MAGIC
    }
}

/// NULLAGBLOCK constant (indicates no sibling).
pub const NULLAGBLOCK: u32 = 0xFFFFFFFF;

/// Search result from B+tree lookup.
#[derive(Debug)]
pub enum SearchResult {
    /// Exact match found at this index.
    Found(usize),
    /// Not found, but would be inserted at this index.
    NotFound(usize),
}

/// Search a leaf block for a record by start block (BNO tree).
pub fn search_bno_leaf(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    start_block: u32,
    is_v5: bool,
) -> FsResult<SearchResult> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }
    header.verify_crc(buffer)?;
    let header_size = header.header_size(is_v5);
    let num_recs = header.validate_leaf_recs(buffer, is_v5)?;

    // Binary search
    let mut left = 0;
    let mut right = num_recs;

    while left < right {
        let mid = left + (right - left) / 2;
        let rec_offset = header_size + mid * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;

        if rec.start_block == start_block {
            return Ok(SearchResult::Found(mid));
        } else if rec.start_block < start_block {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    Ok(SearchResult::NotFound(left))
}

/// Search a leaf block for a record by count (CNT tree).
pub fn search_cnt_leaf(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    block_count: u32,
    start_block: u32,
    is_v5: bool,
) -> FsResult<SearchResult> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }
    header.verify_crc(buffer)?;
    let header_size = header.header_size(is_v5);
    let num_recs = header.validate_leaf_recs(buffer, is_v5)?;

    // Binary search by count, then by start_block
    let mut left = 0;
    let mut right = num_recs;

    while left < right {
        let mid = left + (right - left) / 2;
        let rec_offset = header_size + mid * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;

        if rec.block_count == block_count && rec.start_block == start_block {
            return Ok(SearchResult::Found(mid));
        } else if rec.block_count < block_count
            || (rec.block_count == block_count && rec.start_block < start_block)
        {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    Ok(SearchResult::NotFound(left))
}

/// Find the first free extent with at least `min_blocks` blocks.
pub fn find_free_extent_by_size(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    min_blocks: u32,
    is_v5: bool,
) -> FsResult<Option<(AllocRec, usize)>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    header.verify_crc(buffer)?;
    let header_size = header.header_size(is_v5);
    let num_recs = header.validate_leaf_recs(buffer, is_v5)?;

    // In CNT tree, records are sorted by count ascending
    // Binary search for the first record with count >= min_blocks
    let mut left = 0;
    let mut right = num_recs;

    while left < right {
        let mid = left + (right - left) / 2;
        let rec_offset = header_size + mid * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;

        if rec.block_count < min_blocks {
            left = mid + 1;
        } else {
            right = mid;
        }
    }

    if left < num_recs {
        let rec_offset = header_size + left * AllocRec::SIZE;
        let rec = AllocRec::parse(&buffer[rec_offset..])?;
        if rec.block_count >= min_blocks {
            return Ok(Some((rec, left)));
        }
    }

    Ok(None)
}

/// Read all records from a leaf block.
pub fn read_leaf_records(
    buffer: &[u8],
    header: &AllocBtreeBlock,
    is_v5: bool,
) -> FsResult<Vec<AllocRec>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    header.verify_crc(buffer)?;
    let header_size = header.header_size(is_v5);
    let num_recs = header.validate_leaf_recs(buffer, is_v5)?;
    let mut records = Vec::with_capacity(num_recs);

    for i in 0..num_recs {
        let rec_offset = header_size + i * AllocRec::SIZE;
        records.push(AllocRec::parse(&buffer[rec_offset..])?);
    }

    Ok(records)
}

/// Write records to a leaf block buffer.
pub fn write_leaf_records(
    buffer: &mut [u8],
    header: &AllocBtreeBlock,
    records: &[AllocRec],
    is_v5: bool,
) -> FsResult<()> {
    // Validate the complete update before mutating the buffer.
    let parsed = AllocBtreeBlock::parse(buffer, is_v5)?;
    if parsed.magic != header.magic {
        return Err(FsError::InvalidMagic);
    }
    if records.len() > u16::MAX as usize {
        return Err(FsError::Corrupted);
    }
    let header_size = header.header_size(is_v5);
    let records_size = records
        .len()
        .checked_mul(AllocRec::SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;
    let records_end = header_size
        .checked_add(records_size)
        .ok_or(FsError::ArithmeticOverflow)?;
    if records_end > buffer.len() {
        return Err(FsError::BufferTooSmall);
    }

    for (i, rec) in records.iter().enumerate() {
        let rec_offset = header_size + i * AllocRec::SIZE;
        buffer[rec_offset..rec_offset + AllocRec::SIZE].copy_from_slice(&rec.to_bytes());
    }

    // bb_numrecs is big-endian and is part of the v5 checksum.
    buffer[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    if is_v5 {
        crate::crc::recalculate_crc_le(buffer, AllocBtreeBlock::CRC_OFFSET_V5)
            .ok_or(FsError::BufferTooSmall)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v5_alloc_block() -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&XFS_ABTB_CRC_MAGIC.to_be_bytes());
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());
        let crc =
            crate::crc::xfs_crc32c_with_zeroed_field(&buf, AllocBtreeBlock::CRC_OFFSET_V5).unwrap();
        buf[AllocBtreeBlock::CRC_OFFSET_V5..AllocBtreeBlock::CRC_OFFSET_V5 + 4]
            .copy_from_slice(&crc.to_le_bytes());
        buf
    }

    #[test]
    fn alloc_btree_validates_magic_version_and_crc() {
        let buf = v5_alloc_block();
        let header = AllocBtreeBlock::parse(&buf, true).unwrap();
        assert!(header.verify_crc(&buf).is_ok());
        assert!(matches!(
            AllocBtreeBlock::parse(&buf, false),
            Err(FsError::InvalidMagic)
        ));

        let mut corrupted = buf;
        corrupted[100] ^= 1;
        assert!(matches!(
            header.verify_crc(&corrupted),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn leaf_record_counts_are_bounds_checked() {
        let mut buf = [0u8; AllocBtreeBlock::SIZE_V4];
        buf[0..4].copy_from_slice(&XFS_ABTB_MAGIC.to_be_bytes());
        buf[6..8].copy_from_slice(&3u16.to_be_bytes());
        let header = AllocBtreeBlock::parse(&buf, false).unwrap();
        assert!(matches!(
            read_leaf_records(&buf, &header, false),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn write_leaf_records_updates_count_and_crc() {
        let mut buf = v5_alloc_block();
        let header = AllocBtreeBlock::parse(&buf, true).unwrap();
        let records = [
            AllocRec {
                start_block: 10,
                block_count: 20,
            },
            AllocRec {
                start_block: 40,
                block_count: 50,
            },
        ];
        write_leaf_records(&mut buf, &header, &records, true).unwrap();

        let updated = AllocBtreeBlock::parse(&buf, true).unwrap();
        assert_eq!(updated.num_recs, 2);
        assert_eq!(read_leaf_records(&buf, &updated, true).unwrap(), records);
        assert!(updated.verify_crc(&buf).is_ok());

        let stored = u32::from_le_bytes([
            buf[AllocBtreeBlock::CRC_OFFSET_V5],
            buf[AllocBtreeBlock::CRC_OFFSET_V5 + 1],
            buf[AllocBtreeBlock::CRC_OFFSET_V5 + 2],
            buf[AllocBtreeBlock::CRC_OFFSET_V5 + 3],
        ]);
        assert_eq!(stored, updated.crc);
    }

    #[test]
    fn failed_leaf_write_does_not_partially_update_buffer() {
        let mut buf = v5_alloc_block();
        let original = buf.clone();
        let header = AllocBtreeBlock::parse(&buf, true).unwrap();
        let records = vec![
            AllocRec {
                start_block: 1,
                block_count: 1,
            };
            100
        ];
        assert!(matches!(
            write_leaf_records(&mut buf, &header, &records, true),
            Err(FsError::BufferTooSmall)
        ));
        assert_eq!(buf, original);
    }
}
