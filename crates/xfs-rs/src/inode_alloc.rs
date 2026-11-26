//! Inode Allocation for XFS write support.
//!
//! XFS uses B+trees per Allocation Group for inode management:
//! - IBT (Inode B+Tree): Tracks allocated inode chunks
//! - FIBT (Free Inode B+Tree): Tracks free inodes within allocated chunks
//!
//! This module provides inode allocation and deallocation functionality.

extern crate alloc;

use alloc::vec::Vec;

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Number of inodes per inode chunk.
pub const XFS_INODES_PER_CHUNK: u32 = 64;

/// Inode B+tree record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeBtreeRec {
    /// Starting inode number (AG-relative).
    pub start_ino: u32,
    /// Count of free inodes in this chunk (FIBT) or hole count (IBT).
    pub free_count: u32,
    /// Free inode bitmap (64 bits for 64 inodes).
    pub free_bitmap: u64,
}

impl InodeBtreeRec {
    pub const SIZE: usize = 16;

    /// Parse from bytes.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }

        let record = Self {
            start_ino: buffer.read_be_u32(0)?,
            free_count: buffer.read_be_u32(4)?,
            free_bitmap: buffer.read_be_u64(8)?,
        };
        if record.free_count != record.free_bitmap.count_ones() {
            return Err(FsError::Corrupted);
        }
        Ok(record)
    }

    /// Serialize to bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0..4].copy_from_slice(&self.start_ino.to_be_bytes());
        buf[4..8].copy_from_slice(&self.free_count.to_be_bytes());
        buf[8..16].copy_from_slice(&self.free_bitmap.to_be_bytes());
        buf
    }

    fn bit_for_index(index: u32) -> Option<u64> {
        (index < XFS_INODES_PER_CHUNK).then(|| 1u64 << (63 - index))
    }

    /// Check if a specific inode in the chunk is free.
    pub fn is_inode_free(&self, index: u32) -> bool {
        Self::bit_for_index(index).is_some_and(|mask| self.free_bitmap & mask != 0)
    }

    /// Get the first (lowest-numbered) free inode in this chunk.
    pub fn first_free_inode(&self) -> Option<u32> {
        if self.free_count == 0 || self.free_bitmap == 0 {
            return None;
        }
        let index = self.free_bitmap.leading_zeros();
        self.start_ino.checked_add(index)
    }

    /// Mark an inode as allocated (clear the free bit).
    pub fn allocate_inode(&mut self, index: u32) -> bool {
        let Some(mask) = Self::bit_for_index(index) else {
            return false;
        };
        if self.free_bitmap & mask == 0 {
            return false; // Already allocated
        }
        self.free_bitmap &= !mask;
        self.free_count = self.free_count.saturating_sub(1);
        true
    }

    /// Mark an inode as free (set the free bit).
    pub fn free_inode(&mut self, index: u32) -> bool {
        let Some(mask) = Self::bit_for_index(index) else {
            return false;
        };
        if self.free_bitmap & mask != 0 {
            return false; // Already free
        }
        self.free_bitmap |= mask;
        self.free_count = self.free_count.saturating_add(1);
        true
    }
}

/// Sparse inode B+tree record (`XFS_SB_FEAT_INCOMPAT_SPINODES`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SparseInodeBtreeRec {
    pub start_ino: u32,
    /// Each bit marks four physically absent inodes.
    pub holemask: u16,
    pub inode_count: u8,
    pub free_count: u8,
    pub free_bitmap: u64,
}

impl SparseInodeBtreeRec {
    const INODES_PER_HOLEMASK_BIT: u32 = 4;
    pub const SIZE: usize = 16;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        let record = Self {
            start_ino: buffer.read_be_u32(0)?,
            holemask: buffer.read_be_u16(4)?,
            inode_count: buffer[6],
            free_count: buffer[7],
            free_bitmap: buffer.read_be_u64(8)?,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut buffer = [0u8; Self::SIZE];
        buffer[0..4].copy_from_slice(&self.start_ino.to_be_bytes());
        buffer[4..6].copy_from_slice(&self.holemask.to_be_bytes());
        buffer[6] = self.inode_count;
        buffer[7] = self.free_count;
        buffer[8..16].copy_from_slice(&self.free_bitmap.to_be_bytes());
        buffer
    }

    pub fn validate(&self) -> FsResult<()> {
        let holes = self.expanded_holes();
        let physical = !holes;
        if self.inode_count != physical.count_ones() as u8
            || self.free_bitmap & holes != holes
            || self.free_count != (self.free_bitmap & physical).count_ones() as u8
        {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }

    fn expanded_holes(&self) -> u64 {
        let mut holes = 0u64;
        for bit in 0..16 {
            if self.holemask & (1 << bit) != 0 {
                holes |= ((1u64 << Self::INODES_PER_HOLEMASK_BIT) - 1)
                    << (60 - bit * Self::INODES_PER_HOLEMASK_BIT);
            }
        }
        holes
    }

    fn bit_for_index(index: u32) -> Option<u64> {
        (index < 64).then(|| 1u64 << (63 - index))
    }

    pub fn first_free_inode(&self) -> Option<u32> {
        let available = self.free_bitmap & !self.expanded_holes();
        if self.free_count == 0 || available == 0 {
            return None;
        }
        let index = available.leading_zeros();
        self.start_ino.checked_add(index)
    }

    pub fn allocate_inode(&mut self, index: u32) -> bool {
        let Some(mask) = Self::bit_for_index(index) else {
            return false;
        };
        if self.expanded_holes() & mask != 0 || self.free_bitmap & mask == 0 {
            return false;
        }
        self.free_bitmap &= !mask;
        self.free_count = self.free_count.saturating_sub(1);
        true
    }

    pub fn free_inode(&mut self, index: u32) -> bool {
        let Some(mask) = Self::bit_for_index(index) else {
            return false;
        };
        if self.expanded_holes() & mask != 0 || self.free_bitmap & mask != 0 {
            return false;
        }
        self.free_bitmap |= mask;
        self.free_count = self.free_count.saturating_add(1);
        true
    }
}

/// Inode B+tree key (for internal nodes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeBtreeKey {
    /// Starting inode number.
    pub start_ino: u32,
}

impl InodeBtreeKey {
    pub const SIZE: usize = 4;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            start_ino: buffer.read_be_u32(0)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.start_ino.to_be_bytes()
    }
}

/// Inode B+tree pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InodeBtreePtr {
    /// Block number (AG-relative).
    pub block: u32,
}

impl InodeBtreePtr {
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

/// Inode B+tree block header (short form - AG local).
#[derive(Debug, Clone)]
pub struct InodeBtreeBlock {
    /// Magic number.
    pub magic: u32,
    /// B+tree level (0 = leaf).
    pub level: u16,
    /// Number of records.
    pub num_recs: u16,
    /// Left sibling block.
    pub left_sibling: u32,
    /// Right sibling block.
    pub right_sibling: u32,
    /// Block number (v5 only).
    pub blkno: u64,
    /// Log sequence number (v5 only).
    pub lsn: u64,
    /// UUID (v5 only).
    pub uuid: [u8; 16],
    /// Owner AG (v5 only).
    pub owner: u32,
    /// CRC (v5 only).
    pub crc: u32,
}

impl InodeBtreeBlock {
    /// Offset of the v5 CRC field.
    pub const CRC_OFFSET_V5: usize = 0x34;
    /// Header size for v4.
    pub const V4_SIZE: usize = 16;
    /// Header size for v5.
    pub const V5_SIZE: usize = 56;

    /// Parse header from buffer.
    pub fn parse(buffer: &[u8], is_v5: bool) -> FsResult<Self> {
        let min_size = if is_v5 { Self::V5_SIZE } else { Self::V4_SIZE };
        if buffer.len() < min_size {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;

        // Validate magic
        let valid_magic = matches!(
            magic,
            XFS_IBT_MAGIC | XFS_IBT_CRC_MAGIC | XFS_FIBT_MAGIC | XFS_FIBT_CRC_MAGIC
        );
        if !valid_magic {
            return Err(FsError::InvalidMagic);
        }
        let crc_magic = magic == XFS_IBT_CRC_MAGIC || magic == XFS_FIBT_CRC_MAGIC;
        if is_v5 != crc_magic {
            return Err(FsError::InvalidMagic);
        }

        let level = buffer.read_be_u16(4)?;
        let num_recs = buffer.read_be_u16(6)?;
        let left_sibling = buffer.read_be_u32(8)?;
        let right_sibling = buffer.read_be_u32(12)?;

        let (blkno, lsn, uuid, owner, crc) = if is_v5 {
            let blkno = buffer.read_be_u64(16)?;
            let lsn = buffer.read_be_u64(24)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[32..48]);
            let owner = buffer.read_be_u32(48)?;
            let crc = buffer.read_le_u32(Self::CRC_OFFSET_V5)?;
            (blkno, lsn, uuid, owner, crc)
        } else {
            (0, 0, [0u8; 16], 0, 0)
        };

        Ok(Self {
            magic,
            level,
            num_recs,
            left_sibling,
            right_sibling,
            blkno,
            lsn,
            uuid,
            owner,
            crc,
        })
    }

    /// Check if this is a leaf block.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Check if this is an IBT (allocated inodes) or FIBT (free inodes).
    pub fn is_fibt(&self) -> bool {
        self.magic == XFS_FIBT_MAGIC || self.magic == XFS_FIBT_CRC_MAGIC
    }

    /// Get the header size.
    pub fn header_size(&self, is_v5: bool) -> usize {
        if is_v5 {
            Self::V5_SIZE
        } else {
            Self::V4_SIZE
        }
    }

    /// Returns `true` if this block uses the v5 CRC header.
    pub fn is_v5(&self) -> bool {
        self.magic == XFS_IBT_CRC_MAGIC || self.magic == XFS_FIBT_CRC_MAGIC
    }

    /// Verifies a v5 inode B+tree block CRC over the complete block.
    pub fn verify_crc(&self, raw: &[u8]) -> FsResult<()> {
        if !self.is_v5() {
            return Ok(());
        }
        if raw.len() < Self::V5_SIZE {
            return Err(FsError::BufferTooSmall);
        }
        if raw.read_be_u32(0)? != self.magic {
            return Err(FsError::InvalidMagic);
        }
        crate::crc::verify_crc32c_field(raw, Self::CRC_OFFSET_V5, self.crc, true)
    }
}

/// Read leaf records from an inode B+tree block.
pub fn read_inode_btree_records(
    buffer: &[u8],
    header: &InodeBtreeBlock,
    is_v5: bool,
) -> FsResult<Vec<InodeBtreeRec>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    header.verify_crc(buffer)?;
    let header_size = header.header_size(is_v5);
    if buffer.len() < header_size {
        return Err(FsError::BufferTooSmall);
    }
    let max_recs = (buffer.len() - header_size) / InodeBtreeRec::SIZE;
    let num_recs = header.num_recs as usize;
    if num_recs > max_recs {
        return Err(FsError::Corrupted);
    }
    let mut records = Vec::with_capacity(num_recs);

    for i in 0..num_recs {
        let rec_offset = header_size + i * InodeBtreeRec::SIZE;
        records.push(InodeBtreeRec::parse(&buffer[rec_offset..])?);
    }

    Ok(records)
}

/// Read sparse inode B+tree records from a leaf block.
pub fn read_sparse_inode_btree_records(
    buffer: &[u8],
    header: &InodeBtreeBlock,
    is_v5: bool,
) -> FsResult<Vec<SparseInodeBtreeRec>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }
    header.verify_crc(buffer)?;
    let header_size = header.header_size(is_v5);
    let max_recs = (buffer.len() - header_size) / SparseInodeBtreeRec::SIZE;
    if header.num_recs as usize > max_recs {
        return Err(FsError::Corrupted);
    }
    let mut records = Vec::with_capacity(header.num_recs as usize);
    for index in 0..header.num_recs as usize {
        let offset = header_size + index * SparseInodeBtreeRec::SIZE;
        records.push(SparseInodeBtreeRec::parse(&buffer[offset..])?);
    }
    Ok(records)
}

/// Find a free inode in the FIBT.
///
/// Returns (chunk_record, inode_index_in_chunk) if found.
pub fn find_free_inode(
    buffer: &[u8],
    header: &InodeBtreeBlock,
    is_v5: bool,
) -> FsResult<Option<(InodeBtreeRec, u32)>> {
    if !header.is_leaf() || !header.is_fibt() {
        return Err(FsError::InvalidBlockType);
    }

    let records = read_inode_btree_records(buffer, header, is_v5)?;

    for rec in records {
        if rec.free_count > 0 {
            if let Some(idx) = rec.first_free_inode() {
                let local_idx = idx - rec.start_ino;
                return Ok(Some((rec, local_idx)));
            }
        }
    }

    Ok(None)
}

/// Find a free inode in the IBT (Inode B+tree).
///
/// This is used when FIBT (Free Inode B+tree) is not available.
/// The IBT contains ALL allocated inode chunks, so we scan for chunks
/// that have at least one free inode (free_bitmap != 0).
///
/// Returns (chunk_record, inode_index_in_chunk) if found.
pub fn find_free_inode_in_ibt(
    buffer: &[u8],
    header: &InodeBtreeBlock,
    is_v5: bool,
) -> FsResult<Option<(InodeBtreeRec, u32)>> {
    if !header.is_leaf() {
        return Err(FsError::InvalidBlockType);
    }

    // IBT records have the same format as FIBT records
    let records = read_inode_btree_records(buffer, header, is_v5)?;

    for rec in records {
        // In IBT, free_bitmap shows which inodes are free (bit set = free)
        // free_count may be used differently but free_bitmap is reliable
        if rec.free_bitmap != 0 {
            if let Some(idx) = rec.first_free_inode() {
                let local_idx = idx - rec.start_ino;
                return Ok(Some((rec, local_idx)));
            }
        }
    }

    Ok(None)
}

/// Write leaf records to an inode B+tree block.
pub fn write_inode_btree_records(
    buffer: &mut [u8],
    header: &InodeBtreeBlock,
    records: &[InodeBtreeRec],
    is_v5: bool,
) -> FsResult<()> {
    let parsed = InodeBtreeBlock::parse(buffer, is_v5)?;
    if parsed.magic != header.magic {
        return Err(FsError::InvalidMagic);
    }
    if records.len() > u16::MAX as usize {
        return Err(FsError::Corrupted);
    }
    let header_size = header.header_size(is_v5);
    let records_size = records
        .len()
        .checked_mul(InodeBtreeRec::SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;
    let records_end = header_size
        .checked_add(records_size)
        .ok_or(FsError::ArithmeticOverflow)?;
    if records_end > buffer.len() {
        return Err(FsError::BufferTooSmall);
    }

    for (i, rec) in records.iter().enumerate() {
        let rec_offset = header_size + i * InodeBtreeRec::SIZE;
        buffer[rec_offset..rec_offset + InodeBtreeRec::SIZE].copy_from_slice(&rec.to_bytes());
    }
    buffer[6..8].copy_from_slice(&(records.len() as u16).to_be_bytes());
    if is_v5 {
        crate::crc::recalculate_crc_le(buffer, InodeBtreeBlock::CRC_OFFSET_V5)
            .ok_or(FsError::BufferTooSmall)?;
    }
    Ok(())
}

/// Calculate the absolute inode number from AG number and AG-relative inode.
pub fn make_absolute_inode(
    ag_num: u32,
    ag_ino: u32,
    ag_block_log: u8,
    inode_per_block_log: u8,
) -> u64 {
    let shift = ag_block_log + inode_per_block_log;
    ((ag_num as u64) << shift) | (ag_ino as u64)
}

/// Extract AG number and AG-relative inode from absolute inode number.
pub fn split_inode_number(ino: u64, ag_block_log: u8, inode_per_block_log: u8) -> (u32, u32) {
    let shift = ag_block_log + inode_per_block_log;
    let ag_num = (ino >> shift) as u32;
    let ag_ino = (ino & ((1u64 << shift) - 1)) as u32;
    (ag_num, ag_ino)
}

/// Create a new empty inode core with default values and legacy timestamps.
pub fn create_empty_inode_core(
    mode: u16,
    uid: u32,
    gid: u32,
    version: u8,
    ino: u64,
    uuid: &[u8; 16],
) -> crate::InodeCore {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    create_empty_inode_core_at(
        mode,
        uid,
        gid,
        version,
        ino,
        uuid,
        false,
        now.as_secs().min(i32::MAX as u64) as i64,
        now.subsec_nanos(),
    )
    .expect("current time fits legacy XFS timestamps")
}

/// Create an empty inode core with explicit timestamp encoding.
///
/// `uuid` must be the filesystem metadata UUID on v5 filesystems.  Bigtime is
/// recorded both in the timestamp words and in `di_flags2`, as required by the
/// on-disk format.
#[allow(clippy::too_many_arguments)]
pub fn create_empty_inode_core_at(
    mode: u16,
    uid: u32,
    gid: u32,
    version: u8,
    ino: u64,
    uuid: &[u8; 16],
    has_bigtime: bool,
    unix_seconds: i64,
    nanoseconds: u32,
) -> FsResult<crate::InodeCore> {
    let (sec, nsec) = crate::InodeCore::unix_to_timestamp(unix_seconds, nanoseconds, has_bigtime)?;
    Ok(crate::InodeCore {
        magic: XFS_DINODE_MAGIC,
        mode,
        version,
        format: crate::InodeFormat::Local,
        onlink: 0,
        uid,
        gid,
        nlink: 1,
        projid_lo: 0,
        projid_hi: 0,
        atime_sec: sec,
        atime_nsec: nsec,
        mtime_sec: sec,
        mtime_nsec: nsec,
        ctime_sec: sec,
        ctime_nsec: nsec,
        size: 0,
        nblocks: 0,
        extsize: 0,
        nextents: 0,
        anextents: 0,
        forkoff: 0,
        aformat: crate::InodeFormat::Extents as u8,
        dmevmask: 0,
        dmstate: 0,
        flags: 0,
        gen: 1,
        next_unlinked: 0xFFFFFFFF, // NULLAGINO
        crc: 0,
        changecount: 1,
        lsn: 0,
        flags2: if has_bigtime { 1 << 3 } else { 0 },
        cowextsize: 0,
        crtime_sec: sec,
        crtime_nsec: nsec,
        ino,
        uuid: *uuid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inode_btree_rec_parse() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&100u32.to_be_bytes()); // start_ino
        buf[4..8].copy_from_slice(&5u32.to_be_bytes()); // free_count
        buf[8..16].copy_from_slice(&0x1Fu64.to_be_bytes()); // free_bitmap
                                                            // (first 5 bits
                                                            // set)

        let rec = InodeBtreeRec::parse(&buf).unwrap();
        assert_eq!(rec.start_ino, 100);
        assert_eq!(rec.free_count, 5);
        assert!(rec.is_inode_free(59));
        assert!(rec.is_inode_free(63));
        assert!(!rec.is_inode_free(58));
    }

    #[test]
    fn test_inode_allocation() {
        let mut rec = InodeBtreeRec {
            start_ino: 64,
            free_count: 64,
            free_bitmap: u64::MAX, // All free
        };

        // First free should be index 0
        assert_eq!(rec.first_free_inode(), Some(64));

        // Allocate it
        assert!(rec.allocate_inode(0));
        assert_eq!(rec.free_count, 63);
        assert!(!rec.is_inode_free(0));

        // Next free should be index 1
        assert_eq!(rec.first_free_inode(), Some(65));
    }

    #[test]
    fn inode_btree_crc_is_little_endian_and_version_checked() {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&XFS_IBT_CRC_MAGIC.to_be_bytes());
        let crc =
            crate::crc::xfs_crc32c_with_zeroed_field(&buf, InodeBtreeBlock::CRC_OFFSET_V5).unwrap();
        buf[InodeBtreeBlock::CRC_OFFSET_V5..InodeBtreeBlock::CRC_OFFSET_V5 + 4]
            .copy_from_slice(&crc.to_le_bytes());

        let header = InodeBtreeBlock::parse(&buf, true).unwrap();
        assert_eq!(header.crc, crc);
        assert!(header.verify_crc(&buf).is_ok());
        assert!(matches!(
            InodeBtreeBlock::parse(&buf, false),
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
    fn inode_btree_write_is_atomic_and_updates_count_crc() {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&XFS_IBT_CRC_MAGIC.to_be_bytes());
        let crc =
            crate::crc::xfs_crc32c_with_zeroed_field(&buf, InodeBtreeBlock::CRC_OFFSET_V5).unwrap();
        buf[InodeBtreeBlock::CRC_OFFSET_V5..InodeBtreeBlock::CRC_OFFSET_V5 + 4]
            .copy_from_slice(&crc.to_le_bytes());
        let header = InodeBtreeBlock::parse(&buf, true).unwrap();
        let original = buf.clone();
        let too_many = vec![
            InodeBtreeRec {
                start_ino: 0,
                free_count: 0,
                free_bitmap: 0,
            };
            100
        ];
        assert!(matches!(
            write_inode_btree_records(&mut buf, &header, &too_many, true),
            Err(FsError::BufferTooSmall)
        ));
        assert_eq!(buf, original);

        let records = [InodeBtreeRec {
            start_ino: 64,
            free_count: 1,
            free_bitmap: 1,
        }];
        write_inode_btree_records(&mut buf, &header, &records, true).unwrap();
        let updated = InodeBtreeBlock::parse(&buf, true).unwrap();
        assert_eq!(updated.num_recs, 1);
        assert!(updated.verify_crc(&buf).is_ok());
        assert_eq!(
            read_inode_btree_records(&buf, &updated, true).unwrap(),
            records
        );
    }

    #[test]
    fn inode_btree_does_not_silently_truncate_records() {
        let mut buf = [0u8; InodeBtreeBlock::V4_SIZE];
        buf[0..4].copy_from_slice(&XFS_IBT_MAGIC.to_be_bytes());
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());
        let header = InodeBtreeBlock::parse(&buf, false).unwrap();
        assert!(matches!(
            read_inode_btree_records(&buf, &header, false),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn empty_inode_core_encodes_bigtime_and_metadata_uuid() {
        let uuid = [0xA5; 16];
        let core = create_empty_inode_core_at(
            0o100644,
            0,
            0,
            3,
            123,
            &uuid,
            true,
            1_700_000_000,
            123_456_789,
        )
        .unwrap();
        assert_eq!(core.flags2 & (1 << 3), 1 << 3);
        assert_eq!(core.uuid, uuid);
        assert_eq!(core.mtime(true), (1_700_000_000, 123_456_789));
    }

    #[test]
    fn sparse_inode_record_skips_physical_holes() {
        let mut record = SparseInodeBtreeRec {
            start_ino: 64,
            holemask: 1 << 2, // inodes 8..11 are absent
            inode_count: 60,
            free_count: 60,
            // Hole bits are set in ir_free even though they are not physical.
            free_bitmap: u64::MAX,
        };
        record.validate().unwrap();
        assert_eq!(record.first_free_inode(), Some(64));
        assert!(record.allocate_inode(0));
        assert!(!record.allocate_inode(8));
        assert!(!record.free_inode(8));
        let raw = record.to_bytes();
        assert_eq!(SparseInodeBtreeRec::parse(&raw).unwrap(), record);
    }

    #[test]
    fn test_inode_number_split() {
        let ag_block_log = 16u8;
        let inode_per_block_log = 4u8;

        let (ag, ag_ino) = split_inode_number(0x0001_2345, ag_block_log, inode_per_block_log);
        let reconstructed = make_absolute_inode(ag, ag_ino, ag_block_log, inode_per_block_log);

        assert_eq!(reconstructed, 0x0001_2345);
    }
}
