//! XFS B+Tree structures.
//!
//! XFS uses B+Trees for:
//! - Large file extent lists (BMBT)
//! - Large directories
//! - Free space tracking
//! - Inode allocation

#[cfg(feature = "alloc")]
extern crate alloc;

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// B+Tree block types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BtreeType {
    /// Block map B+tree (for file extents).
    BlockMap,
    /// Directory B+tree.
    Directory,
    /// Free space by block number.
    AllocByBlock,
    /// Free space by size.
    AllocBySize,
    /// Inode B+tree.
    Inode,
    /// Reverse map B+tree.
    ReverseMap,
    /// Reference count B+tree.
    RefCount,
}

/// B+Tree block header (long format, for BMBT).
#[derive(Debug, Clone)]
pub struct BtreeBlockLong {
    /// Magic number.
    pub magic: u32,
    /// B+tree level (0 = leaf).
    pub level: u16,
    /// Number of records/keys.
    pub num_recs: u16,
    /// Left sibling block.
    pub left_sibling: u64,
    /// Right sibling block.
    pub right_sibling: u64,
    /// Block number (v5).
    pub block_no: u64,
    /// Log sequence number (v5).
    pub lsn: u64,
    /// UUID (v5).
    pub uuid: [u8; 16],
    /// Owner inode (v5).
    pub owner: u64,
    /// CRC (v5).
    pub crc: u32,
}

impl BtreeBlockLong {
    /// Offset of the v5 CRC field.
    pub const CRC_OFFSET_V5: usize = 0x40;
    /// Size of v4 header.
    pub const SIZE_V4: usize = 24;
    /// Size of v5 header.
    pub const SIZE_V5: usize = 72;

    /// Parses a long-format B+tree block header.
    pub fn parse(buffer: &[u8], is_v5: bool) -> FsResult<Self> {
        let min_size = if is_v5 { Self::SIZE_V5 } else { Self::SIZE_V4 };
        if buffer.len() < min_size {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;
        // Validate magic and consistency with the filesystem version.
        if magic != XFS_BMAP_MAGIC && magic != XFS_BMAP_CRC_MAGIC {
            return Err(FsError::InvalidMagic);
        }
        if is_v5 != (magic == XFS_BMAP_CRC_MAGIC) {
            return Err(FsError::InvalidMagic);
        }

        let level = buffer.read_be_u16(4)?;
        let num_recs = buffer.read_be_u16(6)?;
        let left_sibling = buffer.read_be_u64(8)?;
        let right_sibling = buffer.read_be_u64(16)?;

        let (block_no, lsn, uuid, owner, crc) = if is_v5 {
            let block_no = buffer.read_be_u64(24)?;
            let lsn = buffer.read_be_u64(32)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[40..56]);
            let owner = buffer.read_be_u64(56)?;
            let crc = buffer.read_le_u32(64)?;
            (block_no, lsn, uuid, owner, crc)
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

    /// Verifies a v5 BMBT block CRC over the complete block buffer.
    pub fn verify_crc(&self, raw: &[u8]) -> FsResult<()> {
        if !self.is_v5() {
            return Ok(());
        }
        if raw.len() < Self::SIZE_V5 {
            return Err(FsError::BufferTooSmall);
        }
        if raw.read_be_u32(0)? != XFS_BMAP_CRC_MAGIC {
            return Err(FsError::InvalidMagic);
        }
        crate::crc::verify_crc32c_field(raw, Self::CRC_OFFSET_V5, self.crc, true)
    }

    /// Returns `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }

    /// Returns `true` if this is a v5 block.
    pub fn is_v5(&self) -> bool {
        self.magic == XFS_BMAP_CRC_MAGIC
    }

    /// Returns the header size.
    pub fn header_size(&self) -> usize {
        if self.is_v5() {
            Self::SIZE_V5
        } else {
            Self::SIZE_V4
        }
    }

    /// Maximum number of records a block of `block_size` bytes can hold.
    ///
    /// XFS lays out a bmbt block as `header | keys | pointers`, where the
    /// pointer array is aligned after the *maximum* key capacity of the block,
    /// not after `num_recs`.  For both leaves and internal nodes the per-record
    /// footprint used for this computation is 16 bytes (one key + one pointer,
    /// or one extent record).
    pub fn max_recs(&self, block_size: usize) -> FsResult<usize> {
        let header_size = self.header_size();
        let payload = block_size
            .checked_sub(header_size)
            .ok_or(FsError::Corrupted)?;
        Ok(payload / (BmbtKey::SIZE + BmbtPtr::SIZE))
    }

    /// Byte offset of the pointer array inside a block of `block_size` bytes.
    pub fn ptrs_offset(&self, block_size: usize) -> FsResult<usize> {
        let max_recs = self.max_recs(block_size)?;
        self.header_size()
            .checked_add(
                max_recs
                    .checked_mul(BmbtKey::SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)
    }

    /// Validates that `num_recs` fits this block and that all records are
    /// entirely inside the buffer.
    pub fn validate_recs(&self, buffer: &[u8]) -> FsResult<usize> {
        let max_recs = self.max_recs(buffer.len())?;
        if self.num_recs as usize > max_recs {
            return Err(FsError::Corrupted);
        }
        Ok(self.num_recs as usize)
    }

    /// Finds the child block pointer for a given file offset in an intermediate
    /// node.
    pub fn get_ptr_for_offset(&self, buffer: &[u8], file_offset: u64) -> FsResult<u64> {
        if self.level == 0 {
            return Err(FsError::InvalidBlockType);
        }

        let header_size = self.header_size();
        let keys_offset = header_size;
        let num_recs_usize = self.validate_recs(buffer)?;
        let ptrs_offset = self.ptrs_offset(buffer.len())?;

        // Validate that the buffer is large enough for all records
        let min_buffer_size = ptrs_offset
            .checked_add(
                num_recs_usize
                    .checked_mul(BmbtPtr::SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        if buffer.len() < min_buffer_size {
            return Err(FsError::BufferTooSmall);
        }

        // Binary search for the largest key <= file_offset
        // Handle the case where there are no records
        if num_recs_usize == 0 {
            return Err(FsError::NotFound);
        }

        // Binary search is only valid for strictly increasing keys.
        let mut previous_key = None;
        for i in 0..num_recs_usize {
            let key_offset = keys_offset
                .checked_add(
                    i.checked_mul(BmbtKey::SIZE)
                        .ok_or(FsError::ArithmeticOverflow)?,
                )
                .ok_or(FsError::ArithmeticOverflow)?;
            let key = BmbtKey::parse(&buffer[key_offset..])?;
            if previous_key.is_some_and(|previous| previous >= key.file_offset) {
                return Err(FsError::Corrupted);
            }
            previous_key = Some(key.file_offset);
        }

        let mut left = 0;
        let mut right = num_recs_usize;
        let mut result_idx = None;

        // Perform binary search - using exclusive upper bound to avoid
        // underflow
        while left < right {
            let mid = left + (right - left) / 2;

            // Validate buffer bounds before parsing
            if keys_offset + mid * BmbtKey::SIZE + BmbtKey::SIZE > buffer.len() {
                return Err(FsError::BufferTooSmall);
            }

            let key = BmbtKey::parse(&buffer[keys_offset + mid * BmbtKey::SIZE..])?;

            if key.file_offset <= file_offset {
                result_idx = Some(mid);
                // Move to right half to find a potentially larger valid key
                left = mid + 1;
            } else {
                // Move to left half
                right = mid;
            }
        }

        match result_idx {
            Some(idx) => {
                // Validate buffer bounds before parsing pointer
                if ptrs_offset + idx * BmbtPtr::SIZE + BmbtPtr::SIZE > buffer.len() {
                    return Err(FsError::BufferTooSmall);
                }

                let ptr = BmbtPtr::parse(&buffer[ptrs_offset + idx * BmbtPtr::SIZE..])?;
                Ok(ptr.block)
            }
            None => Err(FsError::NotFound),
        }
    }

    /// Finds the extent covering a given file offset in a leaf node.
    pub fn get_extent_for_offset(
        &self,
        buffer: &[u8],
        file_offset: u64,
    ) -> FsResult<Option<crate::extent::Extent>> {
        if self.level != 0 {
            return Err(FsError::InvalidBlockType);
        }

        let header_size = self.header_size();
        let num_recs = self.validate_recs(buffer)?;
        for i in 0..num_recs {
            let extent_offset = header_size
                .checked_add(
                    i.checked_mul(crate::extent::Extent::SIZE)
                        .ok_or(FsError::ArithmeticOverflow)?,
                )
                .ok_or(FsError::ArithmeticOverflow)?;
            let extent = crate::extent::Extent::parse(&buffer[extent_offset..])?;
            if extent.contains_file_block(file_offset) {
                return Ok(Some(extent));
            }
        }

        Ok(None)
    }
}

/// B+Tree block header (short format, for AG-local trees).
#[derive(Debug, Clone)]
pub struct BtreeBlockShort {
    /// Magic number.
    pub magic: u32,
    /// B+tree level (0 = leaf).
    pub level: u16,
    /// Number of records/keys.
    pub num_recs: u16,
    /// Left sibling block (AG-relative).
    pub left_sibling: u32,
    /// Right sibling block (AG-relative).
    pub right_sibling: u32,
    /// Block number (v5, AG-relative).
    pub block_no: u32,
    /// Log sequence number (v5).
    pub lsn: u64,
    /// UUID (v5).
    pub uuid: [u8; 16],
    /// Owner AG (v5).
    pub owner: u32,
    /// CRC (v5).
    pub crc: u32,
}

impl BtreeBlockShort {
    /// Offset of the v5 CRC field.
    pub const CRC_OFFSET_V5: usize = 0x34;
    /// Size of v4 header.
    pub const SIZE_V4: usize = 16;
    /// Size of v5 header.
    pub const SIZE_V5: usize = 56;

    /// Parses a short-format B+tree block header.
    pub fn parse(buffer: &[u8], is_v5: bool) -> FsResult<Self> {
        let min_size = if is_v5 { Self::SIZE_V5 } else { Self::SIZE_V4 };
        if buffer.len() < min_size {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0)?;
        let legacy_magic = matches!(
            magic,
            XFS_ABTB_MAGIC | XFS_ABTC_MAGIC | XFS_IBT_MAGIC | XFS_FIBT_MAGIC
        );
        let crc_magic = matches!(
            magic,
            XFS_ABTB_CRC_MAGIC | XFS_ABTC_CRC_MAGIC | XFS_IBT_CRC_MAGIC | XFS_FIBT_CRC_MAGIC
        );
        if (!legacy_magic && !crc_magic) || is_v5 != crc_magic {
            return Err(FsError::InvalidMagic);
        }

        let level = buffer.read_be_u16(4)?;
        let num_recs = buffer.read_be_u16(6)?;
        let left_sibling = buffer.read_be_u32(8)?;
        let right_sibling = buffer.read_be_u32(12)?;

        let (block_no, lsn, uuid, owner, crc) = if is_v5 {
            // Short (AG) btree block: blkno at 0x10, lsn at 0x18,
            // uuid at 0x20..0x30, owner at 0x30, crc (LE) at 0x34.
            let block_no = buffer.read_be_u32(16)?;
            let lsn = buffer.read_be_u64(24)?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(&buffer[32..48]);
            let owner = buffer.read_be_u32(48)?;
            let crc = buffer.read_le_u32(52)?;
            (block_no, lsn, uuid, owner, crc)
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

    /// Returns `true` if this is a v5 block.
    pub fn is_v5(&self) -> bool {
        matches!(
            self.magic,
            XFS_ABTB_CRC_MAGIC | XFS_ABTC_CRC_MAGIC | XFS_IBT_CRC_MAGIC | XFS_FIBT_CRC_MAGIC
        )
    }

    /// Verifies a v5 AG-local B+tree block CRC over the complete block.
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

    /// Returns `true` if this is a leaf node.
    pub fn is_leaf(&self) -> bool {
        self.level == 0
    }
}

/// BMBT (Block Map B+Tree) key structure.
#[derive(Debug, Clone, Copy)]
pub struct BmbtKey {
    /// Starting file offset.
    pub file_offset: u64,
}

impl BmbtKey {
    /// Size of a BMBT key.
    pub const SIZE: usize = 8;

    /// Parses a BMBT key.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            file_offset: buffer.read_be_u64(0)?,
        })
    }
}

/// BMBT pointer structure (block number).
#[derive(Debug, Clone, Copy)]
pub struct BmbtPtr {
    /// Block number.
    pub block: u64,
}

impl BmbtPtr {
    /// Size of a BMBT pointer.
    pub const SIZE: usize = 8;

    /// Parses a BMBT pointer.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        Ok(Self {
            block: buffer.read_be_u64(0)?,
        })
    }
}

/// BMBT record (same as extent, 128 bits).
pub type BmbtRec = crate::extent::Extent;

/// BMBT (Block Map B+Tree) root structure stored in inode data fork.
///
/// When a file grows large enough that its extent list can't fit in the
/// inode's data fork, XFS converts it to a B+Tree structure. The root
/// of this tree is stored inline in the data fork.
///
/// Layout in data fork:
/// ```text
/// +----------+----------+------------------+------------------+
/// | level    | numrecs  | keys[numrecs]    | ptrs[numrecs]    |
/// | (2 bytes)| (2 bytes)| (8 bytes each)   | (8 bytes each)   |
/// +----------+----------+------------------+------------------+
/// ```
#[derive(Debug, Clone)]
pub struct BmbtRoot {
    /// B+tree level (0 = leaf, >0 = intermediate).
    pub level: u16,
    /// Number of keys/pointers in this root.
    pub num_recs: u16,
    /// Keys (file block offsets).
    #[cfg(feature = "alloc")]
    pub keys: alloc::vec::Vec<BmbtKey>,
    /// Pointers (disk block numbers).
    #[cfg(feature = "alloc")]
    pub ptrs: alloc::vec::Vec<BmbtPtr>,
}

impl BmbtRoot {
    /// Header size (level + numrecs).
    pub const HEADER_SIZE: usize = 4;

    /// Parses the BMBT root from an inode's data fork.
    ///
    /// # Arguments
    /// * `data` - The raw data fork bytes (after the 4-byte `level`/`numrecs`
    ///   header produced by `Inode` parsing).  Its length is therefore the
    ///   usable fork size, which determines the maximum record capacity.
    /// * `level` - The B+tree level from the inode
    /// * `num_recs` - The number of records from the inode
    #[cfg(feature = "alloc")]
    pub fn parse(data: &[u8], level: u16, num_recs: u16) -> FsResult<Self> {
        if level == 0 {
            return Err(FsError::Corrupted);
        }

        // The pointer array starts after the maximum key capacity of the fork,
        // not after num_recs (`xfs_bmdr_maxrecs` / `xfs_bmdr_ptr_addr`).
        let max_recs = data.len() / (BmbtKey::SIZE + BmbtPtr::SIZE);
        let num_recs_usize = num_recs as usize;
        if num_recs_usize > max_recs {
            return Err(FsError::Corrupted);
        }

        // Validate we have enough data for keys and pointers
        let keys_size = num_recs_usize
            .checked_mul(BmbtKey::SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        let ptrs_offset = max_recs
            .checked_mul(BmbtKey::SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        let ptrs_size = num_recs_usize
            .checked_mul(BmbtPtr::SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        let required_size = ptrs_offset
            .checked_add(ptrs_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        if data.len() < required_size || data.len() < keys_size {
            return Err(FsError::BufferTooSmall);
        }

        // Parse keys
        let mut keys = alloc::vec::Vec::with_capacity(num_recs_usize);
        for i in 0..num_recs_usize {
            let key = BmbtKey::parse(&data[i * BmbtKey::SIZE..])?;
            keys.push(key);
        }

        // Parse pointers (they come after the maximum key capacity)
        let mut ptrs = alloc::vec::Vec::with_capacity(num_recs_usize);
        for i in 0..num_recs_usize {
            let ptr = BmbtPtr::parse(&data[ptrs_offset + i * BmbtPtr::SIZE..])?;
            ptrs.push(ptr);
        }

        let root = Self {
            level,
            num_recs,
            keys,
            ptrs,
        };
        root.validate()?;
        Ok(root)
    }

    /// Validates the root geometry and key ordering.
    #[cfg(feature = "alloc")]
    pub fn validate(&self) -> FsResult<()> {
        if self.level == 0
            || self.keys.len() != self.num_recs as usize
            || self.ptrs.len() != self.keys.len()
        {
            return Err(FsError::Corrupted);
        }
        if self
            .keys
            .windows(2)
            .any(|pair| pair[0].file_offset >= pair[1].file_offset)
        {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }

    /// Returns `true` if this root points directly to leaf nodes.
    pub fn is_leaf_parent(&self) -> bool {
        self.level == 1
    }

    /// Finds the child block pointer for a given file offset.
    ///
    /// Uses binary search to find the largest key <= file_offset,
    /// then returns the corresponding pointer.
    #[cfg(feature = "alloc")]
    pub fn find_child_ptr(&self, file_offset: u64) -> FsResult<u64> {
        self.validate()?;
        if self.num_recs == 0 {
            return Err(FsError::NotFound);
        }

        // Binary search for the largest key <= file_offset
        let mut left = 0usize;
        let mut right = self.num_recs as usize;
        let mut result_idx = None;

        while left < right {
            let mid = left + (right - left) / 2;
            if self.keys[mid].file_offset <= file_offset {
                result_idx = Some(mid);
                left = mid + 1;
            } else {
                right = mid;
            }
        }

        match result_idx {
            Some(idx) => Ok(self.ptrs[idx].block),
            None => Err(FsError::NotFound),
        }
    }
}

/// Trait for reading disk blocks during B+Tree traversal.
///
/// This allows the B+Tree traversal code to be used with different
/// storage backends (kernel driver, userspace, etc.).
#[cfg(feature = "alloc")]
pub trait BlockReader {
    /// Reads a disk block at the given block number.
    fn read_block(&self, block_num: u64) -> FsResult<alloc::vec::Vec<u8>>;
}

/// Hard upper bound on the number of B+tree blocks visited for a single
/// operation.  Prevents crafted/corrupted trees from consuming unbounded CPU
/// or memory (and from blocking service shutdown).
#[cfg(feature = "alloc")]
pub const MAX_BTREE_BLOCKS_PER_OPERATION: usize = 1 << 20;

/// Result of a B+Tree extent lookup.
#[derive(Debug, Clone)]
pub struct BtreeLookupResult {
    /// The extent containing the requested file block, if found.
    pub extent: Option<crate::extent::Extent>,
    /// The physical disk block for the file block, if found.
    pub disk_block: Option<u64>,
}

/// Traverses a BMBT (Block Map B+Tree) to find the extent for a file block.
///
/// # Arguments
/// * `root` - The BMBT root from the inode
/// * `file_block` - The file block offset to look up
/// * `reader` - A block reader for reading intermediate B+tree nodes
/// * `is_v5` - Whether this is a v5 filesystem (affects header sizes)
///
/// # Returns
/// The extent containing the file block, or None if it's a hole.
#[cfg(feature = "alloc")]
pub fn btree_lookup_extent<R: BlockReader>(
    root: &BmbtRoot,
    file_block: u64,
    reader: &R,
    is_v5: bool,
) -> FsResult<Option<crate::extent::Extent>> {
    use alloc::collections::BTreeSet;

    // The root of a btree-format fork always has level >= 1.
    if root.level == 0 {
        return Err(FsError::Corrupted);
    }

    // Start with the root's child pointer for this file offset
    let mut current_block = root.find_child_ptr(file_block)?;
    let mut current_level = root.level;
    let mut visited = BTreeSet::new();

    // Traverse down the tree.  Each child must be exactly one level below its
    // parent; this also makes cycles impossible, but track visited blocks and
    // enforce a budget as defence in depth.
    while current_level > 0 {
        if !visited.insert(current_block) || visited.len() > MAX_BTREE_BLOCKS_PER_OPERATION {
            return Err(FsError::Corrupted);
        }

        let block_data = reader.read_block(current_block)?;
        let header = BtreeBlockLong::parse(&block_data, is_v5)?;
        header.verify_crc(&block_data)?;
        if header.level.checked_add(1) != Some(current_level) {
            return Err(FsError::Corrupted);
        }

        if header.is_leaf() {
            // We've reached a leaf node - search for the extent
            return header.get_extent_for_offset(&block_data, file_block);
        }

        // Intermediate node - find the next block to visit
        current_block = header.get_ptr_for_offset(&block_data, file_block)?;
        current_level = header.level;
    }

    // If we exit the loop with level 0, something went wrong
    Err(FsError::Corrupted)
}

/// Collects all extents from a BMBT by traversing all leaf nodes.
///
/// This is useful for operations that need the complete extent list,
/// such as calculating total file blocks or validating the tree.
#[cfg(feature = "alloc")]
pub fn btree_collect_extents<R: BlockReader>(
    root: &BmbtRoot,
    reader: &R,
    is_v5: bool,
) -> FsResult<alloc::vec::Vec<crate::extent::Extent>> {
    use alloc::collections::BTreeSet;

    let mut extents = alloc::vec::Vec::new();
    root.validate()?;

    // We need to traverse to find the leftmost leaf, then follow sibling
    // pointers
    if root.num_recs == 0 {
        return Ok(extents);
    }
    if root.level == 0 || root.ptrs.is_empty() {
        return Err(FsError::Corrupted);
    }

    let mut visited = BTreeSet::new();

    // Find the leftmost leaf by always taking the first pointer
    let mut current_block = root.ptrs[0].block;
    let mut current_level = root.level;

    // Traverse down to the leftmost leaf
    while current_level > 1 {
        if !visited.insert(current_block) || visited.len() > MAX_BTREE_BLOCKS_PER_OPERATION {
            return Err(FsError::Corrupted);
        }

        let block_data = reader.read_block(current_block)?;
        let header = BtreeBlockLong::parse(&block_data, is_v5)?;
        header.verify_crc(&block_data)?;
        if header.level.checked_add(1) != Some(current_level) {
            return Err(FsError::Corrupted);
        }

        let num_recs = header.validate_recs(&block_data)?;
        if num_recs == 0 {
            return Err(FsError::Corrupted);
        }

        // Get the first (leftmost) pointer, at the canonical pointer offset.
        let ptrs_offset = header.ptrs_offset(block_data.len())?;
        let ptr = BmbtPtr::parse(&block_data[ptrs_offset..])?;

        current_block = ptr.block;
        current_level = header.level;
    }

    // Now traverse all leaves using sibling pointers
    let mut previous_end: Option<u64> = None;
    loop {
        if !visited.insert(current_block) || visited.len() > MAX_BTREE_BLOCKS_PER_OPERATION {
            return Err(FsError::Corrupted);
        }

        let block_data = reader.read_block(current_block)?;
        let header = BtreeBlockLong::parse(&block_data, is_v5)?;
        header.verify_crc(&block_data)?;

        if !header.is_leaf() {
            return Err(FsError::Corrupted);
        }

        let num_recs = header.validate_recs(&block_data)?;
        let header_size = header.header_size();
        for i in 0..num_recs {
            let extent_offset = header_size
                .checked_add(
                    i.checked_mul(crate::extent::Extent::SIZE)
                        .ok_or(FsError::ArithmeticOverflow)?,
                )
                .ok_or(FsError::ArithmeticOverflow)?;
            let extent = crate::extent::Extent::parse(&block_data[extent_offset..])?;

            // Extent records must be sorted and non-overlapping.
            if let Some(end) = previous_end {
                if extent.file_offset < end {
                    return Err(FsError::Corrupted);
                }
            }
            previous_end = Some(extent.file_end()?);
            extents.push(extent);
        }

        // Move to right sibling, or stop if there is none
        if header.right_sibling == u64::MAX || header.right_sibling == 0 {
            break;
        }
        current_block = header.right_sibling;
    }

    Ok(extents)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    fn internal_block(block_size: usize, level: u16, keys: &[u64], ptrs: &[u64]) -> Vec<u8> {
        let mut buf = vec![0u8; block_size];
        buf[0..4].copy_from_slice(&XFS_BMAP_MAGIC.to_be_bytes());
        buf[4..6].copy_from_slice(&level.to_be_bytes());
        buf[6..8].copy_from_slice(&(keys.len() as u16).to_be_bytes());

        let header = BtreeBlockLong::SIZE_V4;
        for (i, key) in keys.iter().enumerate() {
            let off = header + i * BmbtKey::SIZE;
            buf[off..off + 8].copy_from_slice(&key.to_be_bytes());
        }

        // Canonical pointer array: after the maximum key capacity.
        let max_recs = (block_size - header) / (BmbtKey::SIZE + BmbtPtr::SIZE);
        let ptrs_offset = header + max_recs * BmbtKey::SIZE;
        for (i, ptr) in ptrs.iter().enumerate() {
            let off = ptrs_offset + i * BmbtPtr::SIZE;
            buf[off..off + 8].copy_from_slice(&ptr.to_be_bytes());
        }
        buf
    }

    #[test]
    fn internal_node_pointers_use_max_record_capacity() {
        let buf = internal_block(512, 1, &[0, 10], &[100, 200]);
        let header = BtreeBlockLong::parse(&buf, false).unwrap();
        assert_eq!(header.num_recs, 2);
        assert_eq!(header.get_ptr_for_offset(&buf, 0).unwrap(), 100);
        assert_eq!(header.get_ptr_for_offset(&buf, 9).unwrap(), 100);
        assert_eq!(header.get_ptr_for_offset(&buf, 10).unwrap(), 200);
        assert_eq!(header.get_ptr_for_offset(&buf, 999).unwrap(), 200);
    }

    #[test]
    fn internal_node_rejects_num_recs_above_capacity() {
        let mut buf = internal_block(512, 1, &[0], &[100]);
        buf[6..8].copy_from_slice(&60u16.to_be_bytes()); // max is 30
        let header = BtreeBlockLong::parse(&buf, false).unwrap();
        assert!(matches!(
            header.get_ptr_for_offset(&buf, 0),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn root_pointers_use_fork_capacity() {
        // data.len() = 160 => max_recs = 10, pointer array starts at 80.
        let mut data = vec![0u8; 160];
        data[0..8].copy_from_slice(&0u64.to_be_bytes());
        data[8..16].copy_from_slice(&5u64.to_be_bytes());
        data[80..88].copy_from_slice(&11u64.to_be_bytes());
        data[88..96].copy_from_slice(&22u64.to_be_bytes());

        let root = BmbtRoot::parse(&data, 1, 2).unwrap();
        assert_eq!(root.find_child_ptr(6).unwrap(), 22);
        assert_eq!(root.find_child_ptr(0).unwrap(), 11);
    }

    #[test]
    fn root_rejects_num_recs_above_fork_capacity() {
        let data = vec![0u8; 16];
        assert!(matches!(
            BmbtRoot::parse(&data, 1, 2),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn root_rejects_zero_level_and_unsorted_keys() {
        let data = vec![0u8; 32];
        assert!(matches!(
            BmbtRoot::parse(&data, 0, 1),
            Err(FsError::Corrupted)
        ));

        let mut data = vec![0u8; 32];
        data[0..8].copy_from_slice(&10u64.to_be_bytes());
        data[8..16].copy_from_slice(&10u64.to_be_bytes());
        assert!(matches!(
            BmbtRoot::parse(&data, 1, 2),
            Err(FsError::Corrupted)
        ));
    }

    fn finish_v5_crc(buf: &mut [u8], crc_offset: usize) -> u32 {
        let crc = crate::crc::xfs_crc32c_with_zeroed_field(buf, crc_offset).unwrap();
        buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_le_bytes());
        crc
    }

    #[test]
    fn v5_long_and_short_btree_crcs_are_verified() {
        let mut long = vec![0u8; 512];
        long[0..4].copy_from_slice(&XFS_BMAP_CRC_MAGIC.to_be_bytes());
        let long_crc = finish_v5_crc(&mut long, BtreeBlockLong::CRC_OFFSET_V5);
        let long_header = BtreeBlockLong::parse(&long, true).unwrap();
        assert_eq!(long_header.crc, long_crc);
        assert!(long_header.verify_crc(&long).is_ok());
        long[100] ^= 1;
        assert!(matches!(
            long_header.verify_crc(&long),
            Err(FsError::Corrupted)
        ));

        let mut short = vec![0u8; 512];
        short[0..4].copy_from_slice(&XFS_ABTB_CRC_MAGIC.to_be_bytes());
        let short_crc = finish_v5_crc(&mut short, BtreeBlockShort::CRC_OFFSET_V5);
        let short_header = BtreeBlockShort::parse(&short, true).unwrap();
        assert_eq!(short_header.crc, short_crc);
        assert!(short_header.verify_crc(&short).is_ok());
        short[100] ^= 1;
        assert!(matches!(
            short_header.verify_crc(&short),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn v5_internal_pointers_use_v5_header_capacity() {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&XFS_BMAP_CRC_MAGIC.to_be_bytes());
        buf[4..6].copy_from_slice(&1u16.to_be_bytes());
        buf[6..8].copy_from_slice(&2u16.to_be_bytes());
        buf[BtreeBlockLong::SIZE_V5..BtreeBlockLong::SIZE_V5 + 8]
            .copy_from_slice(&0u64.to_be_bytes());
        buf[BtreeBlockLong::SIZE_V5 + 8..BtreeBlockLong::SIZE_V5 + 16]
            .copy_from_slice(&10u64.to_be_bytes());
        let header = BtreeBlockLong::parse(&buf, true).unwrap();
        let ptrs_offset = header.ptrs_offset(buf.len()).unwrap();
        assert_eq!(
            ptrs_offset,
            BtreeBlockLong::SIZE_V5 + header.max_recs(512).unwrap() * 8
        );
        buf[ptrs_offset..ptrs_offset + 8].copy_from_slice(&100u64.to_be_bytes());
        buf[ptrs_offset + 8..ptrs_offset + 16].copy_from_slice(&200u64.to_be_bytes());
        finish_v5_crc(&mut buf, BtreeBlockLong::CRC_OFFSET_V5);
        let header = BtreeBlockLong::parse(&buf, true).unwrap();
        assert_eq!(header.get_ptr_for_offset(&buf, 10).unwrap(), 200);
    }

    struct MemoryReader {
        blocks: alloc::collections::BTreeMap<u64, Vec<u8>>,
    }

    impl BlockReader for MemoryReader {
        fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
            self.blocks
                .get(&block_num)
                .cloned()
                .ok_or(FsError::InvalidBlockAddress)
        }
    }

    fn root_for(level: u16, child: u64) -> BmbtRoot {
        let mut data = vec![0u8; 16];
        data[8..16].copy_from_slice(&child.to_be_bytes());
        BmbtRoot::parse(&data, level, 1).unwrap()
    }

    fn v5_leaf(right_sibling: u64) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&XFS_BMAP_CRC_MAGIC.to_be_bytes());
        buf[6..8].copy_from_slice(&1u16.to_be_bytes());
        buf[16..24].copy_from_slice(&right_sibling.to_be_bytes());
        let extent = crate::extent::Extent {
            file_offset: 0,
            start_block: 1000,
            block_count: 10,
            is_unwritten: false,
        };
        buf[BtreeBlockLong::SIZE_V5..BtreeBlockLong::SIZE_V5 + 16]
            .copy_from_slice(&extent.to_bytes());
        finish_v5_crc(&mut buf, BtreeBlockLong::CRC_OFFSET_V5);
        buf
    }

    #[test]
    fn traversal_rejects_bad_crc_and_non_decreasing_levels() {
        let root = root_for(1, 100);
        let mut leaf = v5_leaf(u64::MAX);
        leaf[200] ^= 1;
        let reader = MemoryReader {
            blocks: [(100, leaf)].into_iter().collect(),
        };
        assert!(matches!(
            btree_lookup_extent(&root, 5, &reader, true),
            Err(FsError::Corrupted)
        ));

        // The root expects level 1, but this child claims to be a leaf.
        let reader = MemoryReader {
            blocks: [(100, v5_leaf(u64::MAX))].into_iter().collect(),
        };
        let root = root_for(2, 100);
        assert!(matches!(
            btree_lookup_extent(&root, 5, &reader, true),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn collect_detects_sibling_cycles() {
        let root = root_for(1, 100);
        let reader = MemoryReader {
            blocks: [(100, v5_leaf(100))].into_iter().collect(),
        };
        assert!(matches!(
            btree_collect_extents(&root, &reader, true),
            Err(FsError::Corrupted)
        ));
    }
}
