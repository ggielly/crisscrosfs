//! Checked, hash-directed lookup for XFS dir2/dir3 directories.
//!
//! The lookup reads the directory's block map on demand. It descends DA node
//! entries by `xfs_dir2_hash`, follows LEAFN sibling links while the hash
//! matches, and reads only data entries referenced by matching leaf records.
//! It never collects or scans the complete directory.

use alloc::{collections::BTreeSet, vec::Vec};
use core::{cell::Cell, ops::Range};

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use super::{
    dir2_hash,
    parse_shortform_directory,
    BlockInfoV4,
    BlockInfoV5,
    DataHeaderV4,
    DataHeaderV5,
    DirFileType,
    LeafEntry,
};
use crate::{
    address::fs_block_to_daddr,
    btree::{btree_lookup_extent_checked, BlockReader, BmbtRoot},
    constants::*,
    extent::Extent,
    inode::DataFork,
};

/// Default upper bound on backing-block reads for one lookup.
///
/// The budget includes BMBT blocks, directory metadata blocks and data blocks.
pub const MAX_DIR_LOOKUP_BLOCKS_DEFAULT: usize = 1 << 16;

/// Default upper bound on DA node levels. XFS itself permits at most five.
pub const MAX_DIR_LOOKUP_DEPTH_DEFAULT: u16 = XFS_DA_NODE_MAXDEPTH;

/// Filesystem and directory geometry needed by [`lookup_directory`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirGeometry {
    /// Filesystem block size in bytes (`sb_blocksize`).
    pub fs_block_size: u32,
    /// Directory block size in bytes (`1 << (sb_blocklog + sb_dirblklog)`).
    pub dir_block_size: u32,
    /// Optional filesystem length in filesystem blocks (`sb_dblocks`).
    ///
    /// Callers should supply this to reject physical pointers beyond the
    /// filesystem before issuing I/O.
    pub total_fs_blocks: Option<u64>,
}

impl DirGeometry {
    /// Construct geometry with no filesystem-length limit.
    pub const fn new(fs_block_size: u32, dir_block_size: u32) -> Self {
        Self {
            fs_block_size,
            dir_block_size,
            total_fs_blocks: None,
        }
    }

    /// Construct the common case where one directory block is one filesystem
    /// block.
    pub const fn for_block_size(block_size: u32) -> Self {
        Self::new(block_size, block_size)
    }

    /// Set the filesystem length used for physical extent bounds checks.
    pub const fn with_total_fs_blocks(mut self, total_fs_blocks: u64) -> Self {
        self.total_fs_blocks = Some(total_fs_blocks);
        self
    }

    fn validate(self) -> FsResult<()> {
        if !(512..=65_536).contains(&self.fs_block_size)
            || !self.fs_block_size.is_power_of_two()
            || !(512..=65_536).contains(&self.dir_block_size)
            || !self.dir_block_size.is_power_of_two()
            || self.dir_block_size < self.fs_block_size
            || !self.dir_block_size.is_multiple_of(self.fs_block_size)
            || self.total_fs_blocks == Some(0)
        {
            return Err(FsError::InvalidArgument);
        }
        Ok(())
    }

    fn fs_block_count(self) -> FsResult<u32> {
        self.dir_block_size
            .checked_div(self.fs_block_size)
            .ok_or(FsError::InvalidArgument)
    }

    fn leaf_block(self) -> FsResult<u64> {
        XFS_DIR2_LEAF_OFFSET
            .checked_div(u64::from(self.fs_block_size))
            .ok_or(FsError::ArithmeticOverflow)
    }

    fn free_block(self) -> FsResult<u64> {
        XFS_DIR2_FREE_OFFSET
            .checked_div(u64::from(self.fs_block_size))
            .ok_or(FsError::ArithmeticOverflow)
    }
}

/// Identity, feature and resource-budget settings for a directory lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirLookupOptions {
    /// Inode number that owns the directory and all of its metadata blocks.
    pub owner: u64,
    /// Whether the filesystem uses v5/dir3 metadata.
    pub is_v5: bool,
    /// Whether directory data entries contain the one-byte file-type field.
    pub has_ftype: bool,
    /// Expected v5 metadata UUID. Required when `is_v5` is true.
    pub metadata_uuid: Option<[u8; 16]>,
    /// Maximum number of calls to [`BlockReader::read_block`].
    pub max_blocks: usize,
    /// Maximum permitted DA node level (leaf level is zero).
    pub max_depth: u16,
}

impl Default for DirLookupOptions {
    fn default() -> Self {
        Self {
            owner: 0,
            is_v5: false,
            has_ftype: false,
            metadata_uuid: None,
            max_blocks: MAX_DIR_LOOKUP_BLOCKS_DEFAULT,
            max_depth: MAX_DIR_LOOKUP_DEPTH_DEFAULT,
        }
    }
}

impl DirLookupOptions {
    /// Construct options with the default traversal budgets.
    pub const fn new(
        owner: u64,
        is_v5: bool,
        has_ftype: bool,
        metadata_uuid: Option<[u8; 16]>,
    ) -> Self {
        Self {
            owner,
            is_v5,
            has_ftype,
            metadata_uuid,
            max_blocks: MAX_DIR_LOOKUP_BLOCKS_DEFAULT,
            max_depth: MAX_DIR_LOOKUP_DEPTH_DEFAULT,
        }
    }

    fn validate(self) -> FsResult<()> {
        if self.owner == 0 || self.max_blocks == 0 || self.max_depth == 0 {
            return Err(FsError::InvalidArgument);
        }
        if self.is_v5 && self.metadata_uuid.is_none() {
            return Err(FsError::InvalidArgument);
        }
        Ok(())
    }
}

/// Look up raw XFS name bytes in an inode data fork.
///
/// Returns `(inode_number, file_type)`. V4 directories (and filesystems without
/// the FTYPE feature) return [`DirFileType::Unknown`]. Hash collisions with
/// different names are normal and are resolved by comparing the name bytes.
/// Two live entries with the same name are ambiguous corruption and return
/// [`FsError::Corrupted`], even if their inode numbers agree.
///
/// `geometry.fs_block_size` is the unit accepted by `reader`; directory blocks
/// may span multiple such blocks. For v5, CRC, physical block number, owner and
/// UUID are checked for every directory metadata and data block that is read.
pub fn lookup_directory<R: BlockReader>(
    fork: &DataFork,
    name: &[u8],
    geometry: &DirGeometry,
    options: &DirLookupOptions,
    reader: &R,
) -> FsResult<(u64, DirFileType)> {
    geometry.validate()?;
    options.validate()?;
    validate_name(name)?;

    match fork {
        DataFork::Local(data) => lookup_shortform(data, name, options.has_ftype),
        DataFork::Extents(_) => {
            let context = LookupContext::new(fork, *geometry, *options, reader)?;
            lookup_block_directory(&context, name)
        }
        DataFork::Btree { .. } => {
            let context = LookupContext::new(fork, *geometry, *options, reader)?;
            lookup_block_directory(&context, name)
        }
        DataFork::Empty => Err(FsError::Corrupted),
        DataFork::Device { .. } => Err(FsError::NotADirectory),
    }
}

fn validate_name(name: &[u8]) -> FsResult<()> {
    if name.is_empty() || name.iter().any(|byte| matches!(byte, 0 | b'/')) {
        return Err(FsError::InvalidPath);
    }
    if name.len() > XFS_NAME_MAX {
        return Err(FsError::PathTooLong);
    }
    Ok(())
}

fn record_match(
    found: &mut Option<(u64, DirFileType)>,
    inode: u64,
    file_type: DirFileType,
) -> FsResult<()> {
    if found.replace((inode, file_type)).is_some() {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

fn finish_lookup(found: Option<(u64, DirFileType)>) -> FsResult<(u64, DirFileType)> {
    found.ok_or(FsError::NotFound)
}

fn lookup_shortform(data: &[u8], name: &[u8], has_ftype: bool) -> FsResult<(u64, DirFileType)> {
    let (_, iter) = parse_shortform_directory(data, has_ftype)?;
    let mut found = None;
    for entry in iter {
        let entry = entry?;
        validate_name(entry.name_bytes())?;
        if entry.inode == 0 {
            return Err(FsError::Corrupted);
        }
        if entry.name_bytes() == name {
            record_match(&mut found, entry.inode, entry.file_type)?;
        }
    }
    finish_lookup(found)
}

struct BudgetReader<'a, R> {
    inner: &'a R,
    reads: Cell<usize>,
    max_blocks: usize,
}

impl<'a, R: BlockReader> BlockReader for BudgetReader<'a, R> {
    fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
        let reads = self
            .reads
            .get()
            .checked_add(1)
            .ok_or(FsError::ArithmeticOverflow)?;
        if reads > self.max_blocks {
            return Err(FsError::Corrupted);
        }
        self.reads.set(reads);
        self.inner.read_block(block_num)
    }
}

enum ExtentSource<'a> {
    Inline(&'a [Extent]),
    Btree(BmbtRoot),
}

struct LookupContext<'a, R> {
    geometry: DirGeometry,
    options: DirLookupOptions,
    source: ExtentSource<'a>,
    reader: BudgetReader<'a, R>,
}

impl<'a, R: BlockReader> LookupContext<'a, R> {
    fn new(
        fork: &'a DataFork,
        geometry: DirGeometry,
        options: DirLookupOptions,
        reader: &'a R,
    ) -> FsResult<Self> {
        let source = match fork {
            DataFork::Extents(extents) => {
                validate_inline_extents(extents, geometry)?;
                ExtentSource::Inline(extents)
            }
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => ExtentSource::Btree(BmbtRoot::parse(data, *level, *num_recs)?),
            _ => return Err(FsError::InvalidBlockType),
        };
        Ok(Self {
            geometry,
            options,
            source,
            reader: BudgetReader {
                inner: reader,
                reads: Cell::new(0),
                max_blocks: options.max_blocks,
            },
        })
    }

    fn map_fs_block(&self, logical_fs_block: u64) -> FsResult<u64> {
        let extent = match &self.source {
            ExtentSource::Inline(extents) => find_inline_extent(extents, logical_fs_block)?,
            ExtentSource::Btree(root) => btree_lookup_extent_checked(
                root,
                logical_fs_block,
                &self.reader,
                self.options.is_v5,
                self.options.owner,
                self.options.metadata_uuid,
                self.geometry.fs_block_size as usize,
            )?
            .ok_or(FsError::Corrupted)?,
        };
        self.validate_extent(extent)?;
        extent.translate(logical_fs_block)
    }

    fn validate_extent(&self, extent: Extent) -> FsResult<()> {
        if extent.block_count == 0 || extent.is_unwritten {
            return Err(FsError::Corrupted);
        }
        let disk_end = extent.disk_end()?;
        if self
            .geometry
            .total_fs_blocks
            .is_some_and(|total| disk_end > total)
        {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }

    /// Read one complete directory block beginning at an aligned logical
    /// filesystem block.
    fn read_dir_block(&self, logical_fs_block: u64) -> FsResult<DirBlock> {
        let fsb_count = self.geometry.fs_block_count()?;
        if logical_fs_block
            .checked_rem(fsb_count as u64)
            .ok_or(FsError::ArithmeticOverflow)?
            != 0
        {
            return Err(FsError::Corrupted);
        }

        let dir_size = self.geometry.dir_block_size as usize;
        let fs_size = self.geometry.fs_block_size as usize;
        let mut raw = Vec::new();
        raw.try_reserve_exact(dir_size)
            .map_err(|_| FsError::OutOfMemory)?;
        let mut physical_fs_block = None;

        for index in 0..fsb_count as u64 {
            let logical = logical_fs_block
                .checked_add(index)
                .ok_or(FsError::ArithmeticOverflow)?;
            let physical = self.map_fs_block(logical)?;
            if self
                .geometry
                .total_fs_blocks
                .is_some_and(|total| physical >= total)
            {
                return Err(FsError::Corrupted);
            }
            let block = self.reader.read_block(physical)?;
            if block.len() < fs_size {
                return Err(FsError::BufferTooSmall);
            }
            physical_fs_block.get_or_insert(physical);
            raw.extend_from_slice(&block[..fs_size]);
        }

        Ok(DirBlock {
            logical_fs_block,
            physical_fs_block: physical_fs_block.ok_or(FsError::Corrupted)?,
            raw,
        })
    }
}

struct DirBlock {
    logical_fs_block: u64,
    physical_fs_block: u64,
    raw: Vec<u8>,
}

fn validate_inline_extents(extents: &[Extent], geometry: DirGeometry) -> FsResult<()> {
    let mut previous_end = None;
    for extent in extents {
        if extent.block_count == 0 || extent.is_unwritten {
            return Err(FsError::Corrupted);
        }
        let end = extent.file_end()?;
        if previous_end.is_some_and(|previous| end <= previous || extent.file_offset < previous) {
            return Err(FsError::Corrupted);
        }
        let disk_end = extent.disk_end()?;
        if geometry
            .total_fs_blocks
            .is_some_and(|total| disk_end > total)
        {
            return Err(FsError::Corrupted);
        }
        previous_end = Some(end);
    }
    Ok(())
}

fn find_inline_extent(extents: &[Extent], logical_fs_block: u64) -> FsResult<Extent> {
    let mut left = 0usize;
    let mut right = extents.len();
    while left < right {
        let middle = left + (right - left) / 2;
        if extents[middle].file_offset <= logical_fs_block {
            left = middle + 1;
        } else {
            right = middle;
        }
    }
    if left == 0 {
        return Err(FsError::Corrupted);
    }
    let extent = extents[left - 1];
    if extent.contains_file_block(logical_fs_block) {
        Ok(extent)
    } else {
        Err(FsError::Corrupted)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockKind {
    Data,
    Block,
    Leaf1,
    LeafN,
    Node,
}

impl BlockKind {
    fn is_da(self) -> bool {
        matches!(self, Self::Leaf1 | Self::LeafN | Self::Node)
    }

    fn magic(self, is_v5: bool) -> u32 {
        match (self, is_v5) {
            (Self::Data, false) => XFS_DIR2_DATA_MAGIC,
            (Self::Data, true) => XFS_DIR3_DATA_MAGIC,
            (Self::Block, false) => XFS_DIR2_BLOCK_MAGIC,
            (Self::Block, true) => XFS_DIR3_BLOCK_MAGIC,
            (Self::Leaf1, false) => u32::from(XFS_DIR2_LEAF_MAGIC),
            (Self::Leaf1, true) => u32::from(XFS_DIR3_LEAF_MAGIC),
            (Self::LeafN, false) => u32::from(XFS_DIR2_LEAFN_MAGIC),
            (Self::LeafN, true) => u32::from(XFS_DIR3_LEAFN_MAGIC),
            (Self::Node, false) => u32::from(XFS_DIR2_NODE_MAGIC),
            (Self::Node, true) => u32::from(XFS_DIR3_NODE_MAGIC),
        }
    }

    fn header_size(self, is_v5: bool) -> usize {
        if self.is_da() {
            if is_v5 {
                64
            } else {
                16
            }
        } else if is_v5 {
            DataHeaderV5::SIZE
        } else {
            DataHeaderV4::SIZE
        }
    }
}

fn data_block_kind(raw: &[u8], is_v5: bool) -> FsResult<BlockKind> {
    let magic = raw.read_be_u32(0)?;
    if magic == BlockKind::Data.magic(is_v5) {
        Ok(BlockKind::Data)
    } else if magic == BlockKind::Block.magic(is_v5) {
        Ok(BlockKind::Block)
    } else {
        Err(FsError::InvalidMagic)
    }
}

fn da_block_kind(raw: &[u8], is_v5: bool) -> FsResult<BlockKind> {
    let magic = u32::from(raw.read_be_u16(8)?);
    if magic == BlockKind::Leaf1.magic(is_v5) {
        Ok(BlockKind::Leaf1)
    } else if magic == BlockKind::LeafN.magic(is_v5) {
        Ok(BlockKind::LeafN)
    } else if magic == BlockKind::Node.magic(is_v5) {
        Ok(BlockKind::Node)
    } else {
        Err(FsError::InvalidMagic)
    }
}

fn verify_block_metadata(
    block: &DirBlock,
    kind: BlockKind,
    geometry: &DirGeometry,
    options: &DirLookupOptions,
) -> FsResult<()> {
    let raw = block.raw.as_slice();
    let actual_magic = if kind.is_da() {
        u32::from(raw.read_be_u16(8)?)
    } else {
        raw.read_be_u32(0)?
    };
    if actual_magic != kind.magic(options.is_v5) {
        return Err(FsError::InvalidMagic);
    }
    if !options.is_v5 {
        return Ok(());
    }

    let (blkno_offset, uuid_offset, owner_offset) = if kind.is_da() {
        BlockInfoV5::parse(raw, 0)?.verify_crc(raw, 0)?;
        (16, 32, 48)
    } else {
        DataHeaderV5::parse(raw)?.verify_crc(raw)?;
        (8, 24, 40)
    };
    let expected_daddr =
        fs_block_to_daddr(block.physical_fs_block, geometry.fs_block_size as usize)?;
    let uuid = raw
        .get(uuid_offset..uuid_offset + 16)
        .ok_or(FsError::BufferTooSmall)?;
    if raw.read_be_u64(blkno_offset)? != expected_daddr
        || raw.read_be_u64(owner_offset)? != options.owner
        || uuid
            != options
                .metadata_uuid
                .as_ref()
                .ok_or(FsError::InvalidArgument)?
    {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct DaLink {
    forw: u32,
    back: u32,
}

fn parse_da_link(raw: &[u8], is_v5: bool) -> FsResult<DaLink> {
    if is_v5 {
        let info = BlockInfoV5::parse(raw, 0)?;
        Ok(DaLink {
            forw: info.forw,
            back: info.back,
        })
    } else {
        let info = BlockInfoV4::parse(raw, 0)?;
        Ok(DaLink {
            forw: info.forw,
            back: info.back,
        })
    }
}

fn validate_da_link(pointer: u32, current: u64, geometry: &DirGeometry) -> FsResult<()> {
    if pointer == 0 {
        return Ok(());
    }
    let pointer = u64::from(pointer);
    if pointer == current
        || pointer < geometry.leaf_block()?
        || pointer >= geometry.free_block()?
        || pointer
            .checked_rem(geometry.fs_block_count()? as u64)
            .ok_or(FsError::ArithmeticOverflow)?
            != 0
    {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

struct HashEntries<'a> {
    raw: &'a [u8],
    offset: usize,
    count: usize,
}

impl<'a> HashEntries<'a> {
    fn get(&self, index: usize) -> FsResult<LeafEntry> {
        if index >= self.count {
            return Err(FsError::Corrupted);
        }
        let offset = self
            .offset
            .checked_add(
                index
                    .checked_mul(LeafEntry::SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        LeafEntry::parse(self.raw, offset)
    }

    fn last_hash(&self) -> FsResult<u32> {
        if self.count == 0 {
            return Err(FsError::Corrupted);
        }
        Ok(self.get(self.count - 1)?.hashval)
    }

    fn lower_bound(&self, hash: u32) -> FsResult<usize> {
        let mut left = 0usize;
        let mut right = self.count;
        while left < right {
            let middle = left + (right - left) / 2;
            if self.get(middle)?.hashval < hash {
                left = middle + 1;
            } else {
                right = middle;
            }
        }
        Ok(left)
    }

    fn matching_range(&self, hash: u32) -> FsResult<Range<usize>> {
        let start = self.lower_bound(hash)?;
        let mut end = start;
        while end < self.count && self.get(end)?.hashval == hash {
            end += 1;
        }
        Ok(start..end)
    }

    fn validate_leaf(&self, expected_stale: u16) -> FsResult<()> {
        let mut previous = None;
        let mut stale = 0usize;
        for index in 0..self.count {
            let entry = self.get(index)?;
            if previous.is_some_and(|hash| entry.hashval < hash) {
                return Err(FsError::Corrupted);
            }
            previous = Some(entry.hashval);
            if entry.address == XFS_DIR2_NULL_DATAPTR {
                stale += 1;
            }
        }
        if stale != expected_stale as usize {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }

    fn validate_node(&self) -> FsResult<()> {
        let mut previous = None;
        for index in 0..self.count {
            let entry = self.get(index)?;
            if entry.address == XFS_DIR2_NULL_DATAPTR
                || previous.is_some_and(|hash| entry.hashval < hash)
            {
                return Err(FsError::Corrupted);
            }
            previous = Some(entry.hashval);
        }
        Ok(())
    }
}

struct LeafBlock<'a> {
    link: DaLink,
    entries: HashEntries<'a>,
}

fn parse_leaf_block<'a>(
    block: &'a DirBlock,
    expected_kind: BlockKind,
    geometry: &DirGeometry,
    options: &DirLookupOptions,
) -> FsResult<LeafBlock<'a>> {
    verify_block_metadata(block, expected_kind, geometry, options)?;
    let raw = block.raw.as_slice();
    let link = parse_da_link(raw, options.is_v5)?;
    validate_da_link(link.forw, block.logical_fs_block, geometry)?;
    validate_da_link(link.back, block.logical_fs_block, geometry)?;

    let count_offset = if options.is_v5 { 56 } else { 12 };
    let count = raw.read_be_u16(count_offset)?;
    let stale = raw.read_be_u16(count_offset + 2)?;
    if count == 0 || stale > count {
        return Err(FsError::Corrupted);
    }
    let entries_offset = expected_kind.header_size(options.is_v5);
    let entries_end = entries_offset
        .checked_add(
            (count as usize)
                .checked_mul(LeafEntry::SIZE)
                .ok_or(FsError::ArithmeticOverflow)?,
        )
        .ok_or(FsError::ArithmeticOverflow)?;

    let mut best_count = 0usize;
    if expected_kind == BlockKind::Leaf1 {
        let tail_offset = raw.len().checked_sub(4).ok_or(FsError::Corrupted)?;
        best_count = raw.read_be_u32(tail_offset)? as usize;
        let best_bytes = best_count
            .checked_mul(2)
            .ok_or(FsError::ArithmeticOverflow)?;
        let bests_offset = tail_offset
            .checked_sub(best_bytes)
            .ok_or(FsError::Corrupted)?;
        if entries_end > bests_offset {
            return Err(FsError::Corrupted);
        }
    } else if entries_end > raw.len() {
        return Err(FsError::Corrupted);
    }

    let entries = HashEntries {
        raw,
        offset: entries_offset,
        count: count as usize,
    };
    entries.validate_leaf(stale)?;
    validate_leaf_addresses(
        &entries,
        geometry,
        options.is_v5,
        (expected_kind == BlockKind::Leaf1)
            .then(|| u64::try_from(best_count).map_err(|_| FsError::ArithmeticOverflow))
            .transpose()?,
    )?;
    Ok(LeafBlock { link, entries })
}

struct NodeBlock<'a> {
    link: DaLink,
    level: u16,
    entries: HashEntries<'a>,
}

fn parse_node_block<'a>(
    block: &'a DirBlock,
    geometry: &DirGeometry,
    options: &DirLookupOptions,
) -> FsResult<NodeBlock<'a>> {
    verify_block_metadata(block, BlockKind::Node, geometry, options)?;
    let raw = block.raw.as_slice();
    let link = parse_da_link(raw, options.is_v5)?;
    validate_da_link(link.forw, block.logical_fs_block, geometry)?;
    validate_da_link(link.back, block.logical_fs_block, geometry)?;

    let count_offset = if options.is_v5 { 56 } else { 12 };
    let count = raw.read_be_u16(count_offset)?;
    let level = raw.read_be_u16(count_offset + 2)?;
    if count == 0 || level == 0 || level > options.max_depth || level > XFS_DA_NODE_MAXDEPTH {
        return Err(FsError::Corrupted);
    }
    let entries_offset = BlockKind::Node.header_size(options.is_v5);
    let entries_end = entries_offset
        .checked_add(
            (count as usize)
                .checked_mul(LeafEntry::SIZE)
                .ok_or(FsError::ArithmeticOverflow)?,
        )
        .ok_or(FsError::ArithmeticOverflow)?;
    if entries_end > raw.len() {
        return Err(FsError::Corrupted);
    }
    let entries = HashEntries {
        raw,
        offset: entries_offset,
        count: count as usize,
    };
    entries.validate_node()?;
    for index in 0..entries.count {
        validate_da_link(
            entries.get(index)?.address,
            block.logical_fs_block,
            geometry,
        )?;
    }
    Ok(NodeBlock {
        link,
        level,
        entries,
    })
}

struct DataEntry {
    inode: u64,
    file_type: DirFileType,
    matches: bool,
}

fn parse_data_entry(
    raw: &[u8],
    offset: usize,
    end: usize,
    name: &[u8],
    expected_hash: u32,
    has_ftype: bool,
    is_v5: bool,
) -> FsResult<DataEntry> {
    let header_size = BlockKind::Data.header_size(is_v5);
    if offset < header_size
        || offset >= end
        || offset
            .checked_rem(XFS_DIR2_DATA_ALIGN)
            .ok_or(FsError::ArithmeticOverflow)?
            != 0
        || end > raw.len()
    {
        return Err(FsError::Corrupted);
    }
    if raw.read_be_u16(offset)? == XFS_DIR2_DATA_FREE_TAG {
        return Err(FsError::Corrupted);
    }
    let inode = raw.read_be_u64(offset)?;
    let name_len = *raw.get(offset + 8).ok_or(FsError::BufferTooSmall)? as usize;
    if inode == 0 || name_len == 0 || name_len > XFS_NAME_MAX {
        return Err(FsError::Corrupted);
    }
    let name_offset = offset.checked_add(9).ok_or(FsError::ArithmeticOverflow)?;
    let name_end = name_offset
        .checked_add(name_len)
        .ok_or(FsError::ArithmeticOverflow)?;
    if name_end > end {
        return Err(FsError::Corrupted);
    }
    let entry_name = raw
        .get(name_offset..name_end)
        .ok_or(FsError::BufferTooSmall)?;
    validate_name(entry_name)?;
    if dir2_hash(entry_name) != expected_hash {
        return Err(FsError::Corrupted);
    }

    let file_type = if has_ftype {
        let value = *raw.get(name_end).ok_or(FsError::BufferTooSmall)?;
        if value > 8 {
            return Err(FsError::Corrupted);
        }
        DirFileType::from_u8(value)
    } else {
        DirFileType::Unknown
    };
    let entry_size = 8usize
        .checked_add(1)
        .and_then(|size| size.checked_add(name_len))
        .and_then(|size| size.checked_add(usize::from(has_ftype)))
        .and_then(|size| size.checked_add(2))
        .ok_or(FsError::ArithmeticOverflow)?;
    let aligned_size = entry_size
        .checked_add(XFS_DIR2_DATA_ALIGN - 1)
        .map(|size| size & !(XFS_DIR2_DATA_ALIGN - 1))
        .ok_or(FsError::ArithmeticOverflow)?;
    let entry_end = offset
        .checked_add(aligned_size)
        .ok_or(FsError::ArithmeticOverflow)?;
    if entry_end > end {
        return Err(FsError::Corrupted);
    }
    let tag_offset = entry_end.checked_sub(2).ok_or(FsError::Corrupted)?;
    let tag = u16::try_from(offset).map_err(|_| FsError::Corrupted)?;
    if raw.read_be_u16(tag_offset)? != tag {
        return Err(FsError::Corrupted);
    }

    Ok(DataEntry {
        inode,
        file_type,
        matches: entry_name == name,
    })
}

fn lookup_embedded_block(
    context: &LookupContext<'_, impl BlockReader>,
    block: &DirBlock,
    name: &[u8],
) -> FsResult<(u64, DirFileType)> {
    let raw = block.raw.as_slice();
    let tail_offset = raw.len().checked_sub(8).ok_or(FsError::Corrupted)?;
    let count = raw.read_be_u32(tail_offset)? as usize;
    let stale = raw.read_be_u32(tail_offset + 4)?;
    if count == 0 || stale as usize > count {
        return Err(FsError::Corrupted);
    }
    let leaf_bytes = count
        .checked_mul(LeafEntry::SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;
    let leaf_offset = tail_offset
        .checked_sub(leaf_bytes)
        .ok_or(FsError::Corrupted)?;
    let header_size = BlockKind::Block.header_size(context.options.is_v5);
    if leaf_offset < header_size {
        return Err(FsError::Corrupted);
    }
    let entries = HashEntries {
        raw,
        offset: leaf_offset,
        count,
    };
    entries.validate_leaf(stale as u16)?;
    for index in 0..entries.count {
        let address = entries.get(index)?.address;
        if address != XFS_DIR2_NULL_DATAPTR {
            let offset = usize::try_from(
                u64::from(address)
                    .checked_mul(XFS_DIR2_DATA_ALIGN as u64)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .map_err(|_| FsError::ArithmeticOverflow)?;
            if offset < header_size || offset >= leaf_offset {
                return Err(FsError::Corrupted);
            }
        }
    }

    let hash = dir2_hash(name);
    let mut found = None;
    for index in entries.matching_range(hash)? {
        let entry = entries.get(index)?;
        let offset = usize::try_from(
            u64::from(entry.address)
                .checked_mul(XFS_DIR2_DATA_ALIGN as u64)
                .ok_or(FsError::ArithmeticOverflow)?,
        )
        .map_err(|_| FsError::ArithmeticOverflow)?;
        let parsed = parse_data_entry(
            raw,
            offset,
            leaf_offset,
            name,
            hash,
            context.options.has_ftype,
            context.options.is_v5,
        )?;
        if parsed.matches {
            record_match(&mut found, parsed.inode, parsed.file_type)?;
        }
    }
    finish_lookup(found)
}

fn data_pointer_location(address: u32, geometry: &DirGeometry) -> FsResult<(u64, usize)> {
    let byte_offset = u64::from(address)
        .checked_mul(XFS_DIR2_DATA_ALIGN as u64)
        .ok_or(FsError::ArithmeticOverflow)?;
    let dir_size = u64::from(geometry.dir_block_size);
    let data_block = byte_offset
        .checked_div(dir_size)
        .ok_or(FsError::ArithmeticOverflow)?;
    if data_block >= XFS_DIR2_LEAF_OFFSET / dir_size {
        return Err(FsError::Corrupted);
    }
    let logical_fs_block = data_block
        .checked_mul(geometry.fs_block_count()? as u64)
        .ok_or(FsError::ArithmeticOverflow)?;
    let offset =
        usize::try_from(byte_offset % dir_size).map_err(|_| FsError::ArithmeticOverflow)?;
    Ok((logical_fs_block, offset))
}

fn validate_leaf_addresses(
    entries: &HashEntries<'_>,
    geometry: &DirGeometry,
    is_v5: bool,
    best_count: Option<u64>,
) -> FsResult<()> {
    let header_size = BlockKind::Data.header_size(is_v5);
    let fsb_count = geometry.fs_block_count()? as u64;
    for index in 0..entries.count {
        let address = entries.get(index)?.address;
        if address == XFS_DIR2_NULL_DATAPTR {
            continue;
        }
        let (logical_fs_block, offset) = data_pointer_location(address, geometry)?;
        if offset < header_size
            || best_count.is_some_and(|count| logical_fs_block / fsb_count >= count)
        {
            return Err(FsError::Corrupted);
        }
    }
    Ok(())
}

fn scan_leaf_entries(
    context: &LookupContext<'_, impl BlockReader>,
    leaf: &LeafBlock<'_>,
    first_data_block: Option<&DirBlock>,
    name: &[u8],
    found: &mut Option<(u64, DirFileType)>,
) -> FsResult<()> {
    let hash = dir2_hash(name);
    for index in leaf.entries.matching_range(hash)? {
        let entry = leaf.entries.get(index)?;
        if entry.address == XFS_DIR2_NULL_DATAPTR {
            continue;
        }
        let (logical_fs_block, offset) = data_pointer_location(entry.address, &context.geometry)?;
        let data_block;
        let raw = if logical_fs_block == 0 {
            first_data_block.ok_or(FsError::Corrupted)?.raw.as_slice()
        } else {
            data_block = context.read_dir_block(logical_fs_block)?;
            verify_block_metadata(
                &data_block,
                BlockKind::Data,
                &context.geometry,
                &context.options,
            )?;
            data_block.raw.as_slice()
        };
        let parsed = parse_data_entry(
            raw,
            offset,
            raw.len(),
            name,
            hash,
            context.options.has_ftype,
            context.options.is_v5,
        )?;
        if parsed.matches {
            record_match(found, parsed.inode, parsed.file_type)?;
        }
    }
    Ok(())
}

fn scan_leaf_chain(
    context: &LookupContext<'_, impl BlockReader>,
    first: &DirBlock,
    first_leaf: &LeafBlock<'_>,
    first_data_block: Option<&DirBlock>,
    name: &[u8],
    found: &mut Option<(u64, DirFileType)>,
) -> FsResult<()> {
    let hash = dir2_hash(name);
    let mut visited = BTreeSet::new();
    if !visited.insert(first.logical_fs_block) {
        return Err(FsError::Corrupted);
    }
    scan_leaf_entries(context, first_leaf, first_data_block, name, found)?;

    let mut link = first_leaf.link;
    let mut last_hash = first_leaf.entries.last_hash()?;
    let mut previous_logical = first.logical_fs_block;
    while last_hash == hash && link.forw != 0 {
        let next = context.read_dir_block(u64::from(link.forw))?;
        if !visited.insert(next.logical_fs_block) {
            return Err(FsError::Corrupted);
        }
        let next_leaf =
            parse_leaf_block(&next, BlockKind::LeafN, &context.geometry, &context.options)?;
        if next_leaf.link.back != u32::try_from(previous_logical).map_err(|_| FsError::Corrupted)?
            || next_leaf.entries.get(0)?.hashval < last_hash
        {
            return Err(FsError::Corrupted);
        }
        scan_leaf_entries(context, &next_leaf, first_data_block, name, found)?;
        previous_logical = next.logical_fs_block;
        link = next_leaf.link;
        last_hash = next_leaf.entries.last_hash()?;
    }
    Ok(())
}

fn lookup_leafn_tree(
    context: &LookupContext<'_, impl BlockReader>,
    root: &DirBlock,
    first_data_block: Option<&DirBlock>,
    name: &[u8],
) -> FsResult<(u64, DirFileType)> {
    let hash = dir2_hash(name);
    let node = parse_node_block(root, &context.geometry, &context.options)?;
    if node.link.forw != 0 || node.link.back != 0 {
        return Err(FsError::Corrupted);
    }
    let index = node.entries.lower_bound(hash)?;
    if index == node.entries.count {
        return Err(FsError::NotFound);
    }
    let selected = node.entries.get(index)?;
    validate_da_link(selected.address, root.logical_fs_block, &context.geometry)?;
    let child = context.read_dir_block(u64::from(selected.address))?;
    let mut visited = BTreeSet::new();
    if !visited.insert(root.logical_fs_block) {
        return Err(FsError::Corrupted);
    }
    lookup_node_cursor(
        context,
        child,
        first_data_block,
        name,
        Some(node.level - 1),
        Some(selected.hashval),
        visited,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn lookup_node_cursor(
    context: &LookupContext<'_, impl BlockReader>,
    mut current: DirBlock,
    first_data_block: Option<&DirBlock>,
    name: &[u8],
    mut expected_level: Option<u16>,
    mut expected_max_hash: Option<u32>,
    mut visited: BTreeSet<u64>,
    mut found: Option<(u64, DirFileType)>,
) -> FsResult<(u64, DirFileType)> {
    let hash = dir2_hash(name);
    loop {
        if !visited.insert(current.logical_fs_block) {
            return Err(FsError::Corrupted);
        }
        match da_block_kind(&current.raw, context.options.is_v5)? {
            BlockKind::Node => {
                let node = parse_node_block(&current, &context.geometry, &context.options)?;
                if expected_level != Some(node.level)
                    || expected_max_hash
                        .is_some_and(|max| node.entries.last_hash().ok() != Some(max))
                {
                    return Err(FsError::Corrupted);
                }
                expected_level = Some(node.level - 1);
                let index = node.entries.lower_bound(hash)?;
                if index == node.entries.count {
                    return Err(FsError::NotFound);
                }
                let selected = node.entries.get(index)?;
                validate_da_link(
                    selected.address,
                    current.logical_fs_block,
                    &context.geometry,
                )?;
                expected_max_hash = Some(selected.hashval);
                current = context.read_dir_block(u64::from(selected.address))?;
            }
            BlockKind::LeafN => {
                let leaf = parse_leaf_block(
                    &current,
                    BlockKind::LeafN,
                    &context.geometry,
                    &context.options,
                )?;
                if expected_level != Some(0)
                    || expected_max_hash
                        .is_some_and(|max| leaf.entries.last_hash().ok() != Some(max))
                {
                    return Err(FsError::Corrupted);
                }
                scan_leaf_chain(context, &current, &leaf, first_data_block, name, &mut found)?;
                return finish_lookup(found);
            }
            _ => return Err(FsError::InvalidMagic),
        }
    }
}

fn lookup_block_directory(
    context: &LookupContext<'_, impl BlockReader>,
    name: &[u8],
) -> FsResult<(u64, DirFileType)> {
    let first = context.read_dir_block(0)?;
    let kind = data_block_kind(&first.raw, context.options.is_v5)?;
    verify_block_metadata(&first, kind, &context.geometry, &context.options)?;
    if kind == BlockKind::Block {
        return lookup_embedded_block(context, &first, name);
    }

    let root = context.read_dir_block(context.geometry.leaf_block()?)?;
    match da_block_kind(&root.raw, context.options.is_v5)? {
        BlockKind::Leaf1 => {
            let leaf =
                parse_leaf_block(&root, BlockKind::Leaf1, &context.geometry, &context.options)?;
            if leaf.link.forw != 0 || leaf.link.back != 0 {
                return Err(FsError::Corrupted);
            }
            let mut found = None;
            scan_leaf_entries(context, &leaf, Some(&first), name, &mut found)?;
            finish_lookup(found)
        }
        BlockKind::LeafN => {
            let leaf =
                parse_leaf_block(&root, BlockKind::LeafN, &context.geometry, &context.options)?;
            if leaf.link.forw != 0 || leaf.link.back != 0 {
                return Err(FsError::Corrupted);
            }
            let mut found = None;
            scan_leaf_entries(context, &leaf, Some(&first), name, &mut found)?;
            finish_lookup(found)
        }
        BlockKind::Node => lookup_leafn_tree(context, &root, Some(&first), name),
        BlockKind::Data | BlockKind::Block => Err(FsError::InvalidMagic),
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, format, vec, vec::Vec};
    use core::cell::RefCell;

    use super::*;
    use crate::{
        crc,
        dir_write::{
            add_shortform_entry,
            build_block_directory,
            build_leaf_directory,
            build_node_directory,
            leaf_directory_data_block_count,
            leaf_node_record_capacity,
            parse_block_directory,
            NewDirEntry,
        },
    };

    const UUID: [u8; 16] = [0x5A; 16];
    const OWNER: u64 = 128;
    const PARENT: u64 = 64;
    const LEAF_BLOCK: u64 = XFS_DIR2_LEAF_OFFSET / 512;

    #[derive(Debug, Default)]
    struct MemoryReader {
        blocks: BTreeMap<u64, Vec<u8>>,
        reads: RefCell<Vec<u64>>,
    }

    impl MemoryReader {
        fn insert(&mut self, block: u64, raw: Vec<u8>) {
            self.blocks.insert(block, raw);
        }
    }

    impl BlockReader for MemoryReader {
        fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
            self.reads.borrow_mut().push(block_num);
            self.blocks
                .get(&block_num)
                .cloned()
                .ok_or(FsError::InvalidBlockAddress)
        }
    }

    fn options(is_v5: bool) -> DirLookupOptions {
        DirLookupOptions::new(OWNER, is_v5, true, is_v5.then_some(UUID))
    }

    fn geometry(block_size: u32) -> DirGeometry {
        DirGeometry::for_block_size(block_size).with_total_fs_blocks(2_000)
    }

    fn extent(file_offset: u64, start_block: u64, block_count: u32) -> Extent {
        Extent {
            file_offset,
            start_block,
            block_count,
            is_unwritten: false,
        }
    }

    fn block_fixture(is_v5: bool) -> (DataFork, MemoryReader) {
        let entries = [
            NewDirEntry::new(b"alpha", 130, DirFileType::RegularFile),
            NewDirEntry::new(b"beta", 131, DirFileType::Directory),
        ];
        let raw = build_block_directory(&entries, OWNER, PARENT, 4096, is_v5, true, UUID, 320, 9)
            .unwrap();
        let mut reader = MemoryReader::default();
        reader.insert(40, raw);
        (DataFork::Extents(vec![extent(0, 40, 1)]), reader)
    }

    fn leaf_fixture(is_v5: bool) -> (DataFork, MemoryReader) {
        let entries: Vec<_> = (0..20)
            .map(|index| {
                NewDirEntry::new(
                    format!("entry-{index:02}").as_bytes(),
                    100 + index as u64,
                    DirFileType::RegularFile,
                )
            })
            .collect();
        let count =
            leaf_directory_data_block_count(&entries, OWNER, PARENT, 512, is_v5, true).unwrap();
        let mut addresses: Vec<u64> = (0..count).map(|index| 100 + index as u64).collect();
        addresses.push(200);
        let build = build_leaf_directory(
            &entries, OWNER, PARENT, 512, is_v5, true, UUID, &addresses, 9,
        )
        .unwrap();

        let mut reader = MemoryReader::default();
        let mut extents = Vec::new();
        for (index, raw) in build.data_blocks.into_iter().enumerate() {
            reader.insert(100 + index as u64, raw);
            extents.push(extent(index as u64, 100 + index as u64, 1));
        }
        reader.insert(200, build.leaf_block);
        extents.push(extent(LEAF_BLOCK, 200, 1));
        (DataFork::Extents(extents), reader)
    }

    fn node_fixture(is_v5: bool) -> (DataFork, MemoryReader) {
        let entries: Vec<_> = (0..100)
            .map(|index| {
                NewDirEntry::new(
                    format!("node-entry-{index:03}").as_bytes(),
                    1_000 + index as u64,
                    DirFileType::RegularFile,
                )
            })
            .collect();
        let data_count =
            leaf_directory_data_block_count(&entries, OWNER, PARENT, 512, is_v5, true).unwrap();
        let leaf_capacity = leaf_node_record_capacity(512, is_v5).unwrap();
        let leaf_count = (entries.len() + 2).div_ceil(leaf_capacity);
        assert!(leaf_count > 1);

        let mut addresses = Vec::new();
        addresses.extend((0..data_count).map(|index| 100 + index as u64));
        addresses.extend((0..leaf_count).map(|index| 200 + index as u64));
        addresses.push(300);
        addresses.push(400);
        let build = build_node_directory(
            &entries, OWNER, PARENT, 512, is_v5, true, UUID, &addresses, 11,
        )
        .unwrap();

        let mut reader = MemoryReader::default();
        let mut extents = Vec::new();
        for (index, raw) in build.data_blocks.into_iter().enumerate() {
            reader.insert(100 + index as u64, raw);
            extents.push(extent(index as u64, 100 + index as u64, 1));
        }
        for (index, raw) in build.leaf_blocks.into_iter().enumerate() {
            reader.insert(200 + index as u64, raw);
            extents.push(extent(LEAF_BLOCK + 1 + index as u64, 200 + index as u64, 1));
        }
        reader.insert(300, build.root_block);
        extents.push(extent(LEAF_BLOCK, 300, 1));
        reader.insert(400, build.free_block);
        extents.push(extent(XFS_DIR2_FREE_OFFSET / 512, 400, 1));
        extents.sort_by_key(|extent| extent.file_offset);
        (DataFork::Extents(extents), reader)
    }

    fn recalc_da(raw: &mut [u8], is_v5: bool) {
        if is_v5 {
            crc::recalculate_crc_le(raw, 12).unwrap();
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn write_da_block(
        kind: BlockKind,
        _logical: u64,
        physical: u64,
        entries: &[(u32, u32)],
        forw: u32,
        back: u32,
        level: Option<u16>,
        is_v5: bool,
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 512];
        raw[8..10].copy_from_slice(&(kind.magic(is_v5) as u16).to_be_bytes());
        raw[0..4].copy_from_slice(&forw.to_be_bytes());
        raw[4..8].copy_from_slice(&back.to_be_bytes());
        let count_offset = if is_v5 { 56 } else { 12 };
        raw[count_offset..count_offset + 2].copy_from_slice(&(entries.len() as u16).to_be_bytes());
        if let Some(level) = level {
            raw[count_offset + 2..count_offset + 4].copy_from_slice(&level.to_be_bytes());
        }
        let entries_offset = kind.header_size(is_v5);
        for (index, (hash, address)) in entries.iter().enumerate() {
            let offset = entries_offset + index * LeafEntry::SIZE;
            raw[offset..offset + 4].copy_from_slice(&hash.to_be_bytes());
            raw[offset + 4..offset + 8].copy_from_slice(&address.to_be_bytes());
        }
        if is_v5 {
            raw[16..24].copy_from_slice(&physical.to_be_bytes());
            raw[24..32].copy_from_slice(&0u64.to_be_bytes());
            raw[32..48].copy_from_slice(&UUID);
            raw[48..56].copy_from_slice(&OWNER.to_be_bytes());
            recalc_da(&mut raw, true);
        }
        raw
    }

    fn collision_fixture(is_v5: bool) -> (DataFork, MemoryReader, [u32; 2]) {
        let first = b"collision-1001".as_slice();
        let second = b"collision-1100".as_slice();
        assert_eq!(dir2_hash(first), dir2_hash(second));
        let entries = [
            NewDirEntry::new(first, 501, DirFileType::RegularFile),
            NewDirEntry::new(second, 502, DirFileType::Socket),
        ];
        let mut data =
            build_block_directory(&entries, OWNER, PARENT, 512, is_v5, true, UUID, 100, 7).unwrap();
        let (parsed, _) = parse_block_directory(&data, true).unwrap();
        let tags = [
            u32::from(parsed.iter().find(|entry| entry.name == first).unwrap().tag),
            u32::from(
                parsed
                    .iter()
                    .find(|entry| entry.name == second)
                    .unwrap()
                    .tag,
            ),
        ];
        let data_magic = if is_v5 {
            XFS_DIR3_DATA_MAGIC
        } else {
            XFS_DIR2_DATA_MAGIC
        };
        data[0..4].copy_from_slice(&data_magic.to_be_bytes());
        if is_v5 {
            crc::recalculate_crc_le(&mut data, 4).unwrap();
        }

        let hash = dir2_hash(first);
        let root = write_da_block(
            BlockKind::Node,
            LEAF_BLOCK,
            300,
            &[(hash, (LEAF_BLOCK + 1) as u32)],
            0,
            0,
            Some(1),
            is_v5,
        );
        let leaf0 = write_da_block(
            BlockKind::LeafN,
            LEAF_BLOCK + 1,
            200,
            &[(hash, tags[0] / 8)],
            (LEAF_BLOCK + 2) as u32,
            0,
            None,
            is_v5,
        );
        let leaf1 = write_da_block(
            BlockKind::LeafN,
            LEAF_BLOCK + 2,
            201,
            &[(hash, tags[1] / 8)],
            0,
            (LEAF_BLOCK + 1) as u32,
            None,
            is_v5,
        );

        let mut reader = MemoryReader::default();
        reader.insert(100, data);
        reader.insert(200, leaf0);
        reader.insert(201, leaf1);
        reader.insert(300, root);
        let fork = DataFork::Extents(vec![
            extent(0, 100, 1),
            extent(LEAF_BLOCK, 300, 1),
            extent(LEAF_BLOCK + 1, 200, 1),
            extent(LEAF_BLOCK + 2, 201, 1),
        ]);
        (fork, reader, tags)
    }

    #[test]
    fn block_and_single_leaf_lookup_work_for_v4_and_v5() {
        for is_v5 in [false, true] {
            let (fork, reader) = block_fixture(is_v5);
            let (inode, file_type) =
                lookup_directory(&fork, b"alpha", &geometry(4096), &options(is_v5), &reader)
                    .unwrap();
            assert_eq!(inode, 130);
            assert_eq!(file_type, DirFileType::RegularFile);
            assert_eq!(*reader.reads.borrow(), vec![40]);
            assert!(matches!(
                lookup_directory(&fork, b"missing", &geometry(4096), &options(is_v5), &reader,),
                Err(FsError::NotFound)
            ));

            let (fork, reader) = leaf_fixture(is_v5);
            let (inode, file_type) =
                lookup_directory(&fork, b"entry-19", &geometry(512), &options(is_v5), &reader)
                    .unwrap();
            assert_eq!(inode, 119);
            assert_eq!(file_type, DirFileType::RegularFile);
            assert_eq!(reader.reads.borrow().len(), 3);
        }
    }

    #[test]
    fn node_lookup_reads_one_hash_path_instead_of_the_whole_directory() {
        for is_v5 in [false, true] {
            for (name, expected) in [
                ("node-entry-000", 1_000),
                ("node-entry-057", 1_057),
                ("node-entry-099", 1_099),
            ] {
                let (fork, reader) = node_fixture(is_v5);
                let (inode, file_type) = lookup_directory(
                    &fork,
                    name.as_bytes(),
                    &geometry(512),
                    &options(is_v5),
                    &reader,
                )
                .unwrap();
                assert_eq!(inode, expected);
                assert_eq!(file_type, DirFileType::RegularFile);
                let reads = reader.reads.borrow();
                assert!(reads.len() <= 4, "unexpected reads: {reads:?}");
                assert!(reads.len() >= 3);
                assert!(reads.contains(&300));
            }

            let (fork, reader) = node_fixture(is_v5);
            assert!(matches!(
                lookup_directory(
                    &fork,
                    b"not-present",
                    &geometry(512),
                    &options(is_v5),
                    &reader,
                ),
                Err(FsError::NotFound)
            ));
            assert!(reader.reads.borrow().len() <= 3);
        }
    }

    #[test]
    fn btree_data_forks_are_mapped_on_demand() {
        for is_v5 in [false, true] {
            let (fork, mut reader) = node_fixture(is_v5);
            let DataFork::Extents(extents) = fork else {
                unreachable!()
            };
            let plan = crate::bmbt_write::plan_bmbt(
                &extents,
                &[1_000, 1_001, 1_002, 1_003],
                &[],
                20,
                OWNER,
                UUID,
                512,
                512,
                is_v5,
                13,
            )
            .unwrap();
            assert!(plan.root_level > 0);
            for (block, raw) in plan.blocks.into_iter().zip(plan.buffers) {
                reader.insert(block, raw);
            }
            let fork = DataFork::Btree {
                level: plan.root_level,
                num_recs: plan.root_num_records,
                data: plan.root_data,
            };
            let (inode, _) = lookup_directory(
                &fork,
                b"node-entry-057",
                &geometry(512),
                &options(is_v5),
                &reader,
            )
            .unwrap();
            assert_eq!(inode, 1_057);
            assert!(reader.reads.borrow().len() <= 16);
        }
    }

    #[test]
    fn sibling_links_resolve_hash_collisions_and_reject_duplicates() {
        for is_v5 in [false, true] {
            let (fork, mut reader, tags) = collision_fixture(is_v5);
            let first = lookup_directory(
                &fork,
                b"collision-1001",
                &geometry(512),
                &options(is_v5),
                &reader,
            )
            .unwrap();
            assert_eq!(first.0, 501);
            reader.reads.borrow_mut().clear();
            let second = lookup_directory(
                &fork,
                b"collision-1100",
                &geometry(512),
                &options(is_v5),
                &reader,
            )
            .unwrap();
            assert_eq!(second, (502, DirFileType::Socket));
            assert_eq!(*reader.reads.borrow(), vec![100, 300, 200, 201]);

            let mut duplicate = reader.blocks[&201].clone();
            let address_offset = if is_v5 { 68 } else { 20 };
            duplicate[address_offset..address_offset + 4]
                .copy_from_slice(&(tags[0] / 8).to_be_bytes());
            recalc_da(&mut duplicate, is_v5);
            reader.insert(201, duplicate);
            assert!(matches!(
                lookup_directory(
                    &fork,
                    b"collision-1001",
                    &geometry(512),
                    &options(is_v5),
                    &reader,
                ),
                Err(FsError::Corrupted)
            ));
        }
    }

    #[test]
    fn sibling_cycles_and_wrong_back_links_are_corruption() {
        for is_v5 in [false, true] {
            let (fork, mut reader, _) = collision_fixture(is_v5);
            let mut leaf0 = reader.blocks[&200].clone();
            let mut leaf1 = reader.blocks[&201].clone();
            let count_offset = if is_v5 { 56 } else { 12 };
            let address_offset = if is_v5 { 68 } else { 20 };
            leaf0[address_offset..address_offset + 4].copy_from_slice(&0u32.to_be_bytes());
            leaf0[count_offset + 2..count_offset + 4].copy_from_slice(&1u16.to_be_bytes());
            leaf1[0..4].copy_from_slice(&((LEAF_BLOCK + 1) as u32).to_be_bytes());
            recalc_da(&mut leaf0, is_v5);
            recalc_da(&mut leaf1, is_v5);
            reader.insert(200, leaf0);
            reader.insert(201, leaf1.clone());
            assert!(matches!(
                lookup_directory(
                    &fork,
                    b"collision-1001",
                    &geometry(512),
                    &options(is_v5),
                    &reader,
                ),
                Err(FsError::Corrupted)
            ));

            leaf1[4..8].copy_from_slice(&(LEAF_BLOCK as u32).to_be_bytes());
            recalc_da(&mut leaf1, is_v5);
            reader.insert(201, leaf1);
            assert!(matches!(
                lookup_directory(
                    &fork,
                    b"collision-1100",
                    &geometry(512),
                    &options(is_v5),
                    &reader,
                ),
                Err(FsError::Corrupted)
            ));

            let (fork, mut reader, _) = collision_fixture(is_v5);
            let mut leaf1 = reader.blocks[&201].clone();
            let hash_offset = if is_v5 { 64 } else { 16 };
            let hash = dir2_hash(b"collision-1001");
            leaf1[hash_offset..hash_offset + 4].copy_from_slice(&(hash - 1).to_be_bytes());
            recalc_da(&mut leaf1, is_v5);
            reader.insert(201, leaf1);
            assert!(matches!(
                lookup_directory(
                    &fork,
                    b"collision-1100",
                    &geometry(512),
                    &options(is_v5),
                    &reader,
                ),
                Err(FsError::Corrupted)
            ));
        }
    }

    #[test]
    fn v5_lookup_checks_crc_blkno_owner_uuid_and_leaf_bounds() {
        let (fork, mut reader) = leaf_fixture(true);
        let original = reader.blocks[&200].clone();
        for case in 0..8 {
            let mut raw = original.clone();
            match case {
                0 => raw[200] ^= 1,
                1 => {
                    raw[16..24].copy_from_slice(&201u64.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
                2 => {
                    raw[48..56].copy_from_slice(&129u64.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
                3 => {
                    raw[32] ^= 1;
                    recalc_da(&mut raw, true);
                }
                4 => {
                    raw[56..58].copy_from_slice(&u16::MAX.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
                5 => {
                    raw[64..68].copy_from_slice(&u32::MAX.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
                6 => {
                    raw[58..60].copy_from_slice(&1u16.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
                _ => {
                    let target_hash = dir2_hash(b"entry-17");
                    let count = u16::from_be_bytes([raw[56], raw[57]]) as usize;
                    let index = (0..count)
                        .find(|index| {
                            let offset = 64 + index * 8;
                            u32::from_be_bytes(raw[offset..offset + 4].try_into().unwrap())
                                == target_hash
                        })
                        .unwrap();
                    let offset = 64 + index * 8 + 4;
                    raw[offset..offset + 4].copy_from_slice(&1u32.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
            }
            reader.insert(200, raw);
            assert!(
                matches!(
                    lookup_directory(&fork, b"entry-17", &geometry(512), &options(true), &reader,),
                    Err(FsError::Corrupted)
                ),
                "case {case}"
            );
        }
    }

    #[test]
    fn v5_node_identity_fields_are_checked() {
        let (fork, mut reader) = node_fixture(true);
        let original = reader.blocks[&300].clone();
        for case in 0..4 {
            let mut raw = original.clone();
            match case {
                0 => raw[300] ^= 1,
                1 => {
                    raw[16..24].copy_from_slice(&301u64.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
                2 => {
                    raw[48..56].copy_from_slice(&129u64.to_be_bytes());
                    recalc_da(&mut raw, true);
                }
                _ => {
                    raw[32] ^= 1;
                    recalc_da(&mut raw, true);
                }
            }
            reader.insert(300, raw);
            assert!(
                matches!(
                    lookup_directory(
                        &fork,
                        b"node-entry-057",
                        &geometry(512),
                        &options(true),
                        &reader,
                    ),
                    Err(FsError::Corrupted)
                ),
                "case {case}"
            );
        }
    }

    #[test]
    fn data_entry_tags_hashes_and_metadata_are_checked() {
        let (fork, mut reader) = leaf_fixture(true);
        let leaf = reader.blocks[&200].clone();
        let hash = dir2_hash(b"entry-17");
        let count = u16::from_be_bytes([leaf[56], leaf[57]]) as usize;
        let mut selected = None;
        for index in 0..count {
            let offset = 64 + index * 8;
            if u32::from_be_bytes(leaf[offset..offset + 4].try_into().unwrap()) == hash {
                selected = Some(u32::from_be_bytes(
                    leaf[offset + 4..offset + 8].try_into().unwrap(),
                ));
                break;
            }
        }
        let address = selected.unwrap();
        let data_block = u64::from(address) * 8 / 512;
        let data_offset = (u64::from(address) * 8 % 512) as usize;
        let physical = 100 + data_block;
        let original = reader.blocks[&physical].clone();

        let mut bad_tag = original.clone();
        let name_len = bad_tag[data_offset + 8] as usize;
        let size = (8 + 1 + name_len + 1 + 2 + 7) & !7;
        let tag_offset = data_offset + size - 2;
        bad_tag[tag_offset] ^= 1;
        crc::recalculate_crc_le(&mut bad_tag, 4).unwrap();
        reader.insert(physical, bad_tag);
        assert!(matches!(
            lookup_directory(&fork, b"entry-17", &geometry(512), &options(true), &reader,),
            Err(FsError::Corrupted)
        ));

        reader.insert(physical, original.clone());
        let mut bad_location = original;
        bad_location[8..16].copy_from_slice(&(physical + 1).to_be_bytes());
        crc::recalculate_crc_le(&mut bad_location, 4).unwrap();
        reader.insert(physical, bad_location);
        assert!(matches!(
            lookup_directory(&fork, b"entry-17", &geometry(512), &options(true), &reader,),
            Err(FsError::Corrupted)
        ));

        drop(leaf);
        let (fork, mut reader) = leaf_fixture(true);
        let mut reversed = reader.blocks[&200].clone();
        let first_hash: [u8; 4] = reversed[64..68].try_into().unwrap();
        let second_hash: [u8; 4] = reversed[72..76].try_into().unwrap();
        reversed[64..68].copy_from_slice(&second_hash);
        reversed[72..76].copy_from_slice(&first_hash);
        recalc_da(&mut reversed, true);
        reader.insert(200, reversed);
        assert!(matches!(
            lookup_directory(&fork, b"entry-17", &geometry(512), &options(true), &reader,),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn depth_pointer_and_block_budgets_are_enforced() {
        let (fork, reader) = leaf_fixture(false);
        let mut limited = options(false);
        limited.max_blocks = 2;
        assert!(matches!(
            lookup_directory(&fork, b"entry-19", &geometry(512), &limited, &reader,),
            Err(FsError::Corrupted)
        ));

        let (fork, mut reader) = node_fixture(true);
        let mut root = reader.blocks[&300].clone();
        root[58..60].copy_from_slice(&2u16.to_be_bytes());
        recalc_da(&mut root, true);
        reader.insert(300, root);
        assert!(matches!(
            lookup_directory(
                &fork,
                b"node-entry-057",
                &geometry(512),
                &options(true),
                &reader,
            ),
            Err(FsError::Corrupted)
        ));
        let mut shallow = options(true);
        shallow.max_depth = 1;
        assert!(matches!(
            lookup_directory(&fork, b"node-entry-057", &geometry(512), &shallow, &reader,),
            Err(FsError::Corrupted)
        ));

        let (fork, mut reader) = node_fixture(false);
        let mut root = reader.blocks[&300].clone();
        root[20..24].copy_from_slice(&1u32.to_be_bytes());
        reader.insert(300, root);
        assert!(matches!(
            lookup_directory(
                &fork,
                b"node-entry-057",
                &geometry(512),
                &options(false),
                &reader,
            ),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn directory_blocks_may_span_multiple_filesystem_blocks() {
        let entries = [NewDirEntry::new(b"wide", 777, DirFileType::RegularFile)];
        let raw =
            build_block_directory(&entries, OWNER, PARENT, 1024, true, true, UUID, 100, 5).unwrap();
        let mut reader = MemoryReader::default();
        reader.insert(100, raw[..512].to_vec());
        reader.insert(101, raw[512..].to_vec());
        let fork = DataFork::Extents(vec![extent(0, 100, 2)]);
        let geometry = DirGeometry::new(512, 1024).with_total_fs_blocks(1_000);
        let result = lookup_directory(&fork, b"wide", &geometry, &options(true), &reader).unwrap();
        assert_eq!(result, (777, DirFileType::RegularFile));
        assert_eq!(*reader.reads.borrow(), vec![100, 101]);
    }

    #[test]
    fn shortform_lookup_does_not_read_blocks_and_detects_duplicates() {
        let data = add_shortform_entry(
            &[],
            &NewDirEntry::new(b"inline", 900, DirFileType::SymbolicLink),
            PARENT,
            false,
            true,
            256,
        )
        .unwrap();
        let reader = MemoryReader::default();
        let result = lookup_directory(
            &DataFork::Local(data.clone()),
            b"inline",
            &geometry(512),
            &options(false),
            &reader,
        )
        .unwrap();
        assert_eq!(result, (900, DirFileType::SymbolicLink));
        assert!(reader.reads.borrow().is_empty());

        let mut duplicate = data;
        let mut bytes = crate::dir_write::serialize_shortform_entry(
            &NewDirEntry::new(b"inline", 901, DirFileType::RegularFile),
            0,
            false,
            true,
        );
        duplicate.append(&mut bytes);
        duplicate[0] = 2;
        // The duplicate fixture only needs a second matching record; its
        // saved shortform offset is irrelevant to lookup.
        assert!(matches!(
            lookup_directory(
                &DataFork::Local(duplicate),
                b"inline",
                &geometry(512),
                &options(false),
                &reader,
            ),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn invalid_arguments_names_and_extents_are_rejected() {
        let (fork, reader) = block_fixture(false);
        assert!(matches!(
            lookup_directory(&fork, b"", &geometry(4096), &options(false), &reader),
            Err(FsError::InvalidPath)
        ));
        assert!(matches!(
            lookup_directory(
                &fork,
                &[b'x'; XFS_NAME_MAX + 1],
                &geometry(4096),
                &options(false),
                &reader,
            ),
            Err(FsError::PathTooLong)
        ));
        assert!(matches!(
            lookup_directory(
                &fork,
                b"alpha",
                &DirGeometry::new(512, 1023),
                &options(false),
                &reader,
            ),
            Err(FsError::InvalidArgument)
        ));
        assert!(matches!(
            lookup_directory(
                &fork,
                b"alpha",
                &geometry(4096),
                &DirLookupOptions::new(OWNER, true, true, None),
                &reader,
            ),
            Err(FsError::InvalidArgument)
        ));

        let overlapping = DataFork::Extents(vec![extent(0, 40, 2), extent(1, 42, 1)]);
        assert!(matches!(
            lookup_directory(
                &overlapping,
                b"alpha",
                &geometry(4096),
                &options(false),
                &reader,
            ),
            Err(FsError::Corrupted)
        ));
        let mut unwritten = extent(0, 40, 1);
        unwritten.is_unwritten = true;
        assert!(matches!(
            lookup_directory(
                &DataFork::Extents(vec![unwritten]),
                b"alpha",
                &geometry(4096),
                &options(false),
                &reader,
            ),
            Err(FsError::Corrupted)
        ));
    }
}
