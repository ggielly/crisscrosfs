//! Generic collection and bulk encoding for AG-local, short-format XFS B+trees.
//!
//! This module supports the BNO, CNT, IBT and FIBT trees in both v4 and v5
//! formats. Records are kept as raw big-endian on-disk bytes so callers do not
//! need to lose sparse-inode fields or other format details while rebuilding a
//! tree.
//!
//! Block numbers in snapshots, plans, sibling pointers and child pointers are
//! AG-relative. [`crate::btree::BlockReader`] addresses are absolute filesystem
//! block numbers, while v5 `bb_blkno` is a 64-bit disk address in 512-byte
//! basic-block units. Both public operations therefore take `ag_number` and
//! `ag_blocks` to translate these addresses; `sector_size` is validated for
//! compatibility with the filesystem geometry.

#[cfg(feature = "alloc")]
extern crate alloc;

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec,
    vec::Vec,
};

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::{
    btree::{BlockReader, BtreeBlockShort, MAX_BTREE_BLOCKS_PER_OPERATION},
    constants::*,
    freespace::NULLAGBLOCK,
};

const SHORT_PTR_SIZE: usize = 4;
const ALLOC_KEY_SIZE: usize = 8;
const INODE_KEY_SIZE: usize = 4;
const MIN_BLOCK_SIZE: usize = 512;
const MAX_BLOCK_SIZE: usize = 64 * 1024;
const MAX_SHORT_BTREE_LEVEL: u16 = 16;
const MAX_SHORT_BTREE_RECORDS: usize = 1 << 20;
const MAX_SHORT_BTREE_OPERATION_BYTES: usize = 64 * 1024 * 1024;

/// The four AG-local short-format B+tree types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShortBtreeKind {
    /// Free space indexed by starting block number (BNOBT).
    AllocBno,
    /// Free space indexed by block count, then starting block (CNTBT).
    AllocCnt,
    /// Inode allocation B+tree (IBT).
    Inode,
    /// Free inode B+tree (FIBT).
    FreeInode,
}

impl ShortBtreeKind {
    fn magic(self, is_v5: bool) -> u32 {
        match (self, is_v5) {
            (Self::AllocBno, false) => XFS_ABTB_MAGIC,
            (Self::AllocBno, true) => XFS_ABTB_CRC_MAGIC,
            (Self::AllocCnt, false) => XFS_ABTC_MAGIC,
            (Self::AllocCnt, true) => XFS_ABTC_CRC_MAGIC,
            (Self::Inode, false) => XFS_IBT_MAGIC,
            (Self::Inode, true) => XFS_IBT_CRC_MAGIC,
            (Self::FreeInode, false) => XFS_FIBT_MAGIC,
            (Self::FreeInode, true) => XFS_FIBT_CRC_MAGIC,
        }
    }

    fn record_size(self) -> usize {
        match self {
            Self::AllocBno | Self::AllocCnt => 8,
            Self::Inode | Self::FreeInode => 16,
        }
    }

    fn key_size(self) -> usize {
        match self {
            Self::AllocBno | Self::AllocCnt => ALLOC_KEY_SIZE,
            Self::Inode | Self::FreeInode => INODE_KEY_SIZE,
        }
    }

    fn is_alloc(self) -> bool {
        matches!(self, Self::AllocBno | Self::AllocCnt)
    }
}

/// All leaf records and node block numbers collected from a short B+tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortBtreeSnapshot {
    /// Raw big-endian leaf records, in tree order.
    pub records: Vec<Vec<u8>>,
    /// AG-relative node block numbers in root-first depth-first order.
    pub blocks: Vec<u32>,
    /// The root node's level (zero for a single leaf).
    pub root_level: u16,
}

/// A fully encoded short B+tree rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortBtreeBuildPlan {
    /// The root node's level (zero for a single leaf).
    pub root_level: u16,
    /// AG-relative block numbers, with the reused root at index zero.
    pub blocks: Vec<u32>,
    /// Complete block buffers, aligned with [`Self::blocks`].
    pub buffers: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct SortKey([u32; 2]);

#[derive(Debug, Clone, Copy)]
struct PreviousRecord {
    key: SortKey,
    end_block: Option<u64>,
}

#[derive(Debug, Clone, Copy)]
struct NodeSummary {
    first_key: SortKey,
}

#[derive(Debug, Clone, Copy)]
struct LevelTail {
    block: u32,
    right: u32,
}

struct CollectState {
    kind: ShortBtreeKind,
    block_size: usize,
    is_v5: bool,
    ag_number: u32,
    ag_blocks: u32,
    expected_uuid: Option<[u8; 16]>,
    visited: BTreeSet<u64>,
    level_tails: BTreeMap<u16, LevelTail>,
    blocks: Vec<u32>,
    records: Vec<Vec<u8>>,
    previous_record: Option<PreviousRecord>,
    blocks_read: usize,
    bytes_read: usize,
}

impl CollectState {
    fn spend_block(&mut self) -> FsResult<()> {
        if self.blocks_read >= MAX_BTREE_BLOCKS_PER_OPERATION {
            return Err(FsError::Corrupted);
        }
        self.blocks_read = self
            .blocks_read
            .checked_add(1)
            .ok_or(FsError::ArithmeticOverflow)?;
        Ok(())
    }

    fn spend_bytes(&mut self, len: usize) -> FsResult<()> {
        let total = self
            .bytes_read
            .checked_add(len)
            .ok_or(FsError::ArithmeticOverflow)?;
        if total > MAX_SHORT_BTREE_OPERATION_BYTES {
            return Err(FsError::Corrupted);
        }
        self.bytes_read = total;
        Ok(())
    }

    fn spend_record(&mut self) -> FsResult<()> {
        if self.records.len() >= MAX_SHORT_BTREE_RECORDS {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
enum BuildEntries {
    Records { start: usize, end: usize },
    Children(Vec<usize>),
}

#[derive(Debug, Clone)]
struct BuildNode {
    level: u16,
    left: u32,
    right: u32,
    entries: BuildEntries,
}

impl BuildNode {
    fn records(start: usize, end: usize) -> Self {
        Self {
            level: 0,
            left: NULLAGBLOCK,
            right: NULLAGBLOCK,
            entries: BuildEntries::Records { start, end },
        }
    }

    fn children(level: u16, children: Vec<usize>) -> Self {
        Self {
            level,
            left: NULLAGBLOCK,
            right: NULLAGBLOCK,
            entries: BuildEntries::Children(children),
        }
    }

    fn num_entries(&self) -> usize {
        match &self.entries {
            BuildEntries::Records { start, end } => end.saturating_sub(*start),
            BuildEntries::Children(children) => children.len(),
        }
    }
}

fn validate_block_size(block_size: usize) -> FsResult<()> {
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }
    Ok(())
}

fn header_size(is_v5: bool) -> usize {
    if is_v5 {
        BtreeBlockShort::SIZE_V5
    } else {
        BtreeBlockShort::SIZE_V4
    }
}

fn max_records(
    kind: ShortBtreeKind,
    block_size: usize,
    is_v5: bool,
    level: u16,
) -> FsResult<usize> {
    validate_block_size(block_size)?;
    let payload = block_size
        .checked_sub(header_size(is_v5))
        .ok_or(FsError::BufferTooSmall)?;
    let footprint = if level == 0 {
        kind.record_size()
    } else {
        kind.key_size()
            .checked_add(SHORT_PTR_SIZE)
            .ok_or(FsError::ArithmeticOverflow)?
    };
    if footprint == 0 {
        return Err(FsError::InvalidArgument);
    }
    Ok(payload / footprint)
}

fn pointer_offset(
    kind: ShortBtreeKind,
    block_size: usize,
    is_v5: bool,
    level: u16,
) -> FsResult<usize> {
    if level == 0 {
        return Err(FsError::InvalidBlockType);
    }
    let max_records = max_records(kind, block_size, is_v5, level)?;
    header_size(is_v5)
        .checked_add(
            max_records
                .checked_mul(kind.key_size())
                .ok_or(FsError::ArithmeticOverflow)?,
        )
        .ok_or(FsError::ArithmeticOverflow)
}

fn ceil_div(value: usize, divisor: usize) -> FsResult<usize> {
    if divisor == 0 {
        return Err(FsError::InvalidArgument);
    }
    value
        .checked_div(divisor)
        .and_then(|quotient| quotient.checked_add(usize::from(!value.is_multiple_of(divisor))))
        .ok_or(FsError::ArithmeticOverflow)
}

fn absolute_block(ag_number: u32, ag_blocks: u32, ag_block: u32) -> FsResult<u64> {
    if ag_blocks == 0 {
        return Err(FsError::InvalidArgument);
    }
    if u64::from(ag_block) >= u64::from(ag_blocks) {
        return Err(FsError::InvalidArgument);
    }
    let ag_start = (u64::from(ag_number))
        .checked_mul(u64::from(ag_blocks))
        .ok_or(FsError::ArithmeticOverflow)?;
    ag_start
        .checked_add(u64::from(ag_block))
        .ok_or(FsError::ArithmeticOverflow)
}

fn validate_sector_size(sector_size: u32, block_size: usize) -> FsResult<()> {
    let sector_size = usize::try_from(sector_size).map_err(|_| FsError::InvalidArgument)?;
    if sector_size < 512 || sector_size > block_size || !sector_size.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }
    Ok(())
}

fn disk_address(absolute_fs_block: u64, block_size: usize, sector_size: u32) -> FsResult<u64> {
    // Retain sector-size validation for the public API, but xfs_daddr_t is
    // always expressed in 512-byte basic blocks.
    validate_sector_size(sector_size, block_size)?;
    crate::address::fs_block_to_daddr(absolute_fs_block, block_size)
}

fn record_key(kind: ShortBtreeKind, record: &[u8]) -> FsResult<SortKey> {
    if record.len() != kind.record_size() {
        return Err(FsError::Corrupted);
    }
    let first = record.read_be_u32(0)?;
    let key = match kind {
        ShortBtreeKind::AllocBno => SortKey([first, record.read_be_u32(4)?]),
        ShortBtreeKind::AllocCnt => SortKey([record.read_be_u32(4)?, first]),
        ShortBtreeKind::Inode | ShortBtreeKind::FreeInode => SortKey([first, 0]),
    };
    validate_record_values(kind, record)?;
    Ok(key)
}

fn validate_record_values(kind: ShortBtreeKind, record: &[u8]) -> FsResult<Option<u64>> {
    if record.len() != kind.record_size() {
        return Err(FsError::Corrupted);
    }
    if !kind.is_alloc() {
        return Ok(None);
    }

    let start = u64::from(record.read_be_u32(0)?);
    let count = u64::from(record.read_be_u32(4)?);
    if count == 0 {
        return Err(FsError::Corrupted);
    }
    let end = start
        .checked_add(count)
        .ok_or(FsError::ArithmeticOverflow)?;
    if end > u64::from(u32::MAX) + 1 {
        return Err(FsError::Corrupted);
    }
    Ok(Some(end))
}

fn internal_key(kind: ShortBtreeKind, raw: &[u8]) -> FsResult<SortKey> {
    if raw.len() != kind.key_size() {
        return Err(FsError::Corrupted);
    }
    let first = raw.read_be_u32(0)?;
    Ok(match kind {
        ShortBtreeKind::AllocBno => SortKey([first, raw.read_be_u32(4)?]),
        ShortBtreeKind::AllocCnt => SortKey([first, raw.read_be_u32(4)?]),
        ShortBtreeKind::Inode | ShortBtreeKind::FreeInode => SortKey([first, 0]),
    })
}

fn validate_record_sequence(kind: ShortBtreeKind, records: &[Vec<u8>]) -> FsResult<()> {
    let mut previous: Option<PreviousRecord> = None;
    for record in records {
        let key = record_key(kind, record)?;
        let end_block = validate_record_values(kind, record)?;
        if let Some(previous) = previous {
            if key <= previous.key {
                return Err(FsError::Corrupted);
            }
            if kind == ShortBtreeKind::AllocBno
                && previous
                    .end_block
                    .is_some_and(|end| end > u64::from(key.0[0]))
            {
                return Err(FsError::Corrupted);
            }
        }
        previous = Some(PreviousRecord { key, end_block });
    }
    Ok(())
}

fn append_collected_record(state: &mut CollectState, record: &[u8]) -> FsResult<SortKey> {
    state.spend_record()?;
    let key = record_key(state.kind, record)?;
    let end_block = validate_record_values(state.kind, record)?;
    if let Some(previous) = state.previous_record {
        if key <= previous.key {
            return Err(FsError::Corrupted);
        }
        if state.kind == ShortBtreeKind::AllocBno
            && previous
                .end_block
                .is_some_and(|end| end > u64::from(key.0[0]))
        {
            return Err(FsError::Corrupted);
        }
    }
    state.previous_record = Some(PreviousRecord { key, end_block });
    state.records.push(record.to_vec());
    Ok(key)
}

fn collect_node<R: BlockReader>(
    state: &mut CollectState,
    reader: &R,
    ag_block: u32,
    expected_level: u16,
    is_root: bool,
) -> FsResult<Option<NodeSummary>> {
    if ag_block == NULLAGBLOCK || u64::from(ag_block) >= u64::from(state.ag_blocks) {
        return Err(FsError::Corrupted);
    }
    let absolute = absolute_block(state.ag_number, state.ag_blocks, ag_block)?;
    if !state.visited.insert(absolute) {
        return Err(FsError::Corrupted);
    }
    state.spend_block()?;

    let raw = reader.read_block(absolute)?;
    if raw.len() < state.block_size {
        return Err(FsError::BufferTooSmall);
    }
    if raw.len() != state.block_size {
        return Err(FsError::Corrupted);
    }
    state.spend_bytes(raw.len())?;

    let header = BtreeBlockShort::parse(&raw, state.is_v5)?;
    if header.magic != state.kind.magic(state.is_v5) {
        return Err(FsError::InvalidMagic);
    }
    header.verify_metadata(
        &raw,
        absolute,
        state.block_size,
        state.ag_number,
        state.expected_uuid,
    )?;
    if header.level != expected_level {
        return Err(FsError::Corrupted);
    }
    if is_root && (header.left_sibling != NULLAGBLOCK || header.right_sibling != NULLAGBLOCK) {
        return Err(FsError::Corrupted);
    }
    if let Some(previous) = state.level_tails.get(&expected_level) {
        if previous.right != ag_block || header.left_sibling != previous.block {
            return Err(FsError::Corrupted);
        }
    } else if header.left_sibling != NULLAGBLOCK {
        return Err(FsError::Corrupted);
    }
    state.level_tails.insert(
        expected_level,
        LevelTail {
            block: ag_block,
            right: header.right_sibling,
        },
    );

    let capacity = max_records(state.kind, state.block_size, state.is_v5, expected_level)?;
    let num_records = header.num_recs as usize;
    if num_records > capacity {
        return Err(FsError::Corrupted);
    }
    state.blocks.push(ag_block);

    if expected_level == 0 {
        if num_records == 0 {
            if !is_root {
                return Err(FsError::Corrupted);
            }
            return Ok(None);
        }

        let records_end = header_size(state.is_v5)
            .checked_add(
                num_records
                    .checked_mul(state.kind.record_size())
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        if records_end > raw.len() {
            return Err(FsError::BufferTooSmall);
        }

        let mut first_key = None;
        for index in 0..num_records {
            let offset = header_size(state.is_v5)
                .checked_add(
                    index
                        .checked_mul(state.kind.record_size())
                        .ok_or(FsError::ArithmeticOverflow)?,
                )
                .ok_or(FsError::ArithmeticOverflow)?;
            let end = offset
                .checked_add(state.kind.record_size())
                .ok_or(FsError::ArithmeticOverflow)?;
            let record = raw.get(offset..end).ok_or(FsError::BufferTooSmall)?;
            let key = append_collected_record(state, record)?;
            first_key.get_or_insert(key);
        }

        return Ok(Some(NodeSummary {
            first_key: first_key.ok_or(FsError::Corrupted)?,
        }));
    }

    if num_records == 0 {
        return Err(FsError::Corrupted);
    }
    let ptrs_offset = pointer_offset(state.kind, state.block_size, state.is_v5, expected_level)?;
    let ptrs_end = ptrs_offset
        .checked_add(
            num_records
                .checked_mul(SHORT_PTR_SIZE)
                .ok_or(FsError::ArithmeticOverflow)?,
        )
        .ok_or(FsError::ArithmeticOverflow)?;
    if ptrs_end > raw.len() {
        return Err(FsError::BufferTooSmall);
    }

    let mut keys = Vec::with_capacity(num_records);
    let mut pointers = Vec::with_capacity(num_records);
    for index in 0..num_records {
        let key_offset = header_size(state.is_v5)
            .checked_add(
                index
                    .checked_mul(state.kind.key_size())
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        let key_end = key_offset
            .checked_add(state.kind.key_size())
            .ok_or(FsError::ArithmeticOverflow)?;
        let key = internal_key(
            state.kind,
            raw.get(key_offset..key_end)
                .ok_or(FsError::BufferTooSmall)?,
        )?;
        if keys.last().is_some_and(|previous| *previous >= key) {
            return Err(FsError::Corrupted);
        }
        keys.push(key);

        let ptr_offset = ptrs_offset
            .checked_add(
                index
                    .checked_mul(SHORT_PTR_SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        let ptr_end = ptr_offset
            .checked_add(SHORT_PTR_SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        let pointer = raw
            .get(ptr_offset..ptr_end)
            .ok_or(FsError::BufferTooSmall)?
            .read_be_u32(0)?;
        if pointer == NULLAGBLOCK || u64::from(pointer) >= u64::from(state.ag_blocks) {
            return Err(FsError::Corrupted);
        }
        pointers.push(pointer);
    }

    let child_level = expected_level.checked_sub(1).ok_or(FsError::Corrupted)?;
    let mut first_key = None;
    for (index, pointer) in pointers.iter().copied().enumerate() {
        let child =
            collect_node(state, reader, pointer, child_level, false)?.ok_or(FsError::Corrupted)?;
        if child.first_key != keys[index] {
            return Err(FsError::Corrupted);
        }
        first_key.get_or_insert(child.first_key);
    }

    Ok(Some(NodeSummary {
        first_key: first_key.ok_or(FsError::Corrupted)?,
    }))
}

/// Collect every leaf record and validate the complete short-format B+tree.
///
/// `root_block` and returned block numbers are AG-relative. The reader is
/// called with absolute filesystem block numbers computed as
/// `ag_number * ag_blocks + ag_block`. `ag_number`, `ag_blocks` and
/// `sector_size` validate the supplied geometry. The v5 `bb_blkno` field is
/// `absolute_fs_block * block_size / 512`.
///
/// Validation includes magic, version, CRCs, levels, capacity, canonical
/// pointer placement, parent/child keys, record ordering, sibling chains and
/// cycles. An empty tree must consist of one empty root leaf.
#[allow(clippy::too_many_arguments)]
pub fn collect_short_btree<R: BlockReader>(
    kind: ShortBtreeKind,
    root_block: u32,
    root_level: u16,
    block_size: usize,
    is_v5: bool,
    ag_number: u32,
    ag_blocks: u32,
    sector_size: u32,
    reader: &R,
) -> FsResult<ShortBtreeSnapshot> {
    collect_short_btree_internal(
        kind,
        root_block,
        root_level,
        block_size,
        is_v5,
        ag_number,
        ag_blocks,
        sector_size,
        reader,
        None,
    )
}

/// Checked collector for VFS reads that also know the metadata UUID.
#[allow(clippy::too_many_arguments)]
pub fn collect_short_btree_checked<R: BlockReader>(
    kind: ShortBtreeKind,
    root_block: u32,
    root_level: u16,
    block_size: usize,
    is_v5: bool,
    ag_number: u32,
    ag_blocks: u32,
    sector_size: u32,
    reader: &R,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<ShortBtreeSnapshot> {
    collect_short_btree_internal(
        kind,
        root_block,
        root_level,
        block_size,
        is_v5,
        ag_number,
        ag_blocks,
        sector_size,
        reader,
        expected_uuid,
    )
}

#[allow(clippy::too_many_arguments)]
fn collect_short_btree_internal<R: BlockReader>(
    kind: ShortBtreeKind,
    root_block: u32,
    root_level: u16,
    block_size: usize,
    is_v5: bool,
    ag_number: u32,
    ag_blocks: u32,
    sector_size: u32,
    reader: &R,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<ShortBtreeSnapshot> {
    validate_block_size(block_size)?;
    validate_sector_size(sector_size, block_size)?;
    if root_level > MAX_SHORT_BTREE_LEVEL {
        return Err(FsError::InvalidArgument);
    }
    if max_records(kind, block_size, is_v5, 0)? == 0
        || max_records(kind, block_size, is_v5, 1)? == 0
    {
        return Err(FsError::InvalidArgument);
    }
    absolute_block(ag_number, ag_blocks, root_block)?;

    let mut state = CollectState {
        kind,
        block_size,
        is_v5,
        ag_number,
        ag_blocks,
        expected_uuid,
        visited: BTreeSet::new(),
        level_tails: BTreeMap::new(),
        blocks: Vec::new(),
        records: Vec::new(),
        previous_record: None,
        blocks_read: 0,
        bytes_read: 0,
    };
    collect_node(&mut state, reader, root_block, root_level, true)?;
    if state
        .level_tails
        .values()
        .any(|tail| tail.right != NULLAGBLOCK)
    {
        return Err(FsError::Corrupted);
    }

    Ok(ShortBtreeSnapshot {
        records: state.records,
        blocks: state.blocks,
        root_level,
    })
}

/// Return the number of blocks used by the canonical bulk-load tree shape.
///
/// Leaf capacity and internal fan-out are computed independently from the
/// canonical XFS record/key/pointer sizes. The empty tree uses one leaf.
pub fn required_block_count(
    kind: ShortBtreeKind,
    record_count: usize,
    block_size: usize,
    is_v5: bool,
) -> FsResult<usize> {
    let leaf_capacity = max_records(kind, block_size, is_v5, 0)?;
    let internal_capacity = max_records(kind, block_size, is_v5, 1)?;
    if leaf_capacity == 0 || internal_capacity == 0 {
        return Err(FsError::InvalidArgument);
    }
    if record_count == 0 {
        return Ok(1);
    }

    let mut level_nodes = ceil_div(record_count, leaf_capacity)?;
    let mut total = level_nodes;
    let mut level = 0u16;
    while level_nodes > 1 {
        level_nodes = ceil_div(level_nodes, internal_capacity)?;
        total = total
            .checked_add(level_nodes)
            .ok_or(FsError::ArithmeticOverflow)?;
        level = level.checked_add(1).ok_or(FsError::ArithmeticOverflow)?;
        if level > MAX_SHORT_BTREE_LEVEL {
            return Err(FsError::InvalidArgument);
        }
    }
    Ok(total)
}

fn select_candidate_blocks(
    root_block: u32,
    existing_blocks: &[u32],
    extra_blocks: &[u32],
    required: usize,
    ag_blocks: u32,
) -> FsResult<Vec<u32>> {
    let needed = required.checked_sub(1).ok_or(FsError::Corrupted)?;
    let input_count = existing_blocks
        .len()
        .checked_add(extra_blocks.len())
        .ok_or(FsError::ArithmeticOverflow)?;
    if input_count > MAX_BTREE_BLOCKS_PER_OPERATION {
        return Err(FsError::InvalidArgument);
    }

    let mut seen = BTreeSet::new();
    seen.insert(root_block);
    let mut root_mentions = 0usize;
    let mut candidates = Vec::with_capacity(needed.min(input_count));
    for block in existing_blocks.iter().chain(extra_blocks) {
        if *block == NULLAGBLOCK || *block >= ag_blocks {
            return Err(FsError::InvalidArgument);
        }
        if *block == root_block {
            root_mentions = root_mentions
                .checked_add(1)
                .ok_or(FsError::ArithmeticOverflow)?;
            if root_mentions > 1 {
                return Err(FsError::InvalidArgument);
            }
            continue;
        }
        if !seen.insert(*block) {
            return Err(FsError::InvalidArgument);
        }
        if candidates.len() < needed {
            candidates.push(*block);
        }
    }
    if candidates.len() < needed {
        return Err(FsError::NoSpace);
    }
    Ok(candidates)
}

fn first_record_for_node<'a>(
    index: usize,
    root: &BuildNode,
    nodes: &[BuildNode],
    records: &'a [Vec<u8>],
) -> FsResult<&'a [u8]> {
    let mut current = index;
    for _ in 0..=MAX_SHORT_BTREE_LEVEL {
        let node = if current == 0 {
            root
        } else {
            nodes.get(current - 1).ok_or(FsError::Corrupted)?
        };
        match &node.entries {
            BuildEntries::Records { start, .. } => {
                return records
                    .get(*start)
                    .map(Vec::as_slice)
                    .ok_or(FsError::Corrupted);
            }
            BuildEntries::Children(children) => {
                current = *children.first().ok_or(FsError::Corrupted)?;
            }
        }
    }
    Err(FsError::Corrupted)
}

fn node_mut<'a>(
    index: usize,
    root: &'a mut BuildNode,
    nodes: &'a mut [BuildNode],
) -> FsResult<&'a mut BuildNode> {
    if index == 0 {
        Ok(root)
    } else {
        nodes.get_mut(index - 1).ok_or(FsError::Corrupted)
    }
}

fn assign_siblings(
    levels: &[Vec<usize>],
    blocks: &[u32],
    root: &mut BuildNode,
    nodes: &mut [BuildNode],
) -> FsResult<()> {
    for level in levels {
        for (position, index) in level.iter().copied().enumerate() {
            let left = if position == 0 {
                NULLAGBLOCK
            } else {
                blocks[level[position - 1]]
            };
            let right = level
                .get(position + 1)
                .map(|next| blocks[*next])
                .unwrap_or(NULLAGBLOCK);
            let node = node_mut(index, root, nodes)?;
            node.left = left;
            node.right = right;
        }
    }
    Ok(())
}

fn write_key(kind: ShortBtreeKind, record: &[u8], output: &mut [u8]) -> FsResult<()> {
    if record.len() != kind.record_size() || output.len() != kind.key_size() {
        return Err(FsError::Corrupted);
    }
    match kind {
        ShortBtreeKind::AllocBno => {
            // The kernel copies both fields; only ar_startblock is compared.
            output.copy_from_slice(&record[..ALLOC_KEY_SIZE]);
        }
        ShortBtreeKind::AllocCnt => {
            output[..4].copy_from_slice(&record[4..8]);
            output[4..].copy_from_slice(&record[..4]);
        }
        ShortBtreeKind::Inode | ShortBtreeKind::FreeInode => {
            output.copy_from_slice(&record[..INODE_KEY_SIZE]);
        }
    }
    Ok(())
}

fn copy_into_block(buffer: &mut [u8], offset: usize, bytes: &[u8]) -> FsResult<()> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or(FsError::ArithmeticOverflow)?;
    buffer
        .get_mut(offset..end)
        .ok_or(FsError::BufferTooSmall)?
        .copy_from_slice(bytes);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn encode_node(
    kind: ShortBtreeKind,
    node: &BuildNode,
    block: u32,
    blocks: &[u32],
    root: &BuildNode,
    nodes: &[BuildNode],
    records: &[Vec<u8>],
    block_size: usize,
    is_v5: bool,
    ag_number: u32,
    ag_blocks: u32,
    sector_size: u32,
    uuid: [u8; 16],
    lsn: u64,
) -> FsResult<Vec<u8>> {
    let num_entries = node.num_entries();
    let capacity = max_records(kind, block_size, is_v5, node.level)?;
    if num_entries > capacity || num_entries > u16::MAX as usize {
        return Err(FsError::Corrupted);
    }

    let mut buffer = vec![0u8; block_size];
    copy_into_block(&mut buffer, 0, &kind.magic(is_v5).to_be_bytes())?;
    copy_into_block(&mut buffer, 4, &node.level.to_be_bytes())?;
    copy_into_block(&mut buffer, 6, &(num_entries as u16).to_be_bytes())?;
    copy_into_block(&mut buffer, 8, &node.left.to_be_bytes())?;
    copy_into_block(&mut buffer, 12, &node.right.to_be_bytes())?;

    if is_v5 {
        let absolute = absolute_block(ag_number, ag_blocks, block)?;
        let disk_address = disk_address(absolute, block_size, sector_size)?;
        copy_into_block(&mut buffer, 16, &disk_address.to_be_bytes())?;
        copy_into_block(&mut buffer, 24, &lsn.to_be_bytes())?;
        copy_into_block(&mut buffer, 32, &uuid)?;
        copy_into_block(&mut buffer, 48, &ag_number.to_be_bytes())?;
    }

    match &node.entries {
        BuildEntries::Records { start, end } => {
            for (index, record) in records
                .get(*start..*end)
                .ok_or(FsError::Corrupted)?
                .iter()
                .enumerate()
            {
                let offset = header_size(is_v5)
                    .checked_add(
                        index
                            .checked_mul(kind.record_size())
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .ok_or(FsError::ArithmeticOverflow)?;
                copy_into_block(&mut buffer, offset, record)?;
            }
        }
        BuildEntries::Children(children) => {
            let ptrs_offset = pointer_offset(kind, block_size, is_v5, node.level)?;
            for (index, child) in children.iter().copied().enumerate() {
                let record = first_record_for_node(child, root, nodes, records)?;
                let key_offset = header_size(is_v5)
                    .checked_add(
                        index
                            .checked_mul(kind.key_size())
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .ok_or(FsError::ArithmeticOverflow)?;
                let key_end = key_offset
                    .checked_add(kind.key_size())
                    .ok_or(FsError::ArithmeticOverflow)?;
                write_key(
                    kind,
                    record,
                    buffer
                        .get_mut(key_offset..key_end)
                        .ok_or(FsError::BufferTooSmall)?,
                )?;

                let ptr_offset = ptrs_offset
                    .checked_add(
                        index
                            .checked_mul(SHORT_PTR_SIZE)
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .ok_or(FsError::ArithmeticOverflow)?;
                copy_into_block(
                    &mut buffer,
                    ptr_offset,
                    &blocks.get(child).ok_or(FsError::Corrupted)?.to_be_bytes(),
                )?;
            }
        }
    }

    if is_v5 {
        crate::crc::recalculate_crc_le(&mut buffer, BtreeBlockShort::CRC_OFFSET_V5)
            .ok_or(FsError::BufferTooSmall)?;
    }
    Ok(buffer)
}

/// Plan and encode a canonical bulk-loaded short-format B+tree.
///
/// `root_block` is always the top node and is reused. Other nodes consume
/// `existing_blocks` first and then `extra_blocks`, in order; surplus
/// candidates are ignored. A single occurrence of `root_block` in either
/// candidate list is accepted and skipped. Duplicate non-root candidates, null
/// pointers and out-of-AG blocks are rejected.
///
/// `ag_number`, `ag_blocks` and `sector_size` validate the supplied geometry.
/// Every v5 header stores the 64-bit disk address
/// `(ag_number * ag_blocks + ag_block) * block_size / 512`, while
/// [`Self::blocks`] remains AG-relative. Records must already be strictly
/// ordered according to the selected tree kind.
#[allow(clippy::too_many_arguments)]
pub fn plan_short_btree(
    kind: ShortBtreeKind,
    records: &[Vec<u8>],
    existing_blocks: &[u32],
    extra_blocks: &[u32],
    root_block: u32,
    ag_number: u32,
    ag_blocks: u32,
    uuid: [u8; 16],
    block_size: usize,
    sector_size: u32,
    is_v5: bool,
    lsn: u64,
) -> FsResult<ShortBtreeBuildPlan> {
    validate_block_size(block_size)?;
    validate_sector_size(sector_size, block_size)?;
    absolute_block(ag_number, ag_blocks, root_block)?;
    if records.len() > MAX_SHORT_BTREE_RECORDS {
        return Err(FsError::InvalidArgument);
    }
    validate_record_sequence(kind, records)?;

    let required = required_block_count(kind, records.len(), block_size, is_v5)?;
    let total_bytes = required
        .checked_mul(block_size)
        .ok_or(FsError::ArithmeticOverflow)?;
    if required > MAX_BTREE_BLOCKS_PER_OPERATION || total_bytes > MAX_SHORT_BTREE_OPERATION_BYTES {
        return Err(FsError::OutOfMemory);
    }
    let candidates = select_candidate_blocks(
        root_block,
        existing_blocks,
        extra_blocks,
        required,
        ag_blocks,
    )?;
    let mut blocks = Vec::with_capacity(required);
    blocks.push(root_block);
    blocks.extend(candidates);

    let leaf_capacity = max_records(kind, block_size, is_v5, 0)?;
    let internal_capacity = max_records(kind, block_size, is_v5, 1)?;
    let mut nodes: Vec<BuildNode> = Vec::with_capacity(required - 1);
    let mut levels: Vec<Vec<usize>> = Vec::new();
    let root_level;
    let mut root;

    if records.len() <= leaf_capacity {
        root_level = 0;
        root = BuildNode::records(0, records.len());
        levels.push(vec![0]);
    } else {
        let mut current_level = Vec::new();
        let mut start = 0usize;
        while start < records.len() {
            let end = start
                .checked_add(leaf_capacity)
                .ok_or(FsError::ArithmeticOverflow)?
                .min(records.len());
            let index = nodes
                .len()
                .checked_add(1)
                .ok_or(FsError::ArithmeticOverflow)?;
            nodes.push(BuildNode::records(start, end));
            current_level.push(index);
            start = end;
        }
        levels.push(current_level.clone());

        let mut level = 0u16;
        loop {
            let parent_count = ceil_div(current_level.len(), internal_capacity)?;
            level = level.checked_add(1).ok_or(FsError::ArithmeticOverflow)?;
            if level > MAX_SHORT_BTREE_LEVEL {
                return Err(FsError::InvalidArgument);
            }
            if parent_count == 1 {
                root_level = level;
                root = BuildNode::children(level, current_level);
                levels.push(vec![0]);
                break;
            }

            let mut parents = Vec::with_capacity(parent_count);
            for chunk in current_level.chunks(internal_capacity) {
                let index = nodes
                    .len()
                    .checked_add(1)
                    .ok_or(FsError::ArithmeticOverflow)?;
                nodes.push(BuildNode::children(level, chunk.to_vec()));
                parents.push(index);
            }
            levels.push(parents.clone());
            current_level = parents;
        }
    }

    if nodes
        .len()
        .checked_add(1)
        .ok_or(FsError::ArithmeticOverflow)?
        != required
    {
        return Err(FsError::Corrupted);
    }
    assign_siblings(&levels, &blocks, &mut root, &mut nodes)?;

    let mut buffers = Vec::with_capacity(required);
    buffers.push(encode_node(
        kind,
        &root,
        root_block,
        &blocks,
        &root,
        &nodes,
        records,
        block_size,
        is_v5,
        ag_number,
        ag_blocks,
        sector_size,
        uuid,
        lsn,
    )?);
    for (index, node) in nodes.iter().enumerate() {
        let block_index = index.checked_add(1).ok_or(FsError::ArithmeticOverflow)?;
        buffers.push(encode_node(
            kind,
            node,
            blocks[block_index],
            &blocks,
            &root,
            &nodes,
            records,
            block_size,
            is_v5,
            ag_number,
            ag_blocks,
            sector_size,
            uuid,
            lsn,
        )?);
    }

    Ok(ShortBtreeBuildPlan {
        root_level,
        blocks,
        buffers,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_AG: u32 = 3;
    const TEST_AG_BLOCKS: u32 = 1 << 20;
    const TEST_SECTOR_SIZE: u32 = 512;
    const TEST_ROOT: u32 = 128;
    const TEST_UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];

    struct MemoryReader {
        blocks: BTreeMap<u64, Vec<u8>>,
    }

    impl BlockReader for MemoryReader {
        fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
            self.blocks
                .get(&block_num)
                .cloned()
                .ok_or(FsError::InvalidBlockAddress)
        }
    }

    fn reader_for_plan(plan: &ShortBtreeBuildPlan) -> MemoryReader {
        let ag_start = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS);
        MemoryReader {
            blocks: plan
                .blocks
                .iter()
                .copied()
                .zip(plan.buffers.iter().cloned())
                .map(|(block, buffer)| (ag_start + u64::from(block), buffer))
                .collect(),
        }
    }

    fn alloc_record(start: u32, count: u32) -> Vec<u8> {
        let mut record = Vec::with_capacity(8);
        record.extend_from_slice(&start.to_be_bytes());
        record.extend_from_slice(&count.to_be_bytes());
        record
    }

    fn inode_record(start: u32, free_count: u32, bitmap: u64) -> Vec<u8> {
        let mut record = Vec::with_capacity(16);
        record.extend_from_slice(&start.to_be_bytes());
        record.extend_from_slice(&free_count.to_be_bytes());
        record.extend_from_slice(&bitmap.to_be_bytes());
        record
    }

    fn records_for(kind: ShortBtreeKind, count: usize) -> Vec<Vec<u8>> {
        match kind {
            ShortBtreeKind::AllocBno => (0..count)
                .map(|index| alloc_record(index as u32 * 2, 1))
                .collect(),
            ShortBtreeKind::AllocCnt => (0..count)
                .map(|index| alloc_record((count - index) as u32 * 2, index as u32 + 1))
                .collect(),
            ShortBtreeKind::Inode | ShortBtreeKind::FreeInode => (0..count)
                .map(|index| inode_record(index as u32 * 64, 1, 1))
                .collect(),
        }
    }

    fn candidates(count: usize) -> (Vec<u32>, Vec<u32>) {
        let existing = (1..=count)
            .step_by(2)
            .map(|index| TEST_ROOT + index as u32)
            .collect::<Vec<_>>();
        let extra = (2..=count)
            .step_by(2)
            .map(|index| TEST_ROOT + index as u32)
            .collect::<Vec<_>>();
        (existing, extra)
    }

    fn plan_records(
        kind: ShortBtreeKind,
        records: &[Vec<u8>],
        block_size: usize,
        is_v5: bool,
    ) -> ShortBtreeBuildPlan {
        let required = required_block_count(kind, records.len(), block_size, is_v5).unwrap();
        let (existing, extra) = candidates(required);
        plan_short_btree(
            kind,
            records,
            &existing,
            &extra,
            TEST_ROOT,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_UUID,
            block_size,
            TEST_SECTOR_SIZE,
            is_v5,
            0x1122_3344_5566_7788,
        )
        .unwrap()
    }

    fn resign_v5(buffer: &mut [u8]) {
        crate::crc::recalculate_crc_le(buffer, BtreeBlockShort::CRC_OFFSET_V5).unwrap();
    }

    fn assert_round_trip(kind: ShortBtreeKind, count: usize, block_size: usize, is_v5: bool) {
        let records = records_for(kind, count);
        let plan = plan_records(kind, &records, block_size, is_v5);
        assert_eq!(plan.blocks[0], TEST_ROOT);
        assert_eq!(plan.blocks.len(), plan.buffers.len());
        assert!(plan.buffers.iter().all(|buffer| buffer.len() == block_size));
        let reader = reader_for_plan(&plan);
        let snapshot = collect_short_btree(
            kind,
            TEST_ROOT,
            plan.root_level,
            block_size,
            is_v5,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .unwrap_or_else(|error| {
            panic!("round trip failed for {kind:?}, count={count}, v5={is_v5}: {error:?}")
        });
        assert_eq!(snapshot.records, records);
        assert_eq!(snapshot.root_level, plan.root_level);
        assert_eq!(snapshot.blocks.len(), plan.blocks.len());
        assert_eq!(snapshot.blocks[0], TEST_ROOT);
    }

    #[test]
    fn canonical_capacities_and_required_counts() {
        assert_eq!(
            max_records(ShortBtreeKind::AllocBno, 512, false, 0).unwrap(),
            62
        );
        assert_eq!(
            max_records(ShortBtreeKind::AllocBno, 512, false, 1).unwrap(),
            41
        );
        assert_eq!(
            max_records(ShortBtreeKind::Inode, 512, false, 0).unwrap(),
            31
        );
        assert_eq!(
            max_records(ShortBtreeKind::Inode, 512, false, 1).unwrap(),
            62
        );
        assert_eq!(
            max_records(ShortBtreeKind::AllocBno, 512, true, 0).unwrap(),
            57
        );
        assert_eq!(
            max_records(ShortBtreeKind::AllocBno, 512, true, 1).unwrap(),
            38
        );
        assert_eq!(
            max_records(ShortBtreeKind::Inode, 512, true, 0).unwrap(),
            28
        );
        assert_eq!(
            max_records(ShortBtreeKind::Inode, 512, true, 1).unwrap(),
            57
        );

        assert_eq!(
            required_block_count(ShortBtreeKind::AllocBno, 0, 512, false).unwrap(),
            1
        );
        assert_eq!(
            required_block_count(ShortBtreeKind::AllocBno, 62, 512, false).unwrap(),
            1
        );
        assert_eq!(
            required_block_count(ShortBtreeKind::AllocBno, 63, 512, false).unwrap(),
            3
        );
        assert_eq!(
            required_block_count(ShortBtreeKind::AllocBno, 62 * 41 + 1, 512, false).unwrap(),
            45
        );
        assert_eq!(
            pointer_offset(ShortBtreeKind::AllocBno, 512, false, 1).unwrap(),
            16 + 41 * 8
        );
        assert_eq!(
            pointer_offset(ShortBtreeKind::Inode, 512, false, 1).unwrap(),
            16 + 62 * 4
        );
    }

    #[test]
    fn v4_and_v5_round_trip_all_kinds() {
        for kind in [
            ShortBtreeKind::AllocBno,
            ShortBtreeKind::AllocCnt,
            ShortBtreeKind::Inode,
            ShortBtreeKind::FreeInode,
        ] {
            assert_round_trip(kind, 0, 512, false);
            assert_round_trip(kind, 7, 512, false);
            assert_round_trip(kind, 70, 512, false);
            assert_round_trip(kind, 7, 512, true);
            assert_round_trip(kind, 70, 512, true);
        }
    }

    #[test]
    fn multi_level_round_trip_uses_first_record_keys() {
        assert_round_trip(ShortBtreeKind::AllocBno, 62 * 41 + 1, 512, false);
        assert_round_trip(ShortBtreeKind::AllocCnt, 62 * 41 + 1, 512, false);
        assert_round_trip(ShortBtreeKind::Inode, 31 * 62 + 1, 512, false);
        assert_round_trip(ShortBtreeKind::FreeInode, 31 * 62 + 1, 512, false);
        assert_round_trip(ShortBtreeKind::AllocBno, 57 * 38 + 1, 512, true);
        assert_round_trip(ShortBtreeKind::Inode, 28 * 57 + 1, 512, true);
    }

    #[test]
    fn pointers_use_max_key_capacity_not_numrecs() {
        let records = records_for(ShortBtreeKind::AllocBno, 63);
        let plan = plan_records(ShortBtreeKind::AllocBno, &records, 512, false);
        let root = &plan.buffers[0];
        let ptrs = pointer_offset(ShortBtreeKind::AllocBno, 512, false, 1).unwrap();
        assert_eq!(root.read_be_u32(ptrs).unwrap(), plan.blocks[1]);
        assert_eq!(root.read_be_u32(ptrs + 4).unwrap(), plan.blocks[2]);
        assert_eq!(root.read_be_u32(16 + 8).unwrap(), 124);
        assert!(root[16 + 2 * 8..ptrs].iter().all(|byte| *byte == 0));

        let records = records_for(ShortBtreeKind::Inode, 32);
        let plan = plan_records(ShortBtreeKind::Inode, &records, 512, false);
        let root = &plan.buffers[0];
        let ptrs = pointer_offset(ShortBtreeKind::Inode, 512, false, 1).unwrap();
        assert_eq!(root.read_be_u32(ptrs).unwrap(), plan.blocks[1]);
        assert_eq!(root.read_be_u32(ptrs + 4).unwrap(), plan.blocks[2]);
        assert_eq!(root.read_be_u32(20).unwrap(), 31 * 64);
    }

    #[test]
    fn internal_keys_are_derived_from_each_childs_first_record() {
        let bno = records_for(ShortBtreeKind::AllocBno, 63);
        let plan = plan_records(ShortBtreeKind::AllocBno, &bno, 512, false);
        assert_eq!(&plan.buffers[0][24..32], bno[62].as_slice());

        let cnt = records_for(ShortBtreeKind::AllocCnt, 63);
        let plan = plan_records(ShortBtreeKind::AllocCnt, &cnt, 512, false);
        assert_eq!(&plan.buffers[0][24..28], &cnt[62][4..8]);
        assert_eq!(&plan.buffers[0][28..32], &cnt[62][..4]);

        let ino = records_for(ShortBtreeKind::Inode, 32);
        let plan = plan_records(ShortBtreeKind::Inode, &ino, 512, false);
        assert_eq!(&plan.buffers[0][20..24], &ino[31][..4]);
    }

    #[test]
    fn v5_headers_have_disk_address_uuid_owner_lsn_and_le_crc() {
        let records = records_for(ShortBtreeKind::AllocBno, 63);
        let plan = plan_records(ShortBtreeKind::AllocBno, &records, 512, true);
        for (index, buffer) in plan.buffers.iter().enumerate() {
            assert_eq!(buffer.read_be_u32(0).unwrap(), XFS_ABTB_CRC_MAGIC);
            let absolute =
                u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(plan.blocks[index]);
            let expected_disk_address = disk_address(absolute, 512, TEST_SECTOR_SIZE).unwrap();
            assert_eq!(buffer.read_be_u64(16).unwrap(), expected_disk_address);
            assert_eq!(buffer.read_be_u64(24).unwrap(), 0x1122_3344_5566_7788);
            assert_eq!(&buffer[32..48], &TEST_UUID);
            assert_eq!(buffer.read_be_u32(48).unwrap(), TEST_AG);
            let header = BtreeBlockShort::parse(buffer, true).unwrap();
            header.verify_crc(buffer).unwrap();
            assert_eq!(header.crc, buffer.read_le_u32(52).unwrap());
        }
    }

    #[test]
    fn v5_blockno_uses_basic_block_units() {
        let records = records_for(ShortBtreeKind::Inode, 7);
        let plan = plan_records(ShortBtreeKind::Inode, &records, 4096, true);
        let absolute = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(TEST_ROOT);
        assert_eq!(
            plan.buffers[0].read_be_u64(16).unwrap(),
            absolute * u64::from(4096 / TEST_SECTOR_SIZE)
        );
        let reader = reader_for_plan(&plan);
        collect_short_btree(
            ShortBtreeKind::Inode,
            TEST_ROOT,
            0,
            4096,
            true,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .unwrap();
    }

    #[test]
    fn checked_collection_rejects_wrong_uuid() {
        let records = records_for(ShortBtreeKind::Inode, 7);
        let plan = plan_records(ShortBtreeKind::Inode, &records, 512, true);
        let reader = reader_for_plan(&plan);
        assert!(collect_short_btree_checked(
            ShortBtreeKind::Inode,
            TEST_ROOT,
            0,
            512,
            true,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
            Some(TEST_UUID),
        )
        .is_ok());
        assert!(matches!(
            collect_short_btree_checked(
                ShortBtreeKind::Inode,
                TEST_ROOT,
                0,
                512,
                true,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader,
                Some([0xAA; 16]),
            ),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn empty_tree_is_one_empty_leaf() {
        for is_v5 in [false, true] {
            let plan = plan_records(ShortBtreeKind::FreeInode, &[], 512, is_v5);
            assert_eq!(plan.root_level, 0);
            assert_eq!(plan.blocks, vec![TEST_ROOT]);
            assert_eq!(plan.buffers[0].read_be_u16(6).unwrap(), 0);
            assert_eq!(plan.buffers[0].read_be_u32(8).unwrap(), NULLAGBLOCK);
            assert_eq!(plan.buffers[0].read_be_u32(12).unwrap(), NULLAGBLOCK);
            let reader = reader_for_plan(&plan);
            let snapshot = collect_short_btree(
                ShortBtreeKind::FreeInode,
                TEST_ROOT,
                0,
                512,
                is_v5,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader,
            )
            .unwrap();
            assert!(snapshot.records.is_empty());
            assert_eq!(snapshot.blocks, vec![TEST_ROOT]);
        }
    }

    #[test]
    fn crc_corruption_is_rejected() {
        let records = records_for(ShortBtreeKind::AllocCnt, 70);
        let plan = plan_records(ShortBtreeKind::AllocCnt, &records, 512, true);
        let mut reader = reader_for_plan(&plan);
        let root = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(TEST_ROOT);
        reader.blocks.get_mut(&root).unwrap()[100] ^= 1;
        assert!(matches!(
            collect_short_btree(
                ShortBtreeKind::AllocCnt,
                TEST_ROOT,
                plan.root_level,
                512,
                true,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader,
            ),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn v5_blockno_owner_and_version_mismatches_are_rejected() {
        let records = records_for(ShortBtreeKind::Inode, 7);
        let plan = plan_records(ShortBtreeKind::Inode, &records, 512, true);
        let root_ag = TEST_ROOT;
        let root_abs = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(root_ag);

        let mut reader = reader_for_plan(&plan);
        let buffer = reader.blocks.get_mut(&root_abs).unwrap();
        buffer[16] ^= 1;
        resign_v5(buffer);
        assert!(collect_short_btree(
            ShortBtreeKind::Inode,
            root_ag,
            0,
            512,
            true,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .is_err());

        let mut reader = reader_for_plan(&plan);
        let buffer = reader.blocks.get_mut(&root_abs).unwrap();
        buffer[48] ^= 1;
        resign_v5(buffer);
        assert!(collect_short_btree(
            ShortBtreeKind::Inode,
            root_ag,
            0,
            512,
            true,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .is_err());

        assert!(matches!(
            collect_short_btree(
                ShortBtreeKind::Inode,
                root_ag,
                0,
                512,
                false,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader_for_plan(&plan),
            ),
            Err(FsError::InvalidMagic)
        ));
    }

    #[test]
    fn ordering_and_record_shape_are_validated() {
        let mut bno = records_for(ShortBtreeKind::AllocBno, 3);
        bno.swap(0, 1);
        assert!(plan_short_btree(
            ShortBtreeKind::AllocBno,
            &bno,
            &[],
            &[],
            TEST_ROOT,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_UUID,
            512,
            TEST_SECTOR_SIZE,
            false,
            0,
        )
        .is_err());

        let mut cnt = records_for(ShortBtreeKind::AllocCnt, 3);
        cnt.swap(0, 1);
        assert!(plan_short_btree(
            ShortBtreeKind::AllocCnt,
            &cnt,
            &[],
            &[],
            TEST_ROOT,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_UUID,
            512,
            TEST_SECTOR_SIZE,
            false,
            0,
        )
        .is_err());

        let mut overlapping = records_for(ShortBtreeKind::AllocBno, 2);
        overlapping[0] = alloc_record(10, 5);
        overlapping[1] = alloc_record(12, 1);
        assert!(validate_record_sequence(ShortBtreeKind::AllocBno, &overlapping).is_err());
        assert!(record_key(ShortBtreeKind::Inode, &[0; 8]).is_err());
        assert!(record_key(ShortBtreeKind::AllocBno, &alloc_record(1, 0)).is_err());

        let records = records_for(ShortBtreeKind::AllocBno, 3);
        let mut plan = plan_records(ShortBtreeKind::AllocBno, &records, 512, false);
        let (first, second) = plan.buffers[0].split_at_mut(24);
        first[16..24].swap_with_slice(&mut second[..8]);
        let reader = reader_for_plan(&plan);
        assert!(matches!(
            collect_short_btree(
                ShortBtreeKind::AllocBno,
                TEST_ROOT,
                0,
                512,
                false,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader,
            ),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn corrupt_capacity_levels_cycles_and_siblings_are_rejected() {
        let records = records_for(ShortBtreeKind::AllocBno, 63);
        let plan = plan_records(ShortBtreeKind::AllocBno, &records, 512, false);

        let mut reader = reader_for_plan(&plan);
        let root = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(TEST_ROOT);
        reader.blocks.get_mut(&root).unwrap()[6..8].copy_from_slice(&u16::MAX.to_be_bytes());
        assert!(matches!(
            collect_short_btree(
                ShortBtreeKind::AllocBno,
                TEST_ROOT,
                1,
                512,
                false,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader,
            ),
            Err(FsError::Corrupted)
        ));

        assert!(collect_short_btree(
            ShortBtreeKind::AllocBno,
            TEST_ROOT,
            2,
            512,
            false,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader_for_plan(&plan),
        )
        .is_err());

        let mut reader = reader_for_plan(&plan);
        let ptrs = pointer_offset(ShortBtreeKind::AllocBno, 512, false, 1).unwrap();
        reader.blocks.get_mut(&root).unwrap()[ptrs..ptrs + 4]
            .copy_from_slice(&TEST_ROOT.to_be_bytes());
        assert!(matches!(
            collect_short_btree(
                ShortBtreeKind::AllocBno,
                TEST_ROOT,
                1,
                512,
                false,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader,
            ),
            Err(FsError::Corrupted)
        ));

        let mut reader = reader_for_plan(&plan);
        let first_leaf = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(plan.blocks[1]);
        reader.blocks.get_mut(&first_leaf).unwrap()[12..16]
            .copy_from_slice(&NULLAGBLOCK.to_be_bytes());
        assert!(collect_short_btree(
            ShortBtreeKind::AllocBno,
            TEST_ROOT,
            1,
            512,
            false,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .is_err());
    }

    #[test]
    fn multi_level_internal_sibling_links_are_validated() {
        let records = records_for(ShortBtreeKind::AllocBno, 62 * 41 + 1);
        let plan = plan_records(ShortBtreeKind::AllocBno, &records, 512, false);
        let internal_index = plan
            .buffers
            .iter()
            .position(|buffer| buffer.read_be_u16(4).unwrap() == 1)
            .unwrap();
        let mut reader = reader_for_plan(&plan);
        let internal =
            u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(plan.blocks[internal_index]);
        reader.blocks.get_mut(&internal).unwrap()[12..16]
            .copy_from_slice(&NULLAGBLOCK.to_be_bytes());
        assert!(collect_short_btree(
            ShortBtreeKind::AllocBno,
            TEST_ROOT,
            plan.root_level,
            512,
            false,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .is_err());
    }

    #[test]
    fn parent_keys_and_wrong_tree_magic_are_rejected() {
        let records = records_for(ShortBtreeKind::AllocBno, 63);
        let plan = plan_records(ShortBtreeKind::AllocBno, &records, 512, false);
        let mut reader = reader_for_plan(&plan);
        let root = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(TEST_ROOT);
        reader.blocks.get_mut(&root).unwrap()[24..28].copy_from_slice(&0u32.to_be_bytes());
        assert!(collect_short_btree(
            ShortBtreeKind::AllocBno,
            TEST_ROOT,
            1,
            512,
            false,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .is_err());

        // BNO keys contain the full record, so a mismatched block count is
        // corruption even though lookup primarily compares start_block.
        let mut reader = reader_for_plan(&plan);
        reader.blocks.get_mut(&root).unwrap()[28] ^= 1;
        assert!(collect_short_btree(
            ShortBtreeKind::AllocBno,
            TEST_ROOT,
            1,
            512,
            false,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &reader,
        )
        .is_err());

        assert!(matches!(
            collect_short_btree(
                ShortBtreeKind::AllocCnt,
                TEST_ROOT,
                1,
                512,
                false,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader_for_plan(&plan),
            ),
            Err(FsError::InvalidMagic)
        ));
    }

    #[test]
    fn plan_reuses_root_and_validates_candidate_blocks() {
        let records = records_for(ShortBtreeKind::Inode, 40);
        let required =
            required_block_count(ShortBtreeKind::Inode, records.len(), 512, false).unwrap();
        let plan = plan_short_btree(
            ShortBtreeKind::Inode,
            &records,
            &[TEST_ROOT, TEST_ROOT + 1, TEST_ROOT + 2],
            &[],
            TEST_ROOT,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_UUID,
            512,
            TEST_SECTOR_SIZE,
            false,
            0,
        )
        .unwrap();
        assert_eq!(plan.blocks.len(), required);
        assert_eq!(plan.blocks[0], TEST_ROOT);
        assert_eq!(plan.blocks[1], TEST_ROOT + 1);
        assert_eq!(plan.blocks[2], TEST_ROOT + 2);

        assert!(matches!(
            plan_short_btree(
                ShortBtreeKind::Inode,
                &records,
                &[TEST_ROOT + 1, TEST_ROOT + 1],
                &[TEST_ROOT + 2],
                TEST_ROOT,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_UUID,
                512,
                TEST_SECTOR_SIZE,
                false,
                0,
            ),
            Err(FsError::InvalidArgument)
        ));
        assert!(matches!(
            plan_short_btree(
                ShortBtreeKind::Inode,
                &records,
                &[],
                &[TEST_ROOT + 1],
                TEST_ROOT,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_UUID,
                512,
                TEST_SECTOR_SIZE,
                false,
                0,
            ),
            Err(FsError::NoSpace)
        ));
        assert!(plan_short_btree(
            ShortBtreeKind::Inode,
            &records,
            &[NULLAGBLOCK],
            &[],
            TEST_ROOT,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_UUID,
            512,
            TEST_SECTOR_SIZE,
            false,
            0,
        )
        .is_err());
    }

    #[test]
    fn invalid_geometry_and_excessive_levels_are_rejected_without_panics() {
        assert!(required_block_count(ShortBtreeKind::AllocBno, 1, 0, false).is_err());
        assert!(required_block_count(ShortBtreeKind::AllocBno, 1, 513, false).is_err());
        assert!(required_block_count(ShortBtreeKind::AllocBno, 1, 128 * 1024, false).is_err());
        assert!(collect_short_btree(
            ShortBtreeKind::AllocBno,
            TEST_ROOT,
            MAX_SHORT_BTREE_LEVEL + 1,
            512,
            false,
            TEST_AG,
            TEST_AG_BLOCKS,
            TEST_SECTOR_SIZE,
            &MemoryReader {
                blocks: BTreeMap::new()
            },
        )
        .is_err());
        assert!(absolute_block(u32::MAX, u32::MAX, 0).is_ok());
        assert!(absolute_block(TEST_AG, TEST_AG_BLOCKS, TEST_AG_BLOCKS).is_err());
        assert!(validate_sector_size(0, 512).is_err());
        assert!(validate_sector_size(513, 512).is_err());
        assert!(validate_sector_size(1024, 512).is_err());
        assert!(disk_address(u64::MAX, 4096, 512).is_err());

        let root = u64::from(TEST_AG) * u64::from(TEST_AG_BLOCKS) + u64::from(TEST_ROOT);
        for len in [0, 4, 15, 55, 511] {
            let reader = MemoryReader {
                blocks: [(root, vec![0u8; len])].into_iter().collect(),
            };
            assert!(collect_short_btree(
                ShortBtreeKind::AllocBno,
                TEST_ROOT,
                0,
                512,
                true,
                TEST_AG,
                TEST_AG_BLOCKS,
                TEST_SECTOR_SIZE,
                &reader,
            )
            .is_err());
        }
    }
}
