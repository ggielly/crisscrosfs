//! Planning and encoding for long-format XFS block-map B+trees (BMBTs).
//!
//! The BMBT root lives in the inode data fork; only its descendants occupy
//! filesystem blocks. This module emits the root bytes after the four-byte
//! `level`/`numrecs` header separately from the complete disk-node buffers.
//! Block numbers in plans, sibling pointers and child pointers are absolute
//! filesystem block numbers. In v5 nodes, `bb_blkno` is instead an
//! `xfs_daddr_t` in basic-block (sector) units.

#[cfg(feature = "alloc")]
extern crate alloc;

use alloc::{collections::BTreeSet, vec::Vec};

#[cfg(test)]
use fs_abstraction::safe_math::CheckedSliceOps;
use fs_abstraction::{FsError, FsResult};

use crate::{
    btree::{BmbtKey, BmbtPtr, BtreeBlockLong, MAX_BTREE_BLOCKS_PER_OPERATION},
    constants::{XFS_BMAP_CRC_MAGIC, XFS_BMAP_MAGIC},
    extent::Extent,
};

const MIN_BLOCK_SIZE: usize = 512;
const MAX_BLOCK_SIZE: usize = 64 * 1024;
const MAX_FORK_DATA_SIZE: usize = 64 * 1024;
const MAX_BMBT_EXTENTS: usize = 1 << 20;
const MAX_BMBT_LEVEL: u16 = 16;
const MAX_BMBT_OPERATION_BYTES: usize = 64 * 1024 * 1024;
const NULL_FS_BLOCK: u64 = u64::MAX;

/// A complete long-format BMBT rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BmbtBuildPlan {
    /// In-inode root level. Zero means the extents still fit inline.
    pub root_level: u16,
    /// Number of root keys/pointers to write after `root_level`.
    ///
    /// This field is required because [`Self::root_data`] deliberately excludes
    /// the four-byte `level`/`numrecs` header. It is zero for an inline plan.
    pub root_num_records: u16,
    /// Root bytes after the four-byte `level`/`numrecs` header.
    ///
    /// For a B-tree plan this is exactly `fork_data_size - 4` bytes, with
    /// pointers at `((fork_data_size - 4) / 16) * 8`. It is empty when
    /// `root_level == 0`, in which case the caller should retain the `EXTENTS`
    /// inode format.
    pub root_data: Vec<u8>,
    /// Absolute filesystem block numbers for disk nodes, leaves first and then
    /// each successive internal level. Existing candidates are consumed before
    /// extra candidates.
    pub blocks: Vec<u64>,
    /// Complete disk-node buffers, aligned with [`Self::blocks`].
    pub buffers: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
enum NodeEntries {
    Extents { start: usize, end: usize },
    Children(Vec<usize>),
}

#[derive(Debug, Clone)]
struct BuildNode {
    level: u16,
    first_key: u64,
    left: u64,
    right: u64,
    entries: NodeEntries,
}

impl BuildNode {
    fn num_entries(&self) -> usize {
        match self.entries {
            NodeEntries::Extents { start, end } => end - start,
            NodeEntries::Children(ref children) => children.len(),
        }
    }
}

#[derive(Debug)]
struct BuildShape {
    root_level: u16,
    root_num_records: u16,
    root_children: Vec<usize>,
    nodes: Vec<BuildNode>,
    levels: Vec<Vec<usize>>,
}

#[derive(Debug, Clone, Copy)]
struct EncodeConfig {
    block_size: usize,
    is_v5: bool,
    owner: u64,
    uuid: [u8; 16],
    lsn: u64,
}

fn validate_block_size(block_size: usize) -> FsResult<()> {
    if !(MIN_BLOCK_SIZE..=MAX_BLOCK_SIZE).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }
    Ok(())
}

fn validate_sector_size(sector_size: usize, block_size: usize) -> FsResult<()> {
    if sector_size < 512 || sector_size > block_size || !sector_size.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }
    Ok(())
}

fn validate_fork_data_size(fork_data_size: usize) -> FsResult<()> {
    if fork_data_size > MAX_FORK_DATA_SIZE {
        return Err(FsError::InvalidArgument);
    }
    Ok(())
}

fn header_size(is_v5: bool) -> usize {
    if is_v5 {
        BtreeBlockLong::SIZE_V5
    } else {
        BtreeBlockLong::SIZE_V4
    }
}

fn node_capacity(block_size: usize, is_v5: bool) -> FsResult<usize> {
    validate_block_size(block_size)?;
    let payload = block_size
        .checked_sub(header_size(is_v5))
        .ok_or(FsError::BufferTooSmall)?;
    let capacity = payload / (BmbtKey::SIZE + BmbtPtr::SIZE);
    if capacity == 0 || capacity > u16::MAX as usize {
        return Err(FsError::InvalidArgument);
    }
    Ok(capacity)
}

fn node_ptrs_offset(block_size: usize, is_v5: bool) -> FsResult<usize> {
    let capacity = node_capacity(block_size, is_v5)?;
    header_size(is_v5)
        .checked_add(
            capacity
                .checked_mul(BmbtKey::SIZE)
                .ok_or(FsError::ArithmeticOverflow)?,
        )
        .ok_or(FsError::ArithmeticOverflow)
}

fn root_data_size(fork_data_size: usize) -> FsResult<usize> {
    validate_fork_data_size(fork_data_size)?;
    fork_data_size
        .checked_sub(crate::btree::BmbtRoot::HEADER_SIZE)
        .ok_or(FsError::InvalidArgument)
}

fn root_capacity(fork_data_size: usize) -> FsResult<usize> {
    let capacity = root_data_size(fork_data_size)? / (BmbtKey::SIZE + BmbtPtr::SIZE);
    if capacity > u16::MAX as usize {
        return Err(FsError::InvalidArgument);
    }
    Ok(capacity)
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

fn validate_extent_count(extent_count: usize) -> FsResult<()> {
    if extent_count > MAX_BMBT_EXTENTS {
        return Err(FsError::InvalidArgument);
    }
    Ok(())
}

fn validate_operation_budget(
    block_count: usize,
    block_size: usize,
    fork_data_size: usize,
) -> FsResult<()> {
    if block_count > MAX_BTREE_BLOCKS_PER_OPERATION {
        return Err(FsError::OutOfMemory);
    }
    let disk_bytes = block_count
        .checked_mul(block_size)
        .ok_or(FsError::ArithmeticOverflow)?;
    let total_bytes = disk_bytes
        .checked_add(fork_data_size)
        .ok_or(FsError::ArithmeticOverflow)?;
    if total_bytes > MAX_BMBT_OPERATION_BYTES {
        return Err(FsError::OutOfMemory);
    }
    Ok(())
}

fn count_disk_nodes(
    extent_count: usize,
    node_capacity: usize,
    root_capacity: usize,
) -> FsResult<usize> {
    if extent_count == 0 {
        return Ok(0);
    }
    if node_capacity == 0 || root_capacity == 0 {
        return Err(FsError::InvalidArgument);
    }

    let mut level_nodes = ceil_div(extent_count, node_capacity)?;
    let mut total = level_nodes;
    let mut level = 0u16;
    while level_nodes > root_capacity {
        level_nodes = ceil_div(level_nodes, node_capacity)?;
        total = total
            .checked_add(level_nodes)
            .ok_or(FsError::ArithmeticOverflow)?;
        level = level.checked_add(1).ok_or(FsError::ArithmeticOverflow)?;
        if level > MAX_BMBT_LEVEL {
            return Err(FsError::InvalidArgument);
        }
    }
    Ok(total)
}

/// Return a conservative disk-block requirement from extent count and node
/// geometry alone.
///
/// Because this function does not receive the inode fork size, it uses the
/// smallest usable BMBT root capacity (one pointer). The result is exact for
/// such a fork and an upper bound for larger roots. An empty extent list needs
/// no disk blocks; positive counts that actually fit inline may also need zero
/// blocks when passed to [`plan_bmbt`].
pub fn required_block_count(
    extent_count: usize,
    block_size: usize,
    is_v5: bool,
) -> FsResult<usize> {
    validate_extent_count(extent_count)?;
    let capacity = node_capacity(block_size, is_v5)?;
    let required = count_disk_nodes(extent_count, capacity, 1)?;
    validate_operation_budget(required, block_size, 0)?;
    Ok(required)
}

fn validate_extents(extents: &[Extent]) -> FsResult<()> {
    validate_extent_count(extents.len())?;
    let mut previous_end = None;
    for extent in extents {
        // Checking serialization validates all packed field ranges, including
        // the nonzero block count, before any output allocation is made.
        extent.to_bytes_checked()?;
        if previous_end.is_some_and(|end| extent.file_offset < end) {
            return Err(FsError::InvalidArgument);
        }
        previous_end = Some(extent.file_end()?);
    }
    Ok(())
}

fn select_candidate_blocks(
    existing_blocks: &[u64],
    extra_blocks: &[u64],
    required: usize,
) -> FsResult<Vec<u64>> {
    let input_count = existing_blocks
        .len()
        .checked_add(extra_blocks.len())
        .ok_or(FsError::ArithmeticOverflow)?;
    if input_count > MAX_BTREE_BLOCKS_PER_OPERATION {
        return Err(FsError::InvalidArgument);
    }

    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(required)
        .map_err(|_| FsError::OutOfMemory)?;
    let mut seen = BTreeSet::new();
    for block in existing_blocks.iter().chain(extra_blocks) {
        if *block == NULL_FS_BLOCK || !seen.insert(*block) {
            return Err(FsError::InvalidArgument);
        }
        if blocks.len() < required {
            blocks.push(*block);
        }
    }
    if blocks.len() < required {
        return Err(FsError::NoSpace);
    }
    Ok(blocks)
}

fn build_shape(
    extents: &[Extent],
    node_capacity: usize,
    root_capacity: usize,
    required: usize,
) -> FsResult<BuildShape> {
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(required)
        .map_err(|_| FsError::OutOfMemory)?;
    let mut levels = Vec::new();
    levels
        .try_reserve_exact(usize::from(MAX_BMBT_LEVEL) + 1)
        .map_err(|_| FsError::OutOfMemory)?;

    let mut leaves = Vec::new();
    leaves
        .try_reserve_exact(ceil_div(extents.len(), node_capacity)?)
        .map_err(|_| FsError::OutOfMemory)?;
    let mut start = 0usize;
    while start < extents.len() {
        let end = start
            .checked_add(node_capacity)
            .ok_or(FsError::ArithmeticOverflow)?
            .min(extents.len());
        let first_key = extents.get(start).ok_or(FsError::Corrupted)?.file_offset;
        leaves.push(nodes.len());
        nodes.push(BuildNode {
            level: 0,
            first_key,
            left: NULL_FS_BLOCK,
            right: NULL_FS_BLOCK,
            entries: NodeEntries::Extents { start, end },
        });
        start = end;
    }
    levels.push(leaves.clone());

    let mut current = leaves;
    let mut disk_level = 0u16;
    while current.len() > root_capacity {
        disk_level = disk_level
            .checked_add(1)
            .ok_or(FsError::ArithmeticOverflow)?;
        if disk_level > MAX_BMBT_LEVEL {
            return Err(FsError::InvalidArgument);
        }
        let parent_count = ceil_div(current.len(), node_capacity)?;
        let mut parents = Vec::new();
        parents
            .try_reserve_exact(parent_count)
            .map_err(|_| FsError::OutOfMemory)?;
        for chunk in current.chunks(node_capacity) {
            let first_key = nodes.get(chunk[0]).ok_or(FsError::Corrupted)?.first_key;
            parents.push(nodes.len());
            nodes.push(BuildNode {
                level: disk_level,
                first_key,
                left: NULL_FS_BLOCK,
                right: NULL_FS_BLOCK,
                entries: NodeEntries::Children(chunk.to_vec()),
            });
        }
        levels.push(parents.clone());
        current = parents;
    }

    let root_level = disk_level
        .checked_add(1)
        .ok_or(FsError::ArithmeticOverflow)?;
    if root_level > MAX_BMBT_LEVEL || nodes.len() != required || current.is_empty() {
        return Err(FsError::Corrupted);
    }
    let root_num_records = u16::try_from(current.len()).map_err(|_| FsError::InvalidArgument)?;

    Ok(BuildShape {
        root_level,
        root_num_records,
        root_children: current,
        nodes,
        levels,
    })
}

fn assign_siblings(shape: &mut BuildShape, blocks: &[u64]) -> FsResult<()> {
    for level in &shape.levels {
        for (position, index) in level.iter().copied().enumerate() {
            let left = if position == 0 {
                NULL_FS_BLOCK
            } else {
                blocks
                    .get(level[position - 1])
                    .copied()
                    .ok_or(FsError::Corrupted)?
            };
            let right = level
                .get(position + 1)
                .map(|next| blocks.get(*next).copied().ok_or(FsError::Corrupted))
                .transpose()?
                .unwrap_or(NULL_FS_BLOCK);
            let node = shape.nodes.get_mut(index).ok_or(FsError::Corrupted)?;
            node.left = left;
            node.right = right;
        }
    }
    Ok(())
}

fn zeroed_buffer(len: usize) -> FsResult<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(len)
        .map_err(|_| FsError::OutOfMemory)?;
    buffer.resize(len, 0);
    Ok(buffer)
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

fn encode_root_data(
    shape: &BuildShape,
    blocks: &[u64],
    fork_data_size: usize,
) -> FsResult<Vec<u8>> {
    let capacity = root_capacity(fork_data_size)?;
    if shape.root_num_records as usize > capacity {
        return Err(FsError::Corrupted);
    }
    let ptrs_offset = capacity
        .checked_mul(BmbtKey::SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;
    let mut data = zeroed_buffer(root_data_size(fork_data_size)?)?;

    for (index, child) in shape.root_children.iter().copied().enumerate() {
        let key = shape.nodes.get(child).ok_or(FsError::Corrupted)?.first_key;
        let key_offset = index
            .checked_mul(BmbtKey::SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        copy_into_block(&mut data, key_offset, &key.to_be_bytes())?;

        let ptr_offset = ptrs_offset
            .checked_add(
                index
                    .checked_mul(BmbtPtr::SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        let block = blocks.get(child).copied().ok_or(FsError::Corrupted)?;
        copy_into_block(&mut data, ptr_offset, &block.to_be_bytes())?;
    }
    Ok(data)
}

fn disk_address(fs_block: u64, config: EncodeConfig) -> FsResult<u64> {
    crate::address::fs_block_to_daddr(fs_block, config.block_size)
}

/// Plan and encode a canonical long-format BMBT from sorted extents.
///
/// `fork_data_size` is the total usable inode data-fork size, including the
/// four-byte BMBT root header. If all extents fit inline, the returned plan has
/// no disk nodes and the caller should keep the inode in `EXTENTS` format.
/// Otherwise, `root_data` contains the complete post-header fork image and
/// `root_num_records` supplies the accompanying header field.
///
/// Disk nodes consume `existing_blocks` first and then `extra_blocks`, in
/// order. Surplus unique candidates are ignored; duplicates, null candidates
/// and insufficient candidates are rejected. All plan and on-disk child/sibling
/// pointers are absolute filesystem blocks. For v5, each node's `bb_blkno` is
/// `fs_block * block_size / 512`, while `owner`, `uuid` and `lsn` are written
/// to the long header and its CRC at `0x40` is recalculated.
///
/// Extents must be strictly ordered and non-overlapping by logical file offset,
/// and every packed extent field must be representable on disk.
#[allow(clippy::too_many_arguments)]
pub fn plan_bmbt(
    extents: &[Extent],
    existing_blocks: &[u64],
    extra_blocks: &[u64],
    fork_data_size: usize,
    owner: u64,
    uuid: [u8; 16],
    block_size: usize,
    sector_size: usize,
    is_v5: bool,
    lsn: u64,
) -> FsResult<BmbtBuildPlan> {
    validate_block_size(block_size)?;
    validate_sector_size(sector_size, block_size)?;
    validate_fork_data_size(fork_data_size)?;
    validate_extents(extents)?;

    let inline_capacity = fork_data_size / Extent::SIZE;
    if extents.len() <= inline_capacity {
        return Ok(BmbtBuildPlan {
            root_level: 0,
            root_num_records: 0,
            root_data: Vec::new(),
            blocks: Vec::new(),
            buffers: Vec::new(),
        });
    }

    let fork_root_capacity = root_capacity(fork_data_size)?;
    if fork_root_capacity == 0 {
        return Err(FsError::InvalidArgument);
    }
    let capacity = node_capacity(block_size, is_v5)?;
    let required = count_disk_nodes(extents.len(), capacity, fork_root_capacity)?;
    validate_operation_budget(required, block_size, root_data_size(fork_data_size)?)?;
    let blocks = select_candidate_blocks(existing_blocks, extra_blocks, required)?;
    let mut shape = build_shape(extents, capacity, fork_root_capacity, required)?;
    assign_siblings(&mut shape, &blocks)?;

    let root_data = encode_root_data(&shape, &blocks, fork_data_size)?;
    let config = EncodeConfig {
        block_size,
        is_v5,
        owner,
        uuid,
        lsn,
    };
    let mut buffers = Vec::new();
    buffers
        .try_reserve_exact(required)
        .map_err(|_| FsError::OutOfMemory)?;
    for (node, block) in shape.nodes.iter().zip(blocks.iter().copied()) {
        buffers.push(encode_node(node, block, &blocks, extents, &shape, config)?);
    }

    Ok(BmbtBuildPlan {
        root_level: shape.root_level,
        root_num_records: shape.root_num_records,
        root_data,
        blocks,
        buffers,
    })
}

fn encode_node(
    node: &BuildNode,
    block: u64,
    blocks: &[u64],
    extents: &[Extent],
    shape: &BuildShape,
    config: EncodeConfig,
) -> FsResult<Vec<u8>> {
    let capacity = node_capacity(config.block_size, config.is_v5)?;
    let num_entries = node.num_entries();
    if num_entries == 0 || num_entries > capacity || num_entries > u16::MAX as usize {
        return Err(FsError::Corrupted);
    }

    let mut buffer = zeroed_buffer(config.block_size)?;
    let magic = if config.is_v5 {
        XFS_BMAP_CRC_MAGIC
    } else {
        XFS_BMAP_MAGIC
    };
    copy_into_block(&mut buffer, 0, &magic.to_be_bytes())?;
    copy_into_block(&mut buffer, 4, &node.level.to_be_bytes())?;
    copy_into_block(&mut buffer, 6, &(num_entries as u16).to_be_bytes())?;
    copy_into_block(&mut buffer, 8, &node.left.to_be_bytes())?;
    copy_into_block(&mut buffer, 16, &node.right.to_be_bytes())?;

    if config.is_v5 {
        copy_into_block(&mut buffer, 24, &disk_address(block, config)?.to_be_bytes())?;
        copy_into_block(&mut buffer, 32, &config.lsn.to_be_bytes())?;
        copy_into_block(&mut buffer, 40, &config.uuid)?;
        copy_into_block(&mut buffer, 56, &config.owner.to_be_bytes())?;
    }

    match &node.entries {
        NodeEntries::Extents { start, end } => {
            let records = extents.get(*start..*end).ok_or(FsError::Corrupted)?;
            for (index, extent) in records.iter().enumerate() {
                let offset = header_size(config.is_v5)
                    .checked_add(
                        index
                            .checked_mul(Extent::SIZE)
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .ok_or(FsError::ArithmeticOverflow)?;
                copy_into_block(&mut buffer, offset, &extent.to_bytes_checked()?)?;
            }
        }
        NodeEntries::Children(children) => {
            let ptrs_offset = node_ptrs_offset(config.block_size, config.is_v5)?;
            for (index, child) in children.iter().copied().enumerate() {
                let key = shape.nodes.get(child).ok_or(FsError::Corrupted)?.first_key;
                let key_offset = header_size(config.is_v5)
                    .checked_add(
                        index
                            .checked_mul(BmbtKey::SIZE)
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .ok_or(FsError::ArithmeticOverflow)?;
                copy_into_block(&mut buffer, key_offset, &key.to_be_bytes())?;

                let ptr_offset = ptrs_offset
                    .checked_add(
                        index
                            .checked_mul(BmbtPtr::SIZE)
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .ok_or(FsError::ArithmeticOverflow)?;
                let child_block = blocks.get(child).copied().ok_or(FsError::Corrupted)?;
                copy_into_block(&mut buffer, ptr_offset, &child_block.to_be_bytes())?;
            }
        }
    }

    if config.is_v5 {
        crate::crc::recalculate_crc_le(&mut buffer, BtreeBlockLong::CRC_OFFSET_V5)
            .ok_or(FsError::BufferTooSmall)?;
    }
    Ok(buffer)
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use alloc::{collections::BTreeMap, vec, vec::Vec};

    use super::*;
    use crate::btree::{btree_collect_extents, BlockReader, BmbtRoot};

    const TEST_BLOCK_SIZE: usize = 512;
    const TEST_SECTOR_SIZE: usize = 512;
    const TEST_OWNER: u64 = 0x0102_0304_0506_0708;
    const TEST_LSN: u64 = 0x1122_3344_5566_7788;
    const TEST_UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const NULL_BLOCK: u64 = u64::MAX;

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

    fn extents(count: usize) -> Vec<Extent> {
        (0..count)
            .map(|index| Extent {
                file_offset: index as u64 * 2,
                start_block: 1_000 + index as u64 * 4,
                block_count: 1,
                is_unwritten: index % 2 == 0,
            })
            .collect()
    }

    fn candidates(count: usize) -> (Vec<u64>, Vec<u64>) {
        let existing = (1..=count)
            .step_by(2)
            .map(|index| 100 + index as u64)
            .collect();
        let extra = (2..=count)
            .step_by(2)
            .map(|index| 100 + index as u64)
            .collect();
        (existing, extra)
    }

    fn plan_extents(
        extents: &[Extent],
        fork_data_size: usize,
        block_size: usize,
        is_v5: bool,
    ) -> BmbtBuildPlan {
        let count = required_block_count(extents.len(), block_size, is_v5).unwrap();
        let (existing, extra) = candidates(count);
        plan_bmbt(
            extents,
            &existing,
            &extra,
            fork_data_size,
            TEST_OWNER,
            TEST_UUID,
            block_size,
            TEST_SECTOR_SIZE,
            is_v5,
            TEST_LSN,
        )
        .unwrap()
    }

    fn root_for_plan(plan: &BmbtBuildPlan) -> BmbtRoot {
        BmbtRoot::parse(&plan.root_data, plan.root_level, plan.root_num_records).unwrap()
    }

    fn reader_for_plan(plan: &BmbtBuildPlan) -> MemoryReader {
        MemoryReader {
            blocks: plan
                .blocks
                .iter()
                .copied()
                .zip(plan.buffers.iter().cloned())
                .collect(),
        }
    }

    fn assert_round_trip(plan: &BmbtBuildPlan, expected: &[Extent], is_v5: bool) {
        assert_eq!(plan.blocks.len(), plan.buffers.len());
        assert!(plan
            .buffers
            .iter()
            .all(|buffer| buffer.len() == TEST_BLOCK_SIZE));
        let collected =
            btree_collect_extents(&root_for_plan(plan), &reader_for_plan(plan), is_v5).unwrap();
        assert_eq!(collected, expected);
    }

    #[test]
    fn inline_extents_need_no_root_or_disk_blocks() {
        let input = extents(4);
        let plan = plan_extents(&input, 64, TEST_BLOCK_SIZE, false);
        assert_eq!(plan.root_level, 0);
        assert_eq!(plan.root_num_records, 0);
        assert!(plan.root_data.is_empty());
        assert!(plan.blocks.is_empty());
        assert!(plan.buffers.is_empty());

        let empty = plan_extents(&[], 0, TEST_BLOCK_SIZE, true);
        assert_eq!(empty.root_level, 0);
        assert!(empty.blocks.is_empty());
    }

    #[test]
    fn single_leaf_has_an_in_inode_root() {
        for is_v5 in [false, true] {
            let input = extents(3);
            let plan = plan_extents(&input, 32, TEST_BLOCK_SIZE, is_v5);
            assert_eq!(plan.root_level, 1);
            assert_eq!(plan.root_num_records, 1);
            assert_eq!(plan.root_data.len(), 28);
            assert_eq!(plan.root_data.read_be_u64(8).unwrap(), plan.blocks[0]);
            assert_eq!(plan.blocks.len(), 1);
            assert_eq!(plan.buffers.len(), 1);

            let header = BtreeBlockLong::parse(&plan.buffers[0], is_v5).unwrap();
            assert!(header.is_leaf());
            assert_eq!(header.num_recs, 3);
            assert_eq!(header.left_sibling, NULL_BLOCK);
            assert_eq!(header.right_sibling, NULL_BLOCK);
            assert_round_trip(&plan, &input, is_v5);
        }
    }

    #[test]
    fn multi_level_trees_round_trip_for_v4_and_v5() {
        for (is_v5, count) in [(false, 931), (true, 730)] {
            let input = extents(count);
            let plan = plan_extents(&input, 20, TEST_BLOCK_SIZE, is_v5);
            assert_eq!(plan.root_level, 3);
            assert_eq!(plan.root_num_records, 1);
            assert_eq!(
                plan.blocks.len(),
                required_block_count(count, TEST_BLOCK_SIZE, is_v5).unwrap()
            );
            assert_round_trip(&plan, &input, is_v5);
        }
    }

    #[test]
    fn root_and_internal_pointers_use_canonical_max_offsets() {
        let input = extents(70);
        let plan = plan_extents(&input, 164, TEST_BLOCK_SIZE, false);
        let root_ptrs = 10 * BmbtKey::SIZE;
        assert_eq!(root_ptrs, 80);
        assert_eq!(plan.root_data.read_be_u64(0).unwrap(), 0);
        assert_eq!(
            plan.root_data.read_be_u64(root_ptrs).unwrap(),
            plan.blocks[0]
        );
        assert_eq!(
            plan.root_data.read_be_u64(root_ptrs + 8).unwrap(),
            plan.blocks[1]
        );
        assert!(plan.root_data[3 * BmbtKey::SIZE..root_ptrs]
            .iter()
            .all(|byte| *byte == 0));

        for (is_v5, count, header, ptrs, second_child_key) in [
            (false, 31, BtreeBlockLong::SIZE_V4, 24 + 30 * 8, 60),
            (true, 28, BtreeBlockLong::SIZE_V5, 72 + 27 * 8, 54),
        ] {
            let input = extents(count);
            let plan = plan_extents(&input, 20, TEST_BLOCK_SIZE, is_v5);
            let internal = &plan.buffers[2];
            let parsed = BtreeBlockLong::parse(internal, is_v5).unwrap();
            assert_eq!(parsed.level, 1);
            assert_eq!(parsed.ptrs_offset(TEST_BLOCK_SIZE).unwrap(), ptrs);
            assert_eq!(internal.read_be_u64(header).unwrap(), 0);
            assert_eq!(internal.read_be_u64(header + 8).unwrap(), second_child_key);
            assert_eq!(internal.read_be_u64(ptrs).unwrap(), plan.blocks[0]);
            assert_eq!(internal.read_be_u64(ptrs + 8).unwrap(), plan.blocks[1]);
            assert_round_trip(&plan, &input, is_v5);
        }
    }

    #[test]
    fn v4_nodes_use_bmap_and_v5_nodes_have_valid_headers_and_crcs() {
        let input = extents(5);
        let v4 = plan_extents(&input, 32, TEST_BLOCK_SIZE, false);
        assert_eq!(v4.buffers[0].read_be_u32(0).unwrap(), XFS_BMAP_MAGIC);
        BtreeBlockLong::parse(&v4.buffers[0], false)
            .unwrap()
            .verify_crc(&v4.buffers[0])
            .unwrap();

        let v5 = plan_extents(&input, 32, TEST_BLOCK_SIZE, true);
        for (index, buffer) in v5.buffers.iter().enumerate() {
            assert_eq!(buffer.read_be_u32(0).unwrap(), XFS_BMAP_CRC_MAGIC);
            assert_eq!(buffer.read_be_u64(32).unwrap(), TEST_LSN);
            assert_eq!(&buffer[40..56], &TEST_UUID);
            assert_eq!(buffer.read_be_u64(56).unwrap(), TEST_OWNER);
            let header = BtreeBlockLong::parse(buffer, true).unwrap();
            header.verify_crc(buffer).unwrap();
            assert_eq!(header.block_no, v5.blocks[index]);
        }
        assert_round_trip(&v5, &input, true);
    }

    #[test]
    fn v5_blockno_uses_basic_block_units() {
        let input = extents(3);
        let fs_block = 0x1234;
        for sector_size in [512, 1024, 4096] {
            let plan = plan_bmbt(
                &input,
                &[fs_block],
                &[],
                32,
                TEST_OWNER,
                TEST_UUID,
                4096,
                sector_size,
                true,
                TEST_LSN,
            )
            .unwrap();
            assert_eq!(
                plan.buffers[0].read_be_u64(24).unwrap(),
                fs_block * (4096 / 512)
            );
            assert_eq!(plan.blocks, vec![fs_block]);
        }
    }

    #[test]
    fn collect_round_trip_covers_single_and_multiple_leaves() {
        for is_v5 in [false, true] {
            let capacity = node_capacity(TEST_BLOCK_SIZE, is_v5).unwrap();
            for count in [3, capacity + 1, capacity * capacity + 1] {
                let input = extents(count);
                let plan = plan_extents(&input, 20, TEST_BLOCK_SIZE, is_v5);
                assert_round_trip(&plan, &input, is_v5);
            }
        }
    }

    #[test]
    fn extent_order_overlap_and_packed_ranges_are_validated() {
        let valid = Extent {
            file_offset: 10,
            start_block: 20,
            block_count: 2,
            is_unwritten: false,
        };
        for invalid in [
            Extent {
                block_count: 0,
                ..valid
            },
            Extent {
                file_offset: 1 << 54,
                ..valid
            },
            Extent {
                start_block: 1 << 52,
                ..valid
            },
            Extent {
                block_count: (1 << 21) + 1,
                ..valid
            },
        ] {
            assert!(matches!(
                plan_bmbt(
                    &[invalid],
                    &[],
                    &[],
                    32,
                    TEST_OWNER,
                    TEST_UUID,
                    TEST_BLOCK_SIZE,
                    TEST_SECTOR_SIZE,
                    false,
                    TEST_LSN,
                ),
                Err(FsError::InvalidArgument)
            ));
        }

        let overlapping = [
            valid,
            Extent {
                file_offset: 11,
                ..valid
            },
        ];
        assert!(validate_extents(&overlapping).is_err());
        let unsorted = [overlapping[1], overlapping[0]];
        assert!(validate_extents(&unsorted).is_err());
    }

    #[test]
    fn candidate_blocks_are_unique_null_free_and_sufficient() {
        let input = extents(3);
        for (existing, extra, expected) in [
            (vec![101, 101], vec![], FsError::InvalidArgument),
            (vec![NULL_BLOCK], vec![], FsError::InvalidArgument),
            (vec![], vec![], FsError::NoSpace),
        ] {
            let result = plan_bmbt(
                &input,
                &existing,
                &extra,
                32,
                TEST_OWNER,
                TEST_UUID,
                TEST_BLOCK_SIZE,
                TEST_SECTOR_SIZE,
                false,
                TEST_LSN,
            );
            assert_eq!(result.unwrap_err(), expected);
        }

        let plan = plan_bmbt(
            &input,
            &[101, 102],
            &[103],
            32,
            TEST_OWNER,
            TEST_UUID,
            TEST_BLOCK_SIZE,
            TEST_SECTOR_SIZE,
            false,
            TEST_LSN,
        )
        .unwrap();
        assert_eq!(plan.blocks, vec![101]);
    }

    #[test]
    fn geometry_and_operation_budgets_are_checked() {
        assert_eq!(required_block_count(0, 512, false).unwrap(), 0);
        assert_eq!(required_block_count(30, 512, false).unwrap(), 1);
        assert_eq!(required_block_count(31, 512, false).unwrap(), 3);
        assert_eq!(required_block_count(27, 512, true).unwrap(), 1);
        assert_eq!(required_block_count(28, 512, true).unwrap(), 3);

        for block_size in [0, 128, 513, 128 * 1024] {
            assert!(required_block_count(1, block_size, false).is_err());
        }
        assert!(required_block_count(MAX_BMBT_EXTENTS + 1, 512, false).is_err());
        assert!(required_block_count(usize::MAX, 512, false).is_err());
        assert!(plan_bmbt(
            &extents(3),
            &[101],
            &[],
            32,
            TEST_OWNER,
            TEST_UUID,
            512,
            0,
            false,
            TEST_LSN,
        )
        .is_err());
        assert!(plan_bmbt(
            &extents(3),
            &[101],
            &[],
            32,
            TEST_OWNER,
            TEST_UUID,
            512,
            512,
            false,
            TEST_LSN,
        )
        .is_ok());
        assert!(plan_bmbt(
            &extents(3),
            &[u64::MAX - 1],
            &[],
            32,
            TEST_OWNER,
            TEST_UUID,
            4096,
            512,
            true,
            TEST_LSN,
        )
        .is_err());
    }
}
