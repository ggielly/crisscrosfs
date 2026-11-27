//! Transactional XFS inode allocation using existing INOBT/FINOBT chunks.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use fs_abstraction::{BlockDevice, FsError, FsResult};
use xfs_rs::{
    inode_alloc::{InodeBtreeRec, SparseInodeBtreeRec},
    short_btree::{
        collect_short_btree_checked,
        plan_short_btree,
        required_block_count,
        ShortBtreeKind,
        ShortBtreeSnapshot,
    },
    AgInodeHeader,
    Inode,
    Superblock,
};

use crate::{
    io::{read_exact_at, ClosureBlockReader},
    transaction::{MetadataKind, WriteBatch},
};

const XFS_SB_FEAT_RO_COMPAT_FINOBT: u32 = 1 << 0;
const NULLAGINO: u32 = u32::MAX;

#[derive(Debug, Clone)]
enum InodeRecord {
    Full(InodeBtreeRec),
    Sparse(SparseInodeBtreeRec),
}

impl InodeRecord {
    fn start_ino(&self) -> u32 {
        match self {
            Self::Full(record) => record.start_ino,
            Self::Sparse(record) => record.start_ino,
        }
    }

    fn free_count(&self) -> u32 {
        match self {
            Self::Full(record) => record.free_count,
            Self::Sparse(record) => u32::from(record.free_count),
        }
    }

    fn first_free_inode(&self) -> Option<u32> {
        match self {
            Self::Full(record) => record.first_free_inode(),
            Self::Sparse(record) => record.first_free_inode(),
        }
    }

    fn allocate(&mut self, index: u32) -> bool {
        match self {
            Self::Full(record) => record.allocate_inode(index),
            Self::Sparse(record) => record.allocate_inode(index),
        }
    }

    fn free(&mut self, index: u32) -> bool {
        match self {
            Self::Full(record) => record.free_inode(index),
            Self::Sparse(record) => record.free_inode(index),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Full(record) => record.to_bytes().to_vec(),
            Self::Sparse(record) => record.to_bytes().to_vec(),
        }
    }
}

#[derive(Debug)]
struct AgState {
    agi: AgInodeHeader,
    ibt: ShortBtreeSnapshot,
    ibt_records: Vec<InodeRecord>,
    fibt: Option<ShortBtreeSnapshot>,
    fibt_records: Vec<InodeRecord>,
    dirty: bool,
}

/// Allocates and frees inodes in already-existing inode chunks.
///
/// New physical chunk allocation is intentionally rejected until cluster
/// geometry and inode initialization are implemented.
pub struct InodeAllocator {
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
    filesystem_size: u64,
    states: BTreeMap<u32, AgState>,
    free_inode_delta: i128,
    inode_count_delta: i128,
    /// `di_next_unlinked` values changed earlier in the same transaction.
    unlinked_next: BTreeMap<(u32, u32), u32>,
}

impl InodeAllocator {
    pub fn new(device: Arc<dyn BlockDevice>, sb: Superblock) -> FsResult<Self> {
        Ok(Self {
            device,
            filesystem_size: sb.size_bytes()?,
            sb,
            states: BTreeMap::new(),
            free_inode_delta: 0,
            inode_count_delta: 0,
            unlinked_next: BTreeMap::new(),
        })
    }

    pub fn free_inode_delta(&self) -> i128 {
        self.free_inode_delta
    }

    pub fn inode_count_delta(&self) -> i128 {
        self.inode_count_delta
    }

    /// Forget transaction-local accounting after the caller has successfully
    /// committed the staged superblock. The unlinked-pointer overlay is also
    /// transaction-local: retaining it would make later AGI walks observe
    /// links that are no longer pending. On failure the owner rebuilds the
    /// allocator from disk instead of calling this method.
    pub fn finish_transaction(&mut self) {
        self.free_inode_delta = 0;
        self.inode_count_delta = 0;
        self.unlinked_next.clear();
    }

    /// Allocate one inode from an existing chunk.
    pub fn allocate_inode(&mut self, is_directory: bool) -> FsResult<u64> {
        for ag in 0..self.sb.ag_count {
            let state = self.load_ag(ag)?;
            let source = if state.fibt.is_some() { "fibt" } else { "ibt" };
            let index = if state.fibt.is_some() {
                state
                    .fibt_records
                    .iter()
                    .position(|record| record.free_count() != 0)
            } else {
                state
                    .ibt_records
                    .iter()
                    .position(|record| record.free_count() != 0)
            };
            let Some(index) = index else {
                continue;
            };
            let selected_start = if source == "fibt" {
                state.fibt_records[index].start_ino()
            } else {
                state.ibt_records[index].start_ino()
            };
            let ag_ino = if source == "fibt" {
                state.fibt_records[index].first_free_inode()
            } else {
                state.ibt_records[index].first_free_inode()
            }
            .ok_or(FsError::Corrupted)?;
            let ibt_index = state
                .ibt_records
                .iter()
                .position(|record| record.start_ino() == selected_start)
                .ok_or(FsError::Corrupted)?;
            let in_chunk = ag_ino
                .checked_sub(selected_start)
                .ok_or(FsError::Corrupted)?;
            if !state.ibt_records[ibt_index].allocate(in_chunk) {
                return Err(FsError::Corrupted);
            }
            if let Some(fibt_index) = state
                .fibt_records
                .iter()
                .position(|record| record.start_ino() == selected_start)
            {
                if !state.fibt_records[fibt_index].allocate(in_chunk) {
                    return Err(FsError::Corrupted);
                }
                if state.fibt_records[fibt_index].free_count() == 0 {
                    state.fibt_records.remove(fibt_index);
                }
            }
            state.agi.inode_count = state
                .agi
                .inode_count
                .checked_add(1)
                .ok_or(FsError::ArithmeticOverflow)?;
            state.agi.free_inode_count = state
                .agi
                .free_inode_count
                .checked_sub(1)
                .ok_or(FsError::Corrupted)?;
            state.agi.recent_inode = ag_ino;
            if is_directory {
                state.agi.dir_inode = ag_ino;
            }
            state.dirty = true;
            self.free_inode_delta -= 1;
            self.inode_count_delta -= 1;
            let shift = u32::from(self.sb.ag_block_log) + u32::from(self.sb.inode_per_block_log);
            return Ok((u64::from(ag) << shift) | u64::from(ag_ino));
        }
        Err(FsError::NoSpace)
    }

    /// Mark an inode free in its existing chunk.
    pub fn free_inode(&mut self, ino: u64) -> FsResult<()> {
        let shift = u32::from(self.sb.ag_block_log) + u32::from(self.sb.inode_per_block_log);
        let ag = (ino >> shift) as u32;
        let ag_ino = (ino & ((1u64 << shift) - 1)) as u32;
        if ag >= self.sb.ag_count {
            return Err(FsError::InodeNotFound);
        }
        let state = self.load_ag(ag)?;
        let index = state
            .ibt_records
            .iter()
            .position(|record| ag_ino >= record.start_ino() && ag_ino < record.start_ino() + 64)
            .ok_or(FsError::InodeNotFound)?;
        let in_chunk = ag_ino - state.ibt_records[index].start_ino();
        if !state.ibt_records[index].free(in_chunk) {
            return Err(FsError::AlreadyExists);
        }
        if let Some(fibt_index) = state
            .fibt_records
            .iter()
            .position(|record| record.start_ino() == state.ibt_records[index].start_ino())
        {
            if !state.fibt_records[fibt_index].free(in_chunk) {
                return Err(FsError::Corrupted);
            }
        } else if state.fibt.is_some() {
            let mut record = state.ibt_records[index].clone();
            // The IBT record already has the bit set; insert it as-is.
            record.free(in_chunk);
            let insert_at = state
                .fibt_records
                .iter()
                .position(|record| record.start_ino() > ag_ino)
                .unwrap_or(state.fibt_records.len());
            state.fibt_records.insert(insert_at, record);
        }
        state.agi.inode_count = state
            .agi
            .inode_count
            .checked_sub(1)
            .ok_or(FsError::Corrupted)?;
        state.agi.free_inode_count = state
            .agi
            .free_inode_count
            .checked_add(1)
            .ok_or(FsError::Corrupted)?;
        state.dirty = true;
        self.free_inode_delta += 1;
        self.inode_count_delta += 1;
        Ok(())
    }

    /// Insert an AG-relative inode at the head of its AGI unlinked bucket.
    ///
    /// Returns the previous bucket head, which the caller must store in the
    /// inode's `di_next_unlinked` field. The complete chain is checked for
    /// duplicates, cycles and out-of-range inode numbers before mutation.
    pub fn insert_unlinked_inode(&mut self, ag: u32, ag_ino: u32) -> FsResult<u32> {
        let bucket = self.unlinked_bucket(ag, ag_ino)?;
        let head = self.load_ag(ag)?.agi.unlinked[bucket];
        let chain = self.unlinked_chain(ag, head)?;
        if chain.contains(&ag_ino) {
            return Err(FsError::AlreadyExists);
        }

        let state = self.load_ag(ag)?;
        state.agi.unlinked[bucket] = ag_ino;
        state.dirty = true;
        self.unlinked_next.insert((ag, ag_ino), head);
        Ok(head)
    }

    /// Remove an AG-relative inode from its AGI unlinked bucket.
    ///
    /// Returns `(predecessor, successor)`. If `predecessor` is `Some`, the
    /// caller must update that inode's `di_next_unlinked` to `successor` and
    /// stage it in the same transaction. The removed inode's own next pointer
    /// must be reset to `NULLAGINO` by the caller.
    pub fn remove_unlinked_inode(&mut self, ag: u32, ag_ino: u32) -> FsResult<(Option<u32>, u32)> {
        let bucket = self.unlinked_bucket(ag, ag_ino)?;
        let head = self.load_ag(ag)?.agi.unlinked[bucket];
        let chain = self.unlinked_chain(ag, head)?;
        let position = chain
            .iter()
            .position(|candidate| *candidate == ag_ino)
            .ok_or(FsError::NotFound)?;
        let successor = chain.get(position + 1).copied().unwrap_or(NULLAGINO);
        let predecessor = position.checked_sub(1).map(|index| chain[index]);

        if let Some(predecessor) = predecessor {
            self.unlinked_next.insert((ag, predecessor), successor);
        }
        self.unlinked_next.insert((ag, ag_ino), NULLAGINO);
        let state = self.load_ag(ag)?;
        if predecessor.is_none() {
            state.agi.unlinked[bucket] = successor;
        }
        state.dirty = true;
        Ok((predecessor, successor))
    }

    fn unlinked_bucket(&self, ag: u32, ag_ino: u32) -> FsResult<usize> {
        if ag >= self.sb.ag_count {
            return Err(FsError::InvalidArgument);
        }
        let shift = u32::from(self.sb.ag_block_log) + u32::from(self.sb.inode_per_block_log);
        if shift >= 32 {
            return Err(FsError::Corrupted);
        }
        if ag_ino == NULLAGINO || u64::from(ag_ino) >= (1u64 << shift) {
            return Err(FsError::InvalidArgument);
        }
        // Kernel and xfsprogs both hash the AG-relative inode number itself,
        // not its containing inode block: `agino % XFS_AGI_UNLINKED_BUCKETS`.
        Ok((ag_ino % 64) as usize)
    }

    fn unlinked_chain(&self, ag: u32, head: u32) -> FsResult<Vec<u32>> {
        let shift = u32::from(self.sb.ag_block_log) + u32::from(self.sb.inode_per_block_log);
        if shift >= 32 {
            return Err(FsError::Corrupted);
        }
        let capacity = 1u64 << shift;
        if head == NULLAGINO {
            return Ok(Vec::new());
        }
        let expected_bucket = self.unlinked_bucket(ag, head)?;
        let mut chain = Vec::new();
        let mut seen = BTreeSet::new();
        let mut current = head;
        while current != NULLAGINO {
            if self.unlinked_bucket(ag, current)? != expected_bucket {
                return Err(FsError::Corrupted);
            }
            if !seen.insert(current) || seen.len() as u64 > capacity {
                return Err(FsError::Corrupted);
            }
            chain.push(current);
            current = match self.unlinked_next.get(&(ag, current)) {
                Some(next) => *next,
                None => self.read_unlinked_next(ag, current)?,
            };
        }
        Ok(chain)
    }

    fn read_unlinked_next(&self, ag: u32, ag_ino: u32) -> FsResult<u32> {
        let shift = u32::from(self.sb.ag_block_log) + u32::from(self.sb.inode_per_block_log);
        if shift >= 32 || self.sb.inode_per_block_log >= 32 {
            return Err(FsError::Corrupted);
        }
        let inodes_per_block = 1u64 << self.sb.inode_per_block_log;
        let block_in_ag = u64::from(ag_ino) >> self.sb.inode_per_block_log;
        let inode_in_block = u64::from(ag_ino) & (inodes_per_block - 1);
        let block = (u64::from(ag))
            .checked_mul(u64::from(self.sb.ag_blocks))
            .and_then(|value| value.checked_add(block_in_ag))
            .ok_or(FsError::ArithmeticOverflow)?;
        if block >= self.sb.total_blocks {
            return Err(FsError::InodeNotFound);
        }
        let inode_size = self.sb.inode_size as usize;
        let offset = block
            .checked_mul(u64::from(self.sb.block_size))
            .and_then(|value| {
                inode_in_block
                    .checked_mul(inode_size as u64)
                    .and_then(|inode_offset| value.checked_add(inode_offset))
            })
            .ok_or(FsError::ArithmeticOverflow)?;
        let mut raw = vec![0u8; inode_size];
        read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
        let inode = Inode::parse_with_features(&raw, inode_size, self.sb.features_incompat)?;
        if self.sb.is_v5() {
            inode.verify_crc(&raw, inode_size)?;
        }
        Ok(inode.core.next_unlinked)
    }

    /// Stage rebuilt INOBT/FINOBT blocks and AGI sectors.
    pub fn stage(&mut self, batch: &mut WriteBatch) -> FsResult<()> {
        let sb = self.sb.clone();
        let device = self.device.clone();
        let filesystem_size = self.filesystem_size;
        for (&ag, state) in self.states.iter_mut().filter(|(_, state)| state.dirty) {
            let ibt_records: Vec<Vec<u8>> = state
                .ibt_records
                .iter()
                .map(InodeRecord::to_bytes)
                .collect();
            let ibt_plan = Self::plan_inode_tree(
                &sb,
                state,
                ShortBtreeKind::Inode,
                &ibt_records,
                state.agi.inode_root,
                ag,
            )?;
            let fibt_plan = if state.fibt.is_some() {
                let records: Vec<Vec<u8>> = state
                    .fibt_records
                    .iter()
                    .map(InodeRecord::to_bytes)
                    .collect();
                Some(Self::plan_inode_tree(
                    &sb,
                    state,
                    ShortBtreeKind::FreeInode,
                    &records,
                    state.agi.free_inode_root,
                    ag,
                )?)
            } else {
                None
            };

            state.agi.inode_level = u32::from(ibt_plan.root_level) + 1;
            if let Some(plan) = &fibt_plan {
                state.agi.free_inode_level = u32::from(plan.root_level) + 1;
            }
            if sb.is_v5() && (sb.features_ro_compat & (1 << 3)) != 0 {
                state.agi.inode_btree_blocks = ibt_plan.blocks.len() as u32;
                state.agi.free_inode_btree_blocks = fibt_plan
                    .as_ref()
                    .map_or(0, |plan| plan.blocks.len() as u32);
            }
            state.dirty = false;

            let offset = Self::ag_header_offset(&sb, ag, 2)?;
            let mut sector = vec![0u8; sb.sector_size as usize];
            read_exact_at(device.as_ref(), offset, &mut sector, filesystem_size)?;
            let raw = state.agi.apply_to_sector(&sector, sb.is_v5())?;
            batch.stage(
                device.as_ref(),
                offset,
                raw,
                MetadataKind::Agi,
                filesystem_size,
            )?;
            for plan in std::iter::once(ibt_plan).chain(fibt_plan) {
                for (block, buffer) in plan.blocks.into_iter().zip(plan.buffers) {
                    let absolute = (ag as u64)
                        .checked_mul(sb.ag_blocks as u64)
                        .and_then(|value| value.checked_add(block as u64))
                        .ok_or(FsError::ArithmeticOverflow)?;
                    let offset = absolute
                        .checked_mul(sb.block_size as u64)
                        .ok_or(FsError::ArithmeticOverflow)?;
                    batch.stage(
                        device.as_ref(),
                        offset,
                        buffer,
                        MetadataKind::Btree,
                        filesystem_size,
                    )?;
                }
            }
        }
        Ok(())
    }

    fn plan_inode_tree(
        sb: &Superblock,
        state: &AgState,
        kind: ShortBtreeKind,
        records: &[Vec<u8>],
        root: u32,
        ag: u32,
    ) -> FsResult<xfs_rs::ShortBtreeBuildPlan> {
        let existing = match kind {
            ShortBtreeKind::Inode => &state.ibt.blocks,
            ShortBtreeKind::FreeInode => state
                .fibt
                .as_ref()
                .map(|snapshot| &snapshot.blocks)
                .ok_or(FsError::Corrupted)?,
            _ => return Err(FsError::InvalidArgument),
        };
        let required =
            required_block_count(kind, records.len(), sb.block_size as usize, sb.is_v5())?;
        if required != existing.len() {
            return Err(FsError::NotSupported);
        }
        plan_short_btree(
            kind,
            records,
            existing,
            &[],
            root,
            ag,
            sb.ag_blocks,
            sb.metadata_uuid(),
            sb.block_size as usize,
            u32::from(sb.sector_size),
            sb.is_v5(),
            0,
        )
    }

    fn load_ag(&mut self, ag: u32) -> FsResult<&mut AgState> {
        if !self.states.contains_key(&ag) {
            let offset = Self::ag_header_offset(&self.sb, ag, 2)?;
            let mut raw = vec![0u8; self.sb.sector_size as usize];
            read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
            let agi = AgInodeHeader::parse_checked(
                &raw,
                self.sb.is_v5(),
                ag,
                self.sb.is_v5().then_some(self.sb.metadata_uuid()),
            )?;
            if agi.seq_number != ag {
                return Err(FsError::Corrupted);
            }
            let sparse = self.sb.has_sparse_inodes();
            let read_block = |block| self.read_block(block);
            let reader = ClosureBlockReader::new(&read_block);
            let ibt = collect_short_btree_checked(
                ShortBtreeKind::Inode,
                agi.inode_root,
                agi.inode_level.checked_sub(1).ok_or(FsError::Corrupted)? as u16,
                self.sb.block_size as usize,
                self.sb.is_v5(),
                ag,
                self.sb.ag_blocks,
                u32::from(self.sb.sector_size),
                &reader,
                self.sb.is_v5().then_some(self.sb.metadata_uuid()),
            )?;
            let ibt_records = Self::parse_records(&ibt.records, sparse)?;
            let has_finobt = self.sb.features_ro_compat & XFS_SB_FEAT_RO_COMPAT_FINOBT != 0;
            let (fibt, fibt_records) = if has_finobt {
                if agi.free_inode_root == 0 {
                    return Err(FsError::Corrupted);
                }
                let snapshot = collect_short_btree_checked(
                    ShortBtreeKind::FreeInode,
                    agi.free_inode_root,
                    agi.free_inode_level
                        .checked_sub(1)
                        .ok_or(FsError::Corrupted)? as u16,
                    self.sb.block_size as usize,
                    self.sb.is_v5(),
                    ag,
                    self.sb.ag_blocks,
                    u32::from(self.sb.sector_size),
                    &reader,
                    self.sb.is_v5().then_some(self.sb.metadata_uuid()),
                )?;
                let records = Self::parse_records(&snapshot.records, sparse)?;
                (Some(snapshot), records)
            } else {
                (None, Vec::new())
            };
            self.states.insert(
                ag,
                AgState {
                    agi,
                    ibt,
                    ibt_records,
                    fibt,
                    fibt_records,
                    dirty: false,
                },
            );
        }
        Ok(self.states.get_mut(&ag).expect("state was inserted"))
    }

    fn parse_records(raw: &[Vec<u8>], sparse: bool) -> FsResult<Vec<InodeRecord>> {
        raw.iter()
            .map(|bytes| {
                if sparse {
                    SparseInodeBtreeRec::parse(bytes).map(InodeRecord::Sparse)
                } else {
                    InodeBtreeRec::parse(bytes).map(InodeRecord::Full)
                }
            })
            .collect()
    }

    fn read_block(&self, block: u64) -> FsResult<Vec<u8>> {
        let offset = block
            .checked_mul(self.sb.block_size as u64)
            .ok_or(FsError::ArithmeticOverflow)?;
        let mut raw = vec![0u8; self.sb.block_size as usize];
        read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
        Ok(raw)
    }

    fn ag_header_offset(sb: &Superblock, ag: u32, sector: u64) -> FsResult<u64> {
        let ag_offset = (ag as u64)
            .checked_mul(sb.ag_blocks as u64)
            .and_then(|value| value.checked_mul(sb.block_size as u64))
            .ok_or(FsError::ArithmeticOverflow)?;
        ag_offset
            .checked_add(sector.saturating_mul(sb.sector_size as u64))
            .ok_or(FsError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoIoDevice;

    impl BlockDevice for NoIoDevice {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> FsResult<usize> {
            Err(FsError::InvalidBlockAddress)
        }

        fn write_at(&self, _offset: u64, _input: &[u8]) -> FsResult<usize> {
            Err(FsError::ReadOnly)
        }

        fn size(&self) -> u64 {
            0
        }
    }

    fn test_superblock() -> Superblock {
        let mut raw = vec![0u8; xfs_rs::XFS_SB_SIZE_V4];
        raw[0..4].copy_from_slice(&xfs_rs::XFS_SB_MAGIC.to_be_bytes());
        raw[4..8].copy_from_slice(&4096u32.to_be_bytes());
        raw[8..16].copy_from_slice(&1024u64.to_be_bytes());
        raw[0x54..0x58].copy_from_slice(&1024u32.to_be_bytes());
        raw[0x58..0x5C].copy_from_slice(&1u32.to_be_bytes());
        raw[0x64..0x66].copy_from_slice(&4u16.to_be_bytes());
        raw[0x66..0x68].copy_from_slice(&512u16.to_be_bytes());
        raw[0x68..0x6A].copy_from_slice(&256u16.to_be_bytes());
        raw[0x6A..0x6C].copy_from_slice(&16u16.to_be_bytes());
        raw[0x78] = 12;
        raw[0x79] = 9;
        raw[0x7A] = 8;
        raw[0x7B] = 4;
        raw[0x7C] = 10;
        Superblock::parse(&raw).unwrap()
    }

    fn test_agi() -> AgInodeHeader {
        let mut raw = vec![0u8; 512];
        raw[0..4].copy_from_slice(&xfs_rs::XFS_AGI_MAGIC.to_be_bytes());
        raw[4..8].copy_from_slice(&1u32.to_be_bytes());
        let mut agi = AgInodeHeader::parse(&raw).unwrap();
        agi.unlinked.fill(NULLAGINO);
        agi
    }

    fn allocator_with_empty_ag() -> InodeAllocator {
        let mut allocator = InodeAllocator::new(Arc::new(NoIoDevice), test_superblock()).unwrap();
        allocator.states.insert(
            0,
            AgState {
                agi: test_agi(),
                ibt: ShortBtreeSnapshot {
                    records: Vec::new(),
                    blocks: Vec::new(),
                    root_level: 0,
                },
                ibt_records: Vec::new(),
                fibt: None,
                fibt_records: Vec::new(),
                dirty: false,
            },
        );
        allocator
    }

    #[test]
    fn unlinked_insert_and_remove_preserve_bucket_order() {
        let mut allocator = allocator_with_empty_ag();
        assert_eq!(allocator.insert_unlinked_inode(0, 128).unwrap(), NULLAGINO);
        assert_eq!(allocator.insert_unlinked_inode(0, 192).unwrap(), 128);
        assert!(matches!(
            allocator.insert_unlinked_inode(0, 128),
            Err(FsError::AlreadyExists)
        ));

        assert_eq!(
            allocator.remove_unlinked_inode(0, 128).unwrap(),
            (Some(192), NULLAGINO)
        );
        // Simulate the writer staging the predecessor's updated next pointer.
        allocator.unlinked_next.insert((0, 192), NULLAGINO);
        assert_eq!(
            allocator.remove_unlinked_inode(0, 192).unwrap(),
            (None, NULLAGINO)
        );
        assert_eq!(allocator.states[&0].agi.unlinked[0], NULLAGINO);
    }

    #[test]
    fn unlinked_lists_reject_cycles_and_out_of_range_inodes() {
        let mut allocator = allocator_with_empty_ag();
        allocator.states.get_mut(&0).unwrap().agi.unlinked[0] = 128;
        allocator.unlinked_next.insert((0, 128), 192);
        allocator.unlinked_next.insert((0, 192), 128);
        assert!(matches!(
            allocator.insert_unlinked_inode(0, 256),
            Err(FsError::Corrupted)
        ));
        assert!(matches!(
            allocator.insert_unlinked_inode(0, 1 << 14),
            Err(FsError::InvalidArgument)
        ));
        assert!(matches!(
            allocator.insert_unlinked_inode(1, 128),
            Err(FsError::InvalidArgument)
        ));

        let mut cross_bucket = allocator_with_empty_ag();
        cross_bucket.states.get_mut(&0).unwrap().agi.unlinked[0] = 128;
        cross_bucket.unlinked_next.insert((0, 128), 129);
        assert!(matches!(
            cross_bucket.insert_unlinked_inode(0, 256),
            Err(FsError::Corrupted)
        ));
    }
}
