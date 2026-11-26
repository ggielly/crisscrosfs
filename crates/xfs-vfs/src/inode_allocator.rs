//! Transactional XFS inode allocation using existing INOBT/FINOBT chunks.

use std::{collections::BTreeMap, sync::Arc};

use fs_abstraction::{BlockDevice, FsError, FsResult};
use xfs_rs::{
    inode_alloc::{InodeBtreeRec, SparseInodeBtreeRec},
    short_btree::{
        collect_short_btree,
        plan_short_btree,
        required_block_count,
        ShortBtreeKind,
        ShortBtreeSnapshot,
    },
    AgInodeHeader,
    Superblock,
};

use crate::{
    io::{read_exact_at, ClosureBlockReader},
    transaction::{MetadataKind, WriteBatch},
};

const XFS_SB_FEAT_RO_COMPAT_FINOBT: u32 = 1 << 0;

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
        })
    }

    pub fn free_inode_delta(&self) -> i128 {
        self.free_inode_delta
    }

    pub fn inode_count_delta(&self) -> i128 {
        self.inode_count_delta
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
            let agi = AgInodeHeader::parse(&raw)?;
            if self.sb.is_v5() {
                agi.verify_crc(&raw)?;
            }
            if agi.seq_number != ag {
                return Err(FsError::Corrupted);
            }
            let sparse = self.sb.has_sparse_inodes();
            let read_block = |block| self.read_block(block);
            let reader = ClosureBlockReader::new(&read_block);
            let ibt = collect_short_btree(
                ShortBtreeKind::Inode,
                agi.inode_root,
                agi.inode_level.checked_sub(1).ok_or(FsError::Corrupted)? as u16,
                self.sb.block_size as usize,
                self.sb.is_v5(),
                ag,
                self.sb.ag_blocks,
                u32::from(self.sb.sector_size),
                &reader,
            )?;
            let ibt_records = Self::parse_records(&ibt.records, sparse)?;
            let has_finobt = self.sb.features_ro_compat & XFS_SB_FEAT_RO_COMPAT_FINOBT != 0;
            let (fibt, fibt_records) = if has_finobt {
                if agi.free_inode_root == 0 {
                    return Err(FsError::Corrupted);
                }
                let snapshot = collect_short_btree(
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
