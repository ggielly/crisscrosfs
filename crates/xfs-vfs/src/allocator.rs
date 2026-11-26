//! Transactional XFS block allocation.
//!
//! The allocator keeps a per-AG in-memory model of the free extents. BNO and
//! CNT are collected and cross-checked, mutated together, and rebuilt with the
//! canonical short-B+tree codec. AGF and superblock updates are staged in the
//! same journal transaction as the tree blocks.

use std::{collections::BTreeMap, sync::Arc};

use fs_abstraction::{BlockDevice, FsError, FsResult};
use xfs_rs::{
    freespace::AllocRec,
    short_btree::{
        collect_short_btree,
        plan_short_btree,
        required_block_count,
        ShortBtreeKind,
        ShortBtreeSnapshot,
    },
    AgFreeHeader,
    Superblock,
};

use crate::{
    io::{read_exact_at, ClosureBlockReader},
    transaction::{MetadataKind, WriteBatch},
};

/// A contiguous allocation in one allocation group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeExtent {
    pub ag_num: u32,
    pub ag_block: u32,
    pub block_count: u32,
}

impl FreeExtent {
    pub fn to_absolute_block(self, ag_blocks: u32) -> FsResult<u64> {
        (self.ag_num as u64)
            .checked_mul(ag_blocks as u64)
            .and_then(|value| value.checked_add(self.ag_block as u64))
            .ok_or(FsError::ArithmeticOverflow)
    }

    pub fn from_absolute_block(block: u64, count: u32, ag_blocks: u32) -> FsResult<Self> {
        if ag_blocks == 0 || count == 0 {
            return Err(FsError::InvalidArgument);
        }
        let ag_num = block / ag_blocks as u64;
        let ag_block = block % ag_blocks as u64;
        if ag_num > u32::MAX as u64 || ag_block > u32::MAX as u64 {
            return Err(FsError::InvalidBlockAddress);
        }
        let extent = Self {
            ag_num: ag_num as u32,
            ag_block: ag_block as u32,
            block_count: count,
        };
        let end = extent.ag_block as u64 + count as u64;
        if end > ag_blocks as u64 {
            return Err(FsError::InvalidBlockAddress);
        }
        Ok(extent)
    }
}

#[derive(Debug)]
struct AgState {
    agf: AgFreeHeader,
    bno: ShortBtreeSnapshot,
    cnt: ShortBtreeSnapshot,
    free: Vec<AllocRec>,
    refcount: Option<xfs_rs::refcount::RefcountTree>,
    dirty: bool,
}

/// Transaction-scoped allocator. One instance may serve several allocations,
/// but [`Self::stage`] must be called exactly once before journal commit.
pub struct BlockAllocator {
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
    filesystem_size: u64,
    states: BTreeMap<u32, AgState>,
    free_block_delta: i128,
}

impl BlockAllocator {
    pub fn new(device: Arc<dyn BlockDevice>, sb: Superblock) -> FsResult<Self> {
        let filesystem_size = sb.size_bytes()?;
        Ok(Self {
            device,
            sb,
            filesystem_size,
            states: BTreeMap::new(),
            free_block_delta: 0,
        })
    }

    /// Allocate one contiguous extent, searching AGs in order.
    pub fn allocate_blocks(&mut self, count: u32) -> FsResult<FreeExtent> {
        if count == 0 {
            return Err(FsError::InvalidArgument);
        }
        let ag_blocks = self.sb.ag_blocks;
        for ag in 0..self.sb.ag_count {
            let state = self.load_ag(ag)?;
            if state.free.iter().any(|rec| rec.block_count >= count) {
                let index = state
                    .free
                    .iter()
                    .position(|rec| rec.block_count >= count)
                    .ok_or(FsError::Corrupted)?;
                let selected = state.free[index];
                let start = selected.start_block;
                let end = start
                    .checked_add(selected.block_count)
                    .ok_or(FsError::Corrupted)?;
                let allocated_end = start
                    .checked_add(count)
                    .ok_or(FsError::ArithmeticOverflow)?;
                if let Some(tree) = &state.refcount {
                    tree.ensure_unshared(start, count, ag_blocks)?;
                }
                state.free.remove(index);
                if allocated_end < end {
                    state.free.insert(
                        index,
                        AllocRec {
                            start_block: allocated_end,
                            block_count: end - allocated_end,
                        },
                    );
                }
                state.dirty = true;
                canonicalize(&mut state.free)?;
                self.free_block_delta -= i128::from(count);
                return Ok(FreeExtent {
                    ag_num: ag,
                    ag_block: start,
                    block_count: count,
                });
            }
        }
        Err(FsError::NoSpace)
    }

    /// Return a contiguous extent to the free pool.
    pub fn free_blocks(&mut self, extent: FreeExtent) -> FsResult<()> {
        if extent.block_count == 0 || extent.ag_num >= self.sb.ag_count {
            return Err(FsError::InvalidArgument);
        }
        let ag_blocks = self.sb.ag_blocks;
        let ag_length = if extent.ag_num + 1 == self.sb.ag_count {
            self.sb.total_blocks - u64::from(extent.ag_num) * u64::from(ag_blocks)
        } else {
            u64::from(ag_blocks)
        };
        let state = self.load_ag(extent.ag_num)?;
        let start = extent.ag_block;
        let end = start
            .checked_add(extent.block_count)
            .ok_or(FsError::ArithmeticOverflow)?;
        if u64::from(end) > ag_length {
            return Err(FsError::InvalidBlockAddress);
        }
        if state.free.iter().any(|rec| {
            u64::from(rec.start_block) < u64::from(end)
                && u64::from(start) < u64::from(rec.end_block())
        }) {
            return Err(FsError::AlreadyExists);
        }
        if let Some(tree) = &state.refcount {
            tree.ensure_unshared(start, extent.block_count, ag_blocks)?;
        }
        state.free.push(AllocRec {
            start_block: start,
            block_count: extent.block_count,
        });
        canonicalize(&mut state.free)?;
        state.dirty = true;
        self.free_block_delta += i128::from(extent.block_count);
        Ok(())
    }

    /// Reject overwrite or release of an extent tracked as shared or CoW
    /// staged.
    pub fn ensure_extent_unshared(&mut self, start: u64, count: u32) -> FsResult<()> {
        let ag_blocks = self.sb.ag_blocks;
        let extent = FreeExtent::from_absolute_block(start, count, ag_blocks)?;
        let state = self.load_ag(extent.ag_num)?;
        if let Some(tree) = &state.refcount {
            tree.ensure_unshared(extent.ag_block, extent.block_count, ag_blocks)?;
        }
        Ok(())
    }

    /// Net free-block counter delta for this transaction.
    pub fn free_block_delta(&self) -> i128 {
        self.free_block_delta
    }

    /// Stage all modified AG trees and AGF sectors. The caller merges the
    /// counter delta into the shared superblock transaction.
    pub fn stage(&mut self, batch: &mut WriteBatch) -> FsResult<()> {
        let sb = self.sb.clone();
        let device = self.device.clone();
        let filesystem_size = self.filesystem_size;
        let agf_offsets: BTreeMap<u32, u64> = self
            .states
            .keys()
            .copied()
            .map(|ag| Ok((ag, self.ag_header_offset(ag, 1)?)))
            .collect::<FsResult<_>>()?;
        for (&ag_num, state) in self.states.iter_mut().filter(|(_, state)| state.dirty) {
            let mut bno_records: Vec<Vec<u8>> = state
                .free
                .iter()
                .map(|rec| rec.to_bytes().to_vec())
                .collect();
            let mut cnt_records: Vec<AllocRec> = state.free.clone();
            cnt_records.sort_by_key(|rec| (rec.block_count, rec.start_block));
            let mut cnt_records: Vec<Vec<u8>> = cnt_records
                .iter()
                .map(|rec| rec.to_bytes().to_vec())
                .collect();

            let block_size = sb.block_size as usize;
            let is_v5 = sb.is_v5();
            let mut bno_extra = Vec::new();
            let mut cnt_extra = Vec::new();
            let mut free = state.free.clone();

            // Rebuilding may itself need more node blocks, and freeing surplus
            // nodes creates new free extents. Iterate to a stable shape.
            for _ in 0..32 {
                let bno_required = required_block_count(
                    ShortBtreeKind::AllocBno,
                    bno_records.len(),
                    block_size,
                    is_v5,
                )?;
                let cnt_required = required_block_count(
                    ShortBtreeKind::AllocCnt,
                    cnt_records.len(),
                    block_size,
                    is_v5,
                )?;
                let bno_candidates = state.bno.blocks.len() + bno_extra.len();
                let cnt_candidates = state.cnt.blocks.len() + cnt_extra.len();
                let bno_need = bno_required.saturating_sub(bno_candidates);
                let cnt_need = cnt_required.saturating_sub(cnt_candidates);
                if bno_need != 0 || cnt_need != 0 {
                    let taken =
                        take_free_blocks(&mut free, bno_need, &mut bno_extra, self.sb.ag_blocks)?;
                    let taken_cnt =
                        take_free_blocks(&mut free, cnt_need, &mut cnt_extra, self.sb.ag_blocks)?;
                    if taken != bno_need || taken_cnt != cnt_need {
                        return Err(FsError::NoSpace);
                    }
                    bno_records.clear();
                    bno_records.extend(free.iter().map(|rec| rec.to_bytes().to_vec()));
                    cnt_records.clear();
                    let mut sorted = free.clone();
                    sorted.sort_by_key(|rec| (rec.block_count, rec.start_block));
                    cnt_records.extend(sorted.iter().map(|rec| rec.to_bytes().to_vec()));
                    continue;
                }

                if bno_required < state.bno.blocks.len() + bno_extra.len()
                    || cnt_required < state.cnt.blocks.len() + cnt_extra.len()
                {
                    return Err(FsError::NotSupported);
                }

                break;
            }

            let bno_plan = plan_short_btree(
                ShortBtreeKind::AllocBno,
                &bno_records,
                &state.bno.blocks,
                &bno_extra,
                state.agf.bno_root,
                ag_num,
                self.sb.ag_blocks,
                self.sb.metadata_uuid(),
                block_size,
                u32::from(self.sb.sector_size),
                is_v5,
                0,
            )?;
            let cnt_plan = plan_short_btree(
                ShortBtreeKind::AllocCnt,
                &cnt_records,
                &state.cnt.blocks,
                &cnt_extra,
                state.agf.cnt_root,
                ag_num,
                self.sb.ag_blocks,
                self.sb.metadata_uuid(),
                block_size,
                u32::from(self.sb.sector_size),
                is_v5,
                0,
            )?;

            let extra_blocks = bno_extra
                .len()
                .checked_add(cnt_extra.len())
                .ok_or(FsError::ArithmeticOverflow)?;
            self.free_block_delta -=
                i128::try_from(extra_blocks).map_err(|_| FsError::ArithmeticOverflow)?;
            state.agf.btree_blocks = state
                .agf
                .btree_blocks
                .checked_add(u32::try_from(extra_blocks).map_err(|_| FsError::FileTooLarge)?)
                .ok_or(FsError::ArithmeticOverflow)?;
            state.agf.bno_level = u32::from(bno_plan.root_level) + 1;
            state.agf.cnt_level = u32::from(cnt_plan.root_level) + 1;
            state.agf.free_blocks = free
                .iter()
                .fold(0u32, |sum, rec| sum.saturating_add(rec.block_count));
            state.agf.longest_extent = free.iter().map(|rec| rec.block_count).max().unwrap_or(0);
            state.free = free;
            let refcount_raw = state
                .refcount
                .as_ref()
                .map(|tree| {
                    tree.build(
                        ag_num,
                        state.agf.refcount_root,
                        sb.ag_blocks,
                        block_size,
                        sb.sector_size as usize,
                        sb.metadata_uuid(),
                    )
                })
                .transpose()?;
            state.dirty = false;

            let agf_offset = agf_offsets[&ag_num];
            let mut agf_sector = vec![0u8; sb.sector_size as usize];
            read_exact_at(
                device.as_ref(),
                agf_offset,
                &mut agf_sector,
                filesystem_size,
            )?;
            let agf_raw = state.agf.apply_to_sector(&agf_sector, is_v5)?;
            batch.stage(
                device.as_ref(),
                agf_offset,
                agf_raw,
                MetadataKind::Agf,
                filesystem_size,
            )?;
            if let Some(raw) = refcount_raw {
                let absolute = (ag_num as u64)
                    .checked_mul(sb.ag_blocks as u64)
                    .and_then(|value| value.checked_add(u64::from(state.agf.refcount_root)))
                    .ok_or(FsError::ArithmeticOverflow)?;
                let offset = absolute
                    .checked_mul(sb.block_size as u64)
                    .ok_or(FsError::ArithmeticOverflow)?;
                batch.stage(
                    device.as_ref(),
                    offset,
                    raw,
                    MetadataKind::Btree,
                    filesystem_size,
                )?;
            }
            for plan in [bno_plan, cnt_plan] {
                for (block, buffer) in plan.blocks.into_iter().zip(plan.buffers) {
                    let absolute = (ag_num as u64)
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

    fn load_ag(&mut self, ag_num: u32) -> FsResult<&mut AgState> {
        if !self.states.contains_key(&ag_num) {
            let agf_offset = self.ag_header_offset(ag_num, 1)?;
            let mut raw = vec![0u8; self.sb.sector_size as usize];
            read_exact_at(
                self.device.as_ref(),
                agf_offset,
                &mut raw,
                self.filesystem_size,
            )?;
            let agf = AgFreeHeader::parse(&raw)?;
            if self.sb.is_v5() {
                agf.verify_crc(&raw)?;
            }
            let expected_length = if ag_num + 1 == self.sb.ag_count {
                self.sb.total_blocks - u64::from(ag_num) * u64::from(self.sb.ag_blocks)
            } else {
                u64::from(self.sb.ag_blocks)
            };
            if agf.seq_number != ag_num || u64::from(agf.length) != expected_length {
                return Err(FsError::Corrupted);
            }
            // RMAP updates are not implemented. Refuse rather than silently
            // allocating blocks absent from the reverse-map tree.
            if agf.rmap_root != 0 || agf.rmap_blocks != 0 {
                return Err(FsError::NotSupported);
            }

            let read_block = |block| self.read_block(block);
            let reader = ClosureBlockReader::new(&read_block);
            let bno = collect_short_btree(
                ShortBtreeKind::AllocBno,
                agf.bno_root,
                agf.bno_level.checked_sub(1).ok_or(FsError::Corrupted)? as u16,
                self.sb.block_size as usize,
                self.sb.is_v5(),
                ag_num,
                self.sb.ag_blocks,
                u32::from(self.sb.sector_size),
                &reader,
            )?;
            let cnt = collect_short_btree(
                ShortBtreeKind::AllocCnt,
                agf.cnt_root,
                agf.cnt_level.checked_sub(1).ok_or(FsError::Corrupted)? as u16,
                self.sb.block_size as usize,
                self.sb.is_v5(),
                ag_num,
                self.sb.ag_blocks,
                u32::from(self.sb.sector_size),
                &reader,
            )?;
            let refcount = if agf.refcount_root != 0 || agf.refcount_blocks != 0 {
                if agf.refcount_root == 0 || agf.refcount_level != 1 || agf.refcount_blocks != 1 {
                    return Err(FsError::NotSupported);
                }
                let absolute = (ag_num as u64)
                    .checked_mul(self.sb.ag_blocks as u64)
                    .and_then(|value| value.checked_add(u64::from(agf.refcount_root)))
                    .ok_or(FsError::ArithmeticOverflow)?;
                let raw = self.read_block(absolute)?;
                Some(xfs_rs::refcount::RefcountTree::parse(
                    &raw,
                    ag_num,
                    agf.refcount_root,
                    self.sb.ag_blocks,
                    self.sb.block_size as usize,
                    self.sb.sector_size as usize,
                    self.sb.metadata_uuid(),
                )?)
            } else {
                None
            };
            let mut free = Vec::with_capacity(bno.records.len());
            for raw in &bno.records {
                free.push(AllocRec::parse(raw)?);
            }
            canonicalize(&mut free)?;
            let mut cnt_free = Vec::with_capacity(cnt.records.len());
            for raw in &cnt.records {
                cnt_free.push(AllocRec::parse(raw)?);
            }
            cnt_free.sort_by_key(|rec| (rec.block_count, rec.start_block));
            let mut expected = free.clone();
            expected.sort_by_key(|rec| (rec.block_count, rec.start_block));
            if expected != cnt_free {
                return Err(FsError::Corrupted);
            }
            let sum = free
                .iter()
                .fold(0u32, |sum, rec| sum.saturating_add(rec.block_count));
            if sum != agf.free_blocks
                || free.iter().map(|rec| rec.block_count).max().unwrap_or(0) != agf.longest_extent
            {
                return Err(FsError::Corrupted);
            }
            self.states.insert(
                ag_num,
                AgState {
                    agf,
                    bno,
                    cnt,
                    free,
                    refcount,
                    dirty: false,
                },
            );
        }
        Ok(self.states.get_mut(&ag_num).expect("state was inserted"))
    }

    fn read_block(&self, block: u64) -> FsResult<Vec<u8>> {
        if block >= self.sb.total_blocks {
            return Err(FsError::Corrupted);
        }
        let offset = block
            .checked_mul(self.sb.block_size as u64)
            .ok_or(FsError::ArithmeticOverflow)?;
        let mut raw = vec![0u8; self.sb.block_size as usize];
        read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
        Ok(raw)
    }

    fn ag_header_offset(&self, ag_num: u32, sector: u64) -> FsResult<u64> {
        let ag_offset = (ag_num as u64)
            .checked_mul(self.sb.ag_blocks as u64)
            .and_then(|value| value.checked_mul(self.sb.block_size as u64))
            .ok_or(FsError::ArithmeticOverflow)?;
        ag_offset
            .checked_add(sector.saturating_mul(self.sb.sector_size as u64))
            .ok_or(FsError::ArithmeticOverflow)
    }
}

fn canonicalize(records: &mut Vec<AllocRec>) -> FsResult<()> {
    records.sort_by_key(|rec| rec.start_block);
    let mut merged: Vec<AllocRec> = Vec::with_capacity(records.len());
    for rec in records.drain(..) {
        if rec.block_count == 0 {
            return Err(FsError::Corrupted);
        }
        if let Some(last) = merged.last_mut() {
            if rec.start_block < last.end_block() {
                return Err(FsError::Corrupted);
            }
            if rec.start_block == last.end_block() {
                last.block_count = last
                    .block_count
                    .checked_add(rec.block_count)
                    .ok_or(FsError::ArithmeticOverflow)?;
                continue;
            }
        }
        merged.push(rec);
    }
    *records = merged;
    Ok(())
}

fn take_free_blocks(
    free: &mut Vec<AllocRec>,
    count: usize,
    output: &mut Vec<u32>,
    ag_blocks: u32,
) -> FsResult<usize> {
    let mut remaining = count;
    while remaining != 0 {
        let index = free
            .iter()
            .position(|rec| rec.block_count != 0)
            .ok_or(FsError::NoSpace)?;
        let rec = free[index];
        let take = (rec.block_count as usize).min(remaining);
        for offset in 0..take {
            output.push(
                rec.start_block
                    .checked_add(offset as u32)
                    .ok_or(FsError::ArithmeticOverflow)?,
            );
        }
        if take == rec.block_count as usize {
            free.remove(index);
        } else {
            free[index].start_block = rec
                .start_block
                .checked_add(take as u32)
                .ok_or(FsError::ArithmeticOverflow)?;
            free[index].block_count -= take as u32;
        }
        remaining -= take;
    }
    if output.iter().any(|block| *block >= ag_blocks) {
        return Err(FsError::Corrupted);
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_merges_adjacent_and_rejects_overlap() {
        let mut records = vec![
            AllocRec {
                start_block: 8,
                block_count: 2,
            },
            AllocRec {
                start_block: 2,
                block_count: 3,
            },
            AllocRec {
                start_block: 5,
                block_count: 3,
            },
        ];
        canonicalize(&mut records).unwrap();
        assert_eq!(
            records,
            vec![AllocRec {
                start_block: 2,
                block_count: 8
            }]
        );

        let mut overlap = vec![
            AllocRec {
                start_block: 2,
                block_count: 3,
            },
            AllocRec {
                start_block: 4,
                block_count: 1,
            },
        ];
        assert!(matches!(
            canonicalize(&mut overlap),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn absolute_extent_round_trip_checks_ag_bounds() {
        let extent = FreeExtent {
            ag_num: 2,
            ag_block: 15,
            block_count: 3,
        };
        let absolute = extent.to_absolute_block(100).unwrap();
        assert_eq!(absolute, 215);
        assert_eq!(
            FreeExtent::from_absolute_block(absolute, 3, 100).unwrap(),
            extent
        );
        assert!(FreeExtent::from_absolute_block(99, 2, 100).is_err());
    }
}
