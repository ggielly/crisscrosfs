//! Transactional XFS write operations.

use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

use fs_abstraction::{BlockDevice, FsError, FsResult, RenameFlags, VfsFileInfo, VfsTimestamp};
use parking_lot::MutexGuard;
use xfs_rs::{
    bmbt_write::{plan_bmbt, required_block_count},
    btree::{btree_collect_extents_checked, BmbtRoot, BtreeBlockLong},
    constants::{S_IFDIR, S_IFLNK, S_IFREG},
    dir_write::{
        add_block_directory_entry,
        add_shortform_entry,
        build_block_directory,
        build_leaf_directory,
        build_node_directory,
        leaf1_record_capacity,
        leaf_directory_data_block_count,
        leaf_node_record_capacity,
        parse_block_directory,
        remove_block_directory_entry,
        remove_shortform_entry,
        NewDirEntry,
    },
    directory::{DirFileType, ShortformHeader},
    DataFork,
    Extent,
    Inode,
    InodeFormat,
    Superblock,
};

use crate::{
    allocator::BlockAllocator,
    inode::inode_to_file_info,
    inode_allocator::InodeAllocator,
    inode_write::{nblocks_from_fs_blocks, serialize_inode, touch_inode},
    io::{read_exact_at, write_exact_at, ClosureBlockReader, VfsBlockReader},
    journal::Journal,
    transaction::{MetadataKind, WriteBatch},
};

/// Total dirty block memory retained across all inodes. Sparse writes consume
/// one block each, never memory proportional to the logical file size.
pub(crate) const MAX_DELALLOC_BYTES: usize = 16 * 1024 * 1024;
/// Per-inode cap prevents one writer from monopolizing the global budget.
pub(crate) const MAX_DELALLOC_FILE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Default)]
pub(crate) struct DelallocBudget {
    remaining: AtomicUsize,
}

impl DelallocBudget {
    pub(crate) fn with_capacity(capacity: usize) -> Self {
        Self {
            remaining: AtomicUsize::new(capacity),
        }
    }

    pub(crate) fn available(&self) -> usize {
        self.remaining.load(Ordering::Acquire)
    }

    pub(crate) fn try_reserve(&self, bytes: usize) -> FsResult<()> {
        if bytes == 0 {
            return Ok(());
        }
        self.remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(bytes)
            })
            .map(|_| ())
            .map_err(|_| FsError::OutOfMemory)
    }

    pub(crate) fn release(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let _ = self
            .remaining
            .try_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(bytes)
            });
    }
}

/// Dirty full-block images plus the logical EOF for one inode. Access is
/// protected by that inode's RwLock; no internal mutex is needed.
#[derive(Debug, Default)]
pub(crate) struct PendingWrites {
    blocks: BTreeMap<u64, Vec<u8>>,
    size: u64,
}

impl PendingWrites {
    pub(crate) fn with_size(size: u64) -> Self {
        Self {
            blocks: BTreeMap::new(),
            size,
        }
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    pub(crate) fn memory_bytes(&self, block_size: usize) -> usize {
        self.blocks.len().saturating_mul(block_size)
    }

    pub(crate) fn ranges(&self) -> impl Iterator<Item = (u64, &[u8])> {
        self.blocks
            .iter()
            .map(|(&file_block, block)| (file_block, block.as_slice()))
    }

    /// Buffer one write without partial mutation on allocation/budget failure.
    /// Replacements are staged separately and installed only after every block
    /// succeeds. Existing dirty blocks may be temporarily duplicated, bounded
    /// by the same per-inode and global dirty-block limits.
    pub(crate) fn write(
        &mut self,
        offset: u64,
        data: &[u8],
        block_size: usize,
        disk_size: u64,
        budget: &DelallocBudget,
        mut read_disk_block: impl FnMut(u64) -> FsResult<Vec<u8>>,
    ) -> FsResult<usize> {
        if block_size == 0 {
            return Err(FsError::InvalidArgument);
        }
        let data_len = u64::try_from(data.len()).map_err(|_| FsError::ArithmeticOverflow)?;
        let end = offset
            .checked_add(data_len)
            .ok_or(FsError::ArithmeticOverflow)?;
        if end > i64::MAX as u64 {
            return Err(FsError::FileTooLarge);
        }
        if data.is_empty() {
            self.size = self.size.max(disk_size);
            return Ok(0);
        }

        let first = offset / block_size as u64;
        let last = (end - 1) / block_size as u64;
        let count = last - first + 1;
        let max_blocks = (MAX_DELALLOC_FILE_BYTES / block_size) as u64;
        if count > max_blocks {
            return Err(FsError::OutOfMemory);
        }
        let missing = (first..=last)
            .filter(|file_block| !self.blocks.contains_key(file_block))
            .count();
        let additional = missing
            .checked_mul(block_size)
            .ok_or(FsError::OutOfMemory)?;
        let projected = self
            .memory_bytes(block_size)
            .checked_add(additional)
            .ok_or(FsError::OutOfMemory)?;
        if projected > MAX_DELALLOC_FILE_BYTES || additional > budget.available() {
            return Err(FsError::OutOfMemory);
        }

        let mut staged = Vec::new();
        staged
            .try_reserve_exact(count as usize)
            .map_err(|_| FsError::OutOfMemory)?;
        let mut reserved = 0usize;
        let result = (|| -> FsResult<()> {
            for file_block in first..=last {
                let block = if let Some(previous) = self.blocks.get(&file_block) {
                    let mut block = Vec::new();
                    block
                        .try_reserve_exact(previous.len())
                        .map_err(|_| FsError::OutOfMemory)?;
                    block.extend_from_slice(previous);
                    block
                } else {
                    budget.try_reserve(block_size)?;
                    reserved += block_size;
                    let mut block = Vec::new();
                    block
                        .try_reserve_exact(block_size)
                        .map_err(|_| FsError::OutOfMemory)?;
                    block.resize(block_size, 0);
                    block
                };
                staged.push((file_block, block));

                let block_start = file_block
                    .checked_mul(block_size as u64)
                    .ok_or(FsError::ArithmeticOverflow)?;
                let range_start = offset.max(block_start);
                let range_end = end.min(block_start + block_size as u64);
                let dst = usize::try_from(range_start - block_start)
                    .map_err(|_| FsError::ArithmeticOverflow)?;
                let src = usize::try_from(range_start - offset)
                    .map_err(|_| FsError::ArithmeticOverflow)?;
                let len = usize::try_from(range_end - range_start)
                    .map_err(|_| FsError::ArithmeticOverflow)?;
                let block = &mut staged.last_mut().expect("just pushed").1;
                if dst != 0 || len != block_size {
                    let disk = read_disk_block(file_block)?;
                    if disk.len() != block_size {
                        return Err(FsError::Corrupted);
                    }
                    block.copy_from_slice(&disk);
                }
                block[dst..dst + len].copy_from_slice(&data[src..src + len]);
            }
            Ok(())
        })();

        if let Err(error) = result {
            budget.release(reserved);
            return Err(error);
        }

        self.blocks.extend(staged);
        self.size = self.size.max(end);
        Ok(data.len())
    }

    /// Overlay dirty bytes onto a zero-filled disk read. The caller clamps the
    /// read to this logical EOF before invoking this method.
    pub(crate) fn overlay_read(&self, offset: u64, buf: &mut [u8], block_size: usize) {
        if buf.is_empty() || block_size == 0 {
            return;
        }
        let end = offset.saturating_add(buf.len() as u64).min(self.size);
        if end <= offset {
            return;
        }
        let first = offset / block_size as u64;
        for (&file_block, block) in self.blocks.range(first..) {
            let block_start = file_block.saturating_mul(block_size as u64);
            let block_end = block_start.saturating_add(block_size as u64);
            let copy_start = offset.max(block_start);
            let copy_end = end.min(block_end);
            if copy_start >= copy_end {
                if block_start >= end {
                    break;
                }
                continue;
            }
            let dst = usize::try_from(copy_start - offset).unwrap_or(0);
            let src = usize::try_from(copy_start - block_start).unwrap_or(0);
            let count = usize::try_from(copy_end - copy_start).unwrap_or(0);
            if let (Some(destination), Some(source)) =
                (buf.get_mut(dst..dst + count), block.get(src..src + count))
            {
                destination.copy_from_slice(source);
            }
        }
    }
}

/// Mutable writer context. The caller holds the metadata and inode write locks.
pub(crate) struct WriteContext<'a> {
    pub device: Arc<dyn BlockDevice>,
    pub superblock: Superblock,
    pub filesystem_size: u64,
    pub journal: &'a mut Journal,
    pub allocator: MutexGuard<'a, BlockAllocator>,
    pub inode_allocator: MutexGuard<'a, InodeAllocator>,
    /// Blocks staged earlier in the same transaction.
    pub block_overlay: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Original data-block images restored if metadata preparation fails before
    /// a log record is committed.
    pub data_rollback: std::collections::BTreeMap<u64, Vec<u8>>,
    /// Inode images staged earlier in this context. Deferred multi-inode
    /// flushes use these instead of rereading superseded on-disk inodes.
    pub staged_inodes: BTreeMap<u64, Inode>,
    /// Cache invalidation hints collected before the context is dropped.
    pub dirty_inodes: BTreeSet<u64>,
    pub dirty_directories: BTreeSet<u64>,
    pub dirty_blocks: BTreeSet<u64>,
    /// Handles pinned at transaction start; their inodes cannot be reclaimed.
    pub pinned_inodes: BTreeSet<u64>,
}

impl VfsBlockReader for WriteContext<'_> {
    fn read_block(&self, block_num: u64) -> FsResult<Arc<[u8]>> {
        Ok(WriteContext::read_block(self, block_num)?.into())
    }

    fn read_at(&self, block_num: u64, offset: u64, buf: &mut [u8]) -> FsResult<()> {
        let block_size = u64::from(self.superblock.block_size);
        let len = u64::try_from(buf.len()).map_err(|_| FsError::ArithmeticOverflow)?;
        if offset > block_size || len > block_size - offset {
            return Err(FsError::Corrupted);
        }
        let block = WriteContext::read_block(self, block_num)?;
        let start = usize::try_from(offset).map_err(|_| FsError::ArithmeticOverflow)?;
        buf.copy_from_slice(&block[start..start + buf.len()]);
        Ok(())
    }
}

impl Drop for WriteContext<'_> {
    fn drop(&mut self) {
        // Once a log record may be durable, its metadata images and the new
        // data blocks must be recovered together. Rolling data back in that
        // state would make replay produce inconsistent contents.
        if self.journal.is_poisoned() || self.data_rollback.is_empty() {
            self.data_rollback.clear();
            return;
        }
        for (block, original) in self.data_rollback.iter().rev() {
            let offset = match block.checked_mul(u64::from(self.superblock.block_size)) {
                Some(offset) => offset,
                None => continue,
            };
            if let Err(error) =
                write_exact_at(self.device.as_ref(), offset, original, self.filesystem_size)
            {
                tracing::error!(block, %error, "failed to restore data block after aborted write");
            }
        }
        let _ = self.device.flush();
        self.data_rollback.clear();
    }
}

#[derive(Debug, Clone, Copy)]
struct InodeLocation {
    block_offset: u64,
    offset_in_block: usize,
    inode_size: usize,
}

impl WriteContext<'_> {
    fn stage_write_data_with_info(
        &mut self,
        ino: u64,
        offset: u64,
        data: &[u8],
        batch: &mut WriteBatch,
    ) -> FsResult<(usize, VfsFileInfo)> {
        if data.is_empty() {
            let location = self.inode_location(ino)?;
            let inode = self.read_inode(ino, location)?;
            let info = inode_to_file_info(
                ino,
                &inode,
                self.superblock.block_size,
                self.superblock.has_bigtime(),
                self.filesystem_size,
            )?;
            return Ok((0, info));
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(FsError::ArithmeticOverflow)?;
        if end > i64::MAX as u64 {
            return Err(FsError::FileTooLarge);
        }

        let location = self.inode_location(ino)?;
        let mut inode = self.read_inode(ino, location)?;
        if !inode.core.is_file() {
            return Err(FsError::InvalidArgument);
        }
        let block_size = u64::from(self.superblock.block_size);

        if let DataFork::Local(local) = &mut inode.data_fork {
            let capacity = inode.core.data_fork_size(location.inode_size);
            let end_usize = usize::try_from(end).map_err(|_| FsError::FileTooLarge)?;
            if end_usize <= capacity {
                if local.len() < end_usize {
                    local.resize(end_usize, 0);
                }
                let start = usize::try_from(offset).map_err(|_| FsError::FileTooLarge)?;
                local[start..end_usize].copy_from_slice(data);
                inode.core.size = local.len() as u64;
                let info = inode_to_file_info(
                    ino,
                    &inode,
                    self.superblock.block_size,
                    self.superblock.has_bigtime(),
                    self.filesystem_size,
                )?;
                self.stage_inode(batch, ino, location, &inode)?;
                return Ok((data.len(), info));
            }
        }

        let mut extents = match &inode.data_fork {
            DataFork::Local(local) => {
                // Preserve inline bytes in one allocated block. Remaining
                // holes are allocated by the per-file-block loop below, so a
                // sparse write does not materialize every intervening block.
                let blocks = u64::from(!local.is_empty());
                let extents = self.allocate_extents(0, blocks)?;
                let byte_len = usize::try_from(
                    blocks
                        .checked_mul(block_size)
                        .ok_or(FsError::ArithmeticOverflow)?,
                )
                .map_err(|_| FsError::FileTooLarge)?;
                let mut raw = vec![0u8; byte_len];
                let copy_len = local.len().min(raw.len());
                raw[..copy_len].copy_from_slice(&local[..copy_len]);
                let raw_len = raw.len() as u64;
                let copy_start = offset.min(raw_len);
                let copy_end = end.min(raw_len);
                if copy_start < copy_end {
                    let start = usize::try_from(copy_start).map_err(|_| FsError::FileTooLarge)?;
                    let source = usize::try_from(copy_start - offset)
                        .map_err(|_| FsError::ArithmeticOverflow)?;
                    let len = usize::try_from(copy_end - copy_start)
                        .map_err(|_| FsError::ArithmeticOverflow)?;
                    raw[start..start + len].copy_from_slice(&data[source..source + len]);
                }
                for extent in &extents {
                    let file_start = usize::try_from(
                        extent
                            .file_offset
                            .checked_mul(block_size)
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .map_err(|_| FsError::ArithmeticOverflow)?;
                    let len = usize::try_from(
                        u64::from(extent.block_count)
                            .checked_mul(block_size)
                            .ok_or(FsError::ArithmeticOverflow)?,
                    )
                    .map_err(|_| FsError::ArithmeticOverflow)?;
                    self.write_data_block(extent.start_block, &raw[file_start..file_start + len])?;
                }
                extents
            }
            DataFork::Extents(_) | DataFork::Btree { .. } => self.collect_inode_extents(&inode)?,
            _ => return Err(FsError::NotSupported),
        };

        let first_block = offset / block_size;
        let last_block = (end - 1) / block_size;
        for file_block in first_block..=last_block {
            let existing = extents
                .iter()
                .position(|extent| extent.contains_file_block(file_block));
            let (disk_block, zero_first) = if let Some(index) = existing {
                (
                    extents[index].translate(file_block)?,
                    extents[index].is_unwritten,
                )
            } else {
                let allocation = self.allocator.allocate_blocks(1)?;
                let disk_block = allocation.to_absolute_block(self.superblock.ag_blocks)?;
                let insert_at = extents
                    .iter()
                    .position(|extent| extent.file_offset > file_block)
                    .unwrap_or(extents.len());
                extents.insert(
                    insert_at,
                    Extent {
                        file_offset: file_block,
                        start_block: disk_block,
                        block_count: 1,
                        is_unwritten: false,
                    },
                );
                coalesce_extents(&mut extents)?;
                (disk_block, true)
            };
            self.allocator.ensure_extent_unshared(disk_block, 1)?;
            if zero_first {
                let zeros = vec![0u8; block_size as usize];
                self.write_data_block(disk_block, &zeros)?;
                let index = extents
                    .iter()
                    .position(|extent| extent.contains_file_block(file_block))
                    .ok_or(FsError::Corrupted)?;
                let mut extent = extents.remove(index);
                let before = file_block - extent.file_offset;
                let after = extent
                    .block_count
                    .checked_sub(before as u32 + 1)
                    .ok_or(FsError::Corrupted)?;
                let start = extent.start_block;
                extent.block_count = before as u32;
                if before != 0 {
                    extents.insert(index, extent);
                }
                let converted_index = index + usize::from(before != 0);
                let converted_start = start
                    .checked_add(before)
                    .ok_or(FsError::ArithmeticOverflow)?;
                extents.insert(
                    converted_index,
                    Extent {
                        file_offset: file_block,
                        start_block: converted_start,
                        block_count: 1,
                        is_unwritten: false,
                    },
                );
                if after != 0 {
                    let after_start = converted_start
                        .checked_add(1)
                        .ok_or(FsError::ArithmeticOverflow)?;
                    let after_offset = file_block
                        .checked_add(1)
                        .ok_or(FsError::ArithmeticOverflow)?;
                    extents.insert(
                        converted_index + 1,
                        Extent {
                            file_offset: after_offset,
                            start_block: after_start,
                            block_count: after,
                            is_unwritten: true,
                        },
                    );
                }
                coalesce_extents(&mut extents)?;
            }

            let block_start = file_block
                .checked_mul(block_size)
                .ok_or(FsError::ArithmeticOverflow)?;
            let range_start = offset.max(block_start);
            let range_end = end.min(block_start + block_size);
            let dst = usize::try_from(range_start - block_start)
                .map_err(|_| FsError::ArithmeticOverflow)?;
            let src =
                usize::try_from(range_start - offset).map_err(|_| FsError::ArithmeticOverflow)?;
            let len = usize::try_from(range_end - range_start)
                .map_err(|_| FsError::ArithmeticOverflow)?;
            let mut block = if dst == 0 && len == block_size as usize {
                vec![0u8; block_size as usize]
            } else {
                self.read_block(disk_block)?
            };
            block[dst..dst + len].copy_from_slice(&data[src..src + len]);
            self.write_data_block(disk_block, &block)?;
        }
        self.rebuild_data_fork(ino, &mut inode, extents, location.inode_size, batch)?;
        inode.core.size = inode.core.size.max(end);
        let info = inode_to_file_info(
            ino,
            &inode,
            self.superblock.block_size,
            self.superblock.has_bigtime(),
            self.filesystem_size,
        )?;
        self.stage_inode(batch, ino, location, &inode)?;
        Ok((data.len(), info))
    }

    /// Stage one inode's delalloc flush into a batch shared with other inodes.
    pub fn stage_delalloc_to_size(
        &mut self,
        ino: u64,
        pending: &PendingWrites,
        size: u64,
        batch: &mut WriteBatch,
    ) -> FsResult<VfsFileInfo> {
        if size > i64::MAX as u64 {
            return Err(FsError::FileTooLarge);
        }
        if !pending.is_empty() {
            let block_size = u64::from(self.superblock.block_size);
            let retained_blocks = size.div_ceil(block_size);
            for (file_block, block) in pending.ranges() {
                if file_block >= retained_blocks {
                    break;
                }
                let offset = file_block
                    .checked_mul(block_size)
                    .ok_or(FsError::ArithmeticOverflow)?;
                self.stage_write_data_with_info(ino, offset, block, batch)?;
            }
        }
        self.stage_set_size(ino, size, batch)?;
        let location = self.inode_location(ino)?;
        let inode = self.read_inode(ino, location)?;
        inode_to_file_info(
            ino,
            &inode,
            self.superblock.block_size,
            self.superblock.has_bigtime(),
            self.filesystem_size,
        )
    }

    /// Change logical file size, freeing and zeroing extents on shrink and
    /// preserving holes on extend.
    pub fn set_size(&mut self, ino: u64, new_size: u64) -> FsResult<()> {
        let mut batch = WriteBatch::new();
        self.stage_set_size(ino, new_size, &mut batch)?;
        self.flush_staged_data()?;
        self.commit_batch(&mut batch)?;
        self.data_rollback.clear();
        Ok(())
    }

    fn stage_set_size(&mut self, ino: u64, new_size: u64, batch: &mut WriteBatch) -> FsResult<()> {
        if new_size > i64::MAX as u64 {
            return Err(FsError::FileTooLarge);
        }
        let location = self.inode_location(ino)?;
        let mut inode = self.read_inode(ino, location)?;
        if !inode.core.is_file() {
            return Err(FsError::InvalidArgument);
        }
        if inode.core.size == new_size {
            return Ok(());
        }
        let block_size = u64::from(self.superblock.block_size);

        if new_size < inode.core.size {
            match &mut inode.data_fork {
                DataFork::Local(data) => {
                    let size = usize::try_from(new_size).map_err(|_| FsError::FileTooLarge)?;
                    data.truncate(size);
                }
                DataFork::Extents(_) | DataFork::Btree { .. } => {
                    let mut extents = self.collect_inode_extents(&inode)?;
                    let target_blocks = new_size.div_ceil(block_size);
                    let mut retained = Vec::with_capacity(extents.len());
                    for mut extent in extents.drain(..) {
                        if extent.file_offset >= target_blocks {
                            self.free_absolute_extent(extent.start_block, extent.block_count)?;
                            continue;
                        }
                        let extent_end = extent.file_end()?;
                        if extent_end > target_blocks {
                            let keep = (target_blocks - extent.file_offset) as u32;
                            let freed = extent.block_count - keep;
                            if freed != 0 {
                                let start = extent
                                    .start_block
                                    .checked_add(u64::from(keep))
                                    .ok_or(FsError::ArithmeticOverflow)?;
                                self.free_absolute_extent(start, freed)?;
                                extent.block_count = keep;
                            }
                        }
                        retained.push(extent);
                    }
                    coalesce_extents(&mut retained)?;
                    if !new_size.is_multiple_of(block_size) {
                        let file_block = target_blocks - 1;
                        let extent = retained
                            .iter()
                            .find(|extent| extent.contains_file_block(file_block))
                            .ok_or(FsError::Corrupted)?;
                        let disk_block = extent.translate(file_block)?;
                        self.allocator.ensure_extent_unshared(disk_block, 1)?;
                        let mut block = self.read_block(disk_block)?;
                        let tail = usize::try_from(new_size % block_size)
                            .map_err(|_| FsError::ArithmeticOverflow)?;
                        block[tail..].fill(0);
                        self.write_data_block(disk_block, &block)?;
                    }
                    self.rebuild_data_fork(ino, &mut inode, retained, location.inode_size, batch)?;
                }
                _ => return Err(FsError::NotImplemented),
            }
        } else {
            match &mut inode.data_fork {
                DataFork::Local(data) => {
                    let size = usize::try_from(new_size).map_err(|_| FsError::FileTooLarge)?;
                    if size <= inode.core.data_fork_size(location.inode_size) {
                        data.resize(size, 0);
                    } else {
                        let existing = data.clone();
                        let blocks = (existing.len() as u64).div_ceil(block_size);
                        let extents = self.allocate_extents(0, blocks)?;
                        let byte_len = usize::try_from(
                            blocks
                                .checked_mul(block_size)
                                .ok_or(FsError::ArithmeticOverflow)?,
                        )
                        .map_err(|_| FsError::FileTooLarge)?;
                        let mut raw = vec![0u8; byte_len];
                        raw[..existing.len()].copy_from_slice(&existing);
                        for extent in &extents {
                            let file_start = usize::try_from(
                                extent
                                    .file_offset
                                    .checked_mul(block_size)
                                    .ok_or(FsError::ArithmeticOverflow)?,
                            )
                            .map_err(|_| FsError::ArithmeticOverflow)?;
                            let len = usize::try_from(
                                u64::from(extent.block_count)
                                    .checked_mul(block_size)
                                    .ok_or(FsError::ArithmeticOverflow)?,
                            )
                            .map_err(|_| FsError::ArithmeticOverflow)?;
                            self.write_data_block(
                                extent.start_block,
                                &raw[file_start..file_start + len],
                            )?;
                        }
                        self.rebuild_data_fork(
                            ino,
                            &mut inode,
                            extents,
                            location.inode_size,
                            batch,
                        )?;
                    }
                }
                DataFork::Extents(_) | DataFork::Btree { .. } => {}
                _ => return Err(FsError::NotImplemented),
            }
        }

        inode.core.size = new_size;
        self.stage_inode(batch, ino, location, &inode)?;
        Ok(())
    }

    /// Set explicit access/modification timestamps and refresh ctime.
    pub fn set_times(
        &mut self,
        ino: u64,
        atime: Option<VfsTimestamp>,
        mtime: Option<VfsTimestamp>,
    ) -> FsResult<()> {
        let location = self.inode_location(ino)?;
        let mut inode = self.read_inode(ino, location)?;
        if let Some(timestamp) = atime {
            let (sec, nsec) = xfs_rs::InodeCore::unix_to_timestamp(
                timestamp.secs,
                timestamp.nsecs,
                self.superblock.has_bigtime(),
            )?;
            inode.core.atime_sec = sec;
            inode.core.atime_nsec = nsec;
        }
        if let Some(timestamp) = mtime {
            let (sec, nsec) = xfs_rs::InodeCore::unix_to_timestamp(
                timestamp.secs,
                timestamp.nsecs,
                self.superblock.has_bigtime(),
            )?;
            inode.core.mtime_sec = sec;
            inode.core.mtime_nsec = nsec;
        }
        touch_inode(
            &mut inode.core,
            self.superblock.has_bigtime(),
            false,
            false,
            true,
        )?;
        self.commit_inode(ino, location, inode)
    }

    /// Create a regular file, directory, or inline symbolic link.
    pub fn create_inode(
        &mut self,
        parent_ino: u64,
        name: &str,
        mode: u32,
        symlink_target: Option<&[u8]>,
    ) -> FsResult<VfsFileInfo> {
        validate_name(name)?;
        let parent_location = self.inode_location(parent_ino)?;
        let mut parent = self.read_inode(parent_ino, parent_location)?;
        if !parent.core.is_dir() {
            return Err(FsError::NotADirectory);
        }
        if self
            .logical_entries(parent_ino, &parent)?
            .iter()
            .any(|entry| entry.name == name.as_bytes())
        {
            return Err(FsError::AlreadyExists);
        }

        let is_dir = mode & S_IFDIR as u32 != 0;
        let ino = self.inode_allocator.allocate_inode(is_dir)?;
        let location = self.inode_location(ino)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let mut core = xfs_rs::inode_alloc::create_empty_inode_core_at(
            mode as u16,
            parent.core.uid,
            parent.core.gid,
            if self.superblock.is_v5() { 3 } else { 2 },
            ino,
            &self.superblock.metadata_uuid(),
            self.superblock.has_bigtime(),
            i64::try_from(now.as_secs()).map_err(|_| FsError::InvalidArgument)?,
            now.subsec_nanos(),
        )?;
        core.gen = if let Ok(previous) = self.read_inode(ino, location) {
            previous.core.gen.wrapping_add(1)
        } else {
            (now.subsec_nanos() ^ (ino as u32).wrapping_mul(0x9E37_79B9)).max(1)
        };
        if core.gen == 0 {
            core.gen = 1;
        }
        let data_fork = if is_dir {
            core.nlink = 2;
            let header = ShortformHeader {
                count: 0,
                i8count: u8::from(parent_ino > u32::MAX as u64),
                parent: parent_ino,
            };
            DataFork::Local(xfs_rs::dir_write::serialize_shortform_header(
                &header,
                parent_ino > u32::MAX as u64,
            ))
        } else if let Some(target) = symlink_target {
            if target.len() > core.data_fork_size(location.inode_size) {
                return Err(FsError::NotImplemented);
            }
            DataFork::Local(target.to_vec())
        } else {
            DataFork::Local(Vec::new())
        };
        core.size = match &data_fork {
            DataFork::Local(data) => data.len() as u64,
            _ => 0,
        };
        let inode = Inode { core, data_fork };
        let file_type = if is_dir {
            DirFileType::Directory
        } else if symlink_target.is_some() {
            DirFileType::SymbolicLink
        } else {
            DirFileType::RegularFile
        };
        let entry = NewDirEntry::new(name.as_bytes(), ino, file_type);

        let mut batch = WriteBatch::new();
        self.add_directory_entry(&mut batch, parent_ino, parent_location, &mut parent, &entry)?;
        if is_dir {
            parent.core.nlink = parent
                .core
                .nlink
                .checked_add(1)
                .ok_or(FsError::ArithmeticOverflow)?;
        }
        touch_inode(
            &mut parent.core,
            self.superblock.has_bigtime(),
            false,
            true,
            true,
        )?;
        self.stage_inode(&mut batch, parent_ino, parent_location, &parent)?;
        self.stage_inode(&mut batch, ino, location, &inode)?;
        self.commit_batch(&mut batch)?;
        inode_to_file_info(
            ino,
            &inode,
            self.superblock.block_size,
            self.superblock.has_bigtime(),
            self.filesystem_size,
        )
    }

    pub fn create_file(&mut self, parent: u64, name: &str, mode: u32) -> FsResult<VfsFileInfo> {
        self.create_inode(parent, name, (mode & 0o7777) | S_IFREG as u32, None)
    }

    pub fn create_directory(
        &mut self,
        parent: u64,
        name: &str,
        mode: u32,
    ) -> FsResult<VfsFileInfo> {
        self.create_inode(parent, name, (mode & 0o7777) | S_IFDIR as u32, None)
    }

    pub fn create_symlink(
        &mut self,
        parent: u64,
        name: &str,
        target: &str,
    ) -> FsResult<VfsFileInfo> {
        if target.is_empty() || target.len() > 1024 {
            return Err(FsError::InvalidPath);
        }
        self.create_inode(
            parent,
            name,
            0o777 | S_IFLNK as u32,
            Some(target.as_bytes()),
        )
    }

    /// Add a hard link to an existing non-directory inode.
    pub fn link_inode(
        &mut self,
        target_ino: u64,
        parent_ino: u64,
        name: &str,
    ) -> FsResult<VfsFileInfo> {
        validate_name(name)?;
        let target_location = self.inode_location(target_ino)?;
        let mut target = self.read_inode(target_ino, target_location)?;
        if target.core.nlink == 0 {
            return Err(FsError::InodeNotFound);
        }
        if target.core.is_dir() {
            return Err(FsError::PermissionDenied);
        }
        if !target.core.is_file() && !target.core.is_symlink() {
            return Err(FsError::NotSupported);
        }
        let parent_location = self.inode_location(parent_ino)?;
        let mut parent = self.read_inode(parent_ino, parent_location)?;
        if !parent.core.is_dir() {
            return Err(FsError::NotADirectory);
        }
        if self
            .logical_entries(parent_ino, &parent)?
            .iter()
            .any(|entry| entry.name == name.as_bytes())
        {
            return Err(FsError::AlreadyExists);
        }
        let file_type = if target.core.is_symlink() {
            DirFileType::SymbolicLink
        } else {
            DirFileType::RegularFile
        };
        let entry = NewDirEntry::new(name.as_bytes(), target_ino, file_type);
        let mut batch = WriteBatch::new();
        self.add_directory_entry(&mut batch, parent_ino, parent_location, &mut parent, &entry)?;
        target.core.nlink = target
            .core
            .nlink
            .checked_add(1)
            .ok_or(FsError::ArithmeticOverflow)?;
        touch_inode(
            &mut target.core,
            self.superblock.has_bigtime(),
            false,
            false,
            true,
        )?;
        touch_inode(
            &mut parent.core,
            self.superblock.has_bigtime(),
            false,
            true,
            true,
        )?;
        self.stage_inode(&mut batch, target_ino, target_location, &target)?;
        self.stage_inode(&mut batch, parent_ino, parent_location, &parent)?;
        self.commit_batch(&mut batch)?;
        inode_to_file_info(
            target_ino,
            &target,
            self.superblock.block_size,
            self.superblock.has_bigtime(),
            self.filesystem_size,
        )
    }

    /// Remove one directory entry after validating its inode number.
    pub fn unlink_inode(
        &mut self,
        parent_ino: u64,
        name: &str,
        target_ino: u64,
    ) -> FsResult<VfsFileInfo> {
        validate_name(name)?;
        let parent_location = self.inode_location(parent_ino)?;
        let target_location = self.inode_location(target_ino)?;
        let mut parent = self.read_inode(parent_ino, parent_location)?;
        let mut target = self.read_inode(target_ino, target_location)?;
        if !parent.core.is_dir() {
            return Err(FsError::NotADirectory);
        }
        let entry = self
            .logical_entries(parent_ino, &parent)?
            .into_iter()
            .find(|entry| entry.name == name.as_bytes())
            .ok_or(FsError::NotFound)?;
        if entry.inode != target_ino {
            return Err(FsError::InvalidArgument);
        }
        if target.core.is_dir() && !self.logical_entries(target_ino, &target)?.is_empty() {
            return Err(FsError::NotEmpty);
        }

        let mut batch = WriteBatch::new();
        self.remove_directory_entry(&mut batch, parent_ino, &mut parent, name, target_ino)?;
        if target.core.is_dir() {
            target.core.nlink = 0;
            parent.core.nlink = parent.core.nlink.checked_sub(1).ok_or(FsError::Corrupted)?;
        } else {
            target.core.nlink = target.core.nlink.checked_sub(1).ok_or(FsError::Corrupted)?;
        }
        if target.core.nlink == 0 {
            if self.pinned_inodes.contains(&target_ino) {
                let (ag, ag_ino) = self.inode_ag_parts(target_ino)?;
                target.core.next_unlinked =
                    self.inode_allocator.insert_unlinked_inode(ag, ag_ino)?;
            } else {
                self.free_inode_data(&mut target)?;
                self.inode_allocator.free_inode(target_ino)?;
            }
        }
        touch_inode(
            &mut parent.core,
            self.superblock.has_bigtime(),
            false,
            true,
            true,
        )?;
        touch_inode(
            &mut target.core,
            self.superblock.has_bigtime(),
            false,
            false,
            true,
        )?;
        self.stage_inode(&mut batch, parent_ino, parent_location, &parent)?;
        self.stage_inode(&mut batch, target_ino, target_location, &target)?;
        self.commit_batch(&mut batch)?;
        inode_to_file_info(
            target_ino,
            &target,
            self.superblock.block_size,
            self.superblock.has_bigtime(),
            self.filesystem_size,
        )
    }

    /// Reclaim an inode after its final pinned handle is closed. Until then an
    /// unlinked inode keeps its data blocks allocated, matching POSIX open-file
    /// deletion semantics and preventing use-after-free by concurrent readers.
    pub fn reclaim_unlinked_inode(&mut self, ino: u64) -> FsResult<()> {
        let location = self.inode_location(ino)?;
        let mut inode = self.read_inode(ino, location)?;
        if inode.core.nlink != 0 {
            return Ok(());
        }

        // Remove the AGI hash-list entry before releasing any blocks or the
        // inode chunk bitmap. A non-head removal also updates and stages the
        // predecessor in the same transaction.
        let (ag, ag_ino) = self.inode_ag_parts(ino)?;
        let (predecessor, successor) = self.inode_allocator.remove_unlinked_inode(ag, ag_ino)?;
        if inode.core.next_unlinked != successor {
            return Err(FsError::Corrupted);
        }
        inode.core.next_unlinked = u32::MAX;
        let mut batch = WriteBatch::new();
        if let Some(predecessor) = predecessor {
            let predecessor_ino = self.absolute_inode(ag, predecessor)?;
            let predecessor_location = self.inode_location(predecessor_ino)?;
            let mut predecessor_inode = self.read_inode(predecessor_ino, predecessor_location)?;
            if predecessor_inode.core.nlink != 0 {
                return Err(FsError::Corrupted);
            }
            predecessor_inode.core.next_unlinked = successor;
            touch_inode(
                &mut predecessor_inode.core,
                self.superblock.has_bigtime(),
                false,
                false,
                true,
            )?;
            self.stage_inode(
                &mut batch,
                predecessor_ino,
                predecessor_location,
                &predecessor_inode,
            )?;
        }

        self.free_inode_data(&mut inode)?;
        self.inode_allocator.free_inode(ino)?;
        touch_inode(
            &mut inode.core,
            self.superblock.has_bigtime(),
            false,
            false,
            true,
        )?;
        self.stage_inode(&mut batch, ino, location, &inode)?;
        self.commit_batch(&mut batch)
    }

    fn collect_inode_extents(&self, inode: &Inode) -> FsResult<Vec<Extent>> {
        match &inode.data_fork {
            DataFork::Extents(extents) => Ok(extents.clone()),
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                let root = BmbtRoot::parse(data, *level, *num_recs)?;
                let read_block = |block| self.read_block(block);
                let reader = ClosureBlockReader::new(&read_block);
                btree_collect_extents_checked(
                    &root,
                    &reader,
                    self.superblock.is_v5(),
                    inode.core.ino,
                    Some(self.superblock.metadata_uuid()),
                    self.superblock.block_size as usize,
                )
            }
            _ => Err(FsError::NotImplemented),
        }
    }

    fn free_inode_data(&mut self, inode: &mut Inode) -> FsResult<()> {
        if inode.core.anextents != 0 {
            return Err(FsError::NotSupported);
        }
        match &inode.data_fork {
            DataFork::Local(_) | DataFork::Empty | DataFork::Device { .. } => {}
            DataFork::Extents(extents) => {
                for extent in extents {
                    self.free_absolute_extent(extent.start_block, extent.block_count)?;
                }
            }
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                let root = BmbtRoot::parse(data, *level, *num_recs)?;
                let read_block = |block| self.read_block(block);
                let reader = ClosureBlockReader::new(&read_block);
                let extents = btree_collect_extents_checked(
                    &root,
                    &reader,
                    self.superblock.is_v5(),
                    inode.core.ino,
                    Some(self.superblock.metadata_uuid()),
                    self.superblock.block_size as usize,
                )?;
                for extent in extents {
                    self.free_absolute_extent(extent.start_block, extent.block_count)?;
                }
                for block in self.collect_bmbt_blocks(&root, inode.core.ino)? {
                    self.free_absolute_block(block)?;
                }
            }
        }
        inode.core.format = InodeFormat::Extents;
        inode.core.nextents = 0;
        inode.core.nblocks = 0;
        inode.core.size = 0;
        inode.data_fork = DataFork::Extents(Vec::new());
        Ok(())
    }

    fn remove_directory_entry(
        &mut self,
        batch: &mut WriteBatch,
        parent_ino: u64,
        parent: &mut Inode,
        name: &str,
        target_ino: u64,
    ) -> FsResult<()> {
        if self.superblock.dir_block_log != 0 {
            return Err(FsError::NotSupported);
        }
        match parent.data_fork.clone() {
            DataFork::Local(data) => {
                let updated = remove_shortform_entry(
                    &data,
                    name.as_bytes(),
                    self.superblock.is_v5(),
                    self.superblock.has_ftype(),
                )?;
                parent.data_fork = DataFork::Local(updated.clone());
                parent.core.size = updated.len() as u64;
            }
            DataFork::Extents(extents) => {
                if self.superblock.dir_block_log == 0 && extents.len() == 1 {
                    let extent = extents[0];
                    if extent.file_offset != 0 || extent.block_count != 1 {
                        return Err(FsError::Corrupted);
                    }
                    let raw = self.read_block(extent.start_block)?;
                    let directory_parent = Self::block_parent(&raw, self.superblock.has_ftype())?;
                    let updated = remove_block_directory_entry(
                        &raw,
                        name.as_bytes(),
                        target_ino,
                        self.superblock.has_ftype(),
                        parent_ino,
                        directory_parent,
                        self.superblock.block_size as usize,
                        self.superblock.is_v5(),
                        self.superblock.metadata_uuid(),
                        self.disk_address(extent.start_block)?,
                        0,
                    )?;
                    let offset = extent
                        .start_block
                        .checked_mul(u64::from(self.superblock.block_size))
                        .ok_or(FsError::ArithmeticOverflow)?;
                    self.block_overlay
                        .insert(extent.start_block, updated.clone());
                    batch.stage(
                        self.device.as_ref(),
                        offset,
                        updated,
                        MetadataKind::Directory,
                        self.filesystem_size,
                    )?;
                    return Ok(());
                }
                let mut entries = self.logical_entries(parent_ino, parent)?;
                let before = entries.len();
                entries
                    .retain(|entry| !(entry.name == name.as_bytes() && entry.inode == target_ino));
                if entries.len() == before {
                    return Err(FsError::NotFound);
                }
                let location = self.inode_location(parent_ino)?;
                self.rebuild_directory(batch, parent_ino, location, parent, entries)?;
            }
            DataFork::Btree { .. } => {
                let mut entries = self.logical_entries(parent_ino, parent)?;
                let before = entries.len();
                entries
                    .retain(|entry| !(entry.name == name.as_bytes() && entry.inode == target_ino));
                if entries.len() == before {
                    return Err(FsError::NotFound);
                }
                let location = self.inode_location(parent_ino)?;
                self.rebuild_directory(batch, parent_ino, location, parent, entries)?;
            }
            _ => return Err(FsError::NotImplemented),
        }
        Ok(())
    }

    /// Atomically rename a directory entry, optionally replacing an existing
    /// non-directory or empty directory.
    pub fn rename_inode(
        &mut self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        flags: RenameFlags,
    ) -> FsResult<Option<VfsFileInfo>> {
        if flags.exchange {
            return Err(FsError::NotSupported);
        }
        validate_name(old_name)?;
        validate_name(new_name)?;
        if old_parent == new_parent && old_name == new_name {
            return Ok(None);
        }

        let old_location = self.inode_location(old_parent)?;
        let new_location = self.inode_location(new_parent)?;
        let mut old_parent_inode = self.read_inode(old_parent, old_location)?;
        let mut new_parent_inode = if old_parent == new_parent {
            old_parent_inode.clone()
        } else {
            self.read_inode(new_parent, new_location)?
        };
        if !old_parent_inode.core.is_dir() || !new_parent_inode.core.is_dir() {
            return Err(FsError::NotADirectory);
        }
        let source = self
            .logical_entries(old_parent, &old_parent_inode)?
            .into_iter()
            .find(|entry| entry.name == old_name.as_bytes())
            .ok_or(FsError::NotFound)?;
        let target_location = self.inode_location(source.inode)?;
        let mut target = self.read_inode(source.inode, target_location)?;
        let destination = self
            .logical_entries(new_parent, &new_parent_inode)?
            .into_iter()
            .find(|entry| entry.name == new_name.as_bytes());
        if let Some(destination) = &destination {
            if destination.inode == source.inode {
                return Ok(None);
            }
            if flags.no_replace || !flags.replace_if_exists {
                return Err(FsError::AlreadyExists);
            }
        }
        if target.core.is_dir() && self.is_descendant(source.inode, new_parent)? {
            return Err(FsError::InvalidArgument);
        }

        let mut replaced = None;
        if let Some(destination) = destination {
            let destination_location = self.inode_location(destination.inode)?;
            let destination_inode = self.read_inode(destination.inode, destination_location)?;
            if target.core.is_dir() != destination_inode.core.is_dir() {
                return Err(FsError::InvalidArgument);
            }
            if destination_inode.core.is_dir()
                && !self
                    .logical_entries(destination.inode, &destination_inode)?
                    .is_empty()
            {
                return Err(FsError::NotEmpty);
            }
            replaced = Some((destination.inode, destination_location, destination_inode));
        }

        let mut batch = WriteBatch::new();
        self.remove_directory_entry(
            &mut batch,
            old_parent,
            &mut old_parent_inode,
            old_name,
            source.inode,
        )?;
        if old_parent == new_parent {
            new_parent_inode = old_parent_inode.clone();
        }
        if let Some((destination_ino, destination_location, destination_inode)) = &mut replaced {
            self.remove_directory_entry(
                &mut batch,
                new_parent,
                &mut new_parent_inode,
                new_name,
                *destination_ino,
            )?;
            if destination_inode.core.is_dir() {
                destination_inode.core.nlink = 0;
                new_parent_inode.core.nlink = new_parent_inode
                    .core
                    .nlink
                    .checked_sub(1)
                    .ok_or(FsError::Corrupted)?;
            } else {
                destination_inode.core.nlink = destination_inode
                    .core
                    .nlink
                    .checked_sub(1)
                    .ok_or(FsError::Corrupted)?;
            }
            if destination_inode.core.nlink == 0 {
                if self.pinned_inodes.contains(destination_ino) {
                    let (ag, ag_ino) = self.inode_ag_parts(*destination_ino)?;
                    destination_inode.core.next_unlinked =
                        self.inode_allocator.insert_unlinked_inode(ag, ag_ino)?;
                } else {
                    self.free_inode_data(destination_inode)?;
                    self.inode_allocator.free_inode(*destination_ino)?;
                }
            }
            touch_inode(
                &mut destination_inode.core,
                self.superblock.has_bigtime(),
                false,
                false,
                true,
            )?;
            self.stage_inode(
                &mut batch,
                *destination_ino,
                *destination_location,
                destination_inode,
            )?;
        }

        let new_entry = NewDirEntry::new(new_name.as_bytes(), source.inode, source.file_type);
        self.add_directory_entry(
            &mut batch,
            new_parent,
            new_location,
            &mut new_parent_inode,
            &new_entry,
        )?;
        if target.core.is_dir() && old_parent != new_parent {
            old_parent_inode.core.nlink = old_parent_inode
                .core
                .nlink
                .checked_sub(1)
                .ok_or(FsError::Corrupted)?;
            new_parent_inode.core.nlink = new_parent_inode
                .core
                .nlink
                .checked_add(1)
                .ok_or(FsError::ArithmeticOverflow)?;
            self.set_directory_parent(
                &mut batch,
                source.inode,
                target_location,
                &mut target,
                new_parent,
            )?;
        }
        if old_parent == new_parent {
            old_parent_inode = new_parent_inode.clone();
        }
        touch_inode(
            &mut target.core,
            self.superblock.has_bigtime(),
            false,
            false,
            true,
        )?;
        touch_inode(
            &mut old_parent_inode.core,
            self.superblock.has_bigtime(),
            false,
            true,
            true,
        )?;
        self.stage_inode(&mut batch, old_parent, old_location, &old_parent_inode)?;
        self.stage_inode(&mut batch, source.inode, target_location, &target)?;
        if old_parent != new_parent {
            touch_inode(
                &mut new_parent_inode.core,
                self.superblock.has_bigtime(),
                false,
                true,
                true,
            )?;
            self.stage_inode(&mut batch, new_parent, new_location, &new_parent_inode)?;
        }
        self.commit_batch(&mut batch)?;
        match replaced {
            Some((ino, _, inode)) => inode_to_file_info(
                ino,
                &inode,
                self.superblock.block_size,
                self.superblock.has_bigtime(),
                self.filesystem_size,
            )
            .map(Some),
            None => Ok(None),
        }
    }

    fn is_descendant(&self, ancestor: u64, mut inode: u64) -> FsResult<bool> {
        for _ in 0..1024 {
            if inode == ancestor {
                return Ok(true);
            }
            let location = self.inode_location(inode)?;
            let current = self.read_inode(inode, location)?;
            let parent = self.directory_parent_ino(&current)?;
            if parent == inode {
                return Ok(false);
            }
            inode = parent;
        }
        Err(FsError::Corrupted)
    }

    fn directory_parent_ino(&self, inode: &Inode) -> FsResult<u64> {
        match &inode.data_fork {
            DataFork::Local(data) => ShortformHeader::parse(data).map(|header| header.parent),
            DataFork::Extents(_) | DataFork::Btree { .. } => {
                let extents = self.collect_inode_extents(inode)?;
                let block_size = u64::from(self.superblock.block_size);
                for extent in extents {
                    if extent.file_offset.saturating_mul(block_size) >= 1u64 << 35 {
                        continue;
                    }
                    for index in 0..extent.block_count {
                        let raw = self.read_block(
                            extent
                                .start_block
                                .checked_add(u64::from(index))
                                .ok_or(FsError::ArithmeticOverflow)?,
                        )?;
                        let magic = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
                        let is_block = matches!(
                            magic,
                            xfs_rs::constants::XFS_DIR2_BLOCK_MAGIC
                                | xfs_rs::constants::XFS_DIR3_BLOCK_MAGIC
                        );
                        let is_data = matches!(
                            magic,
                            xfs_rs::constants::XFS_DIR2_DATA_MAGIC
                                | xfs_rs::constants::XFS_DIR3_DATA_MAGIC
                        );
                        if !is_block && !is_data {
                            continue;
                        }
                        let iter = xfs_rs::directory::parse_data_block(
                            &raw,
                            self.superblock.has_ftype(),
                            self.superblock.is_v5(),
                            is_block,
                            self.superblock.block_size,
                        )?;
                        for entry in iter {
                            let entry = entry?;
                            if entry.name_bytes() == b".." {
                                return Ok(entry.inode);
                            }
                        }
                    }
                }
                Err(FsError::Corrupted)
            }
            _ => Err(FsError::NotImplemented),
        }
    }

    fn set_directory_parent(
        &mut self,
        batch: &mut WriteBatch,
        ino: u64,
        location: InodeLocation,
        inode: &mut Inode,
        new_parent: u64,
    ) -> FsResult<()> {
        match inode.data_fork.clone() {
            DataFork::Local(data) => {
                let entries = Self::shortform_entries(&data, self.superblock.has_ftype())?;
                let use_64 = new_parent > u32::MAX as u64
                    || entries.iter().any(|entry| entry.inode > u32::MAX as u64);
                let mut rebuilt = xfs_rs::dir_write::serialize_shortform_header(
                    &ShortformHeader {
                        count: 0,
                        i8count: u8::from(use_64),
                        parent: new_parent,
                    },
                    use_64,
                );
                for entry in entries {
                    rebuilt = add_shortform_entry(
                        &rebuilt,
                        &entry,
                        new_parent,
                        self.superblock.is_v5(),
                        self.superblock.has_ftype(),
                        inode.core.data_fork_size(location.inode_size),
                    )?;
                }
                inode.data_fork = DataFork::Local(rebuilt.clone());
                inode.core.size = rebuilt.len() as u64;
            }
            DataFork::Extents(extents) => {
                if self.superblock.dir_block_log != 0 || extents.len() != 1 {
                    let entries = self.logical_entries(ino, inode)?;
                    return self.rebuild_directory_with_parent(
                        batch, ino, location, inode, entries, new_parent,
                    );
                }
                let extent = extents[0];
                let raw = self.read_block(extent.start_block)?;
                let (entries, _) = parse_block_directory(&raw, self.superblock.has_ftype())?;
                let logical: Vec<_> = entries
                    .into_iter()
                    .filter(|entry| entry.name != b"." && entry.name != b"..")
                    .map(|entry| NewDirEntry::new(&entry.name, entry.inode, entry.file_type))
                    .collect();
                let rebuilt = build_block_directory(
                    &logical,
                    ino,
                    new_parent,
                    self.superblock.block_size as usize,
                    self.superblock.is_v5(),
                    self.superblock.has_ftype(),
                    self.superblock.metadata_uuid(),
                    self.disk_address(extent.start_block)?,
                    0,
                )?;
                let offset = extent
                    .start_block
                    .checked_mul(u64::from(self.superblock.block_size))
                    .ok_or(FsError::ArithmeticOverflow)?;
                self.block_overlay
                    .insert(extent.start_block, rebuilt.clone());
                batch.stage(
                    self.device.as_ref(),
                    offset,
                    rebuilt,
                    MetadataKind::Directory,
                    self.filesystem_size,
                )?;
            }
            DataFork::Btree { .. } => {
                let entries = self.logical_entries(ino, inode)?;
                self.rebuild_directory_with_parent(
                    batch, ino, location, inode, entries, new_parent,
                )?;
            }
            _ => return Err(FsError::NotImplemented),
        }
        Ok(())
    }

    fn stage_transaction_metadata(&mut self, batch: &mut WriteBatch) -> FsResult<()> {
        self.allocator.stage(batch)?;
        self.inode_allocator.stage(batch)?;
        self.stage_superblock(batch)?;
        self.dirty_blocks.extend(
            batch
                .buffer_blocks(u64::from(self.superblock.block_size))
                .collect::<Vec<_>>(),
        );
        Ok(())
    }

    pub fn flush_staged_data(&self) -> FsResult<()> {
        self.device.flush().map_err(|_| FsError::DiskError)
    }

    fn commit_batch(&mut self, batch: &mut WriteBatch) -> FsResult<()> {
        self.stage_transaction_metadata(batch)?;
        batch.commit(self.journal)?;
        self.allocator.finish_transaction();
        self.inode_allocator.finish_transaction();
        Ok(())
    }

    /// Commit one already-staged multi-inode delalloc batch with one log force.
    pub fn commit_delalloc_batch(&mut self, batch: &mut WriteBatch) -> FsResult<u64> {
        self.stage_transaction_metadata(batch)?;
        self.flush_staged_data()?;
        let lsn = batch.commit_group(self.journal)?;
        self.allocator.finish_transaction();
        self.inode_allocator.finish_transaction();
        self.data_rollback.clear();
        Ok(lsn)
    }

    fn logical_entries(&self, parent_ino: u64, parent: &Inode) -> FsResult<Vec<NewDirEntry>> {
        let entries = crate::directory::parse_directory_entries(
            parent,
            parent_ino,
            self.superblock.has_ftype(),
            self.superblock.block_size,
            self.superblock.total_blocks,
            self.superblock.is_v5(),
            self,
        )?;
        entries
            .into_iter()
            .map(|entry| {
                Ok(NewDirEntry {
                    name: entry.name.as_bytes().to_vec(),
                    inode: entry.ino,
                    file_type: match entry.file_type {
                        fs_abstraction::VfsFileType::RegularFile => DirFileType::RegularFile,
                        fs_abstraction::VfsFileType::Directory => DirFileType::Directory,
                        fs_abstraction::VfsFileType::Symlink => DirFileType::SymbolicLink,
                        fs_abstraction::VfsFileType::BlockDevice => DirFileType::BlockDevice,
                        fs_abstraction::VfsFileType::CharDevice => DirFileType::CharDevice,
                        fs_abstraction::VfsFileType::Fifo => DirFileType::Fifo,
                        fs_abstraction::VfsFileType::Socket => DirFileType::Socket,
                        // v4 directories store no ftype byte.
                        fs_abstraction::VfsFileType::Unknown => DirFileType::Unknown,
                    },
                })
            })
            .collect::<FsResult<Vec<_>>>()
    }

    fn rebuild_directory(
        &mut self,
        batch: &mut WriteBatch,
        ino: u64,
        location: InodeLocation,
        inode: &mut Inode,
        entries: Vec<NewDirEntry>,
    ) -> FsResult<()> {
        let parent = self.directory_parent_ino(inode)?;
        self.rebuild_directory_with_parent(batch, ino, location, inode, entries, parent)
    }

    fn rebuild_directory_with_parent(
        &mut self,
        batch: &mut WriteBatch,
        ino: u64,
        location: InodeLocation,
        inode: &mut Inode,
        entries: Vec<NewDirEntry>,
        parent: u64,
    ) -> FsResult<()> {
        if self.superblock.dir_block_log != 0 {
            return Err(FsError::NotSupported);
        }
        let block_size = self.superblock.block_size as usize;
        let block_size_u64 = u64::from(self.superblock.block_size);
        let data_count = leaf_directory_data_block_count(
            &entries,
            ino,
            parent,
            block_size,
            self.superblock.is_v5(),
            self.superblock.has_ftype(),
        )?;
        let leaf_offset = (1u64 << 35) / block_size_u64;
        let free_offset = (1u64 << 36) / block_size_u64;
        let all_count = entries
            .len()
            .checked_add(2)
            .ok_or(FsError::ArithmeticOverflow)?;
        let leaf1_capacity =
            leaf1_record_capacity(block_size, self.superblock.is_v5(), data_count)?;

        let (total, new_blocks, data_blocks, metadata_blocks, metadata_offsets) =
            if all_count <= leaf1_capacity {
                let total = data_count
                    .checked_add(1)
                    .ok_or(FsError::ArithmeticOverflow)?;
                let mut new_blocks = Vec::with_capacity(total);
                for _ in 0..total {
                    new_blocks.push(
                        self.allocator
                            .allocate_blocks(1)?
                            .to_absolute_block(self.superblock.ag_blocks)?,
                    );
                }
                let addresses: Vec<u64> = new_blocks
                    .iter()
                    .map(|block| self.disk_address(*block))
                    .collect::<FsResult<_>>()?;
                let build = build_leaf_directory(
                    &entries,
                    ino,
                    parent,
                    block_size,
                    self.superblock.is_v5(),
                    self.superblock.has_ftype(),
                    self.superblock.metadata_uuid(),
                    &addresses,
                    0,
                )?;
                (
                    total,
                    new_blocks,
                    build.data_blocks,
                    vec![build.leaf_block],
                    vec![leaf_offset],
                )
            } else {
                let leaf_capacity = leaf_node_record_capacity(block_size, self.superblock.is_v5())?;
                if leaf_capacity == 0 {
                    return Err(FsError::NotSupported);
                }
                let leaf_count = all_count
                    .checked_add(leaf_capacity - 1)
                    .ok_or(FsError::ArithmeticOverflow)?
                    / leaf_capacity;
                let total = data_count
                    .checked_add(leaf_count)
                    .and_then(|value| value.checked_add(2))
                    .ok_or(FsError::ArithmeticOverflow)?;
                let mut new_blocks = Vec::with_capacity(total);
                for _ in 0..total {
                    new_blocks.push(
                        self.allocator
                            .allocate_blocks(1)?
                            .to_absolute_block(self.superblock.ag_blocks)?,
                    );
                }
                let addresses: Vec<u64> = new_blocks
                    .iter()
                    .map(|block| self.disk_address(*block))
                    .collect::<FsResult<_>>()?;
                let build = build_node_directory(
                    &entries,
                    ino,
                    parent,
                    block_size,
                    self.superblock.is_v5(),
                    self.superblock.has_ftype(),
                    self.superblock.metadata_uuid(),
                    &addresses,
                    0,
                )?;
                let mut metadata_blocks = build.leaf_blocks;
                metadata_blocks.push(build.root_block);
                metadata_blocks.push(build.free_block);
                let mut metadata_offsets = Vec::with_capacity(metadata_blocks.len());
                metadata_offsets.extend((1..=leaf_count).map(|index| leaf_offset + index as u64));
                metadata_offsets.push(leaf_offset);
                metadata_offsets.push(free_offset);
                (
                    total,
                    new_blocks,
                    build.data_blocks,
                    metadata_blocks,
                    metadata_offsets,
                )
            };

        let old_extents = match &inode.data_fork {
            DataFork::Local(_) | DataFork::Empty => Vec::new(),
            DataFork::Extents(_) | DataFork::Btree { .. } => self.collect_inode_extents(inode)?,
            _ => return Err(FsError::NotSupported),
        };
        for extent in &old_extents {
            self.free_absolute_extent(extent.start_block, extent.block_count)?;
        }

        let buffers = data_blocks
            .into_iter()
            .chain(metadata_blocks)
            .collect::<Vec<_>>();
        let mut logical_offsets = (0..data_count as u64).collect::<Vec<_>>();
        logical_offsets.extend(metadata_offsets);
        let mut new_extents = Vec::with_capacity(total);
        for ((block, raw), logical) in new_blocks.into_iter().zip(buffers).zip(logical_offsets) {
            let offset = block
                .checked_mul(block_size_u64)
                .ok_or(FsError::ArithmeticOverflow)?;
            self.block_overlay.insert(block, raw.clone());
            batch.stage(
                self.device.as_ref(),
                offset,
                raw,
                MetadataKind::Directory,
                self.filesystem_size,
            )?;
            new_extents.push(Extent {
                file_offset: logical,
                start_block: block,
                block_count: 1,
                is_unwritten: false,
            });
        }
        coalesce_extents(&mut new_extents)?;
        self.rebuild_data_fork(ino, inode, new_extents, location.inode_size, batch)?;
        inode.core.size = u64::try_from(data_count)
            .ok()
            .and_then(|blocks| blocks.checked_mul(block_size_u64))
            .ok_or(FsError::ArithmeticOverflow)?;
        Ok(())
    }

    fn add_directory_entry(
        &mut self,
        batch: &mut WriteBatch,
        parent_ino: u64,
        location: InodeLocation,
        parent: &mut Inode,
        entry: &NewDirEntry,
    ) -> FsResult<()> {
        if self.superblock.dir_block_log != 0 {
            return Err(FsError::NotSupported);
        }
        match parent.data_fork.clone() {
            DataFork::Local(data) => {
                let fork_size = parent.core.data_fork_size(location.inode_size);
                match add_shortform_entry(
                    &data,
                    entry,
                    parent_ino,
                    self.superblock.is_v5(),
                    self.superblock.has_ftype(),
                    fork_size,
                ) {
                    Ok(updated) => {
                        parent.data_fork = DataFork::Local(updated.clone());
                        parent.core.size = updated.len() as u64;
                        Ok(())
                    }
                    Err(FsError::NoSpace) => {
                        let mut entries =
                            Self::shortform_entries(&data, self.superblock.has_ftype())?;
                        entries.push(entry.clone());
                        let directory_parent = ShortformHeader::parse(&data)?.parent;
                        let probe = build_block_directory(
                            &entries,
                            parent_ino,
                            directory_parent,
                            self.superblock.block_size as usize,
                            self.superblock.is_v5(),
                            self.superblock.has_ftype(),
                            self.superblock.metadata_uuid(),
                            0,
                            0,
                        );
                        let allocated_absolute;
                        let raw = match probe {
                            Ok(_) => {
                                let block = self.allocator.allocate_blocks(1)?;
                                let absolute =
                                    block.to_absolute_block(self.superblock.ag_blocks)?;
                                allocated_absolute = Some(absolute);
                                build_block_directory(
                                    &entries,
                                    parent_ino,
                                    directory_parent,
                                    self.superblock.block_size as usize,
                                    self.superblock.is_v5(),
                                    self.superblock.has_ftype(),
                                    self.superblock.metadata_uuid(),
                                    self.disk_address(absolute)?,
                                    0,
                                )?
                            }
                            Err(FsError::NoSpace) => {
                                return self.rebuild_directory(
                                    batch, parent_ino, location, parent, entries,
                                );
                            }
                            Err(error) => return Err(error),
                        };
                        let absolute = allocated_absolute.ok_or(FsError::Corrupted)?;
                        let offset = absolute
                            .checked_mul(u64::from(self.superblock.block_size))
                            .ok_or(FsError::ArithmeticOverflow)?;
                        self.block_overlay.insert(absolute, raw.clone());
                        batch.stage(
                            self.device.as_ref(),
                            offset,
                            raw,
                            MetadataKind::Directory,
                            self.filesystem_size,
                        )?;
                        parent.core.format = InodeFormat::Extents;
                        parent.core.size = u64::from(self.superblock.block_size);
                        parent.core.nextents = 1;
                        parent.core.nblocks =
                            nblocks_from_fs_blocks(1, self.superblock.block_size)?;
                        parent.data_fork = DataFork::Extents(vec![Extent {
                            file_offset: 0,
                            start_block: absolute,
                            block_count: 1,
                            is_unwritten: false,
                        }]);
                        Ok(())
                    }
                    Err(error) => Err(error),
                }
            }
            DataFork::Extents(extents) => {
                if self.superblock.dir_block_log == 0 && extents.len() == 1 {
                    let extent = extents[0];
                    if extent.file_offset != 0 || extent.block_count != 1 {
                        return Err(FsError::Corrupted);
                    }
                    let raw = self.read_block(extent.start_block)?;
                    let directory_parent = Self::block_parent(&raw, self.superblock.has_ftype())?;
                    match add_block_directory_entry(
                        &raw,
                        entry,
                        self.superblock.has_ftype(),
                        parent_ino,
                        directory_parent,
                        self.superblock.block_size as usize,
                        self.superblock.is_v5(),
                        self.superblock.metadata_uuid(),
                        self.disk_address(extent.start_block)?,
                        0,
                    ) {
                        Ok(updated) => {
                            let offset = extent
                                .start_block
                                .checked_mul(u64::from(self.superblock.block_size))
                                .ok_or(FsError::ArithmeticOverflow)?;
                            self.block_overlay
                                .insert(extent.start_block, updated.clone());
                            batch.stage(
                                self.device.as_ref(),
                                offset,
                                updated,
                                MetadataKind::Directory,
                                self.filesystem_size,
                            )?;
                            return Ok(());
                        }
                        Err(FsError::NoSpace) => {}
                        Err(error) => return Err(error),
                    }
                }
                let mut entries = self.logical_entries(parent_ino, parent)?;
                entries.push(entry.clone());
                self.rebuild_directory(batch, parent_ino, location, parent, entries)
            }
            DataFork::Btree { .. } => {
                let mut entries = self.logical_entries(parent_ino, parent)?;
                entries.push(entry.clone());
                self.rebuild_directory(batch, parent_ino, location, parent, entries)
            }
            _ => Err(FsError::NotImplemented),
        }
    }

    fn shortform_entries(data: &[u8], has_ftype: bool) -> FsResult<Vec<NewDirEntry>> {
        let (_, iter) = xfs_rs::directory::parse_shortform_directory(data, has_ftype)?;
        iter.map(|entry| {
            let entry = entry?;
            Ok(NewDirEntry::new(
                entry.name_bytes(),
                entry.inode,
                entry.file_type,
            ))
        })
        .collect()
    }

    fn block_parent(data: &[u8], has_ftype: bool) -> FsResult<u64> {
        let (entries, _) = parse_block_directory(data, has_ftype)?;
        entries
            .iter()
            .find(|entry| entry.name == b"..")
            .map(|entry| entry.inode)
            .ok_or(FsError::Corrupted)
    }

    fn disk_address(&self, block: u64) -> FsResult<u64> {
        block
            .checked_mul(u64::from(self.superblock.block_size))
            .and_then(|bytes| bytes.checked_div(u64::from(self.superblock.sector_size)))
            .ok_or(FsError::ArithmeticOverflow)
    }

    fn free_absolute_extent(&mut self, start: u64, count: u32) -> FsResult<()> {
        let extent = crate::allocator::FreeExtent::from_absolute_block(
            start,
            count,
            self.superblock.ag_blocks,
        )?;
        self.allocator.free_blocks(extent)
    }

    fn rebuild_data_fork(
        &mut self,
        ino: u64,
        inode: &mut Inode,
        extents: Vec<Extent>,
        inode_size: usize,
        batch: &mut WriteBatch,
    ) -> FsResult<()> {
        let block_size = u64::from(self.superblock.block_size);
        let fork_size = inode.core.data_fork_size(inode_size);
        let btree_blocks = if extents.len().saturating_mul(Extent::SIZE) <= fork_size {
            if let DataFork::Btree {
                level,
                num_recs,
                data,
            } = &inode.data_fork
            {
                let root = BmbtRoot::parse(data, *level, *num_recs)?;
                for block in self.collect_bmbt_blocks(&root, ino)? {
                    self.free_absolute_block(block)?;
                }
            }
            inode.core.format = InodeFormat::Extents;
            inode.data_fork = DataFork::Extents(extents.clone());
            0u64
        } else {
            let existing = match &inode.data_fork {
                DataFork::Btree {
                    level,
                    num_recs,
                    data,
                } => {
                    let root = BmbtRoot::parse(data, *level, *num_recs)?;
                    self.collect_bmbt_blocks(&root, ino)?
                }
                _ => Vec::new(),
            };
            let required = required_block_count(
                extents.len(),
                self.superblock.block_size as usize,
                self.superblock.is_v5(),
            )?;
            let mut extra = Vec::new();
            for _ in existing.len()..required {
                extra.push(
                    self.allocator
                        .allocate_blocks(1)?
                        .to_absolute_block(self.superblock.ag_blocks)?,
                );
            }
            let plan = plan_bmbt(
                &extents,
                &existing,
                &extra,
                fork_size,
                ino,
                self.superblock.metadata_uuid(),
                self.superblock.block_size as usize,
                self.superblock.sector_size as usize,
                self.superblock.is_v5(),
                0,
            )?;
            let used: std::collections::BTreeSet<_> = plan.blocks.iter().copied().collect();
            for block in existing
                .into_iter()
                .chain(extra)
                .filter(|block| !used.contains(block))
            {
                self.free_absolute_block(block)?;
            }
            for (block, buffer) in plan.blocks.iter().copied().zip(&plan.buffers) {
                let offset = block
                    .checked_mul(block_size)
                    .ok_or(FsError::ArithmeticOverflow)?;
                batch.stage(
                    self.device.as_ref(),
                    offset,
                    buffer.clone(),
                    MetadataKind::Btree,
                    self.filesystem_size,
                )?;
            }
            inode.core.format = InodeFormat::Btree;
            inode.data_fork = DataFork::Btree {
                level: plan.root_level,
                num_recs: plan.root_num_records,
                data: plan.root_data,
            };
            plan.blocks.len() as u64
        };

        let data_blocks = extents.iter().try_fold(0u64, |sum, extent| {
            sum.checked_add(u64::from(extent.block_count))
                .ok_or(FsError::ArithmeticOverflow)
        })?;
        inode.core.nextents = u32::try_from(extents.len()).map_err(|_| FsError::FileTooLarge)?;
        inode.core.nblocks = nblocks_from_fs_blocks(
            data_blocks
                .checked_add(btree_blocks)
                .ok_or(FsError::ArithmeticOverflow)?,
            self.superblock.block_size,
        )?;
        Ok(())
    }

    fn stage_superblock(&mut self, batch: &mut WriteBatch) -> FsResult<()> {
        let blocks_delta = self.allocator.free_block_delta();
        let inodes_delta = self.inode_allocator.free_inode_delta();
        let allocated_inodes_delta = self.inode_allocator.inode_count_delta();
        if blocks_delta == 0 && inodes_delta == 0 && allocated_inodes_delta == 0 {
            return Ok(());
        }
        let mut raw = vec![0u8; self.superblock.sector_size as usize];
        read_exact_at(self.device.as_ref(), 0, &mut raw, self.filesystem_size)?;
        let mut sb = Superblock::parse(&raw).map_err(|_| FsError::Corrupted)?;
        if sb.is_v5() {
            sb.verify_crc(&raw)?;
        }
        let free_blocks = i128::from(sb.free_blocks) + blocks_delta;
        let free_inodes = i128::from(sb.free_inodes) + inodes_delta;
        let allocated_inodes = i128::from(sb.inode_count) + allocated_inodes_delta;
        let total_inodes = total_inode_count(&sb)?;
        if free_blocks < 0
            || free_blocks > i128::from(sb.total_blocks)
            || free_inodes < 0
            || allocated_inodes < 0
            || allocated_inodes > i128::from(total_inodes)
            || free_inodes > i128::from(total_inodes) - allocated_inodes
        {
            return Err(FsError::Corrupted);
        }
        sb.free_blocks = u64::try_from(free_blocks).map_err(|_| FsError::Corrupted)?;
        sb.free_inodes = u64::try_from(free_inodes).map_err(|_| FsError::Corrupted)?;
        sb.inode_count = u64::try_from(allocated_inodes).map_err(|_| FsError::Corrupted)?;
        let raw = sb.apply_to_sector(&raw)?;
        batch.stage(
            self.device.as_ref(),
            0,
            raw,
            MetadataKind::Superblock,
            self.filesystem_size,
        )?;
        self.superblock = sb;
        Ok(())
    }

    fn free_absolute_block(&mut self, block: u64) -> FsResult<()> {
        let extent =
            crate::allocator::FreeExtent::from_absolute_block(block, 1, self.superblock.ag_blocks)?;
        self.allocator.free_blocks(extent)
    }

    fn commit_inode(&mut self, ino: u64, location: InodeLocation, inode: Inode) -> FsResult<()> {
        self.commit_inode_with_batch(ino, location, inode, WriteBatch::new())
            .map(|_| ())
    }

    fn commit_inode_with_batch(
        &mut self,
        ino: u64,
        location: InodeLocation,
        mut inode: Inode,
        mut batch: WriteBatch,
    ) -> FsResult<VfsFileInfo> {
        touch_inode(
            &mut inode.core,
            self.superblock.has_bigtime(),
            false,
            true,
            true,
        )?;
        let info = inode_to_file_info(
            ino,
            &inode,
            self.superblock.block_size,
            self.superblock.has_bigtime(),
            self.filesystem_size,
        )?;
        self.stage_inode(&mut batch, ino, location, &inode)?;
        self.allocator.stage(&mut batch)?;
        self.inode_allocator.stage(&mut batch)?;
        self.stage_superblock(&mut batch)?;
        self.dirty_blocks.extend(
            batch
                .buffer_blocks(u64::from(self.superblock.block_size))
                .collect::<Vec<_>>(),
        );
        batch.commit(self.journal)?;
        self.allocator.finish_transaction();
        self.inode_allocator.finish_transaction();
        Ok(info)
    }

    fn allocate_extents(&mut self, file_offset: u64, blocks: u64) -> FsResult<Vec<Extent>> {
        let mut extents = Vec::new();
        let mut current = file_offset;
        let mut remaining = blocks;
        while remaining != 0 {
            let count = remaining.min(0x001F_FFFF).min(u32::MAX as u64) as u32;
            let allocation = self.allocator.allocate_blocks(count)?;
            extents.push(Extent {
                file_offset: current,
                start_block: allocation.to_absolute_block(self.superblock.ag_blocks)?,
                block_count: allocation.block_count,
                is_unwritten: false,
            });
            current = current
                .checked_add(u64::from(allocation.block_count))
                .ok_or(FsError::ArithmeticOverflow)?;
            remaining -= u64::from(allocation.block_count);
        }
        Ok(extents)
    }

    fn write_data_block(&mut self, block: u64, data: &[u8]) -> FsResult<()> {
        let block_size = self.superblock.block_size as usize;
        if data.is_empty() || !data.len().is_multiple_of(block_size) {
            return Err(FsError::InvalidArgument);
        }
        let offset = block
            .checked_mul(u64::from(self.superblock.block_size))
            .ok_or(FsError::ArithmeticOverflow)?;
        if !self.data_rollback.contains_key(&block) {
            let original = self.read_block(block)?;
            self.data_rollback.insert(block, original);
        }
        write_exact_at(self.device.as_ref(), offset, data, self.filesystem_size)
    }

    fn collect_bmbt_blocks(&self, root: &BmbtRoot, owner: u64) -> FsResult<Vec<u64>> {
        let mut blocks = Vec::new();
        for ptr in &root.ptrs {
            self.collect_bmbt_node(ptr.block, root.level, owner, &mut blocks)?;
        }
        Ok(blocks)
    }

    fn collect_bmbt_node(
        &self,
        block: u64,
        level: u16,
        owner: u64,
        output: &mut Vec<u64>,
    ) -> FsResult<()> {
        if !output.iter().all(|seen| *seen != block) || output.len() > 1 << 20 {
            return Err(FsError::Corrupted);
        }
        output.push(block);
        let raw = self.read_block(block)?;
        let header = BtreeBlockLong::parse(&raw, self.superblock.is_v5())?;
        header.verify_metadata(
            &raw,
            block,
            raw.len(),
            Some(owner),
            Some(self.superblock.metadata_uuid()),
        )?;
        if header.level.checked_add(1) != Some(level) {
            return Err(FsError::Corrupted);
        }
        if !header.is_leaf() {
            let ptrs_offset = header.ptrs_offset(raw.len())?;
            for index in 0..header.num_recs as usize {
                let offset = ptrs_offset + index * 8;
                let bytes = raw.get(offset..offset + 8).ok_or(FsError::Corrupted)?;
                let ptr = u64::from_be_bytes(bytes.try_into().map_err(|_| FsError::Corrupted)?);
                self.collect_bmbt_node(ptr, header.level, owner, output)?;
            }
        }
        Ok(())
    }

    pub fn read_block(&self, block: u64) -> FsResult<Vec<u8>> {
        if let Some(raw) = self.block_overlay.get(&block) {
            return Ok(raw.clone());
        }
        if block >= self.superblock.total_blocks {
            return Err(FsError::Corrupted);
        }
        let block_size =
            usize::try_from(self.superblock.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        let offset = block
            .checked_mul(u64::from(self.superblock.block_size))
            .ok_or(FsError::ArithmeticOverflow)?;
        let mut raw = vec![0u8; block_size];
        read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
        Ok(raw)
    }

    fn inode_ag_parts(&self, ino: u64) -> FsResult<(u32, u32)> {
        let shift = u32::from(self.superblock.ag_block_log)
            + u32::from(self.superblock.inode_per_block_log);
        if shift >= 32 {
            return Err(FsError::Corrupted);
        }
        let ag = ino >> shift;
        if ag >= u64::from(self.superblock.ag_count) {
            return Err(FsError::InodeNotFound);
        }
        let ag_ino = ino & ((1u64 << shift) - 1);
        let ag_ino = u32::try_from(ag_ino).map_err(|_| FsError::InodeNotFound)?;
        Ok((ag as u32, ag_ino))
    }

    fn absolute_inode(&self, ag: u32, ag_ino: u32) -> FsResult<u64> {
        if ag >= self.superblock.ag_count {
            return Err(FsError::InodeNotFound);
        }
        let shift = u32::from(self.superblock.ag_block_log)
            + u32::from(self.superblock.inode_per_block_log);
        if shift >= 32 || u64::from(ag_ino) >= (1u64 << shift) {
            return Err(FsError::InodeNotFound);
        }
        Ok((u64::from(ag) << shift) | u64::from(ag_ino))
    }

    fn inode_location(&self, ino: u64) -> FsResult<InodeLocation> {
        let sb = &self.superblock;
        let shift = u32::from(sb.ag_block_log) + u32::from(sb.inode_per_block_log);
        if shift >= 64 {
            return Err(FsError::Corrupted);
        }
        let ag = ino >> shift;
        if ag >= u64::from(sb.ag_count) {
            return Err(FsError::InodeNotFound);
        }
        let ag_ino = ino & ((1u64 << shift) - 1);
        let block_in_ag = ag_ino >> sb.inode_per_block_log;
        let inode_in_block = ag_ino & ((1u64 << sb.inode_per_block_log) - 1);
        let inode_size = sb.inode_size as usize;
        let offset_in_block = inode_in_block
            .checked_mul(inode_size as u64)
            .ok_or(FsError::ArithmeticOverflow)?;
        let block_num = ag
            .checked_mul(u64::from(sb.ag_blocks))
            .and_then(|value| value.checked_add(block_in_ag))
            .ok_or(FsError::ArithmeticOverflow)?;
        if block_num >= sb.total_blocks {
            return Err(FsError::InodeNotFound);
        }
        let block_offset = block_num
            .checked_mul(u64::from(sb.block_size))
            .ok_or(FsError::ArithmeticOverflow)?;
        Ok(InodeLocation {
            block_offset,
            offset_in_block: usize::try_from(offset_in_block)
                .map_err(|_| FsError::ArithmeticOverflow)?,
            inode_size,
        })
    }

    fn read_inode(&self, ino: u64, location: InodeLocation) -> FsResult<Inode> {
        if let Some(inode) = self.staged_inodes.get(&ino) {
            return Ok(inode.clone());
        }
        let block =
            self.read_block(location.block_offset / u64::from(self.superblock.block_size))?;
        let end = location
            .offset_in_block
            .checked_add(location.inode_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        let raw = block
            .get(location.offset_in_block..end)
            .ok_or(FsError::Corrupted)?;
        let inode = Inode::parse(raw, location.inode_size).map_err(|_| FsError::Corrupted)?;
        if self.superblock.is_v5() {
            inode.verify_crc(raw, location.inode_size)?;
            if inode.core.version >= 3 && inode.core.ino != ino {
                return Err(FsError::Corrupted);
            }
            if inode.core.uuid != self.superblock.metadata_uuid() {
                return Err(FsError::Corrupted);
            }
        }
        Ok(inode)
    }

    fn stage_inode(
        &mut self,
        batch: &mut WriteBatch,
        ino: u64,
        location: InodeLocation,
        inode: &Inode,
    ) -> FsResult<()> {
        if inode.core.version >= 3 && inode.core.ino != ino {
            return Err(FsError::InvalidArgument);
        }
        self.dirty_inodes.insert(ino);
        if inode.core.is_dir() {
            self.dirty_directories.insert(ino);
        }
        let serialized = serialize_inode(inode, location.inode_size)?;
        let mut block = batch.read_buffer(
            self.device.as_ref(),
            location.block_offset,
            self.superblock.block_size as usize,
            self.filesystem_size,
        )?;
        let prefix_len = inode
            .core
            .data_fork_offset()
            .checked_add(inode.core.data_fork_size(location.inode_size))
            .ok_or(FsError::ArithmeticOverflow)?;
        let end = location
            .offset_in_block
            .checked_add(prefix_len)
            .ok_or(FsError::ArithmeticOverflow)?;
        block[location.offset_in_block..end].copy_from_slice(&serialized[..prefix_len]);
        if inode.core.version == 3 {
            let inode_end = location
                .offset_in_block
                .checked_add(location.inode_size)
                .ok_or(FsError::ArithmeticOverflow)?;
            xfs_rs::crc::recalculate_crc_le(&mut block[location.offset_in_block..inode_end], 0x64)
                .ok_or(FsError::BufferTooSmall)?;
        }
        batch.stage(
            self.device.as_ref(),
            location.block_offset,
            block,
            MetadataKind::Inode,
            self.filesystem_size,
        )?;
        let block_size = u64::from(self.superblock.block_size);
        if location.block_offset % 512 != 0 || block_size % 512 != 0 {
            return Err(FsError::Corrupted);
        }
        batch.add_inode(xfs_rs::log_format::LogInodeItem::from_inode(
            inode,
            ino,
            location.block_offset / 512,
            u32::try_from(block_size / 512).map_err(|_| FsError::FileTooLarge)?,
            u32::try_from(location.offset_in_block).map_err(|_| FsError::FileTooLarge)?,
            location.inode_size,
            self.journal.current_lsn(),
        )?);
        self.staged_inodes.insert(ino, inode.clone());
        Ok(())
    }
}

fn total_inode_count(sb: &Superblock) -> FsResult<u64> {
    let shift = u32::from(sb.ag_block_log) + u32::from(sb.inode_per_block_log);
    if shift >= 64 {
        return Err(FsError::Corrupted);
    }
    let per_ag = 1u64.checked_shl(shift).ok_or(FsError::ArithmeticOverflow)?;
    u64::from(sb.ag_count)
        .checked_mul(per_ag)
        .ok_or(FsError::ArithmeticOverflow)
}

fn validate_name(name: &str) -> FsResult<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.len() > 255
        || name
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, 0 | b'/' | b'\\'))
    {
        return Err(FsError::InvalidPath);
    }
    Ok(())
}

fn coalesce_extents(extents: &mut Vec<Extent>) -> FsResult<()> {
    extents.sort_by_key(|extent| extent.file_offset);
    let mut merged: Vec<Extent> = Vec::with_capacity(extents.len());
    for extent in extents.drain(..) {
        if extent.block_count == 0 {
            return Err(FsError::Corrupted);
        }
        if let Some(last) = merged.last_mut() {
            if extent.file_offset < last.file_end()? {
                return Err(FsError::Corrupted);
            }
            if extent.file_offset == last.file_end()?
                && extent.start_block == last.disk_end()?
                && extent.is_unwritten == last.is_unwritten
                && u64::from(last.block_count) + u64::from(extent.block_count) <= 0x001F_FFFF
            {
                last.block_count += extent.block_count;
                continue;
            }
        }
        merged.push(extent);
    }
    *extents = merged;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delalloc_budget_is_bounded_and_overwrites_do_not_allocate() {
        let budget = DelallocBudget::with_capacity(128);
        let mut pending = PendingWrites::default();
        pending
            .write(0, &[0x11; 64], 64, 0, &budget, |_| unreachable!())
            .unwrap();
        assert_eq!(budget.available(), 64);
        pending
            .write(64, &[0x22; 64], 64, 64, &budget, |_| unreachable!())
            .unwrap();
        assert_eq!(budget.available(), 0);
        assert!(matches!(
            pending.write(128, &[0x33; 64], 64, 128, &budget, |_| unreachable!()),
            Err(FsError::OutOfMemory)
        ));
        assert_eq!(pending.size(), 128);
        assert_eq!(pending.memory_bytes(64), 128);

        pending
            .write(0, &[0x44; 64], 64, 128, &budget, |_| unreachable!())
            .unwrap();
        assert_eq!(budget.available(), 0);
        let mut read = [0u8; 128];
        pending.overlay_read(0, &mut read, 64);
        assert_eq!(&read[..64], &[0x44; 64]);
        assert_eq!(&read[64..], &[0x22; 64]);
    }

    #[test]
    fn failed_multi_block_write_restores_prior_blocks_and_budget() {
        let budget = DelallocBudget::with_capacity(256);
        let mut pending = PendingWrites::default();
        pending
            .write(0, &[0x11; 64], 64, 0, &budget, |_| unreachable!())
            .unwrap();
        let available = budget.available();
        let result = pending.write(0, &[0x99; 65], 64, 64, &budget, |file_block| {
            if file_block == 1 {
                Err(FsError::DiskError)
            } else {
                Ok(vec![0xAA; 64])
            }
        });
        assert!(matches!(result, Err(FsError::DiskError)));
        assert_eq!(budget.available(), available);
        assert_eq!(pending.memory_bytes(64), 64);
        assert_eq!(pending.size(), 64);
        let mut read = [0u8; 64];
        pending.overlay_read(0, &mut read, 64);
        assert_eq!(read, [0x11; 64]);
    }

    #[test]
    fn partial_delalloc_write_preserves_disk_bytes_and_zeroes_holes() {
        let budget = DelallocBudget::with_capacity(128);
        let mut pending = PendingWrites {
            size: 64,
            ..PendingWrites::default()
        };
        pending
            .write(3, b"XY", 64, 64, &budget, |_| Ok(vec![0xAA; 64]))
            .unwrap();
        let mut read = [0u8; 8];
        pending.overlay_read(0, &mut read, 64);
        assert_eq!(read, [0xAA, 0xAA, 0xAA, b'X', b'Y', 0xAA, 0xAA, 0xAA]);
    }
}
