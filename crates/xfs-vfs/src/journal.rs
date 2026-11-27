//! XFS internal-log v2 transactions and recovery.
//!
//! Records are encoded with the real 512-byte `xlog_rec_header`, native-endian
//! transaction/item descriptors, cycle stamps, and CRC32C. A commit is durable
//! only after the log record has been flushed; metadata is applied afterwards.
//! Recovery replays complete committed buffer and inode records and stops at a
//! clean unmount record. The tail advances after every successful metadata
//! flush, so already-durable records are not replayed over later data reuse.

use std::{collections::BTreeMap, sync::Arc};

use fs_abstraction::{BlockDevice, FsError, FsResult};
use xfs_rs::{
    log_format::{
        decode_record,
        decode_record_header,
        encode_transaction,
        encode_unmount_record,
        LogBufferItem,
        LogRecordHeader,
        LogTransaction,
        XLOG_FMT_LINUX_BE,
        XLOG_FMT_LINUX_LE,
        XLOG_HEADER_MAGIC,
        XLOG_HEADER_SIZE,
        XLOG_VERSION_2,
    },
    Superblock,
};

use crate::{
    io::{read_exact_at, write_exact_at},
    transaction::PreparedTransaction,
};

const BASIC_BLOCK_SIZE: u64 = 512;
const DEFAULT_ICLOG_SIZE: u32 = 32 * 1024;
/// Largest log record this implementation understands: one 32 KiB in-core log
/// buffer plus the 512-byte record header.
const MAX_RECORD_BYTES: u32 = XLOG_HEADER_SIZE as u32 + DEFAULT_ICLOG_SIZE;

#[derive(Debug)]
struct PositionedRecord {
    block: u32,
    header: LogRecordHeader,
    decoded: Option<xfs_rs::log_format::DecodedLogRecord>,
}

/// Manages the single internal XFS log.
#[allow(dead_code)]
pub(crate) struct Journal {
    device: Arc<dyn BlockDevice>,
    superblock: Superblock,
    filesystem_size: u64,
    log_start_bytes: u64,
    log_size_bytes: u64,
    log_basic_blocks: u32,
    cycle: u32,
    head_block: u32,
    prev_block: u32,
    tail_lsn: u64,
    iclog_size: u32,
    next_tid: u32,
    poisoned: bool,
    /// Set by [`Self::recover`] when committed records had to be replayed.
    replayed: bool,
}

impl Journal {
    pub(crate) fn new(device: Arc<dyn BlockDevice>, superblock: Superblock) -> FsResult<Self> {
        if superblock.log_start == 0 || superblock.log_blocks == 0 {
            return Err(FsError::NotSupported);
        }
        // XFS v4 filesystems may still use the original log format. This
        // journal implementation only understands log-v2 records.
        if !superblock.is_v5() && superblock.version & 0x0400 == 0 {
            return Err(FsError::NotSupported);
        }
        let filesystem_size = superblock.size_bytes()?;
        let log_start_bytes = superblock
            .log_start
            .checked_mul(u64::from(superblock.block_size))
            .ok_or(FsError::ArithmeticOverflow)?;
        let log_size_bytes = u64::from(superblock.log_blocks)
            .checked_mul(u64::from(superblock.block_size))
            .ok_or(FsError::ArithmeticOverflow)?;
        let log_end = log_start_bytes
            .checked_add(log_size_bytes)
            .ok_or(FsError::ArithmeticOverflow)?;
        if log_end > filesystem_size || log_size_bytes < 2 * BASIC_BLOCK_SIZE {
            return Err(FsError::Corrupted);
        }
        let log_basic_blocks = u32::try_from(log_size_bytes / BASIC_BLOCK_SIZE)
            .map_err(|_| FsError::ArithmeticOverflow)?;

        Ok(Self {
            device,
            superblock,
            filesystem_size,
            log_start_bytes,
            log_size_bytes,
            log_basic_blocks,
            cycle: 1,
            head_block: 0,
            prev_block: u32::MAX,
            tail_lsn: 0,
            iclog_size: DEFAULT_ICLOG_SIZE,
            next_tid: 1,
            poisoned: false,
            replayed: false,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Whether [`Self::recover`] had to replay committed transactions, i.e. the
    /// volume was not cleanly unmounted.
    pub(crate) fn was_replayed(&self) -> bool {
        self.replayed
    }

    /// Scan the physical log, locate its head/tail, and replay committed
    /// transactions that have not been covered by a clean unmount.
    pub(crate) fn recover(&mut self) -> FsResult<()> {
        let records = self.scan()?;
        let Some(last) = records.last() else {
            return Err(FsError::Corrupted);
        };
        let current_cycle = last.header.h_cycle;
        let current: Vec<_> = records
            .into_iter()
            .filter(|record| record.header.h_cycle == current_cycle)
            .collect();
        let last = current.last().ok_or(FsError::Corrupted)?;

        let last_unmount = current
            .iter()
            .rposition(|record| record.decoded.as_ref().is_some_and(|item| item.unmount));
        let replay_start = last_unmount.map(|index| index + 1).unwrap_or(0);
        let tail_lsn = if let Some(index) = last_unmount {
            Self::lsn_after(&current[index].header, self.log_basic_blocks)
        } else {
            current
                .iter()
                .map(|record| record.header.h_tail_lsn)
                .filter(|lsn| *lsn != 0)
                .min()
                .unwrap_or_else(|| current[0].header.h_lsn)
        };

        let replay: Vec<_> = current[replay_start..]
            .iter()
            .filter(|record| record.header.h_lsn >= tail_lsn)
            .collect();
        self.replayed = !replay.is_empty();
        for pair in replay.windows(2) {
            if pair[1].block != Self::block_after(&pair[0].header, self.log_basic_blocks)
                || pair[1].header.h_prev_block != pair[0].block
            {
                return Err(FsError::Corrupted);
            }
        }
        for record in replay {
            match &record.decoded {
                Some(decoded) if decoded.committed => {
                    self.apply_items(&decoded.items, &decoded.inode_items, record.header.h_lsn)?
                }
                Some(_) => {}
                None => {
                    return Err(FsError::NotSupported);
                }
            }
        }
        self.device.flush().map_err(|_| FsError::DiskError)?;

        let next = Self::lsn_after(&last.header, self.log_basic_blocks);
        self.cycle = (next >> 32) as u32;
        self.head_block = next as u32;
        self.prev_block = last.block;
        self.tail_lsn = tail_lsn;
        self.iclog_size = last.header.h_size;
        self.next_tid = current
            .iter()
            .filter_map(|record| record.decoded.as_ref())
            .map(|record| record.tid)
            .max()
            .unwrap_or(0)
            .wrapping_add(1);
        Ok(())
    }

    /// Append and force one committed transaction, then apply its metadata
    /// images. This is the one-batch form of [`Self::commit_group`].
    pub(crate) fn commit(
        &mut self,
        items: Vec<LogBufferItem>,
        inode_items: Vec<xfs_rs::log_format::LogInodeItem>,
    ) -> FsResult<u64> {
        if self.poisoned {
            return Err(FsError::ReadOnly);
        }
        if items.is_empty() && inode_items.is_empty() {
            return Ok(self.current_lsn());
        }
        self.commit_group(vec![PreparedTransaction::new(items, inode_items)])
    }

    /// Aggregate prepared metadata batches into one standard v2 checkpoint
    /// record and one transaction ID, force it once, then apply the merged
    /// metadata once. Shared buffer/inode targets are coalesced in preparation
    /// order with the last complete image winning. If application fails the
    /// journal is poisoned so remount recovery can finish the group.
    pub(crate) fn commit_group(&mut self, transactions: Vec<PreparedTransaction>) -> FsResult<u64> {
        if self.poisoned {
            return Err(FsError::ReadOnly);
        }
        if transactions
            .iter()
            .all(|transaction| transaction.items.is_empty() && transaction.inode_items.is_empty())
        {
            return Ok(self.current_lsn());
        }

        let tid = self.next_tid;
        let mut items: Vec<LogBufferItem> = Vec::new();
        let mut inode_items: Vec<xfs_rs::log_format::LogInodeItem> = Vec::new();
        let mut buffer_indices = BTreeMap::<u64, usize>::new();
        let mut inode_indices = BTreeMap::<u64, usize>::new();
        for transaction in &transactions {
            for item in &transaction.items {
                if let Some(&index) = buffer_indices.get(&item.block_num) {
                    if items[index].data.len() != item.data.len() {
                        return Err(FsError::InvalidArgument);
                    }
                    items[index] = item.clone();
                    // Earlier batches may have dirtied chunks absent from the
                    // last batch's relative bitmap. Log the complete final
                    // image.
                    items[index].dirty_chunks.clear();
                } else {
                    items.try_reserve(1).map_err(|_| FsError::OutOfMemory)?;
                    buffer_indices.insert(item.block_num, items.len());
                    items.push(item.clone());
                }
            }
            for item in &transaction.inode_items {
                if let Some(&index) = inode_indices.get(&item.ino) {
                    // Writer-prepared inode items are complete images, so the
                    // last item also carries the final data-fork fields.
                    inode_items[index] = item.clone();
                } else {
                    inode_items
                        .try_reserve(1)
                        .map_err(|_| FsError::OutOfMemory)?;
                    inode_indices.insert(item.ino, inode_items.len());
                    inode_items.push(item.clone());
                }
            }
        }
        let tx = LogTransaction {
            tid,
            items,
            inode_items,
        };
        let build = |cycle: u32, block: u32| {
            encode_transaction(
                &tx,
                cycle,
                block,
                self.prev_block,
                self.tail_lsn,
                self.superblock.uuid,
                self.iclog_size,
                Self::native_format(),
                tid,
            )
        };
        let (cycle, start_block, record) = self.frame_record(build)?;
        let record_blocks = u32::try_from(record.len() as u64 / BASIC_BLOCK_SIZE)
            .map_err(|_| FsError::ArithmeticOverflow)?;

        let lsn = (u64::from(cycle) << 32) | u64::from(start_block);
        let offset = self
            .log_start_bytes
            .checked_add(u64::from(start_block) * BASIC_BLOCK_SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        if let Err(error) =
            write_exact_at(self.device.as_ref(), offset, &record, self.filesystem_size)
        {
            self.poisoned = true;
            return Err(error);
        }
        if self.device.flush().is_err() {
            self.poisoned = true;
            return Err(FsError::DiskError);
        }

        if let Err(error) = self.apply_items(&tx.items, &tx.inode_items, lsn) {
            self.poisoned = true;
            return Err(error);
        }
        if self.device.flush().is_err() {
            self.poisoned = true;
            return Err(FsError::DiskError);
        }

        self.advance(cycle, start_block, record_blocks, tid);
        Ok(lsn)
    }

    /// Force all metadata and append a clean unmount record. The caller must
    /// have no active transactions.
    pub(crate) fn shutdown(&mut self) -> FsResult<()> {
        if self.poisoned {
            return Err(FsError::ReadOnly);
        }
        self.device.flush().map_err(|_| FsError::DiskError)?;
        let tid = self.next_tid;
        let build = |cycle: u32, block: u32| {
            encode_unmount_record(
                cycle,
                block,
                self.prev_block,
                self.tail_lsn,
                self.superblock.uuid,
                self.iclog_size,
                Self::native_format(),
                tid,
            )
        };
        let (cycle, start_block, record) = self.frame_record(build)?;
        let record_blocks = u32::try_from(record.len() as u64 / BASIC_BLOCK_SIZE)
            .map_err(|_| FsError::ArithmeticOverflow)?;
        let offset = self
            .log_start_bytes
            .checked_add(u64::from(start_block) * BASIC_BLOCK_SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        write_exact_at(self.device.as_ref(), offset, &record, self.filesystem_size)?;
        self.device.flush().map_err(|_| FsError::DiskError)?;
        self.advance(cycle, start_block, record_blocks, tid);
        Ok(())
    }

    /// Encode a record at the current head, wrapping to block 0 of the next
    /// cycle when it would run past the end of the log.
    fn frame_record(
        &self,
        build: impl Fn(u32, u32) -> FsResult<Vec<u8>>,
    ) -> FsResult<(u32, u32, Vec<u8>)> {
        let record = build(self.cycle, self.head_block)?;
        let record_blocks = u32::try_from(record.len() as u64 / BASIC_BLOCK_SIZE)
            .map_err(|_| FsError::ArithmeticOverflow)?;
        if record_blocks == 0 || record_blocks > self.log_basic_blocks {
            return Err(FsError::NoSpace);
        }
        if u64::from(self.head_block) + u64::from(record_blocks) <= u64::from(self.log_basic_blocks)
        {
            return Ok((self.cycle, self.head_block, record));
        }

        // The record does not fit in the remaining space: start over at the
        // beginning of the log with the next cycle number. A wrapping cycle of
        // 0 or of the header magic would make the record look erased.
        let cycle = self.cycle.wrapping_add(1);
        if cycle == 0 || cycle == XLOG_HEADER_MAGIC {
            return Err(FsError::NotSupported);
        }
        Ok((cycle, 0, build(cycle, 0)?))
    }

    /// Account for a durable record and move the head past it.
    fn advance(&mut self, cycle: u32, start_block: u32, record_blocks: u32, tid: u32) {
        let end = u64::from(start_block) + u64::from(record_blocks);
        if end >= u64::from(self.log_basic_blocks) {
            self.cycle = cycle.wrapping_add(1);
            self.head_block = 0;
        } else {
            self.cycle = cycle;
            self.head_block = end as u32;
        }
        self.prev_block = start_block;
        // The tail is checkpointed synchronously to the head, so everything
        // before it is already durable and may be reclaimed.
        self.tail_lsn = (u64::from(self.cycle) << 32) | u64::from(self.head_block);
        self.next_tid = tid.wrapping_add(1);
    }

    pub(crate) fn current_lsn(&self) -> u64 {
        (u64::from(self.cycle) << 32) | u64::from(self.head_block)
    }

    fn native_format() -> u32 {
        if cfg!(target_endian = "little") {
            XLOG_FMT_LINUX_LE
        } else {
            XLOG_FMT_LINUX_BE
        }
    }

    /// Walk the log from its first block and collect the records that frame
    /// correctly.
    ///
    /// Records are framed by `h_len` (the payload length) plus their 512-byte
    /// header, so the walk jumps from one record to the next instead of probing
    /// every basic block. A torn write cannot start a record: such blocks are
    /// skipped. A well-framed header that this implementation cannot decode is
    /// an error when it is the newest record, because silently dropping it
    /// would report a committed transaction as clean.
    fn scan(&self) -> FsResult<Vec<PositionedRecord>> {
        let mut records = Vec::new();
        let mut newest_unsupported: Option<(u32, u32)> = None;
        let mut block = 0u32;
        while block < self.log_basic_blocks {
            let offset = self
                .log_start_bytes
                .checked_add(u64::from(block) * BASIC_BLOCK_SIZE)
                .ok_or(FsError::ArithmeticOverflow)?;
            let mut prefix = [0u8; 16];
            read_exact_at(
                self.device.as_ref(),
                offset,
                &mut prefix,
                self.filesystem_size,
            )?;
            let cycle = u32::from_be_bytes([prefix[4], prefix[5], prefix[6], prefix[7]]);
            if u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) != XLOG_HEADER_MAGIC
                || u32::from_be_bytes([prefix[8], prefix[9], prefix[10], prefix[11]])
                    != XLOG_VERSION_2
                || cycle == 0
                || cycle == XLOG_HEADER_MAGIC
            {
                block += 1;
                continue;
            }

            let payload_len = u32::from_be_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]);
            // A record is one 512-byte header plus `payload_len` bytes, a whole
            // number of basic blocks, and must fit before the end of the log.
            let record_blocks = 1 + payload_len / BASIC_BLOCK_SIZE as u32;
            if payload_len == 0
                || !payload_len.is_multiple_of(BASIC_BLOCK_SIZE as u32)
                || u64::from(block) + u64::from(record_blocks) > u64::from(self.log_basic_blocks)
            {
                block += 1;
                continue;
            }
            let record_len = XLOG_HEADER_SIZE as u32 + payload_len;

            if record_len > MAX_RECORD_BYTES {
                if newest_unsupported.is_none_or(|(seen_cycle, seen_block)| {
                    (cycle, block) > (seen_cycle, seen_block)
                }) {
                    newest_unsupported = Some((cycle, block));
                }
                block += record_blocks;
                continue;
            }

            let mut raw = vec![0u8; record_len as usize];
            read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
            let header = match decode_record_header(&raw, self.superblock.uuid) {
                Ok(header) => header,
                Err(_) => {
                    block += 1;
                    continue;
                }
            };
            let decoded = if header.h_fmt == Self::native_format() {
                decode_record(&raw, self.superblock.uuid).ok()
            } else {
                None
            };
            records.push(PositionedRecord {
                block,
                header,
                decoded,
            });

            block += record_blocks;
        }

        records.sort_by_key(|record| (record.header.h_cycle, record.block));
        if let Some((cycle, block)) = newest_unsupported {
            let newer_than_records = records
                .last()
                .is_none_or(|last| (cycle, block) > (last.header.h_cycle, last.block));
            if newer_than_records {
                return Err(FsError::NotSupported);
            }
        }
        Ok(records)
    }

    /// Whether the log holds transactions that a mount must replay.
    ///
    /// Used to warn on read-only mounts, which never replay the log.
    pub(crate) fn log_needs_replay(&self) -> FsResult<bool> {
        let records = self.scan()?;
        let Some(last) = records.last() else {
            return Ok(false);
        };
        let current: Vec<_> = records
            .iter()
            .filter(|record| record.header.h_cycle == last.header.h_cycle)
            .collect();
        let last_unmount = current
            .iter()
            .rposition(|record| record.decoded.as_ref().is_some_and(|item| item.unmount));
        Ok(current.len() > last_unmount.map_or(0, |index| index + 1))
    }

    fn apply_items(
        &self,
        items: &[LogBufferItem],
        inode_items: &[xfs_rs::log_format::LogInodeItem],
        lsn: u64,
    ) -> FsResult<()> {
        for item in items {
            let offset = item
                .block_num
                .checked_mul(BASIC_BLOCK_SIZE)
                .ok_or(FsError::ArithmeticOverflow)?;
            let mut raw = vec![0u8; item.data.len()];
            read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
            if item.dirty_chunks.is_empty() {
                raw.copy_from_slice(&item.data);
            } else {
                for &chunk in &item.dirty_chunks {
                    let start = chunk.checked_mul(128).ok_or(FsError::ArithmeticOverflow)?;
                    let end = start.checked_add(128).ok_or(FsError::ArithmeticOverflow)?;
                    let source = item.data.get(start..end).ok_or(FsError::Corrupted)?;
                    let destination = raw.get_mut(start..end).ok_or(FsError::Corrupted)?;
                    destination.copy_from_slice(source);
                }
            }
            write_exact_at(self.device.as_ref(), offset, &raw, self.filesystem_size)?;
        }
        for item in inode_items {
            let offset = item
                .block_num
                .checked_mul(BASIC_BLOCK_SIZE)
                .ok_or(FsError::ArithmeticOverflow)?;
            let len = usize::try_from(item.buffer_len)
                .ok()
                .and_then(|blocks| blocks.checked_mul(BASIC_BLOCK_SIZE as usize))
                .ok_or(FsError::ArithmeticOverflow)?;
            let mut raw = vec![0u8; len];
            read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
            item.apply_to_disk(&mut raw, self.superblock.inode_size as usize, lsn)?;
            write_exact_at(self.device.as_ref(), offset, &raw, self.filesystem_size)?;
        }
        Ok(())
    }

    fn block_after(header: &LogRecordHeader, log_blocks: u32) -> u32 {
        // A record is one 512-byte header block followed by `h_len` payload
        // bytes; `h_len` itself excludes the header.
        let blocks = 1 + header.h_len.div_ceil(BASIC_BLOCK_SIZE as u32);
        let end = u64::from(header.h_lsn as u32) + u64::from(blocks);
        if end >= u64::from(log_blocks) {
            0
        } else {
            end as u32
        }
    }

    fn lsn_after(header: &LogRecordHeader, log_blocks: u32) -> u64 {
        let block = Self::block_after(header, log_blocks);
        let cycle = if block == 0 {
            header.h_cycle.wrapping_add(1)
        } else {
            header.h_cycle
        };
        (u64::from(cycle) << 32) | u64::from(block)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
        Mutex,
    };

    use fs_abstraction::BlockDevice;
    use xfs_rs::log_format::{LogBufferType, XLOG_FMT_LINUX_LE};

    use super::*;

    struct Device {
        data: Mutex<Vec<u8>>,
        flush_calls: AtomicUsize,
        log_writes: AtomicUsize,
        fail_write_at: AtomicU64,
    }

    impl Device {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                data: Mutex::new(vec![0u8; 4096 * 128]),
                flush_calls: AtomicUsize::new(0),
                log_writes: AtomicUsize::new(0),
                fail_write_at: AtomicU64::new(u64::MAX),
            })
        }
    }

    impl BlockDevice for Device {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
            let data = self.data.lock().unwrap();
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            let len = buf.len().min(data.len().saturating_sub(offset));
            buf[..len].copy_from_slice(&data[offset..offset + len]);
            Ok(len)
        }

        fn write_at(&self, offset: u64, input: &[u8]) -> FsResult<usize> {
            if self.fail_write_at.load(Ordering::SeqCst) == offset {
                return Err(FsError::DiskError);
            }
            if (16 * 4096..32 * 4096).contains(&offset) {
                self.log_writes.fetch_add(1, Ordering::SeqCst);
            }
            let mut data = self.data.lock().unwrap();
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            data[offset..offset + input.len()].copy_from_slice(input);
            Ok(input.len())
        }

        fn size(&self) -> u64 {
            self.data.lock().unwrap().len() as u64
        }

        fn supports_write(&self) -> bool {
            true
        }

        fn flush(&self) -> FsResult<()> {
            self.flush_calls.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    fn superblock() -> Superblock {
        let mut raw = vec![0u8; 512];
        raw[0..4].copy_from_slice(&0x5846_5342u32.to_be_bytes());
        raw[4..8].copy_from_slice(&4096u32.to_be_bytes());
        raw[8..16].copy_from_slice(&128u64.to_be_bytes());
        raw[0x30..0x38].copy_from_slice(&16u64.to_be_bytes());
        raw[0x38..0x40].copy_from_slice(&128u64.to_be_bytes());
        raw[0x54..0x58].copy_from_slice(&128u32.to_be_bytes());
        raw[0x58..0x5C].copy_from_slice(&1u32.to_be_bytes());
        raw[0x60..0x64].copy_from_slice(&32u32.to_be_bytes());
        raw[0x64..0x66].copy_from_slice(&5u16.to_be_bytes());
        raw[0x66..0x68].copy_from_slice(&512u16.to_be_bytes());
        raw[0x68..0x6A].copy_from_slice(&512u16.to_be_bytes());
        raw[0x6A..0x6C].copy_from_slice(&8u16.to_be_bytes());
        raw[0x78] = 12;
        raw[0x79] = 9;
        raw[0x7A] = 9;
        raw[0x7B] = 3;
        raw[0x7C] = 7;
        raw[0x20..0x30].fill(0xA5);
        Superblock::parse(&raw).unwrap()
    }

    #[test]
    fn recovery_preserves_chunks_absent_from_the_dirty_bitmap() {
        let device = Device::new();
        let target = 4 * 512;
        {
            let mut data = device.data.lock().unwrap();
            data[target..target + 128].fill(0x11);
            data[target + 128..target + 256].fill(0x22);
            data[target + 256..target + 384].fill(0x33);
            data[target + 384..target + 512].fill(0x44);
        }
        let mut logged = vec![0u8; 512];
        logged[..128].fill(0xA1);
        logged[128..256].fill(0xFF);
        logged[256..384].fill(0xA3);
        logged[384..].fill(0xFF);
        let seed = encode_transaction(
            &LogTransaction {
                tid: 1,
                items: vec![LogBufferItem {
                    block_num: 4,
                    data: logged,
                    buffer_type: LogBufferType::Btree,
                    inode_buffer: false,
                    dirty_chunks: vec![0, 2],
                }],
                inode_items: Vec::new(),
            },
            1,
            0,
            u32::MAX,
            0,
            [0xA5; 16],
            DEFAULT_ICLOG_SIZE,
            XLOG_FMT_LINUX_LE,
            1,
        )
        .unwrap();
        write_exact_at(device.as_ref(), 16 * 4096, &seed, 4096 * 128).unwrap();

        let mut journal = Journal::new(device.clone(), superblock()).unwrap();
        journal.recover().unwrap();
        let data = device.data.lock().unwrap();
        assert_eq!(&data[target..target + 128], &[0xA1; 128]);
        assert_eq!(&data[target + 128..target + 256], &[0x22; 128]);
        assert_eq!(&data[target + 256..target + 384], &[0xA3; 128]);
        assert_eq!(&data[target + 384..target + 512], &[0x44; 128]);
    }

    #[test]
    fn recovery_replays_logical_inode_items() {
        let device = Device::new();
        let mut core = xfs_rs::inode_alloc::create_empty_inode_core_at(
            0o100644,
            0,
            0,
            3,
            42,
            &[0xA5; 16],
            true,
            1_700_000_000,
            0,
        )
        .unwrap();
        core.size = 8192;
        core.nblocks = 16;
        core.format = xfs_rs::InodeFormat::Extents;
        core.nextents = 1;
        let extent = xfs_rs::Extent {
            file_offset: 0,
            start_block: 1234,
            block_count: 2,
            is_unwritten: false,
        };
        let inode = xfs_rs::Inode {
            core,
            data_fork: xfs_rs::DataFork::Extents(vec![extent]),
        };
        let item =
            xfs_rs::log_format::LogInodeItem::from_inode(&inode, 42, 4, 8, 0, 512, 99).unwrap();
        let mut target = vec![0u8; 4096];
        item.apply_to_disk(&mut target, 512, 99).unwrap();
        target[0x38..0x40].copy_from_slice(&1u64.to_be_bytes());
        write_exact_at(device.as_ref(), 4 * 512, &target, 4096 * 128).unwrap();
        let seed = encode_transaction(
            &LogTransaction {
                tid: 1,
                items: Vec::new(),
                inode_items: vec![item],
            },
            1,
            0,
            u32::MAX,
            0,
            [0xA5; 16],
            DEFAULT_ICLOG_SIZE,
            XLOG_FMT_LINUX_LE,
            1,
        )
        .unwrap();
        write_exact_at(device.as_ref(), 16 * 4096, &seed, 4096 * 128).unwrap();

        let mut journal = Journal::new(device.clone(), superblock()).unwrap();
        journal.recover().unwrap();
        let mut recovered = vec![0u8; 4096];
        read_exact_at(device.as_ref(), 4 * 512, &mut recovered, 4096 * 128).unwrap();
        let parsed = xfs_rs::Inode::parse(&recovered[..512], 512).unwrap();
        assert_eq!(parsed.core.size, 8192);
        assert_eq!(parsed.core.lsn, 1 << 32);
        assert!(parsed.verify_crc(&recovered[..512], 512).is_ok());
        match parsed.data_fork {
            xfs_rs::DataFork::Extents(extents) => assert_eq!(extents, vec![extent]),
            other => panic!("unexpected data fork: {other:?}"),
        }
    }

    fn commit_record(tid: u32, block: u32, target: u64, byte: u8, prev_block: u32) -> Vec<u8> {
        encode_transaction(
            &LogTransaction {
                tid,
                items: vec![LogBufferItem {
                    block_num: target,
                    data: vec![byte; 512],
                    buffer_type: LogBufferType::Btree,
                    inode_buffer: false,
                    dirty_chunks: Vec::new(),
                }],
                inode_items: Vec::new(),
            },
            1,
            block,
            prev_block,
            0,
            [0xA5; 16],
            DEFAULT_ICLOG_SIZE,
            XLOG_FMT_LINUX_LE,
            tid,
        )
        .unwrap()
    }

    /// Every remount must resume exactly after the last record. An off-by-one
    /// head position overwrites the previous record and recovery then drops its
    /// transaction.
    #[test]
    fn successive_remounts_append_without_overlapping_records() {
        let device = Device::new();
        let superblock = superblock();
        let log_start = Journal::new(device.clone(), superblock.clone())
            .unwrap()
            .log_start_bytes;

        let seed = commit_record(1, 0, 20, 0xAA, u32::MAX);
        write_exact_at(device.as_ref(), log_start, &seed, device.size()).unwrap();

        let mut previous_head = None;
        for round in 0..3u8 {
            let mut journal = Journal::new(device.clone(), superblock.clone()).unwrap();
            journal.recover().unwrap();
            if let Some((cycle, block)) = previous_head {
                assert_eq!(
                    (journal.cycle, journal.head_block),
                    (cycle, block),
                    "recovery must resume exactly after the last record, not inside it"
                );
            }
            let record = 21 + u64::from(round);
            journal
                .commit(
                    vec![LogBufferItem {
                        block_num: record,
                        data: vec![0x40 + round; 512],
                        buffer_type: LogBufferType::Btree,
                        inode_buffer: false,
                        dirty_chunks: Vec::new(),
                    }],
                    Vec::new(),
                )
                .unwrap();
            previous_head = Some((journal.cycle, journal.head_block));
            // Dropped without shutdown(), like a crash.
        }

        let mut reopened = Journal::new(device.clone(), superblock).unwrap();
        reopened.recover().unwrap();
        let data = device.data.lock().unwrap();
        assert_eq!(&data[20 * 512..21 * 512], &[0xAA; 512]);
        for round in 0..3u8 {
            let record = (21 + u64::from(round)) as usize * 512;
            assert_eq!(&data[record..record + 512], &[0x40 + round; 512]);
        }
    }

    #[test]
    fn commit_wraps_to_the_next_cycle_at_the_end_of_the_log() {
        let device = Device::new();
        let superblock = superblock();
        let mut journal = Journal::new(device.clone(), superblock.clone()).unwrap();

        journal.cycle = 7;
        journal.head_block = journal.log_basic_blocks - 1;
        journal.prev_block = u32::MAX;
        journal.tail_lsn = (7u64 << 32) | u64::from(journal.log_basic_blocks - 1);

        let lsn = journal
            .commit(
                vec![LogBufferItem {
                    block_num: 30,
                    data: vec![0x77; 512],
                    buffer_type: LogBufferType::Btree,
                    inode_buffer: false,
                    dirty_chunks: Vec::new(),
                }],
                Vec::new(),
            )
            .expect("a record that does not fit must wrap instead of failing");
        assert_eq!(lsn >> 32, 8, "wrapped record starts a new cycle");
        assert_eq!(lsn as u32, 0, "wrapped record starts at block 0");
        assert_eq!(journal.cycle, 8);
        assert!(journal.head_block >= 2);

        let mut reopened = Journal::new(device.clone(), superblock).unwrap();
        reopened.recover().unwrap();
        assert_eq!(
            &device.data.lock().unwrap()[30 * 512..31 * 512],
            &[0x77; 512]
        );
        assert_eq!(reopened.cycle, journal.cycle);
        assert_eq!(reopened.head_block, journal.head_block);
    }

    fn buffer_item(target: u64, byte: u8) -> LogBufferItem {
        LogBufferItem {
            block_num: target,
            data: vec![byte; 512],
            buffer_type: LogBufferType::Btree,
            inode_buffer: false,
            dirty_chunks: Vec::new(),
        }
    }

    #[test]
    fn group_commit_uses_one_record_one_id_and_recovers_every_batch() {
        let device = Device::new();
        let superblock = superblock();
        let mut journal = Journal::new(device.clone(), superblock.clone()).unwrap();
        let first_tid = journal.next_tid;
        let lsn = journal
            .commit_group(vec![
                PreparedTransaction::new(vec![buffer_item(20, 0xA1)], Vec::new()),
                PreparedTransaction::new(vec![buffer_item(21, 0xB2)], Vec::new()),
            ])
            .unwrap();
        assert_eq!(lsn >> 32, 1);
        assert_eq!(journal.next_tid, first_tid + 1);
        assert_eq!(device.log_writes.load(Ordering::SeqCst), 1);
        assert_eq!(device.flush_calls.load(Ordering::SeqCst), 2);

        let records = journal.scan().unwrap();
        assert_eq!(records.len(), 1);
        let decoded = records[0].decoded.as_ref().unwrap();
        assert_eq!(decoded.tid, first_tid);
        assert_eq!(decoded.items.len(), 2);
        drop(journal);

        let mut reopened = Journal::new(device.clone(), superblock).unwrap();
        reopened.recover().unwrap();
        assert_eq!(reopened.next_tid, first_tid + 1);
        let data = device.data.lock().unwrap();
        assert_eq!(&data[20 * 512..21 * 512], &[0xA1; 512]);
        assert_eq!(&data[21 * 512..22 * 512], &[0xB2; 512]);
    }

    #[test]
    fn group_commit_coalesces_shared_targets_with_last_image_winning() {
        let device = Device::new();
        let superblock = superblock();
        let mut journal = Journal::new(device.clone(), superblock.clone()).unwrap();
        let tid = journal.next_tid;
        journal
            .commit_group(vec![
                PreparedTransaction::new(vec![buffer_item(20, 0xA1)], Vec::new()),
                PreparedTransaction::new(vec![buffer_item(20, 0xB2)], Vec::new()),
            ])
            .unwrap();
        assert!(!journal.is_poisoned());
        assert_eq!(journal.next_tid, tid + 1);
        assert_eq!(device.log_writes.load(Ordering::SeqCst), 1);
        assert_eq!(device.flush_calls.load(Ordering::SeqCst), 2);
        assert_eq!(
            &device.data.lock().unwrap()[20 * 512..21 * 512],
            &[0xB2; 512]
        );
        drop(journal);

        let mut reopened = Journal::new(device.clone(), superblock).unwrap();
        reopened.recover().unwrap();
        assert_eq!(
            &device.data.lock().unwrap()[20 * 512..21 * 512],
            &[0xB2; 512]
        );
    }

    #[test]
    fn group_apply_failure_poisons_and_recovery_finishes_the_group() {
        let device = Device::new();
        let superblock = superblock();
        let mut journal = Journal::new(device.clone(), superblock.clone()).unwrap();
        device.fail_write_at.store(21 * 512, Ordering::SeqCst);
        assert!(matches!(
            journal.commit_group(vec![
                PreparedTransaction::new(vec![buffer_item(20, 0xA1)], Vec::new()),
                PreparedTransaction::new(vec![buffer_item(21, 0xB2)], Vec::new()),
            ]),
            Err(FsError::DiskError)
        ));
        assert!(journal.is_poisoned());
        assert_eq!(device.log_writes.load(Ordering::SeqCst), 1);
        assert_eq!(
            &device.data.lock().unwrap()[20 * 512..21 * 512],
            &[0xA1; 512]
        );
        drop(journal);

        device.fail_write_at.store(u64::MAX, Ordering::SeqCst);
        let mut reopened = Journal::new(device.clone(), superblock).unwrap();
        reopened.recover().unwrap();
        assert!(!reopened.is_poisoned());
        let data = device.data.lock().unwrap();
        assert_eq!(&data[20 * 512..21 * 512], &[0xA1; 512]);
        assert_eq!(&data[21 * 512..22 * 512], &[0xB2; 512]);
    }

    #[test]
    fn scan_rejects_an_unsupported_record_size_at_the_head() {
        let device = Device::new();
        let superblock = superblock();
        let journal = Journal::new(device.clone(), superblock).unwrap();

        let mut header = vec![0u8; 512];
        header[0..4].copy_from_slice(&XLOG_HEADER_MAGIC.to_be_bytes());
        header[4..8].copy_from_slice(&2u32.to_be_bytes());
        header[8..12].copy_from_slice(&XLOG_VERSION_2.to_be_bytes());
        let oversized = MAX_RECORD_BYTES + 512;
        header[12..16].copy_from_slice(&oversized.to_be_bytes());
        write_exact_at(
            device.as_ref(),
            journal.log_start_bytes,
            &header,
            device.size(),
        )
        .unwrap();

        assert!(
            matches!(journal.scan(), Err(FsError::NotSupported)),
            "a well-framed record this driver cannot decode must not be skipped"
        );
    }

    #[test]
    fn read_only_probe_reports_whether_the_log_needs_replay() {
        let device = Device::new();
        let superblock = superblock();
        let journal = Journal::new(device.clone(), superblock.clone()).unwrap();
        let seed = commit_record(1, 0, 20, 0xAA, u32::MAX);
        write_exact_at(
            device.as_ref(),
            journal.log_start_bytes,
            &seed,
            device.size(),
        )
        .unwrap();
        assert!(journal.log_needs_replay().unwrap());

        let mut mounted = Journal::new(device.clone(), superblock.clone()).unwrap();
        mounted.recover().unwrap();
        mounted.shutdown().unwrap();

        let probe = Journal::new(device.clone(), superblock).unwrap();
        assert!(!probe.log_needs_replay().unwrap());
    }

    #[test]
    fn commit_and_clean_recovery_are_idempotent() {
        let device = Device::new();
        let mut journal = Journal::new(device.clone(), superblock()).unwrap();
        let seed = encode_transaction(
            &LogTransaction {
                tid: 1,
                items: vec![LogBufferItem {
                    block_num: 4,
                    data: vec![0x11; 512],
                    buffer_type: LogBufferType::Btree,
                    inode_buffer: false,
                    dirty_chunks: Vec::new(),
                }],
                inode_items: Vec::new(),
            },
            1,
            0,
            u32::MAX,
            0,
            [0xA5; 16],
            DEFAULT_ICLOG_SIZE,
            XLOG_FMT_LINUX_LE,
            1,
        )
        .unwrap();
        write_exact_at(device.as_ref(), 16 * 4096, &seed, 4096 * 128).unwrap();
        journal.recover().unwrap();
        assert_eq!(
            &device.data.lock().unwrap()[4 * 512..4 * 512 + 512],
            &[0x11; 512]
        );

        let items = vec![LogBufferItem {
            block_num: 5,
            data: vec![0x22; 512],
            buffer_type: LogBufferType::Agf,
            inode_buffer: false,
            dirty_chunks: Vec::new(),
        }];
        journal.commit(items.clone(), Vec::new()).unwrap();
        assert_eq!(
            &device.data.lock().unwrap()[5 * 512..5 * 512 + 512],
            &[0x22; 512]
        );
        journal.shutdown().unwrap();

        let mut reopened = Journal::new(device.clone(), superblock()).unwrap();
        reopened.recover().unwrap();
        assert!(!reopened.is_poisoned());
    }
}
