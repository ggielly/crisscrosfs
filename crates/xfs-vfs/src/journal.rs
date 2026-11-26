//! XFS internal-log v2 transactions and recovery.
//!
//! Records are encoded with the real 512-byte `xlog_rec_header`, native-endian
//! transaction/item descriptors, cycle stamps, and CRC32C. A commit is durable
//! only after the log record has been flushed; metadata is applied afterwards.
//! Recovery replays complete committed buffer and inode records and stops at a
//! clean unmount record. The tail advances after every successful metadata
//! flush, so already-durable records are not replayed over later data reuse.

use std::sync::Arc;

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

use crate::io::{read_exact_at, write_exact_at};

const BASIC_BLOCK_SIZE: u64 = 512;
const DEFAULT_ICLOG_SIZE: u32 = 32 * 1024;

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
        })
    }

    #[allow(dead_code)]
    pub(crate) fn is_poisoned(&self) -> bool {
        self.poisoned
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

        self.cycle = last.header.h_cycle;
        self.head_block = Self::block_after(&last.header, self.log_basic_blocks);
        if self.head_block == 0 {
            self.cycle = self.cycle.wrapping_add(1);
        }
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
    /// images. If application fails after the log commit, the instance is
    /// poisoned and must be remounted so recovery can finish the transaction.
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
        let tid = self.next_tid;
        let tx = LogTransaction {
            tid,
            items,
            inode_items,
        };
        let record = encode_transaction(
            &tx,
            self.cycle,
            self.head_block,
            self.prev_block,
            self.tail_lsn,
            self.superblock.uuid,
            self.iclog_size,
            Self::native_format(),
            tid,
        )?;
        let record_blocks = u32::try_from(record.len() as u64 / BASIC_BLOCK_SIZE)
            .map_err(|_| FsError::ArithmeticOverflow)?;
        if self
            .head_block
            .checked_add(record_blocks)
            .is_none_or(|end| end > self.log_basic_blocks)
        {
            return Err(FsError::NoSpace);
        }

        let lsn = (u64::from(self.cycle) << 32) | u64::from(self.head_block);
        let offset = self
            .log_start_bytes
            .checked_add(u64::from(self.head_block) * BASIC_BLOCK_SIZE)
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

        let next_block = self.head_block + record_blocks;
        self.tail_lsn = if next_block == self.log_basic_blocks {
            u64::from(self.cycle.wrapping_add(1)) << 32
        } else {
            (u64::from(self.cycle) << 32) | u64::from(next_block)
        };
        self.prev_block = self.head_block;
        self.head_block = next_block;
        self.next_tid = tid.wrapping_add(1);
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
        let record = encode_unmount_record(
            self.cycle,
            self.head_block,
            self.prev_block,
            self.tail_lsn,
            self.superblock.uuid,
            self.iclog_size,
            Self::native_format(),
            tid,
        )?;
        let record_blocks = u32::try_from(record.len() as u64 / BASIC_BLOCK_SIZE)
            .map_err(|_| FsError::ArithmeticOverflow)?;
        if self
            .head_block
            .checked_add(record_blocks)
            .is_none_or(|end| end > self.log_basic_blocks)
        {
            return Err(FsError::NoSpace);
        }
        let offset = self
            .log_start_bytes
            .checked_add(u64::from(self.head_block) * BASIC_BLOCK_SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        write_exact_at(self.device.as_ref(), offset, &record, self.filesystem_size)?;
        self.device.flush().map_err(|_| FsError::DiskError)?;
        self.tail_lsn = Self::lsn_after(
            &decode_record_header(&record, self.superblock.uuid)?,
            self.log_basic_blocks,
        );
        self.prev_block = self.head_block;
        self.head_block += record_blocks;
        self.next_tid = tid.wrapping_add(1);
        Ok(())
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

    fn scan(&self) -> FsResult<Vec<PositionedRecord>> {
        let mut records = Vec::new();
        for block in 0..self.log_basic_blocks {
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
                continue;
            }
            let payload_len = u32::from_be_bytes([prefix[12], prefix[13], prefix[14], prefix[15]]);
            if payload_len == 0 || payload_len > 32 * 1024 {
                continue;
            }
            let total = u64::from(XLOG_HEADER_SIZE as u32)
                .checked_add(u64::from(payload_len))
                .ok_or(FsError::ArithmeticOverflow)?;
            if total > self.log_size_bytes
                || u64::from(block)
                    .checked_add(total / BASIC_BLOCK_SIZE)
                    .is_none_or(|end| end > u64::from(self.log_basic_blocks))
            {
                continue;
            }
            let mut raw = vec![0u8; total as usize];
            read_exact_at(self.device.as_ref(), offset, &mut raw, self.filesystem_size)?;
            let header = match decode_record_header(&raw, self.superblock.uuid) {
                Ok(header) => header,
                Err(_) => continue,
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
        }
        records.sort_by_key(|record| (record.header.h_cycle, record.block));
        Ok(records)
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
        let blocks = header.h_len / XLOG_HEADER_SIZE as u32;
        let end = header.h_lsn as u32 + blocks;
        if end >= log_blocks {
            0
        } else {
            end
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
    use std::sync::{Arc, Mutex};

    use fs_abstraction::BlockDevice;
    use xfs_rs::log_format::{LogBufferType, XLOG_FMT_LINUX_LE};

    use super::*;

    struct Device {
        data: Mutex<Vec<u8>>,
    }

    impl Device {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                data: Mutex::new(vec![0u8; 4096 * 128]),
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
