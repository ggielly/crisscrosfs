//! XFS Journal (Log) implementation for write transactions.
//!
//! XFS uses a journal (called the "log") to ensure metadata consistency.
//! This module provides transaction-based logging for write operations.

use std::sync::Arc;

use fs_abstraction::{BlockDevice, FsError, FsResult};
use tracing::{debug, error, info, warn};
use xfs_rs::Superblock;

/// XFS Log Record Header
#[derive(Debug, Clone)]
pub struct LogRecordHeader {
    pub h_cycle: u32,
    pub h_version: u32,
    pub h_type: u32,
    pub h_len: u32,
    pub h_fmt: u32,
    pub h_crc: u32,
    pub h_lsn: u64,
    pub h_tail_lsn: u64,
    pub h_client_id: u32,
}

impl LogRecordHeader {
    pub const SIZE: usize = 32;

    // Standard XFS log record header size

    pub fn new(log_type: u32, length: u32, cycle: u32, client_id: u32) -> Self {
        Self {
            h_cycle: cycle,
            h_version: 2, // XFS log version 2
            h_type: log_type,
            h_len: length,
            h_fmt: 1, // Format identifier
            h_crc: 0, // Will be calculated later
            h_lsn: 0, // Will be set when written
            h_tail_lsn: 0,
            h_client_id: client_id,
        }
    }

    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&self.h_cycle.to_be_bytes());
        bytes[4..8].copy_from_slice(&self.h_version.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.h_type.to_be_bytes());
        bytes[12..16].copy_from_slice(&self.h_len.to_be_bytes());
        bytes[16..20].copy_from_slice(&self.h_fmt.to_be_bytes());
        bytes[20..24].copy_from_slice(&self.h_crc.to_be_bytes());
        bytes[24..32].copy_from_slice(&self.h_lsn.to_be_bytes());
        // We'll reuse some space if needed, but keeping it 32 fixed for this simple
        // header
        bytes
    }
}

/// XFS Log Record Types
pub mod log_types {
    pub const COMMIT: u32 = 2;
    pub const FORMAT: u32 = 4;
    pub const CHECKPOINT: u32 = 5;
    pub const UNMOUNT: u32 = 6;
    pub const INODE: u32 = 7;
    pub const BUFFER: u32 = 8;
    pub const EFD: u32 = 9; // Extended Format Data
    pub const EDD: u32 = 10; // Extended Disk Data
    pub const IQ: u32 = 11; // Inode Quota
    pub const PQ: u32 = 12; // Project Quota
    pub const CQ: u32 = 13; // Cluster Quota
}

/// Represents a single transaction in the XFS journal
#[derive(Debug)]
pub struct Transaction {
    pub id: u64,
    pub lsn: u64,
    pub items: Vec<TransactionItem>,
    pub dirty_buffers: Vec<DirtyBuffer>,
}

/// A single item in a transaction
#[derive(Debug, Clone)]
pub enum TransactionItem {
    InodeUpdate {
        ino: u64,
        data: Vec<u8>,
    },
    BufferUpdate {
        block_num: u64,
        data: Vec<u8>,
    },
    DirectoryEntry {
        parent_ino: u64,
        name: String,
        ino: u64,
        is_create: bool,
    },
}

/// A dirty buffer that needs to be written to the log
#[derive(Debug)]
pub struct DirtyBuffer {
    pub block_num: u64,
    pub data: Vec<u8>,
    pub original_data: Vec<u8>,
}

/// XFS Journal Manager
pub struct Journal {
    device: Arc<dyn BlockDevice>,
    superblock: Superblock,
    log_start_block: u64,
    log_size_blocks: u64,
    current_cycle: u32,
    /// Head position in blocks from log_start_block
    head_block: u64,
    /// Tail position in blocks from log_start_block
    tail_block: u64,
    active_transactions: std::collections::HashMap<u64, Transaction>,
}

impl Journal {
    /// Create a new journal instance
    pub fn new(device: Arc<dyn BlockDevice>, superblock: Superblock) -> FsResult<Self> {
        // Calculate log location from superblock
        let log_start_block = superblock.log_start;
        let log_size_blocks = superblock.log_blocks as u64;

        info!(
            "Initializing XFS Journal: start_block={}, size_blocks={}",
            log_start_block, log_size_blocks
        );

        Ok(Self {
            device,
            superblock,
            log_start_block,
            log_size_blocks,
            current_cycle: 1,
            head_block: 0,
            tail_block: 0,
            active_transactions: std::collections::HashMap::new(),
        })
    }

    /// Calculate LSN from cycle and block
    fn make_lsn(&self, cycle: u32, block: u64) -> u64 {
        ((cycle as u64) << 32) | block
    }

    /// Extract cycle from LSN
    fn lsn_cycle(&self, lsn: u64) -> u32 {
        (lsn >> 32) as u32
    }

    /// Extract block from LSN
    fn lsn_block(&self, lsn: u64) -> u64 {
        lsn & 0xFFFFFFFF
    }

    /// Start a new transaction
    pub fn begin_transaction(&mut self) -> u64 {
        // Simple transaction ID based on current head LSN
        let lsn = self.make_lsn(self.current_cycle, self.head_block);
        let tx_id = lsn;

        self.active_transactions.insert(
            tx_id,
            Transaction {
                id: tx_id,
                lsn,
                items: Vec::new(),
                dirty_buffers: Vec::new(),
            },
        );

        debug!("Started transaction {} at LSN 0x{:x}", tx_id, lsn);
        tx_id
    }

    /// Add an inode update to a transaction
    pub fn add_inode_update(&mut self, tx_id: u64, ino: u64, data: Vec<u8>) -> FsResult<()> {
        if let Some(tx) = self.active_transactions.get_mut(&tx_id) {
            tx.items.push(TransactionItem::InodeUpdate { ino, data });
            Ok(())
        } else {
            Err(FsError::InvalidArgument)
        }
    }

    /// Add a buffer update to a transaction
    pub fn add_buffer_update(&mut self, tx_id: u64, block_num: u64, data: Vec<u8>) -> FsResult<()> {
        // Read original data for potential rollback
        let mut original_data = vec![0u8; self.superblock.block_size as usize];
        self.device
            .read_at(
                block_num * self.superblock.block_size as u64,
                &mut original_data,
            )
            .map_err(|_| FsError::DiskError)?;

        if let Some(tx) = self.active_transactions.get_mut(&tx_id) {
            tx.dirty_buffers.push(DirtyBuffer {
                block_num,
                data,
                original_data,
            });
            Ok(())
        } else {
            Err(FsError::InvalidArgument)
        }
    }

    /// Add a directory operation to a transaction
    pub fn add_directory_op(
        &mut self,
        tx_id: u64,
        parent_ino: u64,
        name: String,
        ino: u64,
        is_create: bool,
    ) -> FsResult<()> {
        if let Some(tx) = self.active_transactions.get_mut(&tx_id) {
            tx.items.push(TransactionItem::DirectoryEntry {
                parent_ino,
                name,
                ino,
                is_create,
            });
            Ok(())
        } else {
            Err(FsError::InvalidArgument)
        }
    }

    /// Commit a transaction to the journal
    pub fn commit_transaction(&mut self, tx_id: u64) -> FsResult<()> {
        if let Some(mut tx) = self.active_transactions.remove(&tx_id) {
            debug!("Committing transaction {}", tx_id);

            // 1. Write transaction items to log
            self.write_transaction_to_log(&mut tx)?;

            // 2. Write commit record (special log record)
            self.write_commit_record(tx.lsn)?;

            // 3. Flush the log to disk - Critical for WAL
            self.device.flush().map_err(|_| FsError::DiskError)?;

            // 4. Apply changes to actual filesystem
            // In a real system, this might be asynchronous/on background
            self.apply_transaction(&tx)?;

            // 5. Optionally flush data too
            self.device.flush().map_err(|_| FsError::DiskError)?;

            info!("Transaction 0x{:x} committed successfully", tx_id);
            Ok(())
        } else {
            error!("Attempted to commit non-existent transaction {}", tx_id);
            Err(FsError::InvalidArgument)
        }
    }

    /// Write a transaction to the journal log
    fn write_transaction_to_log(&mut self, tx: &mut Transaction) -> FsResult<()> {
        let mut log_data = Vec::new();

        let header = LogRecordHeader::new(log_types::FORMAT, 0, self.current_cycle, 0);
        log_data.extend_from_slice(&header.to_bytes());

        for item in &tx.items {
            match item {
                TransactionItem::InodeUpdate { ino, data } => {
                    log_data.extend_from_slice(&log_types::INODE.to_be_bytes());
                    log_data.extend_from_slice(&ino.to_be_bytes());
                    log_data.extend_from_slice(&(data.len() as u32).to_be_bytes());
                    log_data.extend_from_slice(data);
                }
                TransactionItem::BufferUpdate { block_num, data } => {
                    log_data.extend_from_slice(&log_types::BUFFER.to_be_bytes());
                    log_data.extend_from_slice(&block_num.to_be_bytes());
                    log_data.extend_from_slice(&(data.len() as u32).to_be_bytes());
                    log_data.extend_from_slice(data);
                }
                TransactionItem::DirectoryEntry {
                    parent_ino,
                    name,
                    ino,
                    is_create,
                } => {
                    log_data.extend_from_slice(&log_types::FORMAT.to_be_bytes());
                    log_data.extend_from_slice(&parent_ino.to_be_bytes());
                    log_data.extend_from_slice(&ino.to_be_bytes());
                    log_data.extend_from_slice(&[*is_create as u8]);
                    let name_bytes = name.as_bytes();
                    log_data.extend_from_slice(&(name_bytes.len() as u32).to_be_bytes());
                    log_data.extend_from_slice(name_bytes);
                }
            }
        }

        // Pad to 8-byte alignment for ops if needed, but here let's just use current
        // length
        let actual_payload_len = (log_data.len() - LogRecordHeader::SIZE) as u32;

        let mut final_header =
            LogRecordHeader::new(log_types::FORMAT, actual_payload_len, self.current_cycle, 0);
        final_header.h_lsn = self.make_lsn(self.current_cycle, self.head_block);
        final_header.h_tail_lsn = self.make_lsn(self.current_cycle, self.tail_block); // Simplified tail handling

        // Calculate CRC32C
        let _header_bytes = final_header.to_bytes();
        let crc = crc32c::crc32c(&log_data[LogRecordHeader::SIZE..]);
        final_header.h_crc = crc;

        // Update header in log_data
        let final_header_bytes = final_header.to_bytes();
        log_data[..LogRecordHeader::SIZE].copy_from_slice(&final_header_bytes);

        // Reserve space and write
        let blocks_needed = (log_data.len() + self.superblock.block_size as usize - 1)
            / self.superblock.block_size as usize;
        self.ensure_log_space(blocks_needed as u64)?;

        self.write_log_data(&log_data)?;

        tx.lsn = final_header.h_lsn;

        Ok(())
    }

    /// Ensure there is enough space in the log, possibly moving the tail
    fn ensure_log_space(&mut self, blocks: u64) -> FsResult<()> {
        // Simplified: in a real system we'd wait for tail to move (checkpoint)
        // Here we just check and error if full
        let free_blocks = if self.head_block >= self.tail_block {
            self.log_size_blocks - (self.head_block - self.tail_block)
        } else {
            self.tail_block - self.head_block
        };

        if free_blocks < blocks {
            error!(
                "XFS Log is full! tail={} head={} size={}",
                self.tail_block, self.head_block, self.log_size_blocks
            );
            return Err(FsError::NoSpace);
        }

        Ok(())
    }

    /// Write data to the log area with wrap-around
    fn write_log_data(&mut self, data: &[u8]) -> FsResult<()> {
        let block_size = self.superblock.block_size as u64;
        let mut data_pos = 0;
        let mut total_len = data.len() as u64;

        while total_len > 0 {
            let space_to_end = (self.log_size_blocks - self.head_block) * block_size;
            let to_write = total_len.min(space_to_end);

            let disk_offset = (self.log_start_block + self.head_block) * block_size;
            self.device
                .write_at(disk_offset, &data[data_pos..data_pos + to_write as usize])
                .map_err(|_| FsError::DiskError)?;

            data_pos += to_write as usize;
            total_len -= to_write;

            self.head_block += (to_write + block_size - 1) / block_size;

            if self.head_block >= self.log_size_blocks {
                self.head_block = 0;
                self.current_cycle += 1;
                debug!("Log wrapped to cycle {}", self.current_cycle);
            }
        }

        Ok(())
    }

    /// Apply a committed transaction to the filesystem
    fn apply_transaction(&self, tx: &Transaction) -> FsResult<()> {
        debug!("Applying transaction {} to filesystem", tx.id);

        // Apply inode updates
        for item in &tx.items {
            match item {
                TransactionItem::InodeUpdate { ino, data } => {
                    // Calculate inode location and write
                    let inode_offset = self.calculate_inode_offset(*ino)?;
                    self.device
                        .write_at(inode_offset, data)
                        .map_err(|_| FsError::DiskError)?;
                    debug!("Applied inode update for ino {}", ino);
                }
                _ => {} // Other operations handled separately
            }
        }

        // Apply buffer updates
        for buffer in &tx.dirty_buffers {
            let block_offset = buffer.block_num * self.superblock.block_size as u64;
            self.device
                .write_at(block_offset, &buffer.data)
                .map_err(|_| FsError::DiskError)?;
            debug!("Applied buffer update for block {}", buffer.block_num);
        }

        Ok(())
    }

    /// Write a commit record to the log
    fn write_commit_record(&self, lsn: u64) -> FsResult<()> {
        let commit_header = LogRecordHeader::new(
            log_types::COMMIT,
            0, // Length of commit record
            self.current_cycle,
            0, // Client ID
        );

        let mut commit_data = commit_header.to_bytes().to_vec();
        commit_data.extend_from_slice(&lsn.to_be_bytes());

        let log_offset = self.log_start_block * self.superblock.block_size as u64 + lsn;
        self.device
            .write_at(log_offset, &commit_data)
            .map_err(|_| FsError::DiskError)?;

        Ok(())
    }

    /// Calculate the byte offset of an inode on disk
    fn calculate_inode_offset(&self, ino: u64) -> FsResult<u64> {
        let sb = &self.superblock;

        // Calculate AG number and inode within AG
        let ag_number = ino >> (sb.ag_block_log + sb.inode_per_block_log);
        let inode_in_ag = ino & ((1 << (sb.ag_block_log + sb.inode_per_block_log)) - 1);

        // AG start offset
        let ag_start = ag_number * (sb.ag_blocks as u64) * (sb.block_size as u64);

        // Inode offset within AG
        let block_in_ag = inode_in_ag >> sb.inode_per_block_log;
        let inode_in_block = inode_in_ag & ((1 << sb.inode_per_block_log) - 1);

        let offset = ag_start
            + block_in_ag * (sb.block_size as u64)
            + inode_in_block * (sb.inode_size as u64);

        Ok(offset)
    }

    /// Recover from the journal on startup
    pub fn recover(&mut self) -> FsResult<()> {
        info!("Starting journal recovery...");

        let block_size = self.superblock.block_size as u64;
        let mut last_lsn = 0;
        let mut highest_cycle = 0;

        // Scan for the most recent log record header to find the head
        for i in 0..self.log_size_blocks {
            let offset = (self.log_start_block + i) * block_size;
            let mut header_buf = [0u8; LogRecordHeader::SIZE];
            self.device
                .read_at(offset, &mut header_buf)
                .map_err(|_| FsError::DiskError)?;

            let cycle = u32::from_be_bytes(header_buf[0..4].try_into().unwrap());
            if cycle > 0 && cycle < 0xFFFFFFFF {
                let lsn = self.make_lsn(cycle, i);
                if cycle > highest_cycle {
                    highest_cycle = cycle;
                    last_lsn = lsn;
                } else if cycle == highest_cycle && lsn > last_lsn {
                    last_lsn = lsn;
                }
            }
        }

        if last_lsn > 0 {
            self.current_cycle = self.lsn_cycle(last_lsn);
            self.head_block = (self.lsn_block(last_lsn) + 1) % self.log_size_blocks;
            info!("Journal recovery: found head at LSN 0x{:x}", last_lsn);

            // In a real implementation we would now scan backwards for the tail
            // and replay all committed transactions from tail to head.
            warn!(
                "Log replay is not fully implemented: replaying transactions requires parsing log \
                 ops"
            );
        }

        info!("Journal recovery completed");
        Ok(())
    }

    /// Shutdown the journal, ensuring all transactions are committed
    pub fn shutdown(&mut self) -> FsResult<()> {
        info!("Shutting down journal...");

        // Commit any pending transactions
        let pending_txs: Vec<u64> = self.active_transactions.keys().cloned().collect();
        for tx_id in pending_txs {
            warn!("Forcing commit of pending transaction 0x{:x}", tx_id);
            if let Err(e) = self.commit_transaction(tx_id) {
                error!(
                    "Error committing pending transaction 0x{:x}: {:?}",
                    tx_id, e
                );
            }
        }

        // Write unmount record
        self.write_unmount_record()?;

        info!("Journal shutdown completed");
        Ok(())
    }

    /// Write an unmount record to the log
    fn write_unmount_record(&mut self) -> FsResult<()> {
        let unmount_header = LogRecordHeader::new(
            log_types::UNMOUNT,
            0, // Length
            self.current_cycle,
            0, // Client ID
        );

        let unmount_data = unmount_header.to_bytes();
        self.write_log_data(&unmount_data)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_record_header() {
        let header = LogRecordHeader::new(1, 100, 1, 0);
        let bytes = header.to_bytes();
        assert_eq!(bytes.len(), LogRecordHeader::SIZE);
    }
}
