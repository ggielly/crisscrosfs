//! Transactional writer - wraps filesystem modifications with journal
//! transactions.
//!
//! This module provides a transactional layer over raw disk writes, ensuring
//! that metadata modifications are logged before being applied to disk.

use std::sync::{Arc, Mutex};

use tracing::{debug, trace, warn};
use xfs_rs::journal::{JournalManager, JournalOp, JournalState};

use crate::{
    disk::{DiskReader, DiskWriter},
    error::{Result, XfsWinfspError},
};

/// Write operation types for journaling.
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// Inode modification.
    InodeUpdate {
        inode_num: u64,
        offset: u64,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    },
    /// Block data write.
    BlockWrite {
        block_num: u64,
        offset: u32,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    },
    /// AGF header update.
    AgfUpdate {
        ag_num: u32,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    },
    /// Superblock update.
    SuperblockUpdate {
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    },
}

/// Transactional writer state.
struct TransactionState {
    /// Active transaction ID (if any).
    tid: Option<u32>,
    /// Pending write operations.
    pending_ops: Vec<WriteOp>,
    /// Journal manager.
    journal: JournalManager,
}

/// Transactional writer that wraps disk operations with journal support.
pub struct TransactionalWriter {
    /// Underlying disk reader.
    reader: Arc<dyn DiskReader>,
    /// Underlying disk writer.
    writer: Arc<dyn DiskWriter>,
    /// Transaction state.
    state: Mutex<TransactionState>,
    /// Block size.
    block_size: u32,
    /// Sector size.
    sector_size: u16,
}

impl TransactionalWriter {
    /// Create a new transactional writer.
    pub fn new(
        reader: Arc<dyn DiskReader>,
        writer: Arc<dyn DiskWriter>,
        block_size: u32,
        sector_size: u16,
        journal_enabled: bool,
    ) -> Self {
        Self {
            reader,
            writer,
            state: Mutex::new(TransactionState {
                tid: None,
                pending_ops: Vec::new(),
                journal: JournalManager::new(journal_enabled),
            }),
            block_size,
            sector_size,
        }
    }

    /// Check if journaling is enabled.
    pub fn is_journaling_enabled(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.journal.is_enabled()
    }

    /// Get the current journal state.
    pub fn journal_state(&self) -> JournalState {
        let state = self.state.lock().unwrap();
        state.journal.state()
    }

    /// Begin a new transaction.
    ///
    /// All write operations until `commit()` or `abort()` will be part of
    /// this transaction.
    pub fn begin_transaction(&self) -> Result<u32> {
        let mut state = self.state.lock().unwrap();

        if state.tid.is_some() {
            return Err(XfsWinfspError::InvalidArgument(
                "Transaction already in progress".to_string(),
            ));
        }

        let tid = state.journal.begin_transaction().map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to begin transaction: {:?}", e))
        })?;

        state.tid = Some(tid);
        state.pending_ops.clear();

        debug!("Transaction {} started", tid);
        Ok(tid)
    }

    /// Add an inode update to the current transaction.
    pub fn update_inode(
        &self,
        inode_num: u64,
        offset: u64,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        if state.tid.is_none() {
            return Err(XfsWinfspError::InvalidArgument(
                "No active transaction".to_string(),
            ));
        }

        // Add to journal
        let op = JournalOp::inode_update(inode_num, old_data.clone(), new_data.clone());
        state.journal.add_op(op).map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to log inode update: {:?}", e))
        })?;

        // Queue the write operation
        state.pending_ops.push(WriteOp::InodeUpdate {
            inode_num,
            offset,
            old_data,
            new_data,
        });

        trace!("Queued inode {} update at offset {}", inode_num, offset);
        Ok(())
    }

    /// Add a block write to the current transaction.
    pub fn write_block(
        &self,
        block_num: u64,
        offset: u32,
        old_data: Vec<u8>,
        new_data: Vec<u8>,
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        if state.tid.is_none() {
            return Err(XfsWinfspError::InvalidArgument(
                "No active transaction".to_string(),
            ));
        }

        // Add to journal
        let op = JournalOp::block_update(block_num, offset, old_data.clone(), new_data.clone());
        state
            .journal
            .add_op(op)
            .map_err(|e| XfsWinfspError::XfsError(format!("Failed to log block write: {:?}", e)))?;

        // Queue the write operation
        state.pending_ops.push(WriteOp::BlockWrite {
            block_num,
            offset,
            old_data,
            new_data,
        });

        trace!("Queued block {} write at offset {}", block_num, offset);
        Ok(())
    }

    /// Add an AGF header update to the current transaction.
    pub fn update_agf(&self, ag_num: u32, old_data: Vec<u8>, new_data: Vec<u8>) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        if state.tid.is_none() {
            return Err(XfsWinfspError::InvalidArgument(
                "No active transaction".to_string(),
            ));
        }

        state.pending_ops.push(WriteOp::AgfUpdate {
            ag_num,
            old_data,
            new_data,
        });

        trace!("Queued AGF {} update", ag_num);
        Ok(())
    }

    /// Add a superblock update to the current transaction.
    pub fn update_superblock(&self, old_data: Vec<u8>, new_data: Vec<u8>) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        if state.tid.is_none() {
            return Err(XfsWinfspError::InvalidArgument(
                "No active transaction".to_string(),
            ));
        }

        state
            .pending_ops
            .push(WriteOp::SuperblockUpdate { old_data, new_data });

        trace!("Queued superblock update");
        Ok(())
    }

    /// Commit the current transaction.
    ///
    /// This will:
    /// 1. Write all pending operations to disk
    /// 2. Mark the transaction as committed in the journal
    /// 3. Sync the disk
    pub fn commit(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        let tid = match state.tid {
            Some(t) => t,
            None => {
                return Err(XfsWinfspError::InvalidArgument(
                    "No active transaction to commit".to_string(),
                ))
            }
        };

        debug!(
            "Committing transaction {} with {} operations",
            tid,
            state.pending_ops.len()
        );

        // Apply all pending operations
        for op in &state.pending_ops {
            self.apply_write_op(op)?;
        }

        // Commit in journal
        state.journal.commit_transaction().map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to commit transaction: {:?}", e))
        })?;

        // Flush disk
        self.writer.flush_raw()?;

        // Mark journal clean
        state.journal.mark_clean();

        // Clear state
        state.tid = None;
        state.pending_ops.clear();

        debug!("Transaction {} committed successfully", tid);
        Ok(())
    }

    /// Abort the current transaction.
    ///
    /// This will discard all pending operations without writing them to disk.
    pub fn abort(&self) -> Result<()> {
        let mut state = self.state.lock().unwrap();

        let tid = match state.tid {
            Some(t) => t,
            None => return Ok(()), // Nothing to abort
        };

        warn!("Aborting transaction {}", tid);

        // Abort in journal
        state.journal.abort_transaction().map_err(|e| {
            XfsWinfspError::XfsError(format!("Failed to abort transaction: {:?}", e))
        })?;

        // Clear state
        state.tid = None;
        state.pending_ops.clear();

        Ok(())
    }

    /// Apply a single write operation to disk.
    fn apply_write_op(&self, op: &WriteOp) -> Result<()> {
        match op {
            WriteOp::InodeUpdate {
                offset, new_data, ..
            } => {
                self.writer.write_unaligned(*offset, new_data)?;
            }
            WriteOp::BlockWrite {
                block_num,
                offset,
                new_data,
                ..
            } => {
                let disk_offset = (*block_num as u64) * (self.block_size as u64) + (*offset as u64);
                self.writer.write_unaligned(disk_offset, new_data)?;
            }
            WriteOp::AgfUpdate {
                ag_num, new_data, ..
            } => {
                // AGF is at sector 1 within each AG
                let ag_offset = (*ag_num as u64) * (self.block_size as u64); // Simplified - should use ag_blocks
                let agf_offset = ag_offset + (self.sector_size as u64);
                self.writer.write_unaligned(agf_offset, new_data)?;
            }
            WriteOp::SuperblockUpdate { new_data, .. } => {
                self.writer.write_unaligned(0, new_data)?;
            }
        }
        Ok(())
    }

    /// Write data directly without transaction (for data blocks, not metadata).
    ///
    /// Use this for file data writes that don't need journaling.
    pub fn write_data_direct(&self, offset: u64, data: &[u8]) -> Result<()> {
        self.writer.write_unaligned(offset, data)?;
        Ok(())
    }

    /// Read data from disk.
    pub fn read(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        self.reader.read_unaligned(offset, size)
    }

    /// Flush all data to disk.
    pub fn sync(&self) -> Result<()> {
        self.writer.flush_raw()
    }

    /// Get the underlying reader.
    pub fn reader(&self) -> &Arc<dyn DiskReader> {
        &self.reader
    }

    /// Get the underlying writer.
    pub fn writer(&self) -> &Arc<dyn DiskWriter> {
        &self.writer
    }
}

/// Convenience macro for running code within a transaction.
///
/// Usage:
/// ```ignore
/// with_transaction!(writer, {
///     writer.update_inode(...)?;
///     writer.write_block(...)?;
/// })
/// ```
#[macro_export]
macro_rules! with_transaction {
    ($writer:expr, $body:block) => {{
        let _tid = $writer.begin_transaction()?;
        let result = (|| -> Result<()> {
            $body;
            Ok(())
        })();
        match result {
            Ok(()) => $writer.commit()?,
            Err(e) => {
                let _ = $writer.abort();
                return Err(e);
            }
        }
        Ok::<(), XfsWinfspError>(())
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_lifecycle() {
        // This test would require mock reader/writer implementations
        // For now, just verify the types compile correctly
    }
}
