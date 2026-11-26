//! Checked write batching for the XFS VFS.
//!
//! A transaction stages complete metadata buffers in memory, preserves their
//! original bytes for best-effort rollback, and never accepts a short device
//! write as success.  The XFS journal layer is responsible for write-ahead
//! durability; this module is the atomic apply/rollback primitive used after a
//! log record has been committed.

use std::collections::BTreeMap;

use fs_abstraction::{BlockDevice, FsError, FsResult};

use crate::{
    io::{read_exact_at, write_exact_at},
    journal::Journal,
};

/// Metadata buffer classification used when a committed batch is logged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum MetadataKind {
    Btree,
    Agf,
    Agfl,
    Agi,
    Inode,
    Directory,
    Superblock,
    Data,
}

#[derive(Debug)]
#[allow(dead_code)]
struct StagedBuffer {
    offset: u64,
    data: Vec<u8>,
    original: Vec<u8>,
    kind: MetadataKind,
}

/// A coalesced set of positional writes.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub(crate) struct WriteBatch {
    buffers: BTreeMap<u64, StagedBuffer>,
    inode_items: BTreeMap<u64, xfs_rs::log_format::LogInodeItem>,
}

#[allow(dead_code)]
impl WriteBatch {
    pub(crate) fn new() -> Self {
        Self {
            buffers: BTreeMap::new(),
            inode_items: BTreeMap::new(),
        }
    }

    /// Stage a complete buffer after validating it against both the filesystem
    /// and backing-device limits. Re-staging the same offset replaces the data
    /// while retaining the true pre-transaction image.
    pub(crate) fn stage(
        &mut self,
        device: &dyn BlockDevice,
        offset: u64,
        data: Vec<u8>,
        kind: MetadataKind,
        filesystem_limit: u64,
    ) -> FsResult<()> {
        if let Some(existing) = self.buffers.get(&offset) {
            if existing.data.len() != data.len() {
                return Err(FsError::InvalidArgument);
            }
            self.buffers.insert(
                offset,
                StagedBuffer {
                    offset,
                    data,
                    original: existing.original.clone(),
                    kind,
                },
            );
            return Ok(());
        }

        let mut original = vec![0u8; data.len()];
        read_exact_at(device, offset, &mut original, filesystem_limit)?;
        self.buffers.insert(
            offset,
            StagedBuffer {
                offset,
                data,
                original,
                kind,
            },
        );
        Ok(())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buffers.is_empty()
    }

    /// Read a buffer from the pending batch, falling back to the device.
    pub(crate) fn read_buffer(
        &self,
        device: &dyn BlockDevice,
        offset: u64,
        len: usize,
        filesystem_limit: u64,
    ) -> FsResult<Vec<u8>> {
        if let Some(staged) = self.buffers.get(&offset) {
            if staged.data.len() != len {
                return Err(FsError::InvalidArgument);
            }
            return Ok(staged.data.clone());
        }
        let mut raw = vec![0u8; len];
        read_exact_at(device, offset, &mut raw, filesystem_limit)?;
        Ok(raw)
    }

    /// Add or replace the logical inode item for an inode modified in this
    /// batch.
    pub(crate) fn add_inode(&mut self, item: xfs_rs::log_format::LogInodeItem) {
        self.inode_items.insert(item.ino, item);
    }

    pub(crate) fn log_inode_items(&self) -> Vec<xfs_rs::log_format::LogInodeItem> {
        self.inode_items.values().cloned().collect()
    }

    /// Convert staged metadata buffers to real XFS log items.
    pub(crate) fn log_items(&self) -> FsResult<Vec<xfs_rs::log_format::LogBufferItem>> {
        use xfs_rs::log_format::{LogBufferItem, LogBufferType};

        let mut items = Vec::with_capacity(self.buffers.len());
        for buffer in self.buffers.values() {
            if buffer.offset % 512 != 0 || buffer.data.len() % 512 != 0 {
                return Err(FsError::InvalidArgument);
            }
            let dirty_chunks: Vec<usize> = buffer
                .data
                .chunks(128)
                .zip(buffer.original.chunks(128))
                .enumerate()
                .filter_map(|(index, (new, old))| (new != old).then_some(index))
                .collect();
            if dirty_chunks.is_empty() {
                continue;
            }
            let buffer_type = match buffer.kind {
                MetadataKind::Btree => LogBufferType::Btree,
                MetadataKind::Agf => LogBufferType::Agf,
                MetadataKind::Agfl => LogBufferType::Agfl,
                MetadataKind::Agi => LogBufferType::Agi,
                MetadataKind::Inode => LogBufferType::Dino,
                MetadataKind::Directory => directory_buffer_type(&buffer.data),
                MetadataKind::Superblock => LogBufferType::Sb,
                MetadataKind::Data => return Err(FsError::InvalidArgument),
            };
            items.push(LogBufferItem {
                block_num: buffer.offset / 512,
                data: buffer.data.clone(),
                buffer_type,
                inode_buffer: buffer.kind == MetadataKind::Inode,
                dirty_chunks,
            });
        }
        Ok(items)
    }

    /// Commit the staged metadata through the XFS log.
    pub(crate) fn commit(&self, journal: &mut Journal) -> FsResult<u64> {
        journal.commit(self.log_items()?, self.log_inode_items())
    }

    /// Apply every staged buffer and flush the device. If an I/O error occurs,
    /// restore already-written buffers in reverse order on a best-effort basis.
    pub(crate) fn apply(&self, device: &dyn BlockDevice, filesystem_limit: u64) -> FsResult<()> {
        let mut applied = Vec::with_capacity(self.buffers.len());
        for buffer in self.buffers.values() {
            if let Err(error) =
                write_exact_at(device, buffer.offset, &buffer.data, filesystem_limit)
            {
                self.rollback(device, filesystem_limit, &applied);
                return Err(error);
            }
            applied.push(buffer);
        }
        if let Err(error) = device.flush() {
            self.rollback(device, filesystem_limit, &applied);
            return Err(error);
        }
        Ok(())
    }

    fn rollback(&self, device: &dyn BlockDevice, filesystem_limit: u64, applied: &[&StagedBuffer]) {
        for buffer in applied.iter().rev() {
            if let Err(error) =
                write_exact_at(device, buffer.offset, &buffer.original, filesystem_limit)
            {
                tracing::error!(
                    offset = buffer.offset,
                    %error,
                    "failed to restore metadata buffer after write error"
                );
            }
        }
        let _ = device.flush();
    }
}

fn directory_buffer_type(data: &[u8]) -> xfs_rs::log_format::LogBufferType {
    use xfs_rs::{
        constants::{
            XFS_DIR2_BLOCK_MAGIC,
            XFS_DIR2_DATA_MAGIC,
            XFS_DIR2_FREE_MAGIC,
            XFS_DIR2_LEAFN_MAGIC,
            XFS_DIR2_LEAF_MAGIC,
            XFS_DIR2_NODE_MAGIC,
            XFS_DIR3_BLOCK_MAGIC,
            XFS_DIR3_DATA_MAGIC,
            XFS_DIR3_FREE_MAGIC,
            XFS_DIR3_LEAFN_MAGIC,
            XFS_DIR3_LEAF_MAGIC,
            XFS_DIR3_NODE_MAGIC,
        },
        log_format::LogBufferType,
    };

    if data.len() >= 4 {
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match magic {
            XFS_DIR2_BLOCK_MAGIC | XFS_DIR3_BLOCK_MAGIC => return LogBufferType::DirBlock,
            XFS_DIR2_DATA_MAGIC | XFS_DIR3_DATA_MAGIC => return LogBufferType::DirData,
            XFS_DIR2_FREE_MAGIC | XFS_DIR3_FREE_MAGIC => return LogBufferType::DirFree,
            _ => {}
        }
    }
    if data.len() >= 10 {
        let magic = u16::from_be_bytes([data[8], data[9]]);
        match magic {
            XFS_DIR2_LEAF_MAGIC | XFS_DIR3_LEAF_MAGIC => return LogBufferType::DirLeaf1,
            XFS_DIR2_LEAFN_MAGIC | XFS_DIR3_LEAFN_MAGIC => return LogBufferType::DirLeafN,
            XFS_DIR2_NODE_MAGIC | XFS_DIR3_NODE_MAGIC => return LogBufferType::DaNode,
            _ => {}
        }
    }
    LogBufferType::DirBlock
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, RwLock};

    use fs_abstraction::BlockDevice;

    use super::*;

    struct Device {
        data: RwLock<Vec<u8>>,
        max_write: std::sync::atomic::AtomicUsize,
        fail_flush: bool,
    }

    impl Device {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                data: RwLock::new(vec![0xAA; 128]),
                max_write: std::sync::atomic::AtomicUsize::new(usize::MAX),
                fail_flush: false,
            })
        }
    }

    impl BlockDevice for Device {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
            let data = self.data.read().unwrap();
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            let len = buf.len().min(data.len().saturating_sub(offset));
            buf[..len].copy_from_slice(&data[offset..offset + len]);
            Ok(len)
        }

        fn write_at(&self, offset: u64, input: &[u8]) -> FsResult<usize> {
            let mut data = self.data.write().unwrap();
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            let len = input
                .len()
                .min(self.max_write.load(std::sync::atomic::Ordering::SeqCst));
            data[offset..offset + len].copy_from_slice(&input[..len]);
            Ok(len)
        }

        fn size(&self) -> u64 {
            self.data.read().unwrap().len() as u64
        }

        fn flush(&self) -> FsResult<()> {
            if self.fail_flush {
                Err(FsError::DiskError)
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn staging_coalesces_and_preserves_original_bytes() {
        let device = Device::new();
        let mut batch = WriteBatch::new();
        batch
            .stage(
                device.as_ref(),
                8,
                b"first".to_vec(),
                MetadataKind::Data,
                128,
            )
            .unwrap();
        batch
            .stage(
                device.as_ref(),
                8,
                b"final".to_vec(),
                MetadataKind::Data,
                128,
            )
            .unwrap();
        assert_eq!(batch.buffers.len(), 1);
        batch.apply(device.as_ref(), 128).unwrap();
        assert_eq!(&device.data.read().unwrap()[8..13], b"final");
    }

    #[test]
    fn partial_writes_are_retried() {
        let device = Device::new();
        device
            .max_write
            .store(2, std::sync::atomic::Ordering::SeqCst);
        let mut batch = WriteBatch::new();
        batch
            .stage(
                device.as_ref(),
                4,
                b"abcdefgh".to_vec(),
                MetadataKind::Data,
                128,
            )
            .unwrap();
        batch.apply(device.as_ref(), 128).unwrap();
        assert_eq!(&device.data.read().unwrap()[4..12], b"abcdefgh");
    }

    #[test]
    fn apply_error_rolls_back_already_written_buffers() {
        let device = Device::new();
        device
            .max_write
            .store(0, std::sync::atomic::Ordering::SeqCst);
        let mut batch = WriteBatch::new();
        batch
            .stage(
                device.as_ref(),
                0,
                b"changed".to_vec(),
                MetadataKind::Data,
                128,
            )
            .unwrap();
        assert!(matches!(
            batch.apply(device.as_ref(), 128),
            Err(FsError::DiskError)
        ));
        assert!(device.data.read().unwrap().iter().all(|byte| *byte == 0xAA));
    }
}
