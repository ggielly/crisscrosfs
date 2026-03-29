//! XFS VFS filesystem implementation.
//!
//! This module implements the `VfsFileSystem` trait for XFS.

use std::sync::{Arc, Mutex};

use fs_abstraction::{
    BlockDevice,
    FsCapabilities,
    FsError,
    FsResult,
    VfsDirEntry,
    VfsFileInfo,
    VfsFileSystem,
    VfsVolumeInfo,
};
use tracing::{debug, trace, warn};
use xfs_rs::{Inode, Superblock};

use crate::{
    cache::XfsCache,
    directory::{find_entry_by_name, parse_directory_entries},
    inode::{inode_to_file_info, is_directory, is_symlink},
    journal::Journal,
    read_ops::{read_file_data, read_symlink_target},
    write_ops::WriteOperations,
};

/// XFS Virtual File System implementation.
///
/// This struct wraps the XFS parsing library and provides the VFS interface.
pub struct XfsVfs {
    /// Block device containing the filesystem
    device: Arc<dyn BlockDevice>,

    /// Parsed superblock
    superblock: Superblock,

    /// Filesystem capabilities
    capabilities: FsCapabilities,

    /// Cache manager
    cache: XfsCache,

    /// Writer for write operations (if not read-only)
    writer: Option<Arc<dyn BlockDevice>>,

    /// Journal for write transactions
    journal: Arc<Mutex<Option<Journal>>>,
}

impl XfsVfs {
    /// Create a new XFS VFS instance from a block device.
    ///
    /// This reads and validates the superblock.
    pub fn new(device: Arc<dyn BlockDevice>) -> FsResult<Self> {
        Self::with_options(device, true)
    }

    /// Create a new XFS VFS instance with options.
    ///
    /// # Arguments
    /// * `device` - Block device containing the XFS filesystem
    /// * `read_only` - If true, refuse write operations
    pub fn with_options(device: Arc<dyn BlockDevice>, read_only: bool) -> FsResult<Self> {
        // Read superblock (first 512 bytes)
        let mut sb_buf = [0u8; 512];
        device.read_at(0, &mut sb_buf)?;

        // Validate magic
        if &sb_buf[0..4] != b"XFSB" {
            return Err(FsError::InvalidMagic);
        }

        // Parse superblock
        let superblock = Superblock::parse(&sb_buf).map_err(|_| FsError::Corrupted)?;

        // Build capabilities
        let mut capabilities = FsCapabilities::xfs();
        capabilities.read_only = read_only;

        let writer = if read_only {
            None
        } else {
            Some(device.clone())
        };

        // Initialize journal if write-enabled
        let journal = if !read_only {
            match Journal::new(device.clone(), superblock.clone()) {
                Ok(j) => Arc::new(Mutex::new(Some(j))),
                Err(e) => {
                    tracing::warn!(
                        "Failed to initialize journal: {:?}. Continuing without journal support.",
                        e
                    );
                    Arc::new(Mutex::new(None))
                }
            }
        } else {
            Arc::new(Mutex::new(None))
        };

        Ok(Self {
            device,
            superblock,
            capabilities,
            cache: XfsCache::new(),
            writer,
            journal,
        })
    }

    /// Get the superblock.
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    /// Get block size.
    pub fn block_size(&self) -> u32 {
        self.superblock.block_size
    }

    /// Check if filesystem has ftype in directory entries.
    pub fn has_ftype(&self) -> bool {
        self.superblock.has_ftype()
    }

    /// Check if filesystem uses bigtime format for timestamps.
    pub fn has_bigtime(&self) -> bool {
        self.superblock.has_bigtime()
    }

    /// Read an inode from disk or cache.
    fn read_inode_internal(&self, ino: u64) -> FsResult<Inode> {
        // Check cache first
        if let Some(cached) = self.cache.get_inode(ino) {
            return Ok(cached);
        }

        // Calculate inode location
        let inode_offset = self.calculate_inode_offset(ino)?;
        let inode_size = self.superblock.inode_size as usize;

        // Read inode data
        let mut buf = vec![0u8; inode_size];
        self.device.read_at(inode_offset, &mut buf)?;

        // Parse inode
        let inode = Inode::parse(&buf, inode_size).map_err(|_| FsError::Corrupted)?;

        // Cache it
        self.cache.put_inode(ino, inode.clone());

        Ok(inode)
    }

    /// Calculate the byte offset of an inode on disk.
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

    /// Read a filesystem block.
    fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
        let offset = block_num * self.superblock.block_size as u64;
        let mut buf = vec![0u8; self.superblock.block_size as usize];
        self.device.read_at(offset, &mut buf)?;
        Ok(buf)
    }

    /// Read directory entries for an inode.
    fn read_directory_internal(&self, ino: u64) -> FsResult<Vec<VfsDirEntry>> {
        // Check cache first
        if let Some(cached) = self.cache.get_directory(ino) {
            return Ok(cached);
        }

        let inode = self.read_inode_internal(ino)?;

        if !is_directory(&inode) {
            return Err(FsError::NotADirectory);
        }

        let entries = parse_directory_entries(
            &inode,
            ino,
            self.has_ftype(),
            self.block_size(),
            self.superblock.is_v5(),
            |block| self.read_block(block),
        )?;

        // Cache the entries
        self.cache.put_directory(ino, entries.clone());

        Ok(entries)
    }

    /// Resolve a single path component.
    fn lookup_internal(&self, parent_ino: u64, name: &str) -> FsResult<u64> {
        trace!("lookup_internal: parent={}, name='{}'", parent_ino, name);
        let entries = self.read_directory_internal(parent_ino)?;

        match find_entry_by_name(&entries, name) {
            Some(e) => {
                trace!("lookup found ino {} for '{}'", e.ino, name);
                Ok(e.ino)
            }
            None => {
                debug!("lookup: '{}' NOT FOUND in parent {}", name, parent_ino);
                Err(FsError::NotFound)
            }
        }
    }

    /// Get a WriteOperations instance.
    fn get_write_ops(&self) -> FsResult<WriteOperations> {
        let writer = self.writer.as_ref().ok_or(FsError::ReadOnly)?;
        Ok(WriteOperations::new(writer.clone(), &self.superblock))
    }
}

impl VfsFileSystem for XfsVfs {
    fn fs_type(&self) -> &'static str {
        "xfs"
    }

    fn capabilities(&self) -> &FsCapabilities {
        &self.capabilities
    }

    fn root_inode(&self) -> u64 {
        self.superblock.root_inode
    }

    fn get_volume_info(&self) -> FsResult<VfsVolumeInfo> {
        let sb = &self.superblock;
        let block_size = sb.block_size as u64;
        let total_blocks = sb.total_blocks;

        // Free blocks from AG free block info (simplified)
        // A real implementation would sum AG free counts
        let free_blocks = sb.free_blocks;

        Ok(VfsVolumeInfo {
            total_bytes: total_blocks * block_size,
            free_bytes: free_blocks * block_size,
            available_bytes: free_blocks * block_size,
            total_inodes: sb.inode_count,
            free_inodes: sb.free_inodes,
            block_size: sb.block_size,
            max_filename_len: 255,
            fs_type: "xfs".to_string(),
            volume_label: {
                let label = String::from_utf8_lossy(&sb.name)
                    .trim_end_matches('\0')
                    .to_string();
                if label.is_empty() {
                    None
                } else {
                    Some(label)
                }
            },
            uuid: Some(sb.uuid),
        })
    }

    fn stat(&self, ino: u64) -> FsResult<VfsFileInfo> {
        let inode = self.read_inode_internal(ino)?;
        Ok(inode_to_file_info(
            ino,
            &inode,
            self.block_size(),
            self.has_bigtime(),
        ))
    }

    fn lookup(&self, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo> {
        debug!("lookup: parent={}, name='{}'", parent_ino, name);
        let child_ino = self.lookup_internal(parent_ino, name)?;
        trace!("lookup found ino: {}", child_ino);
        self.stat(child_ino)
    }

    fn resolve_path(&self, path: &str) -> FsResult<u64> {
        debug!("resolve_path: '{}'", path);
        // Normalize path
        let normalized = path.replace('\\', "/").trim_start_matches('/').to_string();

        // Check cache
        if let Some(cached) = self.cache.get_path(&normalized) {
            trace!("path cache hit: '{}' -> {}", normalized, cached);
            return Ok(cached);
        }

        trace!("path traversal needed for '{}'", normalized);
        // Handle root
        if normalized.is_empty() {
            return Ok(self.root_inode());
        }

        // Traverse path
        let mut current = self.root_inode();

        for component in normalized.split('/') {
            if component.is_empty() || component == "." {
                continue;
            }
            if component == ".." {
                // Would need parent tracking - simplified: stay at current
                continue;
            }

            // Check that current is a directory
            let inode = self.read_inode_internal(current)?;
            if !is_directory(&inode) {
                warn!(
                    "Component '{}' in '{}' is not a directory (ino {})",
                    component, normalized, current
                );
                return Err(FsError::NotADirectory);
            }

            current = self.lookup_internal(current, component)?;
        }

        trace!("resolved '{}' to {}", normalized, current);
        // Cache result
        self.cache.put_path(normalized, current);

        Ok(current)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let inode = self.read_inode_internal(ino)?;

        if is_directory(&inode) {
            return Err(FsError::IsADirectory);
        }

        read_file_data(&inode, offset, buf, self.block_size(), |block| {
            self.read_block(block)
        })
    }

    fn readdir(&self, ino: u64) -> FsResult<Vec<VfsDirEntry>> {
        self.read_directory_internal(ino)
    }

    fn readlink(&self, ino: u64) -> FsResult<String> {
        let inode = self.read_inode_internal(ino)?;

        if !is_symlink(&inode) {
            return Err(FsError::NotSupported);
        }

        read_symlink_target(&inode, self.block_size(), |block| self.read_block(block))
    }

    // Write operations - return ReadOnly by default (trait provides default impl)
    // These could be implemented by uncommenting and adding proper logic

    fn invalidate_inode(&self, ino: u64) {
        self.cache.invalidate_inode(ino);
    }

    fn write(&self, ino: u64, offset: u64, buf: &[u8]) -> FsResult<usize> {
        let ops = self.get_write_ops()?;
        let written = ops.write_file_data(ino, offset, buf)?;

        // Journal the operation.  Failures are logged but not propagated — the
        // disk write already succeeded and returning an error would falsely
        // signal to the caller that no bytes were written.
        if let Ok(mut journal_guard) = self.journal.try_lock() {
            if let Some(ref mut journal) = *journal_guard {
                let tx_id = journal.begin_transaction();
                let block_num = offset / self.superblock.block_size as u64;
                let result = journal
                    .add_buffer_update(tx_id, block_num, buf.to_vec())
                    .and_then(|_| journal.commit_transaction(tx_id));
                if let Err(e) = result {
                    warn!("journal write log failed (disk write succeeded): {:?}", e);
                }
            }
        }

        self.invalidate_inode(ino);
        Ok(written)
    }

    fn create_file(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        debug!(
            "create_file: parent={}, name='{}', mode=0o{:o}",
            parent_ino, name, mode
        );

        let ops = self.get_write_ops()?;
        let full_mode = 0o100000 | (mode & 0o7777); // S_IFREG + permissions
        let ino = ops.create_entry(parent_ino, name, full_mode as u16)?;

        // Journal the operation.  Failures are logged but not propagated — the
        // inode was already created on disk.
        if let Ok(mut journal_guard) = self.journal.try_lock() {
            if let Some(ref mut journal) = *journal_guard {
                let tx_id = journal.begin_transaction();
                let result = journal
                    .add_directory_op(tx_id, parent_ino, name.to_string(), ino, true)
                    .and_then(|_| journal.commit_transaction(tx_id));
                if let Err(e) = result {
                    warn!("journal create_file log failed (disk write succeeded): {:?}", e);
                }
            }
        }

        debug!("created file ino: {}", ino);
        self.cache.invalidate_directory(parent_ino);
        self.stat(ino)
    }

    fn create_directory(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        debug!(
            "create_directory: parent={}, name='{}', mode=0o{:o}",
            parent_ino, name, mode
        );
        let ops = self.get_write_ops()?;
        let full_mode = 0o040000 | (mode & 0o7777); // S_IFDIR + permissions
        let ino = ops.create_entry(parent_ino, name, full_mode as u16)?;

        // Journal the operation.  Failures are logged but not propagated — the
        // directory was already created on disk.
        if let Ok(mut journal_guard) = self.journal.try_lock() {
            if let Some(ref mut journal) = *journal_guard {
                let tx_id = journal.begin_transaction();
                let result = journal
                    .add_directory_op(tx_id, parent_ino, name.to_string(), ino, true)
                    .and_then(|_| journal.commit_transaction(tx_id));
                if let Err(e) = result {
                    warn!("journal create_directory log failed (disk write succeeded): {:?}", e);
                }
            }
        }

        debug!("created directory ino: {}", ino);
        self.cache.invalidate_directory(parent_ino);
        self.stat(ino)
    }

    fn set_size(&self, ino: u64, size: u64) -> FsResult<()> {
        let ops = self.get_write_ops()?;
        ops.truncate_file(ino, size)?;

        // Journal the operation.  Failures are logged but not propagated — the
        // inode size was already changed on disk.
        if let Ok(mut journal_guard) = self.journal.try_lock() {
            if let Some(ref mut journal) = *journal_guard {
                let tx_id = journal.begin_transaction();
                // ops.read_inode and journal methods use different error types;
                // handle them in separate steps rather than one and_then chain.
                if let Ok(inode) = ops.read_inode(ino) {
                    let data = inode.core.to_bytes();
                    let result = journal
                        .add_inode_update(tx_id, ino, data)
                        .and_then(|_| journal.commit_transaction(tx_id));
                    if let Err(e) = result {
                        warn!("journal set_size log failed (disk write succeeded): {:?}", e);
                    }
                }
            }
        }

        self.invalidate_inode(ino);
        Ok(())
    }

    fn set_times(
        &self,
        ino: u64,
        atime: Option<fs_abstraction::VfsTimestamp>,
        mtime: Option<fs_abstraction::VfsTimestamp>,
    ) -> FsResult<()> {
        let ops = self.get_write_ops()?;
        let a = atime.map(|t| t.secs);
        let m = mtime.map(|t| t.secs);
        ops.set_times(ino, None, a, m)?;

        // Journal the operation.  Failures are logged but not propagated — the
        // timestamps were already updated on disk.
        if let Ok(mut journal_guard) = self.journal.try_lock() {
            if let Some(ref mut journal) = *journal_guard {
                let tx_id = journal.begin_transaction();
                if let Ok(inode) = ops.read_inode(ino) {
                    let data = inode.core.to_bytes();
                    let result = journal
                        .add_inode_update(tx_id, ino, data)
                        .and_then(|_| journal.commit_transaction(tx_id));
                    if let Err(e) = result {
                        warn!("journal set_times log failed (disk write succeeded): {:?}", e);
                    }
                }
            }
        }

        self.invalidate_inode(ino);
        Ok(())
    }

    fn rename(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        _flags: fs_abstraction::RenameFlags,
    ) -> FsResult<()> {
        let ops = self.get_write_ops()?;

        // Resolve the target inode BEFORE mutating the directory.  After
        // rename_entry() moves the entry out of old_parent, looking up
        // old_name there correctly returns NotFound — which the original code
        // then mistakenly propagated as an error to the caller even though
        // the rename had already succeeded on disk.
        let target_ino =
            ops.find_entry_inode(&ops.read_inode(old_parent)?, old_name)?;

        ops.rename_entry(old_parent, old_name, new_parent, new_name)?;

        // Journal the operation.  Failures are logged but not propagated — the
        // rename already happened on disk.
        if let Ok(mut journal_guard) = self.journal.try_lock() {
            if let Some(ref mut journal) = *journal_guard {
                let tx_id = journal.begin_transaction();
                let result = journal
                    .add_directory_op(tx_id, old_parent, old_name.to_string(), target_ino, false)
                    .and_then(|_| journal.add_directory_op(
                        tx_id,
                        new_parent,
                        new_name.to_string(),
                        target_ino,
                        true,
                    ))
                    .and_then(|_| journal.commit_transaction(tx_id));
                if let Err(e) = result {
                    warn!("journal rename log failed (disk write succeeded): {:?}", e);
                }
            }
        }

        self.cache.invalidate_directory(old_parent);
        if old_parent != new_parent {
            self.cache.invalidate_directory(new_parent);
        }
        Ok(())
    }

    fn unlink(&self, parent_ino: u64, name: &str, target_ino: u64) -> FsResult<()> {
        let ops = self.get_write_ops()?;
        ops.delete_entry(parent_ino, name, target_ino)?;

        // Journal the operation.  Failures are logged but not propagated — the
        // entry was already removed from disk.
        if let Ok(mut journal_guard) = self.journal.try_lock() {
            if let Some(ref mut journal) = *journal_guard {
                let tx_id = journal.begin_transaction();
                let result = journal
                    .add_directory_op(tx_id, parent_ino, name.to_string(), target_ino, false)
                    .and_then(|_| journal.commit_transaction(tx_id));
                if let Err(e) = result {
                    warn!("journal unlink log failed (disk write succeeded): {:?}", e);
                }
            }
        }

        self.cache.invalidate_directory(parent_ino);
        self.invalidate_inode(target_ino);
        Ok(())
    }

    fn invalidate_all_caches(&self) {
        self.cache.invalidate_all();
    }
}

// Ensure XfsVfs is Send + Sync
static_assertions::assert_impl_all!(XfsVfs: Send, Sync);

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use fs_abstraction::{BlockDevice, FsError, FsResult, RenameFlags, VfsFileSystem};

    use super::*;

    // ── Minimal read/write in-memory block device ─────────────────────────

    struct InMemoryDevice {
        data: std::sync::RwLock<Vec<u8>>,
    }

    impl InMemoryDevice {
        fn new(data: Vec<u8>) -> Self {
            Self { data: std::sync::RwLock::new(data) }
        }
    }

    impl BlockDevice for InMemoryDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
            let data = self.data.read().unwrap();
            let offset = offset as usize;
            if offset >= data.len() {
                return Ok(0);
            }
            let len = buf.len().min(data.len() - offset);
            buf[..len].copy_from_slice(&data[offset..offset + len]);
            Ok(len)
        }

        fn write_at(&self, offset: u64, input: &[u8]) -> FsResult<usize> {
            let mut data = self.data.write().unwrap();
            let end = offset as usize + input.len();
            if end > data.len() {
                data.resize(end, 0);
            }
            data[offset as usize..end].copy_from_slice(input);
            Ok(input.len())
        }

        fn size(&self) -> u64 {
            self.data.read().unwrap().len() as u64
        }
    }

    // ── Minimal valid XFS v4 superblock ───────────────────────────────────

    /// Returns a 512-byte buffer containing a minimal, parse-valid XFS v4
    /// superblock.  All fields not listed below are zero.
    fn minimal_sb_buf() -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        buf[0x000..0x004].copy_from_slice(&0x58465342u32.to_be_bytes()); // magic
        buf[0x004..0x008].copy_from_slice(&4096u32.to_be_bytes()); // block_size
        buf[0x008..0x010].copy_from_slice(&100u64.to_be_bytes()); // total_blocks
        buf[0x054..0x058].copy_from_slice(&100u32.to_be_bytes()); // ag_blocks
        buf[0x058..0x05C].copy_from_slice(&1u32.to_be_bytes()); // ag_count
        buf[0x064..0x066].copy_from_slice(&4u16.to_be_bytes()); // version
        buf[0x066..0x068].copy_from_slice(&512u16.to_be_bytes()); // sector_size
        buf[0x068..0x06A].copy_from_slice(&256u16.to_be_bytes()); // inode_size
        buf[0x06A..0x06C].copy_from_slice(&16u16.to_be_bytes()); // inodes_per_block
        buf[0x078] = 12; // block_log  = log2(4096)
        buf[0x079] = 9; // sector_log = log2(512)
        buf[0x07A] = 8; // inode_log  = log2(256)
        buf[0x07B] = 4; // inode_per_block_log = log2(16)
        buf[0x07C] = 7; // ag_block_log = ceil(log2(100))
        buf
    }

    /// Create a read-only `XfsVfs` backed by a minimal in-memory image.
    fn make_read_only_xfs() -> XfsVfs {
        let mut device_data = vec![0u8; 4096 * 100]; // 100 blocks
        let sb = minimal_sb_buf();
        device_data[..sb.len()].copy_from_slice(&sb);
        XfsVfs::new(Arc::new(InMemoryDevice::new(device_data)))
            .expect("minimal v4 superblock must parse")
    }

    // ── Read-only guard: every write operation must return ReadOnly ────────
    // These tests document that get_write_ops() enforces the read-only flag
    // at the VFS boundary, before any actual disk mutation can occur.

    #[test]
    fn write_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.write(128, 0, b"data"), Err(FsError::ReadOnly)));
    }

    #[test]
    fn create_file_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.create_file(128, "foo", 0o644), Err(FsError::ReadOnly)));
    }

    #[test]
    fn create_directory_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.create_directory(128, "dir", 0o755), Err(FsError::ReadOnly)));
    }

    #[test]
    fn set_size_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.set_size(128, 0), Err(FsError::ReadOnly)));
    }

    #[test]
    fn set_times_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.set_times(128, None, None), Err(FsError::ReadOnly)));
    }

    #[test]
    fn unlink_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.unlink(128, "foo", 129), Err(FsError::ReadOnly)));
    }

    #[test]
    fn rename_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(
            fs.rename(128, "foo", 128, "bar", RenameFlags::default()),
            Err(FsError::ReadOnly)
        ));
    }
}
