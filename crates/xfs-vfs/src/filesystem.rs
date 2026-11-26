//! XFS VFS filesystem implementation.
//!
//! This module implements the `VfsFileSystem` trait for XFS.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

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
use parking_lot::{Mutex, RwLock};
use tracing::{debug, trace};
use xfs_rs::{Inode, Superblock};

use crate::{
    allocator::BlockAllocator,
    cache::XfsCache,
    directory::{find_entry_by_name, parse_directory_entries},
    inode::{inode_to_file_info, is_directory, is_symlink},
    inode_allocator::InodeAllocator,
    io::{filesystem_size, read_exact_at},
    journal::Journal,
    read_ops::{read_file_data, read_symlink_target},
    writer::WriteContext,
};

/// XFS Virtual File System implementation.
///
/// This struct wraps the XFS parsing library and provides the VFS interface.
pub struct XfsVfs {
    /// Block device containing the filesystem
    device: Arc<dyn BlockDevice>,

    /// Parsed superblock
    superblock: Superblock,

    /// Checked filesystem size in bytes (`total_blocks * block_size`).
    filesystem_size: u64,

    /// Filesystem capabilities
    capabilities: FsCapabilities,

    /// Cache manager
    cache: XfsCache,

    /// Serializes readers against metadata mutations.
    operation_lock: RwLock<()>,

    /// Real XFS journal, present only for writable instances.
    journal: Option<Mutex<Journal>>,

    /// Cached superblock free-space counters updated after each transaction.
    free_blocks: AtomicU64,
    free_inodes: AtomicU64,

    /// Whether the on-disk log showed an unclean unmount when this instance
    /// was opened (replayed for writable mounts, still pending for read-only).
    unclean_unmount: bool,
}

impl XfsVfs {
    /// Create a new structurally read-only XFS VFS instance.
    ///
    /// This reads and validates the superblock.  It is an alias for
    /// [`Self::read_only`].
    pub fn new(device: Arc<dyn BlockDevice>) -> FsResult<Self> {
        Self::read_only(device)
    }

    /// Create a filesystem instance that cannot perform write operations.
    pub fn read_only(device: Arc<dyn BlockDevice>) -> FsResult<Self> {
        Self::with_options(device, true)
    }

    /// Create a new XFS VFS instance with options.
    ///
    /// Writable construction requires a writable device and a valid internal
    /// XFS log. Recovery completes before the instance is returned. Unsupported
    /// metadata features and directory geometries fail with
    /// [`FsError::NotSupported`] or [`FsError::NotImplemented`] before the
    /// transaction is committed.
    pub fn with_options(device: Arc<dyn BlockDevice>, read_only: bool) -> FsResult<Self> {
        if !read_only && !device.supports_write() {
            return Err(FsError::ReadOnly);
        }

        // Read the fixed 512-byte superblock probe exactly.  It contains the
        // complete v4/v5 superblock structure and advertises the logical sector
        // size needed for v5 CRC verification.
        let device_size = device.size();
        let mut probe = [0u8; 512];
        read_exact_at(device.as_ref(), 0, &mut probe, device_size)?;
        if &probe[0..4] != b"XFSB" {
            return Err(FsError::InvalidMagic);
        }
        let advertised = Superblock::parse(&probe).map_err(|_| FsError::Corrupted)?;

        let sector_size = usize::from(advertised.sector_size);
        let sb_buf = if sector_size == probe.len() {
            probe.to_vec()
        } else {
            let mut buf = vec![0u8; sector_size];
            read_exact_at(device.as_ref(), 0, &mut buf, device_size)?;
            buf
        };
        let superblock = Superblock::parse(&sb_buf).map_err(|_| FsError::Corrupted)?;
        if superblock.in_progress != 0 {
            return Err(FsError::NotSupported);
        }

        // Verify v5 CRC over the full logical sector, not just the probe.
        if superblock.is_v5() {
            superblock.verify_crc(&sb_buf)?;
        }

        let filesystem_size = filesystem_size(superblock.total_blocks, superblock.block_size)?;
        if filesystem_size > device_size {
            return Err(FsError::Corrupted);
        }
        if !read_only {
            let quota_flags = sb_buf.get(0xB8..0xBA).ok_or(FsError::BufferTooSmall)?;
            let quota_offsets: &[usize] = if superblock.is_v5() {
                &[0xA0, 0xA8, 0xE8]
            } else {
                &[0xA0, 0xA8, 0xB0]
            };
            let mut quotas_enabled = false;
            for offset in quota_offsets {
                let raw = sb_buf
                    .get(*offset..*offset + 8)
                    .ok_or(FsError::BufferTooSmall)?;
                let ino = u64::from_be_bytes(raw.try_into().map_err(|_| FsError::Corrupted)?);
                if ino != 0 && ino != u64::MAX {
                    quotas_enabled = true;
                    break;
                }
            }
            if superblock.realtime_blocks != 0
                || superblock.features_log_incompat != 0
                || quotas_enabled
                || quota_flags.iter().any(|byte| *byte != 0)
            {
                return Err(FsError::NotSupported);
            }
        }

        let mut unclean_unmount = false;
        let journal = if read_only {
            // Read-only mounts never replay the log, so transactions that were
            // only committed to the log stay invisible: the volume shows the
            // pre-crash view. Say so instead of silently presenting stale
            // metadata (Linux calls this `norecovery`).
            match Journal::new(device.clone(), superblock.clone()) {
                Ok(probe) => match probe.log_needs_replay() {
                    Ok(true) => {
                        unclean_unmount = true;
                        tracing::warn!(
                            "XFS log needs replay but the volume is mounted read-only; recent \
                             metadata changes are not visible (like Linux 'norecovery')"
                        );
                    }
                    Ok(false) => {}
                    Err(error) => {
                        tracing::debug!(?error, "cannot inspect the XFS log on a read-only mount")
                    }
                },
                Err(error) => {
                    tracing::debug!(?error, "cannot inspect the XFS log on a read-only mount")
                }
            }
            None
        } else {
            let mut journal = Journal::new(device.clone(), superblock.clone())?;
            journal.recover()?;
            unclean_unmount = journal.was_replayed();
            Some(Mutex::new(journal))
        };

        let mut capabilities = FsCapabilities::xfs();
        capabilities.read_only = read_only;
        if !read_only {
            // Attribute-fork mutations are not implemented by the writer.
            capabilities.supports_xattr = false;
            tracing::warn!(
                "writable image mounts are experimental: unsupported metadata fails closed, so \
                 keep a backup of the image and validate it with xfs_repair"
            );
        }
        let free_blocks = AtomicU64::new(superblock.free_blocks);
        let free_inodes = AtomicU64::new(superblock.free_inodes);

        Ok(Self {
            device,
            superblock,
            filesystem_size,
            capabilities,
            cache: XfsCache::new(),
            operation_lock: RwLock::new(()),
            journal,
            free_blocks,
            free_inodes,
            unclean_unmount,
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

    fn refresh_superblock_counters(&self) -> FsResult<()> {
        let mut raw = vec![0u8; self.superblock.sector_size as usize];
        read_exact_at(self.device.as_ref(), 0, &mut raw, self.filesystem_size)?;
        let sb = Superblock::parse(&raw).map_err(|_| FsError::Corrupted)?;
        if sb.is_v5() {
            sb.verify_crc(&raw)?;
        }
        self.free_blocks.store(sb.free_blocks, Ordering::Release);
        self.free_inodes.store(sb.free_inodes, Ordering::Release);
        Ok(())
    }

    /// Flush all pending writes. Read-only instances perform no device I/O.
    pub fn sync(&self) -> FsResult<()> {
        let _guard = self.operation_lock.write();
        if self.capabilities.read_only {
            return Ok(());
        }
        self.device.flush().map_err(|_| FsError::DiskError)
    }

    /// Append a clean unmount record after all metadata is durable.
    pub fn shutdown(&self) -> FsResult<()> {
        let _guard = self.operation_lock.write();
        if self.capabilities.read_only {
            return Ok(());
        }
        if let Some(journal) = &self.journal {
            journal.lock().shutdown()?;
        }
        self.device.flush().map_err(|_| FsError::DiskError)
    }

    fn mutate_with_writer<T>(
        &self,
        operation: impl FnOnce(&mut WriteContext<'_>) -> FsResult<T>,
    ) -> FsResult<T> {
        let _guard = self.operation_lock.write();
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let journal = self.journal.as_ref().ok_or(FsError::ReadOnly)?;
        let mut journal = journal.lock();
        if journal.is_poisoned() {
            return Err(FsError::ReadOnly);
        }
        let allocator = BlockAllocator::new(self.device.clone(), self.superblock.clone())?;
        let inode_allocator = InodeAllocator::new(self.device.clone(), self.superblock.clone())?;
        let mut writer = WriteContext {
            device: self.device.clone(),
            superblock: self.superblock.clone(),
            filesystem_size: self.filesystem_size,
            journal: &mut journal,
            allocator,
            inode_allocator,
            block_overlay: Default::default(),
            data_rollback: Default::default(),
        };
        let result = operation(&mut writer);
        drop(writer);
        drop(journal);
        self.cache.invalidate_all();
        if result.is_ok() {
            if let Err(error) = self.refresh_superblock_counters() {
                debug!(%error, "failed to refresh superblock counters after mutation");
            }
        }
        result
    }

    /// Read an inode from disk or cache.
    fn read_inode_internal(&self, ino: u64) -> FsResult<Inode> {
        // Check cache first
        if let Some(cached) = self.cache.get_inode(ino) {
            return Ok(cached);
        }

        // sb_icount counts allocated inodes, not the highest inode number:
        // sparse inode chunks may legitimately contain numbers above it.  AG
        // and block geometry below, followed by inode magic/CRC, validate the
        // address instead.
        //
        // Calculate inode location and read exactly one complete inode.  The
        // shared helper checks both total_blocks and the backing device size.
        let inode_offset = self.calculate_inode_offset(ino)?;
        let inode_size = self.superblock.inode_size as usize;
        let mut buf = vec![0u8; inode_size];
        read_exact_at(
            self.device.as_ref(),
            inode_offset,
            &mut buf,
            self.filesystem_size,
        )?;

        // Parse inode and, on v5 filesystems, verify its CRC.
        let inode = Inode::parse(&buf, inode_size).map_err(|_| FsError::Corrupted)?;
        if self.superblock.is_v5() {
            inode.verify_crc(&buf, inode_size)?;
            if inode.core.version >= 3 && inode.core.ino != 0 && inode.core.ino != ino {
                return Err(FsError::Corrupted);
            }
        }

        // Cache it
        self.cache.put_inode(ino, inode.clone());

        Ok(inode)
    }

    /// Calculate the byte offset of an inode on disk.
    fn calculate_inode_offset(&self, ino: u64) -> FsResult<u64> {
        let sb = &self.superblock;

        // Calculate AG number and inode within AG.
        let shift = u32::from(sb.ag_block_log) + u32::from(sb.inode_per_block_log);
        if shift >= 64 {
            return Err(FsError::Corrupted);
        }

        let ag_number = ino >> shift;
        if ag_number >= u64::from(sb.ag_count) {
            return Err(FsError::InodeNotFound);
        }
        let inode_in_ag = ino & ((1u64 << shift) - 1);

        // AG start offset
        let ag_start = ag_number
            .checked_mul(u64::from(sb.ag_blocks))
            .and_then(|blocks| blocks.checked_mul(u64::from(sb.block_size)))
            .ok_or(FsError::ArithmeticOverflow)?;

        // Inode offset within AG
        if u32::from(sb.inode_per_block_log) >= 64 {
            return Err(FsError::Corrupted);
        }
        let block_in_ag = inode_in_ag >> sb.inode_per_block_log;
        if block_in_ag >= u64::from(sb.ag_blocks) {
            return Err(FsError::InodeNotFound);
        }
        let inode_in_block = inode_in_ag & ((1u64 << sb.inode_per_block_log) - 1);

        let offset = ag_start
            .checked_add(
                block_in_ag
                    .checked_mul(u64::from(sb.block_size))
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .and_then(|o| {
                inode_in_block
                    .checked_mul(u64::from(sb.inode_size))
                    .and_then(|i| o.checked_add(i))
            })
            .ok_or(FsError::ArithmeticOverflow)?;

        Ok(offset)
    }

    /// Read a filesystem block.
    fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
        if block_num >= self.superblock.total_blocks {
            return Err(FsError::Corrupted);
        }
        let block_size =
            usize::try_from(self.superblock.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        let offset = block_num
            .checked_mul(u64::from(self.superblock.block_size))
            .ok_or(FsError::ArithmeticOverflow)?;

        let mut buf = vec![0u8; block_size];
        read_exact_at(self.device.as_ref(), offset, &mut buf, self.filesystem_size)?;
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
            self.superblock.total_blocks,
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
}

impl VfsFileSystem for XfsVfs {
    fn fs_type(&self) -> &'static str {
        "xfs"
    }

    fn sync(&self) -> FsResult<()> {
        XfsVfs::sync(self)
    }

    fn shutdown(&self) -> FsResult<()> {
        XfsVfs::shutdown(self)
    }

    fn unclean_unmount(&self) -> bool {
        self.unclean_unmount
    }

    fn capabilities(&self) -> &FsCapabilities {
        &self.capabilities
    }

    fn root_inode(&self) -> u64 {
        self.superblock.root_inode
    }

    fn get_volume_info(&self) -> FsResult<VfsVolumeInfo> {
        let _guard = self.operation_lock.read();
        let sb = &self.superblock;
        let block_size = sb.block_size as u64;
        let total_blocks = sb.total_blocks;

        // Free blocks from AG free block info (simplified).  Validate the
        // counters before exposing byte counts to callers.
        let free_blocks = self.free_blocks.load(Ordering::Acquire);
        let free_inodes = self.free_inodes.load(Ordering::Acquire);
        let inode_shift = u32::from(sb.ag_block_log) + u32::from(sb.inode_per_block_log);
        let inodes_per_ag = 1u64
            .checked_shl(inode_shift)
            .ok_or(FsError::ArithmeticOverflow)?;
        let total_inodes = u64::from(sb.ag_count)
            .checked_mul(inodes_per_ag)
            .ok_or(FsError::ArithmeticOverflow)?;
        if free_blocks > total_blocks
            || free_inodes > total_inodes
            || sb.inode_count > total_inodes
            || free_inodes > total_inodes - sb.inode_count
        {
            return Err(FsError::Corrupted);
        }
        let free_bytes = free_blocks
            .checked_mul(block_size)
            .ok_or(FsError::ArithmeticOverflow)?;

        Ok(VfsVolumeInfo {
            total_bytes: self.filesystem_size,
            free_bytes,
            available_bytes: free_bytes,
            total_inodes,
            free_inodes,
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
        let _guard = self.operation_lock.read();
        let inode = self.read_inode_internal(ino)?;
        inode_to_file_info(
            ino,
            &inode,
            self.block_size(),
            self.has_bigtime(),
            self.filesystem_size,
        )
    }

    fn lookup(&self, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo> {
        let _guard = self.operation_lock.read();
        debug!("lookup: parent={}, name='{}'", parent_ino, name);
        let child_ino = self.lookup_internal(parent_ino, name)?;
        trace!("lookup found ino: {}", child_ino);
        let inode = self.read_inode_internal(child_ino)?;
        inode_to_file_info(
            child_ino,
            &inode,
            self.block_size(),
            self.has_bigtime(),
            self.filesystem_size,
        )
    }

    fn resolve_path(&self, path: &str) -> FsResult<u64> {
        let _guard = self.operation_lock.read();
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

        // Traverse with an explicit ancestor stack.  ".." must not depend on a
        // directory entry being present or trustworthy, and cannot escape root.
        let mut stack = vec![self.root_inode()];
        let require_directory = |ino: u64| -> FsResult<()> {
            let inode = self.read_inode_internal(ino)?;
            if !is_directory(&inode) {
                return Err(FsError::NotADirectory);
            }
            Ok(())
        };

        for component in normalized.split('/') {
            match component {
                "" => continue,
                "." => require_directory(*stack.last().expect("root is always present"))?,
                ".." => {
                    require_directory(*stack.last().expect("root is always present"))?;
                    if stack.len() > 1 {
                        stack.pop();
                    }
                }
                name => {
                    let parent = *stack.last().expect("root is always present");
                    require_directory(parent)?;
                    let child = self.lookup_internal(parent, name)?;
                    stack.push(child);
                }
            }
        }

        let current = *stack.last().expect("root is always present");
        trace!("resolved '{}' to {}", normalized, current);
        self.cache.put_path(normalized, current);
        Ok(current)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let _guard = self.operation_lock.read();
        let inode = self.read_inode_internal(ino)?;

        if is_directory(&inode) {
            return Err(FsError::IsADirectory);
        }

        read_file_data(
            &inode,
            offset,
            buf,
            self.block_size(),
            self.superblock.total_blocks,
            self.superblock.is_v5(),
            |block| self.read_block(block),
        )
    }

    fn readdir(&self, ino: u64) -> FsResult<Vec<VfsDirEntry>> {
        let _guard = self.operation_lock.read();
        self.read_directory_internal(ino)
    }

    fn readlink(&self, ino: u64) -> FsResult<String> {
        let _guard = self.operation_lock.read();
        let inode = self.read_inode_internal(ino)?;

        if !is_symlink(&inode) {
            return Err(FsError::NotSupported);
        }

        read_symlink_target(
            &inode,
            self.block_size(),
            self.superblock.total_blocks,
            self.superblock.is_v5(),
            |block| self.read_block(block),
        )
    }

    // Writable mutations are serialized and journaled. Unsupported metadata
    // features fail explicitly; read-only instances continue to return
    // ReadOnly.
    fn invalidate_inode(&self, ino: u64) {
        let _guard = self.operation_lock.write();
        self.cache.invalidate_inode(ino);
    }

    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> FsResult<usize> {
        let _guard = self.operation_lock.write();
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let journal = self.journal.as_ref().ok_or(FsError::ReadOnly)?;
        let mut journal = journal.lock();
        if journal.is_poisoned() {
            return Err(FsError::ReadOnly);
        }
        let allocator = BlockAllocator::new(self.device.clone(), self.superblock.clone())?;
        let inode_allocator = InodeAllocator::new(self.device.clone(), self.superblock.clone())?;
        let mut writer = WriteContext {
            device: self.device.clone(),
            superblock: self.superblock.clone(),
            filesystem_size: self.filesystem_size,
            journal: &mut journal,
            allocator,
            inode_allocator,
            block_overlay: Default::default(),
            data_rollback: Default::default(),
        };
        let result = writer.write_data(ino, offset, data);
        drop(writer);
        drop(journal);
        self.cache.invalidate_all();
        if result.is_ok() {
            if let Err(error) = self.refresh_superblock_counters() {
                debug!(%error, "failed to refresh superblock counters after mutation");
            }
        }
        result
    }

    fn create_file(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        self.mutate_with_writer(|writer| writer.create_file(parent_ino, name, mode))
    }

    fn create_directory(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        self.mutate_with_writer(|writer| writer.create_directory(parent_ino, name, mode))
    }

    fn create_symlink(
        &self,
        parent_ino: u64,
        name: &str,
        target: &str,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        self.mutate_with_writer(|writer| writer.create_symlink(parent_ino, name, target))
    }

    fn link(
        &self,
        target_ino: u64,
        parent_ino: u64,
        name: &str,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        self.mutate_with_writer(|writer| writer.link_inode(target_ino, parent_ino, name))
    }

    fn set_size(&self, ino: u64, size: u64) -> FsResult<()> {
        let _guard = self.operation_lock.write();
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let journal = self.journal.as_ref().ok_or(FsError::ReadOnly)?;
        let mut journal = journal.lock();
        if journal.is_poisoned() {
            return Err(FsError::ReadOnly);
        }
        let allocator = BlockAllocator::new(self.device.clone(), self.superblock.clone())?;
        let inode_allocator = InodeAllocator::new(self.device.clone(), self.superblock.clone())?;
        let mut writer = WriteContext {
            device: self.device.clone(),
            superblock: self.superblock.clone(),
            filesystem_size: self.filesystem_size,
            journal: &mut journal,
            allocator,
            inode_allocator,
            block_overlay: Default::default(),
            data_rollback: Default::default(),
        };
        let result = writer.set_size(ino, size);
        drop(writer);
        drop(journal);
        self.cache.invalidate_all();
        if result.is_ok() {
            if let Err(error) = self.refresh_superblock_counters() {
                debug!(%error, "failed to refresh superblock counters after mutation");
            }
        }
        result
    }

    fn set_times(
        &self,
        ino: u64,
        atime: Option<fs_abstraction::VfsTimestamp>,
        mtime: Option<fs_abstraction::VfsTimestamp>,
    ) -> FsResult<()> {
        self.mutate_with_writer(|writer| writer.set_times(ino, atime, mtime))
    }

    fn rename(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        flags: fs_abstraction::RenameFlags,
    ) -> FsResult<()> {
        self.mutate_with_writer(|writer| {
            writer.rename_inode(old_parent, old_name, new_parent, new_name, flags)
        })
    }

    fn unlink(&self, parent_ino: u64, name: &str, target_ino: u64) -> FsResult<()> {
        self.mutate_with_writer(|writer| writer.unlink_inode(parent_ino, name, target_ino))
    }

    fn invalidate_all_caches(&self) {
        let _guard = self.operation_lock.write();
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
        max_read: std::sync::atomic::AtomicUsize,
        read_calls: std::sync::atomic::AtomicUsize,
        write_calls: std::sync::atomic::AtomicUsize,
        writable: bool,
    }

    impl InMemoryDevice {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: std::sync::RwLock::new(data),
                max_read: std::sync::atomic::AtomicUsize::new(usize::MAX),
                read_calls: std::sync::atomic::AtomicUsize::new(0),
                write_calls: std::sync::atomic::AtomicUsize::new(0),
                writable: true,
            }
        }

        fn with_max_read(self, max_read: usize) -> Self {
            self.max_read
                .store(max_read, std::sync::atomic::Ordering::SeqCst);
            self
        }
    }

    impl BlockDevice for InMemoryDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
            use std::sync::atomic::Ordering;

            self.read_calls.fetch_add(1, Ordering::SeqCst);
            let data = self.data.read().unwrap();
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            if offset >= data.len() {
                return Ok(0);
            }
            let max_read = self.max_read.load(std::sync::atomic::Ordering::SeqCst);
            let len = buf.len().min(data.len() - offset).min(max_read);
            buf[..len].copy_from_slice(&data[offset..offset + len]);
            Ok(len)
        }

        fn write_at(&self, offset: u64, input: &[u8]) -> FsResult<usize> {
            use std::sync::atomic::Ordering;

            self.write_calls.fetch_add(1, Ordering::SeqCst);
            let mut data = self.data.write().unwrap();
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            let end = offset
                .checked_add(input.len())
                .ok_or(FsError::ArithmeticOverflow)?;
            if end > data.len() {
                data.resize(end, 0);
            }
            data[offset..end].copy_from_slice(input);
            Ok(input.len())
        }

        fn size(&self) -> u64 {
            self.data.read().unwrap().len() as u64
        }

        fn supports_write(&self) -> bool {
            self.writable
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
        buf[0x038..0x040].copy_from_slice(&128u64.to_be_bytes()); // root_inode
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
        buf[0x080..0x088].copy_from_slice(&1024u64.to_be_bytes()); // inode_count
        buf
    }

    /// Create a read-only `XfsVfs` backed by a minimal in-memory image.
    fn make_read_only_xfs() -> XfsVfs {
        let mut device_data = vec![0u8; 4096 * 100]; // 100 blocks
        let sb = minimal_sb_buf();
        device_data[..sb.len()].copy_from_slice(&sb);
        XfsVfs::read_only(Arc::new(InMemoryDevice::new(device_data)))
            .expect("minimal v4 superblock must parse")
    }

    fn synthetic_inode(mode: u16) -> Inode {
        let mut raw = vec![0u8; 256];
        raw[0..2].copy_from_slice(&0x494Eu16.to_be_bytes());
        raw[2..4].copy_from_slice(&mode.to_be_bytes());
        raw[4] = 2;
        raw[5] = 1; // local fork
        Inode::parse(&raw, raw.len()).unwrap()
    }

    fn synthetic_entry(
        name: &str,
        ino: u64,
        file_type: fs_abstraction::VfsFileType,
    ) -> VfsDirEntry {
        VfsDirEntry {
            name: name.to_string(),
            ino,
            file_type,
            offset: 0,
        }
    }

    fn minimal_image() -> Vec<u8> {
        let mut data = vec![0u8; 4096 * 100];
        let sb = minimal_sb_buf();
        data[..sb.len()].copy_from_slice(&sb);
        data
    }

    #[test]
    fn superblock_partial_read_is_retried_and_truncated_device_is_rejected() {
        let mut data = minimal_image();
        let sb = minimal_sb_buf();
        data[..sb.len()].copy_from_slice(&sb);
        let short = Arc::new(InMemoryDevice::new(data.clone()).with_max_read(511));
        assert!(XfsVfs::read_only(short).is_ok());

        let truncated = Arc::new(InMemoryDevice::new(data[..4096].to_vec()));
        assert!(matches!(
            XfsVfs::read_only(truncated),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn inode_and_block_zero_progress_are_rejected() {
        let device = Arc::new(InMemoryDevice::new(minimal_image()));
        let fs = XfsVfs::read_only(device.clone()).unwrap();

        device
            .max_read
            .store(0, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(fs.read_inode_internal(1), Err(FsError::Corrupted)));
        assert!(matches!(fs.read_block(1), Err(FsError::Corrupted)));
    }

    #[test]
    fn sparse_inode_number_above_allocated_count_is_not_rejected_by_icount() {
        let fs = make_read_only_xfs();
        assert_eq!(fs.superblock().inode_count, 1024);

        // sb_icount is an allocation count, not an inode-number upper bound.
        // Inode 1500 is inside AG 0's geometry even though only 1024 inodes are
        // allocated.  Its zero-filled slot must fail inode magic validation,
        // not be rejected as out-of-range solely because 1500 > sb_icount.
        assert!(matches!(
            fs.read_inode_internal(1500),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn out_of_range_blocks_are_rejected_before_device_io() {
        use std::sync::atomic::Ordering;

        let device = Arc::new(InMemoryDevice::new(minimal_image()));
        let fs = XfsVfs::read_only(device.clone()).unwrap();
        let reads = device.read_calls.load(Ordering::SeqCst);

        assert!(matches!(fs.read_block(100), Err(FsError::Corrupted)));
        assert!(matches!(fs.read_block(u64::MAX), Err(FsError::Corrupted)));
        assert_eq!(device.read_calls.load(Ordering::SeqCst), reads);
    }

    #[test]
    fn resolve_path_uses_an_ancestor_stack_for_dotdot() {
        use fs_abstraction::VfsFileType;

        let fs = make_read_only_xfs();
        fs.cache.put_inode(128, synthetic_inode(0o040755));
        fs.cache.put_inode(129, synthetic_inode(0o040755));
        fs.cache.put_inode(130, synthetic_inode(0o100644));
        fs.cache.put_directory(
            128,
            vec![synthetic_entry("dir", 129, VfsFileType::Directory)],
        );
        // Deliberately omit "." and "..": lexical traversal must not need them.
        fs.cache.put_directory(
            129,
            vec![synthetic_entry("file", 130, VfsFileType::RegularFile)],
        );

        assert_eq!(fs.resolve_path("/dir/../dir/file").unwrap(), 130);
        assert_eq!(fs.resolve_path("/../../dir/./file").unwrap(), 130);
        assert_eq!(fs.resolve_path("/..").unwrap(), 128);
        assert!(matches!(
            fs.resolve_path("/dir/file/.."),
            Err(FsError::NotADirectory)
        ));
    }

    #[test]
    fn writable_construction_checks_device_and_internal_log() {
        use std::sync::atomic::Ordering;

        let mut read_only_device = InMemoryDevice::new(minimal_image());
        read_only_device.writable = false;
        let read_only_device = Arc::new(read_only_device);
        assert!(matches!(
            XfsVfs::with_options(read_only_device.clone(), false),
            Err(FsError::ReadOnly)
        ));
        assert_eq!(read_only_device.read_calls.load(Ordering::SeqCst), 0);

        let device = Arc::new(InMemoryDevice::new(minimal_image()));
        assert!(matches!(
            XfsVfs::with_options(device.clone(), false),
            Err(FsError::NotSupported)
        ));
        assert!(device.read_calls.load(Ordering::SeqCst) > 0);
        assert_eq!(device.write_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn read_only_instance_never_calls_device_write() {
        use std::sync::atomic::Ordering;

        let device = Arc::new(InMemoryDevice::new(minimal_image()));
        let fs = XfsVfs::read_only(device.clone()).unwrap();
        assert!(fs.capabilities().read_only);
        assert!(matches!(fs.write(130, 0, b"x"), Err(FsError::ReadOnly)));
        assert!(matches!(
            fs.create_symlink(128, "link", "target"),
            Err(FsError::ReadOnly)
        ));
        assert!(matches!(
            fs.link(130, 128, "hardlink"),
            Err(FsError::ReadOnly)
        ));
        assert_eq!(device.write_calls.load(Ordering::SeqCst), 0);
    }

    // ── Read-only guard: every write operation must return ReadOnly ────────
    // These tests document that the VFS boundary refuses mutation before any
    // actual disk write can occur.

    #[test]
    fn write_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.write(128, 0, b"data"), Err(FsError::ReadOnly)));
    }

    #[test]
    fn create_file_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(
            fs.create_file(128, "foo", 0o644),
            Err(FsError::ReadOnly)
        ));
    }

    #[test]
    fn create_directory_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(
            fs.create_directory(128, "dir", 0o755),
            Err(FsError::ReadOnly)
        ));
    }

    #[test]
    fn set_size_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(fs.set_size(128, 0), Err(FsError::ReadOnly)));
    }

    #[test]
    fn set_times_on_read_only_returns_read_only() {
        let fs = make_read_only_xfs();
        assert!(matches!(
            fs.set_times(128, None, None),
            Err(FsError::ReadOnly)
        ));
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
