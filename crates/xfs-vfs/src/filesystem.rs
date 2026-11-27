//! XFS VFS filesystem implementation.
//!
//! This module implements the `VfsFileSystem` trait for XFS.

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
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
use xfs_rs::{btree::BmbtRoot, DataFork, Extent, Inode, Superblock};

use crate::{
    allocator::BlockAllocator,
    cache::{DirIndex, XfsCache},
    directory::{lookup_directory_entry, parse_directory_entries_checked},
    inode::{inode_to_file_info, is_directory, is_symlink},
    inode_allocator::InodeAllocator,
    io::{filesystem_size, read_exact_at, VfsBlockReader, XfsBtreeReader},
    journal::Journal,
    name_mangling::{mangle_str, unmangle},
    read_ops::{
        collect_extents_from_btree_checked,
        read_file_data,
        read_file_data_with_extents,
        read_symlink_target_with_uuid,
        validate_extents,
    },
    transaction::WriteBatch,
    writer::{DelallocBudget, PendingWrites, WriteContext, MAX_DELALLOC_BYTES},
};

struct PersistentAllocators {
    block: Mutex<BlockAllocator>,
    inode: Mutex<InodeAllocator>,
}

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

    /// Serializes namespace/metadata mutations and path-cache invalidation.
    /// Ordinary inode reads and buffered data writes do not take this lock.
    metadata_lock: RwLock<()>,

    /// Per-inode locks. The map retains stable lock identities for the mount
    /// lifetime; replacing an entry while users hold its Arc could allow two
    /// locks for one inode and break same-inode exclusion.
    inode_locks: Mutex<HashMap<u64, Arc<RwLock<()>>>>,

    /// Dirty data is keyed by inode because the VFS trait has no handle ID.
    /// Every access is made while holding that inode's lock; the map lock only
    /// guards the lookup so a writer never holds it across disk I/O.
    pending_writes: Mutex<HashMap<u64, Arc<Mutex<PendingWrites>>>>,
    delalloc_budget: DelallocBudget,

    /// Real XFS journal, present only for writable instances.
    journal: Option<Mutex<Journal>>,

    /// Persistent per-AG allocator state, reconstructed only after a failed
    /// transaction. Read-only mounts do not initialize allocators.
    allocators: Mutex<Option<PersistentAllocators>>,

    /// Open-handle pins protect unlinked inodes until their final close.
    pinned_inodes: Mutex<HashMap<u64, usize>>,
    case_insensitive_lookup: AtomicBool,

    /// Cached superblock free-space counters updated after each transaction.
    free_blocks: AtomicU64,
    free_inodes: AtomicU64,
    allocated_inodes: AtomicU64,

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
        let advertised = Superblock::parse(&probe)?;

        let sector_size = usize::from(advertised.sector_size);
        let sb_buf = if sector_size == probe.len() {
            probe.to_vec()
        } else {
            let mut buf = vec![0u8; sector_size];
            read_exact_at(device.as_ref(), 0, &mut buf, device_size)?;
            buf
        };
        let superblock = Superblock::parse(&sb_buf)?;
        if superblock.in_progress != 0 {
            return Err(FsError::NotSupported);
        }

        // Verify v5 CRC over the full logical sector, not just the probe.
        if superblock.is_v5() {
            superblock.verify_crc(&sb_buf)?;
        }
        superblock.validate_feature_support(read_only)?;

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
        let allocated_inodes = AtomicU64::new(superblock.inode_count);
        let allocators = if read_only {
            None
        } else {
            Some(PersistentAllocators {
                block: Mutex::new(BlockAllocator::new(device.clone(), superblock.clone())?),
                inode: Mutex::new(InodeAllocator::new(device.clone(), superblock.clone())?),
            })
        };

        Ok(Self {
            device,
            superblock,
            filesystem_size,
            capabilities,
            cache: XfsCache::new(),
            metadata_lock: RwLock::new(()),
            inode_locks: Mutex::new(HashMap::new()),
            pending_writes: Mutex::new(HashMap::new()),
            delalloc_budget: DelallocBudget::with_capacity(MAX_DELALLOC_BYTES),
            journal,
            allocators: Mutex::new(allocators),
            pinned_inodes: Mutex::new(HashMap::new()),
            case_insensitive_lookup: AtomicBool::new(false),
            free_blocks,
            free_inodes,
            allocated_inodes,
            unclean_unmount,
        })
    }

    /// Get the superblock.
    pub fn superblock(&self) -> &Superblock {
        &self.superblock
    }

    pub fn set_case_insensitive_lookup(&self, enabled: bool) {
        let _guard = self.metadata_lock.write();
        self.case_insensitive_lookup
            .store(enabled, Ordering::Release);
        self.cache.invalidate_paths();
    }

    fn clear_pending_locked(&self, ino: u64) {
        if let Some(pending) = self.pending_writes.lock().remove(&ino) {
            let bytes = pending
                .lock()
                .memory_bytes(usize::try_from(self.superblock.block_size).unwrap_or(0));
            self.delalloc_budget.release(bytes);
        }
    }

    /// Returns the dirty-buffer entry for one inode. Callers keep the inode
    /// lock, so the entry itself is only contended by concurrent readers.
    fn pending_entry(&self, ino: u64) -> Option<Arc<Mutex<PendingWrites>>> {
        self.pending_writes.lock().get(&ino).cloned()
    }

    fn pending_entry_or_insert(&self, ino: u64, disk_size: u64) -> Arc<Mutex<PendingWrites>> {
        let mut map = self.pending_writes.lock();
        map.entry(ino)
            .or_insert_with(|| Arc::new(Mutex::new(PendingWrites::with_size(disk_size))))
            .clone()
    }

    fn pending_size(&self, ino: u64, disk_size: u64) -> u64 {
        self.pending_entry(ino)
            .map_or(disk_size, |pending| pending.lock().size())
    }

    /// Return the stable lock identity for an inode. Geometry is checked before
    /// inserting into the map so arbitrary invalid inode numbers cannot grow
    /// it.
    fn inode_lock(&self, ino: u64) -> FsResult<Arc<RwLock<()>>> {
        self.calculate_inode_offset(ino)?;
        let mut locks = self.inode_locks.lock();
        Ok(locks
            .entry(ino)
            .or_insert_with(|| Arc::new(RwLock::new(())))
            .clone())
    }

    /// Acquire a deterministic set of per-inode locks. Callers must hold the
    /// metadata write lock, establishing the global order metadata -> inodes.
    fn lock_inodes(&self, inos: &[u64]) -> FsResult<Vec<Arc<RwLock<()>>>> {
        let sorted: std::collections::BTreeSet<_> = inos.iter().copied().collect();
        sorted.iter().map(|&ino| self.inode_lock(ino)).collect()
    }

    fn pin_inode(&self, ino: u64) -> FsResult<()> {
        let _guard = self.metadata_lock.read();
        let inode = self.read_inode_internal(ino)?;
        if inode.core.nlink == 0 {
            return Err(FsError::InodeNotFound);
        }
        *self.pinned_inodes.lock().entry(ino).or_insert(0) += 1;
        Ok(())
    }

    fn unpin_inode(&self, ino: u64) {
        let reclaim = {
            let mut pins = self.pinned_inodes.lock();
            let count = pins.get_mut(&ino).copied().unwrap_or(0);
            if count <= 1 {
                pins.remove(&ino);
                count == 1
            } else {
                *pins.get_mut(&ino).expect("checked above") = count - 1;
                false
            }
        };
        if !reclaim || self.capabilities.read_only {
            return;
        }
        let unlinked = {
            let _guard = self.metadata_lock.read();
            self.read_inode_internal(ino)
                .is_ok_and(|inode| inode.core.nlink == 0)
        };
        if !unlinked {
            return;
        }
        if let Err(error) = self.mutate_with_writer(&[ino], |writer| {
            if self.pinned_inodes.lock().contains_key(&ino) {
                return Ok(());
            }
            writer.reclaim_unlinked_inode(ino)?;
            self.clear_pending_locked(ino);
            Ok(())
        }) {
            tracing::error!(ino, %error, "failed to reclaim unlinked inode after final close");
        }
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

    /// Flush all pending writes. Read-only instances perform no device I/O.
    pub fn sync(&self) -> FsResult<()> {
        let _guard = self.metadata_lock.write();
        self.sync_locked()
    }

    /// Materialize one inode's buffered data. The VFS trait cannot identify
    /// open handles, so all handles for an inode share this pending set.
    pub fn flush_file(&self, ino: u64) -> FsResult<()> {
        let _metadata_guard = self.metadata_lock.write();
        if self.capabilities.read_only {
            return Ok(());
        }
        let lock = self.inode_lock(ino)?;
        let _inode_guard = lock.write();
        let mut batch = WriteBatch::new();
        let result = self.mutate_with_writer_locked(|writer| {
            if let Some(pending) = self.pending_entry(ino) {
                let pending = pending.lock();
                writer.stage_delalloc_to_size(ino, &pending, pending.size(), &mut batch)?;
                writer.commit_delalloc_batch(&mut batch)?;
            }
            Ok(())
        });
        if result.is_ok() {
            self.clear_pending_locked(ino);
        }
        result
    }

    /// Caller holds the metadata write lock. Pending inode locks are acquired
    /// in sorted order before any buffered write can race with flushing.
    fn sync_locked(&self) -> FsResult<()> {
        if self.capabilities.read_only {
            return Ok(());
        }
        let mut inos: Vec<_> = self.pending_writes.lock().keys().copied().collect();
        inos.sort_unstable();
        if inos.is_empty() {
            return self.device.flush().map_err(|_| FsError::DiskError);
        }
        let locks = self.lock_inodes(&inos)?;
        let _inode_guards: Vec<_> = locks.iter().map(|lock| lock.write()).collect();
        let mut completed = Vec::with_capacity(inos.len());
        let mut batch = WriteBatch::new();
        let result = self.mutate_with_writer_locked(|writer| {
            for &ino in &inos {
                if let Some(pending) = self.pending_entry(ino) {
                    let pending = pending.lock();
                    writer.stage_delalloc_to_size(ino, &pending, pending.size(), &mut batch)?;
                    completed.push(ino);
                }
            }
            writer.commit_delalloc_batch(&mut batch)?;
            Ok(())
        });
        for ino in completed {
            if result.is_ok() {
                self.clear_pending_locked(ino);
            }
        }
        result?;
        self.device.flush().map_err(|_| FsError::DiskError)
    }

    /// Append a clean unmount record after all metadata is durable.
    pub fn shutdown(&self) -> FsResult<()> {
        let _guard = self.metadata_lock.write();
        if self.capabilities.read_only {
            return Ok(());
        }
        self.sync_locked()?;
        if let Some(journal) = &self.journal {
            journal.lock().shutdown()?;
        }
        self.device.flush().map_err(|_| FsError::DiskError)
    }

    fn mutate_with_writer<T>(
        &self,
        inos: &[u64],
        operation: impl FnOnce(&mut WriteContext<'_>) -> FsResult<T>,
    ) -> FsResult<T> {
        let _metadata_guard = self.metadata_lock.write();
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let locks = self.lock_inodes(inos)?;
        let _inode_guards: Vec<_> = locks.iter().map(|lock| lock.write()).collect();
        self.mutate_with_writer_locked(operation)
    }

    /// Run a mutation while the caller holds the metadata write lock and all
    /// per-inode write locks for every existing inode the operation can modify.
    fn mutate_with_writer_locked<T>(
        &self,
        operation: impl FnOnce(&mut WriteContext<'_>) -> FsResult<T>,
    ) -> FsResult<T> {
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let journal = self.journal.as_ref().ok_or(FsError::ReadOnly)?;
        let mut journal = journal.lock();
        if journal.is_poisoned() {
            return Err(FsError::ReadOnly);
        }
        let mut allocators_guard = self.allocators.lock();
        let allocators = allocators_guard.as_ref().ok_or(FsError::ReadOnly)?;
        let block_allocator = allocators.block.lock();
        let inode_allocator = allocators.inode.lock();
        let pinned_inodes = self.pinned_inodes.lock().keys().copied().collect();
        let mut writer = WriteContext {
            device: self.device.clone(),
            superblock: self.superblock.clone(),
            filesystem_size: self.filesystem_size,
            journal: &mut journal,
            allocator: block_allocator,
            inode_allocator,
            block_overlay: Default::default(),
            data_rollback: Default::default(),
            staged_inodes: Default::default(),
            dirty_inodes: Default::default(),
            dirty_directories: Default::default(),
            dirty_blocks: Default::default(),
            pinned_inodes,
        };
        let result = operation(&mut writer);
        let dirty_inodes = std::mem::take(&mut writer.dirty_inodes);
        let dirty_directories = std::mem::take(&mut writer.dirty_directories);
        let dirty_blocks = std::mem::take(&mut writer.dirty_blocks);
        if result.is_ok() {
            self.free_blocks
                .store(writer.superblock.free_blocks, Ordering::Release);
            self.free_inodes
                .store(writer.superblock.free_inodes, Ordering::Release);
            self.allocated_inodes
                .store(writer.superblock.inode_count, Ordering::Release);
        }
        drop(writer);
        drop(journal);
        let rebuild_result = if result.is_err() {
            // An aborted operation may have changed in-memory allocator state
            // without committing it. Fail closed until fresh on-disk state is
            // loaded; never reuse a potentially inconsistent allocator.
            *allocators_guard = None;
            (|| {
                Ok::<_, FsError>(PersistentAllocators {
                    block: Mutex::new(BlockAllocator::new(
                        self.device.clone(),
                        self.superblock.clone(),
                    )?),
                    inode: Mutex::new(InodeAllocator::new(
                        self.device.clone(),
                        self.superblock.clone(),
                    )?),
                })
            })()
            .map(|allocators| {
                *allocators_guard = Some(allocators);
            })
        } else {
            Ok(())
        };
        self.invalidate_mutation_caches(&dirty_inodes, &dirty_directories, &dirty_blocks);
        rebuild_result?;
        result
    }

    fn invalidate_mutation_caches(
        &self,
        inodes: &std::collections::BTreeSet<u64>,
        directories: &std::collections::BTreeSet<u64>,
        blocks: &std::collections::BTreeSet<u64>,
    ) {
        let _cache_guard = self.cache.invalidation_write();
        if !inodes.is_empty() || !directories.is_empty() || !blocks.is_empty() {
            self.cache.advance_generation();
        }
        for ino in inodes {
            self.cache.invalidate_inode_metadata(*ino);
            if let Ok(offset) = self.calculate_inode_offset(*ino) {
                self.cache
                    .invalidate_inode_buffer(offset / u64::from(self.superblock.block_size));
            }
        }
        for ino in directories {
            self.cache.invalidate_directory(*ino);
        }
        if !directories.is_empty() {
            self.cache.path_cache.invalidate_all();
            self.cache.wide_path_cache.invalidate_all();
        }
        for block in blocks {
            self.cache.block_cache.invalidate(block);
        }
    }

    /// Read an inode from disk or cache. Inodes in the same filesystem block
    /// share one positional read and one immutable buffer.
    fn read_inode_internal(&self, ino: u64) -> FsResult<Arc<Inode>> {
        let generation = self.cache.generation();
        if let Some(cached) = self.cache.get_inode(ino) {
            return Ok(cached);
        }

        let inode_offset = self.calculate_inode_offset(ino)?;
        let inode_size = self.superblock.inode_size as usize;
        let block_size =
            usize::try_from(self.superblock.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        let inode_block = inode_offset / u64::from(self.superblock.block_size);
        let cluster = if let Some(cached) = self.cache.inode_cluster_cache.get(&inode_block) {
            cached
        } else {
            let mut raw = vec![0u8; block_size];
            read_exact_at(
                self.device.as_ref(),
                inode_block * u64::from(self.superblock.block_size),
                &mut raw,
                self.filesystem_size,
            )?;
            let raw: Arc<[u8]> = raw.into();
            self.cache
                .put_inode_cluster_if_current(inode_block, raw.clone(), generation);
            raw
        };

        let offset_in_block = usize::try_from(inode_offset % u64::from(self.superblock.block_size))
            .map_err(|_| FsError::ArithmeticOverflow)?;
        let raw = cluster
            .get(offset_in_block..offset_in_block + inode_size)
            .ok_or(FsError::Corrupted)?;
        let inode = Inode::parse_with_features(raw, inode_size, self.superblock.features_incompat)
            .map_err(|_| FsError::Corrupted)?;
        if self.superblock.is_v5() {
            inode.verify_crc(raw, inode_size)?;
            if inode.core.version >= 3 && inode.core.ino != ino {
                return Err(FsError::Corrupted);
            }
            if inode.core.uuid != self.superblock.metadata_uuid() {
                return Err(FsError::Corrupted);
            }
        }

        let inode = Arc::new(inode);
        self.cache
            .put_inode_if_current(ino, inode.clone(), generation);
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

    /// Read a metadata block into the shared metadata cache.
    fn read_block(&self, block_num: u64) -> FsResult<Arc<[u8]>> {
        let generation = self.cache.generation();
        if block_num >= self.superblock.total_blocks {
            return Err(FsError::Corrupted);
        }
        if let Some(cached) = self.cache.block_cache.get(&block_num) {
            return Ok(cached);
        }
        let block_size =
            usize::try_from(self.superblock.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        let mut buf = vec![0u8; block_size];
        self.read_at(block_num, 0, &mut buf)?;
        let buf: Arc<[u8]> = buf.into();
        self.cache
            .put_block_if_current(block_num, buf.clone(), generation);
        Ok(buf)
    }

    /// Load and cache a complete inode extent map. Mutations invalidate it.
    fn inode_extents(&self, ino: u64, inode: &Inode) -> FsResult<Arc<[Extent]>> {
        let generation = self.cache.generation();
        if let Some(cached) = self.cache.extent_cache.get(&ino) {
            return Ok(cached);
        }
        let extents = match &inode.data_fork {
            DataFork::Extents(extents) => extents.clone(),
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                let root = BmbtRoot::parse(data, *level, *num_recs)?;
                collect_extents_from_btree_checked(
                    &root,
                    self.superblock.is_v5(),
                    ino,
                    Some(self.superblock.metadata_uuid()),
                    self.superblock.block_size as usize,
                    self,
                )?
            }
            DataFork::Local(_) | DataFork::Empty | DataFork::Device { .. } => Vec::new(),
        };
        validate_extents(
            &extents,
            u64::from(self.superblock.block_size),
            self.superblock.total_blocks,
        )?;
        let extents: Arc<[Extent]> = extents.into();
        self.cache
            .put_extents_if_current(ino, extents.clone(), generation);
        Ok(extents)
    }

    /// Read directory entries for an inode.
    fn read_directory_internal(&self, ino: u64) -> FsResult<Arc<DirIndex>> {
        let generation = self.cache.generation();
        if let Some(cached) = self.cache.get_directory(ino) {
            return Ok(cached);
        }

        let inode = self.read_inode_internal(ino)?;

        if !is_directory(&inode) {
            return Err(FsError::NotADirectory);
        }

        let entries = parse_directory_entries_checked(
            &inode,
            ino,
            self.has_ftype(),
            self.block_size(),
            self.superblock.total_blocks,
            self.superblock.is_v5(),
            self,
            self.superblock.metadata_uuid(),
        )?;

        self.cache
            .put_directory_if_current(ino, entries, generation)
    }

    /// Resolve a single path component.
    fn canonical_entry_name(&self, parent_ino: u64, name: &str) -> FsResult<String> {
        let index = self.read_directory_internal(parent_ino)?;
        let entry = if self.case_insensitive_lookup.load(Ordering::Acquire) {
            index.lookup_case_insensitive(name)?
        } else {
            index.lookup(name)
        }
        .ok_or(FsError::NotFound)?;
        Ok(entry.name.clone())
    }

    fn lookup_internal(&self, parent_ino: u64, name: &str) -> FsResult<u64> {
        if !self.case_insensitive_lookup.load(Ordering::Acquire) {
            if self.cache.get_directory(parent_ino).is_some() {
                return self.lookup_internal_index(parent_ino, name);
            }
            let inode = self.read_inode_internal(parent_ino)?;
            if !is_directory(&inode) {
                return Err(FsError::NotADirectory);
            }
            let raw_name = unmangle(name)?;
            let dir_block_size = self
                .superblock
                .block_size
                .checked_shl(u32::from(self.superblock.dir_block_log))
                .ok_or(FsError::ArithmeticOverflow)?;
            let lookup = |bytes: &[u8]| {
                lookup_directory_entry(
                    &inode,
                    parent_ino,
                    bytes,
                    self.has_ftype(),
                    self.block_size(),
                    dir_block_size,
                    self.superblock.total_blocks,
                    self.superblock.is_v5(),
                    self.superblock.metadata_uuid(),
                    self,
                )
                .map(|(ino, _)| ino)
            };
            match lookup(&raw_name) {
                Ok(ino) => return Ok(ino),
                Err(FsError::NotFound) => {
                    // Some images store the presentation spelling itself.
                    if raw_name != name.as_bytes() {
                        match lookup(name.as_bytes()) {
                            Ok(ino) => return Ok(ino),
                            Err(FsError::NotFound) => {}
                            Err(error) => return Err(error),
                        }
                    }
                    return Err(FsError::NotFound);
                }
                Err(FsError::NotSupported | FsError::NotImplemented) => {
                    // Retain the full parser for geometries the directed lookup
                    // does not yet understand.
                }
                Err(error) => return Err(error),
            }
        }
        self.lookup_internal_index(parent_ino, name)
    }

    fn lookup_internal_index(&self, parent_ino: u64, name: &str) -> FsResult<u64> {
        trace!("lookup_internal: parent={}, name='{}'", parent_ino, name);
        let index = self.read_directory_internal(parent_ino)?;
        let found = if self.case_insensitive_lookup.load(Ordering::Acquire) {
            index.lookup_case_insensitive(name)?
        } else {
            index.lookup(name)
        };
        match found {
            Some(entry) => {
                trace!("lookup found ino {} for '{}'", entry.ino, name);
                Ok(entry.ino)
            }
            None => {
                debug!("lookup: '{}' NOT FOUND in parent {}", name, parent_ino);
                Err(FsError::NotFound)
            }
        }
    }

    fn inode_file_info(&self, ino: u64) -> FsResult<VfsFileInfo> {
        let lock = self.inode_lock(ino)?;
        let _guard = lock.read();
        let inode = self.read_inode_internal(ino)?;
        let mut info = inode_to_file_info(
            ino,
            &inode,
            self.block_size(),
            self.has_bigtime(),
            self.filesystem_size,
        )?;
        info.size = self.pending_size(ino, info.size);
        self.attach_posix_acl(ino, &inode, &mut info)?;
        Ok(info)
    }

    /// Attach validated ACL xattrs to file metadata. The caller holds the
    /// inode read/write lock, so the cached inode cluster cannot change beneath
    /// this read. Any malformed ACL is returned as an error.
    fn attach_posix_acl(&self, ino: u64, inode: &Inode, info: &mut VfsFileInfo) -> FsResult<()> {
        if inode.core.forkoff == 0 || inode.core.aformat == 0 {
            return Ok(());
        }
        let inode_offset = self.calculate_inode_offset(ino)?;
        let block_size =
            usize::try_from(self.superblock.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        let inode_size = self.superblock.inode_size as usize;
        let inode_block = inode_offset / u64::from(self.superblock.block_size);
        let offset_in_block = usize::try_from(inode_offset % u64::from(self.superblock.block_size))
            .map_err(|_| FsError::ArithmeticOverflow)?;
        let end = offset_in_block
            .checked_add(inode_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        let cluster = self.cache.inode_cluster_cache.get(&inode_block);
        let owned;
        let raw = if let Some(cluster) = cluster.as_ref() {
            cluster
                .get(offset_in_block..end)
                .ok_or(FsError::Corrupted)?
        } else {
            let mut raw = Vec::new();
            raw.try_reserve_exact(inode_size)
                .map_err(|_| FsError::OutOfMemory)?;
            raw.resize(inode_size, 0);
            read_exact_at(
                self.device.as_ref(),
                inode_offset,
                &mut raw,
                self.filesystem_size,
            )?;
            owned = Some(raw);
            owned.as_deref().expect("just inserted")
        };

        let reader = XfsBtreeReader(self);
        let options = xfs_rs::attr::AttrForkOptions {
            reader: &reader,
            block_size,
            filesystem_size: self.filesystem_size,
            is_v5: self.superblock.is_v5(),
            owner: ino,
            uuid: self.superblock.metadata_uuid(),
        };
        let access = xfs_rs::attr::read_posix_acl(
            inode,
            raw,
            inode_size,
            xfs_rs::attr::PosixAclKind::Access,
            &options,
        )?;
        let default = xfs_rs::attr::read_posix_acl(
            inode,
            raw,
            inode_size,
            xfs_rs::attr::PosixAclKind::Default,
            &options,
        )?;
        if access.is_some() || default.is_some() {
            info.posix_acl = Some(fs_abstraction::types::VfsPosixAcl { access, default });
        }
        Ok(())
    }

    fn read_inode_data(
        &self,
        ino: u64,
        inode: &Inode,
        offset: u64,
        buf: &mut [u8],
    ) -> FsResult<usize> {
        if is_directory(inode) {
            return Err(FsError::IsADirectory);
        }

        if !matches!(
            &inode.data_fork,
            DataFork::Extents(_) | DataFork::Btree { .. }
        ) {
            return read_file_data(
                inode,
                offset,
                buf,
                self.block_size(),
                self.superblock.total_blocks,
                self.superblock.is_v5(),
                self,
            );
        }
        let extents = self.inode_extents(ino, inode)?;
        read_file_data_with_extents(
            inode,
            &extents,
            offset,
            buf,
            self.block_size(),
            self.superblock.total_blocks,
            self,
        )
    }

    /// Materialize one inode's pending blocks while its inode write lock is
    /// held. This data-only flush does not take the metadata lock, avoiding a
    /// lock-order inversion when a buffered write needs backpressure.
    fn flush_pending_locked(&self, ino: u64) -> FsResult<()> {
        let Some(entry) = self.pending_writes.lock().remove(&ino) else {
            return Ok(());
        };
        // Take the dirty buffers out of the entry so the journal commit never
        // runs while an entry lock is held.
        let pending = {
            let mut guard = entry.lock();
            std::mem::replace(&mut *guard, PendingWrites::with_size(0))
        };
        let result = self.mutate_with_writer_locked(|writer| {
            let mut batch = WriteBatch::new();
            writer.stage_delalloc_to_size(ino, &pending, pending.size(), &mut batch)?;
            writer.commit_delalloc_batch(&mut batch)
        });
        match result {
            Ok(_) => {
                self.delalloc_budget.release(
                    pending.memory_bytes(usize::try_from(self.superblock.block_size).unwrap_or(0)),
                );
                Ok(())
            }
            Err(error) => {
                // Keep dirty bytes and their budget reservation for retry. The
                // inode write lock guarantees no other writer re-added an
                // entry.
                self.pending_writes
                    .lock()
                    .insert(ino, Arc::new(Mutex::new(pending)));
                Err(error)
            }
        }
    }

    fn buffer_write_locked(
        &self,
        ino: u64,
        inode: &Inode,
        offset: u64,
        data: &[u8],
    ) -> FsResult<(usize, VfsFileInfo)> {
        if !inode.core.is_file() {
            return Err(FsError::InvalidArgument);
        }
        let mut info = inode_to_file_info(
            ino,
            inode,
            self.block_size(),
            self.has_bigtime(),
            self.filesystem_size,
        )?;
        self.attach_posix_acl(ino, inode, &mut info)?;
        let block_size = self.block_size() as usize;
        let pending = self.pending_entry_or_insert(ino, inode.core.size);
        let mut pending = pending.lock();
        let result = pending.write(
            offset,
            data,
            block_size,
            inode.core.size,
            &self.delalloc_budget,
            |file_block| {
                let read_offset = file_block
                    .checked_mul(block_size as u64)
                    .ok_or(FsError::ArithmeticOverflow)?;
                let mut block = Vec::new();
                block
                    .try_reserve_exact(block_size)
                    .map_err(|_| FsError::OutOfMemory)?;
                block.resize(block_size, 0);
                if read_offset < inode.core.size {
                    self.read_inode_data(ino, inode, read_offset, &mut block)?;
                }
                Ok(block)
            },
        );
        let written = result?;
        info.size = pending.size();
        Ok((written, info))
    }

    /// Buffer one write in bounded chunks, flushing delalloc and refreshing the
    /// inode image whenever the per-file or global dirty budget is exhausted.
    fn buffer_write_chunks_locked(
        &self,
        ino: u64,
        mut offset: u64,
        data: &[u8],
    ) -> FsResult<(usize, VfsFileInfo)> {
        const CHUNK: usize = 1024 * 1024;
        let mut written = 0usize;
        let mut info = None;
        for chunk in data.chunks(CHUNK) {
            loop {
                let inode = self.read_inode_internal(ino)?;
                match self.buffer_write_locked(ino, &inode, offset, chunk) {
                    Ok((count, current)) => {
                        written += count;
                        offset = offset
                            .checked_add(
                                u64::try_from(count).map_err(|_| FsError::ArithmeticOverflow)?,
                            )
                            .ok_or(FsError::ArithmeticOverflow)?;
                        info = Some(current);
                        break;
                    }
                    Err(FsError::OutOfMemory)
                        if self
                            .pending_entry(ino)
                            .is_some_and(|pending| !pending.lock().is_empty()) =>
                    {
                        self.flush_pending_locked(ino)?;
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        let info = match info {
            Some(info) => info,
            None => {
                let inode = self.read_inode_internal(ino)?;
                let mut info = inode_to_file_info(
                    ino,
                    &inode,
                    self.block_size(),
                    self.has_bigtime(),
                    self.filesystem_size,
                )?;
                info.size = self.pending_size(ino, info.size);
                self.attach_posix_acl(ino, &inode, &mut info)?;
                info
            }
        };
        Ok((written, info))
    }

    fn buffer_write_with_info(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
    ) -> FsResult<(usize, VfsFileInfo)> {
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let lock = self.inode_lock(ino)?;
        let _guard = lock.write();
        self.buffer_write_chunks_locked(ino, offset, data)
    }

    /// Atomically select EOF and buffer an append. All handles share the inode
    /// lock, so concurrent appends cannot choose the same offset.
    pub fn append_with_info(&self, ino: u64, data: &[u8]) -> FsResult<(usize, VfsFileInfo)> {
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let lock = self.inode_lock(ino)?;
        let _guard = lock.write();
        let inode = self.read_inode_internal(ino)?;
        let offset = self.pending_size(ino, inode.core.size);
        self.buffer_write_chunks_locked(ino, offset, data)
    }

    /// Append data and return only the byte count.
    pub fn append(&self, ino: u64, data: &[u8]) -> FsResult<usize> {
        self.append_with_info(ino, data).map(|(written, _)| written)
    }
}

impl VfsBlockReader for XfsVfs {
    fn read_block(&self, block_num: u64) -> FsResult<Arc<[u8]>> {
        XfsVfs::read_block(self, block_num)
    }

    fn read_at(&self, block_num: u64, offset: u64, buf: &mut [u8]) -> FsResult<()> {
        if block_num >= self.superblock.total_blocks {
            return Err(FsError::Corrupted);
        }
        let block_size = u64::from(self.superblock.block_size);
        if offset > block_size {
            return Err(FsError::Corrupted);
        }
        let byte_offset = block_num
            .checked_mul(block_size)
            .and_then(|base| base.checked_add(offset))
            .ok_or(FsError::ArithmeticOverflow)?;
        // File data intentionally bypasses `block_cache`.
        read_exact_at(self.device.as_ref(), byte_offset, buf, self.filesystem_size)
    }
}

impl VfsFileSystem for XfsVfs {
    fn fs_type(&self) -> &'static str {
        "xfs"
    }

    fn set_case_insensitive_lookup(&self, enabled: bool) {
        XfsVfs::set_case_insensitive_lookup(self, enabled);
    }

    fn is_case_insensitive_lookup(&self) -> bool {
        self.case_insensitive_lookup.load(Ordering::Acquire)
    }

    fn sync(&self) -> FsResult<()> {
        XfsVfs::sync(self)
    }

    fn flush_file(&self, ino: u64) -> FsResult<()> {
        XfsVfs::flush_file(self, ino)
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
        let _guard = self.metadata_lock.read();
        let sb = &self.superblock;
        let block_size = sb.block_size as u64;
        let total_blocks = sb.total_blocks;

        // Free blocks from AG free block info (simplified).  Validate the
        // counters before exposing byte counts to callers.
        let free_blocks = self.free_blocks.load(Ordering::Acquire);
        let free_inodes = self.free_inodes.load(Ordering::Acquire);
        let allocated_inodes = self.allocated_inodes.load(Ordering::Acquire);
        let inode_shift = u32::from(sb.ag_block_log) + u32::from(sb.inode_per_block_log);
        let inodes_per_ag = 1u64
            .checked_shl(inode_shift)
            .ok_or(FsError::ArithmeticOverflow)?;
        let total_inodes = u64::from(sb.ag_count)
            .checked_mul(inodes_per_ag)
            .ok_or(FsError::ArithmeticOverflow)?;
        if free_blocks > total_blocks
            || free_inodes > total_inodes
            || allocated_inodes > total_inodes
            || free_inodes > total_inodes - allocated_inodes
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
        self.inode_file_info(ino)
    }

    fn stat_many(&self, inos: &[u64]) -> Vec<FsResult<VfsFileInfo>> {
        inos.iter().map(|&ino| self.inode_file_info(ino)).collect()
    }

    fn lookup(&self, parent_ino: u64, name: &str) -> FsResult<VfsFileInfo> {
        let _guard = self.metadata_lock.read();
        debug!("lookup: parent={}, name='{}'", parent_ino, name);
        let parent_lock = self.inode_lock(parent_ino)?;
        let child_ino = {
            let _parent_guard = parent_lock.read();
            self.lookup_internal(parent_ino, name)?
        };
        trace!("lookup found ino: {}", child_ino);
        self.inode_file_info(child_ino)
    }

    fn resolve_path(&self, path: &str) -> FsResult<u64> {
        let _guard = self.metadata_lock.read();
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

    fn lookup_wide(&self, parent_ino: u64, name: &[u16]) -> FsResult<VfsFileInfo> {
        let _guard = self.metadata_lock.read();
        if !self.case_insensitive_lookup.load(Ordering::Acquire) {
            if let Some(index) = self.cache.get_directory(parent_ino) {
                if let Some(entry) = index.lookup_wide(name) {
                    return self.inode_file_info(entry.ino);
                }
            }
        }
        let parent_lock = self.inode_lock(parent_ino)?;
        let child_ino = {
            let _parent_guard = parent_lock.read();
            if self.case_insensitive_lookup.load(Ordering::Acquire) {
                let index = self.read_directory_internal(parent_ino)?;
                index
                    .lookup_wide_case_insensitive(name)?
                    .ok_or(FsError::NotFound)?
                    .ino
            } else {
                self.lookup_internal(parent_ino, &String::from_utf16_lossy(name))?
            }
        };
        self.inode_file_info(child_ino)
    }

    fn resolve_path_wide(&self, path: &[u16]) -> FsResult<u64> {
        let _guard = self.metadata_lock.read();
        let key: Box<[u16]> = path.into();
        if let Some(cached) = self.cache.get_wide_path(&key) {
            return Ok(cached);
        }

        let mut stack = vec![self.root_inode()];
        let require_directory = |ino: u64| -> FsResult<()> {
            let inode = self.read_inode_internal(ino)?;
            if !is_directory(&inode) {
                return Err(FsError::NotADirectory);
            }
            Ok(())
        };
        let mut offset = 0;
        while offset < path.len() {
            while offset < path.len()
                && (path[offset] == b'\\' as u16 || path[offset] == b'/' as u16)
            {
                offset += 1;
            }
            let start = offset;
            while offset < path.len()
                && !(path[offset] == b'\\' as u16 || path[offset] == b'/' as u16)
            {
                offset += 1;
            }
            if start == offset {
                continue;
            }
            let component = &path[start..offset];
            let parent = *stack.last().expect("root is always present");
            if component == [b'.' as u16] {
                require_directory(parent)?;
            } else if component == [b'.' as u16, b'.' as u16] {
                require_directory(parent)?;
                if stack.len() > 1 {
                    stack.pop();
                }
            } else {
                require_directory(parent)?;
                let child = if self.case_insensitive_lookup.load(Ordering::Acquire) {
                    let index = self.read_directory_internal(parent)?;
                    index
                        .lookup_wide_case_insensitive(component)?
                        .ok_or(FsError::NotFound)?
                        .ino
                } else {
                    self.lookup_internal(parent, &String::from_utf16_lossy(component))?
                };
                stack.push(child);
            }
        }
        let ino = *stack.last().expect("root is always present");
        self.cache.put_wide_path(key, ino);
        Ok(ino)
    }

    fn read(&self, ino: u64, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let lock = self.inode_lock(ino)?;
        let _guard = lock.read();
        let inode = self.read_inode_internal(ino)?;
        if is_directory(&inode) {
            return Err(FsError::IsADirectory);
        }
        let logical_size = self.pending_size(ino, inode.core.size);
        let available = logical_size.saturating_sub(offset);
        let to_read = usize::try_from(available.min(buf.len() as u64))
            .map_err(|_| FsError::ArithmeticOverflow)?;
        if to_read == 0 {
            return Ok(0);
        }
        let destination = &mut buf[..to_read];
        destination.fill(0);
        self.read_inode_data(ino, &inode, offset, destination)?;
        if let Some(pending) = self.pending_entry(ino) {
            pending
                .lock()
                .overlay_read(offset, destination, self.block_size() as usize);
        }
        Ok(to_read)
    }

    fn readdir(&self, ino: u64) -> FsResult<Vec<VfsDirEntry>> {
        let lock = self.inode_lock(ino)?;
        let _guard = lock.read();
        Ok(self.read_directory_internal(ino)?.entries.to_vec())
    }

    fn readlink(&self, ino: u64) -> FsResult<String> {
        let lock = self.inode_lock(ino)?;
        let _guard = lock.read();
        let inode = self.read_inode_internal(ino)?;

        if !is_symlink(&inode) {
            return Err(FsError::NotSupported);
        }

        read_symlink_target_with_uuid(
            &inode,
            self.block_size(),
            self.superblock.total_blocks,
            self.superblock.is_v5(),
            Some(self.superblock.metadata_uuid()),
            self,
        )
    }

    // Writable mutations are serialized and journaled. Unsupported metadata
    // features fail explicitly; read-only instances continue to return
    // ReadOnly.
    fn pin_inode(&self, ino: u64) -> FsResult<()> {
        XfsVfs::pin_inode(self, ino)
    }

    fn unpin_inode(&self, ino: u64) {
        XfsVfs::unpin_inode(self, ino);
    }

    fn invalidate_inode(&self, ino: u64) {
        let _metadata_guard = self.metadata_lock.write();
        let lock = self.inode_lock(ino).ok();
        let _inode_guard = lock.as_ref().map(|lock| lock.write());
        self.cache.invalidate_inode(ino);
        self.cache.block_cache.invalidate_all();
        if let Ok(offset) = self.calculate_inode_offset(ino) {
            self.cache
                .invalidate_inode_buffer(offset / u64::from(self.superblock.block_size));
        }
    }

    fn write(&self, ino: u64, offset: u64, data: &[u8]) -> FsResult<usize> {
        self.buffer_write_with_info(ino, offset, data)
            .map(|(written, _)| written)
    }

    fn write_with_info(
        &self,
        ino: u64,
        offset: u64,
        data: &[u8],
    ) -> FsResult<(usize, VfsFileInfo)> {
        self.buffer_write_with_info(ino, offset, data)
    }

    fn create_file(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        let name = mangle_str(name)?;
        self.mutate_with_writer(&[parent_ino], |writer| {
            writer.create_file(parent_ino, &name, mode)
        })
    }

    fn create_directory(
        &self,
        parent_ino: u64,
        name: &str,
        mode: u32,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        let name = mangle_str(name)?;
        self.mutate_with_writer(&[parent_ino], |writer| {
            writer.create_directory(parent_ino, &name, mode)
        })
    }

    fn create_symlink(
        &self,
        parent_ino: u64,
        name: &str,
        target: &str,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        let name = mangle_str(name)?;
        self.mutate_with_writer(&[parent_ino], |writer| {
            writer.create_symlink(parent_ino, &name, target)
        })
    }

    fn link(
        &self,
        target_ino: u64,
        parent_ino: u64,
        name: &str,
    ) -> FsResult<fs_abstraction::VfsFileInfo> {
        let name = mangle_str(name)?;
        self.mutate_with_writer(&[target_ino, parent_ino], |writer| {
            writer.link_inode(target_ino, parent_ino, &name)
        })
        .and_then(|_| self.inode_file_info(target_ino))
    }

    fn set_size(&self, ino: u64, size: u64) -> FsResult<()> {
        let _metadata_guard = self.metadata_lock.write();
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let lock = self.inode_lock(ino)?;
        let _inode_guard = lock.write();
        let had_pending = self.pending_writes.lock().contains_key(&ino);
        let result = self.mutate_with_writer_locked(|writer| {
            if had_pending {
                let entry = self.pending_entry(ino).ok_or(FsError::Corrupted)?;
                let pending = entry.lock();
                let mut batch = WriteBatch::new();
                writer.stage_delalloc_to_size(ino, &pending, size, &mut batch)?;
                writer.commit_delalloc_batch(&mut batch)?;
                Ok(())
            } else {
                writer.set_size(ino, size)
            }
        });
        if result.is_ok() && had_pending {
            self.clear_pending_locked(ino);
        }
        result
    }

    fn set_times(
        &self,
        ino: u64,
        atime: Option<fs_abstraction::VfsTimestamp>,
        mtime: Option<fs_abstraction::VfsTimestamp>,
    ) -> FsResult<()> {
        self.mutate_with_writer(&[ino], |writer| writer.set_times(ino, atime, mtime))
    }

    fn rename(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
        flags: fs_abstraction::RenameFlags,
    ) -> FsResult<()> {
        let new_name = mangle_str(new_name)?;
        if self.capabilities.read_only {
            return Err(FsError::ReadOnly);
        }
        let _metadata_guard = self.metadata_lock.write();
        let old_name = self.canonical_entry_name(old_parent, old_name)?;
        let source_ino = self.lookup_internal_index(old_parent, &old_name)?;
        let destination_ino = match self.lookup_internal_index(new_parent, &new_name) {
            Ok(ino) => Some(ino),
            Err(FsError::NotFound) => None,
            Err(error) => return Err(error),
        };
        let mut inos = vec![old_parent, new_parent, source_ino];
        if let Some(ino) = destination_ino {
            inos.push(ino);
        }
        let locks = self.lock_inodes(&inos)?;
        let _inode_guards: Vec<_> = locks.iter().map(|lock| lock.write()).collect();
        self.mutate_with_writer_locked(|writer| {
            let replaced =
                writer.rename_inode(old_parent, &old_name, new_parent, &new_name, flags)?;
            if let Some(info) = replaced {
                if info.nlink == 0 && !self.pinned_inodes.lock().contains_key(&info.ino) {
                    self.clear_pending_locked(info.ino);
                }
            }
            Ok(())
        })
    }

    fn unlink(&self, parent_ino: u64, name: &str, target_ino: u64) -> FsResult<()> {
        self.mutate_with_writer(&[parent_ino, target_ino], |writer| {
            let name = self.canonical_entry_name(parent_ino, name)?;
            let info = writer.unlink_inode(parent_ino, &name, target_ino)?;
            if info.nlink == 0 && !self.pinned_inodes.lock().contains_key(&target_ino) {
                // Unallocated delalloc data has no open handle to preserve.
                self.clear_pending_locked(target_ino);
            }
            Ok(())
        })
    }

    fn invalidate_all_caches(&self) {
        let _guard = self.metadata_lock.write();
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

    struct GatedDevice {
        inner: InMemoryDevice,
        gate_offset: u64,
        gate_used: std::sync::atomic::AtomicBool,
        entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
        release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    }

    impl GatedDevice {
        fn gated(
            data: Vec<u8>,
            gate_offset: u64,
        ) -> (
            Arc<Self>,
            std::sync::mpsc::Receiver<()>,
            std::sync::mpsc::Sender<()>,
        ) {
            let (entered_tx, entered_rx) = std::sync::mpsc::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            (
                Arc::new(Self {
                    inner: InMemoryDevice::new(data),
                    gate_offset,
                    gate_used: std::sync::atomic::AtomicBool::new(false),
                    entered: Mutex::new(Some(entered_tx)),
                    release: Mutex::new(Some(release_rx)),
                }),
                entered_rx,
                release_tx,
            )
        }
    }

    impl BlockDevice for GatedDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
            if offset == self.gate_offset
                && !self
                    .gate_used
                    .swap(true, std::sync::atomic::Ordering::SeqCst)
            {
                let entered = self.entered.lock().take().expect("single gate");
                let release = self.release.lock().take().expect("single gate");
                entered.send(()).map_err(|_| FsError::DiskError)?;
                release.recv().map_err(|_| FsError::DiskError)?;
            }
            self.inner.read_at(offset, buf)
        }

        fn write_at(&self, offset: u64, input: &[u8]) -> FsResult<usize> {
            self.inner.write_at(offset, input)
        }

        fn size(&self) -> u64 {
            self.inner.size()
        }

        fn supports_write(&self) -> bool {
            self.inner.supports_write()
        }
    }

    fn image_with_two_inodes() -> Vec<u8> {
        let mut data = minimal_image();
        let raw = crate::inode_write::serialize_inode(&synthetic_inode(0o100644), 256).unwrap();
        data[8 * 4096..8 * 4096 + 256].copy_from_slice(&raw);
        data[8 * 4096 + 256..8 * 4096 + 512].copy_from_slice(&raw);
        data
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

    fn minimal_v5_sb_buf(incompat: u32, ro_compat: u32) -> Vec<u8> {
        let mut buf = minimal_sb_buf();
        buf[0x064..0x066].copy_from_slice(&5u16.to_be_bytes());
        buf[0x0D4..0x0D8].copy_from_slice(&ro_compat.to_be_bytes());
        buf[0x0D8..0x0DC].copy_from_slice(&incompat.to_be_bytes());
        xfs_rs::crc::recalculate_crc_le(&mut buf, 0xE0).unwrap();
        buf
    }

    fn image_with_v5_sb(incompat: u32, ro_compat: u32) -> Vec<u8> {
        let mut image = vec![0u8; 4096 * 100];
        let sb = minimal_v5_sb_buf(incompat, ro_compat);
        image[..sb.len()].copy_from_slice(&sb);
        image
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
    fn mount_mode_feature_policy_is_explicit() {
        use xfs_rs::{
            XFS_SB_FEAT_INCOMPAT_BIGTIME,
            XFS_SB_FEAT_INCOMPAT_EXCHANGE,
            XFS_SB_FEAT_INCOMPAT_METADIR,
            XFS_SB_FEAT_INCOMPAT_NREXT64,
            XFS_SB_FEAT_INCOMPAT_PARENT,
            XFS_SB_FEAT_RO_COMPAT_INOBTCNT,
            XFS_SB_FEAT_RO_COMPAT_REFLINK,
            XFS_SB_FEAT_RO_COMPAT_RMAPBT,
        };

        for feature in [XFS_SB_FEAT_INCOMPAT_BIGTIME, XFS_SB_FEAT_INCOMPAT_NREXT64] {
            let device = Arc::new(InMemoryDevice::new(image_with_v5_sb(feature, 0)));
            assert!(XfsVfs::read_only(device).is_ok());
        }
        for feature in [
            XFS_SB_FEAT_RO_COMPAT_INOBTCNT,
            XFS_SB_FEAT_RO_COMPAT_REFLINK,
            XFS_SB_FEAT_RO_COMPAT_RMAPBT,
        ] {
            let device = Arc::new(InMemoryDevice::new(image_with_v5_sb(0, feature)));
            assert!(XfsVfs::read_only(device).is_ok());
        }

        for (incompat, ro_compat) in [
            (XFS_SB_FEAT_INCOMPAT_NREXT64, 0),
            (XFS_SB_FEAT_INCOMPAT_METADIR, 0),
            (XFS_SB_FEAT_INCOMPAT_EXCHANGE, 0),
            (XFS_SB_FEAT_INCOMPAT_PARENT, 0),
            (0, XFS_SB_FEAT_RO_COMPAT_REFLINK),
            (0, XFS_SB_FEAT_RO_COMPAT_RMAPBT),
            (0, XFS_SB_FEAT_RO_COMPAT_INOBTCNT),
        ] {
            let device = Arc::new(InMemoryDevice::new(image_with_v5_sb(incompat, ro_compat)));
            assert!(matches!(
                XfsVfs::with_options(device, false),
                Err(FsError::NotSupported)
            ));
        }

        for (incompat, ro_compat) in [
            (XFS_SB_FEAT_INCOMPAT_METADIR, 0),
            (XFS_SB_FEAT_INCOMPAT_EXCHANGE, 0),
            (XFS_SB_FEAT_INCOMPAT_PARENT, 0),
        ] {
            let device = Arc::new(InMemoryDevice::new(image_with_v5_sb(incompat, ro_compat)));
            assert!(matches!(
                XfsVfs::read_only(device),
                Err(FsError::NotSupported)
            ));
        }
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
    fn btree_extent_map_is_loaded_once_and_shared_between_reads() {
        use std::sync::atomic::Ordering;

        let mut data = minimal_image();
        let mut leaf = vec![0u8; 4096];
        leaf[0..4].copy_from_slice(&0x424D_4150u32.to_be_bytes()); // BMAP
        leaf[6..8].copy_from_slice(&1u16.to_be_bytes());
        leaf[24..40].copy_from_slice(
            &Extent {
                file_offset: 0,
                start_block: 20,
                block_count: 1,
                is_unwritten: false,
            }
            .to_bytes(),
        );
        data[10 * 4096..11 * 4096].copy_from_slice(&leaf);
        let device = Arc::new(InMemoryDevice::new(data));
        let fs = XfsVfs::read_only(device.clone()).unwrap();
        let mut inode = synthetic_inode(0o100644);
        let mut root_data = vec![0u8; 16];
        root_data[8..16].copy_from_slice(&10u64.to_be_bytes());
        inode.data_fork = DataFork::Btree {
            level: 1,
            num_recs: 1,
            data: root_data,
        };
        let before = device.read_calls.load(Ordering::SeqCst);
        let first = fs.inode_extents(128, &inode).unwrap();
        let second = fs.inode_extents(128, &inode).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(device.read_calls.load(Ordering::SeqCst), before + 1);
        fs.cache.invalidate_inode(128);
        assert!(fs.cache.extent_cache.get(&128).is_none());
    }

    #[test]
    fn multi_block_file_read_is_coalesced_uncached_and_eof_clamped() {
        use std::sync::atomic::Ordering;

        let mut data = minimal_image();
        data[10 * 4096..12 * 4096].fill(0xA7);
        let device = Arc::new(InMemoryDevice::new(data));
        let fs = XfsVfs::read_only(device.clone()).unwrap();
        let mut inode = synthetic_inode(0o100644);
        inode.core.size = 5_000;
        inode.data_fork = DataFork::Extents(vec![Extent {
            file_offset: 0,
            start_block: 10,
            block_count: 2,
            is_unwritten: false,
        }]);
        fs.cache.put_inode(128, Arc::new(inode));
        let before = device.read_calls.load(Ordering::SeqCst);
        let mut buf = [0u8; 8192];
        assert_eq!(fs.read(128, 0, &mut buf).unwrap(), 5_000);
        assert_eq!(device.read_calls.load(Ordering::SeqCst), before + 1);
        assert!(buf[..5000].iter().all(|&byte| byte == 0xA7));
        assert!(fs.cache.block_cache.get(&10).is_none());
        assert_eq!(fs.read(128, 5000, &mut buf).unwrap(), 0);
        assert_eq!(device.read_calls.load(Ordering::SeqCst), before + 1);
    }

    #[test]
    fn meta_uuid_inodes_are_validated_against_the_metadata_uuid() {
        let mut sb = minimal_v5_sb_buf(xfs_rs::XFS_SB_FEAT_INCOMPAT_META_UUID, 0);
        sb[0x020..0x030].fill(0xA5);
        sb[0x0F8..0x108].fill(0x5A);
        xfs_rs::crc::recalculate_crc_le(&mut sb, 0xE0).unwrap();

        let mut data = minimal_image();
        data[..sb.len()].copy_from_slice(&sb);
        let mut core = xfs_rs::inode_alloc::create_empty_inode_core_at(
            0o100644,
            0,
            0,
            3,
            128,
            &[0x5A; 16],
            false,
            1_700_000_000,
            0,
        )
        .unwrap();
        core.nlink = 1;
        let inode = Inode {
            core,
            data_fork: DataFork::Local(Vec::new()),
        };
        let raw = crate::inode_write::serialize_inode(&inode, 256).unwrap();
        data[8 * 4096..8 * 4096 + raw.len()].copy_from_slice(&raw);
        let fs = XfsVfs::read_only(Arc::new(InMemoryDevice::new(data))).unwrap();
        assert_eq!(fs.read_inode_internal(128).unwrap().core.uuid, [0x5A; 16]);
    }

    #[test]
    fn inodes_in_one_buffer_share_a_single_device_read() {
        use std::sync::atomic::Ordering;

        let mut data = minimal_image();
        let raw = crate::inode_write::serialize_inode(&synthetic_inode(0o100644), 256).unwrap();
        data[8 * 4096..8 * 4096 + 256].copy_from_slice(&raw);
        data[8 * 4096 + 256..8 * 4096 + 512].copy_from_slice(&raw);
        let device = Arc::new(InMemoryDevice::new(data));
        let fs = XfsVfs::read_only(device.clone()).unwrap();
        let before = device.read_calls.load(Ordering::SeqCst);

        fs.read_inode_internal(128).unwrap();
        let after_first = device.read_calls.load(Ordering::SeqCst);
        fs.read_inode_internal(129).unwrap();
        assert_eq!(after_first, before + 1);
        assert_eq!(device.read_calls.load(Ordering::SeqCst), after_first);
    }

    #[test]
    fn per_inode_locks_allow_unrelated_progress_and_exclude_same_inode() {
        let (device, entered_rx, release_tx) =
            GatedDevice::gated(image_with_two_inodes(), 8 * 4096);
        let fs = Arc::new(XfsVfs::read_only(device).unwrap());
        let first_fs = fs.clone();
        let first = std::thread::spawn(move || first_fs.stat(128));
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("first inode read must reach the device");

        assert!(fs.inode_lock(128).unwrap().try_write().is_none());
        assert!(fs.inode_lock(129).unwrap().try_write().is_some());

        let other_fs = fs.clone();
        let (other_tx, other_rx) = std::sync::mpsc::channel();
        let other = std::thread::spawn(move || {
            let result = other_fs.stat(129);
            let _ = other_tx.send(result);
        });
        other_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("a different inode must progress while inode 128 is blocked")
            .unwrap();
        release_tx.send(()).unwrap();
        first.join().unwrap().unwrap();
        other.join().unwrap();
    }

    #[test]
    fn stale_inode_read_cannot_repopulate_cache_after_invalidation() {
        let (device, entered_rx, release_tx) =
            GatedDevice::gated(image_with_two_inodes(), 8 * 4096);
        let fs = Arc::new(XfsVfs::read_only(device).unwrap());
        let reader_fs = fs.clone();
        let reader = std::thread::spawn(move || reader_fs.stat(128));
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("inode read must reach the device");
        fs.cache.invalidate_inode(128);
        release_tx.send(()).unwrap();
        reader.join().unwrap().unwrap();
        assert!(fs.cache.get_inode(128).is_none());
    }

    #[test]
    fn malformed_local_acl_fails_stat_instead_of_mode_fallback() {
        let mut sb = minimal_v5_sb_buf(0, 0);
        xfs_rs::crc::recalculate_crc_le(&mut sb, 0xE0).unwrap();
        let mut data = minimal_image();
        data[..sb.len()].copy_from_slice(&sb);
        let mut core = xfs_rs::inode_alloc::create_empty_inode_core_at(
            0o100644,
            0,
            0,
            3,
            128,
            &[0; 16],
            false,
            1_700_000_000,
            0,
        )
        .unwrap();
        core.nlink = 1;
        core.aformat = xfs_rs::constants::XFS_DINODE_FMT_LOCAL;
        core.forkoff = 2;
        let inode = Inode {
            core,
            data_fork: DataFork::Local(Vec::new()),
        };
        let mut raw = crate::inode_write::serialize_inode(&inode, 256).unwrap();
        let attr_offset = inode.core.attr_fork_offset(256).unwrap();
        raw[attr_offset..attr_offset + 16].fill(0xFF);
        xfs_rs::crc::recalculate_crc_le(&mut raw, 0x64).unwrap();
        data[8 * 4096..8 * 4096 + raw.len()].copy_from_slice(&raw);
        let fs = XfsVfs::read_only(Arc::new(InMemoryDevice::new(data))).unwrap();
        assert!(matches!(fs.stat(128), Err(FsError::Corrupted)));
    }

    #[test]
    fn v3_inode_with_zero_number_is_rejected() {
        let mut sb = minimal_v5_sb_buf(0, 0);
        xfs_rs::crc::recalculate_crc_le(&mut sb, 0xE0).unwrap();
        let mut data = minimal_image();
        data[..sb.len()].copy_from_slice(&sb);
        let core = xfs_rs::inode_alloc::create_empty_inode_core_at(
            0o100644,
            0,
            0,
            3,
            0,
            &[0; 16],
            false,
            1_700_000_000,
            0,
        )
        .unwrap();
        let inode = Inode {
            core,
            data_fork: DataFork::Local(Vec::new()),
        };
        let raw = crate::inode_write::serialize_inode(&inode, 256).unwrap();
        data[8 * 4096..8 * 4096 + raw.len()].copy_from_slice(&raw);
        let fs = XfsVfs::read_only(Arc::new(InMemoryDevice::new(data))).unwrap();
        assert!(matches!(
            fs.read_inode_internal(128),
            Err(FsError::Corrupted)
        ));
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
        fs.cache.put_inode(128, Arc::new(synthetic_inode(0o040755)));
        fs.cache.put_inode(129, Arc::new(synthetic_inode(0o040755)));
        fs.cache.put_inode(130, Arc::new(synthetic_inode(0o100644)));
        fs.cache
            .put_directory(
                128,
                vec![synthetic_entry("dir", 129, VfsFileType::Directory)],
            )
            .unwrap();
        // Deliberately omit "." and "..": lexical traversal must not need them.
        fs.cache
            .put_directory(
                129,
                vec![synthetic_entry("file", 130, VfsFileType::RegularFile)],
            )
            .unwrap();

        assert_eq!(fs.resolve_path("/dir/../dir/file").unwrap(), 130);
        assert_eq!(fs.resolve_path("/../../dir/./file").unwrap(), 130);
        assert_eq!(fs.resolve_path("/..").unwrap(), 128);
        assert!(matches!(
            fs.resolve_path("/dir/file/.."),
            Err(FsError::NotADirectory)
        ));
    }

    #[test]
    fn wide_resolution_avoids_lossy_transcoding_and_optional_case_folding_rejects_ambiguity() {
        let fs = make_read_only_xfs();
        fs.cache.put_inode(128, Arc::new(synthetic_inode(0o040755)));
        fs.cache.put_inode(129, Arc::new(synthetic_inode(0o100644)));
        fs.cache.put_inode(130, Arc::new(synthetic_inode(0o100644)));
        fs.cache
            .put_directory(
                128,
                vec![
                    synthetic_entry("File", 129, fs_abstraction::VfsFileType::RegularFile),
                    synthetic_entry("file", 130, fs_abstraction::VfsFileType::RegularFile),
                ],
            )
            .unwrap();

        let wide: Vec<u16> = "\\File".encode_utf16().collect();
        assert_eq!(fs.resolve_path_wide(&wide).unwrap(), 129);
        fs.set_case_insensitive_lookup(true);
        assert!(matches!(
            fs.resolve_path_wide(&wide),
            Err(FsError::AlreadyExists)
        ));
        let folded: Vec<u16> = "FILE".encode_utf16().collect();
        assert!(matches!(
            fs.resolve_path_wide(&folded),
            Err(FsError::AlreadyExists)
        ));
    }

    #[test]
    fn exact_lookup_uses_directed_directory_path_without_building_an_index() {
        let fs = make_read_only_xfs();
        let mut parent = synthetic_inode(0o040755);
        let header = xfs_rs::directory::ShortformHeader {
            count: 0,
            i8count: 0,
            parent: 128,
        };
        let mut data = xfs_rs::dir_write::serialize_shortform_header(&header, false);
        data = xfs_rs::dir_write::add_shortform_entry(
            &data,
            &xfs_rs::dir_write::NewDirEntry::new(
                b"file",
                129,
                xfs_rs::directory::DirFileType::RegularFile,
            ),
            128,
            false,
            false,
            parent.core.data_fork_size(256),
        )
        .unwrap();
        parent.core.size = data.len() as u64;
        parent.data_fork = DataFork::Local(data);
        fs.cache.put_inode(128, Arc::new(parent));
        fs.cache.put_inode(129, Arc::new(synthetic_inode(0o100644)));

        assert_eq!(fs.resolve_path("/file").unwrap(), 129);
        assert!(fs.cache.get_directory(128).is_none());
    }

    #[test]
    fn mutations_canonicalize_original_names_to_the_stored_escaped_spelling() {
        let fs = make_read_only_xfs();
        let original = "name\u{F001}suffix";
        let encoded = crate::name_mangling::mangle_str(original).unwrap();
        fs.cache
            .put_directory(
                128,
                vec![synthetic_entry(
                    &encoded,
                    129,
                    fs_abstraction::VfsFileType::RegularFile,
                )],
            )
            .unwrap();
        assert_eq!(fs.canonical_entry_name(128, original).unwrap(), encoded);
        assert_eq!(fs.canonical_entry_name(128, &encoded).unwrap(), encoded);
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
