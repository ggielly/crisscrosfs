//! Write operations for XFS VFS.
//!
//! This module provides write support for XFS filesystems.
//! Includes both low-level XfsWriter and high-level WriteOperations.

use std::sync::Arc;

use fs_abstraction::{BlockDevice, FsError};
use tracing::{debug, trace, warn};
use xfs_rs::{
    constants::{
        XFS_DIR2_BLOCK_MAGIC, XFS_DIR2_DATA_MAGIC, XFS_DIR3_BLOCK_MAGIC, XFS_DIR3_DATA_MAGIC,
        XFS_SB_FEAT_INCOMPAT_FTYPE,
    },
    crc::recalculate_crc,
    dir_write::{
        add_shortform_entry, remove_shortform_entry, serialize_shortform_header, NewDirEntry,
    },
    directory::{
        dir2_hash, parse_shortform_directory, BlockTail, DataHeaderV4, DataHeaderV5, DirFileType,
        LeafEntry, ShortformHeader,
    },
    freespace::NULLAGBLOCK,
    inode_alloc::{
        create_empty_inode_core, find_free_inode_in_ibt, make_absolute_inode, split_inode_number,
        InodeBtreeBlock, InodeBtreeRec,
    },
    AgInodeHeader, DataFork, Extent, Inode, InodeCore, InodeFormat,
};

use crate::{
    allocator::{BlockAllocator, FreeExtent},
    error::{Result, XfsVfsError},
    journal::Journal,
};

// --- ANSI Colors ---
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const COLOR_CREATE: &str = "\x1b[1;32m"; // Bold Green
const COLOR_DELETE: &str = "\x1b[1;31m"; // Bold Red
const COLOR_RENAME: &str = "\x1b[1;35m"; // Bold Magenta
const COLOR_WRITE: &str = "\x1b[0;33m"; // Yellow
const COLOR_INODE: &str = "\x1b[1;36m"; // Bold Cyan
const COLOR_DIM: &str = "\x1b[0;90m"; // Gray

// --- Visual Symbols ---
const SYM_CREATE: &str = "📁➕";
const SYM_DELETE: &str = "📁❌";
const SYM_RENAME: &str = "🔄";
const SYM_WRITE: &str = "✏️";
const SYM_SUCCESS: &str = "✅";

/// Cached superblock data needed for write operations.
#[derive(Clone)]
struct SuperblockData {
    block_size: u32,
    inode_size: u16,
    ag_blocks: u32,
    ag_count: u32,
    ag_block_log: u8,
    inode_per_block_log: u8,
    root_inode: u64,
    uuid: [u8; 16],
    sector_size: u16,
    features_incompat: u32,
}

impl SuperblockData {
    fn from_superblock(sb: &xfs_rs::Superblock) -> Self {
        Self {
            block_size: sb.block_size,
            inode_size: sb.inode_size,
            ag_blocks: sb.ag_blocks,
            ag_count: sb.ag_count,
            ag_block_log: sb.ag_block_log,
            inode_per_block_log: sb.inode_per_block_log,
            root_inode: sb.root_inode,
            uuid: sb.uuid,
            sector_size: sb.sector_size,
            features_incompat: sb.features_incompat,
        }
    }

    fn has_ftype(&self) -> bool {
        (self.features_incompat & XFS_SB_FEAT_INCOMPAT_FTYPE) != 0
    }
}

/// High-level write operations for XFS filesystem.
pub struct WriteOperations {
    /// The block device for I/O.
    device: Arc<dyn BlockDevice>,
    /// Superblock reference data.
    sb_data: SuperblockData,
    /// Is v5 filesystem?
    is_v5: bool,
    /// Block allocator.
    allocator: BlockAllocator,
}

impl WriteOperations {
    /// Create a new WriteOperations instance.
    pub fn new(device: Arc<dyn BlockDevice>, superblock: &xfs_rs::Superblock) -> Self {
        let sb_data = SuperblockData::from_superblock(superblock);
        let is_v5 = superblock.is_v5();
        let allocator = BlockAllocator::new(device.clone(), superblock.clone());
        Self {
            device,
            sb_data,
            is_v5,
            allocator,
        }
    }

    /// Calculate AG offset in bytes.
    fn ag_offset(&self, ag_num: u32) -> u64 {
        (ag_num as u64) * (self.sb_data.ag_blocks as u64) * (self.sb_data.block_size as u64)
    }

    /// Calculate block offset in bytes.
    fn block_offset(&self, block_num: u64) -> u64 {
        block_num * (self.sb_data.block_size as u64)
    }

    /// Calculate inode offset in bytes.
    fn inode_offset(&self, ino: u64) -> u64 {
        let (ag_num, ag_ino) = split_inode_number(
            ino,
            self.sb_data.ag_block_log,
            self.sb_data.inode_per_block_log,
        );

        let inodes_per_block = (self.sb_data.block_size / self.sb_data.inode_size as u32) as u64;
        let ag_start = self.ag_offset(ag_num);
        let block_in_ag = ag_ino as u64 / inodes_per_block;
        let offset_in_block = (ag_ino as u64 % inodes_per_block) * (self.sb_data.inode_size as u64);

        ag_start + block_in_ag * (self.sb_data.block_size as u64) + offset_in_block
    }

    /// Read a block.
    fn read_block(&self, block_num: u64) -> Result<Vec<u8>> {
        let offset = self.block_offset(block_num);
        let mut buffer = vec![0u8; self.sb_data.block_size as usize];
        self.device.read_at(offset, &mut buffer)?;
        Ok(buffer)
    }

    /// Write a block.
    fn write_block(&self, block_num: u64, data: &[u8]) -> Result<()> {
        let offset = self.block_offset(block_num);
        self.device.write_at(offset, data)?;
        Ok(())
    }

    /// Read an inode.
    pub fn read_inode(&self, ino: u64) -> Result<Inode> {
        let offset = self.inode_offset(ino);
        let mut buffer = vec![0u8; self.sb_data.inode_size as usize];
        self.device.read_at(offset, &mut buffer)?;

        Inode::parse(&buffer, self.sb_data.inode_size as usize)
            .map_err(|e| XfsVfsError::Xfs(format!("Failed to parse inode {}: {:?}", ino, e)))
    }

    /// Write an inode.
    fn write_inode(&self, ino: u64, inode: &Inode) -> Result<()> {
        if inode.core.version >= 3 && inode.core.ino != ino {
            return Err(XfsVfsError::Vfs(FsError::InvalidArgument));
        }

        let offset = self.inode_offset(ino);
        let inode_size = self.sb_data.inode_size as usize;

        // Serialize inode
        let mut buffer = inode.core.to_bytes();

        // Serialize data fork
        let data_fork_bytes = self.serialize_data_fork(&inode.data_fork)?;

        let total_size = buffer.len() + data_fork_bytes.len();
        if total_size > inode_size {
            return Err(XfsVfsError::Vfs(FsError::FileTooLarge));
        }

        buffer.extend_from_slice(&data_fork_bytes);
        buffer.resize(inode_size, 0);

        // Recalculate CRC for v5
        if self.is_v5 && inode.core.version >= 3 {
            xfs_rs::crc::recalculate_crc(&mut buffer, 0x64);
        }

        self.device.write_at(offset, &buffer)?;
        Ok(())
    }

    /// Serialize data fork to bytes.
    fn serialize_data_fork(&self, data_fork: &DataFork) -> Result<Vec<u8>> {
        match data_fork {
            DataFork::Device { major, minor } => {
                let dev = ((*major as u32 & 0xFF) << 8) | (*minor as u32 & 0xFF);
                Ok(dev.to_be_bytes().to_vec())
            }
            DataFork::Local(data) => Ok(data.clone()),
            DataFork::Extents(extents) => {
                let mut buffer = Vec::with_capacity(extents.len() * Extent::SIZE);
                for extent in extents {
                    buffer.extend_from_slice(&extent.to_bytes());
                }
                Ok(buffer)
            }
            DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                let mut buffer = Vec::with_capacity(4 + data.len());
                buffer.extend_from_slice(&level.to_be_bytes());
                buffer.extend_from_slice(&num_recs.to_be_bytes());
                buffer.extend_from_slice(data);
                Ok(buffer)
            }
            DataFork::Empty => Ok(Vec::new()),
        }
    }

    /// Update inode timestamps.
    fn update_timestamps(&self, core: &mut InodeCore, atime: bool, mtime: bool, ctime: bool) {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let secs = now.as_secs() as u32;
        let nsecs = now.subsec_nanos();

        if atime {
            core.atime_sec = secs;
            core.atime_nsec = nsecs;
        }
        if mtime {
            core.mtime_sec = secs;
            core.mtime_nsec = nsecs;
        }
        if ctime {
            core.ctime_sec = secs;
            core.ctime_nsec = nsecs;
        }
        if core.version >= 3 {
            core.changecount = core.changecount.wrapping_add(1);
        }
    }

    /// Read AGI.
    fn read_agi(&self, ag_num: u32) -> Result<Vec<u8>> {
        let ag_start = self.ag_offset(ag_num);
        let agi_offset = ag_start + 2 * self.sb_data.sector_size as u64;
        let mut buffer = vec![0u8; self.sb_data.sector_size as usize];
        self.device.read_at(agi_offset, &mut buffer)?;
        Ok(buffer)
    }

    /// Find a free inode in an AG.
    fn find_free_inode_in_ag(&self, ag_num: u32) -> Result<Option<(u64, InodeBtreeRec)>> {
        let agi_buffer = self.read_agi(ag_num)?;
        if agi_buffer.len() < 32 {
            return Err(XfsVfsError::Xfs("AGI too small".to_string()));
        }

        let magic = u32::from_be_bytes(agi_buffer[0..4].try_into().unwrap());
        if magic != 0x58414749 {
            // "XAGI"
            return Err(XfsVfsError::Xfs("Invalid AGI magic".to_string()));
        }

        let ibt_root = u32::from_be_bytes(agi_buffer[20..24].try_into().unwrap());
        if ibt_root == 0 || ibt_root == NULLAGBLOCK {
            return Ok(None);
        }

        self.search_ibt_for_free_inodes(ag_num, ibt_root)
    }

    fn search_ibt_for_free_inodes(
        &self,
        ag_num: u32,
        ibt_root: u32,
    ) -> Result<Option<(u64, InodeBtreeRec)>> {
        let ag_start_block = (ag_num as u64) * (self.sb_data.ag_blocks as u64);
        let btree_block_num = ag_start_block + ibt_root as u64;
        let btree_buffer = self.read_block(btree_block_num)?;

        let header = InodeBtreeBlock::parse(&btree_buffer, self.is_v5)
            .map_err(|e| XfsVfsError::Xfs(format!("Failed to parse IBT: {:?}", e)))?;

        if !header.is_leaf() {
            // Traverse down (simplified: follow leftmost)
            let header_size = header.header_size(self.is_v5);
            let ptr_offset = header_size + (header.num_recs as usize) * 4;
            let child_block =
                u32::from_be_bytes(btree_buffer[ptr_offset..ptr_offset + 4].try_into().unwrap());
            return self.search_ibt_for_free_inodes(ag_num, child_block);
        }

        if let Some((rec, _)) = find_free_inode_in_ibt(&btree_buffer, &header, self.is_v5)
            .map_err(|e| XfsVfsError::Xfs(format!("IBT search failed: {:?}", e)))?
        {
            let local_free = rec
                .first_free_inode()
                .ok_or_else(|| XfsVfsError::Xfs("Record has no free inode".to_string()))?;

            let abs_ino = make_absolute_inode(
                ag_num,
                local_free,
                self.sb_data.ag_block_log,
                self.sb_data.inode_per_block_log,
            );
            return Ok(Some((abs_ino, rec)));
        }

        Ok(None)
    }

    /// Allocate a new inode.
    fn allocate_inode(&self, mode: u16) -> Result<u64> {
        tracing::debug!(
            "{}Allocation: searching for free inode (mode 0o{:o})",
            COLOR_DIM,
            mode
        );

        for ag_num in 0..self.sb_data.ag_count {
            if let Some((ino, mut rec)) = self.find_free_inode_in_ag(ag_num)? {
                let local_idx = rec.first_free_inode().unwrap();
                let idx_in_chunk = local_idx - rec.start_ino;
                rec.allocate_inode(idx_in_chunk);

                // Initialize the inode
                let core = create_empty_inode_core(
                    mode,
                    0,
                    0,
                    if self.is_v5 { 3 } else { 2 },
                    ino,
                    &self.sb_data.uuid,
                );

                let data_fork = if (mode & 0o170000) == 0o040000 {
                    DataFork::Local(Vec::new())
                } else {
                    DataFork::Empty
                };

                let inode = Inode { core, data_fork };
                self.write_inode(ino, &inode)?;

                tracing::info!(
                    "{}{} {}{}Allocated Inode {}{}{} (AG {}){}",
                    COLOR_CREATE,
                    SYM_CREATE,
                    BOLD,
                    COLOR_INODE,
                    ino,
                    RESET,
                    COLOR_DIM,
                    ag_num,
                    RESET
                );

                return Ok(ino);
            }
        }

        Err(XfsVfsError::Vfs(FsError::NoSpace))
    }

    /// Create a new file or directory entry.
    pub fn create_entry(&self, parent_inode: u64, name: &str, mode: u16) -> Result<u64> {
        let is_dir = (mode & 0o170000) == 0o040000;
        let type_label = if is_dir { "DIR" } else { "FILE" };

        tracing::info!(
            "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
            COLOR_CREATE
        );
        tracing::info!(
            "{}║ {}{} {}{}CREATING {}{}: {}{}{} {}║",
            COLOR_CREATE,
            COLOR_CREATE,
            SYM_CREATE,
            BOLD,
            color_for_type(mode),
            type_label,
            RESET,
            BOLD,
            name,
            RESET,
            COLOR_CREATE
        );
        tracing::info!(
            "{}║ {}Parent Inode: {}{}{}, Mode: {}0o{:o}{}{} ║",
            COLOR_CREATE,
            COLOR_DIM,
            BOLD,
            parent_inode,
            RESET,
            BOLD,
            mode,
            RESET,
            COLOR_CREATE
        );
        tracing::info!(
            "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
            COLOR_CREATE
        );

        let new_ino = self.allocate_inode(mode)?;
        let mut parent = self.read_inode(parent_inode)?;

        let file_type = if is_dir {
            DirFileType::Directory
        } else {
            DirFileType::RegularFile
        };
        let new_entry = NewDirEntry::new(name.as_bytes(), new_ino, file_type);

        match &parent.data_fork {
            DataFork::Local(data) => {
                let max_size = (self.sb_data.inode_size as usize) - 100;
                match add_shortform_entry(
                    data,
                    &new_entry,
                    parent_inode,
                    self.sb_data.has_ftype(),
                    max_size,
                ) {
                    Ok(new_data) => {
                        parent.data_fork = DataFork::Local(new_data.clone());
                        parent.core.size = new_data.len() as u64;
                    }
                    Err(_) => {
                        // Try to convert to block format
                        self.convert_shortform_to_block_directory(parent_inode, &mut parent)?;

                        // After conversion, the parent is now in Extents format.
                        // Retry addition in block format.
                        return self.add_block_directory_entry(
                            parent_inode,
                            &mut parent,
                            &new_entry,
                        );
                    }
                }
            }
            _ => return Err(XfsVfsError::Vfs(FsError::NotImplemented)),
        }

        self.update_timestamps(&mut parent.core, false, true, true);

        if is_dir {
            parent.core.nlink = parent.core.nlink.saturating_add(1);
            let mut new_inode = self.read_inode(new_ino)?;
            new_inode.core.nlink = 2;
            let header = ShortformHeader {
                count: 0,
                i8count: 0,
                parent: parent_inode,
            };
            let dir_data = serialize_shortform_header(&header, parent_inode > 0xFFFFFFFF);
            new_inode.data_fork = DataFork::Local(dir_data.clone());
            new_inode.core.size = dir_data.len() as u64;
            new_inode.core.format = InodeFormat::Local;
            self.write_inode(new_ino, &new_inode)?;
        }

        self.write_inode(parent_inode, &parent)?;

        // Flush writes to ensure they're durable before returning
        self.device.flush()?;

        tracing::info!(
            "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
            COLOR_CREATE
        );
        tracing::info!(
            "{}║ {}Successfully created {}{}. Inode: {}{}{}{} ║",
            COLOR_CREATE,
            COLOR_DIM,
            BOLD,
            type_label,
            COLOR_INODE,
            new_ino,
            RESET,
            COLOR_CREATE
        );
        tracing::info!(
            "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
            COLOR_CREATE
        );

        Ok(new_ino)
    }

    /// Delete an entry.
    pub fn delete_entry(
        &self,
        parent_inode_num: u64,
        name: &str,
        target_inode_num: u64,
    ) -> Result<()> {
        let target = self.read_inode(target_inode_num)?;
        let is_dir = (target.core.mode & 0o170000) == 0o040000;

        tracing::info!(
            "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
            COLOR_DELETE
        );
        tracing::info!(
            "{}║ {}{} {}{}DELETING {}: {}{}{} {}║",
            COLOR_DELETE,
            COLOR_DELETE,
            SYM_DELETE,
            BOLD,
            COLOR_DELETE,
            if is_dir { "DIR" } else { "FILE" },
            BOLD,
            name,
            RESET,
            COLOR_DELETE
        );
        tracing::info!(
            "{}║ {}Target Inode: {}{}{}, Parent Inode: {}{}{}{} ║",
            COLOR_DELETE,
            COLOR_DIM,
            BOLD,
            target_inode_num,
            RESET,
            BOLD,
            parent_inode_num,
            RESET,
            COLOR_DELETE
        );
        tracing::info!(
            "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
            COLOR_DELETE
        );

        let mut parent = self.read_inode(parent_inode_num)?;
        let mut target = target;

        match &parent.data_fork {
            DataFork::Local(data) => {
                let new_data =
                    remove_shortform_entry(data, name.as_bytes(), self.sb_data.has_ftype())
                        .map_err(|_| XfsVfsError::Vfs(FsError::NotFound))?;
                parent.data_fork = DataFork::Local(new_data.clone());
                parent.core.size = new_data.len() as u64;
            }
            _ => return Err(XfsVfsError::Vfs(FsError::NotImplemented)),
        }

        target.core.nlink = target.core.nlink.saturating_sub(1);
        if is_dir {
            parent.core.nlink = parent.core.nlink.saturating_sub(1);
        }

        self.update_timestamps(&mut parent.core, false, true, true);
        self.update_timestamps(&mut target.core, false, false, true);

        self.write_inode(parent_inode_num, &parent)?;

        if target.core.nlink == 0 {
            self.free_inode(target_inode_num)?;
        } else {
            self.write_inode(target_inode_num, &target)?;
        }

        // Flush writes to ensure they're durable before returning
        self.device.flush()?;

        tracing::info!(
            "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
            COLOR_DELETE
        );
        tracing::info!(
            "{}║ {}Successfully deleted {}{}. Inode: {}{}{}{} ║",
            COLOR_DELETE,
            COLOR_DIM,
            BOLD,
            if is_dir { "DIR" } else { "FILE" },
            COLOR_INODE,
            target_inode_num,
            RESET,
            COLOR_DELETE
        );
        tracing::info!(
            "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
            COLOR_DELETE
        );

        Ok(())
    }

    /// Rename an entry.
    pub fn rename_entry(
        &self,
        old_parent: u64,
        old_name: &str,
        new_parent: u64,
        new_name: &str,
    ) -> Result<()> {
        tracing::info!(
            "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
            COLOR_RENAME
        );
        tracing::info!(
            "{}║ {}{} {}{}RENAMING: {}{}{} -> {}{}{} {}║",
            COLOR_RENAME,
            COLOR_RENAME,
            SYM_RENAME,
            BOLD,
            COLOR_RENAME,
            BOLD,
            old_name,
            RESET,
            BOLD,
            new_name,
            RESET,
            COLOR_RENAME
        );
        tracing::info!(
            "{}║ {}Old Parent: {}{}{}, Old Name: {}\"{}\"{} {}║",
            COLOR_RENAME,
            COLOR_DIM,
            BOLD,
            old_parent,
            RESET,
            BOLD,
            old_name,
            RESET,
            COLOR_RENAME
        );
        tracing::info!(
            "{}║ {}New Parent: {}{}{}, New Name: {}\"{}\"{} {}║",
            COLOR_RENAME,
            COLOR_DIM,
            BOLD,
            new_parent,
            RESET,
            BOLD,
            new_name,
            RESET,
            COLOR_RENAME
        );
        tracing::info!(
            "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
            COLOR_RENAME
        );

        let old_p_ino = self.read_inode(old_parent)?;
        let target_ino = self.find_entry_inode(&old_p_ino, old_name)?;

        // Remove from old
        self.delete_entry(old_parent, old_name, target_ino)?;

        // Add back (fix nlink)
        let mut target = self.read_inode(target_ino)?;
        target.core.nlink = target.core.nlink.saturating_add(1);
        self.write_inode(target_ino, &target)?;

        // Add to new
        let mut new_p_ino = self.read_inode(new_parent)?;
        let is_dir = (target.core.mode & 0o170000) == 0o040000;
        let file_type = if is_dir {
            DirFileType::Directory
        } else {
            DirFileType::RegularFile
        };
        let new_entry = NewDirEntry::new(new_name.as_bytes(), target_ino, file_type);

        match &new_p_ino.data_fork {
            DataFork::Local(data) => {
                let max_size = (self.sb_data.inode_size as usize) - 100;
                let new_data = add_shortform_entry(
                    data,
                    &new_entry,
                    new_parent,
                    self.sb_data.has_ftype(),
                    max_size,
                )
                .map_err(|_| XfsVfsError::Vfs(FsError::NoSpace))?;
                new_p_ino.data_fork = DataFork::Local(new_data.clone());
                new_p_ino.core.size = new_data.len() as u64;
            }
            _ => return Err(XfsVfsError::Vfs(FsError::NotImplemented)),
        }

        self.update_timestamps(&mut new_p_ino.core, false, true, true);
        self.write_inode(new_parent, &new_p_ino)?;

        // Flush writes to ensure they're durable before returning
        self.device.flush()?;

        tracing::info!(
            "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
            COLOR_RENAME
        );
        tracing::info!(
            "{}║ {}Successfully renamed. Target Inode: {}{}{}{} ║",
            COLOR_RENAME,
            COLOR_DIM,
            COLOR_INODE,
            target_ino,
            RESET,
            COLOR_RENAME
        );
        tracing::info!(
            "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
            COLOR_RENAME
        );

        Ok(())
    }

    /// Find an entry's inode number by name in a directory.
    pub fn find_entry_inode(&self, dir_inode: &Inode, name: &str) -> Result<u64> {
        match &dir_inode.data_fork {
            DataFork::Local(data) => {
                let entry = xfs_rs::directory::find_entry_shortform(
                    data,
                    name.as_bytes(),
                    self.sb_data.has_ftype(),
                )
                .map_err(|_| XfsVfsError::Vfs(FsError::NotFound))?;
                Ok(entry.inode)
            }
            _ => Err(XfsVfsError::Vfs(FsError::NotImplemented)),
        }
    }

    /// Write file data.
    pub fn write_file_data(&self, inode_num: u64, offset: u64, data: &[u8]) -> Result<usize> {
        if !data.is_empty() {
            tracing::info!(
                "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
                COLOR_WRITE
            );
            tracing::info!(
                "{}║ {}{} {}{}WRITING {}{} bytes to Inode {}{} at offset {}{} {}║",
                COLOR_WRITE,
                COLOR_WRITE,
                SYM_WRITE,
                BOLD,
                COLOR_WRITE,
                data.len(),
                RESET,
                COLOR_INODE,
                inode_num,
                RESET,
                offset,
                COLOR_WRITE
            );
            tracing::info!(
                "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
                COLOR_WRITE
            );
        }

        let mut inode = self.read_inode(inode_num)?;
        let new_size = offset + data.len() as u64;

        match &mut inode.data_fork {
            DataFork::Local(local_data) => {
                let max_inline = (self.sb_data.inode_size as usize) - 100;
                if new_size as usize <= max_inline {
                    if local_data.len() < new_size as usize {
                        local_data.resize(new_size as usize, 0);
                    }
                    local_data[offset as usize..(offset as usize + data.len())]
                        .copy_from_slice(data);
                    inode.core.size = local_data.len() as u64;
                } else {
                    return Err(XfsVfsError::Vfs(FsError::NotImplemented));
                }
            }
            DataFork::Extents(extents) => {
                let block_size = self.sb_data.block_size as u64;
                let mut written = 0usize;
                let mut curr_off = offset;
                let mut data_pos = 0usize;

                for extent in extents.iter() {
                    if data_pos >= data.len() {
                        break;
                    }
                    let start = extent.file_offset * block_size;
                    let end = start + (extent.block_count as u64) * block_size;
                    if curr_off >= end {
                        continue;
                    }

                    let write_off = if curr_off > start {
                        curr_off - start
                    } else {
                        0
                    };
                    let remain = end - start - write_off;
                    let to_write = (data.len() - data_pos).min(remain as usize);

                    let disk_off = extent.start_block * block_size + write_off;
                    self.device
                        .write_at(disk_off, &data[data_pos..data_pos + to_write])?;

                    written += to_write;
                    data_pos += to_write;
                    curr_off += to_write as u64;
                }

                if written < data.len() {
                    let needed_len = data.len() - written;
                    let block_size = self.sb_data.block_size as u64;
                    let needed_blocks = (needed_len as u64 + block_size - 1) / block_size;

                    self.allocate_blocks_for_inode(inode_num, &mut inode, needed_blocks as u32)?;

                    // retry writing the rest
                    // (Simplified: in a real implementation we'd continue the loop)
                    return self.write_file_data(inode_num, offset, data);
                }
                if new_size > inode.core.size {
                    inode.core.size = new_size;
                }
            }
            _ => return Err(XfsVfsError::Vfs(FsError::NotImplemented)),
        }

        self.update_timestamps(&mut inode.core, false, true, true);
        self.write_inode(inode_num, &inode)?;

        // Flush writes to ensure they're durable before returning
        self.device.flush()?;

        if !data.is_empty() {
            tracing::info!(
                "{}╔════════════════════════════════════════════════════════════════════════════════════════════════════╗",
                COLOR_WRITE
            );
            tracing::info!(
                "{}║ {}Successfully wrote {}{} bytes to Inode {}{}{} ║",
                COLOR_WRITE,
                COLOR_DIM,
                data.len(),
                RESET,
                COLOR_INODE,
                inode_num,
                RESET
            );
            tracing::info!(
                "{}╚════════════════════════════════════════════════════════════════════════════════════════════════════╝",
                COLOR_WRITE
            );
        }

        Ok(data.len())
    }

    /// Truncate file.
    pub fn truncate_file(&self, inode_num: u64, new_size: u64) -> Result<()> {
        let mut inode = self.read_inode(inode_num)?;
        let old_size = inode.core.size;

        if new_size >= old_size {
            inode.core.size = new_size;
        } else {
            match &mut inode.data_fork {
                DataFork::Local(data) => {
                    data.truncate(new_size as usize);
                    inode.core.size = new_size;
                }
                DataFork::Extents(_) => {
                    inode.core.size = new_size;
                }
                _ => {}
            }
        }

        self.update_timestamps(&mut inode.core, false, true, true);
        self.write_inode(inode_num, &inode)?;
        Ok(())
    }

    /// Set timestamps.
    pub fn set_times(
        &self,
        inode_num: u64,
        c: Option<i64>,
        a: Option<i64>,
        m: Option<i64>,
    ) -> Result<()> {
        let mut inode = self.read_inode(inode_num)?;
        if let Some(val) = c {
            inode.core.ctime_sec = val as u32;
        }
        if let Some(val) = a {
            inode.core.atime_sec = val as u32;
        }
        if let Some(val) = m {
            inode.core.mtime_sec = val as u32;
        }
        self.write_inode(inode_num, &inode)?;
        Ok(())
    }

    /// Free an inode.
    fn free_inode(&self, ino: u64) -> Result<()> {
        let (ag_num, ag_ino) = split_inode_number(
            ino,
            self.sb_data.ag_block_log,
            self.sb_data.inode_per_block_log,
        );
        debug!("Freeing inode {} (AG {}, relative {})", ino, ag_num, ag_ino);

        // 1. Update IBT
        let agi_buffer = self.read_agi(ag_num)?;
        let ibt_root = u32::from_be_bytes(agi_buffer[20..24].try_into().unwrap());

        if ibt_root != 0 && ibt_root != NULLAGBLOCK {
            let ag_start_block = (ag_num as u64) * (self.sb_data.ag_blocks as u64);
            let btree_block_num = ag_start_block + ibt_root as u64;
            let mut btree_buffer = self.read_block(btree_block_num)?;
            let header = InodeBtreeBlock::parse(&btree_buffer, self.is_v5)
                .map_err(|e| XfsVfsError::Xfs(format!("Failed to parse IBT: {:?}", e)))?;

            if !header.is_leaf() {
                // For non-leaf nodes, we'd need to traverse the tree
                // For now, just log that we can't handle this case
                warn!("Cannot free inode {} in non-leaf IBT block", ino);
                return Ok(());
            }

            // Find the record containing this inode
            let header_size = header.header_size(self.is_v5);
            let records =
                xfs_rs::inode_alloc::read_inode_btree_records(&btree_buffer, &header, self.is_v5)
                    .map_err(|e| XfsVfsError::Xfs(format!("IBT read records failed: {:?}", e)))?;

            for (i, orig_rec) in records.iter().enumerate() {
                if ag_ino >= orig_rec.start_ino && ag_ino < orig_rec.start_ino + 64 {
                    let mut rec = orig_rec.clone(); // Clone to make it mutable
                    let idx_in_chunk = (ag_ino - rec.start_ino) as u32;
                    if rec.free_inode(idx_in_chunk) {
                        let rec_offset = header_size + i * InodeBtreeRec::SIZE;
                        btree_buffer[rec_offset..rec_offset + InodeBtreeRec::SIZE]
                            .copy_from_slice(&rec.to_bytes());

                        if self.is_v5 {
                            recalculate_crc(&mut btree_buffer, 52);
                        }

                        self.write_block(btree_block_num, &btree_buffer)?;
                        debug!(
                            "Updated IBT block {} (freed inode {})",
                            btree_block_num, ino
                        );
                        break;
                    }
                }
            }
        }

        // 2. Update AGI
        let mut agi = AgInodeHeader::parse(&agi_buffer)
            .map_err(|e| XfsVfsError::Xfs(format!("Failed to parse AGI for free: {:?}", e)))?;
        agi.free_inode_count = agi.free_inode_count.saturating_add(1);

        let updated_agi = agi.to_bytes();
        let mut final_agi_buffer = vec![0u8; self.sb_data.sector_size as usize];
        final_agi_buffer[..updated_agi.len()].copy_from_slice(&updated_agi);

        if self.is_v5 {
            recalculate_crc(&mut final_agi_buffer, 296);
        }

        let ag_start = self.ag_offset(ag_num);
        let agi_offset = ag_start + 2 * self.sb_data.sector_size as u64;
        self.device.write_at(agi_offset, &final_agi_buffer)?;
        debug!(
            "Updated AGI for AG {} (freed inode, new freecount={})",
            ag_num, agi.free_inode_count
        );

        // Flush writes to ensure they're durable before returning
        self.device.flush()?;

        Ok(())
    }

    /// Flush.
    pub fn flush(&self) -> Result<()> {
        self.device.flush()?;
        Ok(())
    }

    /// Allocate new blocks for an inode and add them to its data fork.
    pub fn allocate_blocks_for_inode(
        &self,
        _ino: u64,
        inode: &mut Inode,
        count: u32,
    ) -> Result<()> {
        debug!("Allocating {} blocks for inode {}", count, inode.core.ino);

        let extent = self
            .allocator
            .allocate_blocks(count)?
            .ok_or(XfsVfsError::Vfs(FsError::NoSpace))?;

        // Mark allocated in B+trees
        self.allocator.mark_allocated(&extent)?;

        // Add to inode data fork
        match &mut inode.data_fork {
            DataFork::Extents(extents) => {
                let file_offset = if let Some(last) = extents.last() {
                    last.file_offset + last.block_count as u64
                } else {
                    0
                };

                extents.push(xfs_rs::Extent {
                    file_offset,
                    start_block: self.allocator.to_absolute_block(&extent),
                    block_count: count,
                    is_unwritten: false,
                });
            }
            DataFork::Local(_) => {
                // Convert local to extents first (simplified: error for now)
                return Err(XfsVfsError::Internal(
                    "Local to Extents conversion not implemented".into(),
                ));
            }
            _ => return Err(XfsVfsError::Vfs(FsError::NotImplemented)),
        }

        // Update inode core (blocks count)
        inode.core.nblocks += count as u64;

        Ok(())
    }

    /// Convert a shortform directory to block format.
    pub fn convert_shortform_to_block_directory(&self, ino: u64, inode: &mut Inode) -> Result<()> {
        debug!(
            "Converting directory {} from shortform to block format",
            ino
        );
        let block_size = self.sb_data.block_size as usize;
        let mut block_data = vec![0u8; block_size];
        let is_v5 = self.is_v5;
        let has_ftype = self.sb_data.has_ftype();

        // 1. Initialize block header
        let header_size = if is_v5 {
            let magic = XFS_DIR3_BLOCK_MAGIC;
            block_data[0..4].copy_from_slice(&magic.to_be_bytes());
            // v5 header fields (simplified: zeros for CRC/LSN/UUID/Owner)
            64
        } else {
            let magic = XFS_DIR2_BLOCK_MAGIC;
            block_data[0..4].copy_from_slice(&magic.to_be_bytes());
            16
        };

        // 2. Add "." and ".." entries (Block format always has them)
        let mut offset = header_size;

        // Parent inode is needed for ".."
        let parent_ino = if let DataFork::Local(sf_data) = &inode.data_fork {
            ShortformHeader::parse(sf_data)
                .map(|h| h.parent)
                .unwrap_or(0)
        } else {
            0
        };

        let initial_entries = vec![
            (b".".as_slice(), inode.core.ino, DirFileType::Directory),
            (b"..".as_slice(), parent_ino, DirFileType::Directory),
        ];

        let mut leaf_entries = Vec::new();

        for (name, ino_val, ft) in initial_entries {
            let entry_size = 8 + 1 + name.len() + if has_ftype { 1 } else { 0 } + 2;
            let aligned_size = (entry_size + 7) & !7;

            block_data[offset..offset + 8].copy_from_slice(&ino_val.to_be_bytes());
            block_data[offset + 8] = name.len() as u8;
            block_data[offset + 9..offset + 9 + name.len()].copy_from_slice(name);
            if has_ftype {
                block_data[offset + 9 + name.len()] = ft as u8;
            }
            let tag = offset as u16;
            block_data[offset + aligned_size - 2..offset + aligned_size]
                .copy_from_slice(&tag.to_be_bytes());

            leaf_entries.push(LeafEntry {
                hashval: dir2_hash(name),
                address: (offset / 8) as u32,
            });

            offset += aligned_size;
        }

        // 3. Add existing entries from shortform
        if let DataFork::Local(sf_data) = &inode.data_fork {
            let (_, iter) = parse_shortform_directory(sf_data, has_ftype)
                .map_err(|e| XfsVfsError::Xfs(format!("Failed to parse SF: {:?}", e)))?;
            for entry_res in iter {
                let e: xfs_rs::directory::DirEntry = entry_res
                    .map_err(|e: fs_abstraction::FsError| XfsVfsError::Xfs(format!("{:?}", e)))?;
                if e.is_dot_entry() {
                    continue;
                }

                let name = e.name_bytes();
                let entry_size = 8 + 1 + name.len() + if has_ftype { 1 } else { 0 } + 2;
                let aligned_size = (entry_size + 7) & !7;

                if offset + aligned_size >= block_size - 64 {
                    break;
                }

                block_data[offset..offset + 8].copy_from_slice(&e.inode.to_be_bytes());
                block_data[offset + 8] = name.len() as u8;
                block_data[offset + 9..offset + 9 + name.len()].copy_from_slice(name);
                if has_ftype {
                    block_data[offset + 9 + name.len()] = e.file_type as u8;
                }
                let tag = offset as u16;
                block_data[offset + aligned_size - 2..offset + aligned_size]
                    .copy_from_slice(&tag.to_be_bytes());

                leaf_entries.push(LeafEntry {
                    hashval: dir2_hash(name),
                    address: (offset / 8) as u32,
                });

                offset += aligned_size;
            }
        }

        // 4. Sort leaf entries by hash
        leaf_entries.sort_by_key(|e| e.hashval);

        // 5. Add leaf entries and tail
        let tail_offset = block_size - 8;
        let leaf_offset = tail_offset - (leaf_entries.len() * 8);

        for (i, leaf) in leaf_entries.iter().enumerate() {
            let off = leaf_offset + i * 8;
            block_data[off..off + 4].copy_from_slice(&leaf.hashval.to_be_bytes());
            block_data[off + 4..off + 8].copy_from_slice(&leaf.address.to_be_bytes());
        }

        let tail = BlockTail {
            count: leaf_entries.len() as u32,
            stale: 0,
        };
        block_data[tail_offset..tail_offset + 4].copy_from_slice(&tail.count.to_be_bytes());
        block_data[tail_offset + 4..tail_offset + 8].copy_from_slice(&tail.stale.to_be_bytes());

        // 6. Recalculate CRC if v5
        if is_v5 {
            // Setup v5 fields
            block_data[8..16].copy_from_slice(&0u64.to_be_bytes()); // Block no (to be set after allocation)
            block_data[16..24].copy_from_slice(&0u64.to_be_bytes()); // LSN
            block_data[24..40].copy_from_slice(&self.sb_data.uuid);
            block_data[40..48].copy_from_slice(&ino.to_be_bytes()); // Owner
        }

        // 7. Allocate and write
        let extent = self
            .allocator
            .allocate_blocks(1)?
            .ok_or(XfsVfsError::Vfs(FsError::NoSpace))?;
        self.allocator.mark_allocated(&extent)?;

        let abs_block = self.allocator.to_absolute_block(&extent);

        if is_v5 {
            block_data[8..16].copy_from_slice(&abs_block.to_be_bytes());
            recalculate_crc(&mut block_data, 4);
        }

        self.device
            .write_at(abs_block * block_size as u64, &block_data)?;

        // 8. Update inode
        inode.core.format = InodeFormat::Extents;
        inode.core.size = block_size as u64;
        inode.core.nblocks = 1;
        inode.data_fork = DataFork::Extents(vec![xfs_rs::Extent {
            file_offset: 0,
            start_block: abs_block,
            block_count: 1,
            is_unwritten: false,
        }]);

        self.write_inode(ino, inode)?;
        Ok(())
    }

    /// Add an entry to a block-format directory.
    pub fn add_block_directory_entry(
        &self,
        ino: u64,
        inode: &mut Inode,
        new_entry: &NewDirEntry,
    ) -> Result<u64> {
        let block_size = self.sb_data.block_size as usize;

        // 1. Get the directory block (Block format has only 1 block at offset 0)
        let extents = if let DataFork::Extents(e) = &inode.data_fork {
            e
        } else {
            return Err(XfsVfsError::Internal("Not in Extents format".into()));
        };

        if extents.is_empty() {
            return Err(XfsVfsError::Internal("Directory has no extents".into()));
        }

        let abs_block = extents[0].start_block;
        let mut block_data = vec![0u8; block_size];
        self.device
            .read_at(abs_block * block_size as u64, &mut block_data)?;

        let is_v5 = self.is_v5;
        let has_ftype = self.sb_data.has_ftype();

        // 2. Parse block metadata
        let tail_offset = block_size - 8;
        let tail = BlockTail::parse(&block_data, tail_offset)
            .map_err(|e| XfsVfsError::Xfs(format!("Tail parse failed: {:?}", e)))?;

        let header_size = if is_v5 { 64 } else { 16 };

        // 3. Find free space for the new entry
        let name = &new_entry.name;
        let entry_size = 8 + 1 + name.len() + if has_ftype { 1 } else { 0 } + 2;
        let aligned_entry_size = (entry_size + 7) & !7;

        let leaf_start = tail_offset - (tail.count as usize * 8);

        let mut offset = header_size;
        let mut found_offset = 0usize;

        while offset < leaf_start {
            let freetag = u16::from_be_bytes([block_data[offset], block_data[offset + 1]]);
            if freetag == 0xFFFF {
                let length =
                    u16::from_be_bytes([block_data[offset + 2], block_data[offset + 3]]) as usize;
                if length >= aligned_entry_size {
                    found_offset = offset;
                    // Split free space if there's enough left
                    if length > aligned_entry_size + 16 {
                        let remaining = length - aligned_entry_size;
                        let new_free_off = offset + aligned_entry_size;
                        block_data[new_free_off..new_free_off + 2]
                            .copy_from_slice(&0xFFFFu16.to_be_bytes());
                        block_data[new_free_off + 2..new_free_off + 4]
                            .copy_from_slice(&(remaining as u16).to_be_bytes());
                    }
                    break;
                }
                offset += length;
            } else {
                // Skip data entry
                let e_name_len = block_data[offset + 8] as usize;
                let e_size = 8 + 1 + e_name_len + if has_ftype { 1 } else { 0 } + 2;
                offset += (e_size + 7) & !7;
            }
        }

        if found_offset == 0 {
            return Err(XfsVfsError::Internal(
                "Block to Leaf directory conversion not implemented".into(),
            ));
        }

        // 4. Insert entry
        block_data[found_offset..found_offset + 8].copy_from_slice(&new_entry.inode.to_be_bytes());
        block_data[found_offset + 8] = name.len() as u8;
        block_data[found_offset + 9..found_offset + 9 + name.len()].copy_from_slice(name);
        if has_ftype {
            block_data[found_offset + 9 + name.len()] = new_entry.file_type as u8;
        }
        let tag = found_offset as u16;
        block_data[found_offset + aligned_entry_size - 2..found_offset + aligned_entry_size]
            .copy_from_slice(&tag.to_be_bytes());

        // 5. Update leaf entries
        let mut leaf_entries = Vec::new();
        for i in 0..tail.count as usize {
            let off = leaf_start + i * 8;
            leaf_entries.push(LeafEntry {
                hashval: u32::from_be_bytes([
                    block_data[off],
                    block_data[off + 1],
                    block_data[off + 2],
                    block_data[off + 3],
                ]),
                address: u32::from_be_bytes([
                    block_data[off + 4],
                    block_data[off + 5],
                    block_data[off + 6],
                    block_data[off + 7],
                ]),
            });
        }

        leaf_entries.push(LeafEntry {
            hashval: dir2_hash(name),
            address: (found_offset / 8) as u32,
        });
        leaf_entries.sort_by_key(|e| e.hashval);

        let new_leaf_start = leaf_start - 8;
        if new_leaf_start < offset {
            return Err(XfsVfsError::Internal("No room for new leaf entry".into()));
        }

        for (i, leaf) in leaf_entries.iter().enumerate() {
            let off = new_leaf_start + i * 8;
            block_data[off..off + 4].copy_from_slice(&leaf.hashval.to_be_bytes());
            block_data[off + 4..off + 8].copy_from_slice(&leaf.address.to_be_bytes());
        }

        // 6. Update tail
        let new_tail = BlockTail {
            count: leaf_entries.len() as u32,
            stale: 0,
        };
        block_data[tail_offset..tail_offset + 4].copy_from_slice(&new_tail.count.to_be_bytes());
        block_data[tail_offset + 4..tail_offset + 8].copy_from_slice(&new_tail.stale.to_be_bytes());

        // 7. Write back
        if is_v5 {
            recalculate_crc(&mut block_data, 4);
        }
        self.device
            .write_at(abs_block * block_size as u64, &block_data)?;

        self.write_inode(ino, inode)?;

        Ok(new_entry.inode)
    }
}

fn color_for_type(mode: u16) -> &'static str {
    match mode & 0o170000 {
        0o040000 => "\x1b[1;34m", // Bold Blue
        _ => "\x1b[0;37m",        // White
    }
}
