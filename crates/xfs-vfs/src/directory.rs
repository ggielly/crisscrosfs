//! Directory operations for XFS VFS.

use fs_abstraction::{FsError, FsResult, VfsDirEntry, VfsFileType};
use xfs_rs::{
    btree::{self, BlockReader, BmbtRoot},
    directory::{parse_shortform_directory, DirFileType},
    DataFork,
    Inode,
};

/// Adapter to implement `BlockReader` from a closure.
struct ClosureBlockReader<'a, F: Fn(u64) -> FsResult<Vec<u8>>>(&'a F);

impl<F: Fn(u64) -> FsResult<Vec<u8>>> BlockReader for ClosureBlockReader<'_, F> {
    fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
        (self.0)(block_num)
    }
}

/// XFS directory leaf space starts at 32 GiB (in bytes).
/// Extents with file_offset >= this threshold (in filesystem blocks) are
/// leaf/free-index blocks, not data blocks containing directory entries.
const XFS_DIR2_LEAF_OFFSET_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Parse directory entries from an XFS inode.
pub fn parse_directory_entries(
    inode: &Inode,
    current_ino: u64,
    has_ftype: bool,
    block_size: u32,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<VfsDirEntry>> {
    match &inode.data_fork {
        DataFork::Local(data) => parse_shortform_directory_entries(data, current_ino, has_ftype),
        DataFork::Extents(extents) => {
            parse_extent_directory_entries(extents, has_ftype, block_size, read_block)
        }
        DataFork::Btree {
            level,
            num_recs,
            data,
        } => parse_btree_directory_entries(
            *level, *num_recs, data, has_ftype, block_size, is_v5, read_block,
        ),
        _ => Err(FsError::NotSupported),
    }
}

/// Parse shortform directory entries.
fn parse_shortform_directory_entries(
    data: &[u8],
    _current_ino: u64,
    has_ftype: bool,
) -> FsResult<Vec<VfsDirEntry>> {
    if data.len() < 6 {
        return Ok(Vec::new());
    }

    let (header, iter) =
        parse_shortform_directory(data, has_ftype).map_err(|_| FsError::Corrupted)?;

    let mut entries = Vec::with_capacity(header.count as usize);
    let mut offset: u64 = 3; // Start after . and ..

    for result in iter {
        let entry = result.map_err(|_| FsError::Corrupted)?;

        let name = match std::str::from_utf8(entry.name_bytes()) {
            Ok(s) => s.to_string(),
            Err(_) => {
                // Try lossy conversion for non-UTF8 names
                String::from_utf8_lossy(entry.name_bytes()).into_owned()
            }
        };

        entries.push(VfsDirEntry {
            name,
            ino: entry.inode,
            file_type: dir_file_type_to_vfs(entry.file_type),
            offset,
        });
        offset += 1;
    }

    Ok(entries)
}

/// Parse extent-based directory entries.
fn parse_extent_directory_entries(
    extents: &[xfs_rs::Extent],
    has_ftype: bool,
    block_size: u32,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<VfsDirEntry>> {
    let mut entries = Vec::new();
    let mut offset: u64 = 3;

    for extent in extents {
        if extent.block_count == 0 {
            continue;
        }

        for block_idx in 0..extent.block_count {
            let block_num = extent.start_block + block_idx as u64;
            let block_data = read_block(block_num)?;

            let block_entries = parse_directory_block(&block_data, has_ftype, block_size)?;
            for mut entry in block_entries {
                entry.offset = offset;
                offset += 1;
                entries.push(entry);
            }
        }
    }

    Ok(entries)
}

/// Parse btree-based directory entries.
///
/// For large directories, XFS stores the extent map as a B+tree in the inode's
/// data fork. The extents map three logical address spaces:
/// - Data blocks (file_offset < 32 GiB / block_size): actual directory entries
/// - Leaf blocks (>= 32 GiB threshold): hash index — skipped
/// - Free index blocks (>= 64 GiB threshold): free space map — skipped
///
/// We collect all extents from the B+tree, filter to data blocks only,
/// then parse directory entries from each data block.
fn parse_btree_directory_entries(
    level: u16,
    num_recs: u16,
    data: &[u8],
    has_ftype: bool,
    block_size: u32,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<VfsDirEntry>> {
    // 1. Parse the B+tree root from the inode data fork
    let root = BmbtRoot::parse(data, level, num_recs)?;

    // 2. Collect all extent mappings by traversing the B+tree
    let reader = ClosureBlockReader(&read_block);
    let extents = btree::btree_collect_extents(&root, &reader, is_v5)?;

    // 3. Threshold: only read DATA blocks (logical offset < leaf space)
    let leaf_offset_blocks = XFS_DIR2_LEAF_OFFSET_BYTES / block_size as u64;

    // 4. Read and parse directory entries from data blocks
    let mut entries = Vec::new();
    let mut dir_offset: u64 = 3; // Start after . and ..

    for extent in &extents {
        // Skip leaf and free-index extents
        if extent.file_offset >= leaf_offset_blocks {
            continue;
        }

        for block_idx in 0..extent.block_count {
            let block_num = extent.start_block + block_idx as u64;
            let block_data = read_block(block_num)?;

            let block_entries = parse_directory_block(&block_data, has_ftype, block_size)?;
            for mut entry in block_entries {
                entry.offset = dir_offset;
                dir_offset += 1;
                entries.push(entry);
            }
        }
    }

    tracing::debug!(
        "Btree directory: collected {} extents, {} data entries",
        extents.len(),
        entries.len()
    );

    Ok(entries)
}

/// Parse a single directory block.
fn parse_directory_block(
    block_data: &[u8],
    has_ftype: bool,
    _block_size: u32,
) -> FsResult<Vec<VfsDirEntry>> {
    let mut entries = Vec::new();

    // Check block magic
    if block_data.len() < 16 {
        return Ok(entries);
    }

    let magic = &block_data[0..4];
    let is_data_block = magic == b"XD2D" || magic == b"XDD3"; // v2/v3 data blocks
    let is_leaf_block = magic == b"XD2L" || magic == b"XDL3"; // v2/v3 leaf blocks

    if !is_data_block && !is_leaf_block {
        // Unknown block type, skip
        return Ok(entries);
    }

    // Data block header is 16 bytes for v2, larger for v3
    let header_size = if magic[3] == b'3' { 64 } else { 16 };
    let mut offset = header_size;

    // Free space info
    if offset + 4 > block_data.len() {
        return Ok(entries);
    }

    // Parse directory entries
    while offset + 8 < block_data.len() {
        // Each entry starts with inode (8 bytes)
        let entry_ino = u64::from_be_bytes(
            block_data[offset..offset + 8]
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        );

        if entry_ino == 0 {
            // Free entry, skip
            offset += 8;
            continue;
        }

        offset += 8;

        // Name length (1 byte)
        if offset >= block_data.len() {
            break;
        }
        let name_len = block_data[offset] as usize;
        offset += 1;

        // Name
        if offset + name_len > block_data.len() {
            break;
        }
        let name_bytes = &block_data[offset..offset + name_len];
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        offset += name_len;

        // File type (if has_ftype)
        let file_type = if has_ftype {
            if offset >= block_data.len() {
                break;
            }
            let ft = block_data[offset];
            offset += 1;
            dir_file_type_from_u8(ft)
        } else {
            VfsFileType::Unknown
        };

        // Align to 8-byte boundary
        offset = (offset + 7) & !7;

        entries.push(VfsDirEntry {
            name,
            ino: entry_ino,
            file_type,
            offset: 0, // Will be set by caller
        });
    }

    Ok(entries)
}

/// Convert XFS directory file type to VFS file type.
pub fn dir_file_type_to_vfs(dt: DirFileType) -> VfsFileType {
    match dt {
        DirFileType::RegularFile => VfsFileType::RegularFile,
        DirFileType::Directory => VfsFileType::Directory,
        DirFileType::CharDevice => VfsFileType::CharDevice,
        DirFileType::BlockDevice => VfsFileType::BlockDevice,
        DirFileType::Fifo => VfsFileType::Fifo,
        DirFileType::Socket => VfsFileType::Socket,
        DirFileType::SymbolicLink => VfsFileType::Symlink,
        DirFileType::Unknown => VfsFileType::Unknown,
    }
}

/// Convert u8 to VFS file type.
fn dir_file_type_from_u8(ft: u8) -> VfsFileType {
    match ft {
        1 => VfsFileType::RegularFile,
        2 => VfsFileType::Directory,
        3 => VfsFileType::CharDevice,
        4 => VfsFileType::BlockDevice,
        5 => VfsFileType::Fifo,
        6 => VfsFileType::Socket,
        7 => VfsFileType::Symlink,
        _ => VfsFileType::Unknown,
    }
}

/// Find an entry by name in a directory.
pub fn find_entry_by_name<'a>(entries: &'a [VfsDirEntry], name: &str) -> Option<&'a VfsDirEntry> {
    entries.iter().find(|e| e.name == name)
}
