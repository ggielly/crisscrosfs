//! Directory operations for XFS VFS.

use fs_abstraction::{FsError, FsResult, VfsDirEntry, VfsFileType};
use xfs_rs::{
    btree::{self, BlockReader, BmbtRoot},
    directory::{parse_shortform_directory, DirFileType},
    DataFork, Inode,
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

/// Upper bound on directory data blocks read for one listing.  A corrupted
/// extent map must not be able to stall the service indefinitely.
const MAX_DIRECTORY_BLOCKS: u64 = 1 << 20;

/// Parse directory entries from an XFS inode.
pub fn parse_directory_entries(
    inode: &Inode,
    current_ino: u64,
    has_ftype: bool,
    block_size: u32,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<VfsDirEntry>> {
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }

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
    current_ino: u64,
    has_ftype: bool,
) -> FsResult<Vec<VfsDirEntry>> {
    if data.len() < 6 {
        return Err(FsError::Corrupted);
    }

    let (header, iter) =
        parse_shortform_directory(data, has_ftype).map_err(|_| FsError::Corrupted)?;

    // Shortform headers store the parent inode separately instead of listing
    // "." and ".."; synthesize them so every directory format exposes the same
    // entries.
    let mut entries = Vec::with_capacity(header.count as usize + 2);
    entries.push(VfsDirEntry {
        name: ".".to_string(),
        ino: current_ino,
        file_type: VfsFileType::Directory,
        offset: 1,
    });
    entries.push(VfsDirEntry {
        name: "..".to_string(),
        ino: header.parent,
        file_type: VfsFileType::Directory,
        offset: 2,
    });

    let mut offset: u64 = 3; // Start after . and ..

    for result in iter {
        let entry = result.map_err(|_| FsError::Corrupted)?;

        // Reject non-UTF-8 names rather than lossily folding distinct names
        // onto the same U+FFFD replacement string.
        let name = std::str::from_utf8(entry.name_bytes())
            .map_err(|_| FsError::Corrupted)?
            .to_string();

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
    let leaf_offset_blocks = XFS_DIR2_LEAF_OFFSET_BYTES / block_size as u64;
    let mut blocks_read: u64 = 0;
    let mut previous_end: u64 = 0;

    for extent in extents {
        if extent.block_count == 0 {
            continue;
        }

        // Extents must be sorted and non-overlapping.
        if extent.file_offset < previous_end {
            return Err(FsError::Corrupted);
        }
        previous_end = extent.file_end()?;

        // Skip leaf/free-index address space (not data blocks).
        if extent.file_offset >= leaf_offset_blocks {
            continue;
        }

        for block_idx in 0..extent.block_count {
            blocks_read += 1;
            if blocks_read > MAX_DIRECTORY_BLOCKS {
                return Err(FsError::Corrupted);
            }
            let block_num = extent
                .start_block
                .checked_add(block_idx as u64)
                .ok_or(FsError::ArithmeticOverflow)?;
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
    let mut blocks_read: u64 = 0;

    for extent in &extents {
        // Skip leaf and free-index extents
        if extent.file_offset >= leaf_offset_blocks {
            continue;
        }

        for block_idx in 0..extent.block_count {
            blocks_read += 1;
            if blocks_read > MAX_DIRECTORY_BLOCKS {
                return Err(FsError::Corrupted);
            }
            let block_num = extent
                .start_block
                .checked_add(block_idx as u64)
                .ok_or(FsError::ArithmeticOverflow)?;
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

    // A directory data block always has at least the 16-byte v2 header.
    if block_data.len() < 16 {
        return Err(FsError::Corrupted);
    }

    let magic = &block_data[0..4];

    // Data blocks contain directory entries.  Leaf blocks (hash index) and
    // free-index blocks are metadata and must never be parsed as entries,
    // even when they are mapped by the inode's extent list.  Single-block
    // directories (XD2B/XDB3) contain both data entries and an embedded leaf;
    // the data area ends where the leaf entries begin.
    let is_data_block = magic == b"XD2D" || magic == b"XDD3"; // v2/v3 data
    let is_single_block = magic == b"XD2B" || magic == b"XDB3"; // v2/v3 block
    let is_index_block = magic == b"XD2L"
        || magic == b"XDL3" // v2/v3 leaf
        || magic == b"XD2F"
        || magic == b"XDF3"; // v2/v3 free index

    if is_index_block {
        return Ok(entries);
    }
    if !is_data_block && !is_single_block {
        // Unknown magic is corruption, not an empty directory.
        return Err(FsError::Corrupted);
    }

    // Data block header is 16 bytes for v2, 64 bytes for v3.
    let header_size = if magic[3] == b'3' { 64 } else { 16 };
    if block_data.len() < header_size {
        return Err(FsError::Corrupted);
    }

    let end = if is_single_block {
        // The last 8 bytes are xfs_dir2_block_tail { count, stale } and the
        // leaf entries are stored immediately before it.
        if block_data.len() < header_size + 8 {
            return Err(FsError::Corrupted);
        }
        let tail_offset = block_data.len() - 8;
        let leaf_count = u32::from_be_bytes(
            block_data[tail_offset..tail_offset + 4]
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        ) as usize;
        let leaf_bytes = leaf_count
            .checked_mul(8)
            .ok_or(FsError::ArithmeticOverflow)?;
        let leaf_start = tail_offset
            .checked_sub(leaf_bytes)
            .ok_or(FsError::Corrupted)?;
        if leaf_start < header_size {
            return Err(FsError::Corrupted);
        }
        leaf_start
    } else {
        block_data.len()
    };

    let mut offset = header_size;

    // Parse the sequence of entries and free-space records.
    while offset + 4 <= end {
        let free_tag = u16::from_be_bytes([block_data[offset], block_data[offset + 1]]);

        if free_tag == 0xFFFF {
            // XFS free space record: freetag (2) + length (2), where `length`
            // is the total size of the free region (including the tag and the
            // trailing offset tag).
            if offset + 4 > end {
                return Err(FsError::Corrupted);
            }
            let free_len =
                u16::from_be_bytes([block_data[offset + 2], block_data[offset + 3]]) as usize;
            let next = offset
                .checked_add(free_len)
                .ok_or(FsError::ArithmeticOverflow)?;
            if free_len < 6 || next > end {
                return Err(FsError::Corrupted);
            }
            offset = next;
            continue;
        }

        // Allocated entry: inode(8) + namelen(1) + name + [ftype(1)] + tag(2),
        // padded to an 8-byte boundary.
        if offset + 9 > end {
            return Err(FsError::Corrupted);
        }
        let entry_ino = u64::from_be_bytes(
            block_data[offset..offset + 8]
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        );
        if entry_ino == 0 {
            // Inode 0 is not a valid directory entry.
            return Err(FsError::Corrupted);
        }

        let name_len = block_data[offset + 8] as usize;
        if name_len == 0 || name_len > 255 {
            return Err(FsError::Corrupted);
        }

        let name_start = offset + 9;
        let name_end = name_start
            .checked_add(name_len)
            .ok_or(FsError::ArithmeticOverflow)?;
        if name_end > end {
            return Err(FsError::Corrupted);
        }

        let file_type = if has_ftype {
            if name_end >= end {
                return Err(FsError::Corrupted);
            }
            dir_file_type_from_u8(block_data[name_end])
        } else {
            VfsFileType::Unknown
        };

        // Reject names that are not valid UTF-8 instead of lossily converting
        // them: two distinct XFS names could otherwise collide on U+FFFD.
        let name = std::str::from_utf8(&block_data[name_start..name_end])
            .map_err(|_| FsError::Corrupted)?
            .to_string();

        // The entry includes a 2-byte tag after name/ftype, then is rounded up
        // to 8 bytes (xfs_dir2_data_entsize).
        let payload_end = name_end + usize::from(has_ftype);
        let next = payload_end
            .checked_add(2)
            .and_then(|n| n.checked_add(7))
            .ok_or(FsError::ArithmeticOverflow)?
            & !7;
        if next > end {
            return Err(FsError::Corrupted);
        }
        offset = next;

        entries.push(VfsDirEntry {
            name,
            ino: entry_ino,
            file_type,
            offset: 0, // Will be set by caller
        });
    }

    // Only zero padding may remain after the last entry/free record.
    if offset < end && block_data[offset..end].iter().any(|&b| b != 0) {
        return Err(FsError::Corrupted);
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

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_data_block() -> Vec<u8> {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"XD2D");
        block
    }

    fn write_entry(block: &mut [u8], offset: usize, ino: u64, name: &[u8], ftype: u8) -> usize {
        block[offset..offset + 8].copy_from_slice(&ino.to_be_bytes());
        block[offset + 8] = name.len() as u8;
        block[offset + 9..offset + 9 + name.len()].copy_from_slice(name);
        let mut end = offset + 9 + name.len();
        block[end] = ftype;
        end += 1;
        (end + 2 + 7) & !7
    }

    fn write_free(block: &mut [u8], offset: usize, length: usize) {
        block[offset..offset + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());
        block[offset + 2..offset + 4].copy_from_slice(&(length as u16).to_be_bytes());
    }

    #[test]
    fn parses_entry_followed_by_free_space() {
        let mut block = empty_data_block();
        let next = write_entry(&mut block, 16, 200, b"abc", 1);
        let free_len = block.len() - next;
        write_free(&mut block, next, free_len);

        let entries = parse_directory_block(&block, true, 512).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ino, 200);
        assert_eq!(entries[0].name, "abc");
        assert_eq!(entries[0].file_type, VfsFileType::RegularFile);
    }

    #[test]
    fn free_record_length_is_honoured() {
        let mut block = empty_data_block();
        let first_end = write_entry(&mut block, 16, 200, b"a", 1);
        write_free(&mut block, first_end, 16);
        let second = first_end + 16;
        let second_end = write_entry(&mut block, second, 201, b"b", 2);
        let free_len = block.len() - second_end;
        write_free(&mut block, second_end, free_len);

        let entries = parse_directory_block(&block, true, 512).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "a");
        assert_eq!(entries[1].name, "b");
    }

    #[test]
    fn single_block_directory_stops_before_leaf_entries() {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"XD2B");

        let next = write_entry(&mut block, 16, 200, b"abc", 1);
        let tail_offset = block.len() - 8;
        let leaf_start = tail_offset - 8; // one leaf entry
        let free_len = leaf_start - next;
        write_free(&mut block, next, free_len);
        block[tail_offset..tail_offset + 4].copy_from_slice(&1u32.to_be_bytes());

        let entries = parse_directory_block(&block, true, 512).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "abc");
    }

    #[test]
    fn index_blocks_are_not_parsed_as_entries() {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"XD2L");
        assert!(parse_directory_block(&block, true, 512).unwrap().is_empty());
    }

    #[test]
    fn unknown_magic_is_corruption() {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"JUNK");
        assert!(matches!(
            parse_directory_block(&block, true, 512),
            Err(FsError::Corrupted)
        ));
    }
}
