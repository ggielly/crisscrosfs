//! Directory operations for XFS VFS.

use fs_abstraction::{FsError, FsResult, VfsDirEntry, VfsFileType};
use xfs_rs::{
    btree::{self, BmbtRoot},
    directory::{
        lookup_directory,
        parse_shortform_directory,
        DirFileType,
        DirGeometry,
        DirLookupOptions,
    },
    DataFork,
    Extent,
    Inode,
};

use crate::{
    io::{VfsBlockReader, XfsBtreeReader},
    name_mangling::mangle_bytes,
    read_ops::validate_extents,
};

/// XFS directory leaf space starts at 32 GiB (in bytes).
/// Extents with file_offset >= this threshold (in filesystem blocks) are
/// leaf/free-index blocks, not data blocks containing directory entries.
const XFS_DIR2_LEAF_OFFSET_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Upper bound on directory data blocks read for one listing.  A corrupted
/// extent map must not be able to stall the service indefinitely.
const MAX_DIRECTORY_BLOCKS: u64 = 1 << 20;

/// Hash-directed lookup for a single raw XFS name. Unlike building a DirIndex,
/// this reads only the BMBT/DA path and data blocks needed for the name.
#[allow(clippy::too_many_arguments)]
pub fn lookup_directory_entry(
    inode: &Inode,
    owner: u64,
    name: &[u8],
    has_ftype: bool,
    block_size: u32,
    dir_block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    metadata_uuid: [u8; 16],
    reader: &impl VfsBlockReader,
) -> FsResult<(u64, VfsFileType)> {
    let geometry = DirGeometry::new(block_size, dir_block_size).with_total_fs_blocks(total_blocks);
    let options = DirLookupOptions::new(owner, is_v5, has_ftype, Some(metadata_uuid));
    let reader = XfsBtreeReader(reader);
    let (ino, file_type) = lookup_directory(&inode.data_fork, name, &geometry, &options, &reader)?;
    Ok((ino, dir_file_type_to_vfs(file_type)))
}

/// Parse directory entries from an XFS inode.
pub fn parse_directory_entries(
    inode: &Inode,
    current_ino: u64,
    has_ftype: bool,
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    reader: &impl VfsBlockReader,
) -> FsResult<Vec<VfsDirEntry>> {
    parse_directory_entries_internal(
        inode,
        current_ino,
        has_ftype,
        block_size,
        total_blocks,
        is_v5,
        reader,
        None,
        false,
    )
}

/// Checked VFS directory parser that also validates the metadata UUID.
#[allow(clippy::too_many_arguments)]
pub fn parse_directory_entries_checked(
    inode: &Inode,
    current_ino: u64,
    has_ftype: bool,
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    reader: &impl VfsBlockReader,
    metadata_uuid: [u8; 16],
) -> FsResult<Vec<VfsDirEntry>> {
    parse_directory_entries_internal(
        inode,
        current_ino,
        has_ftype,
        block_size,
        total_blocks,
        is_v5,
        reader,
        Some(metadata_uuid),
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_directory_entries_internal(
    inode: &Inode,
    current_ino: u64,
    has_ftype: bool,
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    reader: &impl VfsBlockReader,
    metadata_uuid: Option<[u8; 16]>,
    check_identity: bool,
) -> FsResult<Vec<VfsDirEntry>> {
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }

    match &inode.data_fork {
        DataFork::Local(data) => parse_shortform_directory_entries(data, has_ftype),
        DataFork::Extents(extents) => parse_extent_directory_entries(
            extents,
            current_ino,
            has_ftype,
            block_size,
            total_blocks,
            reader,
            metadata_uuid,
            check_identity,
        ),
        DataFork::Btree {
            level,
            num_recs,
            data,
        } => parse_btree_directory_entries(
            *level,
            *num_recs,
            data,
            current_ino,
            has_ftype,
            block_size,
            total_blocks,
            is_v5,
            reader,
            metadata_uuid,
            check_identity,
        ),
        _ => Err(FsError::NotSupported),
    }
}

/// Parse shortform directory entries.
fn parse_shortform_directory_entries(data: &[u8], has_ftype: bool) -> FsResult<Vec<VfsDirEntry>> {
    if data.len() < 6 {
        return Err(FsError::Corrupted);
    }

    let (header, iter) =
        parse_shortform_directory(data, has_ftype).map_err(|_| FsError::Corrupted)?;
    let mut entries = Vec::with_capacity(usize::from(header.count));
    let mut offset = 0u64;

    for result in iter {
        let entry = result.map_err(|_| FsError::Corrupted)?;

        let raw_name = entry.name_bytes();
        if raw_name == b"." || raw_name == b".." {
            continue;
        }
        // Preserve arbitrary XFS bytes using a reversible Windows-safe name.
        let name = mangle_bytes(raw_name).map_err(|_| FsError::Corrupted)?;

        entries.push(VfsDirEntry {
            name,
            ino: entry.inode,
            file_type: dir_file_type_to_vfs(entry.file_type),
            offset,
        });
        offset = offset.checked_add(1).ok_or(FsError::ArithmeticOverflow)?;
    }

    Ok(entries)
}

/// Parse extent-based directory entries.
#[allow(clippy::too_many_arguments)]
fn parse_extent_directory_entries(
    extents: &[Extent],
    current_ino: u64,
    has_ftype: bool,
    block_size: u32,
    total_blocks: u64,
    reader: &impl VfsBlockReader,
    metadata_uuid: Option<[u8; 16]>,
    check_identity: bool,
) -> FsResult<Vec<VfsDirEntry>> {
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }
    validate_extents(extents, u64::from(block_size), total_blocks)?;

    let mut entries = Vec::new();
    let mut offset = 0u64;
    let leaf_offset_blocks = XFS_DIR2_LEAF_OFFSET_BYTES / u64::from(block_size);
    let mut blocks_read: u64 = 0;

    for extent in extents {
        // Never scan leaf/free-index address space, even if a malformed extent
        // starts in the data range and straddles the boundary.
        if extent.file_offset >= leaf_offset_blocks {
            continue;
        }
        let data_blocks = std::cmp::min(
            u64::from(extent.block_count),
            leaf_offset_blocks - extent.file_offset,
        );

        for block_idx in 0..data_blocks {
            blocks_read = blocks_read
                .checked_add(1)
                .ok_or(FsError::ArithmeticOverflow)?;
            if blocks_read > MAX_DIRECTORY_BLOCKS {
                return Err(FsError::Corrupted);
            }
            let block_num = extent
                .start_block
                .checked_add(block_idx)
                .ok_or(FsError::ArithmeticOverflow)?;
            let block_data = reader.read_block(block_num)?;
            let block_entries = parse_directory_block_checked(
                &block_data,
                has_ftype,
                block_size,
                check_identity.then_some(block_num),
                check_identity.then_some(current_ino),
                metadata_uuid,
            )?;
            for mut entry in block_entries {
                entry.offset = offset;
                offset = offset.checked_add(1).ok_or(FsError::ArithmeticOverflow)?;
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
#[allow(clippy::too_many_arguments)]
fn parse_btree_directory_entries(
    level: u16,
    num_recs: u16,
    data: &[u8],
    current_ino: u64,
    has_ftype: bool,
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    reader: &impl VfsBlockReader,
    metadata_uuid: Option<[u8; 16]>,
    check_identity: bool,
) -> FsResult<Vec<VfsDirEntry>> {
    // 1. Parse the B+tree root from the inode data fork.  A btree-format fork
    // always points at child nodes; level 0 belongs to the extents format.
    let root = BmbtRoot::parse(data, level, num_recs)?;
    if root.level == 0 || root.num_recs == 0 {
        return Err(FsError::Corrupted);
    }

    // 2. Collect all extent mappings by traversing the B+tree
    let btree_reader = XfsBtreeReader(reader);
    let extents = if check_identity {
        btree::btree_collect_extents_checked(
            &root,
            &btree_reader,
            is_v5,
            current_ino,
            metadata_uuid,
            block_size as usize,
        )?
    } else {
        btree::btree_collect_extents(&root, &btree_reader, is_v5)?
    };

    // The xfs-rs walker is cycle-checked and block-budgeted. Apply the same
    // extent and DATA-space validation used for inline extent lists.
    let entries = parse_extent_directory_entries(
        &extents,
        current_ino,
        has_ftype,
        block_size,
        total_blocks,
        reader,
        metadata_uuid,
        check_identity,
    )?;

    tracing::debug!(
        "Btree directory: collected {} extents, {} data entries",
        extents.len(),
        entries.len()
    );

    Ok(entries)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryBlockKind {
    Data,
    Block,
    Leaf,
    Node,
    FreeIndex,
}

fn directory_block_kind(block_data: &[u8]) -> FsResult<DirectoryBlockKind> {
    let magic = block_data.get(..4).ok_or(FsError::Corrupted)?;
    match magic {
        b"XD2D" | b"XDD3" => Ok(DirectoryBlockKind::Data),
        b"XD2B" | b"XDB3" => Ok(DirectoryBlockKind::Block),
        b"XD2F" | b"XDF3" => Ok(DirectoryBlockKind::FreeIndex),
        _ => {
            // DA leaf/node blocks start with forward/back pointers; their
            // 16-bit magic is at offset 8, not at the start of the block.
            let raw = block_data.get(8..10).ok_or(FsError::Corrupted)?;
            match u16::from_be_bytes([raw[0], raw[1]]) {
                xfs_rs::XFS_DIR2_LEAF_MAGIC
                | xfs_rs::XFS_DIR3_LEAF_MAGIC
                | xfs_rs::XFS_DIR3_LEAFN_MAGIC => Ok(DirectoryBlockKind::Leaf),
                xfs_rs::XFS_DIR2_NODE_MAGIC | xfs_rs::XFS_DIR3_NODE_MAGIC => {
                    Ok(DirectoryBlockKind::Node)
                }
                _ => Err(FsError::Corrupted),
            }
        }
    }
}

fn is_v3_directory_block(block_data: &[u8]) -> FsResult<bool> {
    let magic = block_data.get(..4).ok_or(FsError::Corrupted)?;
    if matches!(magic, b"XDD3" | b"XDB3" | b"XDF3") {
        return Ok(true);
    }
    if matches!(magic, b"XD2D" | b"XD2B" | b"XD2F") {
        return Ok(false);
    }
    let raw = block_data.get(8..10).ok_or(FsError::Corrupted)?;
    Ok(matches!(
        u16::from_be_bytes([raw[0], raw[1]]),
        xfs_rs::XFS_DIR3_LEAF_MAGIC | xfs_rs::XFS_DIR3_LEAFN_MAGIC | xfs_rs::XFS_DIR3_NODE_MAGIC
    ))
}

/// Parse a single directory block.
#[cfg(test)]
fn parse_directory_block(
    block_data: &[u8],
    has_ftype: bool,
    block_size: u32,
) -> FsResult<Vec<VfsDirEntry>> {
    parse_directory_block_checked(block_data, has_ftype, block_size, None, None, None)
}

fn parse_directory_block_checked(
    block_data: &[u8],
    has_ftype: bool,
    block_size: u32,
    expected_fs_block: Option<u64>,
    expected_owner: Option<u64>,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<Vec<VfsDirEntry>> {
    let block_size = usize::try_from(block_size).map_err(|_| FsError::ArithmeticOverflow)?;
    if block_size < 16 || block_data.len() < block_size {
        return Err(FsError::Corrupted);
    }
    // Never inspect bytes appended after the advertised filesystem block.
    let block_data = &block_data[..block_size];
    let kind = directory_block_kind(block_data)?;
    let is_v3 = is_v3_directory_block(block_data)?;

    // All v3 directory block formats carry their CRC at offset 4, calculated
    // over the complete block with that field zeroed. Checked VFS reads also
    // validate blkno, owner and UUID for data, block, leaf, node and free
    // headers through the shared xfs-rs verifier.
    if is_v3 {
        if let (Some(expected_fs_block), Some(expected_owner)) = (expected_fs_block, expected_owner)
        {
            xfs_rs::directory::verify_v5_directory_block(
                block_data,
                expected_fs_block,
                expected_owner,
                expected_uuid,
            )?;
        } else {
            xfs_rs::directory::verify_v5_directory_block_crc(block_data)?;
        }
    }

    // Leaf and free-index blocks are metadata, not directory entry storage.
    if matches!(
        kind,
        DirectoryBlockKind::Leaf | DirectoryBlockKind::Node | DirectoryBlockKind::FreeIndex
    ) {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let header_size = if is_v3 { 64 } else { 16 };
    if block_size < header_size {
        return Err(FsError::Corrupted);
    }

    let end = if kind == DirectoryBlockKind::Block {
        // The last 8 bytes are xfs_dir2_block_tail { count, stale }.  Leaf
        // entries sit immediately before it and must not be scanned as data.
        let tail_offset = block_size.checked_sub(8).ok_or(FsError::Corrupted)?;
        if tail_offset < header_size {
            return Err(FsError::Corrupted);
        }
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
        block_size
    };

    let mut offset = header_size;

    // Parse the sequence of entries and free-space records.
    while offset < end {
        let remaining = end.checked_sub(offset).ok_or(FsError::ArithmeticOverflow)?;
        if remaining < 4 {
            if block_data[offset..end].iter().any(|&byte| byte != 0) {
                return Err(FsError::Corrupted);
            }
            break;
        }
        let free_tag = u16::from_be_bytes([block_data[offset], block_data[offset + 1]]);

        if free_tag == 0xFFFF {
            // XFS free space record: freetag (2) + length (2), where `length`
            // is the total size of the free region (including its trailing
            // tag bytes).  Jump by that length; never scan the free payload.
            let free_len =
                u16::from_be_bytes([block_data[offset + 2], block_data[offset + 3]]) as usize;
            let next = offset
                .checked_add(free_len)
                .ok_or(FsError::ArithmeticOverflow)?;
            if free_len < 8 || free_len % 8 != 0 || next > end {
                return Err(FsError::Corrupted);
            }
            let end_tag_offset = next.checked_sub(2).ok_or(FsError::Corrupted)?;
            let expected_tag = u16::try_from(offset).map_err(|_| FsError::Corrupted)?;
            let end_tag =
                u16::from_be_bytes([block_data[end_tag_offset], block_data[end_tag_offset + 1]]);
            if end_tag != expected_tag {
                return Err(FsError::Corrupted);
            }
            offset = next;
            continue;
        }

        // Allocated entry: inode(8) + namelen(1) + name + [ftype(1)] + tag(2),
        // padded to an 8-byte boundary.
        if remaining < 9 {
            return Err(FsError::Corrupted);
        }
        let entry_ino = u64::from_be_bytes(
            block_data[offset..offset + 8]
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        );
        if entry_ino == 0 {
            return Err(FsError::Corrupted);
        }

        let name_len = block_data[offset + 8] as usize;
        if name_len == 0 || name_len > 255 {
            return Err(FsError::Corrupted);
        }

        let name_start = offset.checked_add(9).ok_or(FsError::ArithmeticOverflow)?;
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

        let raw_name = &block_data[name_start..name_end];
        let name = mangle_bytes(raw_name).map_err(|_| FsError::Corrupted)?;

        // The entry includes a 2-byte tag after name/ftype, then is rounded up
        // to 8 bytes (xfs_dir2_data_entsize).
        let payload_end = name_end
            .checked_add(usize::from(has_ftype))
            .ok_or(FsError::ArithmeticOverflow)?;
        let next = payload_end
            .checked_add(2)
            .and_then(|value| value.checked_add(7))
            .ok_or(FsError::ArithmeticOverflow)?
            & !7;
        if next > end {
            return Err(FsError::Corrupted);
        }
        let tag_offset = next.checked_sub(2).ok_or(FsError::Corrupted)?;
        let expected_tag = u16::try_from(offset).map_err(|_| FsError::Corrupted)?;
        let stored_tag = u16::from_be_bytes([block_data[tag_offset], block_data[tag_offset + 1]]);
        if stored_tag != expected_tag {
            return Err(FsError::Corrupted);
        }
        offset = next;

        // The VFS readdir contract excludes "." and ".." in every format,
        // including block directories where XFS stores them physically.
        if raw_name == b"." || raw_name == b".." {
            continue;
        }

        entries.push(VfsDirEntry {
            name,
            ino: entry_ino,
            file_type,
            offset: 0, // Assigned by the caller.
        });
    }

    // Only zero padding may remain after the last entry/free record.
    if offset < end && block_data[offset..end].iter().any(|&byte| byte != 0) {
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
        let aligned_size = (end - offset + 2 + 7) & !7;
        let next = offset + aligned_size;
        block[next - 2..next].copy_from_slice(&(offset as u16).to_be_bytes());
        next
    }

    fn write_free(block: &mut [u8], offset: usize, length: usize) {
        block[offset..offset + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());
        block[offset + 2..offset + 4].copy_from_slice(&(length as u16).to_be_bytes());
        if length >= 2
            && offset
                .checked_add(length)
                .is_some_and(|end| end <= block.len())
        {
            let tag = offset + length - 2;
            block[tag..tag + 2].copy_from_slice(&(offset as u16).to_be_bytes());
        }
    }

    fn write_v3_crc(block: &mut [u8]) {
        write_v3_crc_at(block, 4);
    }

    fn write_v3_crc_at(block: &mut [u8], offset: usize) {
        block[offset..offset + 4].fill(0);
        let crc = xfs_rs::crc::xfs_crc32c(block);
        block[offset..offset + 4].copy_from_slice(&crc.to_be_bytes());
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
    fn arbitrary_name_bytes_are_mangled_without_collapsing() {
        let mut block = empty_data_block();
        let next = write_entry(&mut block, 16, 200, b"a\xFF", 1);
        let free_len = block.len() - next;
        write_free(&mut block, next, free_len);
        let entries = parse_directory_block(&block, true, 512).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].name.contains('\u{F001}'));
        assert!(!entries[0].name.contains('\u{FFFD}'));
    }

    #[test]
    fn free_record_length_is_honoured() {
        let mut block = empty_data_block();
        let first_end = write_entry(&mut block, 16, 200, b"a", 1);
        write_free(&mut block, first_end, 16);
        let second = first_end + 16;
        // Free-space payload is opaque; bytes that resemble an entry must be
        // skipped according to the recorded length.
        block[first_end + 4..second - 2].fill(0xAA);
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
        for magic in [
            xfs_rs::XFS_DIR2_LEAF_MAGIC,
            xfs_rs::XFS_DIR3_LEAF_MAGIC,
            xfs_rs::XFS_DIR2_NODE_MAGIC,
            xfs_rs::XFS_DIR3_NODE_MAGIC,
        ] {
            let mut block = vec![0u8; 512];
            block[8..10].copy_from_slice(&magic.to_be_bytes());
            if matches!(
                magic,
                xfs_rs::XFS_DIR3_LEAF_MAGIC
                    | xfs_rs::XFS_DIR3_LEAFN_MAGIC
                    | xfs_rs::XFS_DIR3_NODE_MAGIC
            ) {
                write_v3_crc_at(&mut block, 12);
            }
            assert!(parse_directory_block(&block, true, 512).unwrap().is_empty());
        }
        for magic in [xfs_rs::XFS_DIR2_FREE_MAGIC, xfs_rs::XFS_DIR3_FREE_MAGIC] {
            let mut block = vec![0u8; 512];
            block[0..4].copy_from_slice(&magic.to_be_bytes());
            if magic == xfs_rs::XFS_DIR3_FREE_MAGIC {
                write_v3_crc(&mut block);
            }
            assert!(parse_directory_block(&block, true, 512).unwrap().is_empty());
        }
    }

    #[test]
    fn parser_does_not_scan_bytes_after_the_advertised_block() {
        let mut block = empty_data_block();
        let free_len = block.len() - 16;
        write_free(&mut block, 16, free_len);
        let appended = block.len();
        block.resize(appended + 32, 0);
        write_entry(&mut block, appended, 200, b"tail", 1);

        assert!(parse_directory_block(&block, true, 512).unwrap().is_empty());
    }

    #[test]
    fn invalid_free_record_lengths_are_corruption() {
        for length in [0u16, 6, 9, 600] {
            let mut block = empty_data_block();
            write_free(&mut block, 16, length as usize);
            assert!(matches!(
                parse_directory_block(&block, true, 512),
                Err(FsError::Corrupted)
            ));
        }
    }

    #[test]
    fn invalid_free_record_end_tag_is_corruption() {
        let mut block = empty_data_block();
        write_free(&mut block, 16, 16);
        block[30..32].copy_from_slice(&18u16.to_be_bytes()); // must equal 16
        assert!(matches!(
            parse_directory_block(&block, true, 512),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn invalid_allocated_entry_tag_is_corruption() {
        let mut block = empty_data_block();
        let next = write_entry(&mut block, 16, 200, b"abc", 1);
        block[next - 2..next].copy_from_slice(&99u16.to_be_bytes());
        assert!(matches!(
            parse_directory_block(&block, true, 512),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn v3_single_block_stops_before_its_leaf_and_tail() {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"XDB3");
        let next = write_entry(&mut block, 64, 200, b"v3", 2);
        let tail = block.len() - 8;
        let leaf_start = tail - 8;
        write_free(&mut block, next, leaf_start - next);
        block[tail..tail + 4].copy_from_slice(&1u32.to_be_bytes());
        write_v3_crc(&mut block);

        let entries = parse_directory_block(&block, true, 512).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "v3");
    }

    #[test]
    fn block_directory_dot_entries_are_not_exposed() {
        let mut block = empty_data_block();
        let mut offset = write_entry(&mut block, 16, 128, b".", 2);
        offset = write_entry(&mut block, offset, 128, b"..", 2);
        let end = write_entry(&mut block, offset, 200, b"file", 1);
        let free_len = block.len() - end;
        write_free(&mut block, end, free_len);

        let entries = parse_directory_block(&block, true, 512).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "file");
        assert_eq!(entries[0].offset, 0);
    }

    #[test]
    fn shortform_directory_does_not_synthesize_dot_entries() {
        let mut data = vec![0u8; 6];
        data[0] = 1; // one real entry
        data[1] = 0; // 32-bit inode numbers
        data[2..6].copy_from_slice(&128u32.to_be_bytes()); // parent

        let name = b"file";
        data.push(name.len() as u8);
        data.extend_from_slice(&[0, 0]); // unused name offset
        data.extend_from_slice(name);
        data.extend_from_slice(&200u32.to_be_bytes());

        let entries = parse_shortform_directory_entries(&data, false).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "file");
        assert_eq!(entries[0].ino, 200);
        assert_eq!(entries[0].offset, 0);
    }

    #[test]
    fn v3_directory_block_crc_is_verified() {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"XDD3");
        let free_len = block.len() - 64;
        write_free(&mut block, 64, free_len);
        write_v3_crc(&mut block);
        assert!(parse_directory_block(&block, true, 512).unwrap().is_empty());

        block[100] ^= 1;
        assert!(matches!(
            parse_directory_block(&block, true, 512),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn v3_directory_block_accepts_xfsprogs_little_endian_crc() {
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"XDD3");
        let free_len = block.len() - 64;
        write_free(&mut block, 64, free_len);
        block[4..8].fill(0);
        let crc = xfs_rs::crc::xfs_crc32c(&block);
        block[4..8].copy_from_slice(&crc.to_le_bytes());

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
