//! Read operations for XFS VFS.

use fs_abstraction::{FsError, FsResult};
use xfs_rs::{
    btree::{self, BmbtRoot},
    DataFork,
    Extent,
    Inode,
};

use crate::io::ClosureBlockReader;

/// Read file data from an XFS inode.
pub fn read_file_data(
    inode: &Inode,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    let file_size = inode.core.size;

    // Check for read past EOF
    if offset >= file_size {
        return Ok(0);
    }

    // Calculate how much we can actually read without narrowing conversions.
    let available = file_size - offset;
    let buffer_len = u64::try_from(buf.len()).map_err(|_| FsError::ArithmeticOverflow)?;
    let to_read = usize::try_from(std::cmp::min(buffer_len, available))
        .map_err(|_| FsError::ArithmeticOverflow)?;

    if to_read == 0 {
        return Ok(0);
    }

    match &inode.data_fork {
        DataFork::Local(data) => {
            // Inline data must actually contain the advertised file size.
            if file_size > u64::try_from(data.len()).map_err(|_| FsError::ArithmeticOverflow)? {
                return Err(FsError::Corrupted);
            }
            read_local_data(data, offset, &mut buf[..to_read])
        }
        DataFork::Extents(extents) => read_extent_data(
            extents,
            offset,
            &mut buf[..to_read],
            block_size,
            total_blocks,
            read_block,
        ),
        DataFork::Btree {
            level,
            num_recs,
            data,
        } => {
            // Parse the btree root from the data fork
            let root = BmbtRoot::parse(data, *level, *num_recs)?;
            read_btree_data(
                &root,
                offset,
                &mut buf[..to_read],
                block_size,
                total_blocks,
                is_v5,
                read_block,
            )
        }
        _ => Err(FsError::NotSupported),
    }
}

/// Read data stored inline in the inode (local format).
fn read_local_data(data: &[u8], offset: u64, buf: &mut [u8]) -> FsResult<usize> {
    let offset = usize::try_from(offset).map_err(|_| FsError::ArithmeticOverflow)?;

    if offset >= data.len() {
        return Ok(0);
    }

    let available = data.len() - offset;
    let to_copy = std::cmp::min(buf.len(), available);

    buf[..to_copy].copy_from_slice(&data[offset..offset + to_copy]);

    Ok(to_copy)
}

/// Read data from extent-based storage.
///
/// Reads are done one logical filesystem block at a time.  Any logical block
/// not covered by a written extent (a hole or an unwritten/preallocated
/// extent) is filled with zeroes instead of copying bytes from an unrelated
/// extent.  Extents are validated for ordering/overlap and all arithmetic is
/// checked.
fn read_extent_data(
    extents: &[Extent],
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    total_blocks: u64,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    let block_size = u64::from(block_size);
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }
    if buf.is_empty() {
        return Ok(0);
    }

    validate_extents(extents, block_size, total_blocks)?;

    let buffer_len = u64::try_from(buf.len()).map_err(|_| FsError::ArithmeticOverflow)?;
    let end = offset
        .checked_add(buffer_len)
        .ok_or(FsError::ArithmeticOverflow)?;

    let mut written = 0usize;
    let mut current_offset = offset;
    let mut extent_index = 0usize;

    while current_offset < end {
        let logical_block = current_offset / block_size;
        let block_start = logical_block
            .checked_mul(block_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        let chunk_end = std::cmp::min(
            block_start
                .checked_add(block_size)
                .ok_or(FsError::ArithmeticOverflow)?,
            end,
        );
        let chunk_len =
            usize::try_from(chunk_end - current_offset).map_err(|_| FsError::ArithmeticOverflow)?;

        // Advance past extents that end at or before this logical block.
        while extent_index < extents.len() && extents[extent_index].file_end()? <= logical_block {
            extent_index += 1;
        }

        let covering = extents.get(extent_index);
        let use_extent = match covering {
            Some(extent) => extent.contains_file_block(logical_block) && !extent.is_unwritten,
            None => false,
        };

        if use_extent {
            let extent = covering.expect("checked above");
            let physical_block = extent.translate(logical_block)?;
            let block_data = read_block(physical_block)?;

            // The block device must return a complete block.  Zero-filling a
            // short read would silently fabricate file contents.
            if block_data.len() < block_size as usize {
                return Err(FsError::Corrupted);
            }

            let start_in_block = usize::try_from(current_offset - block_start)
                .map_err(|_| FsError::ArithmeticOverflow)?;
            let copy_end = start_in_block
                .checked_add(chunk_len)
                .ok_or(FsError::ArithmeticOverflow)?;
            if copy_end > block_data.len() {
                return Err(FsError::Corrupted);
            }
            let output_end = written
                .checked_add(chunk_len)
                .ok_or(FsError::ArithmeticOverflow)?;
            buf[written..output_end].copy_from_slice(&block_data[start_in_block..copy_end]);
        } else {
            // Hole or unwritten (preallocated) extent: logical zeroes.
            let output_end = written
                .checked_add(chunk_len)
                .ok_or(FsError::ArithmeticOverflow)?;
            buf[written..output_end].fill(0);
        }

        written += chunk_len;
        current_offset = chunk_end;
    }

    Ok(written)
}

/// Validate extent ordering and both logical and physical bounds.
///
/// Unwritten extents still reserve physical blocks, so they are subject to the
/// same filesystem bounds as written extents.  Zero-length records are not
/// valid members of an XFS extent list; an empty fork is represented by an
/// empty list.
pub(crate) fn validate_extents(
    extents: &[Extent],
    block_size: u64,
    total_blocks: u64,
) -> FsResult<()> {
    if block_size == 0 || total_blocks == 0 {
        return Err(FsError::Corrupted);
    }

    let mut previous_end = 0u64;
    for extent in extents {
        if extent.block_count == 0 {
            return Err(FsError::Corrupted);
        }
        if extent.file_offset < previous_end {
            return Err(FsError::Corrupted);
        }

        let file_end = extent.file_end()?;
        file_end
            .checked_mul(block_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        let disk_end = extent.disk_end()?;
        if disk_end > total_blocks {
            return Err(FsError::Corrupted);
        }
        previous_end = file_end;
    }
    Ok(())
}

/// Read data from btree-based storage.
fn read_btree_data(
    root: &BmbtRoot,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    // Collect extents with the shared, bounded and cycle-checking xfs-rs
    // walker, then validate physical bounds before reading the requested range.
    let extents = collect_extents_from_btree(root, is_v5, &read_block)?;
    read_extent_data(&extents, offset, buf, block_size, total_blocks, read_block)
}

/// Collect all extents from a btree structure.
fn collect_extents_from_btree(
    root: &BmbtRoot,
    is_v5: bool,
    read_block: &impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<xfs_rs::Extent>> {
    if root.level == 0 || root.num_recs == 0 {
        // A btree-format fork always has a root level >= 1 and at least one
        // child pointer; an empty fork uses the extents/empty format instead.
        return Err(FsError::Corrupted);
    }

    let reader = ClosureBlockReader::new(read_block);
    btree::btree_collect_extents(root, &reader, is_v5)
}

/// Read symlink target from an XFS inode.
pub fn read_symlink_target(
    inode: &Inode,
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<String> {
    // XFS symlink targets are bounded by MAXPATHLEN (1024 bytes); never trust
    // the on-disk size for an allocation.
    const MAX_SYMLINK_LEN: u64 = 1024;
    const DSYMLINK_HDR_SIZE: usize = 56;
    const DSYMLINK_MAGIC: &[u8; 4] = b"XSLM";

    if inode.core.size > MAX_SYMLINK_LEN {
        return Err(FsError::Corrupted);
    }
    let target_len = usize::try_from(inode.core.size).map_err(|_| FsError::ArithmeticOverflow)?;
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }

    let mut buf = Vec::with_capacity(target_len);

    match &inode.data_fork {
        DataFork::Local(data) => {
            if target_len > data.len() {
                return Err(FsError::Corrupted);
            }
            buf.extend_from_slice(&data[..target_len]);
        }
        _ if !is_v5 => {
            // v4 remote symlink: the target is stored contiguously.
            buf.resize(target_len, 0);
            let read = read_file_data(
                inode,
                0,
                &mut buf,
                block_size,
                total_blocks,
                is_v5,
                read_block,
            )?;
            buf.truncate(read);
        }
        DataFork::Extents(extents) => {
            read_remote_symlink_v5(
                extents,
                target_len,
                block_size,
                total_blocks,
                DSYMLINK_HDR_SIZE,
                DSYMLINK_MAGIC,
                &read_block,
                &mut buf,
            )?;
        }
        DataFork::Btree {
            level,
            num_recs,
            data,
        } => {
            let root = BmbtRoot::parse(data, *level, *num_recs)?;
            let extents = collect_extents_from_btree(&root, is_v5, &read_block)?;
            read_remote_symlink_v5(
                &extents,
                target_len,
                block_size,
                total_blocks,
                DSYMLINK_HDR_SIZE,
                DSYMLINK_MAGIC,
                &read_block,
                &mut buf,
            )?;
        }
        _ => return Err(FsError::NotSupported),
    }

    // Remove a trailing null terminator if present.
    if buf.last() == Some(&0) {
        buf.pop();
    }

    String::from_utf8(buf).map_err(|_| FsError::Corrupted)
}

/// Read a v5 remote symlink, skipping the per-block `xfs_dsymlink_hdr`.
#[allow(clippy::too_many_arguments)]
fn read_remote_symlink_v5(
    extents: &[Extent],
    target_len: usize,
    block_size: u32,
    total_blocks: u64,
    header_size: usize,
    magic: &[u8; 4],
    read_block: &impl Fn(u64) -> FsResult<Vec<u8>>,
    out: &mut Vec<u8>,
) -> FsResult<()> {
    let block_size = u64::from(block_size);
    if block_size == 0 || header_size >= block_size as usize {
        return Err(FsError::Corrupted);
    }
    validate_extents(extents, block_size, total_blocks)?;

    let mut logical_block = 0u64;
    let mut extent_index = 0usize;

    while out.len() < target_len {
        while extent_index < extents.len()
            && !extents[extent_index].contains_file_block(logical_block)
        {
            if extents[extent_index].file_end()? > logical_block {
                return Err(FsError::Corrupted);
            }
            extent_index += 1;
        }
        let extent = extents.get(extent_index).ok_or(FsError::Corrupted)?;
        if extent.is_unwritten {
            return Err(FsError::Corrupted);
        }
        let physical = extent.translate(logical_block)?;
        let block = read_block(physical)?;
        if block.len() < block_size as usize {
            return Err(FsError::Corrupted);
        }
        if &block[..4] != magic {
            return Err(FsError::Corrupted);
        }

        let take = std::cmp::min(block_size as usize - header_size, target_len - out.len());
        out.extend_from_slice(&block[header_size..header_size + take]);
        logical_block = logical_block
            .checked_add(1)
            .ok_or(FsError::ArithmeticOverflow)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use xfs_rs::Extent;

    use super::*;

    const BLOCK: u32 = 16;

    fn reader_for(block: u64) -> FsResult<Vec<u8>> {
        if block == 10 {
            Ok(vec![0xAA; BLOCK as usize])
        } else {
            Err(FsError::InvalidBlockAddress)
        }
    }

    #[test]
    fn holes_are_zero_filled() {
        // Only logical block 1 is allocated.
        let extents = vec![Extent {
            file_offset: 1,
            start_block: 10,
            block_count: 1,
            is_unwritten: false,
        }];

        let mut buf = [0x55u8; 32];
        let n = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, reader_for).unwrap();
        assert_eq!(n, 32);
        assert_eq!(&buf[..16], &[0u8; 16]);
        assert_eq!(&buf[16..], &[0xAAu8; 16]);
    }

    #[test]
    fn unwritten_extents_are_zero_filled() {
        let extents = vec![Extent {
            file_offset: 0,
            start_block: 10,
            block_count: 1,
            is_unwritten: true,
        }];

        let mut buf = [0x55u8; 16];
        let n = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, reader_for).unwrap();
        assert_eq!(n, 16);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn overlapping_extents_are_rejected() {
        let extents = vec![
            Extent {
                file_offset: 0,
                start_block: 10,
                block_count: 2,
                is_unwritten: false,
            },
            Extent {
                file_offset: 1,
                start_block: 10,
                block_count: 1,
                is_unwritten: false,
            },
        ];

        let mut buf = [0u8; 16];
        assert!(matches!(
            read_extent_data(&extents, 0, &mut buf, BLOCK, 100, reader_for),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn short_block_read_is_rejected() {
        let extents = vec![Extent {
            file_offset: 0,
            start_block: 10,
            block_count: 1,
            is_unwritten: false,
        }];

        let mut buf = [0u8; 16];
        let result = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, |_| Ok(vec![0xAA; 8]));
        assert!(matches!(result, Err(FsError::Corrupted)));
    }

    #[test]
    fn partial_read_across_hole_keeps_extent_alignment() {
        let extents = vec![Extent {
            file_offset: 1,
            start_block: 10,
            block_count: 1,
            is_unwritten: false,
        }];

        let mut buf = [0x55u8; 20];
        let read = read_extent_data(&extents, 12, &mut buf, BLOCK, 100, reader_for).unwrap();
        assert_eq!(read, buf.len());
        assert_eq!(&buf[..4], &[0u8; 4]);
        assert_eq!(&buf[4..], &[0xAAu8; 16]);
    }

    #[test]
    fn trailing_hole_is_zero_filled() {
        let extents = vec![Extent {
            file_offset: 0,
            start_block: 10,
            block_count: 1,
            is_unwritten: false,
        }];

        let mut buf = [0x55u8; 32];
        assert_eq!(
            read_extent_data(&extents, 0, &mut buf, BLOCK, 100, reader_for).unwrap(),
            32
        );
        assert_eq!(&buf[..16], &[0xAAu8; 16]);
        assert_eq!(&buf[16..], &[0u8; 16]);
    }

    #[test]
    fn unwritten_extent_does_not_read_physical_data() {
        let extents = vec![Extent {
            file_offset: 0,
            start_block: 10,
            block_count: 1,
            is_unwritten: true,
        }];

        let mut buf = [0x55u8; 16];
        let read = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, |_| {
            panic!("unwritten extent must not be read")
        })
        .unwrap();
        assert_eq!(read, 16);
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn unsorted_extents_are_rejected() {
        let extents = vec![
            Extent {
                file_offset: 2,
                start_block: 10,
                block_count: 1,
                is_unwritten: false,
            },
            Extent {
                file_offset: 1,
                start_block: 11,
                block_count: 1,
                is_unwritten: false,
            },
        ];
        assert!(matches!(
            read_extent_data(&extents, 0, &mut [0u8; 16], BLOCK, 100, reader_for),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn physical_extent_bounds_are_checked() {
        let extents = vec![Extent {
            file_offset: 0,
            start_block: 100,
            block_count: 1,
            is_unwritten: false,
        }];
        assert!(matches!(
            read_extent_data(&extents, 0, &mut [0u8; 16], BLOCK, 100, reader_for),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn zero_length_and_overflowing_extents_are_rejected() {
        let zero_length = vec![Extent {
            file_offset: 0,
            start_block: 0,
            block_count: 0,
            is_unwritten: false,
        }];
        assert!(matches!(
            read_extent_data(&zero_length, 0, &mut [0u8; 16], BLOCK, 100, reader_for),
            Err(FsError::Corrupted)
        ));

        let overflowing = vec![Extent {
            file_offset: u64::MAX,
            start_block: 10,
            block_count: 1,
            is_unwritten: false,
        }];
        assert!(matches!(
            read_extent_data(&overflowing, 0, &mut [0u8; 16], BLOCK, 100, reader_for),
            Err(FsError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn btree_sibling_cycle_is_bounded_and_rejected() {
        use std::cell::Cell;

        use xfs_rs::btree::{BmbtKey, BmbtPtr, BmbtRoot};

        let root = BmbtRoot {
            level: 1,
            num_recs: 1,
            keys: vec![BmbtKey { file_offset: 0 }],
            ptrs: vec![BmbtPtr { block: 10 }],
        };
        let mut leaf = vec![0u8; 128];
        leaf[0..4].copy_from_slice(&0x424D_4150u32.to_be_bytes()); // "BMAP"
        leaf[4..6].copy_from_slice(&0u16.to_be_bytes()); // leaf level
        leaf[6..8].copy_from_slice(&0u16.to_be_bytes()); // no records
        leaf[16..24].copy_from_slice(&10u64.to_be_bytes()); // right sibling ->
                                                            // self

        let reads = Cell::new(0usize);
        let result = collect_extents_from_btree(&root, false, &|block| {
            assert_eq!(block, 10);
            reads.set(reads.get() + 1);
            Ok(leaf.clone())
        });
        assert!(matches!(result, Err(FsError::Corrupted)));
        assert_eq!(
            reads.get(),
            1,
            "the repeated block must be rejected before a second read"
        );
    }
}

#[cfg(test)]
mod symlink_tests {
    use xfs_rs::Extent;

    use super::*;

    fn symlink_inode(target_len: u64) -> Inode {
        let mut buf = vec![0u8; 256];
        buf[0..2].copy_from_slice(&0x494Eu16.to_be_bytes()); // XFS_DINODE_MAGIC
        buf[2..4].copy_from_slice(&0o120777u16.to_be_bytes()); // S_IFLNK
        buf[4] = 2; // inode version
        buf[5] = 2; // XFS_DINODE_FMT_EXTENTS
        buf[0x38..0x40].copy_from_slice(&target_len.to_be_bytes());
        buf[0x4C..0x50].copy_from_slice(&1u32.to_be_bytes()); // nextents

        let extent = Extent {
            file_offset: 0,
            start_block: 5,
            block_count: 1,
            is_unwritten: false,
        };
        buf[100..116].copy_from_slice(&extent.to_bytes());
        Inode::parse(&buf, 256).unwrap()
    }

    #[test]
    fn v5_remote_symlink_skips_block_header() {
        let inode = symlink_inode(5);
        let target = read_symlink_target(&inode, 512, 1024, true, |_| {
            let mut block = vec![0u8; 512];
            block[0..4].copy_from_slice(b"XSLM");
            block[56..61].copy_from_slice(b"hello");
            Ok(block)
        })
        .unwrap();
        assert_eq!(target, "hello");
    }

    #[test]
    fn v4_remote_symlink_is_contiguous() {
        let inode = symlink_inode(5);
        let target = read_symlink_target(&inode, 512, 1024, false, |_| {
            let mut block = vec![0u8; 512];
            block[0..5].copy_from_slice(b"world");
            Ok(block)
        })
        .unwrap();
        assert_eq!(target, "world");
    }

    #[test]
    fn oversized_symlink_is_rejected_before_allocation_or_io() {
        let inode = symlink_inode(1025);
        let result = read_symlink_target(&inode, 512, 1024, true, |_| {
            panic!("oversized symlink must not read any block")
        });
        assert!(matches!(result, Err(FsError::Corrupted)));
    }
}
