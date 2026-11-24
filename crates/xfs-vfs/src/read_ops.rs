//! Read operations for XFS VFS.

use fs_abstraction::{FsError, FsResult};
use xfs_rs::{
    btree::{self, BlockReader, BmbtRoot},
    DataFork, Inode,
};

/// Adapter to implement `BlockReader` from a closure.
struct ClosureBlockReader<'a, F: Fn(u64) -> FsResult<Vec<u8>>>(&'a F);

impl<F: Fn(u64) -> FsResult<Vec<u8>>> BlockReader for ClosureBlockReader<'_, F> {
    fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
        (self.0)(block_num)
    }
}

/// Read file data from an XFS inode.
pub fn read_file_data(
    inode: &Inode,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    let file_size = inode.core.size;

    // Check for read past EOF
    if offset >= file_size {
        return Ok(0);
    }

    // Calculate how much we can actually read
    let available = file_size - offset;
    let to_read = std::cmp::min(buf.len() as u64, available) as usize;

    if to_read == 0 {
        return Ok(0);
    }

    match &inode.data_fork {
        DataFork::Local(data) => {
            // Inline data must actually contain the advertised file size.
            if file_size > data.len() as u64 {
                return Err(FsError::Corrupted);
            }
            read_local_data(data, offset, &mut buf[..to_read])
        }
        DataFork::Extents(extents) => {
            read_extent_data(extents, offset, &mut buf[..to_read], block_size, read_block)
        }
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
                is_v5,
                read_block,
            )
        }
        _ => Err(FsError::NotSupported),
    }
}

/// Read data stored inline in the inode (local format).
fn read_local_data(data: &[u8], offset: u64, buf: &mut [u8]) -> FsResult<usize> {
    let offset = offset as usize;

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
    extents: &[xfs_rs::Extent],
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    let block_size = u64::from(block_size);
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }
    if buf.is_empty() {
        return Ok(0);
    }

    // Validate extents up front: sorted, non-overlapping, in-bounds lengths.
    let mut previous_end = 0u64;
    for (index, extent) in extents.iter().enumerate() {
        let file_end = extent.file_end()?;
        if extent.block_count == 0 {
            continue;
        }
        if index > 0 && extent.file_offset < previous_end {
            return Err(FsError::Corrupted);
        }
        if file_end < extent.file_offset {
            return Err(FsError::Corrupted);
        }
        previous_end = file_end;
    }

    let end = offset
        .checked_add(buf.len() as u64)
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
        let chunk_len = (chunk_end - current_offset) as usize;

        // Advance past extents that end at or before this logical block.
        while extent_index < extents.len() {
            let extent = &extents[extent_index];
            if extent.block_count == 0 {
                extent_index += 1;
                continue;
            }
            if extent.file_end()? <= logical_block {
                extent_index += 1;
                continue;
            }
            break;
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

            let start_in_block = (current_offset - block_start) as usize;
            let copy_end = start_in_block
                .checked_add(chunk_len)
                .ok_or(FsError::ArithmeticOverflow)?;
            if copy_end > block_data.len() {
                return Err(FsError::Corrupted);
            }
            buf[written..written + chunk_len]
                .copy_from_slice(&block_data[start_in_block..copy_end]);
        } else {
            // Hole or unwritten (preallocated) extent: logical zeroes.
            buf[written..written + chunk_len].fill(0);
        }

        written += chunk_len;
        current_offset = chunk_end;
    }

    Ok(written)
}

/// Read data from btree-based storage.
fn read_btree_data(
    root: &BmbtRoot,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    // Collect extents with the shared, validated btree walker, then read the
    // requested range (holes/unwritten extents become zeroes).
    let extents = collect_extents_from_btree(root, is_v5, &read_block)?;
    read_extent_data(&extents, offset, buf, block_size, read_block)
}

/// Collect all extents from a btree structure.
fn collect_extents_from_btree(
    root: &BmbtRoot,
    is_v5: bool,
    read_block: &impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<xfs_rs::Extent>> {
    if root.level == 0 {
        // A btree-format fork always has a root level >= 1; level 0 is
        // represented by the extents format instead.
        return Err(FsError::Corrupted);
    }

    let reader = ClosureBlockReader(read_block);
    btree::btree_collect_extents(root, &reader, is_v5)
}

/// Read symlink target from an XFS inode.
pub fn read_symlink_target(
    inode: &Inode,
    block_size: u32,
    is_v5: bool,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<String> {
    // XFS symlink targets are bounded by MAXPATHLEN (1024 bytes); never trust
    // the on-disk size for an allocation.
    const MAX_SYMLINK_LEN: u64 = 4096;
    const DSYMLINK_HDR_SIZE: usize = 56;
    const DSYMLINK_MAGIC: &[u8; 4] = b"XSLM";

    if inode.core.size > MAX_SYMLINK_LEN {
        return Err(FsError::Corrupted);
    }
    let target_len = inode.core.size as usize;
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
            let read = read_file_data(inode, 0, &mut buf, block_size, is_v5, read_block)?;
            buf.truncate(read);
        }
        DataFork::Extents(extents) => {
            read_remote_symlink_v5(
                extents,
                target_len,
                block_size,
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
    extents: &[xfs_rs::Extent],
    target_len: usize,
    block_size: u32,
    header_size: usize,
    magic: &[u8; 4],
    read_block: &impl Fn(u64) -> FsResult<Vec<u8>>,
    out: &mut Vec<u8>,
) -> FsResult<()> {
    let block_size = block_size as u64;
    if header_size >= block_size as usize {
        return Err(FsError::Corrupted);
    }

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
        logical_block += 1;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use xfs_rs::Extent;

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
        let n = read_extent_data(&extents, 0, &mut buf, BLOCK, reader_for).unwrap();
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
        let n = read_extent_data(&extents, 0, &mut buf, BLOCK, reader_for).unwrap();
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
            read_extent_data(&extents, 0, &mut buf, BLOCK, reader_for),
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
        let result = read_extent_data(&extents, 0, &mut buf, BLOCK, |_| Ok(vec![0xAA; 8]));
        assert!(matches!(result, Err(FsError::Corrupted)));
    }
}

#[cfg(test)]
mod symlink_tests {
    use super::*;
    use xfs_rs::Extent;

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
        let target = read_symlink_target(&inode, 512, true, |_| {
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
        let target = read_symlink_target(&inode, 512, false, |_| {
            let mut block = vec![0u8; 512];
            block[0..5].copy_from_slice(b"world");
            Ok(block)
        })
        .unwrap();
        assert_eq!(target, "world");
    }
}
