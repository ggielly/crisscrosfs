//! Read operations for XFS VFS.

use fs_abstraction::{FsError, FsResult};
use xfs_rs::{BmbtRoot, DataFork, Inode};

/// Read file data from an XFS inode.
pub fn read_file_data(
    inode: &Inode,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
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
        DataFork::Local(data) => read_local_data(data, offset, &mut buf[..to_read]),
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
            read_btree_data(&root, offset, &mut buf[..to_read], block_size, read_block)
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
fn read_extent_data(
    extents: &[xfs_rs::Extent],
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    let block_size = block_size as u64;
    let mut bytes_read = 0;
    let mut current_offset = offset;

    for extent in extents {
        // Calculate extent's file offset range
        let extent_file_start = extent.file_offset * block_size;
        let extent_file_end = extent_file_start + (extent.block_count as u64 * block_size);

        // Skip extents before our read position
        if extent_file_end <= current_offset {
            continue;
        }

        // Check if we've read enough
        if bytes_read >= buf.len() {
            break;
        }

        // Calculate read position within this extent
        let extent_read_start = if current_offset > extent_file_start {
            current_offset - extent_file_start
        } else {
            0
        };

        // Calculate which block within the extent
        let block_in_extent = (extent_read_start / block_size) as u32;
        let offset_in_block = (extent_read_start % block_size) as usize;

        // Read blocks from this extent
        for block_idx in block_in_extent..extent.block_count {
            if bytes_read >= buf.len() {
                break;
            }

            let physical_block = extent.start_block + block_idx as u64;
            let block_data = read_block(physical_block)?;

            // Calculate how much to copy from this block
            let start_in_block = if block_idx == block_in_extent {
                offset_in_block
            } else {
                0
            };
            let available_in_block = block_data.len() - start_in_block;
            let remaining = buf.len() - bytes_read;
            let to_copy = std::cmp::min(available_in_block, remaining);

            buf[bytes_read..bytes_read + to_copy]
                .copy_from_slice(&block_data[start_in_block..start_in_block + to_copy]);

            bytes_read += to_copy;
            current_offset += to_copy as u64;
        }
    }

    Ok(bytes_read)
}

/// Read data from btree-based storage.
fn read_btree_data(
    root: &BmbtRoot,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<usize> {
    // For btree format, we need to traverse the btree to find extents
    // The root contains pointers to the btree structure

    // First, read the extents from the btree leaf blocks
    let extents = collect_extents_from_btree(root, block_size, &read_block)?;

    // Then read data using those extents
    read_extent_data(&extents, offset, buf, block_size, read_block)
}

/// Collect all extents from a btree structure.
fn collect_extents_from_btree(
    root: &BmbtRoot,
    block_size: u32,
    read_block: &impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<xfs_rs::Extent>> {
    let mut extents = Vec::new();

    // For now, try to read any immediate extents from the root
    // A full implementation would traverse the btree nodes

    if root.level == 0 {
        // Root is a leaf - extents are stored directly
        // This is actually handled by DataFork::Extents case
        tracing::debug!("Btree with level 0 - treating as leaf");
    } else {
        // Need to traverse the tree
        // Read each pointer and follow to leaf blocks
        for ptr in &root.ptrs {
            let ptr_block = ptr.block;
            if ptr_block == 0 {
                continue;
            }

            // Read the block at this pointer
            let block_data = read_block(ptr_block)?;

            // Parse as btree node or leaf
            let leaf_extents =
                parse_btree_block(&block_data, root.level - 1, block_size, read_block)?;
            extents.extend(leaf_extents);
        }
    }

    Ok(extents)
}

/// Parse a btree block and extract extents.
fn parse_btree_block(
    block_data: &[u8],
    level: u16,
    block_size: u32,
    read_block: &impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<Vec<xfs_rs::Extent>> {
    let mut extents = Vec::new();

    if block_data.len() < 16 {
        return Ok(extents);
    }

    // Check magic
    let magic = &block_data[0..4];
    let is_bmbt = magic == b"BMA3" || magic == b"BMAP"; // v3/v2 bmap btree

    if !is_bmbt {
        tracing::warn!("Unknown btree block magic: {:?}", magic);
        return Ok(extents);
    }

    // Header size varies by version
    let header_size = if magic == b"BMA3" { 72 } else { 24 };

    if level == 0 {
        // Leaf block - contains extent records
        // Each extent record is 16 bytes
        let mut offset = header_size;
        while offset + 16 <= block_data.len() {
            if let Some(extent) = parse_extent_record(&block_data[offset..offset + 16]) {
                if extent.block_count > 0 {
                    extents.push(extent);
                }
            }
            offset += 16;
        }
    } else {
        // Node block - contains pointers to next level
        // Each pointer is 8 bytes (key) + 8 bytes (ptr) = 16 bytes
        let mut offset = header_size;
        while offset + 16 <= block_data.len() {
            let ptr = u64::from_be_bytes(
                block_data[offset + 8..offset + 16]
                    .try_into()
                    .map_err(|_| FsError::Corrupted)?,
            );

            if ptr != 0 {
                let child_data = read_block(ptr)?;
                let child_extents =
                    parse_btree_block(&child_data, level - 1, block_size, read_block)?;
                extents.extend(child_extents);
            }

            offset += 16;
        }
    }

    Ok(extents)
}

/// Parse a 16-byte extent record.
fn parse_extent_record(data: &[u8]) -> Option<xfs_rs::Extent> {
    if data.len() < 16 {
        return None;
    }

    // XFS extent record format (16 bytes):
    // Bit 127: Unwritten flag
    // Bits 126-73: File offset (54 bits)
    // Bits 72-21: Start block (52 bits)
    // Bits 20-0: Block count (21 bits)

    // Read as two 64-bit values
    let hi = u64::from_be_bytes(data[0..8].try_into().ok()?);
    let lo = u64::from_be_bytes(data[8..16].try_into().ok()?);

    // Extract fields
    let is_unwritten = (hi >> 63) != 0;
    let file_offset = ((hi & 0x7FFF_FFFF_FFFF_FFFF) >> 9) & 0x003F_FFFF_FFFF_FFFF;
    let start_block = ((hi & 0x1FF) << 43) | ((lo >> 21) & 0x7FF_FFFF_FFFF);
    let block_count = (lo & 0x1F_FFFF) as u32;

    Some(xfs_rs::Extent {
        file_offset,
        start_block,
        block_count,
        is_unwritten,
    })
}

/// Read symlink target from an XFS inode.
pub fn read_symlink_target(
    inode: &Inode,
    block_size: u32,
    read_block: impl Fn(u64) -> FsResult<Vec<u8>>,
) -> FsResult<String> {
    let mut buf = vec![0u8; inode.core.size as usize];
    let bytes_read = read_file_data(inode, 0, &mut buf, block_size, read_block)?;
    buf.truncate(bytes_read);

    // Remove null terminator if present
    if buf.last() == Some(&0) {
        buf.pop();
    }

    String::from_utf8(buf).map_err(|_| FsError::Corrupted)
}
