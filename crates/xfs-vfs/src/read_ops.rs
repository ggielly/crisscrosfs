//! Read operations for XFS VFS.

use fs_abstraction::{FsError, FsResult};
use xfs_rs::{
    btree::{self, BmbtRoot},
    DataFork,
    Extent,
    Inode,
};

use crate::io::{VfsBlockReader, XfsBtreeReader};

/// Read file data from an XFS inode.
pub fn read_file_data(
    inode: &Inode,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    reader: &impl VfsBlockReader,
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
            reader,
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
                inode.core.ino,
                offset,
                &mut buf[..to_read],
                block_size,
                total_blocks,
                is_v5,
                reader,
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
/// Each written extent segment covered by the request is read with one
/// positional I/O directly into the caller's buffer. There is no per-block
/// allocation or intermediate copy. Holes and unwritten extents are zeroed.
pub(crate) fn read_extent_data(
    extents: &[Extent],
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    total_blocks: u64,
    reader: &impl VfsBlockReader,
) -> FsResult<usize> {
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }
    if buf.is_empty() {
        return Ok(0);
    }
    validate_extents(extents, u64::from(block_size), total_blocks)?;

    read_extent_data_validated(extents, offset, buf, block_size, total_blocks, reader)
}

/// Read an extent map that was validated when it entered the in-core cache.
pub(crate) fn read_extent_data_validated(
    extents: &[Extent],
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    _total_blocks: u64,
    reader: &impl VfsBlockReader,
) -> FsResult<usize> {
    let block_size = u64::from(block_size);
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }
    if buf.is_empty() {
        return Ok(0);
    }

    let buffer_len = u64::try_from(buf.len()).map_err(|_| FsError::ArithmeticOverflow)?;
    let end = offset
        .checked_add(buffer_len)
        .ok_or(FsError::ArithmeticOverflow)?;

    let mut written = 0usize;
    let mut current = offset;
    let mut index = extents.partition_point(|extent| {
        // `validate_extents` has already checked every file_end.
        extent
            .file_offset
            .saturating_add(u64::from(extent.block_count))
            * block_size
            <= current
    });

    while current < end {
        let extent = extents.get(index);
        let extent_start = match extent {
            Some(extent) => extent
                .file_offset
                .checked_mul(block_size)
                .ok_or(FsError::ArithmeticOverflow)?,
            None => end,
        };
        let extent_end = extent
            .map(|e| {
                e.file_end()?
                    .checked_mul(block_size)
                    .ok_or(FsError::ArithmeticOverflow)
            })
            .transpose()?
            .unwrap_or(end);

        if current < extent_start {
            // Hole up to the next extent (or EOF of this request).
            let run_end = end.min(extent_start);
            let run_len =
                usize::try_from(run_end - current).map_err(|_| FsError::ArithmeticOverflow)?;
            buf[written..written + run_len].fill(0);
            written += run_len;
            current = run_end;
            continue;
        }

        let Some(extent) = extent else {
            let run_len =
                usize::try_from(end - current).map_err(|_| FsError::ArithmeticOverflow)?;
            buf[written..written + run_len].fill(0);
            written += run_len;
            current = end;
            continue;
        };

        let run_end = end.min(extent_end);
        let run_len =
            usize::try_from(run_end - current).map_err(|_| FsError::ArithmeticOverflow)?;
        if extent.is_unwritten {
            buf[written..written + run_len].fill(0);
        } else {
            let logical_block = current / block_size;
            let physical_block = extent.translate(logical_block)?;
            let offset_in_block = current % block_size;
            reader.read_at(
                physical_block,
                offset_in_block,
                &mut buf[written..written + run_len],
            )?;
        }
        written += run_len;
        current = run_end;
        if current == extent_end {
            index += 1;
        }
    }

    Ok(written)
}

/// EOF-clamped file read using an already validated/cached extent map.
pub(crate) fn read_file_data_with_extents(
    inode: &Inode,
    extents: &[Extent],
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    total_blocks: u64,
    reader: &impl VfsBlockReader,
) -> FsResult<usize> {
    if offset >= inode.core.size {
        return Ok(0);
    }
    let available = inode.core.size - offset;
    let to_read = usize::try_from(available.min(buf.len() as u64))
        .map_err(|_| FsError::ArithmeticOverflow)?;
    if to_read == 0 {
        return Ok(0);
    }
    read_extent_data_validated(
        extents,
        offset,
        &mut buf[..to_read],
        block_size,
        total_blocks,
        reader,
    )
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
#[allow(clippy::too_many_arguments)]
fn read_btree_data(
    root: &BmbtRoot,
    owner: u64,
    offset: u64,
    buf: &mut [u8],
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    reader: &impl VfsBlockReader,
) -> FsResult<usize> {
    // Collect extents with the shared, bounded and cycle-checking xfs-rs
    // walker, then validate physical bounds before reading the requested range.
    let extents =
        collect_extents_from_btree_checked(root, is_v5, owner, None, block_size as usize, reader)?;
    read_extent_data(&extents, offset, buf, block_size, total_blocks, reader)
}

/// Collect all extents from a btree structure.
#[cfg(test)]
pub(crate) fn collect_extents_from_btree(
    root: &BmbtRoot,
    is_v5: bool,
    reader: &impl VfsBlockReader,
) -> FsResult<Vec<xfs_rs::Extent>> {
    if root.level == 0 || root.num_recs == 0 {
        // A btree-format fork always has a root level >= 1 and at least one
        // child pointer; an empty fork uses the extents/empty format instead.
        return Err(FsError::Corrupted);
    }

    let reader = XfsBtreeReader(reader);
    btree::btree_collect_extents(root, &reader, is_v5)
}

/// Collect BMBT extents after checking the owning inode and metadata UUID.
pub(crate) fn collect_extents_from_btree_checked(
    root: &BmbtRoot,
    is_v5: bool,
    owner: u64,
    metadata_uuid: Option<[u8; 16]>,
    block_size: usize,
    reader: &impl VfsBlockReader,
) -> FsResult<Vec<xfs_rs::Extent>> {
    if root.level == 0 || root.num_recs == 0 {
        return Err(FsError::Corrupted);
    }
    let reader = XfsBtreeReader(reader);
    btree::btree_collect_extents_checked(root, &reader, is_v5, owner, metadata_uuid, block_size)
}

/// Read symlink target from an XFS inode.
#[allow(dead_code)] // Public compatibility wrapper; VFS uses the UUID-checked
                    // form.
pub fn read_symlink_target(
    inode: &Inode,
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    reader: &impl VfsBlockReader,
) -> FsResult<String> {
    read_symlink_target_with_uuid(inode, block_size, total_blocks, is_v5, None, reader)
}

/// Checked symlink read used by the VFS, including the v5 metadata UUID.
pub fn read_symlink_target_with_uuid(
    inode: &Inode,
    block_size: u32,
    total_blocks: u64,
    is_v5: bool,
    metadata_uuid: Option<[u8; 16]>,
    reader: &impl VfsBlockReader,
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
            let read = read_file_data(inode, 0, &mut buf, block_size, total_blocks, is_v5, reader)?;
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
                reader,
                &mut buf,
            )?;
        }
        DataFork::Btree {
            level,
            num_recs,
            data,
        } => {
            let root = BmbtRoot::parse(data, *level, *num_recs)?;
            let extents = collect_extents_from_btree_checked(
                &root,
                is_v5,
                inode.core.ino,
                metadata_uuid,
                block_size as usize,
                reader,
            )?;
            read_remote_symlink_v5(
                &extents,
                target_len,
                block_size,
                total_blocks,
                DSYMLINK_HDR_SIZE,
                DSYMLINK_MAGIC,
                reader,
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
    reader: &impl VfsBlockReader,
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
        let mut block =
            vec![0u8; usize::try_from(block_size).map_err(|_| FsError::ArithmeticOverflow)?];
        reader.read_at(physical, 0, &mut block)?;
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
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    use xfs_rs::Extent;

    use super::*;

    const BLOCK: u32 = 16;

    struct TestReader {
        data: Vec<u8>,
        expected_block: u64,
        reads: AtomicUsize,
        panic_on_read: bool,
    }

    impl TestReader {
        fn for_block(block: u64) -> Self {
            Self {
                data: vec![0xAA; BLOCK as usize],
                expected_block: block,
                reads: AtomicUsize::new(0),
                panic_on_read: false,
            }
        }
    }

    impl VfsBlockReader for TestReader {
        fn read_block(&self, block_num: u64) -> FsResult<Arc<[u8]>> {
            assert_eq!(block_num, self.expected_block);
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(Arc::from(self.data.as_slice()))
        }

        fn read_at(&self, block_num: u64, offset: u64, buf: &mut [u8]) -> FsResult<()> {
            assert!(!self.panic_on_read, "unexpected data read");
            assert_eq!(block_num, self.expected_block);
            self.reads.fetch_add(1, Ordering::SeqCst);
            let offset = usize::try_from(offset).unwrap();
            if offset + buf.len() > self.data.len() {
                return Err(FsError::Corrupted);
            }
            buf.copy_from_slice(&self.data[offset..offset + buf.len()]);
            Ok(())
        }
    }

    fn reader_for(block: u64) -> TestReader {
        TestReader::for_block(block)
    }

    #[test]
    fn contiguous_extent_is_read_with_one_positional_io() {
        let extents = vec![Extent {
            file_offset: 0,
            start_block: 10,
            block_count: 8,
            is_unwritten: false,
        }];
        let mut reader = reader_for(10);
        reader.data = (0..128u8).collect();
        let mut buf = [0u8; 128];
        assert_eq!(
            read_extent_data(&extents, 0, &mut buf, BLOCK, 100, &reader).unwrap(),
            128
        );
        assert_eq!(reader.reads.load(Ordering::SeqCst), 1);
        assert_eq!(buf, reader.data.as_slice());
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
        let n = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, &reader_for(10)).unwrap();
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
        let n = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, &reader_for(10)).unwrap();
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
            read_extent_data(&extents, 0, &mut buf, BLOCK, 100, &reader_for(10)),
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
        let mut reader = reader_for(10);
        reader.data.resize(8, 0xAA);
        let result = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, &reader);
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
        let read = read_extent_data(&extents, 12, &mut buf, BLOCK, 100, &reader_for(10)).unwrap();
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
            read_extent_data(&extents, 0, &mut buf, BLOCK, 100, &reader_for(10)).unwrap(),
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
        let mut reader = reader_for(10);
        reader.panic_on_read = true;
        let read = read_extent_data(&extents, 0, &mut buf, BLOCK, 100, &reader).unwrap();
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
            read_extent_data(&extents, 0, &mut [0u8; 16], BLOCK, 100, &reader_for(10)),
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
            read_extent_data(&extents, 0, &mut [0u8; 16], BLOCK, 100, &reader_for(10)),
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
            read_extent_data(&zero_length, 0, &mut [0u8; 16], BLOCK, 100, &reader_for(10)),
            Err(FsError::Corrupted)
        ));

        let overflowing = vec![Extent {
            file_offset: u64::MAX,
            start_block: 10,
            block_count: 1,
            is_unwritten: false,
        }];
        assert!(matches!(
            read_extent_data(&overflowing, 0, &mut [0u8; 16], BLOCK, 100, &reader_for(10)),
            Err(FsError::ArithmeticOverflow)
        ));
    }

    #[test]
    fn btree_sibling_cycle_is_bounded_and_rejected() {
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

        let reader = TestReader {
            data: leaf,
            expected_block: 10,
            reads: AtomicUsize::new(0),
            panic_on_read: false,
        };
        let result = collect_extents_from_btree(&root, false, &reader);
        assert!(matches!(result, Err(FsError::Corrupted)));
        assert_eq!(
            reader.reads.load(Ordering::SeqCst),
            1,
            "the repeated block must be rejected before a second read"
        );
    }
}

#[cfg(test)]
mod symlink_tests {
    use std::sync::Arc;

    use xfs_rs::Extent;

    use super::*;

    struct SymlinkReader(Vec<u8>);

    impl VfsBlockReader for SymlinkReader {
        fn read_block(&self, block: u64) -> FsResult<Arc<[u8]>> {
            assert_eq!(block, 5);
            Ok(Arc::from(self.0.as_slice()))
        }

        fn read_at(&self, block: u64, offset: u64, buf: &mut [u8]) -> FsResult<()> {
            assert_eq!(block, 5);
            let offset = usize::try_from(offset).map_err(|_| FsError::ArithmeticOverflow)?;
            buf.copy_from_slice(&self.0[offset..offset + buf.len()]);
            Ok(())
        }
    }

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
        let mut block = vec![0u8; 512];
        block[0..4].copy_from_slice(b"XSLM");
        block[56..61].copy_from_slice(b"hello");
        let target = read_symlink_target(&inode, 512, 1024, true, &SymlinkReader(block)).unwrap();
        assert_eq!(target, "hello");
    }

    #[test]
    fn v4_remote_symlink_is_contiguous() {
        let inode = symlink_inode(5);
        let mut block = vec![0u8; 512];
        block[0..5].copy_from_slice(b"world");
        let target = read_symlink_target(&inode, 512, 1024, false, &SymlinkReader(block)).unwrap();
        assert_eq!(target, "world");
    }

    #[test]
    fn oversized_symlink_is_rejected_before_allocation_or_io() {
        let inode = symlink_inode(1025);
        let result = read_symlink_target(&inode, 512, 1024, true, &SymlinkReader(Vec::new()));
        assert!(matches!(result, Err(FsError::Corrupted)));
    }
}
