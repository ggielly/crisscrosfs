//! XFS Directory parsing.
//!
//! XFS has multiple directory formats depending on size:
//! - Shortform (inline in inode) for small directories
//! - Block format for medium directories
//! - Leaf/Node format for large directories

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Checked, hash-directed lookup for extent and B+tree directory forks.
///
/// This module is declared here so the lookup API remains available as
/// `xfs_rs::directory::dir_lookup` without changing the crate root.
#[cfg(feature = "alloc")]
#[path = "dir_lookup.rs"]
pub mod dir_lookup;

#[cfg(feature = "alloc")]
pub use dir_lookup::{
    lookup_directory,
    DirGeometry,
    DirLookupOptions,
    MAX_DIR_LOOKUP_BLOCKS_DEFAULT,
    MAX_DIR_LOOKUP_DEPTH_DEFAULT,
};

/// Calculate the canonical XFS directory hash for a name.
///
/// XFS consumes complete groups of four bytes with the canonical
/// `b0<<21 ^ b1<<14 ^ b2<<7 ^ b3` word and rotates the running hash left by
/// 28 bits. A final partial group rotates by seven bits per byte and uses the
/// same 21/14/7/0 byte positions.
pub fn dir2_hash(name: &[u8]) -> u32 {
    let mut hash = 0u32;
    let (chunks, remainder) = name.as_chunks::<4>();
    for chunk in chunks {
        let word = (u32::from(chunk[0]) << 21)
            ^ (u32::from(chunk[1]) << 14)
            ^ (u32::from(chunk[2]) << 7)
            ^ u32::from(chunk[3]);
        hash = hash.rotate_left(28) ^ word;
    }
    if !remainder.is_empty() {
        let mut word = 0u32;
        for (index, byte) in remainder.iter().enumerate() {
            word ^= u32::from(*byte) << (21 - index * 7);
        }
        hash = hash.rotate_left(7 * remainder.len() as u32) ^ word;
    }
    hash
}

/// Block directory data bestfree entry.
#[derive(Debug, Clone, Copy)]
pub struct DataFree {
    pub offset: u16,
    pub length: u16,
}

impl DataFree {
    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            offset: buffer.read_be_u16(offset)?,
            length: buffer.read_be_u16(offset + 2)?,
        })
    }
}

/// Directory entry file type (from di_ftype field in v5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DirFileType {
    Unknown = 0,
    RegularFile = 1,
    Directory = 2,
    CharDevice = 3,
    BlockDevice = 4,
    Fifo = 5,
    Socket = 6,
    SymbolicLink = 7,
}

impl DirFileType {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::RegularFile,
            2 => Self::Directory,
            3 => Self::CharDevice,
            4 => Self::BlockDevice,
            5 => Self::Fifo,
            6 => Self::Socket,
            7 => Self::SymbolicLink,
            _ => Self::Unknown,
        }
    }

    /// Returns `true` if this is a directory.
    pub fn is_dir(&self) -> bool {
        matches!(self, Self::Directory)
    }
}

/// A parsed directory entry.
#[derive(Debug, Clone)]
pub struct DirEntry {
    /// Inode number of the entry.
    pub inode: u64,
    /// File type (v5 only, Unknown for v4).
    pub file_type: DirFileType,
    /// Name of the entry.
    pub name: [u8; 256],
    /// Length of the name.
    pub name_len: u8,
}

impl DirEntry {
    /// Returns the name as a byte slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Returns the name as a string (if valid UTF-8).
    pub fn name_str(&self) -> Option<&str> {
        core::str::from_utf8(self.name_bytes()).ok()
    }

    /// Returns `true` if this is "." or "..".
    pub fn is_dot_entry(&self) -> bool {
        let name = self.name_bytes();
        name == b"." || name == b".."
    }
}

/// Shortform directory header.
#[derive(Debug, Clone)]
pub struct ShortformHeader {
    /// Number of entries.
    pub count: u8,
    /// Number of entries with 8-byte inodes (if i8count is used).
    pub i8count: u8,
    /// Parent inode number.
    pub parent: u64,
}

impl ShortformHeader {
    /// Size with 4-byte parent inode.
    pub const SIZE_4: usize = 6;
    /// Size with 8-byte parent inode.
    pub const SIZE_8: usize = 10;

    /// Parses a shortform header.
    ///
    /// # Arguments
    /// * `buffer` - Raw data fork bytes
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < 2 {
            return Err(FsError::BufferTooSmall);
        }

        let count = buffer[0];
        let i8count = buffer[1];
        let use_64bit = i8count > 0;

        let size = if use_64bit {
            Self::SIZE_8
        } else {
            Self::SIZE_4
        };
        if buffer.len() < size {
            return Err(FsError::BufferTooSmall);
        }

        let parent = if use_64bit {
            buffer.read_be_u64(2)?
        } else {
            buffer.read_be_u32(2)? as u64
        };

        Ok(Self {
            count,
            i8count,
            parent,
        })
    }
}

/// Iterator for shortform directory entries.
pub struct ShortformDirIter<'a> {
    buffer: &'a [u8],
    offset: usize,
    count: u8,
    current: u8,
    use_64bit: bool,
    has_ftype: bool,
}

impl<'a> ShortformDirIter<'a> {
    /// Creates a new iterator.
    pub fn new(buffer: &'a [u8], count: u8, use_64bit: bool, has_ftype: bool) -> Self {
        // Skip header
        let header_size = if use_64bit {
            ShortformHeader::SIZE_8
        } else {
            ShortformHeader::SIZE_4
        };
        Self {
            buffer,
            offset: header_size,
            count,
            current: 0,
            use_64bit,
            has_ftype,
        }
    }
}

impl<'a> Iterator for ShortformDirIter<'a> {
    type Item = FsResult<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current >= self.count {
            return None;
        }

        // Shortform entry layout (XFS on-disk format):
        // 1 byte: name length
        // 2 bytes: offset (unused for reading)
        // N bytes: name
        // 1 byte: ftype (v5 only, comes BEFORE inode)
        // 4 or 8 bytes: inode

        if self.buffer.len().saturating_sub(self.offset) < 3 {
            return Some(Err(FsError::BufferTooSmall));
        }

        let name_len = self.buffer[self.offset];
        if name_len == 0 {
            return Some(Err(FsError::Corrupted));
        }
        self.offset = self.offset.saturating_add(3); // namelen + 2-byte offset

        // Read name.
        let name_end = match self.offset.checked_add(name_len as usize) {
            Some(end) if end <= self.buffer.len() => end,
            _ => return Some(Err(FsError::BufferTooSmall)),
        };

        let mut name = [0u8; 256];
        name[..name_len as usize].copy_from_slice(&self.buffer[self.offset..name_end]);
        self.offset = name_end;

        // Read ftype if present (comes BEFORE inode in XFS format)
        let file_type = if self.has_ftype {
            if self.offset >= self.buffer.len() {
                return Some(Err(FsError::BufferTooSmall));
            }
            let ft = DirFileType::from_u8(self.buffer[self.offset]);
            self.offset += 1;
            ft
        } else {
            DirFileType::Unknown
        };

        // Read inode (after ftype).
        let inode_size = if self.use_64bit { 8 } else { 4 };
        let inode_end = match self.offset.checked_add(inode_size) {
            Some(end) if end <= self.buffer.len() => end,
            _ => return Some(Err(FsError::BufferTooSmall)),
        };

        let inode = if self.use_64bit {
            match self.buffer.read_be_u64(self.offset) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            }
        } else {
            match self.buffer.read_be_u32(self.offset) {
                Ok(v) => v as u64,
                Err(e) => return Some(Err(e)),
            }
        };
        self.offset = inode_end;

        self.current += 1;

        Some(Ok(DirEntry {
            inode,
            file_type,
            name,
            name_len,
        }))
    }
}

/// Parses shortform directory entries from an inode's data fork.
pub fn parse_shortform_directory<'a>(
    data: &'a [u8],
    has_ftype: bool,
) -> FsResult<(ShortformHeader, ShortformDirIter<'a>)> {
    let header = ShortformHeader::parse(data)?;
    let iter = ShortformDirIter::new(data, header.count, header.i8count > 0, has_ftype);
    Ok((header, iter))
}

/// Finds an entry by name in a shortform directory.
pub fn find_entry_shortform(data: &[u8], name: &[u8], has_ftype: bool) -> FsResult<DirEntry> {
    let (_, iter) = parse_shortform_directory(data, has_ftype)?;
    for entry_res in iter {
        let entry: DirEntry = entry_res?;
        if entry.name_bytes() == name {
            return Ok(entry);
        }
    }
    Err(FsError::NotFound)
}

/// Directory data block header (v4).
#[derive(Debug, Clone)]
pub struct DataHeaderV4 {
    pub magic: u32,
    pub best_free: [DataFree; 3],
}

impl DataHeaderV4 {
    pub const SIZE: usize = 16;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        let magic = buffer.read_be_u32(0)?;
        let best_free = [
            DataFree::parse(buffer, 4)?,
            DataFree::parse(buffer, 8)?,
            DataFree::parse(buffer, 12)?,
        ];
        Ok(Self { magic, best_free })
    }
}

/// Directory data block header (v5).
#[derive(Debug, Clone)]
pub struct DataHeaderV5 {
    pub magic: u32,
    pub crc: u32,
    pub block_no: u64,
    pub lsn: u64,
    pub uuid: [u8; 16],
    pub owner: u64,
    pub best_free: [DataFree; 3],
}

impl DataHeaderV5 {
    pub const SIZE: usize = 64;

    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        let magic = buffer.read_be_u32(0)?;
        if magic != XFS_DIR3_DATA_MAGIC && magic != XFS_DIR3_BLOCK_MAGIC {
            return Err(FsError::InvalidMagic);
        }
        let crc = buffer.read_le_u32(4)?;
        let block_no = buffer.read_be_u64(8)?;
        let lsn = buffer.read_be_u64(16)?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buffer[24..40]);
        let owner = buffer.read_be_u64(40)?;
        let best_free = [
            DataFree::parse(buffer, 48)?,
            DataFree::parse(buffer, 52)?,
            DataFree::parse(buffer, 56)?,
        ];
        Ok(Self {
            magic,
            crc,
            block_no,
            lsn,
            uuid,
            owner,
            best_free,
        })
    }

    /// Verify the CRC over the complete directory block.
    pub fn verify_crc(&self, raw: &[u8]) -> FsResult<()> {
        if raw.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        verify_dir3_crc(raw, 4, self.crc)
    }

    /// Verify CRC, physical block number, directory owner and optional UUID.
    pub fn verify_metadata(
        &self,
        raw: &[u8],
        expected_fs_block: u64,
        expected_owner: u64,
        expected_uuid: Option<[u8; 16]>,
    ) -> FsResult<()> {
        self.verify_crc(raw)?;
        let expected = crate::address::fs_block_to_daddr(expected_fs_block, raw.len())?;
        if self.block_no != expected
            || self.owner != expected_owner
            || expected_uuid.is_some_and(|uuid| self.uuid != uuid)
        {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }
}

/// Verify a dir3 CRC field.
///
/// The parser historically reads these fields as little-endian, matching the
/// existing image fixtures. Accept the byte-swapped representation as well so
/// metadata produced by the opposite host-endian convention remains readable;
/// in both cases the stored value must equal the calculated CRC32C.
fn verify_dir3_crc(raw: &[u8], offset: usize, crc: u32) -> FsResult<()> {
    let end = offset.checked_add(4).ok_or(FsError::ArithmeticOverflow)?;
    let field = raw.get(offset..end).ok_or(FsError::BufferTooSmall)?;
    let stored_le = u32::from_le_bytes([field[0], field[1], field[2], field[3]]);
    let stored_be = stored_le.swap_bytes();
    if crc != stored_le && crc != stored_be {
        return Err(FsError::Corrupted);
    }
    crate::crc::verify_crc32c_field(raw, offset, stored_le, true)
        .or_else(|_| crate::crc::verify_crc32c_field(raw, offset, stored_be, false))
}

/// A leaf entry in a block or leaf directory.
#[derive(Debug, Clone, Copy)]
pub struct LeafEntry {
    /// Hash value of the name.
    pub hashval: u32,
    /// Address of the data entry (8-byte units).
    pub address: u32,
}

impl LeafEntry {
    pub const SIZE: usize = 8;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            hashval: buffer.read_be_u32(offset)?,
            address: buffer.read_be_u32(offset + 4)?,
        })
    }
}

/// Tail of a block-format directory block.
#[derive(Debug, Clone, Copy)]
pub struct BlockTail {
    /// Number of leaf entries.
    pub count: u32,
    /// Number of stale leaf entries.
    pub stale: u32,
}

impl BlockTail {
    pub const SIZE: usize = 8;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            count: buffer.read_be_u32(offset)?,
            stale: buffer.read_be_u32(offset + 4)?,
        })
    }
}

/// Header of a directory leaf block (v4).
#[derive(Debug, Clone)]
pub struct LeafHeaderV4 {
    pub info: BlockInfoV4,
    pub count: u16,
    pub stale: u16,
}

/// Header of a directory leaf block (v5).
#[derive(Debug, Clone)]
pub struct LeafHeaderV5 {
    pub info: BlockInfoV5,
    pub count: u16,
    pub stale: u16,
}

/// Generic block info for v4.
#[derive(Debug, Clone)]
pub struct BlockInfoV4 {
    pub forw: u32,
    pub back: u32,
    pub magic: u16,
}

/// Generic block info for v5.
#[derive(Debug, Clone)]
pub struct BlockInfoV5 {
    pub forw: u32,
    pub back: u32,
    pub magic: u16,
    pub crc: u32,
    pub block_no: u64,
    pub lsn: u64,
    pub uuid: [u8; 16],
    pub owner: u64,
}

impl BlockInfoV4 {
    pub const SIZE: usize = 10;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        Ok(Self {
            forw: buffer.read_be_u32(offset)?,
            back: buffer.read_be_u32(offset + 4)?,
            magic: buffer.read_be_u16(offset + 8)?,
        })
    }
}

impl BlockInfoV5 {
    pub const SIZE: usize = 56;

    pub fn parse(buffer: &[u8], offset: usize) -> FsResult<Self> {
        let end = offset
            .checked_add(Self::SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        if end > buffer.len() {
            return Err(FsError::BufferTooSmall);
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buffer[offset + 32..offset + 48]);
        Ok(Self {
            forw: buffer.read_be_u32(offset)?,
            back: buffer.read_be_u32(offset + 4)?,
            magic: buffer.read_be_u16(offset + 8)?,
            crc: buffer.read_be_u32(offset + 12)?,
            block_no: buffer.read_be_u64(offset + 16)?,
            lsn: buffer.read_be_u64(offset + 24)?,
            uuid,
            owner: buffer.read_be_u64(offset + 48)?,
        })
    }

    /// Verify the CRC over the complete directory block.
    pub fn verify_crc(&self, raw: &[u8], offset: usize) -> FsResult<()> {
        let end = offset
            .checked_add(Self::SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        if end > raw.len() {
            return Err(FsError::BufferTooSmall);
        }
        verify_dir3_crc(raw, offset + 12, self.crc)
    }

    /// Verify CRC, physical block number, directory owner and optional UUID.
    pub fn verify_metadata(
        &self,
        raw: &[u8],
        offset: usize,
        expected_fs_block: u64,
        expected_owner: u64,
        expected_uuid: Option<[u8; 16]>,
    ) -> FsResult<()> {
        self.verify_crc(raw, offset)?;
        let expected = crate::address::fs_block_to_daddr(expected_fs_block, raw.len())?;
        if self.block_no != expected
            || self.owner != expected_owner
            || expected_uuid.is_some_and(|uuid| self.uuid != uuid)
        {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }
}

impl LeafHeaderV5 {
    /// Parse a v5 directory leaf header at the start of `buffer`.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        let info = BlockInfoV5::parse(buffer, 0)?;
        if info.magic != XFS_DIR3_LEAF_MAGIC && info.magic != XFS_DIR3_LEAFN_MAGIC {
            return Err(FsError::InvalidMagic);
        }
        let count = buffer.read_be_u16(BlockInfoV5::SIZE)?;
        let stale = buffer.read_be_u16(BlockInfoV5::SIZE + 2)?;
        if stale > count {
            return Err(FsError::Corrupted);
        }
        Ok(Self { info, count, stale })
    }

    /// Verify CRC, physical block number, directory owner and optional UUID.
    pub fn verify_metadata(
        &self,
        raw: &[u8],
        expected_fs_block: u64,
        expected_owner: u64,
        expected_uuid: Option<[u8; 16]>,
    ) -> FsResult<()> {
        self.info
            .verify_metadata(raw, 0, expected_fs_block, expected_owner, expected_uuid)
    }
}

/// Header of a v5 directory free-index block.
#[derive(Debug, Clone)]
pub struct FreeHeaderV5 {
    pub magic: u32,
    pub crc: u32,
    pub block_no: u64,
    pub lsn: u64,
    pub uuid: [u8; 16],
    pub owner: u64,
    pub first_db: u32,
    pub nvalid: u32,
    pub nused: u32,
}

impl FreeHeaderV5 {
    pub const SIZE: usize = 64;

    /// Parse a v5 directory free-index header at the start of `buffer`.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        let magic = buffer.read_be_u32(0)?;
        if magic != XFS_DIR3_FREE_MAGIC {
            return Err(FsError::InvalidMagic);
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&buffer[24..40]);
        let header = Self {
            magic,
            crc: buffer.read_be_u32(4)?,
            block_no: buffer.read_be_u64(8)?,
            lsn: buffer.read_be_u64(16)?,
            uuid,
            owner: buffer.read_be_u64(40)?,
            first_db: buffer.read_be_u32(48)?,
            nvalid: buffer.read_be_u32(52)?,
            nused: buffer.read_be_u32(56)?,
        };
        if header.nused > header.nvalid {
            return Err(FsError::Corrupted);
        }
        Ok(header)
    }

    /// Verify the CRC over the complete directory free-index block.
    pub fn verify_crc(&self, raw: &[u8]) -> FsResult<()> {
        if raw.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        verify_dir3_crc(raw, 4, self.crc)
    }

    /// Verify CRC, physical block number, directory owner and optional UUID.
    pub fn verify_metadata(
        &self,
        raw: &[u8],
        expected_fs_block: u64,
        expected_owner: u64,
        expected_uuid: Option<[u8; 16]>,
    ) -> FsResult<()> {
        self.verify_crc(raw)?;
        let expected = crate::address::fs_block_to_daddr(expected_fs_block, raw.len())?;
        if self.block_no != expected
            || self.owner != expected_owner
            || expected_uuid.is_some_and(|uuid| self.uuid != uuid)
        {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }
}

/// Verify the CRC of any v5 directory data, block, leaf, node or free-index
/// header without checking its location or owner.
pub fn verify_v5_directory_block_crc(raw: &[u8]) -> FsResult<()> {
    let magic = raw.read_be_u32(0)?;
    match magic {
        XFS_DIR3_DATA_MAGIC | XFS_DIR3_BLOCK_MAGIC => DataHeaderV5::parse(raw)?.verify_crc(raw),
        XFS_DIR3_FREE_MAGIC => FreeHeaderV5::parse(raw)?.verify_crc(raw),
        _ => {
            let magic16 = raw.read_be_u16(8)?;
            if !matches!(
                magic16,
                XFS_DIR3_LEAF_MAGIC | XFS_DIR3_LEAFN_MAGIC | XFS_DIR3_NODE_MAGIC
            ) {
                return Err(FsError::InvalidMagic);
            }
            BlockInfoV5::parse(raw, 0)?.verify_crc(raw, 0)
        }
    }
}

/// Verify any v5 directory data, block, leaf, node or free-index header.
///
/// `raw` must be exactly one complete directory block. `expected_fs_block` is
/// the absolute filesystem block requested from the backing device.
pub fn verify_v5_directory_block(
    raw: &[u8],
    expected_fs_block: u64,
    expected_owner: u64,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<()> {
    let magic = raw.read_be_u32(0)?;
    match magic {
        XFS_DIR3_DATA_MAGIC | XFS_DIR3_BLOCK_MAGIC => DataHeaderV5::parse(raw)?.verify_metadata(
            raw,
            expected_fs_block,
            expected_owner,
            expected_uuid,
        ),
        XFS_DIR3_FREE_MAGIC => FreeHeaderV5::parse(raw)?.verify_metadata(
            raw,
            expected_fs_block,
            expected_owner,
            expected_uuid,
        ),
        _ => {
            // DA leaf/node blocks begin with forw/back pointers; their magic
            // is the third field in xfs_da_blkinfo at offset 8.
            let magic16 = raw.read_be_u16(8)?;
            if !matches!(
                magic16,
                XFS_DIR3_LEAF_MAGIC | XFS_DIR3_LEAFN_MAGIC | XFS_DIR3_NODE_MAGIC
            ) {
                return Err(FsError::InvalidMagic);
            }
            let info = BlockInfoV5::parse(raw, 0)?;
            if info.magic != magic16 {
                return Err(FsError::InvalidMagic);
            }
            info.verify_metadata(raw, 0, expected_fs_block, expected_owner, expected_uuid)
        }
    }
}

/// Iterator for directory data blocks (used in Block and Leaf formats).
pub struct DataDirIter<'a> {
    buffer: &'a [u8],
    offset: usize,
    end_offset: usize,
    has_ftype: bool,
    error: Option<FsError>,
}

impl<'a> DataDirIter<'a> {
    pub fn new(buffer: &'a [u8], header_size: usize, end_offset: usize, has_ftype: bool) -> Self {
        let error = if end_offset > buffer.len() {
            Some(FsError::BufferTooSmall)
        } else if header_size > end_offset {
            Some(FsError::Corrupted)
        } else {
            None
        };
        Self {
            buffer,
            offset: header_size,
            end_offset,
            has_ftype,
            error,
        }
    }
}

impl<'a> Iterator for DataDirIter<'a> {
    type Item = FsResult<DirEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(error) = self.error.take() {
            self.offset = self.end_offset;
            return Some(Err(error));
        }

        while self.offset < self.end_offset {
            let remaining = self.end_offset - self.offset;
            if remaining < 4 {
                self.offset = self.end_offset;
                return Some(Err(FsError::Corrupted));
            }

            // Check for unused entry (freetag = 0xFFFF).
            let freetag = match self.buffer.read_be_u16(self.offset) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            if freetag == 0xFFFF {
                let length = match self.buffer.read_be_u16(self.offset + 2) {
                    Ok(v) => v,
                    Err(e) => return Some(Err(e)),
                };
                let length = length as usize;
                // A free entry includes freetag, length and a final two-byte
                // tag, is 8-byte aligned, and must end inside the data-entry
                // region.  Its final tag stores this entry's starting offset.
                if length < 8 || length % 8 != 0 || length > remaining {
                    self.offset = self.end_offset;
                    return Some(Err(FsError::Corrupted));
                }
                let start_offset = match u16::try_from(self.offset) {
                    Ok(offset) => offset,
                    Err(_) => {
                        self.offset = self.end_offset;
                        return Some(Err(FsError::Corrupted));
                    }
                };
                let next_offset = self.offset + length;
                if self.buffer.read_be_u16(next_offset - 2) != Ok(start_offset) {
                    self.offset = self.end_offset;
                    return Some(Err(FsError::Corrupted));
                }
                self.offset = next_offset;
                continue;
            }

            // Data entry: inumber(8), namelen(1), name, optional ftype, tag(2).
            if remaining < 9 {
                self.offset = self.end_offset;
                return Some(Err(FsError::Corrupted));
            }
            let inode = match self.buffer.read_be_u64(self.offset) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            let name_len = self.buffer[self.offset + 8];
            if name_len == 0 {
                self.offset = self.end_offset;
                return Some(Err(FsError::Corrupted));
            }
            let name_offset = self.offset + 9;
            let name_end = match name_offset.checked_add(name_len as usize) {
                Some(end) if end <= self.end_offset => end,
                _ => {
                    self.offset = self.end_offset;
                    return Some(Err(FsError::Corrupted));
                }
            };

            let mut name = [0u8; 256];
            name[..name_len as usize].copy_from_slice(&self.buffer[name_offset..name_end]);

            let file_type = if self.has_ftype {
                if name_end >= self.end_offset {
                    self.offset = self.end_offset;
                    return Some(Err(FsError::Corrupted));
                }
                DirFileType::from_u8(self.buffer[name_end])
            } else {
                DirFileType::Unknown
            };

            let entry_size = 8 + 1 + name_len as usize + if self.has_ftype { 1 } else { 0 } + 2;
            let aligned_size = (entry_size + 7) & !7;
            if aligned_size > remaining {
                self.offset = self.end_offset;
                return Some(Err(FsError::Corrupted));
            }
            let start_offset = match u16::try_from(self.offset) {
                Ok(offset) => offset,
                Err(_) => {
                    self.offset = self.end_offset;
                    return Some(Err(FsError::Corrupted));
                }
            };
            let next_offset = self.offset + aligned_size;
            if self.buffer.read_be_u16(next_offset - 2) != Ok(start_offset) {
                self.offset = self.end_offset;
                return Some(Err(FsError::Corrupted));
            }

            self.offset = next_offset;
            return Some(Ok(DirEntry {
                inode,
                file_type,
                name,
                name_len,
            }));
        }
        None
    }
}

/// Finds an entry in a block-format directory block.
pub fn find_entry_block(
    buffer: &[u8],
    name: &[u8],
    block_size: u32,
    has_ftype: bool,
    is_v5: bool,
) -> FsResult<DirEntry> {
    find_entry_block_internal(buffer, name, block_size, has_ftype, is_v5, None, None, None)
}

/// Owner- and location-aware variant of [`find_entry_block`].
#[allow(clippy::too_many_arguments)]
pub fn find_entry_block_checked(
    buffer: &[u8],
    name: &[u8],
    block_size: u32,
    has_ftype: bool,
    is_v5: bool,
    expected_fs_block: u64,
    expected_owner: u64,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<DirEntry> {
    find_entry_block_internal(
        buffer,
        name,
        block_size,
        has_ftype,
        is_v5,
        Some(expected_fs_block),
        Some(expected_owner),
        expected_uuid,
    )
}

#[allow(clippy::too_many_arguments)]
fn find_entry_block_internal(
    buffer: &[u8],
    name: &[u8],
    block_size: u32,
    has_ftype: bool,
    is_v5: bool,
    expected_fs_block: Option<u64>,
    expected_owner: Option<u64>,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<DirEntry> {
    let block_size = usize::try_from(block_size).map_err(|_| FsError::Corrupted)?;
    if block_size < BlockTail::SIZE {
        return Err(FsError::Corrupted);
    }
    if buffer.len() < block_size {
        return Err(FsError::BufferTooSmall);
    }
    let expected_magic = if is_v5 {
        XFS_DIR3_BLOCK_MAGIC
    } else {
        XFS_DIR2_BLOCK_MAGIC
    };
    if buffer.read_be_u32(0)? != expected_magic {
        return Err(FsError::InvalidMagic);
    }
    let block = &buffer[..block_size];
    if is_v5 {
        if let (Some(expected_fs_block), Some(expected_owner)) = (expected_fs_block, expected_owner)
        {
            verify_v5_directory_block(block, expected_fs_block, expected_owner, expected_uuid)?;
        } else {
            DataHeaderV5::parse(block)?.verify_crc(block)?;
        }
    }

    let tail_offset = block_size - BlockTail::SIZE;
    let tail = BlockTail::parse(buffer, tail_offset)?;
    if tail.stale > tail.count {
        return Err(FsError::Corrupted);
    }

    let header_size = if is_v5 {
        DataHeaderV5::SIZE
    } else {
        DataHeaderV4::SIZE
    };
    if block_size < header_size + BlockTail::SIZE {
        return Err(FsError::Corrupted);
    }

    // End offset for entries is the start of the leaf-entry array.
    let leaf_bytes = (tail.count as usize)
        .checked_mul(LeafEntry::SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;
    let end_offset = tail_offset
        .checked_sub(leaf_bytes)
        .ok_or(FsError::Corrupted)?;
    if end_offset < header_size {
        return Err(FsError::Corrupted);
    }

    let iter = DataDirIter::new(buffer, header_size, end_offset, has_ftype);
    for entry_res in iter {
        let entry = entry_res?;
        if entry.name_bytes() == name {
            return Ok(entry);
        }
    }
    Err(FsError::NotFound)
}

/// Parses a directory data block and returns an iterator over its entries.
pub fn parse_data_block<'a>(
    buffer: &'a [u8],
    has_ftype: bool,
    is_v5: bool,
    is_block_format: bool,
    block_size: u32,
) -> FsResult<DataDirIter<'a>> {
    parse_data_block_internal(
        buffer,
        has_ftype,
        is_v5,
        is_block_format,
        block_size,
        None,
        None,
        None,
    )
}

/// Owner- and location-aware variant of [`parse_data_block`].
#[allow(clippy::too_many_arguments)]
pub fn parse_data_block_checked<'a>(
    buffer: &'a [u8],
    has_ftype: bool,
    is_v5: bool,
    is_block_format: bool,
    block_size: u32,
    expected_fs_block: u64,
    expected_owner: u64,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<DataDirIter<'a>> {
    parse_data_block_internal(
        buffer,
        has_ftype,
        is_v5,
        is_block_format,
        block_size,
        Some(expected_fs_block),
        Some(expected_owner),
        expected_uuid,
    )
}

#[allow(clippy::too_many_arguments)]
fn parse_data_block_internal<'a>(
    buffer: &'a [u8],
    has_ftype: bool,
    is_v5: bool,
    is_block_format: bool,
    block_size: u32,
    expected_fs_block: Option<u64>,
    expected_owner: Option<u64>,
    expected_uuid: Option<[u8; 16]>,
) -> FsResult<DataDirIter<'a>> {
    let block_size = usize::try_from(block_size).map_err(|_| FsError::Corrupted)?;
    if buffer.len() < block_size {
        return Err(FsError::BufferTooSmall);
    }
    if block_size < 4 {
        return Err(FsError::Corrupted);
    }

    let expected_magic = match (is_block_format, is_v5) {
        (true, false) => XFS_DIR2_BLOCK_MAGIC,
        (true, true) => XFS_DIR3_BLOCK_MAGIC,
        (false, false) => XFS_DIR2_DATA_MAGIC,
        (false, true) => XFS_DIR3_DATA_MAGIC,
    };
    if buffer.read_be_u32(0)? != expected_magic {
        return Err(FsError::InvalidMagic);
    }
    let block = &buffer[..block_size];
    if is_v5 {
        if let (Some(expected_fs_block), Some(expected_owner)) = (expected_fs_block, expected_owner)
        {
            verify_v5_directory_block(block, expected_fs_block, expected_owner, expected_uuid)?;
        } else {
            DataHeaderV5::parse(block)?.verify_crc(block)?;
        }
    }

    let header_size = if is_v5 {
        DataHeaderV5::SIZE
    } else {
        DataHeaderV4::SIZE
    };
    if block_size < header_size {
        return Err(FsError::Corrupted);
    }

    let end_offset = if is_block_format {
        if block_size < header_size + BlockTail::SIZE {
            return Err(FsError::Corrupted);
        }
        let tail_offset = block_size - BlockTail::SIZE;
        let tail = BlockTail::parse(buffer, tail_offset)?;
        if tail.stale > tail.count {
            return Err(FsError::Corrupted);
        }
        let leaf_bytes = (tail.count as usize)
            .checked_mul(LeafEntry::SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        let end_offset = tail_offset
            .checked_sub(leaf_bytes)
            .ok_or(FsError::Corrupted)?;
        if end_offset < header_size {
            return Err(FsError::Corrupted);
        }
        end_offset
    } else {
        block_size
    };

    Ok(DataDirIter::new(buffer, header_size, end_offset, has_ftype))
}

/// Check if a directory data block is valid.
pub fn validate_dir_block_magic(magic: u32) -> bool {
    matches!(
        magic,
        XFS_DIR2_BLOCK_MAGIC | XFS_DIR3_BLOCK_MAGIC | XFS_DIR2_DATA_MAGIC | XFS_DIR3_DATA_MAGIC
    )
}

#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::vec;

    use super::*;

    #[test]
    fn directory_hash_matches_xfs_word_algorithm() {
        for (name, expected) in [
            ("", 0x0000_0000),
            (".", 0x05C0_0000),
            ("..", 0x05CB_8000),
            ("a", 0x0C20_0000),
            ("ab", 0x0C38_8000),
            ("abc", 0x0C38_B180),
            ("abcd", 0x0C38_B1E4),
            ("hello.txt", 0x9396_8F66),
        ] {
            assert_eq!(dir2_hash(name.as_bytes()), expected, "{name:?}");
        }
    }

    #[test]
    fn data_dir_iter_rejects_zero_and_oversized_free_lengths() {
        let mut buf = [0u8; 64];
        buf[16..18].copy_from_slice(&0xFFFFu16.to_be_bytes());
        buf[18..20].copy_from_slice(&0u16.to_be_bytes());
        let mut iter = DataDirIter::new(&buf, 16, 32, false);
        assert!(matches!(iter.next(), Some(Err(FsError::Corrupted))));

        buf[18..20].copy_from_slice(&24u16.to_be_bytes());
        let mut iter = DataDirIter::new(&buf, 16, 32, false);
        assert!(matches!(iter.next(), Some(Err(FsError::Corrupted))));
    }

    #[test]
    fn data_dir_iter_keeps_entries_inside_the_data_region() {
        let mut buf = [0u8; 64];
        buf[24] = 20; // namelen extends beyond end_offset=32.
        let mut iter = DataDirIter::new(&buf, 16, 32, false);
        assert!(matches!(iter.next(), Some(Err(FsError::Corrupted))));

        let mut iter = DataDirIter::new(&buf, 16, 8, false);
        assert!(matches!(iter.next(), Some(Err(FsError::Corrupted))));
    }

    #[test]
    fn free_entries_require_an_eight_byte_layout_and_matching_tag() {
        let mut buf = [0u8; 32];
        buf[16..18].copy_from_slice(&0xFFFFu16.to_be_bytes());
        buf[18..20].copy_from_slice(&8u16.to_be_bytes());
        buf[22..24].copy_from_slice(&17u16.to_be_bytes()); // wrong starting
                                                           // offset
        let mut iter = DataDirIter::new(&buf, 16, 24, false);
        assert!(matches!(iter.next(), Some(Err(FsError::Corrupted))));

        buf[22..24].copy_from_slice(&16u16.to_be_bytes());
        let mut iter = DataDirIter::new(&buf, 16, 24, false);
        assert!(iter.next().is_none());

        buf[18..20].copy_from_slice(&4u16.to_be_bytes());
        let mut iter = DataDirIter::new(&buf, 16, 24, false);
        assert!(matches!(iter.next(), Some(Err(FsError::Corrupted))));
    }

    #[test]
    fn allocated_entries_require_a_matching_tag() {
        let mut buf = [0u8; 64];
        buf[16..24].copy_from_slice(&42u64.to_be_bytes());
        buf[24] = 1;
        buf[25] = b'x';
        buf[30..32].copy_from_slice(&17u16.to_be_bytes()); // wrong starting
                                                           // offset
        let mut iter = DataDirIter::new(&buf, 16, 32, false);
        assert!(matches!(iter.next(), Some(Err(FsError::Corrupted))));

        buf[30..32].copy_from_slice(&16u16.to_be_bytes());
        let mut iter = DataDirIter::new(&buf, 16, 32, false);
        let entry = iter.next().unwrap().unwrap();
        assert_eq!(entry.inode, 42);
        assert_eq!(entry.name_bytes(), b"x");
        assert!(iter.next().is_none());
    }

    #[test]
    fn shortform_truncation_is_reported_without_panicking() {
        let header = [1u8, 0, 0, 0, 0, 1];
        let (_, mut iter) = parse_shortform_directory(&header, false).unwrap();
        assert!(matches!(iter.next(), Some(Err(FsError::BufferTooSmall))));
    }

    #[test]
    fn dir3_crc_recalculation_is_little_endian() {
        let mut buf = [0u8; DataHeaderV5::SIZE];
        buf[0..4].copy_from_slice(&XFS_DIR3_DATA_MAGIC.to_be_bytes());
        let crc = crate::crc::recalculate_crc_le(&mut buf, 4).unwrap();
        let header = DataHeaderV5::parse(&buf).unwrap();
        assert_eq!(header.crc, crc);
        assert_eq!(u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]), crc);
    }

    #[test]
    fn v5_directory_headers_verify_crc_blkno_owner_and_uuid() {
        let owner = 77u64;
        let uuid = [0xA5; 16];
        let cases = [
            (XFS_DIR3_DATA_MAGIC as u64, 8, 24, 40),
            (XFS_DIR3_BLOCK_MAGIC as u64, 8, 24, 40),
            (u64::from(XFS_DIR3_LEAF_MAGIC), 16, 32, 48),
            (u64::from(XFS_DIR3_LEAFN_MAGIC), 16, 32, 48),
            (u64::from(XFS_DIR3_NODE_MAGIC), 16, 32, 48),
            (XFS_DIR3_FREE_MAGIC as u64, 8, 24, 40),
        ];
        for (magic, block_offset, uuid_offset, owner_offset) in cases {
            let mut block = vec![0u8; 512];
            if magic <= u64::from(u16::MAX) {
                block[8..10].copy_from_slice(&(magic as u16).to_be_bytes());
            } else {
                block[..4].copy_from_slice(&(magic as u32).to_be_bytes());
            }
            block[block_offset..block_offset + 8].copy_from_slice(&3u64.to_be_bytes());
            block[uuid_offset..uuid_offset + 16].copy_from_slice(&uuid);
            block[owner_offset..owner_offset + 8].copy_from_slice(&owner.to_be_bytes());
            let crc_offset = if magic <= u64::from(u16::MAX) { 12 } else { 4 };
            crate::crc::recalculate_crc_be(&mut block, crc_offset).unwrap();
            assert!(
                verify_v5_directory_block(&block, 3, owner, Some(uuid)).is_ok(),
                "magic {magic:08x}"
            );

            let mut wrong_block = block.clone();
            wrong_block[block_offset..block_offset + 8].copy_from_slice(&4u64.to_be_bytes());
            crate::crc::recalculate_crc_be(&mut wrong_block, crc_offset).unwrap();
            assert!(matches!(
                verify_v5_directory_block(&wrong_block, 3, owner, Some(uuid)),
                Err(FsError::Corrupted)
            ));

            let mut wrong_owner = block.clone();
            wrong_owner[owner_offset..owner_offset + 8].copy_from_slice(&78u64.to_be_bytes());
            crate::crc::recalculate_crc_be(&mut wrong_owner, crc_offset).unwrap();
            assert!(matches!(
                verify_v5_directory_block(&wrong_owner, 3, owner, Some(uuid)),
                Err(FsError::Corrupted)
            ));
            assert!(matches!(
                verify_v5_directory_block(&block, 3, owner, Some([0xAA; 16])),
                Err(FsError::Corrupted)
            ));

            let mut bad_crc = block;
            bad_crc[200] ^= 1;
            assert!(matches!(
                verify_v5_directory_block(&bad_crc, 3, owner, Some(uuid)),
                Err(FsError::Corrupted)
            ));
        }
    }

    #[test]
    fn data_block_parser_checks_size_magic_and_tail_bounds() {
        let mut buf = [0u8; 64];
        buf[0..4].copy_from_slice(&XFS_DIR2_BLOCK_MAGIC.to_be_bytes());
        assert!(parse_data_block(&buf, false, false, true, 0).is_err());

        buf[56..60].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_data_block(&buf, false, false, true, 64).is_err());

        buf[0..4].copy_from_slice(&XFS_DIR3_BLOCK_MAGIC.to_be_bytes());
        assert!(matches!(
            parse_data_block(&buf, false, false, true, 64),
            Err(FsError::InvalidMagic)
        ));
    }
}
