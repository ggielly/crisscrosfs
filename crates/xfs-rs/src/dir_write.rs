//! Directory write operations for XFS.
//!
//! This module provides functions to add and remove entries from XFS
//! directories. It handles shortform, block, and (TODO) leaf/node directory
//! formats.

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::mem;

use fs_abstraction::{FsError, FsResult};

use crate::{
    constants::*,
    directory::{dir2_hash, DirFileType, LeafEntry, ShortformHeader},
};

/// Maximum entries in a shortform directory before conversion to block format.
/// This depends on inode size, but typically around 4-10 entries.
pub const SHORTFORM_MAX_ENTRIES: u8 = 10;

/// Entry to add to a directory.
#[derive(Debug, Clone)]
pub struct NewDirEntry {
    /// Name of the entry (max 255 bytes).
    pub name: Vec<u8>,
    /// Inode number.
    pub inode: u64,
    /// File type.
    pub file_type: DirFileType,
}

impl NewDirEntry {
    /// Create a new directory entry.
    pub fn new(name: &[u8], inode: u64, file_type: DirFileType) -> Self {
        Self {
            name: name.to_vec(),
            inode,
            file_type,
        }
    }

    /// Calculate the size of this entry in shortform format.
    pub fn shortform_size(&self, use_64bit: bool, has_ftype: bool) -> usize {
        let mut size = 1 + 2 + self.name.len(); // namelen + offset + name
        if has_ftype {
            size += 1; // ftype
        }
        size += if use_64bit { 8 } else { 4 }; // inode
        size
    }
}

fn aligned_dir_entry_size(name_len: usize, has_ftype: bool) -> FsResult<usize> {
    let size = 8usize
        .checked_add(1)
        .and_then(|value| value.checked_add(name_len))
        .and_then(|value| value.checked_add(usize::from(has_ftype)))
        .and_then(|value| value.checked_add(2))
        .ok_or(FsError::ArithmeticOverflow)?;
    size.checked_add(7)
        .map(|value| value & !7)
        .ok_or(FsError::ArithmeticOverflow)
}

fn shortform_first_entry_offset(is_v5: bool, has_ftype: bool) -> FsResult<u16> {
    let header_size: usize = if is_v5 { 64 } else { 16 };
    let dot = aligned_dir_entry_size(1, has_ftype)?;
    let dotdot = aligned_dir_entry_size(2, has_ftype)?;
    let offset = header_size
        .checked_add(dot)
        .and_then(|value| value.checked_add(dotdot))
        .ok_or(FsError::ArithmeticOverflow)?;
    u16::try_from(offset).map_err(|_| FsError::ArithmeticOverflow)
}

/// Serialize a shortform directory header.
pub fn serialize_shortform_header(header: &ShortformHeader, use_64bit: bool) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(header.count);
    buf.push(header.i8count);

    if use_64bit {
        buf.extend_from_slice(&header.parent.to_be_bytes());
    } else {
        buf.extend_from_slice(&(header.parent as u32).to_be_bytes());
    }

    buf
}

/// Serialize a shortform directory entry.
pub fn serialize_shortform_entry(
    entry: &NewDirEntry,
    offset: u16,
    use_64bit: bool,
    has_ftype: bool,
) -> Vec<u8> {
    let mut buf = Vec::new();

    // Name length
    buf.push(entry.name.len() as u8);

    // Offset (2 bytes)
    buf.extend_from_slice(&offset.to_be_bytes());

    // Name
    buf.extend_from_slice(&entry.name);

    // File type (before inode in XFS format)
    if has_ftype {
        buf.push(entry.file_type as u8);
    }

    // Inode
    if use_64bit {
        buf.extend_from_slice(&entry.inode.to_be_bytes());
    } else {
        buf.extend_from_slice(&(entry.inode as u32).to_be_bytes());
    }

    buf
}

/// Add an entry to a shortform directory.
///
/// Returns the new directory data, or an error if the directory is full
/// and needs to be converted to block format.
pub fn add_shortform_entry(
    current_data: &[u8],
    entry: &NewDirEntry,
    parent_ino: u64,
    is_v5: bool,
    has_ftype: bool,
    max_size: usize,
) -> FsResult<Vec<u8>> {
    if entry.name.is_empty() || entry.name.len() > XFS_NAME_MAX {
        return Err(FsError::InvalidPath);
    }

    let header = if current_data.len() >= 2 {
        ShortformHeader::parse(current_data)?
    } else {
        ShortformHeader {
            count: 0,
            i8count: 0,
            parent: parent_ino,
        }
    };
    let current_is_64 = header.i8count > 0;
    let target_is_64 =
        current_is_64 || entry.inode > u32::MAX as u64 || header.parent > u32::MAX as u64;

    let mut entries = Vec::new();
    if header.count != 0 {
        let (_, iter) = crate::directory::parse_shortform_directory(current_data, has_ftype)?;
        for parsed in iter {
            let parsed = parsed.map_err(|error| match error {
                FsError::BufferTooSmall => FsError::Corrupted,
                other => other,
            })?;
            if parsed.name_bytes() == entry.name {
                return Err(FsError::AlreadyExists);
            }
            entries.push(NewDirEntry::new(
                parsed.name_bytes(),
                parsed.inode,
                parsed.file_type,
            ));
        }
    }
    if entries.len() >= u8::MAX as usize {
        return Err(FsError::NoSpace);
    }
    entries.push(entry.clone());

    let count = u8::try_from(entries.len()).map_err(|_| FsError::NoSpace)?;
    let i8count = u8::try_from(
        usize::from(header.parent > u32::MAX as u64)
            + entries
                .iter()
                .filter(|entry| entry.inode > u32::MAX as u64)
                .count(),
    )
    .map_err(|_| FsError::NoSpace)?;
    let new_header = ShortformHeader {
        count,
        i8count,
        parent: header.parent,
    };
    let header_size = if target_is_64 {
        ShortformHeader::SIZE_8
    } else {
        ShortformHeader::SIZE_4
    };
    let mut total_size = header_size;
    for existing in &entries {
        total_size = total_size
            .checked_add(existing.shortform_size(target_is_64, has_ftype))
            .ok_or(FsError::ArithmeticOverflow)?;
    }
    if total_size > max_size {
        return Err(FsError::NoSpace);
    }

    let mut new_data = Vec::with_capacity(total_size);
    new_data.extend(serialize_shortform_header(&new_header, target_is_64));
    let mut offset = shortform_first_entry_offset(is_v5, has_ftype)?;
    for existing in &entries {
        new_data.extend(serialize_shortform_entry(
            existing,
            offset,
            target_is_64,
            has_ftype,
        ));
        offset = offset
            .checked_add(
                u16::try_from(aligned_dir_entry_size(existing.name.len(), has_ftype)?)
                    .map_err(|_| FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
    }
    Ok(new_data)
}

/// Remove an entry from a shortform directory by name.
pub fn remove_shortform_entry(
    current_data: &[u8],
    name: &[u8],
    is_v5: bool,
    has_ftype: bool,
) -> FsResult<Vec<u8>> {
    let header = ShortformHeader::parse(current_data)?;
    let current_is_64 = header.i8count > 0;
    let mut entries = Vec::new();
    let mut found = false;
    if header.count != 0 {
        let (_, iter) = crate::directory::parse_shortform_directory(current_data, has_ftype)?;
        for parsed in iter {
            let parsed = parsed.map_err(|error| match error {
                FsError::BufferTooSmall => FsError::Corrupted,
                other => other,
            })?;
            if parsed.name_bytes() == name {
                found = true;
                continue;
            }
            entries.push(NewDirEntry::new(
                parsed.name_bytes(),
                parsed.inode,
                parsed.file_type,
            ));
        }
    }
    if !found {
        return Err(FsError::NotFound);
    }

    let use_64bit = current_is_64
        && (header.parent > u32::MAX as u64
            || entries.iter().any(|entry| entry.inode > u32::MAX as u64));
    let count = u8::try_from(entries.len()).map_err(|_| FsError::Corrupted)?;
    let i8count = if use_64bit {
        u8::try_from(
            usize::from(header.parent > u32::MAX as u64)
                + entries
                    .iter()
                    .filter(|entry| entry.inode > u32::MAX as u64)
                    .count(),
        )
        .map_err(|_| FsError::Corrupted)?
    } else {
        0
    };
    let new_header = ShortformHeader {
        count,
        i8count,
        parent: header.parent,
    };
    let mut new_data = Vec::new();
    new_data.extend(serialize_shortform_header(&new_header, use_64bit));
    let mut offset = shortform_first_entry_offset(is_v5, has_ftype)?;
    for entry in &entries {
        new_data.extend(serialize_shortform_entry(
            entry, offset, use_64bit, has_ftype,
        ));
        offset = offset
            .checked_add(
                u16::try_from(aligned_dir_entry_size(entry.name.len(), has_ftype)?)
                    .map_err(|_| FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
    }
    Ok(new_data)
}

/// Check if a name exists in a shortform directory.
pub fn shortform_contains(data: &[u8], name: &[u8], has_ftype: bool) -> FsResult<bool> {
    match crate::directory::find_entry_shortform(data, name, has_ftype) {
        Ok(_) => Ok(true),
        Err(FsError::NotFound) => Ok(false),
        Err(e) => Err(e),
    }
}

impl From<u8> for DirFileType {
    fn from(v: u8) -> Self {
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
}

// ─── Block Directory Operations ───────────────────────────────────────────

/// Block directory data entry header.
#[derive(Debug, Clone)]
pub struct BlockDirEntry {
    /// Inode number.
    pub inode: u64,
    /// Name length.
    pub name_len: u8,
    /// Name bytes.
    pub name: Vec<u8>,
    /// File type (v5).
    pub file_type: DirFileType,
    /// Entry tag (offset from start of block).
    pub tag: u16,
}

impl BlockDirEntry {
    /// Calculate the on-disk size of this entry (8-byte aligned).
    pub fn disk_size(&self, has_ftype: bool) -> usize {
        // inumber (8) + namelen (1) + name + ftype? + tag (2)
        let base_size = 8 + 1 + self.name.len() + if has_ftype { 1 } else { 0 } + 2;
        // Round up to 8-byte alignment
        (base_size + 7) & !7
    }
}

/// Rebuild a complete single-block XFS directory from its logical entries.
///
/// The caller supplies entries other than `.` and `..`.  The resulting block
/// contains canonical data entries, a single trailing free-space record, a
/// hash-sorted leaf table, the block tail, best-free metadata, and (for v5) the
/// identification fields and CRC.  Rebuilding avoids in-place free-list surgery
/// and guarantees that tags and leaf addresses remain consistent.
#[allow(clippy::too_many_arguments)]
pub fn build_block_directory(
    entries: &[NewDirEntry],
    owner: u64,
    parent: u64,
    block_size: usize,
    is_v5: bool,
    has_ftype: bool,
    uuid: [u8; 16],
    disk_address: u64,
    lsn: u64,
) -> FsResult<Vec<u8>> {
    const FREE_TAG: u16 = 0xFFFF;
    const NULL_DATA_OFF: u16 = 0xFFFF;

    if !(512..=65_536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }
    let header_size: usize = if is_v5 { 64 } else { 16 };
    let tail_offset = block_size.checked_sub(8).ok_or(FsError::Corrupted)?;
    if tail_offset < header_size + 8 {
        return Err(FsError::BufferTooSmall);
    }

    let mut all_entries = Vec::with_capacity(entries.len().saturating_add(2));
    all_entries.push(NewDirEntry::new(b".", owner, DirFileType::Directory));
    all_entries.push(NewDirEntry::new(b"..", parent, DirFileType::Directory));
    all_entries.extend_from_slice(entries);

    for entry in &all_entries {
        if entry.name.is_empty() || entry.name.len() > XFS_NAME_MAX {
            return Err(FsError::InvalidPath);
        }
        if entry
            .name
            .iter()
            .any(|byte| matches!(byte, 0 | b'/' | b'\\'))
        {
            return Err(FsError::InvalidPath);
        }
    }

    let leaf_bytes = all_entries
        .len()
        .checked_mul(8)
        .ok_or(FsError::ArithmeticOverflow)?;
    let leaf_offset = tail_offset
        .checked_sub(leaf_bytes)
        .filter(|offset| *offset >= header_size)
        .ok_or(FsError::NoSpace)?;

    let mut block = vec![0u8; block_size];
    let magic = if is_v5 {
        XFS_DIR3_BLOCK_MAGIC
    } else {
        XFS_DIR2_BLOCK_MAGIC
    };
    block[0..4].copy_from_slice(&magic.to_be_bytes());

    let mut data_offset = header_size;
    let mut leaf_entries = Vec::with_capacity(all_entries.len());
    for entry in &all_entries {
        let base_size = 8u64
            .checked_add(1)
            .and_then(|value| value.checked_add(entry.name.len() as u64))
            .and_then(|value| value.checked_add(u64::from(has_ftype)))
            .and_then(|value| value.checked_add(2))
            .ok_or(FsError::ArithmeticOverflow)?;
        let aligned = base_size
            .checked_add(7)
            .map(|value| value & !7)
            .ok_or(FsError::ArithmeticOverflow)?;
        let aligned = usize::try_from(aligned).map_err(|_| FsError::ArithmeticOverflow)?;
        let end = data_offset
            .checked_add(aligned)
            .ok_or(FsError::ArithmeticOverflow)?;
        if end > leaf_offset {
            return Err(FsError::NoSpace);
        }

        block[data_offset..data_offset + 8].copy_from_slice(&entry.inode.to_be_bytes());
        block[data_offset + 8] = entry.name.len() as u8;
        let name_start = data_offset + 9;
        block[name_start..name_start + entry.name.len()].copy_from_slice(&entry.name);
        let cursor = name_start + entry.name.len();
        if has_ftype {
            block[cursor] = entry.file_type as u8;
        }
        let tag_offset = end.checked_sub(2).ok_or(FsError::Corrupted)?;
        block[tag_offset..end].copy_from_slice(&(data_offset as u16).to_be_bytes());

        leaf_entries.push(LeafEntry {
            hashval: dir2_hash(&entry.name),
            address: (data_offset / 8) as u32,
        });
        data_offset = end;
    }

    let free_length = leaf_offset
        .checked_sub(data_offset)
        .ok_or(FsError::ArithmeticOverflow)?;
    if free_length < 8 || free_length % 8 != 0 || free_length > u16::MAX as usize {
        return Err(FsError::NoSpace);
    }
    block[data_offset..data_offset + 2].copy_from_slice(&FREE_TAG.to_be_bytes());
    block[data_offset + 2..data_offset + 4].copy_from_slice(&(free_length as u16).to_be_bytes());
    block[leaf_offset - 2..leaf_offset].copy_from_slice(&(data_offset as u16).to_be_bytes());

    // bestfree[0] describes the only free record.  The remaining slots use the
    // canonical NULLDATAOFF sentinel.
    let best_free_offset = if is_v5 { 48 } else { 4 };
    block[best_free_offset..best_free_offset + 2]
        .copy_from_slice(&(data_offset as u16).to_be_bytes());
    block[best_free_offset + 2..best_free_offset + 4]
        .copy_from_slice(&(free_length as u16).to_be_bytes());
    for slot in 1..3 {
        let offset = best_free_offset + slot * 4;
        block[offset..offset + 2].copy_from_slice(&NULL_DATA_OFF.to_be_bytes());
        block[offset + 2..offset + 4].copy_from_slice(&0u16.to_be_bytes());
    }

    leaf_entries.sort_by_key(|entry| entry.hashval);
    for (index, leaf) in leaf_entries.iter().enumerate() {
        let offset = leaf_offset + index * 8;
        block[offset..offset + 4].copy_from_slice(&leaf.hashval.to_be_bytes());
        block[offset + 4..offset + 8].copy_from_slice(&leaf.address.to_be_bytes());
    }
    block[tail_offset..tail_offset + 4].copy_from_slice(&(all_entries.len() as u32).to_be_bytes());
    block[tail_offset + 4..tail_offset + 8].copy_from_slice(&0u32.to_be_bytes());

    if is_v5 {
        block[8..16].copy_from_slice(&disk_address.to_be_bytes());
        block[16..24].copy_from_slice(&lsn.to_be_bytes());
        block[24..40].copy_from_slice(&uuid);
        block[40..48].copy_from_slice(&owner.to_be_bytes());
        crate::crc::recalculate_crc_le(&mut block, 4).ok_or(FsError::BufferTooSmall)?;
    }

    Ok(block)
}

/// Add an entry by rebuilding a single-block directory.
#[allow(clippy::too_many_arguments)]
pub fn add_block_directory_entry(
    data: &[u8],
    entry: &NewDirEntry,
    has_ftype: bool,
    owner: u64,
    parent: u64,
    block_size: usize,
    is_v5: bool,
    uuid: [u8; 16],
    disk_address: u64,
    lsn: u64,
) -> FsResult<Vec<u8>> {
    let (mut entries, _) = parse_block_directory(data, has_ftype)?;
    if entries.iter().any(|existing| existing.name == entry.name) {
        return Err(FsError::AlreadyExists);
    }
    entries.push(BlockDirEntry {
        inode: entry.inode,
        name_len: entry.name.len() as u8,
        name: entry.name.clone(),
        file_type: entry.file_type,
        tag: 0,
    });
    let logical: Vec<_> = entries
        .into_iter()
        .filter(|existing| existing.name != b"." && existing.name != b"..")
        .map(|existing| NewDirEntry::new(&existing.name, existing.inode, existing.file_type))
        .collect();
    build_block_directory(
        &logical,
        owner,
        parent,
        block_size,
        is_v5,
        has_ftype,
        uuid,
        disk_address,
        lsn,
    )
}

/// Remove an entry by rebuilding a single-block directory.
#[allow(clippy::too_many_arguments)]
pub fn remove_block_directory_entry(
    data: &[u8],
    name: &[u8],
    expected_inode: u64,
    has_ftype: bool,
    owner: u64,
    parent: u64,
    block_size: usize,
    is_v5: bool,
    uuid: [u8; 16],
    disk_address: u64,
    lsn: u64,
) -> FsResult<Vec<u8>> {
    let (entries, _) = parse_block_directory(data, has_ftype)?;
    let mut found = false;
    let logical: Vec<_> = entries
        .into_iter()
        .filter(|existing| {
            if existing.name == b"." || existing.name == b".." {
                return false;
            }
            if existing.name == name {
                if existing.inode != expected_inode {
                    return true;
                }
                found = true;
                return false;
            }
            true
        })
        .map(|existing| NewDirEntry::new(&existing.name, existing.inode, existing.file_type))
        .collect();
    if !found {
        return Err(FsError::NotFound);
    }
    build_block_directory(
        &logical,
        owner,
        parent,
        block_size,
        is_v5,
        has_ftype,
        uuid,
        disk_address,
        lsn,
    )
}

/// A complete leaf-format directory rebuild.
#[derive(Debug, Clone)]
pub struct DirLeafBuild {
    pub data_blocks: Vec<Vec<u8>>,
    pub leaf_block: Vec<u8>,
    pub best_free: Vec<u16>,
}

struct DirectoryDataBuild {
    raw: Vec<u8>,
    leaf_entries: Vec<(u32, u32)>,
    best_free: u16,
}

#[allow(clippy::too_many_arguments)]
fn build_directory_data_block(
    entries: &[NewDirEntry],
    owner: u64,
    block_size: usize,
    is_v5: bool,
    has_ftype: bool,
    uuid: [u8; 16],
    disk_address: u64,
    lsn: u64,
) -> FsResult<DirectoryDataBuild> {
    let header_size: usize = if is_v5 { 64 } else { 16 };
    let magic = if is_v5 {
        XFS_DIR3_DATA_MAGIC
    } else {
        XFS_DIR2_DATA_MAGIC
    };
    let mut raw = vec![0u8; block_size];
    raw[0..4].copy_from_slice(&magic.to_be_bytes());
    let mut offset = header_size;
    let mut leaf_entries = Vec::new();
    for entry in entries {
        let size = aligned_dir_entry_size(entry.name.len(), has_ftype)?;
        let end = offset
            .checked_add(size)
            .ok_or(FsError::ArithmeticOverflow)?;
        if end > block_size.saturating_sub(8) {
            return Err(FsError::NoSpace);
        }
        raw[offset..offset + 8].copy_from_slice(&entry.inode.to_be_bytes());
        raw[offset + 8] = entry.name.len() as u8;
        let name_start = offset + 9;
        raw[name_start..name_start + entry.name.len()].copy_from_slice(&entry.name);
        if has_ftype {
            raw[name_start + entry.name.len()] = entry.file_type as u8;
        }
        raw[end - 2..end].copy_from_slice(&(offset as u16).to_be_bytes());
        leaf_entries.push((dir2_hash(&entry.name), offset as u32));
        offset = end;
    }
    let free_length = block_size - offset;
    if free_length < 8 || free_length > u16::MAX as usize {
        return Err(FsError::NoSpace);
    }
    raw[offset..offset + 2].copy_from_slice(&0xFFFFu16.to_be_bytes());
    raw[offset + 2..offset + 4].copy_from_slice(&(free_length as u16).to_be_bytes());
    raw[block_size - 2..block_size].copy_from_slice(&(offset as u16).to_be_bytes());
    let best_free_offset = if is_v5 { 48 } else { 4 };
    raw[best_free_offset..best_free_offset + 2].copy_from_slice(&(offset as u16).to_be_bytes());
    raw[best_free_offset + 2..best_free_offset + 4]
        .copy_from_slice(&(free_length as u16).to_be_bytes());
    if is_v5 {
        raw[8..16].copy_from_slice(&disk_address.to_be_bytes());
        raw[16..24].copy_from_slice(&lsn.to_be_bytes());
        raw[24..40].copy_from_slice(&uuid);
        raw[40..48].copy_from_slice(&owner.to_be_bytes());
        crate::crc::recalculate_crc_le(&mut raw, 4).ok_or(FsError::BufferTooSmall)?;
    }
    Ok(DirectoryDataBuild {
        raw,
        leaf_entries,
        best_free: free_length as u16,
    })
}

fn plan_leaf_groups(
    all: &[NewDirEntry],
    block_size: usize,
    is_v5: bool,
    has_ftype: bool,
) -> FsResult<Vec<Vec<NewDirEntry>>> {
    let header_size: usize = if is_v5 { 64 } else { 16 };
    let mut groups: Vec<Vec<NewDirEntry>> = Vec::new();
    let mut current = Vec::new();
    let mut used = header_size;
    for entry in all {
        let size = aligned_dir_entry_size(entry.name.len(), has_ftype)?;
        if !current.is_empty() && used + size + 8 > block_size {
            groups.push(mem::take(&mut current));
            used = header_size;
        }
        used = used.checked_add(size).ok_or(FsError::ArithmeticOverflow)?;
        current.push(entry.clone());
    }
    if !current.is_empty() {
        groups.push(current);
    }
    Ok(groups)
}

/// Return the number of data blocks required for a leaf-format directory.
#[allow(clippy::too_many_arguments)]
pub fn leaf_directory_data_block_count(
    entries: &[NewDirEntry],
    owner: u64,
    parent: u64,
    block_size: usize,
    is_v5: bool,
    has_ftype: bool,
) -> FsResult<usize> {
    let mut all = Vec::with_capacity(entries.len() + 2);
    all.push(NewDirEntry::new(b".", owner, DirFileType::Directory));
    all.push(NewDirEntry::new(b"..", parent, DirFileType::Directory));
    all.extend_from_slice(entries);
    Ok(plan_leaf_groups(&all, block_size, is_v5, has_ftype)?.len())
}

/// Build a complete multi-data-block directory with one LEAF1 index block.
///
/// `disk_addresses` contains one physical 512-byte disk address per data block,
/// followed by the leaf block address. The function rejects directories that
/// do not fit in a single leaf; callers must not silently truncate them.
#[allow(clippy::too_many_arguments)]
pub fn build_leaf_directory(
    entries: &[NewDirEntry],
    owner: u64,
    parent: u64,
    block_size: usize,
    is_v5: bool,
    has_ftype: bool,
    uuid: [u8; 16],
    disk_addresses: &[u64],
    lsn: u64,
) -> FsResult<DirLeafBuild> {
    if !(512..=65_536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }
    let mut all = Vec::with_capacity(entries.len() + 2);
    all.push(NewDirEntry::new(b".", owner, DirFileType::Directory));
    all.push(NewDirEntry::new(b"..", parent, DirFileType::Directory));
    all.extend_from_slice(entries);

    let groups = plan_leaf_groups(&all, block_size, is_v5, has_ftype)?;
    if disk_addresses.len() != groups.len() + 1 {
        return Err(FsError::InvalidArgument);
    }

    let leaf_header_size = if is_v5 { 64 } else { 16 };
    let best_bytes = groups
        .len()
        .checked_mul(2)
        .ok_or(FsError::ArithmeticOverflow)?;
    let leaf_capacity = block_size
        .saturating_sub(leaf_header_size)
        .saturating_sub(best_bytes)
        .saturating_sub(4)
        / 8;
    if all.len() > leaf_capacity {
        return Err(FsError::NoSpace);
    }

    let mut data_blocks = Vec::with_capacity(groups.len());
    let mut leaf_entries = Vec::with_capacity(all.len());
    let mut best_free = Vec::with_capacity(groups.len());
    for (index, group) in groups.iter().enumerate() {
        let build = build_directory_data_block(
            group,
            owner,
            block_size,
            is_v5,
            has_ftype,
            uuid,
            disk_addresses[index],
            lsn,
        )?;
        for (hash, offset) in build.leaf_entries {
            let address = (index * block_size + offset as usize) / 8;
            leaf_entries.push(LeafEntry {
                hashval: hash,
                address: address as u32,
            });
        }
        best_free.push(build.best_free);
        data_blocks.push(build.raw);
    }
    leaf_entries.sort_by_key(|entry| entry.hashval);

    let mut leaf = vec![0u8; block_size];
    if is_v5 {
        leaf[8..10].copy_from_slice(&XFS_DIR3_LEAF_MAGIC.to_be_bytes());
        leaf[16..24].copy_from_slice(&disk_addresses[groups.len()].to_be_bytes());
        leaf[24..32].copy_from_slice(&lsn.to_be_bytes());
        leaf[32..48].copy_from_slice(&uuid);
        leaf[48..56].copy_from_slice(&owner.to_be_bytes());
        leaf[56..58].copy_from_slice(&(all.len() as u16).to_be_bytes());
        crate::crc::recalculate_crc_le(&mut leaf, 12).ok_or(FsError::BufferTooSmall)?;
    } else {
        leaf[8..10].copy_from_slice(&XFS_DIR2_LEAF_MAGIC.to_be_bytes());
        leaf[12..14].copy_from_slice(&(all.len() as u16).to_be_bytes());
    }
    let tail_offset = block_size - 4;
    let entries_offset = leaf_header_size;
    for (index, entry) in leaf_entries.iter().enumerate() {
        let offset = entries_offset + index * 8;
        leaf[offset..offset + 4].copy_from_slice(&entry.hashval.to_be_bytes());
        leaf[offset + 4..offset + 8].copy_from_slice(&entry.address.to_be_bytes());
    }
    let bests_offset = tail_offset - best_bytes;
    for (index, best) in best_free.iter().enumerate() {
        let offset = bests_offset + index * 2;
        leaf[offset..offset + 2].copy_from_slice(&best.to_be_bytes());
    }
    leaf[tail_offset..tail_offset + 4].copy_from_slice(&(groups.len() as u32).to_be_bytes());
    if is_v5 {
        crate::crc::recalculate_crc_le(&mut leaf, 12).ok_or(FsError::BufferTooSmall)?;
    }
    Ok(DirLeafBuild {
        data_blocks,
        leaf_block: leaf,
        best_free,
    })
}

/// Maximum entries in a LEAFN block.
pub fn leaf_node_record_capacity(block_size: usize, is_v5: bool) -> FsResult<usize> {
    let header_size = if is_v5 { 64 } else { 16 };
    Ok(block_size.saturating_sub(header_size) / 8)
}

/// Maximum entries in a LEAF1 block with `data_blocks` best-free slots.
pub fn leaf1_record_capacity(
    block_size: usize,
    is_v5: bool,
    data_blocks: usize,
) -> FsResult<usize> {
    let header_size = if is_v5 { 64 } else { 16 };
    let best_bytes = data_blocks
        .checked_mul(2)
        .ok_or(FsError::ArithmeticOverflow)?;
    Ok(block_size
        .saturating_sub(header_size)
        .saturating_sub(best_bytes)
        .saturating_sub(4)
        / 8)
}

/// A complete node-format directory rebuild.
#[derive(Debug, Clone)]
pub struct DirNodeBuild {
    pub data_blocks: Vec<Vec<u8>>,
    pub leaf_blocks: Vec<Vec<u8>>,
    pub root_block: Vec<u8>,
    pub free_block: Vec<u8>,
    pub best_free: Vec<u16>,
}

fn write_dir3_identification(
    raw: &mut [u8],
    disk_address: u64,
    lsn: u64,
    uuid: [u8; 16],
    owner: u64,
) {
    raw[16..24].copy_from_slice(&disk_address.to_be_bytes());
    raw[24..32].copy_from_slice(&lsn.to_be_bytes());
    raw[32..48].copy_from_slice(&uuid);
    raw[48..56].copy_from_slice(&owner.to_be_bytes());
}

/// Build data blocks, LEAFN blocks, a DA node root, and one free-index block.
///
/// `disk_addresses` is ordered as data blocks, leaf blocks, root node, free
/// index. The layout supports one DA-node level and one free-index block.
#[allow(clippy::too_many_arguments)]
pub fn build_node_directory(
    entries: &[NewDirEntry],
    owner: u64,
    parent: u64,
    block_size: usize,
    is_v5: bool,
    has_ftype: bool,
    uuid: [u8; 16],
    disk_addresses: &[u64],
    lsn: u64,
) -> FsResult<DirNodeBuild> {
    if !(512..=65_536).contains(&block_size) || !block_size.is_power_of_two() {
        return Err(FsError::InvalidArgument);
    }
    let mut all = Vec::with_capacity(entries.len() + 2);
    all.push(NewDirEntry::new(b".", owner, DirFileType::Directory));
    all.push(NewDirEntry::new(b"..", parent, DirFileType::Directory));
    all.extend_from_slice(entries);
    let data_count =
        leaf_directory_data_block_count(entries, owner, parent, block_size, is_v5, has_ftype)?;
    let leaf_capacity = leaf_node_record_capacity(block_size, is_v5)?;
    if leaf_capacity == 0 {
        return Err(FsError::InvalidArgument);
    }
    let leaf_count = all.len().div_ceil(leaf_capacity);
    let node_capacity = leaf_node_record_capacity(block_size, is_v5)?;
    if leaf_count > node_capacity {
        return Err(FsError::NoSpace);
    }
    let free_header_size = if is_v5 { 72 } else { 16 };
    let free_capacity = block_size.saturating_sub(free_header_size) / 2;
    if data_count > free_capacity {
        return Err(FsError::NoSpace);
    }
    let expected = data_count
        .checked_add(leaf_count)
        .and_then(|value| value.checked_add(2))
        .ok_or(FsError::ArithmeticOverflow)?;
    if disk_addresses.len() != expected {
        return Err(FsError::InvalidArgument);
    }

    let groups = plan_leaf_groups(&all, block_size, is_v5, has_ftype)?;
    let mut data_blocks = Vec::with_capacity(data_count);
    let mut leaf_entries = Vec::with_capacity(all.len());
    let mut best_free = Vec::with_capacity(data_count);
    for (index, group) in groups.iter().enumerate() {
        let build = build_directory_data_block(
            group,
            owner,
            block_size,
            is_v5,
            has_ftype,
            uuid,
            disk_addresses[index],
            lsn,
        )?;
        for (hash, offset) in build.leaf_entries {
            leaf_entries.push(LeafEntry {
                hashval: hash,
                address: ((index * block_size + offset as usize) / 8) as u32,
            });
        }
        best_free.push(build.best_free);
        data_blocks.push(build.raw);
    }
    leaf_entries.sort_by_key(|entry| entry.hashval);

    let leaf_header_size = if is_v5 { 64 } else { 16 };
    let leaf_offset = (1u64 << 35) / block_size as u64;
    let mut leaf_blocks = Vec::with_capacity(leaf_count);
    let mut root_entries = Vec::with_capacity(leaf_count);
    for (leaf_index, chunk) in leaf_entries.chunks(leaf_capacity).enumerate() {
        let mut leaf = vec![0u8; block_size];
        let logical = leaf_offset + leaf_index as u64 + 1;
        if leaf_index != 0 {
            leaf[0..4].copy_from_slice(&((logical - 1) as u32).to_be_bytes());
        }
        if leaf_index + 1 < leaf_count {
            leaf[4..8].copy_from_slice(&((logical + 1) as u32).to_be_bytes());
        }
        if is_v5 {
            leaf[8..10].copy_from_slice(&XFS_DIR3_LEAFN_MAGIC.to_be_bytes());
            write_dir3_identification(
                &mut leaf,
                disk_addresses[data_count + leaf_index],
                lsn,
                uuid,
                owner,
            );
            leaf[56..58].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
        } else {
            leaf[8..10].copy_from_slice(&XFS_DIR2_LEAFN_MAGIC.to_be_bytes());
            leaf[12..14].copy_from_slice(&(chunk.len() as u16).to_be_bytes());
        }
        for (index, entry) in chunk.iter().enumerate() {
            let offset = leaf_header_size + index * 8;
            leaf[offset..offset + 4].copy_from_slice(&entry.hashval.to_be_bytes());
            leaf[offset + 4..offset + 8].copy_from_slice(&entry.address.to_be_bytes());
        }
        if is_v5 {
            crate::crc::recalculate_crc_le(&mut leaf, 12).ok_or(FsError::BufferTooSmall)?;
        }
        root_entries.push((
            chunk.last().ok_or(FsError::Corrupted)?.hashval,
            logical as u32,
        ));
        leaf_blocks.push(leaf);
    }

    let root_address = disk_addresses[data_count + leaf_count];
    let mut root = vec![0u8; block_size];
    if is_v5 {
        root[8..10].copy_from_slice(&XFS_DIR3_NODE_MAGIC.to_be_bytes());
        write_dir3_identification(&mut root, root_address, lsn, uuid, owner);
        root[56..58].copy_from_slice(&(leaf_count as u16).to_be_bytes());
        root[58..60].copy_from_slice(&1u16.to_be_bytes());
    } else {
        root[8..10].copy_from_slice(&XFS_DIR2_NODE_MAGIC.to_be_bytes());
        root[12..14].copy_from_slice(&(leaf_count as u16).to_be_bytes());
        root[14..16].copy_from_slice(&1u16.to_be_bytes());
    }
    for (index, (hash, before)) in root_entries.iter().enumerate() {
        let offset = leaf_header_size + index * 8;
        root[offset..offset + 4].copy_from_slice(&hash.to_be_bytes());
        root[offset + 4..offset + 8].copy_from_slice(&before.to_be_bytes());
    }
    if is_v5 {
        crate::crc::recalculate_crc_le(&mut root, 12).ok_or(FsError::BufferTooSmall)?;
    }

    let free_address = disk_addresses[data_count + leaf_count + 1];
    let mut free = vec![0u8; block_size];
    if is_v5 {
        free[0..4].copy_from_slice(&XFS_DIR3_FREE_MAGIC.to_be_bytes());
        write_dir3_identification(&mut free, free_address, lsn, uuid, owner);
        free[56..60].copy_from_slice(&0u32.to_be_bytes());
        free[60..64].copy_from_slice(&(data_count as u32).to_be_bytes());
        free[64..68].copy_from_slice(&(data_count as u32).to_be_bytes());
    } else {
        free[0..4].copy_from_slice(&XFS_DIR2_FREE_MAGIC.to_be_bytes());
        free[4..8].copy_from_slice(&0u32.to_be_bytes());
        free[8..12].copy_from_slice(&(data_count as u32).to_be_bytes());
        free[12..16].copy_from_slice(&(data_count as u32).to_be_bytes());
    }
    let bests_offset = if is_v5 { 72 } else { 16 };
    for (index, best) in best_free.iter().enumerate() {
        let offset = bests_offset + index * 2;
        free[offset..offset + 2].copy_from_slice(&best.to_be_bytes());
    }
    if is_v5 {
        crate::crc::recalculate_crc_le(&mut free, 12).ok_or(FsError::BufferTooSmall)?;
    }
    Ok(DirNodeBuild {
        data_blocks,
        leaf_blocks,
        root_block: root,
        free_block: free,
        best_free,
    })
}

/// Free space entry in a block directory.
#[derive(Debug, Clone, Copy)]
pub struct BlockDirFree {
    /// Offset of this free entry.
    pub offset: u16,
    /// Length of free space (8-byte aligned).
    pub length: u16,
}

impl BlockDirFree {
    /// Minimum usable free space (for smallest possible entry).
    pub const MIN_USEFUL: u16 = 16;
    pub const SIZE: usize = 8; // freetag(2) + length(2) + padding + final
                               // tag(2)
}

/// Parse a block directory and return entries and free spaces.
pub fn parse_block_directory(
    data: &[u8],
    has_ftype: bool,
) -> FsResult<(Vec<BlockDirEntry>, Vec<BlockDirFree>)> {
    // Check magic
    if data.len() < 16 {
        return Err(FsError::BufferTooSmall);
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if !crate::directory::validate_dir_block_magic(magic) {
        return Err(FsError::InvalidMagic);
    }

    let is_v5 = magic == XFS_DIR3_BLOCK_MAGIC || magic == XFS_DIR3_DATA_MAGIC;
    let is_block = magic == XFS_DIR2_BLOCK_MAGIC || magic == XFS_DIR3_BLOCK_MAGIC;
    let header_size: usize = if is_v5 { 64 } else { 16 };
    if data.len() < header_size {
        return Err(FsError::BufferTooSmall);
    }
    if is_v5 {
        let crc = u32::from_le_bytes(data[4..8].try_into().map_err(|_| FsError::Corrupted)?);
        crate::crc::verify_crc32c_field(data, 4, crc, true)?;
    }

    // Only the single-block format has a tail containing leaf pointers. Data
    // blocks use their entire length for entries and free-space records.
    let end = if is_block {
        let tail_offset = data.len().checked_sub(8).ok_or(FsError::Corrupted)?;
        if tail_offset < header_size {
            return Err(FsError::Corrupted);
        }
        let leaf_count = u32::from_be_bytes(
            data[tail_offset..tail_offset + 4]
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        ) as usize;
        let leaf_bytes = leaf_count
            .checked_mul(8)
            .ok_or(FsError::ArithmeticOverflow)?;
        tail_offset
            .checked_sub(leaf_bytes)
            .filter(|start| *start >= header_size)
            .ok_or(FsError::Corrupted)?
    } else {
        data.len()
    };

    let mut entries = Vec::new();
    let mut frees = Vec::new();
    let mut offset = header_size;

    while offset < end {
        let remaining = end.checked_sub(offset).ok_or(FsError::Corrupted)?;
        if remaining < 4 {
            return Err(FsError::Corrupted);
        }
        let freetag = u16::from_be_bytes([data[offset], data[offset + 1]]);

        if freetag == 0xFFFF {
            let length = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            let next = offset
                .checked_add(length)
                .ok_or(FsError::ArithmeticOverflow)?;
            if length < 8 || length % 8 != 0 || next > end {
                return Err(FsError::Corrupted);
            }
            let tag_offset = next.checked_sub(2).ok_or(FsError::Corrupted)?;
            let stored_tag = u16::from_be_bytes([data[tag_offset], data[tag_offset + 1]]);
            if stored_tag != offset as u16 {
                return Err(FsError::Corrupted);
            }
            frees.push(BlockDirFree {
                offset: offset as u16,
                length: length as u16,
            });
            offset = next;
            continue;
        }

        if remaining < 9 {
            return Err(FsError::Corrupted);
        }
        let inode = u64::from_be_bytes(
            data[offset..offset + 8]
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        );
        let name_len = data[offset + 8] as usize;
        if name_len == 0 || name_len > 255 {
            return Err(FsError::Corrupted);
        }

        let entry_size = 8 + 1 + name_len + if has_ftype { 1 } else { 0 } + 2;
        let aligned_size = (entry_size + 7) & !7;
        if aligned_size > remaining {
            return Err(FsError::Corrupted);
        }

        let name_start = offset + 9;
        let name_end = name_start.checked_add(name_len).ok_or(FsError::Corrupted)?;
        let name = data[name_start..name_end].to_vec();
        let file_type = if has_ftype {
            DirFileType::from(data[name_end])
        } else {
            DirFileType::Unknown
        };

        let tag_offset = offset
            .checked_add(aligned_size)
            .and_then(|end| end.checked_sub(2))
            .ok_or(FsError::Corrupted)?;
        let tag = u16::from_be_bytes([data[tag_offset], data[tag_offset + 1]]);
        if tag != offset as u16 {
            return Err(FsError::Corrupted);
        }

        entries.push(BlockDirEntry {
            inode,
            name_len: name_len as u8,
            name,
            file_type,
            tag,
        });
        offset += aligned_size;
    }

    Ok((entries, frees))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::directory::DirFileType;

    #[test]
    fn test_add_shortform_entry_empty() {
        let entry = NewDirEntry::new(b"test", 123, DirFileType::RegularFile);
        let result = add_shortform_entry(&[], &entry, 456, false, true, 256).unwrap();

        let header = ShortformHeader::parse(&result).unwrap();
        assert_eq!(header.count, 1);
        assert_eq!(header.parent, 456);
        assert_eq!(header.i8count, 0); // Both fit in 32-bit
        let first_offset = u16::from_be_bytes([result[7], result[8]]);
        assert_eq!(first_offset, 48); // v4 header + aligned . and ..
    }

    #[test]
    fn test_add_shortform_entry_64bit() {
        let entry = NewDirEntry::new(b"test", 0x1_0000_0000, DirFileType::RegularFile);
        let result = add_shortform_entry(&[], &entry, 456, true, true, 256).unwrap();

        let header = ShortformHeader::parse(&result).unwrap();
        assert_eq!(header.count, 1);
        assert_eq!(header.i8count, 1);
        assert_eq!(header.parent, 456);
        let first_offset = u16::from_be_bytes([result[11], result[12]]);
        assert_eq!(first_offset, 96); // v5 header + aligned . and ..
    }

    #[test]
    fn leaf_directory_rebuild_round_trips_v4_and_v5() {
        let entries: Vec<_> = (0..20)
            .map(|index| {
                NewDirEntry::new(
                    format!("entry-{index:02}").as_bytes(),
                    100 + index as u64,
                    DirFileType::RegularFile,
                )
            })
            .collect();
        for is_v5 in [false, true] {
            let count =
                leaf_directory_data_block_count(&entries, 128, 64, 512, is_v5, true).unwrap();
            let addresses: Vec<u64> = (0..=count).map(|index| 8 + index as u64 * 8).collect();
            let build = build_leaf_directory(
                &entries, 128, 64, 512, is_v5, true, [0xA5; 16], &addresses, 9,
            )
            .unwrap();
            assert_eq!(build.data_blocks.len(), count);
            assert_eq!(build.best_free.len(), count);
            for (index, raw) in build.data_blocks.iter().enumerate() {
                let (parsed, _) = parse_block_directory(raw, true).unwrap();
                assert!(parsed.len() >= if index == 0 { 2 } else { 1 });
            }
            if is_v5 {
                let crc = u32::from_le_bytes([
                    build.leaf_block[12],
                    build.leaf_block[13],
                    build.leaf_block[14],
                    build.leaf_block[15],
                ]);
                assert!(crate::crc::verify_crc32c_field(&build.leaf_block, 12, crc, true).is_ok());
            }
        }
    }

    #[test]
    fn node_directory_rebuild_round_trips_v4_and_v5() {
        let entries: Vec<_> = (0..100)
            .map(|index| {
                NewDirEntry::new(
                    format!("node-entry-{index:03}").as_bytes(),
                    1_000 + index as u64,
                    DirFileType::RegularFile,
                )
            })
            .collect();
        for is_v5 in [false, true] {
            let data_count =
                leaf_directory_data_block_count(&entries, 128, 64, 512, is_v5, true).unwrap();
            let leaf_capacity = leaf_node_record_capacity(512, is_v5).unwrap();
            let leaf_count = (entries.len() + 2).div_ceil(leaf_capacity);
            assert!(leaf_count > 1);
            let addresses: Vec<u64> = (0..data_count + leaf_count + 2)
                .map(|index| 16 + index as u64 * 8)
                .collect();
            let build = build_node_directory(
                &entries, 128, 64, 512, is_v5, true, [0x5A; 16], &addresses, 11,
            )
            .unwrap();
            assert_eq!(build.data_blocks.len(), data_count);
            assert_eq!(build.leaf_blocks.len(), leaf_count);
            assert_eq!(build.best_free.len(), data_count);

            let leaf_magic = if is_v5 {
                XFS_DIR3_LEAFN_MAGIC
            } else {
                XFS_DIR2_LEAFN_MAGIC
            };
            let leaf_offset = (1u64 << 35) / 512;
            for (index, leaf) in build.leaf_blocks.iter().enumerate() {
                assert_eq!(u16::from_be_bytes([leaf[8], leaf[9]]), leaf_magic);
                let logical = leaf_offset + index as u64 + 1;
                assert_eq!(
                    u32::from_be_bytes([leaf[0], leaf[1], leaf[2], leaf[3]]),
                    if index == 0 { 0 } else { (logical - 1) as u32 }
                );
                assert_eq!(
                    u32::from_be_bytes([leaf[4], leaf[5], leaf[6], leaf[7]]),
                    if index + 1 == leaf_count {
                        0
                    } else {
                        (logical + 1) as u32
                    }
                );
                if is_v5 {
                    let crc = u32::from_le_bytes([leaf[12], leaf[13], leaf[14], leaf[15]]);
                    assert!(crate::crc::verify_crc32c_field(leaf, 12, crc, true).is_ok());
                }
            }
            let node_magic = if is_v5 {
                XFS_DIR3_NODE_MAGIC
            } else {
                XFS_DIR2_NODE_MAGIC
            };
            assert_eq!(
                u16::from_be_bytes([build.root_block[8], build.root_block[9]]),
                node_magic
            );
            let (count_offset, level_offset) = if is_v5 { (56, 58) } else { (12, 14) };
            assert_eq!(
                u16::from_be_bytes([
                    build.root_block[count_offset],
                    build.root_block[count_offset + 1]
                ]),
                leaf_count as u16
            );
            assert_eq!(
                u16::from_be_bytes([
                    build.root_block[level_offset],
                    build.root_block[level_offset + 1]
                ]),
                1
            );
            if is_v5 {
                let crc = u32::from_le_bytes([
                    build.root_block[12],
                    build.root_block[13],
                    build.root_block[14],
                    build.root_block[15],
                ]);
                assert!(crate::crc::verify_crc32c_field(&build.root_block, 12, crc, true).is_ok());
            }
            let (firstdb, nvalid, nused) = if is_v5 { (56, 60, 64) } else { (4, 8, 12) };
            assert_eq!(
                u32::from_be_bytes([
                    build.free_block[firstdb],
                    build.free_block[firstdb + 1],
                    build.free_block[firstdb + 2],
                    build.free_block[firstdb + 3]
                ]),
                0
            );
            assert_eq!(
                u32::from_be_bytes([
                    build.free_block[nvalid],
                    build.free_block[nvalid + 1],
                    build.free_block[nvalid + 2],
                    build.free_block[nvalid + 3]
                ]),
                data_count as u32
            );
            assert_eq!(
                u32::from_be_bytes([
                    build.free_block[nused],
                    build.free_block[nused + 1],
                    build.free_block[nused + 2],
                    build.free_block[nused + 3]
                ]),
                data_count as u32
            );
        }
    }

    #[test]
    fn block_directory_rebuild_round_trips_v4_and_v5() {
        let entries = [
            NewDirEntry::new(b"alpha", 130, DirFileType::RegularFile),
            NewDirEntry::new(b"beta", 131, DirFileType::Directory),
        ];
        for is_v5 in [false, true] {
            let block =
                build_block_directory(&entries, 128, 64, 4096, is_v5, true, [0xA5; 16], 777, 9)
                    .unwrap();
            let (parsed, frees) = parse_block_directory(&block, true).unwrap();
            assert_eq!(parsed.len(), 4);
            assert!(parsed.iter().any(|entry| entry.name == b"alpha"));
            assert!(parsed.iter().any(|entry| entry.name == b"beta"));
            assert_eq!(frees.len(), 1);
            assert!(frees[0].length >= 8);

            let added = add_block_directory_entry(
                &block,
                &NewDirEntry::new(b"gamma", 132, DirFileType::RegularFile),
                true,
                128,
                64,
                4096,
                is_v5,
                [0xA5; 16],
                777,
                10,
            )
            .unwrap();
            let (parsed, _) = parse_block_directory(&added, true).unwrap();
            assert!(parsed.iter().any(|entry| entry.name == b"gamma"));

            let removed = remove_block_directory_entry(
                &added, b"beta", 131, true, 128, 64, 4096, is_v5, [0xA5; 16], 777, 11,
            )
            .unwrap();
            let (parsed, _) = parse_block_directory(&removed, true).unwrap();
            assert!(!parsed.iter().any(|entry| entry.name == b"beta"));
            assert!(parsed.iter().any(|entry| entry.name == b"alpha"));
            assert!(parsed.iter().any(|entry| entry.name == b"gamma"));
            assert_eq!(parsed.iter().filter(|entry| entry.name == b".").count(), 1);
            assert_eq!(parsed.iter().filter(|entry| entry.name == b"..").count(), 1);

            if is_v5 {
                let mut corrupted = block;
                corrupted[100] ^= 1;
                assert!(matches!(
                    parse_block_directory(&corrupted, true),
                    Err(FsError::Corrupted)
                ));
            }
        }
    }

    #[test]
    fn removing_last_entry_preserves_a_64_bit_parent() {
        let parent = 0x1_0000_0000u64;
        let entry = NewDirEntry::new(b"only", 7, DirFileType::RegularFile);
        let data = add_shortform_entry(&[], &entry, parent, false, true, 256).unwrap();
        let emptied = remove_shortform_entry(&data, b"only", false, true).unwrap();

        let header = ShortformHeader::parse(&emptied).unwrap();
        assert_eq!(header.count, 0);
        assert_eq!(header.parent, parent);
        assert_eq!(header.i8count, 1);
    }

    #[test]
    fn block_directory_rejects_zero_length_free_record() {
        let mut data = [0u8; 64];
        data[..4].copy_from_slice(&XFS_DIR2_DATA_MAGIC.to_be_bytes());
        data[16..18].copy_from_slice(&0xFFFFu16.to_be_bytes());
        data[18..20].copy_from_slice(&0u16.to_be_bytes());
        assert!(matches!(
            parse_block_directory(&data, false),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn block_directory_rejects_invalid_free_record_tag() {
        let mut data = [0u8; 64];
        data[..4].copy_from_slice(&XFS_DIR2_DATA_MAGIC.to_be_bytes());
        data[16..18].copy_from_slice(&0xFFFFu16.to_be_bytes());
        data[18..20].copy_from_slice(&8u16.to_be_bytes());
        data[22..24].copy_from_slice(&99u16.to_be_bytes());
        assert!(matches!(
            parse_block_directory(&data, false),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn truncated_shortform_entry_returns_error_instead_of_panicking() {
        let data = [1, 0, 0, 0, 0, 1, 1];
        assert!(matches!(
            remove_shortform_entry(&data, b"x", false, false),
            Err(FsError::Corrupted)
        ));
    }
}
