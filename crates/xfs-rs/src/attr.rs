//! Read-only XFS attribute-fork and POSIX ACL parsing.
//!
//! XFS stores small attribute lists in the inode literal area and larger lists
//! in extent-mapped DA-btree leaf blocks. Large values live in separate blocks
//! referenced by a leaf entry. This module validates fork geometry, metadata
//! CRCs, v5 block locations/owners/UUIDs, and remote-value chunk boundaries
//! before returning an immutable copy of an ACL xattr.
//!
//! It deliberately exposes no attribute mutation API.

use alloc::{collections::BTreeSet, sync::Arc, vec::Vec};

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::{
    address,
    btree::{BlockReader, BmbtRoot},
    constants::*,
    crc,
    extent::Extent,
    inode::Inode,
};

const XFS_ATTR_LEAF_MAGIC: u16 = 0xFBEE;
const XFS_ATTR3_LEAF_MAGIC: u16 = 0x3BEE;
const XFS_DA_NODE_MAGIC: u16 = 0xFEBE;
const XFS_DA3_NODE_MAGIC: u16 = 0x3EBE;
const XFS_ATTR3_RMT_MAGIC: u32 = 0x5841_524D; // "XARM"

const XFS_ATTR_LOCAL: u8 = 0x01;
const XFS_ATTR_ROOT: u8 = 0x02;
const XFS_ATTR_SECURE: u8 = 0x04;
const XFS_ATTR_PARENT: u8 = 0x08;
const XFS_ATTR_INCOMPLETE: u8 = 0x80;
const XFS_ATTR_NAMESPACE_MASK: u8 = XFS_ATTR_ROOT | XFS_ATTR_SECURE | XFS_ATTR_PARENT;
const XFS_ATTR_KNOWN_FLAGS: u8 = XFS_ATTR_LOCAL | XFS_ATTR_NAMESPACE_MASK | XFS_ATTR_INCOMPLETE;

const DA3_INFO_SIZE: usize = 56;
const DA3_INFO_CRC_OFFSET: usize = 12;
const ATTR_LEAF_HEADER_SIZE_V4: usize = 32;
const ATTR_LEAF_HEADER_SIZE_V5: usize = 80;
const ATTR_LEAF_ENTRY_SIZE: usize = 8;
const DA_NODE_HEADER_SIZE_V4: usize = 16;
const DA_NODE_HEADER_SIZE_V5: usize = 64;
const DA_NODE_ENTRY_SIZE: usize = 8;
const ATTR_RMT_HEADER_SIZE: usize = 56;
const ATTR_RMT_CRC_OFFSET: usize = 12;
const ATTR_NAME_ALIGN: usize = 4;
const XFS_XATTR_SIZE_MAX: usize = 1 << 16;
const MAX_DA_NODE_DEPTH: u16 = 5;
const MAX_ATTR_BLOCKS_PER_OPERATION: usize = 1 << 20;

const POSIX_ACL_XATTR_VERSION: u32 = 2;
const POSIX_ACL_HEADER_SIZE: usize = 4;
const POSIX_ACL_ENTRY_SIZE: usize = 8;

/// Linux POSIX ACL entry tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum AclEntryTag {
    UserObj = 0x01,
    User = 0x02,
    GroupObj = 0x04,
    Group = 0x08,
    Mask = 0x10,
    Other = 0x20,
}

impl AclEntryTag {
    fn from_raw(tag: u16) -> FsResult<Self> {
        match tag {
            0x01 => Ok(Self::UserObj),
            0x02 => Ok(Self::User),
            0x04 => Ok(Self::GroupObj),
            0x08 => Ok(Self::Group),
            0x10 => Ok(Self::Mask),
            0x20 => Ok(Self::Other),
            _ => Err(FsError::Corrupted),
        }
    }

    /// Whether this entry carries a UID or GID qualifier.
    pub const fn is_named(self) -> bool {
        matches!(self, Self::User | Self::Group)
    }
}

/// One validated entry from a Linux `posix_acl_xattr` value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AclEntry {
    pub tag: AclEntryTag,
    /// Permission bits (`0..=7`), before applying an ACL mask.
    pub perm: u8,
    /// UID/GID for named entries; `u32::MAX` is customary for base entries.
    pub id: u32,
}

/// Validated POSIX ACL xattr contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PosixAcl {
    entries: Vec<AclEntry>,
}

impl PosixAcl {
    /// Parse the little-endian Linux POSIX ACL xattr representation.
    ///
    /// The version, exact length, entry tags, permissions, required base
    /// entries, duplicate entries, and mask requirements are all checked.
    pub fn parse(bytes: &[u8]) -> FsResult<Self> {
        if bytes.len() < POSIX_ACL_HEADER_SIZE || bytes.len() > XFS_XATTR_SIZE_MAX {
            return Err(FsError::Corrupted);
        }
        let version = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if version != POSIX_ACL_XATTR_VERSION {
            return Err(FsError::UnsupportedVersion);
        }

        let payload_len = bytes.len() - POSIX_ACL_HEADER_SIZE;
        if !payload_len.is_multiple_of(POSIX_ACL_ENTRY_SIZE) {
            return Err(FsError::Corrupted);
        }
        let count = payload_len / POSIX_ACL_ENTRY_SIZE;
        if count > (XFS_XATTR_SIZE_MAX - POSIX_ACL_HEADER_SIZE) / POSIX_ACL_ENTRY_SIZE {
            return Err(FsError::Corrupted);
        }

        let mut entries = Vec::with_capacity(count);
        let mut seen_base = 0u8;
        let mut seen_mask = false;
        let mut seen_users = BTreeSet::new();
        let mut seen_groups = BTreeSet::new();
        let mut has_named = false;

        for raw in bytes[POSIX_ACL_HEADER_SIZE..]
            .as_chunks::<POSIX_ACL_ENTRY_SIZE>()
            .0
        {
            let tag = AclEntryTag::from_raw(u16::from_le_bytes([raw[0], raw[1]]))?;
            let perm_raw = u16::from_le_bytes([raw[2], raw[3]]);
            if perm_raw > 7 {
                return Err(FsError::Corrupted);
            }
            let id = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);

            let base_bit = match tag {
                AclEntryTag::UserObj => 1,
                AclEntryTag::GroupObj => 2,
                AclEntryTag::Other => 4,
                _ => 0,
            };
            if base_bit != 0 {
                if seen_base & base_bit != 0 {
                    return Err(FsError::Corrupted);
                }
                seen_base |= base_bit;
            }

            match tag {
                AclEntryTag::User => {
                    has_named = true;
                    if id == u32::MAX || !seen_users.insert(id) {
                        return Err(FsError::Corrupted);
                    }
                }
                AclEntryTag::Group => {
                    has_named = true;
                    if id == u32::MAX || !seen_groups.insert(id) {
                        return Err(FsError::Corrupted);
                    }
                }
                AclEntryTag::Mask => {
                    if seen_mask {
                        return Err(FsError::Corrupted);
                    }
                    seen_mask = true;
                }
                _ => {}
            }

            entries.push(AclEntry {
                tag,
                perm: perm_raw as u8,
                id,
            });
        }

        if seen_base != 0b111 || (has_named && !seen_mask) {
            return Err(FsError::Corrupted);
        }
        Ok(Self { entries })
    }

    /// Validated entries in their on-disk order.
    pub fn entries(&self) -> &[AclEntry] {
        &self.entries
    }
}

/// Which POSIX ACL xattr to retrieve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosixAclKind {
    Access,
    Default,
}

/// Filesystem geometry and identity used while reading an attribute fork.
pub struct AttrForkOptions<'a, R> {
    pub reader: &'a R,
    /// Complete filesystem block size, including metadata headers.
    pub block_size: usize,
    /// Checked filesystem size in bytes (`total_blocks * block_size`).
    pub filesystem_size: u64,
    pub is_v5: bool,
    /// Inode number that must own v5 attribute metadata and remote values.
    pub owner: u64,
    /// Filesystem UUID that must appear in v5 metadata headers.
    pub uuid: [u8; 16],
}

impl<R> AttrForkOptions<'_, R> {
    fn validate(&self) -> FsResult<()> {
        if !(512..=XFS_XATTR_SIZE_MAX).contains(&self.block_size)
            || !self.block_size.is_power_of_two()
        {
            return Err(FsError::Corrupted);
        }
        let block_size = u64::try_from(self.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        if self.filesystem_size < block_size {
            return Err(FsError::Corrupted);
        }
        if self.is_v5 && self.owner == 0 {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }
}

/// Read a raw POSIX ACL xattr from an inode's local or remote attribute fork.
///
/// `None` means that the requested attribute is absent. A malformed fork,
/// metadata block, or remote value is an error; callers must not silently fall
/// back to mode bits when an ACL exists but cannot be validated.
#[cfg(feature = "alloc")]
pub fn read_posix_acl<R: BlockReader>(
    inode: &Inode,
    raw_inode: &[u8],
    inode_size: usize,
    kind: PosixAclKind,
    options: &AttrForkOptions<'_, R>,
) -> FsResult<Option<Arc<[u8]>>> {
    options.validate()?;
    let Some(fork) = inode.core.attr_fork_bytes(raw_inode, inode_size)? else {
        return Ok(None);
    };

    if inode.core.version >= 3 {
        if inode.core.ino != 0 && inode.core.ino != options.owner {
            return Err(FsError::Corrupted);
        }
        if inode.core.uuid != options.uuid {
            return Err(FsError::Corrupted);
        }
    }
    if kind == PosixAclKind::Default && !inode.core.is_dir() {
        return Ok(None);
    }
    if inode.core.aformat == XFS_DINODE_FMT_EXTENTS && inode.core.attr_extent_count() == 0 {
        return Ok(None);
    }

    match inode.core.aformat {
        XFS_DINODE_FMT_LOCAL => read_shortform(fork, kind),
        XFS_DINODE_FMT_EXTENTS | XFS_DINODE_FMT_BTREE => {
            let extents = AttrExtentMap::parse(inode, fork, options)?;
            let mut found = None;
            let mut visited = BTreeSet::new();
            visit_da_block(&extents, options, 0, None, kind, &mut visited, &mut found)?;
            Ok(found)
        }
        _ => Err(FsError::Corrupted),
    }
}

fn is_acl_name(kind: PosixAclKind, flags: u8, name: &[u8]) -> bool {
    if flags & XFS_ATTR_ROOT == 0 || flags & (XFS_ATTR_SECURE | XFS_ATTR_PARENT) != 0 {
        return false;
    }
    match kind {
        PosixAclKind::Access => {
            name == b"SGI_ACL_FILE"
                || name == b"posix_acl_access"
                || name == b"system.posix_acl_access"
        }
        PosixAclKind::Default => {
            name == b"SGI_ACL_DEFAULT"
                || name == b"posix_acl_default"
                || name == b"system.posix_acl_default"
        }
    }
}

fn validate_attr_flags(flags: u8) -> FsResult<()> {
    if flags & !XFS_ATTR_KNOWN_FLAGS != 0 || (flags & XFS_ATTR_NAMESPACE_MASK).count_ones() > 1 {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

fn read_shortform(fork: &[u8], kind: PosixAclKind) -> FsResult<Option<Arc<[u8]>>> {
    const HEADER_SIZE: usize = 4;
    if fork.len() < HEADER_SIZE {
        return Err(FsError::BufferTooSmall);
    }
    let total_size = usize::from(u16::from_be_bytes([fork[0], fork[1]]));
    let count = usize::from(fork[2]);
    if fork[3] != 0 || total_size < HEADER_SIZE || total_size > fork.len() {
        return Err(FsError::Corrupted);
    }
    if count > (total_size - HEADER_SIZE) / 3 {
        return Err(FsError::Corrupted);
    }

    let mut offset = HEADER_SIZE;
    let mut found = None;
    for _ in 0..count {
        let fixed_end = offset.checked_add(3).ok_or(FsError::ArithmeticOverflow)?;
        if fixed_end > total_size {
            return Err(FsError::Corrupted);
        }
        let name_len = usize::from(fork[offset]);
        let value_len = usize::from(fork[offset + 1]);
        let flags = fork[offset + 2];
        validate_attr_flags(flags)?;
        if flags & (XFS_ATTR_LOCAL | XFS_ATTR_INCOMPLETE) != 0 || name_len == 0 {
            return Err(FsError::Corrupted);
        }
        let name_end = fixed_end
            .checked_add(name_len)
            .ok_or(FsError::ArithmeticOverflow)?;
        let entry_end = name_end
            .checked_add(value_len)
            .ok_or(FsError::ArithmeticOverflow)?;
        if entry_end > total_size {
            return Err(FsError::Corrupted);
        }
        let name = &fork[fixed_end..name_end];
        if name.contains(&0) {
            return Err(FsError::Corrupted);
        }
        if is_acl_name(kind, flags, name) {
            if found.is_some() {
                return Err(FsError::Corrupted);
            }
            found = Some(Arc::from(&fork[name_end..entry_end]));
        }
        offset = entry_end;
    }
    if offset != total_size {
        return Err(FsError::Corrupted);
    }
    Ok(found)
}

enum AttrExtentMap {
    Inline(Vec<Extent>),
    Btree(BmbtRoot),
}

impl AttrExtentMap {
    fn parse<R>(inode: &Inode, fork: &[u8], options: &AttrForkOptions<'_, R>) -> FsResult<Self> {
        let count = inode.core.attr_extent_count();
        let filesystem_blocks = options.filesystem_size
            / u64::try_from(options.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        if count > filesystem_blocks {
            return Err(FsError::Corrupted);
        }

        match inode.core.aformat {
            XFS_DINODE_FMT_EXTENTS => {
                if count > (fork.len() / Extent::SIZE) as u64 {
                    return Err(FsError::Corrupted);
                }
                let count = usize::try_from(count).map_err(|_| FsError::ArithmeticOverflow)?;
                let mut extents = Vec::with_capacity(count);
                let mut previous_end = None;
                for index in 0..count {
                    let offset = index
                        .checked_mul(Extent::SIZE)
                        .ok_or(FsError::ArithmeticOverflow)?;
                    let extent = Extent::parse(fork.get(offset..).ok_or(FsError::BufferTooSmall)?)?;
                    Self::validate_extent(extent, options)?;
                    if previous_end.is_some_and(|end| extent.file_offset < end) {
                        return Err(FsError::Corrupted);
                    }
                    previous_end = Some(extent.file_end()?);
                    extents.push(extent);
                }
                Ok(Self::Inline(extents))
            }
            XFS_DINODE_FMT_BTREE => {
                if fork.len() < BmbtRoot::HEADER_SIZE {
                    return Err(FsError::BufferTooSmall);
                }
                let level = fork.read_be_u16(0)?;
                let num_recs = fork.read_be_u16(2)?;
                let root = BmbtRoot::parse(&fork[BmbtRoot::HEADER_SIZE..], level, num_recs)?;
                Ok(Self::Btree(root))
            }
            _ => Err(FsError::Corrupted),
        }
    }

    fn validate_extent<R>(extent: Extent, options: &AttrForkOptions<'_, R>) -> FsResult<()> {
        if extent.block_count == 0 || extent.start_block == 0 || extent.is_unwritten {
            return Err(FsError::Corrupted);
        }
        let disk_end = extent.disk_end()?;
        let block_size =
            u64::try_from(options.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        let byte_end = disk_end
            .checked_mul(block_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        if byte_end > options.filesystem_size {
            return Err(FsError::Corrupted);
        }
        Ok(())
    }

    fn physical_block<R>(
        &self,
        logical_block: u64,
        options: &AttrForkOptions<'_, R>,
    ) -> FsResult<u64>
    where
        R: BlockReader,
    {
        let extent = match self {
            Self::Inline(extents) => extents
                .iter()
                .find(|extent| extent.contains_file_block(logical_block))
                .copied(),
            Self::Btree(root) => crate::btree::btree_lookup_extent_checked(
                root,
                logical_block,
                options.reader,
                options.is_v5,
                options.owner,
                Some(options.uuid),
                options.block_size,
            )?,
        };
        let extent = extent.ok_or(FsError::Corrupted)?;
        Self::validate_extent(extent, options)?;
        extent.translate(logical_block)
    }

    fn read_physical_block<R: BlockReader>(
        physical_block: u64,
        options: &AttrForkOptions<'_, R>,
    ) -> FsResult<Vec<u8>> {
        let block_size =
            u64::try_from(options.block_size).map_err(|_| FsError::ArithmeticOverflow)?;
        let byte_offset = physical_block
            .checked_mul(block_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        let byte_end = byte_offset
            .checked_add(block_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        if byte_end > options.filesystem_size {
            return Err(FsError::Corrupted);
        }
        let block = options.reader.read_block(physical_block)?;
        if block.len() != options.block_size {
            return Err(FsError::Corrupted);
        }
        Ok(block)
    }
}

#[derive(Debug)]
enum DaHeader {
    Leaf {
        count: u16,
        used_bytes: u16,
        first_used: usize,
        entries_offset: usize,
        freemap_offset: usize,
    },
    Node {
        level: u16,
        count: u16,
        entries_offset: usize,
    },
}

fn verify_da3_metadata<R>(
    raw: &[u8],
    physical_block: u64,
    options: &AttrForkOptions<'_, R>,
) -> FsResult<()> {
    if raw.len() < DA3_INFO_SIZE {
        return Err(FsError::BufferTooSmall);
    }
    let stored_crc = raw.read_le_u32(DA3_INFO_CRC_OFFSET)?;
    crc::verify_crc32c_field(raw, DA3_INFO_CRC_OFFSET, stored_crc, true)?;
    let block_no = raw.read_be_u64(16)?;
    let expected_block_no = address::fs_block_to_daddr(physical_block, options.block_size)?;
    if block_no != expected_block_no
        || raw[32..48] != options.uuid
        || raw.read_be_u64(48)? != options.owner
    {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

fn parse_da_header<R>(
    raw: &[u8],
    physical_block: u64,
    options: &AttrForkOptions<'_, R>,
) -> FsResult<DaHeader> {
    if raw.len() < 12 {
        return Err(FsError::BufferTooSmall);
    }
    let magic = raw.read_be_u16(8)?;
    let is_v5_magic = matches!(magic, XFS_ATTR3_LEAF_MAGIC | XFS_DA3_NODE_MAGIC);
    if is_v5_magic != options.is_v5 {
        return Err(FsError::InvalidMagic);
    }
    if options.is_v5 {
        verify_da3_metadata(raw, physical_block, options)?;
    }

    match magic {
        XFS_ATTR_LEAF_MAGIC | XFS_ATTR3_LEAF_MAGIC => {
            let header_size = if options.is_v5 {
                ATTR_LEAF_HEADER_SIZE_V5
            } else {
                ATTR_LEAF_HEADER_SIZE_V4
            };
            if raw.len() < header_size {
                return Err(FsError::BufferTooSmall);
            }
            let count_offset = if options.is_v5 { 56 } else { 12 };
            let count = raw.read_be_u16(count_offset)?;
            let used_bytes = raw.read_be_u16(count_offset + 2)?;
            let first_used_raw = raw.read_be_u16(count_offset + 4)?;
            let first_used = if first_used_raw == 0 {
                if options.is_v5
                    && options.block_size > u16::MAX as usize
                    && count == 0
                    && used_bytes == 0
                {
                    options.block_size
                } else {
                    return Err(FsError::Corrupted);
                }
            } else {
                usize::from(first_used_raw)
            };
            let entries_offset = header_size;
            let freemap_offset = count_offset + 8;
            Ok(DaHeader::Leaf {
                count,
                used_bytes,
                first_used,
                entries_offset,
                freemap_offset,
            })
        }
        XFS_DA_NODE_MAGIC | XFS_DA3_NODE_MAGIC => {
            let header_size = if options.is_v5 {
                DA_NODE_HEADER_SIZE_V5
            } else {
                DA_NODE_HEADER_SIZE_V4
            };
            if raw.len() < header_size {
                return Err(FsError::BufferTooSmall);
            }
            let count_offset = if options.is_v5 { 56 } else { 12 };
            let count = raw.read_be_u16(count_offset)?;
            let level = raw.read_be_u16(count_offset + 2)?;
            Ok(DaHeader::Node {
                level,
                count,
                entries_offset: header_size,
            })
        }
        _ => Err(FsError::InvalidMagic),
    }
}

#[allow(clippy::too_many_arguments)]
fn visit_da_block<R: BlockReader>(
    extents: &AttrExtentMap,
    options: &AttrForkOptions<'_, R>,
    logical_block: u64,
    expected_level: Option<u16>,
    kind: PosixAclKind,
    visited: &mut BTreeSet<u64>,
    found: &mut Option<Arc<[u8]>>,
) -> FsResult<()> {
    if !visited.insert(logical_block) || visited.len() > MAX_ATTR_BLOCKS_PER_OPERATION {
        return Err(FsError::Corrupted);
    }
    let physical_block = extents.physical_block(logical_block, options)?;
    let raw = AttrExtentMap::read_physical_block(physical_block, options)?;
    match parse_da_header(&raw, physical_block, options)? {
        DaHeader::Leaf {
            count,
            used_bytes,
            first_used,
            entries_offset,
            freemap_offset,
        } => {
            if expected_level.is_some_and(|level| level != 0) {
                return Err(FsError::Corrupted);
            }
            scan_leaf(
                &raw,
                count,
                used_bytes,
                first_used,
                entries_offset,
                freemap_offset,
                extents,
                options,
                kind,
                found,
            )?;
        }
        DaHeader::Node {
            level,
            count,
            entries_offset,
        } => {
            if level == 0
                || level > MAX_DA_NODE_DEPTH
                || expected_level.is_some_and(|expected| expected != level)
            {
                return Err(FsError::Corrupted);
            }
            let count = usize::from(count);
            if count == 0 || count > (raw.len() - entries_offset) / DA_NODE_ENTRY_SIZE {
                return Err(FsError::Corrupted);
            }
            let mut previous_hash = None;
            for index in 0..count {
                let offset = entries_offset
                    .checked_add(index * DA_NODE_ENTRY_SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?;
                let hash = raw.read_be_u32(offset)?;
                if previous_hash.is_some_and(|previous| hash < previous) {
                    return Err(FsError::Corrupted);
                }
                previous_hash = Some(hash);
                let child = u64::from(raw.read_be_u32(offset + 4)?);
                if child == 0 {
                    return Err(FsError::Corrupted);
                }
                visit_da_block(
                    extents,
                    options,
                    child,
                    Some(level - 1),
                    kind,
                    visited,
                    found,
                )?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn scan_leaf<R: BlockReader>(
    raw: &[u8],
    count: u16,
    used_bytes: u16,
    first_used: usize,
    entries_offset: usize,
    freemap_offset: usize,
    extents: &AttrExtentMap,
    options: &AttrForkOptions<'_, R>,
    kind: PosixAclKind,
    found: &mut Option<Arc<[u8]>>,
) -> FsResult<()> {
    let count = usize::from(count);
    let entries_end = entries_offset
        .checked_add(count * ATTR_LEAF_ENTRY_SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;
    if first_used > raw.len() || entries_end > first_used || freemap_offset + 12 > raw.len() {
        return Err(FsError::Corrupted);
    }

    let mut free_regions = [(0usize, 0usize); 3];
    for (index, region) in free_regions.iter_mut().enumerate() {
        let offset = freemap_offset + index * 4;
        let base = usize::from(raw.read_be_u16(offset)?);
        let size = usize::from(raw.read_be_u16(offset + 2)?);
        if base > raw.len()
            || size > raw.len()
            || base % ATTR_NAME_ALIGN != 0
            || size % ATTR_NAME_ALIGN != 0
        {
            return Err(FsError::Corrupted);
        }
        let end = base.checked_add(size).ok_or(FsError::ArithmeticOverflow)?;
        if end > raw.len() || (size != 0 && base < entries_end) {
            return Err(FsError::Corrupted);
        }
        *region = (base, end);
    }
    for (index, (base, end)) in free_regions.iter().enumerate() {
        for (other_base, other_end) in &free_regions[index + 1..] {
            if *end > *base && *other_end > *other_base && *base < *other_end && *other_base < *end
            {
                return Err(FsError::Corrupted);
            }
        }
    }

    let mut computed_used = 0usize;
    let mut previous_hash = None;
    for index in 0..count {
        let entry_offset = entries_offset
            .checked_add(index * ATTR_LEAF_ENTRY_SIZE)
            .ok_or(FsError::ArithmeticOverflow)?;
        let hash = raw.read_be_u32(entry_offset)?;
        if previous_hash.is_some_and(|previous| hash < previous) {
            return Err(FsError::Corrupted);
        }
        previous_hash = Some(hash);
        let name_index = usize::from(raw.read_be_u16(entry_offset + 4)?);
        let flags = raw[entry_offset + 6];
        validate_attr_flags(flags)?;
        if name_index < first_used
            || name_index >= raw.len()
            || name_index < entries_end
            || name_index % ATTR_NAME_ALIGN != 0
        {
            return Err(FsError::Corrupted);
        }

        let (name, value, remote): (&[u8], &[u8], Option<(u64, usize)>) =
            if flags & XFS_ATTR_LOCAL != 0 {
                if name_index + 3 > raw.len() {
                    return Err(FsError::BufferTooSmall);
                }
                let value_len = usize::from(raw.read_be_u16(name_index)?);
                let name_len = usize::from(raw[name_index + 2]);
                if name_len == 0 {
                    return Err(FsError::Corrupted);
                }
                let name_start = name_index + 3;
                let name_end = name_start
                    .checked_add(name_len)
                    .ok_or(FsError::ArithmeticOverflow)?;
                let value_start = name_end;
                let value_end = value_start
                    .checked_add(value_len)
                    .ok_or(FsError::ArithmeticOverflow)?;
                let entry_size = round_up(3 + name_len + value_len, ATTR_NAME_ALIGN)?;
                let padded_end = name_index
                    .checked_add(entry_size)
                    .ok_or(FsError::ArithmeticOverflow)?;
                if value_end > raw.len() || padded_end > raw.len() {
                    return Err(FsError::Corrupted);
                }
                computed_used = computed_used
                    .checked_add(entry_size)
                    .ok_or(FsError::ArithmeticOverflow)?;
                (
                    &raw[name_start..name_end],
                    &raw[value_start..value_end],
                    None,
                )
            } else {
                if name_index + 9 > raw.len() {
                    return Err(FsError::BufferTooSmall);
                }
                let value_block = u64::from(raw.read_be_u32(name_index)?);
                let value_len = raw.read_be_u32(name_index + 4)? as usize;
                let name_len = usize::from(raw[name_index + 8]);
                if name_len == 0 || value_len > XFS_XATTR_SIZE_MAX {
                    return Err(FsError::Corrupted);
                }
                if flags & XFS_ATTR_INCOMPLETE == 0 && value_block == 0 {
                    return Err(FsError::Corrupted);
                }
                let name_start = name_index + 9;
                let name_end = name_start
                    .checked_add(name_len)
                    .ok_or(FsError::ArithmeticOverflow)?;
                let entry_size = round_up(11 + name_len, ATTR_NAME_ALIGN)?;
                let padded_end = name_index
                    .checked_add(entry_size)
                    .ok_or(FsError::ArithmeticOverflow)?;
                if name_end > raw.len() || padded_end > raw.len() {
                    return Err(FsError::Corrupted);
                }
                computed_used = computed_used
                    .checked_add(entry_size)
                    .ok_or(FsError::ArithmeticOverflow)?;
                (
                    &raw[name_start..name_end],
                    &[],
                    Some((value_block, value_len)),
                )
            };

        if name.contains(&0) || flags & XFS_ATTR_INCOMPLETE != 0 {
            continue;
        }
        if !is_acl_name(kind, flags, name) {
            continue;
        }
        if found.is_some() {
            return Err(FsError::Corrupted);
        }
        *found = Some(match remote {
            Some((value_block, value_len)) => {
                read_remote_value(extents, options, value_block, value_len)?
            }
            None => Arc::from(value),
        });
    }

    if computed_used != usize::from(used_bytes)
        || computed_used > raw.len().saturating_sub(first_used)
    {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

fn read_remote_value<R: BlockReader>(
    extents: &AttrExtentMap,
    options: &AttrForkOptions<'_, R>,
    value_block: u64,
    value_len: usize,
) -> FsResult<Arc<[u8]>> {
    if value_len == 0 || value_len > XFS_XATTR_SIZE_MAX {
        return Err(FsError::Corrupted);
    }
    let payload_size = if options.is_v5 {
        options
            .block_size
            .checked_sub(ATTR_RMT_HEADER_SIZE)
            .ok_or(FsError::Corrupted)?
    } else {
        options.block_size
    };
    if payload_size == 0 {
        return Err(FsError::Corrupted);
    }
    let block_count = value_len
        .checked_add(payload_size - 1)
        .ok_or(FsError::ArithmeticOverflow)?
        / payload_size;
    let mut value = Vec::with_capacity(value_len);
    let mut value_offset = 0usize;

    for index in 0..block_count {
        let logical_block = value_block
            .checked_add(index as u64)
            .ok_or(FsError::ArithmeticOverflow)?;
        let physical_block = extents.physical_block(logical_block, options)?;
        let raw = AttrExtentMap::read_physical_block(physical_block, options)?;
        let expected_chunk = payload_size.min(value_len - value_offset);
        let data = if options.is_v5 {
            if raw.read_be_u32(0)? != XFS_ATTR3_RMT_MAGIC {
                return Err(FsError::InvalidMagic);
            }
            let chunk_offset =
                u32::try_from(value_offset).map_err(|_| FsError::ArithmeticOverflow)?;
            let chunk_len =
                u32::try_from(expected_chunk).map_err(|_| FsError::ArithmeticOverflow)?;
            if raw.read_be_u32(4)? != chunk_offset
                || raw.read_be_u32(8)? != chunk_len
                || raw[16..32] != options.uuid
                || raw.read_be_u64(32)? != options.owner
                || raw.read_be_u64(40)?
                    != address::fs_block_to_daddr(physical_block, options.block_size)?
                || raw.read_be_u64(48)? != u64::MAX
            {
                return Err(FsError::Corrupted);
            }
            let stored_crc = raw.read_le_u32(ATTR_RMT_CRC_OFFSET)?;
            crc::verify_crc32c_field(&raw, ATTR_RMT_CRC_OFFSET, stored_crc, true)?;
            &raw[ATTR_RMT_HEADER_SIZE..ATTR_RMT_HEADER_SIZE + expected_chunk]
        } else {
            &raw[..expected_chunk]
        };
        value.extend_from_slice(data);
        value_offset = value_offset
            .checked_add(expected_chunk)
            .ok_or(FsError::ArithmeticOverflow)?;
    }
    if value_offset != value_len {
        return Err(FsError::Corrupted);
    }
    Ok(value.into())
}

fn round_up(value: usize, alignment: usize) -> FsResult<usize> {
    let rem = value % alignment;
    if rem == 0 {
        Ok(value)
    } else {
        value
            .checked_add(alignment - rem)
            .ok_or(FsError::ArithmeticOverflow)
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, vec, vec::Vec};

    use super::*;
    use crate::inode::InodeCore;

    // Small helpers keep the on-disk fixtures explicit and independent of any
    // writer implementation.
    fn acl_bytes(entries: &[(AclEntryTag, u8, u32)]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + entries.len() * 8);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        for &(tag, perm, id) in entries {
            bytes.extend_from_slice(&(tag as u16).to_le_bytes());
            bytes.extend_from_slice(&(perm as u16).to_le_bytes());
            bytes.extend_from_slice(&id.to_le_bytes());
        }
        bytes
    }

    fn minimal_acl() -> Vec<u8> {
        acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::GroupObj, 4, u32::MAX),
            (AclEntryTag::Other, 4, u32::MAX),
        ])
    }

    fn shortform(name: &[u8], value: &[u8]) -> Vec<u8> {
        let total = 4 + 3 + name.len() + value.len();
        let mut fork = Vec::with_capacity(total);
        fork.extend_from_slice(&(total as u16).to_be_bytes());
        fork.push(1);
        fork.push(0);
        fork.push(name.len() as u8);
        fork.push(value.len() as u8);
        fork.push(XFS_ATTR_ROOT);
        fork.extend_from_slice(name);
        fork.extend_from_slice(value);
        fork
    }

    fn inode_with_fork(version: u8, aformat: u8, fork: &[u8]) -> (Vec<u8>, Inode) {
        let inode_size = 512;
        let forkoff = 4;
        let mut raw = vec![0u8; inode_size];
        raw[0..2].copy_from_slice(&XFS_DINODE_MAGIC.to_be_bytes());
        raw[2..4].copy_from_slice(&0o100644u16.to_be_bytes());
        raw[4] = version;
        raw[5] = XFS_DINODE_FMT_EXTENTS;
        raw[0x52] = forkoff;
        raw[0x53] = aformat;
        if aformat == XFS_DINODE_FMT_EXTENTS || aformat == XFS_DINODE_FMT_BTREE {
            raw[0x50..0x52].copy_from_slice(&1u16.to_be_bytes());
        }
        let data_fork_offset = if version == 3 {
            InodeCore::V3_SIZE
        } else {
            InodeCore::V2_SIZE
        };
        let attr_offset = data_fork_offset + forkoff as usize * 8;
        raw[attr_offset..attr_offset + fork.len()].copy_from_slice(fork);
        if version == 3 {
            raw[0x98..0xA0].copy_from_slice(&42u64.to_be_bytes());
            raw[0xA0..0xB0].copy_from_slice(&TEST_UUID);
            crate::crc::recalculate_crc_le(&mut raw, 0x64).unwrap();
        }
        let inode = Inode::parse_with_features(&raw, inode_size, 0).unwrap();
        (raw, inode)
    }

    const TEST_UUID: [u8; 16] = [7; 16];

    struct TestReader {
        blocks: BTreeMap<u64, Vec<u8>>,
    }

    impl BlockReader for TestReader {
        fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
            self.blocks
                .get(&block_num)
                .cloned()
                .ok_or(FsError::NotFound)
        }
    }

    fn options(reader: &TestReader, is_v5: bool) -> AttrForkOptions<'_, TestReader> {
        AttrForkOptions {
            reader,
            block_size: 4096,
            filesystem_size: 4096 * 1024,
            is_v5,
            owner: 42,
            uuid: TEST_UUID,
        }
    }

    fn extent(file_offset: u64, start_block: u64, block_count: u32) -> Extent {
        Extent {
            file_offset,
            start_block,
            block_count,
            is_unwritten: false,
        }
    }

    fn leaf_block(
        is_v5: bool,
        physical_block: u64,
        local: bool,
        name: &[u8],
        value: &[u8],
    ) -> Vec<u8> {
        let mut raw = vec![0u8; 4096];
        let header_size = if is_v5 { 80 } else { 32 };
        let magic = if is_v5 {
            XFS_ATTR3_LEAF_MAGIC
        } else {
            XFS_ATTR_LEAF_MAGIC
        };
        raw[8..10].copy_from_slice(&magic.to_be_bytes());
        let count_offset = if is_v5 { 56 } else { 12 };
        raw[count_offset..count_offset + 2].copy_from_slice(&1u16.to_be_bytes());

        let name_index = if local {
            let size = round_up(3 + name.len() + value.len(), 4).unwrap();
            let name_index = 4096 - size;
            raw[name_index..name_index + 2].copy_from_slice(&(value.len() as u16).to_be_bytes());
            raw[name_index + 2] = name.len() as u8;
            raw[name_index + 3..name_index + 3 + name.len()].copy_from_slice(name);
            raw[name_index + 3 + name.len()..name_index + 3 + name.len() + value.len()]
                .copy_from_slice(value);
            raw[count_offset + 2..count_offset + 4].copy_from_slice(&(size as u16).to_be_bytes());
            raw[count_offset + 4..count_offset + 6]
                .copy_from_slice(&(name_index as u16).to_be_bytes());
            name_index
        } else {
            let size = round_up(11 + name.len(), 4).unwrap();
            let name_index = 4096 - size;
            raw[name_index..name_index + 4].copy_from_slice(&1u32.to_be_bytes());
            raw[name_index + 4..name_index + 8]
                .copy_from_slice(&(value.len() as u32).to_be_bytes());
            raw[name_index + 8] = name.len() as u8;
            raw[name_index + 9..name_index + 9 + name.len()].copy_from_slice(name);
            raw[count_offset + 2..count_offset + 4].copy_from_slice(&(size as u16).to_be_bytes());
            raw[count_offset + 4..count_offset + 6]
                .copy_from_slice(&(name_index as u16).to_be_bytes());
            name_index
        };
        raw[header_size + 4..header_size + 6].copy_from_slice(&(name_index as u16).to_be_bytes());
        raw[header_size + 6] = XFS_ATTR_ROOT | if local { XFS_ATTR_LOCAL } else { 0 };
        let free_offset = count_offset + 8;
        raw[free_offset..free_offset + 2]
            .copy_from_slice(&((header_size + 8) as u16).to_be_bytes());
        raw[free_offset + 2..free_offset + 4]
            .copy_from_slice(&((name_index - header_size - 8) as u16).to_be_bytes());

        if is_v5 {
            raw[16..24].copy_from_slice(&(physical_block * 8).to_be_bytes());
            raw[32..48].copy_from_slice(&TEST_UUID);
            raw[48..56].copy_from_slice(&42u64.to_be_bytes());
            crate::crc::recalculate_crc_le(&mut raw, 12).unwrap();
        }
        raw
    }

    fn remote_block(value: &[u8], physical_block: u64, offset: usize, is_v5: bool) -> Vec<u8> {
        let mut raw = vec![0u8; 4096];
        if is_v5 {
            raw[0..4].copy_from_slice(&XFS_ATTR3_RMT_MAGIC.to_be_bytes());
            raw[4..8].copy_from_slice(&(offset as u32).to_be_bytes());
            raw[8..12].copy_from_slice(&(value.len() as u32).to_be_bytes());
            raw[16..32].copy_from_slice(&TEST_UUID);
            raw[32..40].copy_from_slice(&42u64.to_be_bytes());
            raw[40..48].copy_from_slice(&(physical_block * 8).to_be_bytes());
            raw[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
            raw[56..56 + value.len()].copy_from_slice(value);
            crate::crc::recalculate_crc_le(&mut raw, 12).unwrap();
        } else {
            raw[..value.len()].copy_from_slice(value);
        }
        raw
    }

    #[test]
    fn posix_acl_parser_accepts_minimal_and_masked_entries() {
        let acl = PosixAcl::parse(&minimal_acl()).unwrap();
        assert_eq!(acl.entries().len(), 3);

        let raw = acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::User, 7, 1000),
            (AclEntryTag::GroupObj, 7, u32::MAX),
            (AclEntryTag::Group, 5, 2000),
            (AclEntryTag::Mask, 4, u32::MAX),
            (AclEntryTag::Other, 1, u32::MAX),
        ]);
        let acl = PosixAcl::parse(&raw).unwrap();
        assert_eq!(acl.entries()[1].id, 1000);
        assert_eq!(acl.entries()[4].tag, AclEntryTag::Mask);
    }

    #[test]
    fn posix_acl_parser_rejects_malformed_values() {
        let mut raw = minimal_acl();
        raw[0] = 3;
        assert!(matches!(
            PosixAcl::parse(&raw),
            Err(FsError::UnsupportedVersion)
        ));

        let mut raw = minimal_acl();
        raw[6..8].copy_from_slice(&8u16.to_le_bytes());
        assert!(matches!(PosixAcl::parse(&raw), Err(FsError::Corrupted)));

        let mut raw = minimal_acl();
        raw.truncate(27);
        assert!(matches!(PosixAcl::parse(&raw), Err(FsError::Corrupted)));

        let raw = acl_bytes(&[
            (AclEntryTag::UserObj, 6, u32::MAX),
            (AclEntryTag::User, 4, 1000),
            (AclEntryTag::GroupObj, 4, u32::MAX),
            (AclEntryTag::Other, 4, u32::MAX),
        ]);
        assert!(matches!(PosixAcl::parse(&raw), Err(FsError::Corrupted)));
    }

    #[test]
    fn reads_local_acl_from_shortform_fork() {
        let acl = minimal_acl();
        let fork = shortform(b"SGI_ACL_FILE", &acl);
        let (raw, inode) = inode_with_fork(3, XFS_DINODE_FMT_LOCAL, &fork);
        let reader = TestReader {
            blocks: BTreeMap::new(),
        };
        let found = read_posix_acl(
            &inode,
            &raw,
            raw.len(),
            PosixAclKind::Access,
            &options(&reader, true),
        )
        .unwrap()
        .unwrap();
        assert_eq!(&*found, acl.as_slice());
    }

    #[test]
    fn reads_local_acl_from_v4_leaf() {
        let acl = minimal_acl();
        let leaf = leaf_block(false, 100, true, b"SGI_ACL_FILE", acl.as_slice());
        let reader = TestReader {
            blocks: BTreeMap::from([(100, leaf)]),
        };
        let fork = extent(0, 100, 1).to_bytes();
        let (raw, inode) = inode_with_fork(2, XFS_DINODE_FMT_EXTENTS, &fork);
        let found = read_posix_acl(
            &inode,
            &raw,
            raw.len(),
            PosixAclKind::Access,
            &options(&reader, false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(&*found, acl.as_slice());
    }

    #[test]
    fn reads_remote_acl_from_v4_value_blocks() {
        let acl = minimal_acl();
        let leaf = leaf_block(false, 100, false, b"SGI_ACL_FILE", &acl);
        let value = remote_block(&acl, 101, 0, false);
        let reader = TestReader {
            blocks: BTreeMap::from([(100, leaf), (101, value)]),
        };
        let fork = extent(0, 100, 2).to_bytes();
        let (raw, inode) = inode_with_fork(2, XFS_DINODE_FMT_EXTENTS, &fork);
        let found = read_posix_acl(
            &inode,
            &raw,
            raw.len(),
            PosixAclKind::Access,
            &options(&reader, false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(&*found, acl.as_slice());
    }

    #[test]
    fn reads_remote_acl_and_checks_v5_crc_location_and_owner() {
        let acl = minimal_acl();
        let leaf = leaf_block(true, 100, false, b"SGI_ACL_FILE", &acl);
        let value = remote_block(&acl, 101, 0, true);
        let reader = TestReader {
            blocks: BTreeMap::from([(100, leaf.clone()), (101, value.clone())]),
        };
        let fork = extent(0, 100, 2).to_bytes();
        let (raw, inode) = inode_with_fork(3, XFS_DINODE_FMT_EXTENTS, &fork);
        let opts = options(&reader, true);
        let found = read_posix_acl(&inode, &raw, raw.len(), PosixAclKind::Access, &opts)
            .unwrap()
            .unwrap();
        assert_eq!(&*found, acl.as_slice());

        let mut corrupted = value;
        corrupted[56] ^= 1;
        let reader = TestReader {
            blocks: BTreeMap::from([(100, leaf), (101, corrupted)]),
        };
        let opts = options(&reader, true);
        assert!(matches!(
            read_posix_acl(&inode, &raw, raw.len(), PosixAclKind::Access, &opts),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn reads_acl_through_da_node_and_attribute_bmbt() {
        let acl = minimal_acl();
        let leaf = leaf_block(false, 101, true, b"SGI_ACL_FILE", acl.as_slice());
        let mut node = vec![0u8; 4096];
        node[8..10].copy_from_slice(&XFS_DA_NODE_MAGIC.to_be_bytes());
        node[12..14].copy_from_slice(&1u16.to_be_bytes());
        node[14..16].copy_from_slice(&1u16.to_be_bytes());
        node[20..24].copy_from_slice(&1u32.to_be_bytes()); // child logical
                                                           // block 1

        let mut bmbt = vec![0u8; 4096];
        bmbt[0..4].copy_from_slice(&XFS_BMAP_MAGIC.to_be_bytes());
        bmbt[6..8].copy_from_slice(&1u16.to_be_bytes());
        bmbt[24..40].copy_from_slice(&extent(0, 100, 2).to_bytes());

        let reader = TestReader {
            blocks: BTreeMap::from([(100, node), (101, leaf), (200, bmbt)]),
        };
        let attr_offset = InodeCore::V2_SIZE + 4 * 8;
        let fork_len = 512 - attr_offset;
        let max_recs = (fork_len - 4) / 16;
        let ptr_offset = 4 + max_recs * 8;
        let mut fork = vec![0u8; fork_len];
        fork[0..2].copy_from_slice(&1u16.to_be_bytes()); // BMBT root level
        fork[2..4].copy_from_slice(&1u16.to_be_bytes()); // one root key/pointer
        fork[ptr_offset..ptr_offset + 8].copy_from_slice(&200u64.to_be_bytes());
        let (raw, inode) = inode_with_fork(2, XFS_DINODE_FMT_BTREE, &fork);
        let found = read_posix_acl(
            &inode,
            &raw,
            raw.len(),
            PosixAclKind::Access,
            &options(&reader, false),
        )
        .unwrap()
        .unwrap();
        assert_eq!(&*found, acl.as_slice());
    }

    #[test]
    fn remote_v5_values_validate_each_chunk_offset() {
        let value = vec![0x5A; 5000];
        let leaf = leaf_block(true, 100, false, b"SGI_ACL_FILE", &value);
        let first = remote_block(&value[..4040], 101, 0, true);
        let second = remote_block(&value[4040..], 102, 4040, true);
        let reader = TestReader {
            blocks: BTreeMap::from([(100, leaf), (101, first), (102, second)]),
        };
        let fork = extent(0, 100, 3).to_bytes();
        let (raw, inode) = inode_with_fork(3, XFS_DINODE_FMT_EXTENTS, &fork);
        let found = read_posix_acl(
            &inode,
            &raw,
            raw.len(),
            PosixAclKind::Access,
            &options(&reader, true),
        )
        .unwrap()
        .unwrap();
        assert_eq!(&*found, value.as_slice());
    }

    #[test]
    fn rejects_shortform_overrun_and_wrong_v5_location() {
        let mut fork = shortform(b"SGI_ACL_FILE", &minimal_acl());
        fork[0..2].copy_from_slice(&u16::MAX.to_be_bytes());
        let (raw, inode) = inode_with_fork(3, XFS_DINODE_FMT_LOCAL, &fork);
        let reader = TestReader {
            blocks: BTreeMap::new(),
        };
        assert!(matches!(
            read_posix_acl(
                &inode,
                &raw,
                raw.len(),
                PosixAclKind::Access,
                &options(&reader, true),
            ),
            Err(FsError::Corrupted)
        ));

        let acl = minimal_acl();
        let mut leaf = leaf_block(true, 100, true, b"SGI_ACL_FILE", acl.as_slice());
        leaf[16..24].copy_from_slice(&0u64.to_be_bytes());
        crate::crc::recalculate_crc_le(&mut leaf, 12).unwrap();
        let reader = TestReader {
            blocks: BTreeMap::from([(100, leaf)]),
        };
        let fork = extent(0, 100, 1).to_bytes();
        let (raw, inode) = inode_with_fork(3, XFS_DINODE_FMT_EXTENTS, &fork);
        assert!(matches!(
            read_posix_acl(
                &inode,
                &raw,
                raw.len(),
                PosixAclKind::Access,
                &options(&reader, true),
            ),
            Err(FsError::Corrupted)
        ));
    }
}
