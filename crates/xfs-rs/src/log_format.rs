//! XFS v5 internal-log v2 record encoding and parsing.
//!
//! The layouts in this module follow Linux's
//! `fs/xfs/libxfs/xfs_log_format.h`, `xlog_cil.c`, and `xfs_buf_item.c`.
//! Record framing is big-endian, except for the little-endian record CRC.
//! Transaction and buffer-item structures are native-endian, as selected by
//! `h_fmt`.
//!
//! The encoder emits one complete checkpoint transaction in one physical log
//! record. Each [`LogBufferItem`] is represented by an
//! `xfs_buf_log_format` operation followed by operations containing its dirty
//! runs. Each [`LogInodeItem`] carries the native-endian inode core and
//! optional data-fork region. The decoder accepts partial-buffer dirty bitmaps
//! and reconstructs full buffer images.
//!
//! Only the single-block v2 record header is implemented. Consequently,
//! `log_size_bytes` (the on-disk `h_size`, more precisely the in-core log
//! buffer size) must be at most 32 KiB. Records requiring extended headers,
//! transactions continued across records, and log stripe-unit rounding are
//! rejected rather than encoded incorrectly.
//!
//! Physical payload length is padded to a 512-byte basic block (and therefore
//! to eight bytes), while full buffer data is a multiple of 128 bytes.
//! Individual operation payload lengths follow Linux's four-byte iovec
//! alignment; adding eight-byte padding inside `xfs_buf_log_format` would not
//! match the kernel's on-disk layout.

extern crate alloc;

use alloc::{vec, vec::Vec};

use fs_abstraction::{FsError, FsResult};

use crate::crc::{xfs_crc32c, xfs_crc32c_with_zeroed_field};

/// `XLOG_HEADER_MAGIC_NUM`.
pub const XLOG_HEADER_MAGIC: u32 = 0xFEED_BABE;
/// `XLOG_VERSION_2`.
pub const XLOG_VERSION_2: u32 = 2;
/// Size of the basic-block record header (`XLOG_HEADER_SIZE`).
pub const XLOG_HEADER_SIZE: usize = 512;
/// Transaction log client (`XFS_TRANSACTION`).
pub const XFS_TRANSACTION: u8 = 0x69;
/// Log client used by unmount records (`XFS_LOG`).
pub const XFS_LOG: u8 = 0xAA;
/// `XFS_TRANS_HEADER_MAGIC`.
pub const XFS_TRANS_HEADER_MAGIC: u32 = 0x5452_414E;
/// Checkpoint transaction type (`XFS_TRANS_CHECKPOINT`).
pub const XFS_TRANS_CHECKPOINT: u32 = 40;
/// Buffer log item type (`XFS_LI_BUF`).
pub const XFS_LI_BUF: u16 = 0x123C;
/// Inode log item type (`XFS_LI_INODE`).
pub const XFS_LI_INODE: u16 = 0x123B;
/// Log the inode core.
pub const XFS_ILOG_CORE: u32 = 0x001;
/// Log inline data-fork bytes.
pub const XFS_ILOG_DDATA: u32 = 0x002;
/// Log data-fork extent records.
pub const XFS_ILOG_DEXT: u32 = 0x004;
/// Log the data-fork B+tree root.
pub const XFS_ILOG_DBROOT: u32 = 0x008;
/// Log a device inode's encoded device number.
pub const XFS_ILOG_DEV: u32 = 0x010;

/// Start a transaction (`XLOG_START_TRANS`).
pub const XLOG_START_TRANS: u8 = 0x01;
/// Commit a transaction (`XLOG_COMMIT_TRANS`).
pub const XLOG_COMMIT_TRANS: u8 = 0x02;
/// Mark a clean unmount record (`XLOG_UNMOUNT_TRANS`).
pub const XLOG_UNMOUNT_TRANS: u8 = 0x20;
/// Native-endian unmount payload magic (`XLOG_UNMOUNT_TYPE`).
pub const XLOG_UNMOUNT_TYPE: u16 = 0x556E;

/// Linux little-endian log format.
pub const XLOG_FMT_LINUX_LE: u32 = 1;
/// Linux big-endian log format.
pub const XLOG_FMT_LINUX_BE: u32 = 2;

const XLOG_REC_SIZE: usize = 328;
const XLOG_REC_SIZE_OTHER: usize = 324;
const XLOG_HEADER_CYCLE_SIZE: usize = 32 * 1024;
const XLOG_CYCLE_DATA_ENTRIES: usize = 64;
const XLOG_OP_HEADER_SIZE: usize = 12;
const XFS_TRANS_HEADER_SIZE: usize = 16;
const XFS_UNMOUNT_FORMAT_SIZE: usize = 8;
const XFS_BLF_FIXED_SIZE: usize = 20;
const XFS_INODE_LOG_FORMAT_SIZE: usize = 56;
const XFS_BLF_CHUNK: usize = 128;
const XFS_BLF_BITS_PER_WORD: usize = 32;
const XFS_MAX_BLOCKSIZE: usize = 64 * 1024;
const XFS_BLFT_SHIFT: u16 = 11;
const XFS_BLFT_MASK: u16 = 0xF800;
const XFS_BLF_INODE_BUF: u16 = 1;

const H_CRC_OFFSET: usize = 32;
const H_PREV_BLOCK_OFFSET: usize = 36;
const H_NUM_LOG_OPS_OFFSET: usize = 40;
const H_CYCLE_DATA_OFFSET: usize = 44;
const H_FMT_OFFSET: usize = 300;
const H_FS_UUID_OFFSET: usize = 304;
const H_SIZE_OFFSET: usize = 320;

/// Metadata buffer types encoded in the upper five bits of `blf_flags`.
///
/// The discriminants are the corresponding `enum xfs_blft` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LogBufferType {
    /// B+tree block (`XFS_BLFT_BTREE_BUF`).
    Btree = 4,
    /// Allocation-group free-space header (`XFS_BLFT_AGF_BUF`).
    Agf = 5,
    /// Allocation-group freelist (`XFS_BLFT_AGFL_BUF`).
    Agfl = 6,
    /// Allocation-group inode header (`XFS_BLFT_AGI_BUF`).
    Agi = 7,
    /// Inode cluster buffer (`XFS_BLFT_DINO_BUF`).
    Dino = 8,
    /// Symbolic-link block (`XFS_BLFT_SYMLINK_BUF`).
    Symlink = 9,
    /// Directory block (`XFS_BLFT_DIR_BLOCK_BUF`).
    DirBlock = 10,
    /// Directory data block (`XFS_BLFT_DIR_DATA_BUF`).
    DirData = 11,
    /// Directory free-space block (`XFS_BLFT_DIR_FREE_BUF`).
    DirFree = 12,
    /// Format-1 directory leaf (`XFS_BLFT_DIR_LEAF1_BUF`).
    DirLeaf1 = 13,
    /// Format-N directory leaf (`XFS_BLFT_DIR_LEAFN_BUF`).
    DirLeafN = 14,
    /// Directory/attribute node (`XFS_BLFT_DA_NODE_BUF`).
    DaNode = 15,
    /// Attribute leaf (`XFS_BLFT_ATTR_LEAF_BUF`).
    AttrLeaf = 16,
    /// Remote attribute block (`XFS_BLFT_ATTR_RMT_BUF`).
    AttrRmt = 17,
    /// Superblock buffer (`XFS_BLFT_SB_BUF`).
    Sb = 19,
}

impl LogBufferType {
    /// Return the raw `xfs_blft` value stored in `blf_flags`.
    pub const fn as_raw(self) -> u16 {
        self as u16
    }

    /// Parse a raw `xfs_blft` value supported by this module.
    pub const fn from_raw(raw: u16) -> Option<Self> {
        match raw {
            4 => Some(Self::Btree),
            5 => Some(Self::Agf),
            6 => Some(Self::Agfl),
            7 => Some(Self::Agi),
            8 => Some(Self::Dino),
            9 => Some(Self::Symlink),
            10 => Some(Self::DirBlock),
            11 => Some(Self::DirData),
            12 => Some(Self::DirFree),
            13 => Some(Self::DirLeaf1),
            14 => Some(Self::DirLeafN),
            15 => Some(Self::DaNode),
            16 => Some(Self::AttrLeaf),
            17 => Some(Self::AttrRmt),
            19 => Some(Self::Sb),
            _ => None,
        }
    }
}

/// One metadata buffer logged by a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogBufferItem {
    /// Absolute device address in 512-byte basic blocks (`blf_blkno`).
    pub block_num: u64,
    /// Full buffer image. The encoder requires the complete buffer; the
    /// decoder zero-fills chunks absent from a partial Linux dirty bitmap.
    pub data: Vec<u8>,
    /// Metadata buffer type (`xfs_blft`).
    pub buffer_type: LogBufferType,
    /// Whether `XFS_BLF_INODE_BUF` is set.
    pub inode_buffer: bool,
    /// Dirty 128-byte chunk indices. An empty list means the entire buffer.
    pub dirty_chunks: Vec<usize>,
}

/// One inode log item (`xfs_inode_log_format` plus native-endian regions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogInodeItem {
    /// Absolute inode number.
    pub ino: u64,
    /// Absolute device address of the inode cluster in 512-byte basic blocks.
    pub block_num: u64,
    /// Inode-cluster buffer length in basic blocks.
    pub buffer_len: u32,
    /// Byte offset of the inode within its cluster buffer.
    pub boffset: u32,
    /// `ilf_fields`.
    pub fields: u32,
    /// Unpadded data-fork byte count (`ilf_dsize`).
    pub dsize: u16,
    /// Native-endian `xfs_log_dinode` image.
    pub core: Vec<u8>,
    /// Optional native-endian data-fork region.
    pub fork: Option<Vec<u8>>,
    /// Native-endian encoded device number for `XFS_ILOG_DEV`.
    pub device: u32,
}

impl LogInodeItem {
    /// Build a Linux-compatible inode log item from a parsed on-disk inode.
    #[cfg(feature = "alloc")]
    pub fn from_inode(
        inode: &crate::Inode,
        ino: u64,
        block_num: u64,
        buffer_len: u32,
        boffset: u32,
        inode_size: usize,
        lsn: u64,
    ) -> FsResult<Self> {
        if buffer_len == 0 || block_num > i64::MAX as u64 {
            return Err(FsError::InvalidBlockAddress);
        }
        let core_size = inode.core.data_fork_offset();
        let fork_size = inode.core.data_fork_size(inode_size);
        if core_size
            .checked_add(fork_size)
            .is_none_or(|end| end > inode_size)
        {
            return Err(FsError::Corrupted);
        }
        let has_bigtime = inode.core.version >= 3 && inode.core.flags2 & (1 << 3) != 0;
        let core = inode_core_to_log(&inode.core, has_bigtime, lsn)?;
        let mut fields = XFS_ILOG_CORE;
        let mut device = 0;
        let fork = match &inode.data_fork {
            crate::DataFork::Local(data) if !data.is_empty() => {
                if data.len() > fork_size {
                    return Err(FsError::Corrupted);
                }
                fields |= XFS_ILOG_DDATA;
                Some(data.clone())
            }
            crate::DataFork::Extents(extents) if !extents.is_empty() => {
                let needed = extents
                    .len()
                    .checked_mul(crate::Extent::SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?;
                if needed > fork_size {
                    return Err(FsError::FileTooLarge);
                }
                fields |= XFS_ILOG_DEXT;
                let mut raw = Vec::with_capacity(needed);
                for extent in extents {
                    raw.extend_from_slice(&extent_to_native(*extent)?);
                }
                Some(raw)
            }
            crate::DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                fields |= XFS_ILOG_DBROOT;
                Some(broot_to_native(*level, *num_recs, data)?)
            }
            crate::DataFork::Device { major, minor } => {
                fields |= XFS_ILOG_DEV;
                device = ((major & 0xFF) << 8) | (minor & 0xFF);
                None
            }
            _ => None,
        };
        let dsize = u16::try_from(fork.as_ref().map_or(0, |data| data.len()))
            .map_err(|_| FsError::FileTooLarge)?;
        let mut fork = fork;
        if let Some(data) = &mut fork {
            let padded = data
                .len()
                .checked_add(3)
                .map(|value| value & !3)
                .ok_or(FsError::ArithmeticOverflow)?;
            data.resize(padded, 0);
        }
        Ok(Self {
            ino,
            block_num,
            buffer_len,
            boffset,
            fields,
            dsize,
            core,
            fork,
            device,
        })
    }

    /// Replay this item into an inode-cluster buffer.
    pub fn apply_to_disk(
        &self,
        raw: &mut [u8],
        inode_size: usize,
        current_lsn: u64,
    ) -> FsResult<()> {
        let core_size = self.core.len();
        let version = *self.core.get(4).ok_or(FsError::BufferTooSmall)?;
        let expected_core_size = match version {
            3 => crate::InodeCore::V3_SIZE,
            2 | 1 => crate::InodeCore::V2_SIZE,
            _ => return Err(FsError::UnsupportedVersion),
        };
        let expected_buffer_len = usize::try_from(self.buffer_len)
            .ok()
            .and_then(|blocks| blocks.checked_mul(512))
            .ok_or(FsError::ArithmeticOverflow)?;
        if core_size != expected_core_size
            || core_size > inode_size
            || raw.len() != expected_buffer_len
        {
            return Err(FsError::Corrupted);
        }
        let start = self.boffset as usize;
        let end = start
            .checked_add(inode_size)
            .ok_or(FsError::ArithmeticOverflow)?;
        let inode_raw = raw.get_mut(start..end).ok_or(FsError::BufferTooSmall)?;
        let next_unlinked = inode_raw
            .get(0x60..0x64)
            .ok_or(FsError::BufferTooSmall)?
            .to_vec();
        let disk_core = inode_core_to_disk(&self.core, current_lsn)?;
        inode_raw[..core_size].copy_from_slice(&disk_core);
        inode_raw[0x60..0x64].copy_from_slice(&next_unlinked);
        if self.fields & XFS_ILOG_DEV != 0 {
            inode_raw
                .get_mut(core_size..core_size + 4)
                .ok_or(FsError::BufferTooSmall)?
                .copy_from_slice(&self.device.to_be_bytes());
        }
        if let Some(fork) = &self.fork {
            let disk_fork = match self.fields & (XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT) {
                XFS_ILOG_DDATA => fork.clone(),
                XFS_ILOG_DEXT => extents_from_native(fork)?,
                XFS_ILOG_DBROOT => {
                    let level = read_ne_u16(fork, 0)?;
                    let num_recs = read_ne_u16(fork, 2)?;
                    broot_from_native(level, num_recs, &fork[4..])?
                }
                _ => return Err(FsError::Corrupted),
            };
            let mut disk_fork = disk_fork;
            if self.fields & XFS_ILOG_DBROOT != 0 {
                if disk_fork.len() > self.dsize as usize {
                    return Err(FsError::Corrupted);
                }
                disk_fork.resize(self.dsize as usize, 0);
            } else if disk_fork.len() < self.dsize as usize {
                return Err(FsError::Corrupted);
            }
            disk_fork.truncate(self.dsize as usize);
            let fork_end = core_size
                .checked_add(disk_fork.len())
                .ok_or(FsError::ArithmeticOverflow)?;
            if fork_end > inode_size {
                return Err(FsError::Corrupted);
            }
            inode_raw[core_size..fork_end].copy_from_slice(&disk_fork);
        }
        if self.core[4] == 3 {
            crate::crc::recalculate_crc_le(inode_raw, 0x64).ok_or(FsError::BufferTooSmall)?;
        }
        Ok(())
    }
}

#[cfg(feature = "alloc")]
fn inode_core_to_log(core: &crate::InodeCore, has_bigtime: bool, lsn: u64) -> FsResult<Vec<u8>> {
    let size = if core.version == 3 {
        crate::InodeCore::V3_SIZE
    } else {
        crate::InodeCore::V2_SIZE
    };
    let mut raw = vec![0u8; size];
    raw[0..2].copy_from_slice(&core.magic.to_ne_bytes());
    raw[2..4].copy_from_slice(&core.mode.to_ne_bytes());
    raw[4] = if core.version == 3 { 3 } else { 2 };
    raw[5] = core.format.to_u8();
    raw[6..8].copy_from_slice(&core.onlink.to_ne_bytes());
    raw[8..12].copy_from_slice(&core.uid.to_ne_bytes());
    raw[12..16].copy_from_slice(&core.gid.to_ne_bytes());
    raw[16..20].copy_from_slice(&core.nlink.to_ne_bytes());
    raw[20..22].copy_from_slice(&core.projid_lo.to_ne_bytes());
    raw[22..24].copy_from_slice(&core.projid_hi.to_ne_bytes());
    log_timestamp(&mut raw, 0x20, core.atime_sec, core.atime_nsec, has_bigtime);
    log_timestamp(&mut raw, 0x28, core.mtime_sec, core.mtime_nsec, has_bigtime);
    log_timestamp(&mut raw, 0x30, core.ctime_sec, core.ctime_nsec, has_bigtime);
    raw[0x38..0x40].copy_from_slice(&core.size.to_ne_bytes());
    raw[0x40..0x48].copy_from_slice(&core.nblocks.to_ne_bytes());
    raw[0x48..0x4C].copy_from_slice(&core.extsize.to_ne_bytes());
    raw[0x4C..0x50].copy_from_slice(&core.nextents.to_ne_bytes());
    raw[0x50..0x52].copy_from_slice(&core.anextents.to_ne_bytes());
    raw[0x52] = core.forkoff;
    raw[0x53] = core.aformat;
    raw[0x54..0x58].copy_from_slice(&core.dmevmask.to_ne_bytes());
    raw[0x58..0x5A].copy_from_slice(&core.dmstate.to_ne_bytes());
    raw[0x5A..0x5C].copy_from_slice(&core.flags.to_ne_bytes());
    raw[0x5C..0x60].copy_from_slice(&core.gen.to_ne_bytes());
    raw[0x60..0x64].copy_from_slice(&u32::MAX.to_ne_bytes());
    if core.version == 3 {
        raw[0x68..0x70].copy_from_slice(&core.changecount.to_ne_bytes());
        raw[0x70..0x78].copy_from_slice(&lsn.to_ne_bytes());
        raw[0x78..0x80].copy_from_slice(&core.flags2.to_ne_bytes());
        raw[0x80..0x84].copy_from_slice(&core.cowextsize.to_ne_bytes());
        log_timestamp(
            &mut raw,
            0x90,
            core.crtime_sec,
            core.crtime_nsec,
            has_bigtime,
        );
        raw[0x98..0xA0].copy_from_slice(&core.ino.to_ne_bytes());
        raw[0xA0..0xB0].copy_from_slice(&core.uuid);
    }
    Ok(raw)
}

fn inode_core_to_disk(raw: &[u8], current_lsn: u64) -> FsResult<Vec<u8>> {
    let version = *raw.get(4).ok_or(FsError::BufferTooSmall)?;
    let size = if version == 3 {
        crate::InodeCore::V3_SIZE
    } else if version == 2 || version == 1 {
        crate::InodeCore::V2_SIZE
    } else {
        return Err(FsError::UnsupportedVersion);
    };
    if raw.len() != size {
        return Err(FsError::Corrupted);
    }
    let has_bigtime = version == 3 && read_ne_u64(raw, 0x78)? & (1 << 3) != 0;
    let mut disk = vec![0u8; size];
    disk[0..2].copy_from_slice(&read_ne_u16(raw, 0)?.to_be_bytes());
    disk[2..4].copy_from_slice(&read_ne_u16(raw, 2)?.to_be_bytes());
    disk[4] = version;
    disk[5] = raw[5];
    disk[6..8].copy_from_slice(&read_ne_u16(raw, 6)?.to_be_bytes());
    disk[8..12].copy_from_slice(&read_ne_u32(raw, 8)?.to_be_bytes());
    disk[12..16].copy_from_slice(&read_ne_u32(raw, 12)?.to_be_bytes());
    disk[16..20].copy_from_slice(&read_ne_u32(raw, 16)?.to_be_bytes());
    disk[20..22].copy_from_slice(&read_ne_u16(raw, 20)?.to_be_bytes());
    disk[22..24].copy_from_slice(&read_ne_u16(raw, 22)?.to_be_bytes());
    disk_timestamp(&mut disk, 0x20, raw, 0x20, has_bigtime)?;
    disk_timestamp(&mut disk, 0x28, raw, 0x28, has_bigtime)?;
    disk_timestamp(&mut disk, 0x30, raw, 0x30, has_bigtime)?;
    disk[0x38..0x40].copy_from_slice(&read_ne_u64(raw, 0x38)?.to_be_bytes());
    disk[0x40..0x48].copy_from_slice(&read_ne_u64(raw, 0x40)?.to_be_bytes());
    disk[0x48..0x4C].copy_from_slice(&read_ne_u32(raw, 0x48)?.to_be_bytes());
    disk[0x4C..0x50].copy_from_slice(&read_ne_u32(raw, 0x4C)?.to_be_bytes());
    disk[0x50..0x52].copy_from_slice(&read_ne_u16(raw, 0x50)?.to_be_bytes());
    disk[0x52] = raw[0x52];
    disk[0x53] = raw[0x53];
    disk[0x54..0x58].copy_from_slice(&read_ne_u32(raw, 0x54)?.to_be_bytes());
    disk[0x58..0x5A].copy_from_slice(&read_ne_u16(raw, 0x58)?.to_be_bytes());
    disk[0x5A..0x5C].copy_from_slice(&read_ne_u16(raw, 0x5A)?.to_be_bytes());
    disk[0x5C..0x60].copy_from_slice(&read_ne_u32(raw, 0x5C)?.to_be_bytes());
    if version == 3 {
        disk[0x68..0x70].copy_from_slice(&read_ne_u64(raw, 0x68)?.to_be_bytes());
        disk[0x70..0x78].copy_from_slice(&current_lsn.to_be_bytes());
        disk[0x78..0x80].copy_from_slice(&read_ne_u64(raw, 0x78)?.to_be_bytes());
        disk[0x80..0x84].copy_from_slice(&read_ne_u32(raw, 0x80)?.to_be_bytes());
        disk_timestamp(&mut disk, 0x90, raw, 0x90, has_bigtime)?;
        disk[0x98..0xA0].copy_from_slice(&read_ne_u64(raw, 0x98)?.to_be_bytes());
        disk[0xA0..0xB0].copy_from_slice(&raw[0xA0..0xB0]);
    }
    Ok(disk)
}

#[cfg(feature = "alloc")]
fn log_timestamp(out: &mut [u8], offset: usize, sec: u32, nsec: u32, has_bigtime: bool) {
    if has_bigtime {
        let value = (u64::from(sec) << 32) | u64::from(nsec);
        out[offset..offset + 8].copy_from_slice(&value.to_ne_bytes());
    } else {
        out[offset..offset + 4].copy_from_slice(&sec.to_ne_bytes());
        out[offset + 4..offset + 8].copy_from_slice(&nsec.to_ne_bytes());
    }
}

fn disk_timestamp(
    out: &mut [u8],
    offset: usize,
    raw: &[u8],
    raw_offset: usize,
    has_bigtime: bool,
) -> FsResult<()> {
    if has_bigtime {
        let value = read_ne_u64(raw, raw_offset)?;
        out[offset..offset + 4].copy_from_slice(&((value >> 32) as u32).to_be_bytes());
        out[offset + 4..offset + 8].copy_from_slice(&(value as u32).to_be_bytes());
    } else {
        out[offset..offset + 4].copy_from_slice(&read_ne_u32(raw, raw_offset)?.to_be_bytes());
        out[offset + 4..offset + 8]
            .copy_from_slice(&read_ne_u32(raw, raw_offset + 4)?.to_be_bytes());
    }
    Ok(())
}

#[cfg(feature = "alloc")]
fn extent_to_native(extent: crate::Extent) -> FsResult<[u8; 16]> {
    let disk = extent.to_bytes_checked()?;
    let hi = u64::from_be_bytes(disk[..8].try_into().map_err(|_| FsError::Corrupted)?);
    let lo = u64::from_be_bytes(disk[8..].try_into().map_err(|_| FsError::Corrupted)?);
    let mut native = [0u8; 16];
    native[..8].copy_from_slice(&hi.to_ne_bytes());
    native[8..].copy_from_slice(&lo.to_ne_bytes());
    Ok(native)
}

fn extents_from_native(raw: &[u8]) -> FsResult<Vec<u8>> {
    if !raw.len().is_multiple_of(crate::Extent::SIZE) {
        return Err(FsError::Corrupted);
    }
    let mut disk = Vec::with_capacity(raw.len());
    let (records, remainder) = raw.as_chunks::<{ crate::Extent::SIZE }>();
    if !remainder.is_empty() {
        return Err(FsError::Corrupted);
    }
    for record in records {
        let hi = read_ne_u64(record, 0)?;
        let lo = read_ne_u64(record, 8)?;
        let mut encoded = [0u8; 16];
        encoded[..8].copy_from_slice(&hi.to_be_bytes());
        encoded[8..].copy_from_slice(&lo.to_be_bytes());
        crate::Extent::parse(&encoded)?;
        disk.extend_from_slice(&encoded);
    }
    Ok(disk)
}

#[cfg(feature = "alloc")]
fn broot_to_native(level: u16, num_recs: u16, data: &[u8]) -> FsResult<Vec<u8>> {
    let max_recs = data.len() / 16;
    if num_recs as usize > max_recs {
        return Err(FsError::Corrupted);
    }
    let mut raw = vec![0u8; 4 + max_recs * 16];
    raw[..2].copy_from_slice(&level.to_ne_bytes());
    raw[2..4].copy_from_slice(&num_recs.to_ne_bytes());
    let ptr_offset = max_recs * 8;
    for index in 0..num_recs as usize {
        let key = u64::from_be_bytes(
            data.get(index * 8..index * 8 + 8)
                .ok_or(FsError::BufferTooSmall)?
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        );
        let ptr = u64::from_be_bytes(
            data.get(ptr_offset + index * 8..ptr_offset + index * 8 + 8)
                .ok_or(FsError::BufferTooSmall)?
                .try_into()
                .map_err(|_| FsError::Corrupted)?,
        );
        raw[4 + index * 8..12 + index * 8].copy_from_slice(&key.to_ne_bytes());
        raw[4 + ptr_offset + index * 8..12 + ptr_offset + index * 8]
            .copy_from_slice(&ptr.to_ne_bytes());
    }
    Ok(raw)
}

fn broot_from_native(level: u16, num_recs: u16, data: &[u8]) -> FsResult<Vec<u8>> {
    let max_recs = data.len() / 16;
    if num_recs as usize > max_recs {
        return Err(FsError::Corrupted);
    }
    let mut disk = vec![0u8; 4 + max_recs * 16];
    disk[..2].copy_from_slice(&level.to_be_bytes());
    disk[2..4].copy_from_slice(&num_recs.to_be_bytes());
    let ptr_offset = max_recs * 8;
    for index in 0..num_recs as usize {
        let key = read_ne_u64(data, index * 8)?;
        let ptr = read_ne_u64(data, ptr_offset + index * 8)?;
        disk[4 + index * 8..12 + index * 8].copy_from_slice(&key.to_be_bytes());
        disk[4 + ptr_offset + index * 8..12 + ptr_offset + index * 8]
            .copy_from_slice(&ptr.to_be_bytes());
    }
    Ok(disk)
}

fn read_ne_u16(raw: &[u8], offset: usize) -> FsResult<u16> {
    let bytes = raw.get(offset..offset + 2).ok_or(FsError::BufferTooSmall)?;
    Ok(u16::from_ne_bytes(
        bytes.try_into().map_err(|_| FsError::Corrupted)?,
    ))
}

fn read_ne_u32(raw: &[u8], offset: usize) -> FsResult<u32> {
    let bytes = raw.get(offset..offset + 4).ok_or(FsError::BufferTooSmall)?;
    Ok(u32::from_ne_bytes(
        bytes.try_into().map_err(|_| FsError::Corrupted)?,
    ))
}

fn read_ne_u64(raw: &[u8], offset: usize) -> FsResult<u64> {
    let bytes = raw.get(offset..offset + 8).ok_or(FsError::BufferTooSmall)?;
    Ok(u64::from_ne_bytes(
        bytes.try_into().map_err(|_| FsError::Corrupted)?,
    ))
}

/// A checkpoint transaction containing metadata buffer and inode updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogTransaction {
    /// Native-endian `th_tid` in the transaction header. Linux currently
    /// leaves this field unused during recovery; operation headers carry the
    /// authoritative transaction ID.
    pub tid: u32,
    /// Buffer items in log order.
    pub items: Vec<LogBufferItem>,
    /// Inode items in log order.
    pub inode_items: Vec<LogInodeItem>,
}

/// A validated log record header and its committed contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLogRecord {
    /// `h_magicno`.
    pub h_magicno: u32,
    /// `h_cycle`.
    pub h_cycle: u32,
    /// `h_version`.
    pub h_version: u32,
    /// `h_len`: payload length in bytes, padded to whole basic blocks. The
    /// record occupies one 512-byte header block plus `h_len` bytes.
    pub h_len: u32,
    /// `h_lsn`.
    pub h_lsn: u64,
    /// `h_tail_lsn`.
    pub h_tail_lsn: u64,
    /// `h_crc`.
    pub h_crc: u32,
    /// `h_prev_block`.
    pub h_prev_block: u32,
    /// `h_num_logops`.
    pub h_num_logops: u32,
    /// `h_fmt`.
    pub h_fmt: u32,
    /// `h_fs_uuid`.
    pub h_fs_uuid: [u8; 16],
    /// `h_size`.
    pub h_size: u32,
    /// Transaction ID from the operation headers.
    pub tid: u32,
    /// Whether a commit operation was present.
    pub committed: bool,
    /// Whether this is the single-operation clean-unmount record.
    pub unmount: bool,
    /// Committed metadata buffers, in log order.
    pub items: Vec<LogBufferItem>,
    /// Committed inode items, in log order.
    pub inode_items: Vec<LogInodeItem>,
}

/// Encode one committed checkpoint transaction as a physical v2 log record.
///
/// `block` and `prev_block` are basic-block positions in the internal log.
/// `prev_block` is the start of the previous record, or `u32::MAX` when there
/// is none; it cannot be derived from `block` because the previous record may
/// have any length. `tail_lsn`, `uuid`, and `tid` are written unchanged to
/// their corresponding header/operation fields. `tx.tid` is written to the
/// native-endian transaction header.
///
/// `log_size_bytes` is the in-core log buffer size (`h_size`), not the total
/// size of the internal log. It must be a power of two from 1 KiB through
/// 32 KiB. `format` must match this host's endianness because item structures
/// are emitted in native byte order.
///
/// The returned allocation is one 512-byte header followed by `h_len` bytes of
/// payload, zero-padded to a basic-block boundary. Every
/// payload basic block is cycle-stamped, with displaced first words saved in
/// `h_cycle_data`. The CRC covers the 328-byte C header through `h_pad0` and
/// the stamped payload.
#[allow(clippy::too_many_arguments)]
pub fn encode_transaction(
    tx: &LogTransaction,
    cycle: u32,
    block: u32,
    prev_block: u32,
    tail_lsn: u64,
    uuid: [u8; 16],
    log_size_bytes: u32,
    format: u32,
    tid: u32,
) -> FsResult<Vec<u8>> {
    validate_placement(cycle, log_size_bytes, format)?;

    let mut item_ops = 0usize;
    let mut payload_len = XLOG_OP_HEADER_SIZE
        .checked_add(XLOG_OP_HEADER_SIZE + XFS_TRANS_HEADER_SIZE)
        .ok_or(FsError::ArithmeticOverflow)?
        .checked_add(XLOG_OP_HEADER_SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;

    for item in &tx.items {
        let map_size = buffer_map_size(&item.data)?;
        let blf_size = XFS_BLF_FIXED_SIZE
            .checked_add(map_size.checked_mul(4).ok_or(FsError::ArithmeticOverflow)?)
            .ok_or(FsError::ArithmeticOverflow)?;
        let runs = dirty_runs(item)?;
        item_ops = item_ops
            .checked_add(1)
            .and_then(|value| value.checked_add(runs.len()))
            .ok_or(FsError::ArithmeticOverflow)?;
        payload_len = payload_len
            .checked_add(
                XLOG_OP_HEADER_SIZE
                    .checked_add(blf_size)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        for (_, count) in runs {
            let bytes = count
                .checked_mul(XFS_BLF_CHUNK)
                .ok_or(FsError::ArithmeticOverflow)?;
            payload_len = payload_len
                .checked_add(
                    XLOG_OP_HEADER_SIZE
                        .checked_add(bytes)
                        .ok_or(FsError::ArithmeticOverflow)?,
                )
                .ok_or(FsError::ArithmeticOverflow)?;
        }
    }
    for item in &tx.inode_items {
        let regions = inode_regions(item)?;
        item_ops = item_ops
            .checked_add(1)
            .and_then(|value| value.checked_add(regions.len()))
            .ok_or(FsError::ArithmeticOverflow)?;
        payload_len = payload_len
            .checked_add(
                XLOG_OP_HEADER_SIZE
                    .checked_add(XFS_INODE_LOG_FORMAT_SIZE)
                    .ok_or(FsError::ArithmeticOverflow)?,
            )
            .ok_or(FsError::ArithmeticOverflow)?;
        for region in regions {
            payload_len = payload_len
                .checked_add(
                    XLOG_OP_HEADER_SIZE
                        .checked_add(region.len())
                        .ok_or(FsError::ArithmeticOverflow)?,
                )
                .ok_or(FsError::ArithmeticOverflow)?;
        }
    }
    let num_logops = u32::try_from(item_ops)
        .ok()
        .and_then(|value| value.checked_add(3))
        .ok_or(FsError::ArithmeticOverflow)?;

    let payload = transaction_payload(tx, tid, payload_len)?;
    finalize_record(
        &payload,
        num_logops,
        cycle,
        block,
        prev_block,
        tail_lsn,
        uuid,
        log_size_bytes,
    )
}

/// Encode the clean-unmount record written by `xlog_write_unmount_record`.
///
/// Arguments have the same meaning as in [`encode_transaction`]. The record
/// contains one `XFS_LOG` operation with `XLOG_UNMOUNT_TRANS` and an eight-byte
/// native-endian `xfs_unmount_log_format` payload.
#[allow(clippy::too_many_arguments)]
pub fn encode_unmount_record(
    cycle: u32,
    block: u32,
    prev_block: u32,
    tail_lsn: u64,
    uuid: [u8; 16],
    log_size_bytes: u32,
    format: u32,
    tid: u32,
) -> FsResult<Vec<u8>> {
    validate_placement(cycle, log_size_bytes, format)?;

    let mut payload = zeroed_vec(
        XLOG_OP_HEADER_SIZE
            .checked_add(XFS_UNMOUNT_FORMAT_SIZE)
            .ok_or(FsError::ArithmeticOverflow)?,
    )?;
    let mut cursor = 0;
    write_op_header(
        &mut payload,
        &mut cursor,
        tid,
        0,
        XFS_LOG,
        XLOG_UNMOUNT_TRANS,
    );
    payload[XLOG_OP_HEADER_SIZE..XLOG_OP_HEADER_SIZE + 2]
        .copy_from_slice(&XLOG_UNMOUNT_TYPE.to_ne_bytes());

    finalize_record(
        &payload,
        1,
        cycle,
        block,
        prev_block,
        tail_lsn,
        uuid,
        log_size_bytes,
    )
}

/// Validate and decode one physical v2 log record.
///
/// `raw` may contain trailing bytes beyond the record; only the declared
/// record (header plus `h_len` payload bytes) is checksummed and parsed. Both
/// Linux little- and big-endian `h_fmt` values are understood. Unknown formats,
/// multi-block record headers, continued operations, unsupported log items, and
/// records containing more than one transaction are rejected.
///
/// Buffer and inode items are returned only after a matching commit operation.
/// An unmount record decodes with `unmount = true`, `committed = false`, and no
/// items.
pub fn decode_record(raw: &[u8], expected_uuid: [u8; 16]) -> FsResult<DecodedLogRecord> {
    let (header, endian) = validate_header(raw, expected_uuid)?;
    let payload = unpack_payload(raw, header.h_len)?;
    let mut cursor = 0;

    if header.h_num_logops == 1 {
        let op = next_op(&payload, &mut cursor)?;
        if op.clientid != XFS_LOG || op.flags != XLOG_UNMOUNT_TRANS || !op.data.is_empty() {
            return Err(FsError::NotSupported);
        }
        // Linux leaves oh_len zero for the unmount operation and appends the
        // eight-byte xfs_unmount_log_format immediately after the header.
        let format = payload
            .get(cursor..cursor + XFS_UNMOUNT_FORMAT_SIZE)
            .ok_or(FsError::Corrupted)?;
        if read_u16(format, 0, endian) != XLOG_UNMOUNT_TYPE
            || format[2..].iter().any(|&byte| byte != 0)
        {
            return Err(FsError::Corrupted);
        }
        return Ok(DecodedLogRecord {
            h_magicno: header.h_magicno,
            h_cycle: header.h_cycle,
            h_version: header.h_version,
            h_len: header.h_len,
            h_lsn: header.h_lsn,
            h_tail_lsn: header.h_tail_lsn,
            h_crc: header.h_crc,
            h_prev_block: header.h_prev_block,
            h_num_logops: header.h_num_logops,
            h_fmt: header.h_fmt,
            h_fs_uuid: header.h_fs_uuid,
            h_size: header.h_size,
            tid: op.tid,
            committed: false,
            unmount: true,
            items: Vec::new(),
            inode_items: Vec::new(),
        });
    }

    let start = next_op(&payload, &mut cursor)?;
    require_transaction_op(&start, XLOG_START_TRANS)?;
    if !start.data.is_empty() {
        return Err(FsError::Corrupted);
    }

    let trans_op = next_op(&payload, &mut cursor)?;
    require_transaction_op(&trans_op, 0)?;
    if trans_op.tid != start.tid {
        return Err(FsError::Corrupted);
    }
    if trans_op.data.len() != XFS_TRANS_HEADER_SIZE
        || read_u32(trans_op.data, 0, endian) != XFS_TRANS_HEADER_MAGIC
        || read_u32(trans_op.data, 4, endian) != XFS_TRANS_CHECKPOINT
    {
        return Err(FsError::Corrupted);
    }
    let item_count = read_u32(trans_op.data, 12, endian) as usize;
    let mut items = Vec::new();
    let mut inode_items = Vec::new();
    let mut regions_total = 3usize;
    for _ in 0..item_count {
        let format_op = next_op(&payload, &mut cursor)?;
        require_transaction_op(&format_op, 0)?;
        if format_op.tid != start.tid {
            return Err(FsError::Corrupted);
        }
        if format_op.data.len() < 2 {
            return Err(FsError::Corrupted);
        }
        let item_type = read_u16(format_op.data, 0, endian);
        match item_type {
            XFS_LI_BUF => {
                let (item, regions) =
                    decode_buffer_item(&format_op, &payload, &mut cursor, endian)?;
                regions_total = regions_total
                    .checked_add(regions)
                    .ok_or(FsError::ArithmeticOverflow)?;
                items.try_reserve(1).map_err(|_| FsError::OutOfMemory)?;
                items.push(item);
            }
            XFS_LI_INODE => {
                let (item, regions) = decode_inode_item(&format_op, &payload, &mut cursor, endian)?;
                regions_total = regions_total
                    .checked_add(regions)
                    .ok_or(FsError::ArithmeticOverflow)?;
                inode_items
                    .try_reserve(1)
                    .map_err(|_| FsError::OutOfMemory)?;
                inode_items.push(item);
            }
            _ => return Err(FsError::NotSupported),
        }
    }

    let commit = next_op(&payload, &mut cursor)?;
    require_transaction_op(&commit, XLOG_COMMIT_TRANS)?;
    if commit.tid != start.tid
        || !commit.data.is_empty()
        || regions_total != header.h_num_logops as usize
        || payload[cursor..].iter().any(|&byte| byte != 0)
    {
        return Err(FsError::Corrupted);
    }

    Ok(DecodedLogRecord {
        h_magicno: header.h_magicno,
        h_cycle: header.h_cycle,
        h_version: header.h_version,
        h_len: header.h_len,
        h_lsn: header.h_lsn,
        h_tail_lsn: header.h_tail_lsn,
        h_crc: header.h_crc,
        h_prev_block: header.h_prev_block,
        h_num_logops: header.h_num_logops,
        h_fmt: header.h_fmt,
        h_fs_uuid: header.h_fs_uuid,
        h_size: header.h_size,
        tid: start.tid,
        committed: true,
        unmount: false,
        items,
        inode_items,
    })
}

/// Validate and decode only the physical record header.
///
/// This is used by log-head scanning where transaction item types may be
/// unsupported by the writer but framing and CRC still need to be trusted.
pub fn decode_record_header(raw: &[u8], expected_uuid: [u8; 16]) -> FsResult<LogRecordHeader> {
    validate_header(raw, expected_uuid).map(|(header, _)| header)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemEndian {
    Little,
    Big,
}

#[derive(Debug, Clone, Copy)]
pub struct LogRecordHeader {
    pub h_magicno: u32,
    pub h_cycle: u32,
    pub h_version: u32,
    pub h_len: u32,
    pub h_lsn: u64,
    pub h_tail_lsn: u64,
    pub h_crc: u32,
    pub h_prev_block: u32,
    pub h_num_logops: u32,
    pub h_fmt: u32,
    pub h_fs_uuid: [u8; 16],
    pub h_size: u32,
}

struct Op<'a> {
    tid: u32,
    data: &'a [u8],
    clientid: u8,
    flags: u8,
}

fn validate_placement(cycle: u32, log_size_bytes: u32, format: u32) -> FsResult<()> {
    if cycle == 0 || cycle == XLOG_HEADER_MAGIC {
        return Err(FsError::InvalidArgument);
    }
    if format != native_format() {
        return Err(FsError::InvalidArgument);
    }
    let size = log_size_bytes as usize;
    if !(2 * XLOG_HEADER_SIZE..=XLOG_HEADER_CYCLE_SIZE).contains(&size)
        || !size.is_power_of_two()
        || !size.is_multiple_of(XLOG_HEADER_SIZE)
    {
        return Err(FsError::NotSupported);
    }
    Ok(())
}

fn native_format() -> u32 {
    if cfg!(target_endian = "little") {
        XLOG_FMT_LINUX_LE
    } else {
        XLOG_FMT_LINUX_BE
    }
}

fn buffer_map_size(data: &[u8]) -> FsResult<usize> {
    if data.is_empty()
        || !data.len().is_multiple_of(XLOG_HEADER_SIZE)
        || data.len() > XFS_MAX_BLOCKSIZE
    {
        return Err(FsError::InvalidArgument);
    }
    let chunks = data.len() / XFS_BLF_CHUNK;
    let words = chunks.div_ceil(XFS_BLF_BITS_PER_WORD);
    if words == 0 || words > XFS_MAX_BLOCKSIZE / XFS_BLF_CHUNK / XFS_BLF_BITS_PER_WORD {
        return Err(FsError::InvalidArgument);
    }
    Ok(words)
}

fn dirty_chunks(item: &LogBufferItem) -> FsResult<Vec<usize>> {
    let chunks = item.data.len() / XFS_BLF_CHUNK;
    if item.dirty_chunks.is_empty() {
        return Ok((0..chunks).collect());
    }
    let mut previous = None;
    let mut result = Vec::with_capacity(item.dirty_chunks.len());
    for &chunk in &item.dirty_chunks {
        if chunk >= chunks || previous.is_some_and(|value| value >= chunk) {
            return Err(FsError::InvalidArgument);
        }
        result.push(chunk);
        previous = Some(chunk);
    }
    Ok(result)
}

fn inode_regions(item: &LogInodeItem) -> FsResult<Vec<&[u8]>> {
    let version = *item.core.get(4).ok_or(FsError::BufferTooSmall)?;
    let core_size = match version {
        3 => crate::InodeCore::V3_SIZE,
        2 | 1 => crate::InodeCore::V2_SIZE,
        _ => return Err(FsError::UnsupportedVersion),
    };
    if item.core.len() != core_size
        || item.fields & XFS_ILOG_CORE == 0
        || item.fields
            & !(XFS_ILOG_CORE | XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT | XFS_ILOG_DEV)
            != 0
        || item.boffset > i32::MAX as u32
        || item.buffer_len == 0
    {
        return Err(FsError::Corrupted);
    }
    let fork_fields = item.fields & (XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT);
    if fork_fields.count_ones() > 1 || (fork_fields == 0) == item.fork.is_some() {
        return Err(FsError::Corrupted);
    }
    let padded_dsize = usize::from(item.dsize)
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(FsError::ArithmeticOverflow)?;
    if (fork_fields == 0 && item.dsize != 0)
        || (fork_fields != 0 && item.dsize == 0)
        || item
            .fork
            .as_ref()
            .is_some_and(|fork| fork.len() != padded_dsize)
    {
        return Err(FsError::Corrupted);
    }
    let mut regions = vec![item.core.as_slice()];
    if let Some(fork) = &item.fork {
        regions.push(fork);
    }
    Ok(regions)
}

fn dirty_runs(item: &LogBufferItem) -> FsResult<Vec<(usize, usize)>> {
    let chunks = dirty_chunks(item)?;
    let mut runs = Vec::new();
    let mut index = 0usize;
    while index < chunks.len() {
        let first = index;
        while index + 1 < chunks.len() && chunks[index + 1] == chunks[index] + 1 {
            index += 1;
        }
        runs.push((chunks[first], chunks[index] - chunks[first] + 1));
        index += 1;
    }
    Ok(runs)
}

fn transaction_payload(tx: &LogTransaction, tid: u32, payload_len: usize) -> FsResult<Vec<u8>> {
    let mut payload = zeroed_vec(payload_len)?;
    let mut cursor = 0;

    write_op_header(
        &mut payload,
        &mut cursor,
        tid,
        0,
        XFS_TRANSACTION,
        XLOG_START_TRANS,
    );

    write_op_header(
        &mut payload,
        &mut cursor,
        tid,
        XFS_TRANS_HEADER_SIZE as u32,
        XFS_TRANSACTION,
        0,
    );
    payload[cursor..cursor + 4].copy_from_slice(&XFS_TRANS_HEADER_MAGIC.to_ne_bytes());
    payload[cursor + 4..cursor + 8].copy_from_slice(&XFS_TRANS_CHECKPOINT.to_ne_bytes());
    payload[cursor + 8..cursor + 12].copy_from_slice(&tx.tid.to_ne_bytes());
    let item_count = tx
        .items
        .len()
        .checked_add(tx.inode_items.len())
        .ok_or(FsError::ArithmeticOverflow)?;
    payload[cursor + 12..cursor + 16].copy_from_slice(
        &u32::try_from(item_count)
            .map_err(|_| FsError::FileTooLarge)?
            .to_ne_bytes(),
    );
    cursor += XFS_TRANS_HEADER_SIZE;

    for item in &tx.items {
        if item.block_num > i64::MAX as u64 {
            return Err(FsError::InvalidBlockAddress);
        }
        let map_size = buffer_map_size(&item.data)?;
        let blf_len = item.data.len() / XLOG_HEADER_SIZE;
        let blf_len_u16 = u16::try_from(blf_len).map_err(|_| FsError::InvalidArgument)?;
        let blf_bytes = XFS_BLF_FIXED_SIZE + map_size * 4;
        let runs = dirty_runs(item)?;
        let blf_size = u16::try_from(runs.len()).map_err(|_| FsError::InvalidArgument)?;
        let flags = (item.buffer_type.as_raw() << XFS_BLFT_SHIFT)
            | if item.inode_buffer {
                XFS_BLF_INODE_BUF
            } else {
                0
            };

        write_op_header(
            &mut payload,
            &mut cursor,
            tid,
            blf_bytes as u32,
            XFS_TRANSACTION,
            0,
        );
        let blf = cursor;
        payload[blf..blf + 2].copy_from_slice(&XFS_LI_BUF.to_ne_bytes());
        payload[blf + 2..blf + 4].copy_from_slice(&blf_size.to_ne_bytes());
        payload[blf + 4..blf + 6].copy_from_slice(&flags.to_ne_bytes());
        payload[blf + 6..blf + 8].copy_from_slice(&blf_len_u16.to_ne_bytes());
        payload[blf + 8..blf + 16].copy_from_slice(&(item.block_num as i64).to_ne_bytes());
        payload[blf + 16..blf + 20].copy_from_slice(&(map_size as u32).to_ne_bytes());

        let chunks = dirty_chunks(item)?;
        for &chunk in &chunks {
            let word = chunk / XFS_BLF_BITS_PER_WORD;
            let bit = chunk % XFS_BLF_BITS_PER_WORD;
            let at = blf + XFS_BLF_FIXED_SIZE + word * 4;
            let mut bitmap = u32::from_ne_bytes(
                payload[at..at + 4]
                    .try_into()
                    .map_err(|_| FsError::Corrupted)?,
            );
            bitmap |= 1u32 << bit;
            payload[at..at + 4].copy_from_slice(&bitmap.to_ne_bytes());
        }
        cursor += blf_bytes;

        for (first, count) in runs {
            let bytes = count * XFS_BLF_CHUNK;
            let start = first * XFS_BLF_CHUNK;
            write_op_header(
                &mut payload,
                &mut cursor,
                tid,
                bytes as u32,
                XFS_TRANSACTION,
                0,
            );
            payload[cursor..cursor + bytes].copy_from_slice(&item.data[start..start + bytes]);
            cursor += bytes;
        }
    }

    for item in &tx.inode_items {
        if item.block_num > i64::MAX as u64
            || item.buffer_len == 0
            || item.buffer_len > i32::MAX as u32
        {
            return Err(FsError::InvalidBlockAddress);
        }
        let regions = inode_regions(item)?;
        let size = u16::try_from(regions.len() + 1).map_err(|_| FsError::InvalidArgument)?;
        write_op_header(
            &mut payload,
            &mut cursor,
            tid,
            XFS_INODE_LOG_FORMAT_SIZE as u32,
            XFS_TRANSACTION,
            0,
        );
        let at = cursor;
        payload[at..at + 2].copy_from_slice(&XFS_LI_INODE.to_ne_bytes());
        payload[at + 2..at + 4].copy_from_slice(&size.to_ne_bytes());
        payload[at + 4..at + 8].copy_from_slice(&item.fields.to_ne_bytes());
        payload[at + 8..at + 10].copy_from_slice(&0u16.to_ne_bytes());
        payload[at + 10..at + 12].copy_from_slice(&item.dsize.to_ne_bytes());
        payload[at + 12..at + 16].fill(0);
        payload[at + 16..at + 24].copy_from_slice(&item.ino.to_ne_bytes());
        payload[at + 24..at + 28].copy_from_slice(&item.device.to_ne_bytes());
        payload[at + 28..at + 40].fill(0);
        payload[at + 40..at + 48].copy_from_slice(&(item.block_num as i64).to_ne_bytes());
        payload[at + 48..at + 52].copy_from_slice(&(item.buffer_len as i32).to_ne_bytes());
        payload[at + 52..at + 56].copy_from_slice(&(item.boffset as i32).to_ne_bytes());
        cursor += XFS_INODE_LOG_FORMAT_SIZE;
        for region in regions {
            write_op_header(
                &mut payload,
                &mut cursor,
                tid,
                u32::try_from(region.len()).map_err(|_| FsError::FileTooLarge)?,
                XFS_TRANSACTION,
                0,
            );
            payload[cursor..cursor + region.len()].copy_from_slice(region);
            cursor += region.len();
        }
    }

    write_op_header(
        &mut payload,
        &mut cursor,
        tid,
        0,
        XFS_TRANSACTION,
        XLOG_COMMIT_TRANS,
    );
    debug_assert_eq!(cursor, payload.len());
    Ok(payload)
}

#[allow(clippy::too_many_arguments)]
fn finalize_record(
    payload: &[u8],
    num_logops: u32,
    cycle: u32,
    block: u32,
    prev_block: u32,
    tail_lsn: u64,
    uuid: [u8; 16],
    log_size_bytes: u32,
) -> FsResult<Vec<u8>> {
    let payload_blocks = payload.len().div_ceil(XLOG_HEADER_SIZE);
    if payload_blocks > XLOG_CYCLE_DATA_ENTRIES {
        return Err(FsError::NoSpace);
    }
    let h_len = payload_blocks
        .checked_mul(XLOG_HEADER_SIZE)
        .ok_or(FsError::ArithmeticOverflow)?;
    let h_len_u32 = u32::try_from(h_len).map_err(|_| FsError::ArithmeticOverflow)?;
    let capacity = (log_size_bytes as usize)
        .checked_sub(XLOG_HEADER_SIZE)
        .ok_or(FsError::NotSupported)?;
    if h_len > capacity {
        return Err(FsError::NoSpace);
    }

    let total = XLOG_HEADER_SIZE
        .checked_add(h_len)
        .ok_or(FsError::ArithmeticOverflow)?;
    let mut raw = zeroed_vec(total)?;
    raw[0..4].copy_from_slice(&XLOG_HEADER_MAGIC.to_be_bytes());
    raw[4..8].copy_from_slice(&cycle.to_be_bytes());
    raw[8..12].copy_from_slice(&XLOG_VERSION_2.to_be_bytes());
    raw[12..16].copy_from_slice(&h_len_u32.to_be_bytes());
    let lsn = (u64::from(cycle) << 32) | u64::from(block);
    raw[16..24].copy_from_slice(&lsn.to_be_bytes());
    raw[24..32].copy_from_slice(&tail_lsn.to_be_bytes());
    raw[H_PREV_BLOCK_OFFSET..H_PREV_BLOCK_OFFSET + 4].copy_from_slice(&prev_block.to_be_bytes());
    raw[H_NUM_LOG_OPS_OFFSET..H_NUM_LOG_OPS_OFFSET + 4].copy_from_slice(&num_logops.to_be_bytes());
    raw[H_FMT_OFFSET..H_FMT_OFFSET + 4].copy_from_slice(&native_format().to_be_bytes());
    raw[H_FS_UUID_OFFSET..H_FS_UUID_OFFSET + 16].copy_from_slice(&uuid);
    raw[H_SIZE_OFFSET..H_SIZE_OFFSET + 4].copy_from_slice(&log_size_bytes.to_be_bytes());
    raw[XLOG_HEADER_SIZE..XLOG_HEADER_SIZE + payload.len()].copy_from_slice(payload);

    for block_index in 0..payload_blocks {
        let at = XLOG_HEADER_SIZE + block_index * XLOG_HEADER_SIZE;
        let original = [raw[at], raw[at + 1], raw[at + 2], raw[at + 3]];
        let cycle_at = H_CYCLE_DATA_OFFSET + block_index * 4;
        raw[cycle_at..cycle_at + 4].copy_from_slice(&original);
        raw[at..at + 4].copy_from_slice(&cycle.to_be_bytes());
    }

    let crc = record_crc(&raw, h_len, XLOG_REC_SIZE);
    raw[H_CRC_OFFSET..H_CRC_OFFSET + 4].copy_from_slice(&crc.to_le_bytes());
    Ok(raw)
}

fn write_op_header(
    out: &mut [u8],
    cursor: &mut usize,
    tid: u32,
    len: u32,
    clientid: u8,
    flags: u8,
) {
    out[*cursor..*cursor + 4].copy_from_slice(&tid.to_be_bytes());
    out[*cursor + 4..*cursor + 8].copy_from_slice(&len.to_be_bytes());
    out[*cursor + 8] = clientid;
    out[*cursor + 9] = flags;
    out[*cursor + 10..*cursor + 12].fill(0);
    *cursor += XLOG_OP_HEADER_SIZE;
}

fn zeroed_vec(len: usize) -> FsResult<Vec<u8>> {
    let mut out = Vec::new();
    out.try_reserve_exact(len)
        .map_err(|_| FsError::OutOfMemory)?;
    out.resize(len, 0);
    Ok(out)
}

fn record_crc(raw: &[u8], payload_len: usize, header_size: usize) -> u32 {
    let header_crc = xfs_crc32c_with_zeroed_field(&raw[..header_size], H_CRC_OFFSET)
        .expect("record header and CRC offset are validated");
    let payload_crc = xfs_crc32c(&raw[XLOG_HEADER_SIZE..XLOG_HEADER_SIZE + payload_len]);
    crc32c::crc32c_combine(header_crc, payload_crc, payload_len)
}

fn validate_header(raw: &[u8], expected_uuid: [u8; 16]) -> FsResult<(LogRecordHeader, ItemEndian)> {
    if raw.len() < XLOG_HEADER_SIZE {
        return Err(FsError::BufferTooSmall);
    }

    let h_magicno = be_u32(raw, 0);
    if h_magicno != XLOG_HEADER_MAGIC {
        return Err(FsError::InvalidMagic);
    }
    let h_version = be_u32(raw, 8);
    if h_version != XLOG_VERSION_2 {
        return Err(FsError::UnsupportedVersion);
    }

    let h_len = be_u32(raw, 12) as usize;
    let h_size = be_u32(raw, H_SIZE_OFFSET) as usize;
    if h_len == 0
        || h_len % 8 != 0
        || !h_len.is_multiple_of(XLOG_HEADER_SIZE)
        || h_len / XLOG_HEADER_SIZE > XLOG_CYCLE_DATA_ENTRIES
    {
        return Err(FsError::Corrupted);
    }
    if !(2 * XLOG_HEADER_SIZE..=XLOG_HEADER_CYCLE_SIZE).contains(&h_size) {
        return Err(FsError::NotSupported);
    }
    if !h_size.is_power_of_two()
        || !h_size.is_multiple_of(XLOG_HEADER_SIZE)
        || h_len > h_size - XLOG_HEADER_SIZE
    {
        return Err(FsError::Corrupted);
    }
    if raw.len() < XLOG_HEADER_SIZE + h_len {
        return Err(FsError::BufferTooSmall);
    }

    let h_cycle = be_u32(raw, 4);
    let h_lsn = be_u64(raw, 16);
    if h_lsn >> 32 != u64::from(h_cycle) || h_cycle == 0 || h_cycle == XLOG_HEADER_MAGIC {
        return Err(FsError::Corrupted);
    }

    let h_fmt = be_u32(raw, H_FMT_OFFSET);
    let endian = match h_fmt {
        XLOG_FMT_LINUX_LE => ItemEndian::Little,
        XLOG_FMT_LINUX_BE => ItemEndian::Big,
        _ => return Err(FsError::UnsupportedVersion),
    };
    let h_fs_uuid: [u8; 16] = raw[H_FS_UUID_OFFSET..H_FS_UUID_OFFSET + 16]
        .try_into()
        .expect("16-byte UUID slice");
    if h_fs_uuid != expected_uuid {
        return Err(FsError::Corrupted);
    }

    let h_crc = le_u32(raw, H_CRC_OFFSET);
    if h_crc != record_crc(raw, h_len, XLOG_REC_SIZE)
        && h_crc != record_crc(raw, h_len, XLOG_REC_SIZE_OTHER)
    {
        return Err(FsError::Corrupted);
    }

    for block_index in 0..h_len / XLOG_HEADER_SIZE {
        let at = XLOG_HEADER_SIZE + block_index * XLOG_HEADER_SIZE;
        if raw[at..at + 4] != h_cycle.to_be_bytes() {
            return Err(FsError::Corrupted);
        }
    }

    Ok((
        LogRecordHeader {
            h_magicno,
            h_cycle,
            h_version,
            h_len: h_len as u32,
            h_lsn,
            h_tail_lsn: be_u64(raw, 24),
            h_crc,
            h_prev_block: be_u32(raw, H_PREV_BLOCK_OFFSET),
            h_num_logops: be_u32(raw, H_NUM_LOG_OPS_OFFSET),
            h_fmt,
            h_fs_uuid,
            h_size: h_size as u32,
        },
        endian,
    ))
}

fn unpack_payload(raw: &[u8], h_len: u32) -> FsResult<Vec<u8>> {
    let len = h_len as usize;
    let mut payload = zeroed_vec(len)?;
    payload.copy_from_slice(&raw[XLOG_HEADER_SIZE..XLOG_HEADER_SIZE + len]);
    for block_index in 0..len / XLOG_HEADER_SIZE {
        let at = block_index * XLOG_HEADER_SIZE;
        let cycle_at = H_CYCLE_DATA_OFFSET + block_index * 4;
        payload[at..at + 4].copy_from_slice(&raw[cycle_at..cycle_at + 4]);
    }
    Ok(payload)
}

fn next_op<'a>(payload: &'a [u8], cursor: &mut usize) -> FsResult<Op<'a>> {
    let remaining = payload.len().saturating_sub(*cursor);
    if remaining < XLOG_OP_HEADER_SIZE {
        return Err(FsError::Corrupted);
    }
    let at = *cursor;
    let tid = be_u32(payload, at);
    let len = be_u32(payload, at + 4) as usize;
    if len % 4 != 0 {
        return Err(FsError::Corrupted);
    }
    let clientid = payload[at + 8];
    let flags = payload[at + 9];
    if payload[at + 10..at + 12] != [0, 0] {
        return Err(FsError::Corrupted);
    }
    let data_at = at + XLOG_OP_HEADER_SIZE;
    let end = data_at
        .checked_add(len)
        .ok_or(FsError::ArithmeticOverflow)?;
    if end > payload.len() {
        return Err(FsError::Corrupted);
    }
    *cursor = end;
    Ok(Op {
        tid,
        data: &payload[data_at..end],
        clientid,
        flags,
    })
}

fn require_transaction_op(op: &Op<'_>, flags: u8) -> FsResult<()> {
    if op.clientid != XFS_TRANSACTION || op.flags != flags {
        return Err(FsError::NotSupported);
    }
    Ok(())
}

fn decode_buffer_item(
    format_op: &Op<'_>,
    payload: &[u8],
    cursor: &mut usize,
    endian: ItemEndian,
) -> FsResult<(LogBufferItem, usize)> {
    let blf = format_op.data;
    if blf.len() < XFS_BLF_FIXED_SIZE || read_u16(blf, 0, endian) != XFS_LI_BUF {
        return Err(FsError::Corrupted);
    }
    let flags = read_u16(blf, 4, endian);
    if flags & !(XFS_BLFT_MASK | XFS_BLF_INODE_BUF) != 0 {
        return Err(FsError::NotSupported);
    }
    let buffer_type = LogBufferType::from_raw((flags & XFS_BLFT_MASK) >> XFS_BLFT_SHIFT)
        .ok_or(FsError::NotSupported)?;
    let blf_len = read_u16(blf, 6, endian) as usize;
    if blf_len == 0 || blf_len > XFS_MAX_BLOCKSIZE / XLOG_HEADER_SIZE {
        return Err(FsError::Corrupted);
    }
    let block_num = read_i64(blf, 8, endian);
    if block_num < 0 {
        return Err(FsError::Corrupted);
    }
    let map_size = read_u32(blf, 16, endian) as usize;
    let max_map_size = XFS_MAX_BLOCKSIZE / XFS_BLF_CHUNK / XFS_BLF_BITS_PER_WORD;
    let format_size = XFS_BLF_FIXED_SIZE
        .checked_add(map_size.checked_mul(4).ok_or(FsError::ArithmeticOverflow)?)
        .ok_or(FsError::ArithmeticOverflow)?;
    if map_size == 0 || map_size > max_map_size || format_size != blf.len() {
        return Err(FsError::Corrupted);
    }
    let region_count = read_u16(blf, 2, endian) as usize;

    let chunks = blf_len * (XLOG_HEADER_SIZE / XFS_BLF_CHUNK);
    for bit in chunks..map_size * XFS_BLF_BITS_PER_WORD {
        if bitmap_bit(blf, bit, endian) {
            return Err(FsError::Corrupted);
        }
    }

    let mut data = zeroed_vec(blf_len * XLOG_HEADER_SIZE)?;
    let mut dirty_chunks = Vec::new();
    let mut data_ops = 0usize;
    let mut bit = 0;
    while bit < chunks {
        if !bitmap_bit(blf, bit, endian) {
            bit += 1;
            continue;
        }
        let first = bit;
        while bit < chunks && bitmap_bit(blf, bit, endian) {
            bit += 1;
        }
        let run_bytes = (bit - first) * XFS_BLF_CHUNK;
        let op = next_op(payload, cursor)?;
        require_transaction_op(&op, 0)?;
        if op.tid != format_op.tid || op.data.len() != run_bytes {
            return Err(FsError::Corrupted);
        }
        let dst = first * XFS_BLF_CHUNK;
        data[dst..dst + run_bytes].copy_from_slice(op.data);
        dirty_chunks.extend(first..bit);
        data_ops += 1;
    }
    if region_count != data_ops {
        return Err(FsError::Corrupted);
    }

    Ok((
        LogBufferItem {
            block_num: block_num as u64,
            data,
            buffer_type,
            inode_buffer: flags & XFS_BLF_INODE_BUF != 0,
            dirty_chunks,
        },
        1 + data_ops,
    ))
}

fn decode_inode_item(
    format_op: &Op<'_>,
    payload: &[u8],
    cursor: &mut usize,
    endian: ItemEndian,
) -> FsResult<(LogInodeItem, usize)> {
    let format = format_op.data;
    if format.len() != XFS_INODE_LOG_FORMAT_SIZE || read_u16(format, 0, endian) != XFS_LI_INODE {
        return Err(FsError::Corrupted);
    }
    let size = read_u16(format, 2, endian) as usize;
    if size != 2 && size != 3 {
        return Err(FsError::NotSupported);
    }
    let fields = read_u32(format, 4, endian);
    if fields & XFS_ILOG_CORE == 0
        || fields
            & !(XFS_ILOG_CORE | XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT | XFS_ILOG_DEV)
            != 0
        || read_u16(format, 8, endian) != 0
        || read_u32(format, 12, endian) != 0
    {
        return Err(FsError::Corrupted);
    }
    let fork_fields = fields & (XFS_ILOG_DDATA | XFS_ILOG_DEXT | XFS_ILOG_DBROOT);
    if fork_fields.count_ones() > 1 || (fork_fields == 0) != (size == 2) {
        return Err(FsError::Corrupted);
    }
    let ino = read_u64(format, 16, endian);
    let device = read_u32(format, 24, endian);
    let block_num = read_i64(format, 40, endian);
    let buffer_len = read_u32(format, 48, endian);
    let boffset = read_u32(format, 52, endian);
    if block_num < 0 || buffer_len == 0 || buffer_len > i32::MAX as u32 || boffset > i32::MAX as u32
    {
        return Err(FsError::Corrupted);
    }

    let core_op = next_op(payload, cursor)?;
    require_transaction_op(&core_op, 0)?;
    if core_op.tid != format_op.tid {
        return Err(FsError::Corrupted);
    }
    let version = *core_op.data.get(4).ok_or(FsError::Corrupted)?;
    let core_size = match version {
        3 => crate::InodeCore::V3_SIZE,
        2 | 1 => crate::InodeCore::V2_SIZE,
        _ => return Err(FsError::UnsupportedVersion),
    };
    if core_op.data.len() != core_size {
        return Err(FsError::Corrupted);
    }
    let dsize = read_u16(format, 10, endian);
    let padded_dsize = usize::from(dsize)
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(FsError::ArithmeticOverflow)?;
    let fork = if size == 3 {
        let fork_op = next_op(payload, cursor)?;
        require_transaction_op(&fork_op, 0)?;
        if dsize == 0
            || fork_op.tid != format_op.tid
            || fork_op.data.len() != padded_dsize
            || !fork_op.data.len().is_multiple_of(4)
        {
            return Err(FsError::Corrupted);
        }
        Some(fork_op.data.to_vec())
    } else {
        if dsize != 0 {
            return Err(FsError::Corrupted);
        }
        None
    };
    Ok((
        LogInodeItem {
            ino,
            block_num: block_num as u64,
            buffer_len,
            boffset,
            fields,
            dsize,
            core: core_op.data.to_vec(),
            fork,
            device,
        },
        size,
    ))
}

fn bitmap_bit(blf: &[u8], bit: usize, endian: ItemEndian) -> bool {
    let word = bit / XFS_BLF_BITS_PER_WORD;
    let value = read_u32(blf, XFS_BLF_FIXED_SIZE + word * 4, endian);
    value & (1u32 << (bit % XFS_BLF_BITS_PER_WORD)) != 0
}

fn be_u32(raw: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]])
}

fn be_u64(raw: &[u8], at: usize) -> u64 {
    u64::from_be_bytes([
        raw[at],
        raw[at + 1],
        raw[at + 2],
        raw[at + 3],
        raw[at + 4],
        raw[at + 5],
        raw[at + 6],
        raw[at + 7],
    ])
}

fn le_u32(raw: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([raw[at], raw[at + 1], raw[at + 2], raw[at + 3]])
}

fn read_u16(raw: &[u8], at: usize, endian: ItemEndian) -> u16 {
    let bytes = [raw[at], raw[at + 1]];
    match endian {
        ItemEndian::Little => u16::from_le_bytes(bytes),
        ItemEndian::Big => u16::from_be_bytes(bytes),
    }
}

fn read_u32(raw: &[u8], at: usize, endian: ItemEndian) -> u32 {
    let bytes = [raw[at], raw[at + 1], raw[at + 2], raw[at + 3]];
    match endian {
        ItemEndian::Little => u32::from_le_bytes(bytes),
        ItemEndian::Big => u32::from_be_bytes(bytes),
    }
}

fn read_u64(raw: &[u8], at: usize, endian: ItemEndian) -> u64 {
    let bytes = [
        raw[at],
        raw[at + 1],
        raw[at + 2],
        raw[at + 3],
        raw[at + 4],
        raw[at + 5],
        raw[at + 6],
        raw[at + 7],
    ];
    match endian {
        ItemEndian::Little => u64::from_le_bytes(bytes),
        ItemEndian::Big => u64::from_be_bytes(bytes),
    }
}

fn read_i64(raw: &[u8], at: usize, endian: ItemEndian) -> i64 {
    let bytes = [
        raw[at],
        raw[at + 1],
        raw[at + 2],
        raw[at + 3],
        raw[at + 4],
        raw[at + 5],
        raw[at + 6],
        raw[at + 7],
    ];
    match endian {
        ItemEndian::Little => i64::from_le_bytes(bytes),
        ItemEndian::Big => i64::from_be_bytes(bytes),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::*;

    const UUID: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const CYCLE: u32 = 7;
    const BLOCK: u32 = 23;
    const PREV_BLOCK: u32 = 11;
    const TAIL_LSN: u64 = (6 << 32) | 19;
    const ICLOG_SIZE: u32 = 32 * 1024;
    const TID: u32 = 0x1020_3040;

    fn item(block_num: u64, len: usize, seed: u8) -> LogBufferItem {
        LogBufferItem {
            block_num,
            data: (0..len)
                .map(|index| seed.wrapping_add(index as u8))
                .collect(),
            buffer_type: LogBufferType::Btree,
            inode_buffer: false,
            dirty_chunks: Vec::new(),
        }
    }

    fn native_endian() -> ItemEndian {
        if native_format() == XLOG_FMT_LINUX_LE {
            ItemEndian::Little
        } else {
            ItemEndian::Big
        }
    }

    fn encode(tx: &LogTransaction) -> Vec<u8> {
        encode_transaction(
            tx,
            CYCLE,
            BLOCK,
            PREV_BLOCK,
            TAIL_LSN,
            UUID,
            ICLOG_SIZE,
            native_format(),
            TID,
        )
        .expect("valid transaction")
    }

    #[test]
    fn transaction_header_and_buffer_offsets_match_xfs_structures() {
        let tx = LogTransaction {
            tid: 0x5566_7788,
            items: vec![item(0x1234, 512, 0xA0)],
            inode_items: Vec::new(),
        };
        let raw = encode(&tx);
        let endian = native_endian();

        assert_eq!(be_u32(&raw, 0), XLOG_HEADER_MAGIC);
        assert_eq!(be_u32(&raw, 4), CYCLE);
        assert_eq!(be_u32(&raw, 8), XLOG_VERSION_2);
        assert_eq!(be_u32(&raw, 12), 1024);
        assert_eq!(
            be_u64(&raw, 16),
            (u64::from(CYCLE) << 32) | u64::from(BLOCK)
        );
        assert_eq!(be_u64(&raw, 24), TAIL_LSN);
        assert_eq!(be_u32(&raw, H_PREV_BLOCK_OFFSET), PREV_BLOCK);
        assert_eq!(be_u32(&raw, H_NUM_LOG_OPS_OFFSET), 5);
        assert_eq!(be_u32(&raw, H_FMT_OFFSET), native_format());
        assert_eq!(&raw[H_FS_UUID_OFFSET..H_FS_UUID_OFFSET + 16], &UUID);
        assert_eq!(be_u32(&raw, H_SIZE_OFFSET), ICLOG_SIZE);
        assert_eq!(raw.len(), XLOG_HEADER_SIZE + 1024);

        // START, transaction header, buffer format, buffer data, COMMIT.
        // The first word of the START operation is replaced by the cycle stamp.
        assert_eq!(&raw[512..516], &CYCLE.to_be_bytes());
        assert_eq!(
            &raw[H_CYCLE_DATA_OFFSET..H_CYCLE_DATA_OFFSET + 4],
            &TID.to_be_bytes()
        );
        assert_eq!(be_u32(&raw, 516), 0);
        assert_eq!(raw[520], XFS_TRANSACTION);
        assert_eq!(raw[521], XLOG_START_TRANS);

        assert_eq!(be_u32(&raw, 524), TID);
        assert_eq!(be_u32(&raw, 528), 16);
        assert_eq!(read_u32(&raw, 536, endian), XFS_TRANS_HEADER_MAGIC);
        assert_eq!(read_u32(&raw, 540, endian), XFS_TRANS_CHECKPOINT);
        assert_eq!(read_u32(&raw, 544, endian), tx.tid);
        assert_eq!(read_u32(&raw, 548, endian), 1);

        assert_eq!(be_u32(&raw, 552), TID);
        assert_eq!(be_u32(&raw, 556), 24);
        assert_eq!(read_u16(&raw, 564, endian), XFS_LI_BUF);
        assert_eq!(read_u16(&raw, 566, endian), 1);
        assert_eq!(
            read_u16(&raw, 568, endian),
            LogBufferType::Btree.as_raw() << XFS_BLFT_SHIFT
        );
        assert_eq!(read_u16(&raw, 570, endian), 1);
        assert_eq!(read_i64(&raw, 572, endian), 0x1234);
        assert_eq!(read_u32(&raw, 580, endian), 1);
        assert_eq!(read_u32(&raw, 584, endian), 0x0000_000F);

        assert_eq!(be_u32(&raw, 588), TID);
        assert_eq!(be_u32(&raw, 592), 512);
        assert_eq!(raw[596], XFS_TRANSACTION);
        assert_eq!(raw[597], 0);
        assert_eq!(raw[600], 0xA0);
        assert_eq!(be_u32(&raw, 1112), TID);
        assert_eq!(be_u32(&raw, 1116), 0);
        assert_eq!(raw[1120], XFS_TRANSACTION);
        assert_eq!(raw[1121], XLOG_COMMIT_TRANS);

        // The second payload basic block stamps over buffer byte 424.
        assert_eq!(&raw[1024..1028], &CYCLE.to_be_bytes());
        assert_eq!(
            &raw[H_CYCLE_DATA_OFFSET + 4..H_CYCLE_DATA_OFFSET + 8],
            &tx.items[0].data[424..428]
        );
        assert_eq!(
            &raw[H_CYCLE_DATA_OFFSET..H_CYCLE_DATA_OFFSET + 4],
            &TID.to_be_bytes()
        );
    }

    #[test]
    fn crc_is_little_endian_and_covers_the_stamped_record() {
        let tx = LogTransaction {
            tid: 1,
            items: vec![item(8, 4096, 3)],
            inode_items: Vec::new(),
        };
        let raw = encode(&tx);
        let stored = le_u32(&raw, H_CRC_OFFSET);
        assert_eq!(
            stored,
            record_crc(&raw, be_u32(&raw, 12) as usize, XLOG_REC_SIZE)
        );

        let mut damaged = raw.clone();
        damaged[700] ^= 1;
        assert!(matches!(
            decode_record(&damaged, UUID),
            Err(FsError::Corrupted)
        ));

        let mut damaged_crc = raw;
        damaged_crc[H_CRC_OFFSET] ^= 1;
        assert!(matches!(
            decode_record(&damaged_crc, UUID),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn partial_dirty_bitmap_logs_only_changed_chunks() {
        let mut buffer = item(0x100, 4096, 0x10);
        buffer.dirty_chunks = vec![1, 3];
        let tx = LogTransaction {
            tid: 7,
            items: vec![buffer.clone()],
            inode_items: Vec::new(),
        };
        let decoded = decode_record(&encode(&tx), UUID).unwrap();
        assert_eq!(decoded.items[0].dirty_chunks, vec![1, 3]);
        assert_eq!(decoded.items[0].data[128..256], buffer.data[128..256]);
        assert_eq!(decoded.items[0].data[384..512], buffer.data[384..512]);
        assert!(decoded.items[0].data[..128].iter().all(|byte| *byte == 0));
        assert_eq!(decoded.h_num_logops, 6);
    }

    #[test]
    fn multi_item_transaction_round_trips() {
        let tx = LogTransaction {
            tid: 99,
            items: vec![
                item(0x100, 4096, 0x10),
                LogBufferItem {
                    block_num: 0x200,
                    data: vec![0x5A; 8192],
                    buffer_type: LogBufferType::Agi,
                    inode_buffer: false,
                    dirty_chunks: Vec::new(),
                },
                LogBufferItem {
                    block_num: 0x300,
                    data: vec![0x3C; 512],
                    buffer_type: LogBufferType::Dino,
                    inode_buffer: true,
                    dirty_chunks: Vec::new(),
                },
            ],
            inode_items: Vec::new(),
        };
        let decoded = decode_record(&encode(&tx), UUID).expect("round trip");
        assert!(decoded.committed);
        assert!(!decoded.unmount);
        assert_eq!(decoded.tid, TID);
        assert_eq!(decoded.items.len(), tx.items.len());
        for (decoded, expected) in decoded.items.iter().zip(&tx.items) {
            assert_eq!(decoded.block_num, expected.block_num);
            assert_eq!(decoded.data, expected.data);
            assert_eq!(decoded.buffer_type, expected.buffer_type);
            assert_eq!(decoded.inode_buffer, expected.inode_buffer);
            assert_eq!(
                decoded.dirty_chunks.len(),
                expected.data.len() / XFS_BLF_CHUNK
            );
        }
        assert_eq!(decoded.h_num_logops, 9);
    }

    #[cfg(feature = "std")]
    #[test]
    fn inode_log_item_round_trips_core_and_extents() {
        let mut core = crate::inode_alloc::create_empty_inode_core_at(
            0o100644,
            7,
            8,
            3,
            42,
            &[0xA5; 16],
            true,
            1_700_000_000,
            123_456_789,
        )
        .unwrap();
        core.size = 8192;
        core.nblocks = 16;
        core.format = crate::InodeFormat::Extents;
        core.nextents = 1;
        let extent = crate::Extent {
            file_offset: 0,
            start_block: 1234,
            block_count: 2,
            is_unwritten: false,
        };
        let inode = crate::Inode {
            core,
            data_fork: crate::DataFork::Extents(vec![extent]),
        };
        let item = LogInodeItem::from_inode(&inode, 42, 8, 8, 0, 512, 0x1234_5678).unwrap();
        let tx = LogTransaction {
            tid: 77,
            items: Vec::new(),
            inode_items: vec![item.clone()],
        };
        let decoded = decode_record(&encode(&tx), UUID).unwrap();
        assert_eq!(decoded.inode_items, vec![item]);
        assert_eq!(decoded.h_num_logops, 6);

        let mut raw = vec![0u8; 4096];
        decoded.inode_items[0]
            .apply_to_disk(&mut raw, 512, 0x1234_5678)
            .unwrap();
        let parsed = crate::Inode::parse(&raw[..512], 512).unwrap();
        assert_eq!(parsed.core.size, 8192);
        assert_eq!(parsed.core.mtime(true), (1_700_000_000, 123_456_789));
        assert_eq!(parsed.core.lsn, 0x1234_5678);
        assert!(parsed.verify_crc(&raw[..512], 512).is_ok());
        match parsed.data_fork {
            crate::DataFork::Extents(extents) => assert_eq!(extents, vec![extent]),
            other => panic!("unexpected data fork: {other:?}"),
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn inode_log_item_round_trips_btree_root() {
        let mut core = crate::inode_alloc::create_empty_inode_core_at(
            0o100644,
            0,
            0,
            3,
            42,
            &[0xA5; 16],
            true,
            1_700_000_000,
            0,
        )
        .unwrap();
        core.format = crate::InodeFormat::Btree;
        core.nextents = 40;
        let mut root = vec![0u8; 324];
        root[..8].copy_from_slice(&0u64.to_be_bytes());
        root[160..168].copy_from_slice(&1234u64.to_be_bytes());
        let inode = crate::Inode {
            core,
            data_fork: crate::DataFork::Btree {
                level: 1,
                num_recs: 1,
                data: root,
            },
        };
        let item = LogInodeItem::from_inode(&inode, 42, 8, 8, 0, 512, 99).unwrap();
        let tx = LogTransaction {
            tid: 78,
            items: Vec::new(),
            inode_items: vec![item.clone()],
        };
        let decoded = decode_record(&encode(&tx), UUID).unwrap();
        assert_eq!(decoded.inode_items, vec![item]);
        let mut raw = vec![0u8; 4096];
        decoded.inode_items[0]
            .apply_to_disk(&mut raw, 512, 99)
            .unwrap();
        let parsed = crate::Inode::parse(&raw[..512], 512).unwrap();
        assert!(parsed.verify_crc(&raw[..512], 512).is_ok());
        match parsed.data_fork {
            crate::DataFork::Btree {
                level,
                num_recs,
                data,
            } => {
                assert_eq!((level, num_recs), (1, 1));
                assert_eq!(data.len(), 332);
                assert_eq!(u64::from_be_bytes(data[160..168].try_into().unwrap()), 1234);
            }
            other => panic!("unexpected data fork: {other:?}"),
        }
    }

    #[test]
    fn unmount_record_has_one_log_client_operation() {
        let raw = encode_unmount_record(
            CYCLE,
            BLOCK,
            PREV_BLOCK,
            TAIL_LSN,
            UUID,
            ICLOG_SIZE,
            native_format(),
            TID,
        )
        .expect("unmount record");
        assert_eq!(raw.len(), 1024);
        assert_eq!(be_u32(&raw, 12), 512);
        assert_eq!(be_u32(&raw, H_NUM_LOG_OPS_OFFSET), 1);
        assert_eq!(&raw[512..516], &CYCLE.to_be_bytes());
        assert_eq!(
            &raw[H_CYCLE_DATA_OFFSET..H_CYCLE_DATA_OFFSET + 4],
            &TID.to_be_bytes()
        );
        assert_eq!(be_u32(&raw, 516), 0);
        assert_eq!(raw[520], XFS_LOG);
        assert_eq!(raw[521], XLOG_UNMOUNT_TRANS);
        assert_eq!(read_u16(&raw, 524, native_endian()), XLOG_UNMOUNT_TYPE);
        assert_eq!(&raw[526..532], &[0; 6]);

        let decoded = decode_record(&raw, UUID).expect("decode unmount");
        assert!(decoded.unmount);
        assert!(!decoded.committed);
        assert!(decoded.items.is_empty());
        assert_eq!(decoded.tid, TID);
    }

    #[test]
    fn decoder_rejects_wrong_uuid_truncation_and_unknown_format() {
        let raw = encode(&LogTransaction {
            tid: 1,
            items: vec![item(4, 512, 0)],
            inode_items: Vec::new(),
        });
        assert!(matches!(
            decode_record(&raw, [0; 16]),
            Err(FsError::Corrupted)
        ));
        assert!(matches!(
            decode_record(&raw[..raw.len() - 1], UUID),
            Err(FsError::BufferTooSmall)
        ));

        let mut unknown_format = raw;
        unknown_format[H_FMT_OFFSET..H_FMT_OFFSET + 4].copy_from_slice(&3u32.to_be_bytes());
        assert!(matches!(
            decode_record(&unknown_format, UUID),
            Err(FsError::UnsupportedVersion)
        ));
    }

    #[test]
    fn encoder_rejects_unsupported_headers_and_oversized_transactions() {
        assert!(matches!(
            encode_unmount_record(CYCLE, 0, u32::MAX, 0, UUID, 64 * 1024, native_format(), 1),
            Err(FsError::NotSupported)
        ));

        let tx = LogTransaction {
            tid: 1,
            items: vec![item(0, 64 * 1024, 0), item(1, 64 * 1024, 0)],
            inode_items: Vec::new(),
        };
        assert!(matches!(
            encode_transaction(
                &tx,
                CYCLE,
                0,
                u32::MAX,
                0,
                UUID,
                ICLOG_SIZE,
                native_format(),
                TID
            ),
            Err(FsError::NoSpace)
        ));
        let other_format = if native_format() == XLOG_FMT_LINUX_LE {
            XLOG_FMT_LINUX_BE
        } else {
            XLOG_FMT_LINUX_LE
        };
        assert!(matches!(
            encode_transaction(
                &tx,
                CYCLE,
                0,
                u32::MAX,
                0,
                UUID,
                ICLOG_SIZE,
                other_format,
                TID
            ),
            Err(FsError::InvalidArgument)
        ));
    }
}
