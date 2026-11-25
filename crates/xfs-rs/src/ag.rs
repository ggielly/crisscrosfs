//! Allocation Group (AG) structures.
//!
//! XFS divides the filesystem into Allocation Groups, each with its own
//! headers and free space management.

extern crate alloc;

use alloc::{vec, vec::Vec};

use fs_abstraction::{safe_math::CheckedSliceOps, FsError, FsResult};

use crate::constants::*;

/// Allocation Group Free space header (AGF).
#[derive(Debug, Clone)]
pub struct AgFreeHeader {
    /// Magic number (XFS_AGF_MAGIC).
    pub magic: u32,
    /// Version (always 1).
    pub version: u32,
    /// AG sequence number.
    pub seq_number: u32,
    /// AG length in blocks.
    pub length: u32,
    /// Free space btree roots.
    pub bno_root: u32,
    pub cnt_root: u32,
    /// Reverse map btree root.
    pub rmap_root: u32,
    /// Free space btree levels.
    pub bno_level: u32,
    pub cnt_level: u32,
    /// Reverse map btree level.
    pub rmap_level: u32,
    /// Free list info.
    pub free_list_first: u32,
    pub free_list_last: u32,
    pub free_list_count: u32,
    /// Free blocks count.
    pub free_blocks: u32,
    /// Longest free extent.
    pub longest_extent: u32,
    /// Blocks used for btrees.
    pub btree_blocks: u32,

    // V5 fields.  The common header ends at 0x40; the CRC fields are near
    // the end of the fixed structure, not immediately after the v4 fields.
    /// Filesystem UUID (v5).
    pub uuid: [u8; 16],
    /// Blocks used by the reverse map btree (v5).
    pub rmap_blocks: u32,
    /// Blocks used by the refcount btree (v5).
    pub refcount_blocks: u32,
    /// Refcount btree root (v5).
    pub refcount_root: u32,
    /// Refcount btree level (v5).
    pub refcount_level: u32,
    /// Log sequence number (v5).
    pub lsn: u64,
    /// CRC of the AGF sector (v5, big-endian).
    pub crc: u32,
}

impl AgFreeHeader {
    /// Offset of the v5 CRC field.
    pub const CRC_OFFSET_V5: usize = 0xD8;
    /// Size of the legacy AGF fields.
    pub const SIZE: usize = 64;
    /// Size of the fixed v5 AGF fields.
    pub const SIZE_V5: usize = 0xE0;

    /// Parses an AGF from a byte buffer.
    ///
    /// A legacy AGF only needs the first 64 bytes.  If the complete v5 fixed
    /// structure is present, its identification and CRC fields are parsed at
    /// their canonical offsets.  Callers on v5 filesystems should additionally
    /// call [`Self::verify_crc`] with the full sector buffer.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        if buffer.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0x000)?;
        if magic != XFS_AGF_MAGIC {
            return Err(FsError::InvalidMagic);
        }
        let version = buffer.read_be_u32(0x004)?;
        if version != 1 {
            return Err(FsError::UnsupportedVersion);
        }

        let mut agf = Self {
            magic,
            version,
            seq_number: buffer.read_be_u32(0x008)?,
            length: buffer.read_be_u32(0x00C)?,
            bno_root: buffer.read_be_u32(0x010)?,
            cnt_root: buffer.read_be_u32(0x014)?,
            rmap_root: buffer.read_be_u32(0x018)?,
            bno_level: buffer.read_be_u32(0x01C)?,
            cnt_level: buffer.read_be_u32(0x020)?,
            rmap_level: buffer.read_be_u32(0x024)?,
            free_list_first: buffer.read_be_u32(0x028)?,
            free_list_last: buffer.read_be_u32(0x02C)?,
            free_list_count: buffer.read_be_u32(0x030)?,
            free_blocks: buffer.read_be_u32(0x034)?,
            longest_extent: buffer.read_be_u32(0x038)?,
            btree_blocks: buffer.read_be_u32(0x03C)?,
            uuid: [0u8; 16],
            rmap_blocks: 0,
            refcount_blocks: 0,
            refcount_root: 0,
            refcount_level: 0,
            lsn: 0,
            crc: 0,
        };

        if buffer.len() >= Self::SIZE_V5 {
            agf.uuid.copy_from_slice(&buffer[0x40..0x50]);
            agf.rmap_blocks = buffer.read_be_u32(0x50)?;
            agf.refcount_blocks = buffer.read_be_u32(0x54)?;
            agf.refcount_root = buffer.read_be_u32(0x58)?;
            agf.refcount_level = buffer.read_be_u32(0x5C)?;
            agf.lsn = buffer.read_be_u64(0xD0)?;
            // Unlike superblock/inode/btree CRCs, AGF CRC fields are __be32.
            agf.crc = buffer.read_be_u32(Self::CRC_OFFSET_V5)?;
        }

        Ok(agf)
    }

    /// Verifies a v5 AGF CRC over the complete sector supplied in `raw`.
    pub fn verify_crc(&self, raw: &[u8]) -> FsResult<()> {
        if raw.len() < 512 {
            return Err(FsError::BufferTooSmall);
        }
        crate::crc::verify_crc32c_field(raw, Self::CRC_OFFSET_V5, self.crc, false)
    }

    /// Serialize the legacy AGF header fields.
    ///
    /// This preserves the historical 64-byte return value.  V5 callers that
    /// need the identification and CRC fields should use
    /// [`Self::to_sector_bytes`].
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; Self::SIZE];
        self.write_common_fields(&mut buf);
        buf
    }

    /// Serialize a complete 512-byte AGF sector, including v5 fields.
    ///
    /// The stored CRC is serialized as-is; callers changing metadata must
    /// recalculate it with [`crate::crc::recalculate_crc_be`] before writing.
    pub fn to_sector_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 512];
        self.write_common_fields(&mut buf);
        buf[0x40..0x50].copy_from_slice(&self.uuid);
        buf[0x50..0x54].copy_from_slice(&self.rmap_blocks.to_be_bytes());
        buf[0x54..0x58].copy_from_slice(&self.refcount_blocks.to_be_bytes());
        buf[0x58..0x5C].copy_from_slice(&self.refcount_root.to_be_bytes());
        buf[0x5C..0x60].copy_from_slice(&self.refcount_level.to_be_bytes());
        buf[0xD0..0xD8].copy_from_slice(&self.lsn.to_be_bytes());
        buf[Self::CRC_OFFSET_V5..Self::CRC_OFFSET_V5 + 4].copy_from_slice(&self.crc.to_be_bytes());
        buf
    }

    fn write_common_fields(&self, buf: &mut [u8]) {
        buf[0x000..0x004].copy_from_slice(&self.magic.to_be_bytes());
        buf[0x004..0x008].copy_from_slice(&self.version.to_be_bytes());
        buf[0x008..0x00C].copy_from_slice(&self.seq_number.to_be_bytes());
        buf[0x00C..0x010].copy_from_slice(&self.length.to_be_bytes());
        buf[0x010..0x014].copy_from_slice(&self.bno_root.to_be_bytes());
        buf[0x014..0x018].copy_from_slice(&self.cnt_root.to_be_bytes());
        buf[0x018..0x01C].copy_from_slice(&self.rmap_root.to_be_bytes());
        buf[0x01C..0x020].copy_from_slice(&self.bno_level.to_be_bytes());
        buf[0x020..0x024].copy_from_slice(&self.cnt_level.to_be_bytes());
        buf[0x024..0x028].copy_from_slice(&self.rmap_level.to_be_bytes());
        buf[0x028..0x02C].copy_from_slice(&self.free_list_first.to_be_bytes());
        buf[0x02C..0x030].copy_from_slice(&self.free_list_last.to_be_bytes());
        buf[0x030..0x034].copy_from_slice(&self.free_list_count.to_be_bytes());
        buf[0x034..0x038].copy_from_slice(&self.free_blocks.to_be_bytes());
        buf[0x038..0x03C].copy_from_slice(&self.longest_extent.to_be_bytes());
        buf[0x03C..0x040].copy_from_slice(&self.btree_blocks.to_be_bytes());
    }
}

/// Allocation Group Inode header (AGI).
#[derive(Debug, Clone)]
pub struct AgInodeHeader {
    /// Magic number (XFS_AGI_MAGIC).
    pub magic: u32,
    /// Version.
    pub version: u32,
    /// AG sequence number.
    pub seq_number: u32,
    /// AG length in blocks.
    pub length: u32,
    /// Total count of inodes allocated in this AG.
    pub inode_count: u32,
    /// Root of inode B+tree.
    pub inode_root: u32,
    /// Level of inode B+tree.
    pub inode_level: u32,
    /// Number of free inodes in this AG.
    pub free_inode_count: u32,
    /// Most recently allocated inode (AG-relative).
    pub recent_inode: u32,
    /// Most recently allocated directory inode (AG-relative).
    pub dir_inode: u32,
    /// Unlinked inode hash table.
    pub unlinked: [u32; 64],

    // V5 fields
    /// CRC checksum (v5).
    pub crc: u32,
    /// Log sequence number (v5).
    pub lsn: u64,
    /// UUID (v5).
    pub uuid: [u8; 16],
    /// Free inode B+tree root (v5).
    pub free_inode_root: u32,
    /// Free inode B+tree level (v5).
    pub free_inode_level: u32,
}

impl AgInodeHeader {
    /// Offset of the v5 CRC field.
    pub const CRC_OFFSET_V5: usize = 0x138;
    /// Size of an AGI sector on disk.
    pub const SIZE: usize = 512;
    /// Size of the fixed v5 AGI fields.
    pub const SIZE_V5: usize = 0x150;

    /// Parses an AGI from a byte buffer.
    pub fn parse(buffer: &[u8]) -> FsResult<Self> {
        // The unlinked hash table ends at 0x128, so even a legacy AGI needs
        // that many bytes.
        if buffer.len() < 0x128 {
            return Err(FsError::BufferTooSmall);
        }

        let magic = buffer.read_be_u32(0x000)?;
        if magic != XFS_AGI_MAGIC {
            return Err(FsError::InvalidMagic);
        }

        let mut unlinked = [0u32; 64];
        for (index, entry) in unlinked.iter_mut().enumerate() {
            *entry = buffer.read_be_u32(0x028 + index * 4)?;
        }

        let version = buffer.read_be_u32(0x004)?;
        if version != 1 {
            return Err(FsError::UnsupportedVersion);
        }

        let mut agi = Self {
            magic,
            version,
            seq_number: buffer.read_be_u32(0x008)?,
            length: buffer.read_be_u32(0x00C)?,
            inode_count: buffer.read_be_u32(0x010)?,
            inode_root: buffer.read_be_u32(0x014)?,
            inode_level: buffer.read_be_u32(0x018)?,
            free_inode_count: buffer.read_be_u32(0x01C)?,
            recent_inode: buffer.read_be_u32(0x020)?,
            dir_inode: buffer.read_be_u32(0x024)?,
            unlinked,
            crc: 0,
            lsn: 0,
            uuid: [0u8; 16],
            free_inode_root: 0,
            free_inode_level: 0,
        };

        // V5 layout: uuid at 0x128, crc (__be32) at 0x138,
        // lsn at 0x140, finobt root/level at 0x148/0x14C.
        if buffer.len() >= Self::SIZE_V5 {
            agi.uuid.copy_from_slice(&buffer[0x128..0x138]);
            agi.crc = buffer.read_be_u32(Self::CRC_OFFSET_V5)?;
            agi.lsn = buffer.read_be_u64(0x140)?;
            agi.free_inode_root = buffer.read_be_u32(0x148)?;
            agi.free_inode_level = buffer.read_be_u32(0x14C)?;
        }

        Ok(agi)
    }

    /// Verifies a v5 AGI CRC over the complete sector supplied in `raw`.
    pub fn verify_crc(&self, raw: &[u8]) -> FsResult<()> {
        if raw.len() < Self::SIZE {
            return Err(FsError::BufferTooSmall);
        }
        crate::crc::verify_crc32c_field(raw, Self::CRC_OFFSET_V5, self.crc, false)
    }

    /// Serialize AGI header to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; 512]; // Sector size
        buf[0x000..0x004].copy_from_slice(&self.magic.to_be_bytes());
        buf[0x004..0x008].copy_from_slice(&self.version.to_be_bytes());
        buf[0x008..0x00C].copy_from_slice(&self.seq_number.to_be_bytes());
        buf[0x00C..0x010].copy_from_slice(&self.length.to_be_bytes());
        buf[0x010..0x014].copy_from_slice(&self.inode_count.to_be_bytes());
        buf[0x014..0x018].copy_from_slice(&self.inode_root.to_be_bytes());
        buf[0x018..0x01C].copy_from_slice(&self.inode_level.to_be_bytes());
        buf[0x01C..0x020].copy_from_slice(&self.free_inode_count.to_be_bytes());
        buf[0x020..0x024].copy_from_slice(&self.recent_inode.to_be_bytes());
        buf[0x024..0x028].copy_from_slice(&self.dir_inode.to_be_bytes());

        for i in 0..64 {
            buf[0x028 + i * 4..0x02C + i * 4].copy_from_slice(&self.unlinked[i].to_be_bytes());
        }

        // V5 layout (uuid at 0x128, crc __be32 at 0x138, lsn at 0x140).
        buf[0x128..0x138].copy_from_slice(&self.uuid);
        buf[Self::CRC_OFFSET_V5..Self::CRC_OFFSET_V5 + 4].copy_from_slice(&self.crc.to_be_bytes());
        buf[0x140..0x148].copy_from_slice(&self.lsn.to_be_bytes());
        buf[0x148..0x14C].copy_from_slice(&self.free_inode_root.to_be_bytes());
        buf[0x14C..0x150].copy_from_slice(&self.free_inode_level.to_be_bytes());
        buf
    }
}

/// Offsets within an AG for common structures.
pub struct AgOffsets;

impl AgOffsets {
    /// AGF follows superblock (1 sector).
    pub const AGF: u64 = 1;
    /// AGFL follows AGI (3 sectors).
    pub const AGFL: u64 = 3;
    /// AGI follows AGF (2 sectors).
    pub const AGI: u64 = 2;
    /// Superblock is at offset 0.
    pub const SUPERBLOCK: u64 = 0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agf_fields_are_read_at_real_offsets() {
        let mut buf = vec![0u8; 512];
        buf[0x000..0x004].copy_from_slice(&XFS_AGF_MAGIC.to_be_bytes());
        buf[0x004..0x008].copy_from_slice(&1u32.to_be_bytes());
        buf[0x008..0x00C].copy_from_slice(&0u32.to_be_bytes()); // seqno
        buf[0x00C..0x010].copy_from_slice(&1024u32.to_be_bytes()); // length
        buf[0x010..0x014].copy_from_slice(&3u32.to_be_bytes()); // bno_root
        buf[0x014..0x018].copy_from_slice(&4u32.to_be_bytes()); // cnt_root
        buf[0x018..0x01C].copy_from_slice(&5u32.to_be_bytes()); // rmap_root
        buf[0x01C..0x020].copy_from_slice(&1u32.to_be_bytes()); // bno_level
        buf[0x020..0x024].copy_from_slice(&1u32.to_be_bytes()); // cnt_level
        buf[0x028..0x02C].copy_from_slice(&7u32.to_be_bytes()); // flfirst
        buf[0x02C..0x030].copy_from_slice(&8u32.to_be_bytes()); // fllast
        buf[0x030..0x034].copy_from_slice(&9u32.to_be_bytes()); // flcount
        buf[0x034..0x038].copy_from_slice(&100u32.to_be_bytes()); // freeblks
        buf[0x038..0x03C].copy_from_slice(&50u32.to_be_bytes()); // longest
        buf[0x03C..0x040].copy_from_slice(&10u32.to_be_bytes()); // btreeblks

        let agf = AgFreeHeader::parse(&buf).unwrap();
        assert_eq!(agf.bno_root, 3);
        assert_eq!(agf.cnt_root, 4);
        assert_eq!(agf.rmap_root, 5);
        assert_eq!(agf.bno_level, 1);
        assert_eq!(agf.cnt_level, 1);
        assert_eq!(agf.free_list_first, 7);
        assert_eq!(agf.free_blocks, 100);
        assert_eq!(agf.btree_blocks, 10);

        let roundtrip = agf.to_bytes();
        assert_eq!(roundtrip.len(), AgFreeHeader::SIZE);
        assert_eq!(&roundtrip[..0x40], &buf[..0x40]);
    }

    #[test]
    fn agi_v5_fields_are_read_at_real_offsets() {
        let mut buf = vec![0u8; 512];
        buf[0x000..0x004].copy_from_slice(&XFS_AGI_MAGIC.to_be_bytes());
        buf[0x004..0x008].copy_from_slice(&1u32.to_be_bytes());
        buf[0x128..0x138].copy_from_slice(&[0xAA; 16]); // uuid
        buf[0x138..0x13C].copy_from_slice(&0x11223344u32.to_be_bytes()); // crc
        buf[0x140..0x148].copy_from_slice(&99u64.to_be_bytes()); // lsn
        buf[0x148..0x14C].copy_from_slice(&6u32.to_be_bytes()); // finobt root
        buf[0x14C..0x150].copy_from_slice(&2u32.to_be_bytes()); // finobt level

        let agi = AgInodeHeader::parse(&buf).unwrap();
        assert_eq!(agi.uuid, [0xAA; 16]);
        assert_eq!(agi.crc, 0x11223344);
        assert_eq!(agi.lsn, 99);
        assert_eq!(agi.free_inode_root, 6);
        assert_eq!(agi.free_inode_level, 2);
    }

    #[test]
    fn agf_v5_offsets_and_crc_are_verified() {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&XFS_AGF_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[0x24..0x28].copy_from_slice(&3u32.to_be_bytes());
        buf[0x40..0x50].copy_from_slice(&[0x5A; 16]);
        buf[0x50..0x54].copy_from_slice(&11u32.to_be_bytes());
        buf[0x54..0x58].copy_from_slice(&12u32.to_be_bytes());
        buf[0x58..0x5C].copy_from_slice(&13u32.to_be_bytes());
        buf[0x5C..0x60].copy_from_slice(&14u32.to_be_bytes());
        buf[0xD0..0xD8].copy_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
        let crc = crate::crc::recalculate_crc_be(&mut buf, AgFreeHeader::CRC_OFFSET_V5).unwrap();

        let agf = AgFreeHeader::parse(&buf).unwrap();
        assert_eq!(agf.rmap_level, 3);
        assert_eq!(agf.uuid, [0x5A; 16]);
        assert_eq!(agf.rmap_blocks, 11);
        assert_eq!(agf.refcount_blocks, 12);
        assert_eq!(agf.refcount_root, 13);
        assert_eq!(agf.refcount_level, 14);
        assert_eq!(agf.lsn, 0x1122_3344_5566_7788);
        assert_eq!(agf.crc, crc);
        assert_eq!(agf.to_sector_bytes(), buf);
        assert!(agf.verify_crc(&buf).is_ok());

        let mut corrupted = buf;
        corrupted[0x40] ^= 1;
        assert!(matches!(
            agf.verify_crc(&corrupted),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn agi_v5_crc_is_big_endian_at_0x138() {
        let mut buf = vec![0u8; 512];
        buf[0..4].copy_from_slice(&XFS_AGI_MAGIC.to_be_bytes());
        buf[4..8].copy_from_slice(&1u32.to_be_bytes());
        buf[0x128..0x138].copy_from_slice(&[0xA5; 16]);
        let crc = crate::crc::recalculate_crc_be(&mut buf, AgInodeHeader::CRC_OFFSET_V5).unwrap();

        let agi = AgInodeHeader::parse(&buf).unwrap();
        assert_eq!(agi.crc, crc);
        assert!(agi.verify_crc(&buf).is_ok());

        let mut corrupted = buf;
        corrupted[0x128] ^= 1;
        assert!(matches!(
            agi.verify_crc(&corrupted),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn ag_headers_reject_unknown_versions() {
        let mut agf = vec![0u8; AgFreeHeader::SIZE];
        agf[0..4].copy_from_slice(&XFS_AGF_MAGIC.to_be_bytes());
        agf[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert!(matches!(
            AgFreeHeader::parse(&agf),
            Err(FsError::UnsupportedVersion)
        ));

        let mut agi = vec![0u8; 0x128];
        agi[0..4].copy_from_slice(&XFS_AGI_MAGIC.to_be_bytes());
        agi[4..8].copy_from_slice(&2u32.to_be_bytes());
        assert!(matches!(
            AgInodeHeader::parse(&agi),
            Err(FsError::UnsupportedVersion)
        ));
    }
}
