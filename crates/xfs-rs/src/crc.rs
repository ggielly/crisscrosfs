//! CRC32C implementation for XFS v5 metadata validation.
//!
//! XFS v5 uses CRC32C (Castagnoli polynomial) to verify metadata integrity.
//! This module uses the `crc32c` crate which provides optimized CRC32C
//! calculation with automatic hardware acceleration (SSE4.2 + PCLMULQDQ).
//!
//! Performance: ~6-7 GiB/s on modern CPUs with PCLMULQDQ support.

use fs_abstraction::{FsError, FsResult};

/// Calculate CRC32C checksum for XFS metadata.
///
/// This function follows XFS conventions:
/// - Start with 0xFFFFFFFF (implicit in crc32c crate)
/// - Invert final result (implicit in crc32c crate)
///
/// # Arguments
/// * `data` - Byte slice to checksum
///
/// # Returns
/// The final CRC32C value as used in XFS v5 metadata
#[inline]
pub fn xfs_crc32c(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

/// Calculate CRC32C over `data` with a four-byte field treated as zero.
///
/// XFS metadata checksums exclude the contents of the stored CRC field.  This
/// helper computes the same value without modifying or allocating a copy of
/// the input buffer, which keeps the read-only parsers `no_std` friendly.
pub fn xfs_crc32c_with_zeroed_field(data: &[u8], field_offset: usize) -> Option<u32> {
    let field_end = field_offset.checked_add(4)?;
    if field_end > data.len() {
        return None;
    }

    let zero_field = [0u8; 4];
    let prefix_crc = xfs_crc32c(&data[..field_offset]);
    let after_field_crc = crc32c::crc32c_combine(prefix_crc, xfs_crc32c(&zero_field), 4);
    Some(crc32c::crc32c_combine(
        after_field_crc,
        xfs_crc32c(&data[field_end..]),
        data.len() - field_end,
    ))
}

/// Verify an XFS metadata CRC field.
///
/// `expected` is the value parsed by the caller.  Checking both it and the
/// value in `raw` prevents a stale parsed header from validating different
/// bytes.  `little_endian` must match the on-disk field definition; XFS uses
/// both byte orders depending on the metadata structure.
pub fn verify_crc32c_field(
    raw: &[u8],
    field_offset: usize,
    expected: u32,
    little_endian: bool,
) -> FsResult<()> {
    let field_end = field_offset
        .checked_add(4)
        .ok_or(FsError::ArithmeticOverflow)?;
    if field_end > raw.len() {
        return Err(FsError::BufferTooSmall);
    }

    let field = &raw[field_offset..field_end];
    let stored = if little_endian {
        u32::from_le_bytes([field[0], field[1], field[2], field[3]])
    } else {
        u32::from_be_bytes([field[0], field[1], field[2], field[3]])
    };

    let calculated =
        xfs_crc32c_with_zeroed_field(raw, field_offset).ok_or(FsError::BufferTooSmall)?;
    if stored != expected || stored != calculated {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

/// Calculate CRC32C for a superblock.
///
/// The CRC field itself must be zeroed before calculation.
///
/// # Arguments
/// * `sb_bytes` - Superblock bytes (typically 512 bytes)
pub fn superblock_crc(sb_bytes: &[u8]) -> u32 {
    xfs_crc32c(sb_bytes)
}

/// Calculate CRC32C for an inode (v3/v5).
///
/// The CRC field itself must be zeroed before calculation.
/// For v5 inodes, the CRC is calculated over the entire inode buffer
/// including the UUID (0xA0..0xB0) and inode number (0x98..0xA0).
///
/// # Arguments
/// * `inode_bytes` - Full inode bytes with CRC field zeroed
///
/// # Panics
/// Panics in debug builds if the CRC field (0x64..0x68) is not zeroed
pub fn inode_crc(inode_bytes: &[u8]) -> u32 {
    // In debug builds, verify that the CRC field is zeroed
    #[cfg(debug_assertions)]
    if inode_bytes.len() >= 0x68 {
        let crc_field = &inode_bytes[0x64..0x68];
        debug_assert_eq!(
            crc_field,
            &[0, 0, 0, 0],
            "CRC field must be zeroed before calculation"
        );
    }

    xfs_crc32c(inode_bytes)
}

/// Byte order of an on-disk XFS CRC field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrcEndian {
    /// `__le32`, used by superblock, inode and B+tree block CRCs.
    Little,
    /// `__be32`, used by AGF, AGI and dir3 CRCs.
    Big,
}

/// Zero out a CRC field and recalculate it using an explicit byte order.
///
/// # Arguments
/// * `buf` - Mutable metadata buffer
/// * `crc_offset` - Offset of the four-byte CRC field
/// * `endian` - Byte order required by the structure being updated
///
/// # Returns
/// The new CRC value, also written into `buf`, or `None` if the field is out
/// of bounds.
pub fn recalculate_crc_with_endian(
    buf: &mut [u8],
    crc_offset: usize,
    endian: CrcEndian,
) -> Option<u32> {
    let field_end = crc_offset.checked_add(4)?;
    if field_end > buf.len() {
        return None;
    }

    buf[crc_offset..field_end].fill(0);
    let crc = xfs_crc32c(buf);
    let bytes = match endian {
        CrcEndian::Little => crc.to_le_bytes(),
        CrcEndian::Big => crc.to_be_bytes(),
    };
    buf[crc_offset..field_end].copy_from_slice(&bytes);
    Some(crc)
}

/// Recalculate a little-endian (`__le32`) metadata CRC field.
///
/// This preserves the historical helper behavior for superblock, inode and
/// B+tree callers.  Use [`recalculate_crc_with_endian`] for new structure
/// specific code.
pub fn recalculate_crc(buf: &mut [u8], crc_offset: usize) -> Option<u32> {
    recalculate_crc_with_endian(buf, crc_offset, CrcEndian::Little)
}

/// Recalculate a little-endian (`__le32`) metadata CRC field.
pub fn recalculate_crc_le(buf: &mut [u8], crc_offset: usize) -> Option<u32> {
    recalculate_crc_with_endian(buf, crc_offset, CrcEndian::Little)
}

/// Recalculate a big-endian (`__be32`) metadata CRC field.
pub fn recalculate_crc_be(buf: &mut [u8], crc_offset: usize) -> Option<u32> {
    recalculate_crc_with_endian(buf, crc_offset, CrcEndian::Big)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32c_empty() {
        // CRC32C of empty data
        let crc = xfs_crc32c(&[]);
        assert_eq!(crc, 0);
    }

    #[test]
    fn test_crc32c_known_value() {
        // Test vector from iSCSI spec: "123456789" should give 0xE3069283
        let data = b"123456789";
        let crc = xfs_crc32c(data);
        assert_eq!(crc, 0xE3069283);
    }

    #[test]
    fn zeroed_field_crc_matches_buffer_copy() {
        let mut buf = [0u8; 37];
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(29).wrapping_add(7);
        }

        let calculated = xfs_crc32c_with_zeroed_field(&buf, 11).unwrap();
        buf[11..15].fill(0);
        assert_eq!(calculated, xfs_crc32c(&buf));
        assert!(xfs_crc32c_with_zeroed_field(&buf, 35).is_none());
    }

    #[test]
    fn verify_crc_field_uses_the_requested_endianness() {
        let mut raw = [0u8; 16];
        raw[..4].copy_from_slice(b"test");
        let crc = xfs_crc32c_with_zeroed_field(&raw, 8).unwrap();
        raw[8..12].copy_from_slice(&crc.to_le_bytes());
        assert!(verify_crc32c_field(&raw, 8, crc, true).is_ok());
        assert!(matches!(
            verify_crc32c_field(&raw, 8, crc, false),
            Err(FsError::Corrupted)
        ));

        raw[8..12].copy_from_slice(&crc.to_be_bytes());
        assert!(verify_crc32c_field(&raw, 8, crc, false).is_ok());
        assert!(matches!(
            verify_crc32c_field(&raw, 8, crc, true),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn test_recalculate_crc() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        let crc = recalculate_crc(&mut buf, 8).unwrap();

        // Verify CRC was written (little-endian)
        let stored = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(crc, stored);
    }

    #[test]
    fn recalculate_crc_supports_big_endian_metadata() {
        let mut buf = [0u8; 16];
        buf[..4].copy_from_slice(b"agf!");
        let crc = recalculate_crc_be(&mut buf, 8).unwrap();
        assert_eq!(u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]), crc);
        assert!(verify_crc32c_field(&buf, 8, crc, false).is_ok());

        let before = buf;
        assert!(recalculate_crc_with_endian(&mut buf, 15, CrcEndian::Big).is_none());
        assert_eq!(buf, before);
    }

    #[test]
    fn test_xfs_superblock_crc() {
        // Test with a simulated XFS superblock
        let mut sb = [0u8; 512];

        // Fill with test data
        sb[0] = b'X';
        sb[1] = b'F';
        sb[2] = b'S';
        sb[3] = b'B';

        // Calculate CRC
        let _crc = superblock_crc(&sb);

        // Verify that recalculate_crc works
        let mut sb_with_crc = sb;
        let offset = 0xE0; // Typical CRC position in XFS superblock

        if offset + 4 <= sb_with_crc.len() {
            let calculated = recalculate_crc_le(&mut sb_with_crc, offset).unwrap();

            // The CRC stored should match the calculated one
            let stored = u32::from_le_bytes([
                sb_with_crc[offset],
                sb_with_crc[offset + 1],
                sb_with_crc[offset + 2],
                sb_with_crc[offset + 3],
            ]);
            assert_eq!(calculated, stored);
        }
    }

    #[test]
    fn test_inode_crc_consistency() {
        // Simulate an XFS inode (typically 256 or 512 bytes)
        let mut inode = [0u8; 256];

        // Fill with test data
        inode[0x98..0xA0].copy_from_slice(&12345u64.to_be_bytes()); // inode number
        inode[0xA0..0xB0].copy_from_slice(&[0xAAu8; 16]); // UUID

        // Calculate CRC
        let crc1 = inode_crc(&inode);

        // Recalculate via recalculate_crc
        let mut inode_with_crc = inode;
        let crc2 = recalculate_crc_le(&mut inode_with_crc, 0x64).unwrap();

        assert_eq!(crc1, crc2);
    }
}
