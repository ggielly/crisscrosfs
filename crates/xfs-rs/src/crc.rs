//! CRC32C implementation for XFS v5 metadata validation.
//!
//! XFS v5 uses CRC32C (Castagnoli polynomial) to verify metadata integrity.
//! This module uses the `crc32c` crate which provides optimized CRC32C
//! calculation with automatic hardware acceleration (SSE4.2 + PCLMULQDQ).
//!
//! Performance: ~6-7 GiB/s on modern CPUs with PCLMULQDQ support.

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

/// Zero out the CRC field in a buffer and recalculate.
///
/// # Arguments
/// * `buf` - Mutable buffer with data
/// * `crc_offset` - Offset of the 4-byte CRC field
///
/// # Returns
/// The new CRC value (also written into the buffer)
pub fn recalculate_crc(buf: &mut [u8], crc_offset: usize) -> Option<u32> {
    // Check that the offset is valid
    if crc_offset + 4 > buf.len() {
        return None;
    }

    // Zero the CRC field
    buf[crc_offset..crc_offset + 4].fill(0);

    let crc = xfs_crc32c(buf);

    // Write CRC back (big-endian for XFS)
    buf[crc_offset..crc_offset + 4].copy_from_slice(&crc.to_be_bytes());

    Some(crc)
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
    fn test_recalculate_crc() {
        let mut buf = [0u8; 16];
        buf[0..4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        let crc = recalculate_crc(&mut buf, 8).unwrap();

        // Verify CRC was written
        let stored = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);
        assert_eq!(crc, stored);
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
            let calculated = recalculate_crc(&mut sb_with_crc, offset).unwrap();

            // The CRC stored should match the calculated one
            let stored = u32::from_be_bytes([
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
        let crc2 = recalculate_crc(&mut inode_with_crc, 0x64).unwrap();

        assert_eq!(crc1, crc2);
    }
}
