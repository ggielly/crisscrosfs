#[cfg(test)]
mod corrupted_image_tests {
    use fs_abstraction::FsError;
    use xfs_rs::superblock::Superblock;

    #[test]
    fn test_corrupted_magic() {
        let mut data = vec![0u8; 512]; // Simulate a minimal buffer
                                       // Set invalid magic
        data[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        match Superblock::parse(&data) {
            Err(FsError::InvalidMagic) => {} // Expected
            _ => panic!("Expected InvalidMagic error"),
        }
    }

    #[test]
    fn test_truncated_superblock() {
        let data = vec![0x58, 0x46, 0x53, 0x42]; // Just "XFSB" magic, nothing
                                                 // else
        match Superblock::parse(&data) {
            Err(FsError::BufferTooSmall) => {} // Expected
            _ => panic!("Expected BufferTooSmall error"),
        }
    }

    #[test]
    fn test_overflow_block_count() {
        let mut data = vec![0; 512]; // Larger buffer
                                     // Set magic to valid value
        data[0..4].copy_from_slice(&0x58465342u32.to_be_bytes());
        // Set block size to valid value
        data[4..8].copy_from_slice(&4096u32.to_be_bytes());
        // Set dblocks to u64::MAX to trigger overflow
        data[8..16].copy_from_slice(&u64::MAX.to_be_bytes());

        // This should result in an error during validation
        let result = Superblock::parse(&data);
        // The exact error type may vary, but it should fail
        assert!(result.is_err());
    }
}
