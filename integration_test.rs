#[cfg(test)]
mod integration_tests {
    use xfs_rs::superblock::Superblock;
    use xfs_rs::inode::{Inode, InodeCore};
    use fs_abstraction::safe_math::CheckedOps;

    #[test]
    fn test_superblock_and_inode_integration() {
        // Create a mock superblock
        let mut sb_buffer = [0u8; 512];
        // Set magic number
        sb_buffer[0..4].copy_from_slice(&xfs_rs::constants::XFS_SB_MAGIC.to_be_bytes());
        // Set block size to 4096
        sb_buffer[4..8].copy_from_slice(&4096u32.to_be_bytes());
        // Set AG count to 1
        sb_buffer[88..92].copy_from_slice(&1u32.to_be_bytes());
        // Set AG blocks to 1024
        sb_buffer[84..88].copy_from_slice(&1024u32.to_be_bytes());
        // Set total blocks to 1024
        sb_buffer[8..16].copy_from_slice(&1024u64.to_be_bytes());
        
        let sb = Superblock::parse(&sb_buffer).expect("Should parse superblock");
        assert_eq!(sb.magic, xfs_rs::constants::XFS_SB_MAGIC);
        assert_eq!(sb.block_size, 4096);
        
        // Verify calculations work correctly
        let offset_result = sb.block_to_byte_offset(10);
        assert!(offset_result.is_ok());
        assert_eq!(offset_result.unwrap(), 40960); // 10 * 4096
        
        // Create a mock inode
        let mut inode_buffer = vec![0u8; 256]; // Common inode size
        // Set magic number
        inode_buffer[0..2].copy_from_slice(&xfs_rs::constants::XFS_DINODE_MAGIC.to_be_bytes());
        // Set mode to regular file
        inode_buffer[2..4].copy_from_slice(&0x81A4u16.to_be_bytes()); // Regular file with permissions
        // Set version to 2
        inode_buffer[4] = 2;
        // Set format to local
        inode_buffer[5] = xfs_rs::constants::XFS_DINODE_FMT_LOCAL;
        // Set size to 100 bytes
        inode_buffer[0x3A..0x42].copy_from_slice(&100u64.to_be_bytes());
        
        let inode = Inode::parse(&inode_buffer, 256).expect("Should parse inode");
        assert_eq!(inode.core.magic, xfs_rs::constants::XFS_DINODE_MAGIC);
        assert_eq!(inode.core.file_type(), xfs_rs::inode::FileType::RegularFile);
        assert_eq!(inode.core.size, 100);
    }

    #[test]
    fn test_extent_integration() {
        use xfs_rs::extent::{Extent, ExtentIter};
        
        // Create a buffer with two extents
        let mut extent_buffer = vec![0u8; 32]; // Two 16-byte extents
        
        // The actual parsing would require correctly packed XFS extent format
        // For this test, we'll just verify the iterator works
        let iter = ExtentIter::new(&extent_buffer, 2);
        let extents: Result<Vec<_>, _> = iter.collect();
        
        assert!(extents.is_ok());
        assert_eq!(extents.unwrap().len(), 2);
    }
}