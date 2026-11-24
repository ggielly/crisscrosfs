#[cfg(test)]
mod integration_tests {
    use xfs_rs::inode::Inode;
    use xfs_rs::superblock::Superblock;

    #[test]
    fn test_superblock_and_inode_integration() {
        // Build a minimally valid XFS v4 superblock.
        let mut sb_buffer = [0u8; 512];
        sb_buffer[0..4].copy_from_slice(&xfs_rs::constants::XFS_SB_MAGIC.to_be_bytes());
        sb_buffer[4..8].copy_from_slice(&4096u32.to_be_bytes()); // block size
        sb_buffer[8..16].copy_from_slice(&1024u64.to_be_bytes()); // total blocks
        sb_buffer[0x54..0x58].copy_from_slice(&1024u32.to_be_bytes()); // ag blocks
        sb_buffer[0x58..0x5C].copy_from_slice(&1u32.to_be_bytes()); // ag count
        sb_buffer[0x64..0x66].copy_from_slice(&4u16.to_be_bytes()); // version
        sb_buffer[0x66..0x68].copy_from_slice(&512u16.to_be_bytes()); // sector size
        sb_buffer[0x68..0x6A].copy_from_slice(&256u16.to_be_bytes()); // inode size
        sb_buffer[0x6A..0x6C].copy_from_slice(&16u16.to_be_bytes()); // inodes/block
        sb_buffer[0x78] = 12; // block_log
        sb_buffer[0x79] = 9; // sector_log
        sb_buffer[0x7A] = 8; // inode_log
        sb_buffer[0x7B] = 4; // inode_per_block_log
        sb_buffer[0x7C] = 10; // ag_block_log

        let sb = Superblock::parse(&sb_buffer).expect("Should parse superblock");
        assert_eq!(sb.magic, xfs_rs::constants::XFS_SB_MAGIC);
        assert_eq!(sb.block_size, 4096);

        // Verify calculations work correctly.
        let offset_result = sb.block_to_byte_offset(10);
        assert!(offset_result.is_ok());
        assert_eq!(offset_result.unwrap(), 40960); // 10 * 4096

        // Create a minimal v2 local-format inode.
        let mut inode_buffer = vec![0u8; 256];
        inode_buffer[0..2].copy_from_slice(&xfs_rs::constants::XFS_DINODE_MAGIC.to_be_bytes());
        inode_buffer[2..4].copy_from_slice(&0x81A4u16.to_be_bytes()); // regular file
        inode_buffer[4] = 2; // inode version
        inode_buffer[5] = xfs_rs::constants::XFS_DINODE_FMT_LOCAL;
        inode_buffer[0x38..0x40].copy_from_slice(&100u64.to_be_bytes()); // size

        let inode = Inode::parse(&inode_buffer, 256).expect("Should parse inode");
        assert_eq!(inode.core.magic, xfs_rs::constants::XFS_DINODE_MAGIC);
        assert_eq!(inode.core.file_type(), xfs_rs::inode::FileType::RegularFile);
        assert_eq!(inode.core.size, 100);
    }

    #[test]
    fn test_extent_integration() {
        use xfs_rs::extent::{Extent, ExtentIter};

        // Create a buffer with two extents.
        let extent_buffer = vec![0u8; 32];

        let iter = ExtentIter::new(&extent_buffer, 2);
        let extents: Result<Vec<_>, _> = iter.collect();

        assert!(extents.is_ok());
        assert_eq!(extents.unwrap().len(), 2);

        // Round-trip a known extent through the packed on-disk format.
        let extent = Extent {
            file_offset: 123,
            start_block: 456,
            block_count: 7,
            is_unwritten: true,
        };
        let parsed = Extent::parse(&extent.to_bytes()).unwrap();
        assert_eq!(parsed, extent);
    }
}
