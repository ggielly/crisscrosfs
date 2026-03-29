use proptest::prelude::*;
use xfs_rs::{
    freespace::{AllocBtreeBlock, AllocKey, AllocPtr, AllocRec},
    superblock::Superblock,
};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn superblock_parse_never_panics(data: Vec<u8>) {
        // The parser should never panic, regardless of input
        let _ = Superblock::parse(&data);
    }

    #[test]
    fn inode_parse_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        // Parse with a default inode size of 256 bytes
        let _ = xfs_rs::inode::Inode::parse(&data, 256);
    }

    // ── Allocator B+tree parsers must never panic ─────────────────────────
    // These parsers are called on untrusted on-disk data along write paths;
    // panicking on malformed input would be a DoS.

    #[test]
    fn alloc_rec_parse_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..64)
    ) {
        let _ = AllocRec::parse(&data);
    }

    #[test]
    fn alloc_key_parse_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..64)
    ) {
        let _ = AllocKey::parse(&data);
    }

    #[test]
    fn alloc_ptr_parse_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..64)
    ) {
        let _ = AllocPtr::parse(&data);
    }

    #[test]
    fn alloc_btree_block_parse_v4_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = AllocBtreeBlock::parse(&data, false);
    }

    #[test]
    fn alloc_btree_block_parse_v5_never_panics(
        data in proptest::collection::vec(any::<u8>(), 0..4096)
    ) {
        let _ = AllocBtreeBlock::parse(&data, true);
    }
}