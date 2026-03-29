// fuzz_targets/superblock_fuzz.rs
// Fuzzing harness for XFS superblock parsing

#![no_main]
use libfuzzer_sys::fuzz_target;

use xfs_rs::superblock::Superblock;

fuzz_target!(|data: &[u8]| {
    // The parser should never panic, regardless of input
    let _ = Superblock::parse(data);
});