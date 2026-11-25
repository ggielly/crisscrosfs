#![no_main]

use libfuzzer_sys::fuzz_target;
use xfs_rs::superblock::Superblock;

fuzz_target!(|data: &[u8]| {
    let _ = Superblock::parse(data);
});
