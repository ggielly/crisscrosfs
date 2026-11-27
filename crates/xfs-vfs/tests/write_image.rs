//! Writable-image regression tests against a disposable copy of the real XFS
//! fixture. The committed fixture is never modified.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use fs_abstraction::{BlockDevice, FsError, FsResult, VfsFileSystem, VfsFileType};
use xfs_rs::btree::BlockReader;
use xfs_vfs::XfsVfs;

struct FileDevice {
    file: Mutex<File>,
    size: u64,
}

impl FileDevice {
    fn open(path: &Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let size = file.metadata()?.len();
        Ok(Self {
            file: Mutex::new(file),
            size,
        })
    }
}

impl BlockDevice for FileDevice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| FsError::DiskError)?;
        file.read(buf).map_err(|_| FsError::DiskError)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> FsResult<usize> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(offset))
            .map_err(|_| FsError::DiskError)?;
        file.write(data).map_err(|_| FsError::DiskError)
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn supports_write(&self) -> bool {
        true
    }

    fn flush(&self) -> FsResult<()> {
        self.file
            .lock()
            .unwrap()
            .sync_all()
            .map_err(|_| FsError::DiskError)
    }
}

fn fixture_path() -> Option<PathBuf> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-images")
        .join("xfs-16M.img");
    fixture.is_file().then_some(fixture)
}

/// Open a disposable fixture for writing. Modern mkfs.xfs enables features
/// such as RMAPBT that are safe for reads but deliberately unsupported by the
/// experimental writer; those fixtures exercise the rejection path instead.
fn open_writable_fixture(path: &Path) -> Option<XfsVfs> {
    let device = Arc::new(FileDevice::open(path).unwrap());
    match XfsVfs::with_options(device, false) {
        Ok(fs) => Some(fs),
        Err(FsError::NotSupported) => {
            eprintln!(
                "fixture uses XFS features the experimental writer refuses (for example \
                 reflink/refcount); skipping writable test"
            );
            None
        }
        Err(error) => panic!("writable XFS mount: {error:?}"),
    }
}

#[test]
fn writable_mount_rejects_rmapbt_fixture() {
    let Some(fixture) = fixture_path() else {
        return;
    };
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(fixture, temp.path()).unwrap();
    let device = Arc::new(FileDevice::open(temp.path()).unwrap());
    let mut probe = [0u8; 512];
    read_device_exact(device.as_ref(), 0, &mut probe);
    let ro_compat = u32::from_be_bytes([probe[0xD4], probe[0xD5], probe[0xD6], probe[0xD7]]);
    if ro_compat & xfs_rs::constants::XFS_SB_FEAT_RO_COMPAT_RMAPBT == 0 {
        return;
    }
    assert!(XfsVfs::read_only(device.clone()).is_ok());
    assert!(matches!(
        XfsVfs::with_options(device, false),
        Err(FsError::NotSupported)
    ));
}

fn resolve(fs: &XfsVfs, path: &str) -> u64 {
    fs.resolve_path(path)
        .unwrap_or_else(|error| panic!("resolve {path:?}: {error:?}"))
}

fn read_all(fs: &XfsVfs, ino: u64, size: u64) -> Vec<u8> {
    let mut data = vec![0u8; size as usize];
    let mut done = 0usize;
    while done < data.len() {
        let count = fs.read(ino, done as u64, &mut data[done..]).unwrap();
        assert!(count > 0);
        done += count;
    }
    data
}

fn read_device_exact(device: &FileDevice, mut offset: u64, mut buf: &mut [u8]) {
    while !buf.is_empty() {
        let count = device.read_at(offset, buf).unwrap();
        assert!(count > 0);
        offset += count as u64;
        buf = &mut buf[count..];
    }
}

struct FixtureBlockReader<'a> {
    device: &'a FileDevice,
    block_size: u64,
}

impl xfs_rs::btree::BlockReader for FixtureBlockReader<'_> {
    fn read_block(&self, block: u64) -> FsResult<Vec<u8>> {
        let mut raw = vec![0u8; self.block_size as usize];
        read_device_exact(self.device, block * self.block_size, &mut raw);
        Ok(raw)
    }
}

#[test]
fn real_node_directory_headers_match_the_writer_layout() -> FsResult<()> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-images")
        .join("xfs-300M.img");
    if !fixture.is_file() {
        eprintln!("large real XFS fixture unavailable; skipping");
        return Ok(());
    }
    let mut probe = [0u8; 512];
    let probe_device = FileDevice::open(&fixture).unwrap();
    read_device_exact(&probe_device, 0, &mut probe);
    let device = Arc::new(probe_device);
    let fs = match XfsVfs::read_only(device.clone()) {
        Ok(fs) => fs,
        Err(FsError::NotSupported) => {
            eprintln!("large fixture uses an unsupported XFS feature; skipping");
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let ino = resolve(&fs, "/many");
    let sb = fs.superblock();
    assert!(sb.is_v5());
    let block_size = u64::from(sb.block_size);
    let shift = u32::from(sb.ag_block_log) + u32::from(sb.inode_per_block_log);
    let ag = ino >> shift;
    let ag_ino = ino & ((1u64 << shift) - 1);
    let inode_block = ag * u64::from(sb.ag_blocks) + (ag_ino >> sb.inode_per_block_log);
    let inode_in_block = ag_ino & ((1u64 << sb.inode_per_block_log) - 1);
    let inode_offset = inode_block * block_size + inode_in_block * u64::from(sb.inode_size);
    let mut raw_inode = vec![0u8; sb.inode_size as usize];
    read_device_exact(&device, inode_offset, &mut raw_inode);
    let inode = xfs_rs::Inode::parse(&raw_inode, sb.inode_size as usize).unwrap();
    let reader = FixtureBlockReader {
        device: &device,
        block_size,
    };
    let extents = inode.collect_extents(&reader, true).unwrap();
    let block_for = |logical: u64| -> FsResult<u64> {
        extents
            .iter()
            .find(|extent| extent.contains_file_block(logical))
            .ok_or_else(|| {
                eprintln!("no extent for logical block {logical}");
                FsError::Corrupted
            })?
            .translate(logical)
    };

    let leaf_offset = (1u64 << 35) / block_size;
    let free_offset = (1u64 << 36) / block_size;
    let root = reader.read_block(block_for(leaf_offset)?)?;
    assert_eq!(
        u16::from_be_bytes([root[8], root[9]]),
        xfs_rs::constants::XFS_DIR3_NODE_MAGIC
    );
    let leaf_count = u16::from_be_bytes([root[56], root[57]]) as usize;
    assert_eq!(u16::from_be_bytes([root[58], root[59]]), 1);
    assert!(leaf_count > 1);
    let logicals: Vec<u64> = (0..leaf_count)
        .map(|index| {
            let entry_offset = 64 + index * 8;
            u32::from_be_bytes([
                root[entry_offset + 4],
                root[entry_offset + 5],
                root[entry_offset + 6],
                root[entry_offset + 7],
            ]) as u64
        })
        .collect();
    let mut indexed_entries = 0usize;
    let mut leaf_heads = 0usize;
    let mut leaf_tails = 0usize;
    for (index, &logical) in logicals.iter().enumerate() {
        let entry_offset = 64 + index * 8;
        let max_hash = u32::from_be_bytes([
            root[entry_offset],
            root[entry_offset + 1],
            root[entry_offset + 2],
            root[entry_offset + 3],
        ]);
        assert!(logical > leaf_offset);
        let leaf = reader.read_block(block_for(logical)?)?;
        assert_eq!(
            u16::from_be_bytes([leaf[8], leaf[9]]),
            xfs_rs::constants::XFS_DIR3_LEAFN_MAGIC
        );
        let count = u16::from_be_bytes([leaf[56], leaf[57]]) as usize;
        assert!(count > 0);
        let last = 64 + (count - 1) * 8;
        let last_hash =
            u32::from_be_bytes([leaf[last], leaf[last + 1], leaf[last + 2], leaf[last + 3]]);
        assert_eq!(max_hash, last_hash);
        let previous = u32::from_be_bytes([leaf[0], leaf[1], leaf[2], leaf[3]]);
        let next = u32::from_be_bytes([leaf[4], leaf[5], leaf[6], leaf[7]]);
        if previous == 0 {
            leaf_heads += 1;
        } else {
            assert!(logicals.contains(&u64::from(previous)));
        }
        if next == 0 {
            leaf_tails += 1;
        } else {
            assert!(logicals.contains(&u64::from(next)));
        }
        indexed_entries += count;
    }
    assert_eq!(leaf_heads, 1);
    assert_eq!(leaf_tails, 1);
    assert_eq!(fs.readdir(ino).unwrap().len() + 2, indexed_entries);

    let free = reader.read_block(block_for(free_offset)?)?;
    assert_eq!(
        u32::from_be_bytes([free[0], free[1], free[2], free[3]]),
        xfs_rs::constants::XFS_DIR3_FREE_MAGIC
    );
    let data_blocks = extents
        .iter()
        .filter(|extent| extent.file_offset < leaf_offset)
        .try_fold(0u64, |sum, extent| {
            sum.checked_add(u64::from(extent.block_count))
                .ok_or(FsError::ArithmeticOverflow)
        })?;
    assert_eq!(
        u32::from_be_bytes([free[48], free[49], free[50], free[51]]),
        0
    );
    assert_eq!(
        u32::from_be_bytes([free[52], free[53], free[54], free[55]]),
        data_blocks as u32
    );
    assert_eq!(
        u32::from_be_bytes([free[56], free[57], free[58], free[59]]),
        data_blocks as u32
    );
    assert_eq!(
        u32::from_be_bytes([free[60], free[61], free[62], free[63]]),
        0
    );
    Ok(())
}

#[test]
fn persistent_allocator_deltas_are_not_reapplied_by_later_transactions() {
    let Some(fixture) = fixture_path() else {
        return;
    };
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(fixture, temp.path()).unwrap();
    let Some(fs) = open_writable_fixture(temp.path()) else {
        return;
    };

    let root = fs.root_inode();
    let before = fs.get_volume_info().unwrap();
    let first = fs.create_file(root, "delta-first.txt", 0o644).unwrap();
    let after_first = fs.get_volume_info().unwrap();
    assert_eq!(after_first.free_inodes + 1, before.free_inodes);

    let second = fs.create_file(root, "delta-second.txt", 0o644).unwrap();
    let after_second = fs.get_volume_info().unwrap();
    assert_eq!(after_second.free_inodes + 2, before.free_inodes);
    assert_eq!(after_second.free_inodes + 1, after_first.free_inodes);

    fs.unlink(root, "delta-first.txt", first.ino).unwrap();
    fs.unlink(root, "delta-second.txt", second.ino).unwrap();
    let after_unlink = fs.get_volume_info().unwrap();
    assert_eq!(after_unlink.free_inodes, before.free_inodes);
}

#[test]
fn delalloc_read_flush_truncate_and_atomic_append() {
    let Some(fixture) = fixture_path() else {
        return;
    };
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(fixture, temp.path()).unwrap();
    let Some(fs) = open_writable_fixture(temp.path()) else {
        return;
    };
    let fs = Arc::new(fs);
    let root = fs.root_inode();
    let created = fs.create_file(root, "delalloc.txt", 0o644).unwrap();

    fs.write(created.ino, 0, b"abc").unwrap();
    fs.write(created.ino, 5, b"xy").unwrap();
    assert_eq!(fs.stat(created.ino).unwrap().size, 7);
    assert_eq!(read_all(&fs, created.ino, 7), b"abc\0\0xy");

    let mut threads = Vec::new();
    for index in 1..=8u8 {
        let fs = fs.clone();
        threads.push(std::thread::spawn(move || {
            let data = vec![index; 1024];
            fs.append_with_info(created.ino, &data)
                .map(|(written, info)| {
                    assert_eq!(written, data.len());
                    info.size
                })
        }));
    }
    let mut reported_sizes = Vec::new();
    for thread in threads {
        reported_sizes.push(thread.join().unwrap().unwrap());
    }
    reported_sizes.sort_unstable();
    assert_eq!(reported_sizes[0], 7 + 1024);
    assert_eq!(reported_sizes.last(), Some(&(7 + 8 * 1024)));
    assert_eq!(fs.stat(created.ino).unwrap().size, 7 + 8 * 1024);

    let appended = read_all(&fs, created.ino, 7 + 8 * 1024);
    assert_eq!(&appended[..7], b"abc\0\0xy");
    for index in 1..=8u8 {
        assert_eq!(
            appended[7 + (index as usize - 1) * 1024..7 + index as usize * 1024]
                .iter()
                .filter(|&&byte| byte == index)
                .count(),
            1024
        );
    }

    fs.flush_file(created.ino).unwrap();
    assert_eq!(read_all(&fs, created.ino, appended.len() as u64), appended);
    fs.append(created.ino, b"tail").unwrap();
    fs.set_size(created.ino, 10).unwrap();
    assert_eq!(fs.stat(created.ino).unwrap().size, 10);
    assert_eq!(read_all(&fs, created.ino, 10), &appended[..10]);
    fs.append(created.ino, b"Z").unwrap();
    assert_eq!(fs.stat(created.ino).unwrap().size, 11);
    fs.flush_file(created.ino).unwrap();

    fs.shutdown().unwrap();
    drop(fs);
    let reopened = XfsVfs::read_only(Arc::new(FileDevice::open(temp.path()).unwrap())).unwrap();
    assert_eq!(reopened.stat(created.ino).unwrap().size, 11);
    let mut final_byte = [0u8; 1];
    assert_eq!(reopened.read(created.ino, 10, &mut final_byte).unwrap(), 1);
    assert_eq!(final_byte, *b"Z");
}

#[test]
fn large_write_is_flushed_past_the_per_file_delalloc_cap() {
    let Some(fixture) = fixture_path() else {
        return;
    };
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(fixture, temp.path()).unwrap();
    let Some(fs) = open_writable_fixture(temp.path()) else {
        return;
    };
    let fs = Arc::new(fs);
    let created = fs.create_file(fs.root_inode(), "big.bin", 0o644).unwrap();

    // Six MiB in one call: a single chunk stays under the cap, so only the
    // cumulative budget can force an intermediate delalloc flush.
    const SIZE: usize = 6 * 1024 * 1024;
    let data: Vec<u8> = (0..SIZE).map(|index| (index % 251) as u8).collect();
    let (written, info) = fs.write_with_info(created.ino, 0, &data).unwrap();
    assert_eq!(written, SIZE);
    assert_eq!(info.size, SIZE as u64);

    fs.flush_file(created.ino).unwrap();
    let on_disk = read_all(&fs, created.ino, SIZE as u64);
    assert_eq!(on_disk.len(), SIZE);
    assert_eq!(on_disk, data);

    fs.shutdown().unwrap();
    drop(fs);

    let reopened = XfsVfs::read_only(Arc::new(FileDevice::open(temp.path()).unwrap())).unwrap();
    assert_eq!(reopened.stat(created.ino).unwrap().size, SIZE as u64);
    let mut tail = vec![0u8; 4096];
    let tail_offset = (SIZE - tail.len()) as u64;
    assert_eq!(
        reopened.read(created.ino, tail_offset, &mut tail).unwrap(),
        tail.len()
    );
    assert_eq!(tail, &data[SIZE - tail.len()..]);
}

#[test]
fn writable_image_overwrites_inline_and_extent_files_and_recovers_cleanly() {
    let Some(fixture) = fixture_path() else {
        eprintln!("real XFS fixture unavailable; skipping");
        return;
    };
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(fixture, temp.path()).unwrap();

    let Some(fs) = open_writable_fixture(temp.path()) else {
        return;
    };
    assert!(!fs.capabilities().read_only);

    let hello = resolve(&fs, "/hello.txt");
    assert_eq!(fs.write(hello, 0, b"Written by Rust\n").unwrap(), 16);
    assert_eq!(read_all(&fs, hello, 16), b"Written by Rust\n");

    let exact = resolve(&fs, "/data/exact-4096.bin");
    let mut replacement_data = vec![0x5Au8; 4096];
    replacement_data[17] = 0xA5;
    assert_eq!(fs.write(exact, 0, &replacement_data).unwrap(), 4096);
    assert_eq!(read_all(&fs, exact, 4096), replacement_data);

    fs.set_size(hello, 8).unwrap();
    assert_eq!(read_all(&fs, hello, 8), b"Written ");
    fs.set_size(exact, 8192).unwrap();
    let extended = read_all(&fs, exact, 8192);
    assert_eq!(&extended[..4096], &replacement_data);
    assert!(extended[4096..].iter().all(|byte| *byte == 0));
    fs.set_size(hello, 16).unwrap();
    fs.write(hello, 0, b"Written by Rust\n").unwrap();

    let empty_dir = resolve(&fs, "/empty-dir");
    let free_inodes_before = fs.get_volume_info().unwrap().free_inodes;
    let created = fs.create_file(empty_dir, "new.txt", 0o644).unwrap();
    assert_eq!(
        fs.get_volume_info().unwrap().free_inodes + 1,
        free_inodes_before
    );
    let timestamp = fs_abstraction::VfsTimestamp {
        secs: 1_600_000_000,
        nsecs: 123_456_789,
    };
    fs.set_times(created.ino, Some(timestamp), Some(timestamp))
        .unwrap();
    assert_eq!(fs.stat(created.ino).unwrap().atime, timestamp);
    fs.write(created.ino, 0, b"created\n").unwrap();
    assert_eq!(read_all(&fs, created.ino, 8), b"created\n");
    fs.set_size(created.ino, 600).unwrap();
    let converted = read_all(&fs, created.ino, 600);
    assert_eq!(&converted[..8], b"created\n");
    assert!(converted[8..].iter().all(|byte| *byte == 0));
    assert_eq!(resolve(&fs, "/empty-dir/new.txt"), created.ino);
    let linked = fs.link(created.ino, empty_dir, "hard.txt").unwrap();
    assert_eq!(linked.ino, created.ino);
    let symlink = fs.create_symlink(empty_dir, "sym.txt", "new.txt").unwrap();
    assert_eq!(fs.readlink(symlink.ino).unwrap(), "new.txt");
    assert!(matches!(
        fs.create_file(empty_dir, "new.txt", 0o644),
        Err(FsError::AlreadyExists)
    ));
    let free_inodes_settled = fs.get_volume_info().unwrap().free_inodes;
    let disposable = fs.create_file(empty_dir, "delete.txt", 0o644).unwrap();
    fs.unlink(empty_dir, "delete.txt", disposable.ino).unwrap();
    assert!(matches!(
        fs.resolve_path("/empty-dir/delete.txt"),
        Err(FsError::NotFound)
    ));
    let disposable_dir = fs.create_directory(empty_dir, "delete-dir", 0o755).unwrap();
    fs.unlink(empty_dir, "delete-dir", disposable_dir.ino)
        .unwrap();
    assert!(matches!(
        fs.resolve_path("/empty-dir/delete-dir"),
        Err(FsError::NotFound)
    ));
    assert_eq!(
        fs.get_volume_info().unwrap().free_inodes,
        free_inodes_settled
    );

    fs.rename(
        empty_dir,
        "new.txt",
        empty_dir,
        "renamed.txt",
        fs_abstraction::RenameFlags::default(),
    )
    .unwrap();
    assert!(matches!(
        fs.resolve_path("/empty-dir/new.txt"),
        Err(FsError::NotFound)
    ));
    assert_eq!(resolve(&fs, "/empty-dir/renamed.txt"), created.ino);
    assert_eq!(resolve(&fs, "/empty-dir/hard.txt"), created.ino);

    fs.create_file(empty_dir, "replacement.txt", 0o644).unwrap();
    fs.rename(
        empty_dir,
        "renamed.txt",
        empty_dir,
        "replacement.txt",
        fs_abstraction::RenameFlags {
            replace_if_exists: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(resolve(&fs, "/empty-dir/replacement.txt"), created.ino);
    assert!(matches!(
        fs.resolve_path("/empty-dir/renamed.txt"),
        Err(FsError::NotFound)
    ));

    let move_dir = fs.create_directory(empty_dir, "move-dir", 0o755).unwrap();
    let dest_dir = fs.create_directory(empty_dir, "dest-dir", 0o755).unwrap();
    let child = fs.create_file(move_dir.ino, "child.txt", 0o644).unwrap();
    assert_eq!(resolve(&fs, "/empty-dir/move-dir/child.txt"), child.ino);
    fs.rename(
        move_dir.ino,
        "child.txt",
        dest_dir.ino,
        "child.txt",
        Default::default(),
    )
    .unwrap();
    fs.rename(
        empty_dir,
        "move-dir",
        dest_dir.ino,
        "moved-dir",
        Default::default(),
    )
    .unwrap();
    assert_eq!(resolve(&fs, "/empty-dir/dest-dir/child.txt"), child.ino);
    assert_eq!(resolve(&fs, "/empty-dir/dest-dir/moved-dir"), move_dir.ino);

    let block_dir = resolve(&fs, "/dirs/alpha/beta/gamma");
    let block_file = fs.create_file(block_dir, "block-new.txt", 0o644).unwrap();
    fs.write(block_file.ino, 0, b"block\n").unwrap();
    fs.rename(
        block_dir,
        "block-new.txt",
        block_dir,
        "block-renamed.txt",
        Default::default(),
    )
    .unwrap();
    assert_eq!(read_all(&fs, block_file.ino, 6), b"block\n");
    fs.unlink(block_dir, "block-renamed.txt", block_file.ino)
        .unwrap();

    let allocated = fs.create_file(empty_dir, "allocated.bin", 0o644).unwrap();
    let payload: Vec<u8> = (0..10_000u32).map(|index| (index % 251) as u8).collect();
    assert_eq!(fs.write(allocated.ino, 0, &payload).unwrap(), payload.len());
    assert_eq!(read_all(&fs, allocated.ino, payload.len() as u64), payload);
    assert_eq!(fs.write(allocated.ino, 16_384, b"HOLE").unwrap(), 4);
    let sparse = read_all(&fs, allocated.ino, 16_388);
    assert_eq!(&sparse[..payload.len()], &payload);
    assert!(sparse[payload.len()..16_384].iter().all(|byte| *byte == 0));
    assert_eq!(&sparse[16_384..], b"HOLE");
    fs.set_size(allocated.ino, 5_000).unwrap();
    assert_eq!(read_all(&fs, allocated.ino, 5_000), payload[..5_000]);
    fs.set_size(allocated.ino, 0).unwrap();
    assert_eq!(fs.stat(allocated.ino).unwrap().size, 0);
    fs.unlink(empty_dir, "allocated.bin", allocated.ino)
        .unwrap();

    let btree_file = fs.create_file(empty_dir, "btree.bin", 0o644).unwrap();
    for index in 0..40u64 {
        let byte = (index % 251) as u8;
        assert_eq!(
            fs.write(btree_file.ino, index * 2 * 4096, &[byte]).unwrap(),
            1
        );
    }
    for index in 0..40u64 {
        let mut byte = [0u8; 1];
        assert_eq!(
            fs.read(btree_file.ino, index * 2 * 4096, &mut byte)
                .unwrap(),
            1
        );
        assert_eq!(byte[0], (index % 251) as u8);
        if index + 1 < 40 {
            let mut hole = [0xFFu8; 1];
            assert_eq!(
                fs.read(btree_file.ino, index * 2 * 4096 + 1, &mut hole)
                    .unwrap(),
                1
            );
            assert_eq!(hole[0], 0);
        }
    }
    fs.set_size(btree_file.ino, 0).unwrap();
    fs.unlink(empty_dir, "btree.bin", btree_file.ino).unwrap();

    let grow_dir = fs.create_directory(empty_dir, "grow-dir", 0o755).unwrap();
    let long_a = "a".repeat(200);
    let long_b = "b".repeat(200);
    let grown_a = fs.create_file(grow_dir.ino, &long_a, 0o644).unwrap();
    let grown_b = fs.create_file(grow_dir.ino, &long_b, 0o644).unwrap();
    assert_eq!(
        resolve(&fs, &format!("/empty-dir/grow-dir/{long_a}")),
        grown_a.ino
    );
    assert_eq!(
        resolve(&fs, &format!("/empty-dir/grow-dir/{long_b}")),
        grown_b.ino
    );
    fs.unlink(grow_dir.ino, &long_a, grown_a.ino).unwrap();
    fs.unlink(grow_dir.ino, &long_b, grown_b.ino).unwrap();

    let leaf_dir = resolve(&fs, "/many");
    let leaf_file = fs.create_file(leaf_dir, "leaf-new.txt", 0o644).unwrap();
    fs.write(leaf_file.ino, 0, b"leaf\n").unwrap();
    fs.rename(
        leaf_dir,
        "leaf-new.txt",
        leaf_dir,
        "leaf-renamed.txt",
        Default::default(),
    )
    .unwrap();
    assert_eq!(read_all(&fs, leaf_file.ino, 5), b"leaf\n");
    fs.unlink(leaf_dir, "leaf-renamed.txt", leaf_file.ino)
        .unwrap();
    fs.shutdown().unwrap();
    drop(fs);

    let reopened_device = Arc::new(FileDevice::open(temp.path()).unwrap());
    let reopened = XfsVfs::read_only(reopened_device).unwrap();
    assert_eq!(read_all(&reopened, hello, 16), b"Written by Rust\n");
    assert_eq!(read_all(&reopened, exact, 4096), replacement_data);
    assert_eq!(read_all(&reopened, created.ino, 8), b"created\n");
    assert_eq!(resolve(&reopened, "/empty-dir/hard.txt"), created.ino);
    assert_eq!(
        resolve(&reopened, "/empty-dir/replacement.txt"),
        created.ino
    );
    assert_eq!(reopened.readlink(symlink.ino).unwrap(), "new.txt");
}

/// The fixture root contains `special.fifo`. Creating entries there used to
/// fail with `NotSupported` because POSIX "other" file types had no mapping to
/// the on-disk directory ftype byte that the duplicate-name scan needs.
#[test]
fn creating_entries_in_the_root_preserves_non_file_directory_types() {
    let Some(fixture) = fixture_path() else {
        eprintln!("real XFS fixture unavailable; skipping");
        return;
    };
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(fixture, temp.path()).unwrap();

    let Some(fs) = open_writable_fixture(temp.path()) else {
        return;
    };
    let root = resolve(&fs, "/");

    let created = fs.create_file(root, "root-created.txt", 0o644).unwrap();
    fs.write(created.ino, 0, b"root\n").unwrap();
    assert_eq!(read_all(&fs, created.ino, 5), b"root\n");
    assert_eq!(fs.resolve_path("/root-created.txt").unwrap(), created.ino);

    let directory = fs.create_directory(root, "root-dir", 0o755).unwrap();
    assert!(fs.stat(directory.ino).unwrap().is_dir());

    let fifo = resolve(&fs, "/special.fifo");
    assert_eq!(fs.stat(fifo).unwrap().file_type, VfsFileType::Fifo);
    assert_eq!(fs.resolve_path("/special.fifo").unwrap(), fifo);

    fs.shutdown().unwrap();
    drop(fs);

    let reopened = XfsVfs::read_only(Arc::new(FileDevice::open(temp.path()).unwrap())).unwrap();
    assert_eq!(read_all(&reopened, created.ino, 5), b"root\n");
    assert!(reopened.stat(directory.ino).unwrap().is_dir());
    let fifo = resolve(&reopened, "/special.fifo");
    assert_eq!(reopened.stat(fifo).unwrap().file_type, VfsFileType::Fifo);
}

/// The front-end uses `unclean_unmount` to warn about volumes that were not
/// cleanly unmounted: pending log transactions for read-only mounts, replayed
/// transactions for writable ones.
#[test]
fn unclean_unmount_is_reported_until_the_log_is_closed_cleanly() {
    let Some(fixture) = fixture_path() else {
        eprintln!("real XFS fixture unavailable; skipping");
        return;
    };
    let temp = tempfile::NamedTempFile::new().unwrap();
    std::fs::copy(fixture, temp.path()).unwrap();

    let clean = XfsVfs::read_only(Arc::new(FileDevice::open(temp.path()).unwrap())).unwrap();
    assert!(
        !clean.unclean_unmount(),
        "the committed fixture was unmounted cleanly"
    );
    drop(clean);

    // Commit a transaction and drop the instance without shutdown(): this is
    // what a crash leaves behind.
    {
        let Some(fs) = open_writable_fixture(temp.path()) else {
            return;
        };
        let root = resolve(&fs, "/");
        fs.create_file(root, "dirty-marker.txt", 0o644).unwrap();
    }

    let pending = XfsVfs::read_only(Arc::new(FileDevice::open(temp.path()).unwrap())).unwrap();
    assert!(
        pending.unclean_unmount(),
        "a read-only mount must report transactions that still need replay"
    );
    drop(pending);

    let replayed = open_writable_fixture(temp.path()).expect("fixture remained writable-supported");
    assert!(
        replayed.unclean_unmount(),
        "a writable mount must report that it replayed the log"
    );
    replayed.shutdown().unwrap();
    drop(replayed);

    let recovered = XfsVfs::read_only(Arc::new(FileDevice::open(temp.path()).unwrap())).unwrap();
    assert!(
        !recovered.unclean_unmount(),
        "a clean unmount must clear the flag"
    );
}
