//! End-to-end read test against a real XFS image.
//!
//! Generate an image with `mkfs.xfs` and point `XFS_TEST_IMAGE` at it:
//!
//! ```text
//! truncate -s 64M /tmp/xfs.img
//! mkfs.xfs -f /tmp/xfs.img
//! set XFS_TEST_IMAGE=C:\path\to\xfs.img
//! cargo test -p xfs-vfs --test real_image
//! ```
//!
//! Without the environment variable the test is skipped, so CI does not need
//! `mkfs.xfs`.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Mutex},
};

use fs_abstraction::{BlockDevice, FsResult, VfsFileSystem, VfsFileType};
use xfs_vfs::XfsVfs;

struct FileDevice {
    file: Mutex<File>,
    size: u64,
}

impl FileDevice {
    fn open(path: &str) -> std::io::Result<Self> {
        let file = File::open(path)?;
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
            .map_err(|_| fs_abstraction::FsError::DiskError)?;
        file.read(buf)
            .map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

#[test]
fn real_image_mount_readdir_and_read() {
    let path = match std::env::var("XFS_TEST_IMAGE") {
        Ok(path) => path,
        Err(_) => {
            eprintln!("XFS_TEST_IMAGE not set; skipping real-image test");
            return;
        }
    };

    let device = Arc::new(FileDevice::open(&path).expect("open test image"));
    let fs = XfsVfs::new(device).expect("parse XFS superblock");

    let root = fs.root_inode();
    let entries = fs.readdir(root).expect("read root directory");
    assert!(
        entries.iter().any(|entry| entry.name == "."),
        "root directory must contain '.'"
    );

    let mut files_read = 0usize;
    for entry in entries
        .iter()
        .filter(|entry| entry.name != "." && entry.name != "..")
    {
        let info = fs.stat(entry.ino).expect("stat directory entry");
        if !matches!(info.file_type, VfsFileType::RegularFile) || info.size == 0 {
            continue;
        }

        let len = info.size.min(4096) as usize;
        let mut buf = vec![0u8; len];
        let read = fs.read(entry.ino, 0, &mut buf).expect("read file data");
        assert_eq!(
            read, len,
            "short read for '{}' ({} bytes expected)",
            entry.name, len
        );
        files_read += 1;
        if files_read >= 8 {
            break;
        }
    }
}
