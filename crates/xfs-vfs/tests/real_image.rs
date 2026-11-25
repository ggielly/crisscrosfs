//! End-to-end read tests against the repository's real XFS fixture.
//!
//! `test-images/xfs-16M.img` is used automatically when present.  Set
//! `XFS_TEST_IMAGE` to test another image when that fixture is unavailable:
//!
//! ```text
//! set XFS_TEST_IMAGE=C:\path\to\xfs.img
//! cargo test -p xfs-vfs --test real_image
//! ```
//!
//! Regenerate the 16 MiB fixture on Linux (or in a container) with xfsprogs:
//!
//! ```sh
//! truncate -s 16M test-images/xfs-16M.img
//! mkfs.xfs -f test-images/xfs-16M.img
//! sudo mount -o loop test-images/xfs-16M.img /mnt/xfs
//! sudo bash scripts/populate.sh /mnt/xfs small
//! sudo umount /mnt/xfs
//! xfs_repair -n test-images/xfs-16M.img
//! ```
//!
//! If neither the fixture nor `XFS_TEST_IMAGE` is available, the test is
//! skipped.  Directory listings are treated as opaque: this VFS deliberately
//! does not synthesize `.` and `..` entries.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use fs_abstraction::{BlockDevice, FsError, FsResult, VfsFileSystem};
use xfs_vfs::{VfsFileInfo, XfsVfs};

struct FileDevice {
    file: Mutex<File>,
    size: u64,
}

impl FileDevice {
    fn open(path: &Path) -> std::io::Result<Self> {
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
            .map_err(|_| FsError::DiskError)?;
        file.read(buf).map_err(|_| FsError::DiskError)
    }

    fn size(&self) -> u64 {
        self.size
    }
}

fn fixture_path() -> Option<PathBuf> {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("test-images")
        .join("xfs-16M.img");
    if fixture.is_file() {
        return Some(fixture);
    }

    std::env::var_os("XFS_TEST_IMAGE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn resolve(fs: &XfsVfs, path: &str) -> u64 {
    fs.resolve_path(path)
        .unwrap_or_else(|error| panic!("resolve {path:?}: {error:?}"))
}

fn stat(fs: &XfsVfs, path: &str) -> VfsFileInfo {
    let ino = resolve(fs, path);
    fs.stat(ino)
        .unwrap_or_else(|error| panic!("stat {path:?}: {error:?}"))
}

fn read_all(fs: &XfsVfs, info: &VfsFileInfo) -> Vec<u8> {
    let size = usize::try_from(info.size).expect("fixture files fit in memory");
    let mut buf = vec![0u8; size];
    let mut offset = 0usize;
    while offset < buf.len() {
        let read = fs
            .read(info.ino, offset as u64, &mut buf[offset..])
            .unwrap_or_else(|error| panic!("read inode {}: {error:?}", info.ino));
        assert!(read > 0, "unexpected EOF for inode {}", info.ino);
        offset += read;
    }
    buf
}

fn read_path(fs: &XfsVfs, path: &str) -> Vec<u8> {
    let info = stat(fs, path);
    assert!(info.is_file(), "{path:?} must be a regular file");
    read_all(fs, &info)
}

fn assert_zeroes(data: &[u8], range: std::ops::Range<usize>, context: &str) {
    assert!(
        data[range.clone()].iter().all(|&byte| byte == 0),
        "non-zero byte in {context} {:?}",
        range
    );
}

#[test]
fn real_image_known_contents_and_directory_formats() {
    let Some(path) = fixture_path() else {
        eprintln!(
            "test-images/xfs-16M.img not found and XFS_TEST_IMAGE is unset; skipping real-image \
             test"
        );
        return;
    };
    assert!(
        path.is_file(),
        "test image does not exist: {}",
        path.display()
    );

    let device = Arc::new(FileDevice::open(&path).expect("open test image"));
    let fs = XfsVfs::read_only(device).expect("parse XFS superblock");
    assert!(fs.capabilities().read_only);

    // Do not require dot entries: readdir exposes only real directory names.
    let root = fs.root_inode();
    let root_entries = fs.readdir(root).expect("read root directory");
    for required in [
        "hello.txt",
        "Case.txt",
        "case.txt",
        "data",
        "many",
        "unicode",
    ] {
        assert!(
            root_entries.iter().any(|entry| entry.name == required),
            "root directory is missing {required:?}"
        );
    }
    assert_eq!(fs.read(root, 0, &mut [0u8; 1]), Err(FsError::IsADirectory));

    assert_eq!(read_path(&fs, "/hello.txt"), b"Hello from XFS!\n");
    assert_eq!(
        read_path(&fs, "/links/hardlink-hello.txt"),
        b"Hello from XFS!\n"
    );
    assert_eq!(
        resolve(&fs, "/hello.txt"),
        resolve(&fs, "/links/hardlink-hello.txt")
    );
    assert_eq!(
        fs.readlink(resolve(&fs, "/links/symlink-hello.txt"))
            .unwrap(),
        "../hello.txt"
    );

    // Case is significant and both names remain independently addressable.
    let case_upper = resolve(&fs, "/Case.txt");
    let case_lower = resolve(&fs, "/case.txt");
    assert_ne!(case_upper, case_lower);
    assert_eq!(read_path(&fs, "/Case.txt"), b"case-sensitive A\n");
    assert_eq!(read_path(&fs, "/case.txt"), b"case-sensitive b\n");
    assert!(matches!(
        fs.lookup(root, "CASE.txt"),
        Err(FsError::NotFound)
    ));

    // Three written fragments separated by holes, including a four-byte tail
    // in the final block.  Every other byte must read as zero.
    let holes_info = stat(&fs, "/data/holes.bin");
    assert_eq!(holes_info.size, 128 * 1024);
    let holes = read_all(&fs, &holes_info);
    assert_eq!(&holes[0..4], b"HEAD");
    assert_eq!(&holes[65_536..65_542], b"MIDDLE");
    assert_eq!(&holes[131_068..131_072], b"TAIL");
    assert_zeroes(&holes, 4..65_536, "holes.bin first hole");
    assert_zeroes(&holes, 65_542..131_068, "holes.bin second hole");

    // A 1 MiB sparse file has no data blocks and must read entirely as zero.
    let sparse_info = stat(&fs, "/sparse.bin");
    assert_eq!(sparse_info.size, 1024 * 1024);
    assert_eq!(sparse_info.blocks, 0);
    let sparse = read_all(&fs, &sparse_info);
    assert_zeroes(&sparse, 0..sparse.len(), "sparse.bin");

    // The small fixture leaves shortform directory format and has 200 files.
    let many_ino = resolve(&fs, "/many");
    let many = fs.readdir(many_ino).expect("read many/ directory");
    let named: Vec<_> = many
        .iter()
        .filter(|entry| entry.name != "." && entry.name != "..")
        .collect();
    assert!(named.len() >= 200, "many/ has only {} entries", named.len());
    for index in [0, 199] {
        let name = format!("entry-{index:04}-abcdefghijklmnop.txt");
        assert!(named.iter().any(|entry| entry.name == name));
        assert_eq!(stat(&fs, &format!("/many/{name}")).size, 0);
    }

    assert_eq!(read_path(&fs, "/unicode/héllo-世界.txt"), b"unicode\n");
    assert_eq!(read_path(&fs, "/dirs/alpha/beta/gamma/file.txt"), b"deep\n");
    assert_eq!(
        read_path(&fs, "/with space/nested dir/file with spaces.txt"),
        b"spaces\n"
    );
}
