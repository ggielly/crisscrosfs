# CrissCrossFS — XFS filesystem driver for Windows

CrissCrossFS is an experimental XFS filesystem driver for Windows, written in Rust. It uses WinFsp for the kernel-mode filesystem interface and a user-mode Rust VFS for XFS parsing, reads, and transactional writes to regular image files.

> **Status:** experimental. Do not use on production data. Physical disks, partitions, and volumes remain read-only. Writable image mounts use the real XFS internal log, but supported on-disk feature combinations and directory geometries are intentionally bounded.

## Features

- Read access to XFS v4 and v5 filesystems
- Local, extent, and B+tree file reads
- Shortform, block, leaf, and node-directory reads
- Transactional image-file writes with XFS log-v2 buffer/inode records, dirty bitmaps, tail advancement, and recovery
- BNO/CNT and existing-chunk INOBT/FINOBT allocation
- Local/extent/B+tree file writes, sparse holes, truncate, and timestamps
- File/directory/symlink creation, hard links, unlink, and rename
- Shortform, block, single-leaf, and bounded single-level node directories
- Physical disk, partition, volume, and image-file sources
- WinFsp mount/unmount lifecycle and clean shutdown records
- Property-based parser tests, real-image write regressions, and libFuzzer targets

## Requirements

- Windows 10/11 x64
- Administrator privileges for raw disk access
- [WinFsp](https://winfsp.dev/) 2.1 or newer
- Rust nightly (`rust-toolchain.toml`)
- LLVM/libclang available to `bindgen`; set `LIBCLANG_PATH` to the directory containing `libclang.dll` if Cargo cannot find it

## Build

```powershell
cargo build -p fs-winfsp-glue
```

The executables are written to `target\debug\crisscrossfs.exe` (CLI) and
`target\debug\crisscrossfs-gui.exe` (GUI).

For a release build:

```powershell
cargo build -p fs-winfsp-glue --release
```

## Usage

Run from an elevated terminal.

```powershell
# Mount an XFS partition by drive letter
crisscrossfs.exe mount --partition D: --mount-point X:

# Mount a physical disk
crisscrossfs.exe mount --disk 1 --mount-point X:

# Mount an XFS image file read-only
crisscrossfs.exe mount --image C:\images\disk.img --mount-point X:

# Mount a regular XFS image file read-write (experimental)
crisscrossfs.exe mount --image C:\images\disk.img --mount-point X: --rw

# Mount a Windows volume path
crisscrossfs.exe mount --volume '\\.\HarddiskVolume5' --mount-point X:

# Inspect or list an image
crisscrossfs.exe info --image C:\images\disk.img
crisscrossfs.exe ls --image C:\images\disk.img /

# Scan physical disks
crisscrossfs.exe scan
```

Press `Ctrl+C` to unmount. Writable mounts flush metadata and append a clean unmount record during shutdown. `--rw` is rejected for physical disks, partitions, and Windows volume paths; it is accepted only for regular image files.

### Writable-image limitations

The writer fails closed rather than silently producing incomplete metadata:

- New physical inode-cluster allocation is not implemented; only free inodes in existing chunks are reused.
- Realtime or quota-enabled filesystems and RMAP-backed allocation groups are rejected.
- REFCOUNBT is validated as a single leaf; shared and CoW staging extents are rejected, and refcount records are not mutated.
- Directory rebuilding supports one LEAF1 or one DA-node level with one free-index block. Larger node trees fail with `NotSupported`.
- A transaction must fit in one 32 KiB log record; log wrap/checkpointing and multi-record continuation are not implemented.
- Extended-attribute mutation is not implemented, but existing attribute-fork bytes are preserved when inodes are rewritten; unlinking an inode with attribute extents is rejected rather than leaking those blocks.
- Real WinFsp mount/unmount and Linux `xfs_repair` validation are still required before release.

## Desktop GUI

`crisscrossfs-gui.exe` is a native Win32 front-end built directly on the `windows`
crate: it lists the XFS volumes found on the machine plus any image file you
pick, mounts and unmounts them on a free drive letter, and keeps running in the
notification area when the window is closed.

```powershell
# Windowless build, meant for Explorer or a Start-menu shortcut
target\debug\crisscrossfs-gui.exe

# Same UI from a console (handy while developing)
crisscrossfs.exe gui
```

The tray icon offers *Show CrissCrossFS*, *Unmount all* and *Exit*. The GUI and the
CLI share the same mount layer, so a volume mounted from the GUI behaves exactly
like one mounted with `crisscrossfs mount`.

## Windows service

```powershell
crisscrossfs.exe service install
crisscrossfs.exe service start
crisscrossfs.exe service stop
crisscrossfs.exe service uninstall
```

The service is registered as **CrissCrossFS Service** (`CrissCrossFSService`) and runs as `LocalSystem`. Install it only from a protected directory and review the mount-point access policy before exposing volumes to other users.

## POSIX permissions and Windows ACLs

XFS `mode`/`uid`/`gid` are mapped to a protected Windows DACL:

- uid 0 → `NT AUTHORITY\SYSTEM`; gid 0 → `BUILTIN\Administrators`.
- Non-root IDs are **not guessed**. They must be listed in an optional
  `XFS_ACL_MAP` TOML file; an unmapped uid gets an empty DACL (fail closed).
- Owner/group/other rights use explicit deny ACEs to reproduce POSIX class
  precedence instead of Windows' usual union of matching allow ACEs.
- Read-only mounts never grant write/delete rights.
- Sticky directories do not receive `FILE_DELETE_CHILD`. Setuid/setgid have no
  Windows ACL equivalent and are ignored.

Example `xfs-acl.toml`:

```toml
[uids]
"1000" = "S-1-5-21-100-200-300-1001"
"1001" = "CURRENT_USER"

[gids]
"1000" = "S-1-5-32-545"
```

```powershell
$env:XFS_ACL_MAP = "C:\path\to\xfs-acl.toml"
crisscrossfs.exe mount --image C:\images\disk.img --mount-point X:
```

Without this file only root-owned entries are accessible. This conservative
default prevents an XFS gid from silently granting access to every authenticated
Windows user.

## Tests

```powershell
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

The suite includes real XFS v5 fixtures under `test-images/`, VFS read/readdir regressions, and `crates/xfs-vfs/tests/write_image.rs`, which mutates only a disposable temporary copy. The write test covers allocation, sparse writes, truncate, BMBT conversion, directory growth, namespace operations, clean shutdown, and read-only reopen. A real WinFsp mount in a Windows VM and Linux `xfs_repair` validation are still required before release.

## Fuzzing

```powershell
cargo install cargo-fuzz --locked
cargo fuzz run superblock_fuzz
```

## Documentation

```powershell
cargo doc --workspace --document-private-items --open
```

## License

GPL-3.0.
