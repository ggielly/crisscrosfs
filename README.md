# XFS filesystem driver for Windows

This project implements an experimental, read-only XFS filesystem for Windows in Rust. It uses WinFsp for the kernel-mode filesystem interface and a user-mode Rust VFS for XFS parsing and reads.

> **Status:** experimental. Do not use on production data. Write support is currently disabled because block/inode allocation, journaling, and recovery are not complete.

## Features

- Read-only access to XFS v4 and v5 filesystems
- Local, extent, and B+tree file reads
- Shortform, block, leaf, and B+tree directory reads
- Physical disk, partition, volume, and image-file sources
- WinFsp mount/unmount lifecycle
- Property-based parser tests and libFuzzer targets

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

The executable is written to `target\debug\xfs-mount.exe`.

For a release build:

```powershell
cargo build -p fs-winfsp-glue --release
```

## Usage

Run from an elevated terminal.

```powershell
# Mount an XFS partition by drive letter
xfs-mount.exe mount --partition D: --mount-point X:

# Mount a physical disk
xfs-mount.exe mount --disk 1 --mount-point X:

# Mount an XFS image file
xfs-mount.exe mount --image C:\images\disk.img --mount-point X:

# Mount a Windows volume path
xfs-mount.exe mount --volume '\\.\HarddiskVolume5' --mount-point X:

# Inspect or list an image
xfs-mount.exe info --image C:\images\disk.img
xfs-mount.exe ls --image C:\images\disk.img /

# Scan physical disks
xfs-mount.exe scan
```

Press `Ctrl+C` to unmount. The `--rw` flag is intentionally rejected: enabling it before allocation and journal recovery are complete can corrupt the filesystem.

## Windows service

```powershell
xfs-mount.exe service install
xfs-mount.exe service start
xfs-mount.exe service stop
xfs-mount.exe service uninstall
```

The service runs as `LocalSystem`. Install it only from a protected directory and review the mount-point access policy before exposing volumes to other users.

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
xfs-mount.exe mount --image C:\images\disk.img --mount-point X:
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

The suite includes real XFS v5 fixtures under `test-images/` and a VFS read/readdir regression test. A real WinFsp mount in a Windows VM is still required before release.

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
