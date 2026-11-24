# XFS filesystem driver for MS-Windows

This project implements XFS filesystem driver for Windows using Rust. WiP : read-only for now. But I plan to add write support in the future.

## Overview

The XFS driver enables Windows systems to read XFS-formatted volumes without requiring third-party software. This is a read-only implementation, meaning you can view and copy files from XFS volumes but cannot modify them at this time. This feature will be added in the future.

## Features

- Read-only access to XFS volumes
- XFS v4 and v5 parsing (v5 superblock and inode CRC32c verification)
- Fast I/O operations through Windows Cache Manager
- ETW logging for debugging and monitoring
- Error handling and security checks
- Property-based testing with proptest
- cargo-fuzz targets (see `fuzz/`)

Write support is intentionally disabled: the block allocator, AGF/AGI
handling and journal recovery are incomplete.  `--rw` and the write-enabled
`XfsVfs`/`detect_and_create` entry points return an error.

## Requirements

- Windows 10/11 (x64)
- [WinFsp](https://winfsp.dev/) 2.x installed (runtime and service)
- Rust stable toolchain
- LLVM/Clang (`libclang.dll`) on `PATH`, or `LIBCLANG_PATH` pointing to it
  (needed by `bindgen` for the WinFsp bindings)

## Getting started

`cargo install cargo-make --no-default-features --features tls-native`

## Documentation

`cargo doc --document-private-items --open`

## Building and running

1. Do not use your production Windows: use a VM!
2. `cargo build --release -p fs-winfsp-glue` produces
   `target/release/xfs-mount.exe`.
3. Mount an image read-only:
   `xfs-mount.exe mount --image disk.img --mount-point X:`
4. Mount a physical disk read-only:
   `xfs-mount.exe mount --disk 1 --mount-point X:`

The CLI requires a subcommand; running `xfs-mount.exe` without arguments
only prints help.  `xfs-mount.exe service install` registers the service with
the `service run` arguments.

`cargo make` or `scripts/build.ps1` build the same user-mode binary (there is
no kernel `.sys` driver).

## Testing

`cargo test --workspace` runs unit, parser, property-based and corrupted-image
tests.  To run the end-to-end read test against a real XFS image:

```powershell
truncate -s 64M xfs.img      # or create it on Linux
mkfs.xfs -f xfs.img
$env:XFS_TEST_IMAGE = (Resolve-Path xfs.img)
cargo test -p xfs-vfs --test real_image
```

`cargo fuzz run superblock` (nightly, see `fuzz/`) exercises the superblock
parser.

## Security notes

- The driver is read-only.  Write entry points return an error at the API
  boundary, not only in the CLI.
- XFS POSIX mode/uid/gid are **not** mapped to Windows security descriptors.
  WinFsp does not enforce per-file XFS permissions; the mounted volume is
  readable by users who can access the mount point.  Do not mount untrusted
  XFS images on multi-user systems without an external access restriction.
- The service runs as LocalSystem and mounts volumes read-only.

## License

This project is licensed under the GPL-v3 terms.