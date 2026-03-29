# XFS filesystem driver for MS-Windows

This project implements XFS filesystem driver for Windows using Rust. WiP : read-only for now. But I plan to add write support in the future.

## Overview

The XFS driver enables Windows systems to read XFS-formatted volumes without requiring third-party software. This is a read-only implementation, meaning you can view and copy files from XFS volumes but cannot modify them at this time. This feature will be added in the future.

## Features

- Read-only access to XFS volumes
- Support for XFS v4 and v5 filesystems
- Fast I/O operations through Windows Cache Manager
- ETW logging for debugging and monitoring
- Error handling and security checks
- Property-based testing with proptest
- AFL++ fuzzing support

## Getting started

### Setuping Rust

Run the following commands after setting up Rust.

`cargo install cargo-make --no-default-features --features tls-native`

## Documentation

`cargo doc --document-private-items --open`

## Building

1. Doo not use your production windows : use a VM !
2. `cargo make`  or `cargo run`
3. Enjoy.

## License

This project is licensed under the GPL-v3 terms.