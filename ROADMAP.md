# XFS Driver Implementation Roadmap

> **Version**: 6.0
> **Last Updated**: 2026-11-26
> **Overall Status**: 🚧 Experimental read/write image support

---

## Architecture

```text
fs-abstraction → xfs-rs → xfs-vfs → fs-winfsp-glue
   (traits)    (parser)   (VFS)     (xfs-mount.exe)
```

- `xfs-rs` owns on-disk parsing, validation, and metadata codecs.
- `xfs-vfs` owns filesystem operations, allocation, transactions, and recovery.
- `fs-winfsp-glue` owns Windows device access, WinFsp callbacks, mount policy, and ACL mapping.
- `VfsFileSystem` in `crates/fs-abstraction/src/vfs.rs` is the object-safe integration boundary.

### On-disk conventions

- XFS metadata is big-endian; CRC fields are little-endian `__le32`.
- Use checked arithmetic and bounded slices for all device-derived values.
- Use `tracing`, not ad-hoc logging.
- Verify v5 metadata CRCs before trusting structure contents.
- Preserve unmodeled inode bytes, especially the attribute fork.

---

## Current status

### Reading: experimental

- [x] XFS v4/v5 superblock, inode, extent, and B+tree parsing
- [x] Local, extent, and B+tree file reads
- [x] Sparse and unwritten extent semantics
- [x] Shortform, block, leaf, and node-directory data reads
- [x] Cycle, depth, record-count, CRC, and physical-bound validation
- [x] Real XFS v5 fixture read/readdir regressions
- [ ] Real XFS v4 image fixture
- [ ] WinFsp mount E2E validation in a Windows VM

### Writable image mounts: experimental

- [x] Real XFS log-v2 record encoding, CRC32C, commit records, and unmount records
- [x] Logical inode log items with native-endian core and data-fork regions
- [x] Recovery scanning and replay of committed buffer and inode items
- [x] Partial-buffer dirty bitmaps (128-byte chunks)
- [x] Tail advancement after each durable metadata flush
- [x] Checked write batching, short-write retries, data-block rollback, and best-effort metadata rollback
- [x] Transactional BNO/CNT collection and rebuild
- [x] AGF, AGFL, and superblock free-space updates
- [x] Existing-chunk INOBT/FINOBT allocation/free and AGI updates
- [x] Sparse inode B+tree records
- [x] Single-leaf REFCOUNBT validation and shared/CoW overwrite/free rejection
- [x] Local/extent/B+tree file writes and BMBT rebuild
- [x] Hole allocation, unwritten conversion, truncate/free, and timestamps
- [x] Local → extents conversion, including inline-size extension
- [x] Partial unwritten-extent conversion without exposing stale blocks
- [x] File, directory, and inline-symlink creation
- [x] Hard links, unlink, rename/replacement, and cross-directory moves
- [x] Shortform and single-block directory mutation
- [x] Block → single-leaf conversion
- [x] Bounded single-level LEAFN/DA-node directory rebuilding
- [x] Attribute-fork preservation during inode serialization
- [x] Disposable real-image write regression and clean read-only reopen
- [x] WinFsp policy permits writable regular image files only
- [x] Physical disks, partitions, and Windows volume paths remain read-only

### Explicit write limitations

The writer fails closed for these cases:

- New physical inode-cluster allocation; only existing free inode chunks are reused.
- Realtime or quota-enabled filesystems and RMAP-backed allocation groups.
- REFCOUNBT mutation, including shared-refcount and CoW staging extents.
- Directory node trees requiring more than one DA-node level or more than one free-index block.
- Transactions larger than one 32 KiB log record.
- Log wrap/checkpointing and multi-record continuation.
- Extended-attribute mutation.
- Physical-device writes and service auto-mount writes.

### Validation still required

- [ ] Linux `xfs_repair -n` after the real-image write suite
- [ ] Linux mount/read/write/unmount interoperability
- [ ] Real WinFsp writable mount/unmount in a Windows VM
- [ ] Crash-injection and recovery stress tests
- [ ] Larger real-image directory and allocation stress tests
- [ ] Concurrency and filesystem-full scenarios

---

## Implementation map

| Area | Primary files |
|------|---------------|
| On-disk codecs | `crates/xfs-rs/src/{log_format,short_btree,bmbt_write,refcount,dir_write}.rs` |
| Journal and replay | `crates/xfs-vfs/src/journal.rs` |
| Staged writes | `crates/xfs-vfs/src/transaction.rs` |
| Block allocation | `crates/xfs-vfs/src/allocator.rs` |
| Inode allocation | `crates/xfs-vfs/src/inode_allocator.rs` |
| Mutation engine | `crates/xfs-vfs/src/writer.rs` |
| VFS dispatch/locking | `crates/xfs-vfs/src/filesystem.rs` |
| WinFsp policy | `crates/fs-winfsp-glue/src/{main,mount,disk,context,winfsp_mount}.rs` |
| Real-image writes | `crates/xfs-vfs/tests/write_image.rs` |

---

## Next priorities

### Priority 1: external correctness validation

1. Run `xfs_repair -n` on a disposable image after `write_image`.
2. Mount the image on Linux and verify namespaces, data, sparse files, and clean unmount.
3. Repeat through a real WinFsp image mount on Windows.
4. Add crash points between log force and metadata apply, then verify replay.

### Priority 2: bounded writer completion

1. Implement new inode-cluster allocation with correct cluster geometry and initialization.
2. Implement RMAP updates or retain explicit rejection.
3. Generalize REFCOUNBT and directory node-tree rebuilding beyond one level.
4. Implement log wrap/checkpointing and multi-record transactions.
5. Add attribute-fork mutation only with complete local/remote attribute codecs.

### Priority 3: hardening and performance

1. Stress allocation, fragmentation, filesystem-full, and rollback paths.
2. Add writer fuzz targets and malformed-metadata transaction tests.
3. Reduce directory rebuild amplification with in-place mutation where safe.
4. Benchmark BMBT, allocation-tree, and journal paths on larger images.
5. Keep physical-device writes disabled until exclusive-access and dismount semantics are proven.

---

## Required checks

```powershell
cargo fmt --all -- --check
cargo test --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-features --all-targets
cargo check -p xfs-rs --no-default-features
cargo test -p xfs-vfs --test write_image
cargo build -p fs-winfsp-glue --release
```

The real-image write test copies `test-images/xfs-16M.img` to a temporary file. It must never modify the committed fixture.

---

## Safety policy

- Do not enable physical-device writes.
- Do not silently accept unsupported metadata features.
- Do not commit a filesystem mutation before its log record is durable.
- Do not expose a successful write when device I/O makes zero progress.
- Keep read-only mounts structurally unable to call device writes.
- Treat every writable-image mount as experimental until external checker and mount validation pass.
