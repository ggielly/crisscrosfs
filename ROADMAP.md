# XFS Driver Implementation Roadmap

> **Version**: 5.0
> **Last Updated**: 2026-02-06
> **Overall Status**: 🚧 Actively Under Development

---

## 🧠 MEMORY - Key Points to Remember

> **Quick reference section for developers and AI**
> Check this section before any code modifications

### Critical Architecture

**4 Active Crates (User-Mode):**
```
fs-abstraction → xfs-rs → xfs-vfs → fs-winfsp-glue
   (traits)    (parser)   (VFS)     (mount.exe)
```

**Main Trait:** `VfsFileSystem` in `fs-abstraction/src/vfs.rs`
- Object-safe, `Send + Sync`
- Required read methods, write methods return `ReadOnly` by default
- Integration point between xfs-vfs and fs-winfsp-glue

### Essential Code Conventions

1. **Big-Endian Everywhere (except CRCs)**: XFS metadata is big-endian, but CRC fields (`sb_crc`, `di_crc`, btree/dir CRC) are little-endian `__le32`. Use `from_be_bytes()` for fields and `from_le_bytes()` for CRCs.
2. **Nightly Rustfmt**: `rustfmt.toml` uses unstable features (`imports_granularity`, etc.)
3. **Tracing, Not Log**: Use `trace!()`, `debug!()`, `info!()` from the `tracing` crate
4. **CheckedOps**: Safe arithmetic via `CheckedOps` trait → returns `FsError::ArithmeticOverflow`
5. **FsError**: Single error type with NTSTATUS mapping for Windows

### Common Build Commands

```bash
# Full build
cargo build -p fs-winfsp-glue

# Tests (read operations work)
cargo test -p xfs-vfs
cargo test -p xfs-rs

# Linter
cargo clippy -- -D warnings

# Format (NIGHTLY required)
cargo fmt

# Run (example; a subcommand is required)
cargo run -p fs-winfsp-glue -- mount --disk 1 --mount-point X:
cargo run -p fs-winfsp-glue -- mount --image test.img --mount-point X:
```

### B+Tree: Implementation Details

**Key Function:** `btree::btree_collect_extents()` in `xfs-rs`
- Used for both files AND directories (same BMBT structure)
- Directory B+trees: blocks contain directory entries instead of file data
- DATA blocks threshold: `file_offset < 32 GiB / block_size`
- Above threshold: Leaf/Free blocks

**Important Adapter:** `ClosureBlockReader` in `xfs-vfs/src/directory.rs`
- Bridges closures to `BlockReader` trait
- Allows passing lambdas to xfs-rs parsing functions

**is_v5 Parameter:** Added to `parse_directory_entries()` (2026-02-05)
- Necessary to correctly parse v4 vs v5 headers

### LRU Caching

`XfsCache` in `xfs-vfs/src/cache.rs`:
- Inodes: 4096 entries
- Blocks: 1024 entries
- Paths: 2048 entries
- Directories: 512 entries
- Protection: `parking_lot::RwLock`
- Configurable TTL per cache

### 🔴 CRITICAL BUGS TO NEVER FORGET

#### 1. Incomplete Allocator (TOTAL BLOCKER)
```rust
// crates/xfs-vfs/src/allocator.rs lines 144-149, 152-155
mark_allocated()  // STUB - does NOT update BNO/CNT B+trees
free_blocks()     // STUB - does NOT update B+trees
```
**Consequence:** Same block reallocated multiple times → **GUARANTEED CORRUPTION**
**Action:** NEVER enable write in production without fixing this

#### 2. Missing Journal Recovery
```rust
// crates/xfs-vfs/src/journal.rs line 418-456
recover()  // Scans head LSN but does NOT replay transactions
```
**Consequence:** Crash = data loss, journal useless
**Action:** Implement replay before any serious usage

### ⚠️ Write Support Limitations

**Works:**
- ✅ Shortform directories (inline in inode)
- ✅ Local (inline) and Extents files
- ✅ Shortform → block directory conversion

**Does NOT Work:**
- ❌ Extent-based or B+tree directories (returns `NotImplemented`)
- ❌ B+tree files (returns `NotImplemented`)
- ❌ Local → Extents file conversion
- ❌ Block → Leaf directory conversion

**Key Code Lines:**
- `write_ops.rs:413, 483, 569, 602` - Directory ops not shortform
- `write_ops.rs:636` - Overflow inline file
- `write_ops.rs:676` - B+tree file write
- `write_ops.rs:843` - Local→Extents conversion
- `write_ops.rs:1072` - Block→Leaf conversion

### Documentation Files

```
docs/IMPLEMENTATION_TRACKER.md  - Detailed tracker (EN)
docs/WRITE_SUPPORT_STATUS.md    - Write ops status
docs/XFS_Driver_v4.md           - Complete spec
docs/MODULAR_VFS_ARCHITECTURE.md - VFS Architecture
CLAUDE.md                       - Claude Code Guide
ROADMAP.md                      - THIS FILE (single source of truth)
```

### Common Pitfalls & Solutions

**Pitfall 1:** Forgetting that XFS is big-endian
→ **Solution:** Always use `from_be_bytes()` / `to_be_bytes()`

**Pitfall 2:** Using `log!()` instead of `tracing!`
→ **Solution:** Import `use tracing::{trace, debug, info};`

**Pitfall 3:** Unchecked arithmetic
→ **Solution:** Use `CheckedOps` trait or `.checked_add()/.checked_mul()`

**Pitfall 4:** Assuming write works for all formats
→ **Solution:** ALWAYS check format (shortform only currently)

**Pitfall 5:** Forgetting to update CRCs (v5)
→ **Solution:** Call `crc::recalculate_crc()` after modification

**Pitfall 6:** Accessing buffers without validation
→ **Solution:** Use `CheckedSliceOps::get_slice_checked()`

### Code Patterns Used

**Pattern 1: Format Dispatch**
```rust
match inode.di_format {
    InodeFormat::Local => { /* inline data */ },
    InodeFormat::Extents => { /* extent list */ },
    InodeFormat::Btree => { /* B+tree root */ },
    _ => Err(FsError::NotImplemented),
}
```

**Pattern 2: Cached Reading**
```rust
// Try cache first
if let Some(cached) = self.cache.get(key) {
    return Ok(cached);
}
// Otherwise read and cache
let data = self.read_from_disk()?;
self.cache.insert(key, data.clone());
Ok(data)
```

**Pattern 3: Journal Transaction**
```rust
let txn = journal.begin_transaction()?;
txn.add_inode_update(ino, old, new)?;
txn.add_buffer_update(block, data)?;
journal.commit_transaction(txn)?;
```

**Pattern 4: Binary Search B+tree** (recommended, not everywhere)
```rust
let mut left = 0;
let mut right = num_recs;
while left < right {
    let mid = left + (right - left) / 2;
    if key <= target { left = mid + 1; }
    else { right = mid; }
}
```

### Important Design Decisions

1. **User-Mode vs Kernel-Mode**: User-mode chosen (WinFsp), kernel archived in `_old/`
   - Reason: Easier to develop, debug, deploy
   - Trade-off: Slightly lower performance

2. **Read-Only by Default**: Write ops return `ReadOnly` unless implemented
   - Reason: Security, avoid accidental corruptions
   - Activation: `--writable` flag + full implementation required

3. **No `unsafe`**: Zero unsafe in user-mode crates
   - Reason: Maximum security, avoid UB
   - Trade-off: May be slightly less performant

4. **LRU with TTL**: Caches expire after timeout
   - Reason: Avoid staleness, bounded memory
   - Configuration: Different TTL per cache type

5. **Journal WAL**: Write-Ahead Logging implemented
   - Reason: Consistency after crash (when recovery is implemented)
   - State: Infrastructure OK, replay missing

### Tests to Always Run

**Before Commit:**
```bash
cargo test                     # All tests
cargo clippy -- -D warnings    # Strict linting
cargo fmt -- --check           # Format check
```

**Before Release:**
```bash
cargo test --release           # Optimized tests
cargo bench                    # Benchmarks
cargo doc --document-private-items  # Complete docs
```

**Write Tests (When Implemented):**
```bash
cargo test -p xfs-vfs write_   # Write tests
cargo test -p xfs-vfs allocator  # Allocator tests
cargo test -p xfs-vfs journal  # Journal tests
```

### Quick Metrics

| Component | Completeness | Status |
|-----------|--------------|--------|
| Reading | 100% | ✅ Production-ready |
| Shortform Writing | 30% | ⚠️ Experimental |
| Full Writing | 0% | ❌ Non-functional (allocator) |
| Stability | 10% | 🧪 Tests only |

### Absolute Priorities (Don't Forget)

1. 🔴 **Finish allocator** (mark_allocated, free_blocks)
2. 🔴 **Implement journal recovery** (replay transactions)
3. 🟡 Extent/B+tree directory support
4. 🟡 Local→Extents file conversion
5. 🟢 B+tree optimizations (binary search, caching)

---

## Overview

This document tracks the progress of the XFS driver implementation for Windows in Rust. The project uses a user-mode architecture via WinFsp (`fs-winfsp-glue` → `xfs-mount.exe`).

### Legend
- `[x]` Completed and functional
- `[/]` Partially implemented / In progress
- `[!]` Implemented but with critical bugs/limitations
- `[ ]` Not started

---

## Current Project Status (February 2026)

### Read Operations: ✅ COMPLETE
- ✅ Complete XFS v4 and v5 support with CRC validation
- ✅ All directory formats (shortform, extent, B+tree)
- ✅ All file formats (Local, Extents, Btree)
- ✅ Complete B+tree traversal for large files and directories
- ✅ LRU cache with TTL (inodes, blocks, paths, directories)

### Write Operations: ⚠️ EXPERIMENTAL & PARTIAL

#### ✅ Functional:
- Operations on shortform directories (inline)
  - File/directory creation
  - Entry deletion
  - Rename
  - Automatic shortform → block conversion when full
- Inode allocation (search in IBT, creation, release)
- Writing to Local (inline) and Extents files
- File truncation
- Timestamp updates
- Journal infrastructure (transaction writing)
- All WinFsp callbacks properly implemented

#### ⚠️ Critical Bugs:
- `allocator.mark_allocated()` - **STUB**: does NOT update BNO/CNT B+trees
- `allocator.free_blocks()` - **STUB**: does NOT update B+trees
  - **Major risk**: filesystem corruption due to block reuse

#### ❌ Not Implemented:
- Write operations on extent-based or B+tree directories
- Local → Extents conversion for files exceeding inline size
- Block → Leaf conversion for large directories
- Writing to files in B+tree format
- Journal transaction replay (recovery)

---

## Phase 1: Workspace Infrastructure ✅ COMPLETED

### 1.1 Cargo Workspace Configuration
- [x] Create root `Cargo.toml` workspace
- [x] Configure member crates (4 active crates)
- [x] Configure build profiles (release, dev)

### 1.2 `fs-abstraction` Crate
- [x] `VfsFileSystem` trait (object-safe, Send + Sync)
- [x] `BlockDevice` trait (read_at, write_at)
- [x] `FsError` enum with NTSTATUS mapping
- [x] `CheckedOps` trait for safe arithmetic
- [x] `WindowsString` for UTF-16 conversion

### 1.3 Kernel Crates (Archived)
- [x] `kernel-alloc`, `kernel-sync`, `kernel-etw` moved to `_old/`
- [x] `fs-driver-core` excluded from workspace (kernel-mode not maintained)

---

## Phase 2: XFS Parser ✅ COMPLETED

### 2.1 `xfs-rs` Crate (Pure Rust Parser, no_std)
- [x] Superblock Parsing (v4 and v5)
- [x] Inode Parsing (all data fork formats)
- [x] Extent Parsing (128-bit)
- [x] Directory Parsing (shortform, extent, B+tree)
- [x] Complete B+tree Navigation
- [x] Address Calculation and Big-Endian Conversion
- [x] CRC32C Support for XFS v5
- [x] Serialization (to_bytes) for Superblock, Inode, Extent

### 2.2 Unit Tests
- [x] Superblock tests
- [x] Inode tests
- [x] Extent tests
- [x] Property-based testing with proptest
- [x] Corruption tests

---

## Phase 3: XFS VFS ✅ COMPLETE READING

### 3.1 `xfs-vfs` Crate (VfsFileSystem Implementation)
- [x] `XfsVfs` structure with LRU cache
- [x] Complete implementation of read methods from `VfsFileSystem` trait
- [x] Cache management (inodes: 4096, blocks: 1024, paths: 2048, dirs: 512)
- [x] Reading all file and directory formats

### 3.2 Read Operations (read_ops.rs)
- [x] `read_inode()` - Reading and caching inodes
- [x] `read_file_data()` - Support for Local, Extents, Btree
- [x] `readdir()` - Support for shortform, extent, B+tree
- [x] B+tree traversal with `btree_collect_extents()`

### 3.3 Write Operations (write_ops.rs) ⚠️ PARTIAL
- [x] `WriteOperations` infrastructure with superblock cache
- [x] `read_block()`, `write_block()`, `write_inode()`
- [x] `serialize_data_fork()` - Data fork serialization
- [x] `update_timestamps()` - Timestamp updates

#### Inode Allocation
- [x] `allocate_inode()` - Searching for free inode in IBT
- [x] `find_free_inode_in_ag()` - AG traversal
- [x] `search_ibt_for_free_inodes()` - Inode B+tree traversal
- [x] `free_inode()` - Release and IBT/AGI update

#### Directory Operations
- [x] `create_entry()` - File/directory creation (shortform only)
- [x] `delete_entry()` - Deletion (shortform only)
- [x] `rename_entry()` - Rename (shortform only)
- [x] `convert_shortform_to_block_directory()` - Conversion when full
- [x] `add_block_directory_entry()` - Adding to block directory
- [!] Operations on extent/B+tree directories **NOT IMPLEMENTED**

#### File Operations
- [x] `write_file_data()` - Writing Local and Extents
- [x] `truncate_file()` - Truncation
- [x] `set_times()` - Timestamp updates
- [x] `allocate_blocks_for_inode()` - Block allocation for extension
- [!] Writing to B+tree files **NOT IMPLEMENTED**
- [!] Local → Extents conversion **NOT IMPLEMENTED**

### 3.4 Block Allocator (allocator.rs) ⚠️ CRITICAL
- [x] `allocate_blocks()` - Search in CNT tree
- [x] `search_cnt_tree()` - B+tree CNT traversal
- [x] `read_agf()` - Read AG Free header
- [!] `mark_allocated()` - **STUB**: Does NOT update BNO/CNT B+trees
- [!] `free_blocks()` - **STUB**: Does NOT update B+trees

**⚠️ MAJOR ISSUE**: Blocks are found but never marked as allocated in allocation B+trees. This causes:
- Reuse of the same blocks on consecutive writes
- Guaranteed filesystem corruption
- Data loss

### 3.5 Journal (journal.rs) ⚠️ PARTIAL
- [x] `LogRecordHeader` - Log record format
- [x] `Transaction` - Transaction structure with items
- [x] `Journal` - Main journal manager
- [x] `begin_transaction()`, `commit_transaction()`
- [x] `add_inode_update()`, `add_buffer_update()`, `add_directory_op()`
- [x] `write_transaction_to_log()` - Serialization with CRC
- [x] `write_log_data()` - Writing with wrap-around
- [x] `write_commit_record()` - Commit record
- [x] `shutdown()`, `write_unmount_record()`
- [!] `recover()` - **INCOMPLETE**: Scans head LSN but NO transaction replay
- [!] `ensure_log_space()` - Simplified, no real checkpoints

**⚠️ ISSUE**: Transactions are written to the log but are never replayed after a crash, making the log useless for recovery.

### 3.6 Directory Operations (directory.rs) ✅ READ ONLY
- [x] `parse_directory_entries()` - Dispatch to correct parser
- [x] `parse_shortform_directory_entries()` - Inline directories
- [x] `parse_extent_directory_entries()` - Block-based directories
- [x] `parse_btree_directory_entries()` - Large B+tree directories
- [x] `parse_directory_block()` - Directory data blocks
- [x] `find_entry_by_name()` - Name search
- [ ] No write operations (all in write_ops.rs)

---

## Phase 4: WinFsp Integration ✅ COMPLETED

### 4.1 `fs-winfsp-glue` Crate
- [x] CLI with clap (scan, mount, version)
- [x] Automatic XFS disk detection
- [x] Mounting via `\\.\PhysicalDriveN` or image file
- [x] All WinFsp callbacks implemented

### 4.2 WinFsp Callbacks (context.rs)
- [x] `get_volume_info()` - Volume info
- [x] `get_security_by_name()` - Security by name
- [x] `open()` - File opening
- [x] `close()` - Closing
- [x] `read()` - Reading delegated to `VfsFileSystem::read()`
- [x] `write()` - Writing delegated to `VfsFileSystem::write()`
- [x] `get_file_info()` - Metadata
- [x] `set_basic_info()` - Timestamps
- [x] `set_file_size()` - Truncation/extension
- [x] `can_delete()` - Deletion check
- [x] `rename()` - Rename
- [x] `read_directory()` - Enumeration
- [x] `create()` - File/directory creation
- [x] `overwrite()` - Overwriting
- [x] `cleanup()` - Delete-on-close
- [ ] `set_security()` - Permissions (not implemented)

### 4.3 Disk I/O (disk.rs)
- [x] `BlockDevice` trait for reading
- [x] `DiskWriter` trait for writing
- [x] `PhysicalDisk` - Windows physical disk access
- [x] `ImageFileWriter` - Image file read/write
- [x] Aligned and non-aligned sector management

---

## Phase 5: Build & Deploy ✅ COMPLETED

### 5.1 Build Configuration
- [x] `Cargo.toml` with 4-crate workspace
- [x] `Makefile.toml` for cargo-make
- [x] `rustfmt.toml` with nightly features
- [x] Nightly toolchain required

### 5.2 PowerShell Scripts
- [x] `scripts/build.ps1`
- [x] `scripts/install.ps1`
- [x] `scripts/uninstall.ps1`

---

## Phase 6: Tests & Validation ✅ PARTIAL

### 6.1 Unit Tests
- [x] `xfs-rs` tests (parsing)
- [x] `fs-abstraction` tests
- [x] `xfs-vfs` tests (read operations)
- [/] `xfs-vfs` tests (write operations - partial)

### 6.2 Integration Tests
- [x] Creation of test XFS images
- [x] Mount/unmount tests
- [x] File reading tests (all formats)
- [x] Directory navigation tests (all formats)
- [x] Large file tests with B+tree
- [/] Write tests (only shortform directories)

### 6.3 Fuzzing
- [x] Proptest for xfs-rs
- [x] Tests with corrupted images
- [ ] AFL++ via WSL2 (optional)

---

## Phase 7: Documentation ✅ COMPLETED

- [x] Complete README.md
- [x] CLAUDE.md for development guidance
- [x] API documentation (rustdoc)
- [x] `docs/IMPLEMENTATION_TRACKER.md` (progress tracker in English)
- [x] `docs/WRITE_SUPPORT_STATUS.md` (write operation status)
- [x] `docs/XFS_Driver_v4.md` (complete specification)
- [x] `docs/MODULAR_VFS_ARCHITECTURE.md` (VFS architecture)

---

## WEAKNESS & BUG ANALYSIS

### B+Tree Analysis (btree_analysis.txt - 2026-01-21)

This analysis identified several weaknesses in the original B+tree implementation:

#### 1. Error Handling
**Identified Issues:**
- Incomplete magic number validation
- Insufficient distinction between error types (corruption vs not-found)
- Insufficient edge case handling in `find_child_ptr()`

**Current State (2026-02-06):**
- ✅ **FIXED**: `BmbtRoot::find_child_ptr()` now implements binary search
- ✅ **IMPROVED**: Better error handling with specific types
- ✅ **IMPROVED**: Buffer validation with `CheckedSliceOps`

#### 2. Data Validation and Memory Security
**Identified Issues:**
- No validation that `num_recs` is consistent with buffer size
- Unsafe buffer access in `get_extent_for_offset()`
- No boundary checking in `btree_collect_extents()`
- Risk of out-of-bounds reads

**Current State (2026-02-06):**
- ✅ **IMPROVED**: Use of `CheckedSliceOps` for secure access
- ⚠️ **REMAINING**: Validation that `num_recs` is consistent with buffer size
- ⚠️ **REMAINING**: Overflow protection in index calculations
- ⚠️ **REMAINING**: Cycle detection in sibling traversal

#### 3. Search Algorithms
**Identified Issues:**
- Linear search O(n) in `get_ptr_for_offset()` instead of binary O(log n)
- Suboptimal traversal in `btree_collect_extents()`
- No infinite loop protection

**Current State (2026-02-06):**
- ✅ **FIXED**: `BmbtRoot::find_child_ptr()` uses binary search
- ⚠️ **REMAINING**: `BtreeBlockLong::get_ptr_for_offset()` still uses linear search
- ⚠️ **REMAINING**: Cycle detection in sibling traversal

#### 4. v4 vs v5 Version Management
**Identified Issues:**
- Inconsistencies between `is_v5` parameter and magic number detection
- Insufficient validation of v5-specific fields
- No cross-validation

**Current State (2026-02-06):**
- ✅ **FIXED**: Automatic detection via magic numbers
- ✅ **IMPROVED**: CRC validation for v5
- ✅ **IMPROVED**: Proper propagation of `is_v5` parameter

#### 5. Documentation
**Current State (2026-02-06):**
- ✅ **IMPROVED**: Complete documentation for most functions
- ✅ **IMPROVED**: Comments on v4/v5 differences
- ⚠️ **REMAINING**: Document expected invariants
- ⚠️ **REMAINING**: Add usage examples

### Security Analysis (analysis_report_2026-02-01.md)

#### 1. TODO Placeholders
**Identified in Report:**
- ✅ **RESOLVED**: B+tree traversal for directories (implemented 2026-02-05)
- ⚠️ **PARTIAL**: Write operations (only shortform)
- ❌ **NOT RESOLVED**: Complete B+tree parsing for writing
- ❌ **NOT RESOLVED**: Journal integration for recovery
- ❌ **NOT RESOLVED**: CRC recalculation on modifications

#### 2. Security Vulnerabilities
**Buffer Overflows:**
```rust
// Example of potentially dangerous code identified:
let ino_in_buffer = u64::from_be_bytes(buffer[0x98..0xA0].try_into().unwrap());
```

**Current State (2026-02-06):**
- ✅ **IMPROVED**: Use of `CheckedSliceOps::get_slice_checked()`
- ⚠️ **REMAINING**: Replace all `.unwrap()` with error handling
- ⚠️ **REMAINING**: Add size validation before slicing

**Unsafe Code:**
- ✅ **N/A**: Kernel crates (`kernel-sync`, etc.) archived in `_old/`
- ✅ **NONE** unsafe in active user-mode crates

#### 3. Error Handling
**Identified Issues:**
- Use of `todo!()` and `unimplemented!()` that panic
- Functions returning `FsError::NotImplemented` instead of real implementations

**Current State (2026-02-06):**
- ✅ **IMPROVED**: Most `todo!()` replaced with implementations or `NotImplemented`
- ⚠️ **REMAINING**: Stubs in allocator (mark_allocated, free_blocks)
- ⚠️ **REMAINING**: NotImplemented for extent/btree directory operations

#### 4. Write Operations
**State according to report (2026-02-01):**
- Experimental with corruption warnings
- No journal integration
- No rollback mechanisms

**Current State (2026-02-06):**
- ✅ **ADDED**: Complete journal infrastructure
- ✅ **ADDED**: Transactions with commit/abort
- ✅ **ADDED**: CRC for v5
- ❌ **MISSING**: Recovery (transaction replay)
- ❌ **MISSING**: Allocation B+tree updates

#### 5. Resource Management
**Identified Issues:**
- Handles not always closed on error
- Potential memory leaks

**Current State (2026-02-06):**
- ✅ **RESOLVED**: RAII with `Arc<RwLock<>>` for caches
- ✅ **RESOLVED**: Automatic resource management via Drop
- ✅ **RESOLVED**: WinFsp handles resources via its callbacks

---

## CRITICAL BUGS TO FIX (Priority 1)

### 🔴 CRITICAL: Incomplete Block Allocator
**File:** `crates/xfs-vfs/src/allocator.rs`
**Lines:** 144-149 (mark_allocated), 152-155 (free_blocks)

**Problem:**
```rust
pub fn mark_allocated(&mut self, ag: u32, start_agblock: u32, count: u32) -> FsResult<()> {
    warn!("STUB: mark_allocated() AG={} start={} count={} - B+tree update not implemented",
          ag, start_agblock, count);
    Ok(())
}
```

**Impact:**
- Allocated blocks are never marked in BNO/CNT B+trees
- Reallocation of same blocks → guaranteed corruption
- **Filesystem is NOT usable for writing**

**Required Solution:**
1. Implement `update_bno_tree()` to remove/split free extents in BNO tree
2. Implement `update_cnt_tree()` to update CNT tree (sorted by size)
3. Update AGF header (free_blocks, longest_extent)
4. Atomic operations to avoid partial corruption

### 🔴 CRITICAL: Unimplemented Journal Recovery
**File:** `crates/xfs-vfs/src/journal.rs`
**Line:** 418-456 (recover)

**Problem:**
```rust
pub fn recover(&mut self) -> FsResult<()> {
    // Scan for head LSN but does NOT replay committed transactions
    // ...
    Ok(())
}
```

**Impact:**
- Crash during a write = loss of data not yet written to disk
- Journal useless without recovery
- Committed transactions never replayed

**Required Solution:**
1. Parse log records from head LSN
2. Identify complete transactions (with commit record)
3. Replay operations (inode updates, buffer writes, directory ops)
4. Update tail LSN after recovery

---

## FUNCTIONAL LIMITATIONS TO IMPLEMENT (Priority 2)

### 🟡 Extent/B+tree Directory Operations
**Files:** `crates/xfs-vfs/src/write_ops.rs` lines 413, 483, 569, 602

**Missing:**
- `create_entry()` for extent-based directories
- `delete_entry()` for extent-based directories
- `rename_entry()` for extent-based directories
- Block → Leaf conversion for large directories

**Required Solution:**
1. Parse extent-based directory blocks
2. Implement add/delete in directory data blocks
3. Manage leaf blocks and free space maps
4. Implement block → leaf → node conversion

### 🟡 Local → Extents File Conversion
**File:** `crates/xfs-vfs/src/write_ops.rs` line 636, 843

**Missing:**
- Automatic conversion when inline data exceeds inode size
- Block allocation for new extent format

**Required Solution:**
1. Detect when write exceeds max di_size for Local
2. Allocate one or more blocks via allocator
3. Copy inline data to new blocks
4. Change di_format from Local → Extents
5. Create extents in di_u (data fork)

### 🟡 B+tree File Writing
**File:** `crates/xfs-vfs/src/write_ops.rs` line 676

**Missing:**
- Support for writing to files using extent B+tree
- B+tree traversal to find appropriate extents

**Required Solution:**
1. Use `btree_collect_extents()` to find extents covering the offset
2. Write to corresponding blocks
3. Handle allocation of new extents if necessary
4. Update extent B+tree

---

## OPTIMIZATIONS & IMPROVEMENTS (Priority 3)

### 🟢 Binary Search in B+tree
**File:** `crates/xfs-rs/src/btree.rs`
**Function:** `BtreeBlockLong::get_ptr_for_offset()`

**Problem:**
- Uses linear search O(n)
- `BmbtRoot::find_child_ptr()` already uses binary, inconsistent

**Solution:**
Implement binary search as in `find_child_ptr()`

### 🟢 Strict Data Validation
**Files:** All parsers in `xfs-rs`

**Improvements:**
1. Validate that `num_recs * RECORD_SIZE + HEADER_SIZE <= buffer.len()`
2. Check consistency of magic number / v5 version
3. Validate CRC before parsing (v5)
4. Add maximum limits (max B+tree depth, max extents, etc.)

### 🟢 Cycle Detection
**File:** `crates/xfs-rs/src/btree.rs`
**Function:** `btree_collect_extents()`

**Problem:**
- Sibling traversal can loop infinitely if cyclic pointers
- No detection of already visited blocks

**Solution:**
Maintain a `HashSet<u64>` of visited blocks, error if cycle detected

### 🟢 B+tree Node Cache
**File:** `crates/xfs-vfs/src/cache.rs`

**Improvement:**
- Add cache for B+tree nodes (BtreeBlockLong, BmbtRoot)
- Reduce repeated reads during multiple traversals
- Same LRU structure as other caches

---

## NEXT IMMEDIATE STEPS

### Sprint 1: Fix Critical Bugs (2-3 weeks)
1. **Implement complete `mark_allocated()` and `free_blocks()`**
   - Parse and modify BNO B+tree
   - Parse and modify CNT B+tree
   - Update AGF header
   - Unit tests for allocation/release

2. **Implement journal recovery**
   - Parse log records
   - Replay committed transactions
   - Update tail LSN
   - Crash recovery tests

### Sprint 2: Directory Operations (2 weeks)
1. **Support extent-based directories**
   - create_entry for extent format
   - delete_entry for extent format
   - rename_entry for extent format

2. **Block → Leaf Conversion**
   - Detection when block directory is full
   - Create leaf and free space blocks
   - Data migration

### Sprint 3: File Operations (2 weeks)
1. **Local → Extents Conversion**
   - Overflow inline detection
   - Block allocation
   - Data migration
   - Update data fork format

2. **B+tree File Support**
   - Writing via B+tree traversal
   - New extent allocation
   - B+tree structure update

### Sprint 4: Optimizations & Stabilization (2 weeks)
1. **Improve B+tree**
   - Binary search everywhere
   - Cycle detection
   - B+tree node cache

2. **Intensive Testing**
   - Stress tests (concurrent writes)
   - Corruption tests
   - Recovery tests
   - Write operation fuzzing

---

## COMPLETENESS METRICS

### Read Operations
```
████████████████████████████████████████ 100% (10/10)
```
- [x] read() Local files
- [x] read() Extent files
- [x] read() Btree files
- [x] readdir() shortform
- [x] readdir() extent
- [x] readdir() B+tree
- [x] stat() / get_file_info()
- [x] B+tree traversal
- [x] XFS v4/v5 parsing
- [x] CRC validation

### Write Operations (Functional)
```
████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 30% (6/20)
```
- [x] create() shortform directories
- [x] write() Local/Extent files
- [x] unlink() shortform directories
- [x] rename() shortform directories
- [x] truncate() files
- [x] Shortform → block directory conversion
- [ ] create() extent/btree directories
- [ ] unlink() extent/btree directories
- [ ] rename() extent/btree directories
- [ ] write() Btree files
- [ ] Local → Extents file conversion
- [ ] Block → Leaf directory conversion
- [ ] mkdir() all formats
- [ ] rmdir() all formats
- [ ] symlink()
- [ ] Complete setattr()
- [ ] Extended attributes
- [ ] Quotas
- [ ] Project IDs
- [ ] Reflink/dedupe

### Write Infrastructure (Technical Completeness)
```
██████████████████░░░░░░░░░░░░░░░░░░░░░░ 45% (9/20)
```
- [x] XFS structure serialization
- [x] DiskWriter trait
- [x] WriteOperations infrastructure
- [x] Journal structure
- [x] Transaction management
- [x] CRC calculation (v5)
- [x] Inode allocation
- [x] Block searching (CNT tree)
- [x] WinFsp callbacks
- [!] Block allocation tracking (STUB)
- [ ] Block deallocation tracking
- [ ] Journal recovery
- [ ] Checkpoint mechanism
- [ ] Dirty inode tracking
- [ ] Extent tree modification
- [ ] Directory B+tree modification
- [ ] AGF header updates
- [ ] Superblock updates
- [ ] Filesystem dirty flag
- [ ] Graceful unmount

### Stability & Production-Ready
```
████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░ 10% (2/20)
```
- [x] Unit tests (read operations)
- [x] API documentation
- [ ] Unit tests (write operations)
- [ ] Integration tests (write)
- [ ] Crash recovery tests
- [ ] Stress tests
- [ ] Write operation fuzzing
- [ ] Filesystem checker validation
- [ ] Performance benchmarks
- [ ] Multi-threading tests
- [ ] Corruption detection tests
- [ ] Limits tests (max file size, etc.)
- [ ] Memory leak detection
- [ ] Code coverage > 80%
- [ ] Security audit
- [ ] Peer review
- [ ] Production deployment guide
- [ ] Monitoring & logging
- [ ] Rollback mechanism
- [ ] Backup/restore procedures

---

## IMPORTANT NOTES

### ⚠️ Warnings
1. **DO NOT USE IN PRODUCTION** with write support enabled
2. **ALWAYS HAVE A BACKUP** before enabling write
3. Incomplete allocator **GUARANTEES CORRUPTION** on multiple writes
4. Journal without recovery does **NOT** protect against crashes

### 🎯 Short-Term Goals
- Finish allocator (mark_allocated, free_blocks) = **Absolute Priority**
- Implement journal recovery = **Second Priority**
- Exhaustive tests before any real usage

### 📊 Overall Status
- **Reading**: Production-ready ✅
- **Shortform Writing**: Experimental ⚠️
- **Complete Writing**: Non-functional ❌
- **Stability**: Light testing only 🧪

---

## CHANGELOG

### 2026-02-06
- Complete roadmap update based on actual code analysis
- Integration of security analyses (btree_analysis.txt, analysis_report_2026-02-01.md)
- Precise identification of critical stubs (allocator)
- Added completeness metrics
- Clear prioritization of critical bugs vs improvements

### 2026-02-05
- Implemented B+tree traversal for directories
- Added `parse_btree_directory_entries()` using `btree_collect_extents()`
- Added `is_v5` parameter to `parse_directory_entries()`
- Added `ClosureBlockReader` adapter for bridges

### 2026-01-21
- In-depth B+tree analysis (btree_analysis.txt)
- Identified algorithm weakness
- Recommended validation and security improvements

### 2026-02-01
- Complete security analysis report (analysis_report_2026-02-01.md)
- Identified TODOs and placeholders
- Documented buffer overflow vulnerabilities
- Recommended testing and fuzzing

---

**End of Document**