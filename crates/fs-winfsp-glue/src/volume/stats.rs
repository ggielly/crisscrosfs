//! Volume statistics tracking.

use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics for a mounted volume.
#[derive(Debug, Default)]
pub struct VolumeStats {
    /// Total bytes read from disk.
    pub bytes_read: AtomicU64,
    /// Total bytes written (will be 0 for read-only).
    pub bytes_written: AtomicU64,
    /// Number of read operations.
    pub read_ops: AtomicU64,
    /// Number of write operations (will be 0 for read-only).
    pub write_ops: AtomicU64,
    /// Number of directory listings.
    pub dir_listings: AtomicU64,
    /// Number of file opens.
    pub file_opens: AtomicU64,
    /// Number of file closes.
    pub file_closes: AtomicU64,
    /// Number of cache hits (inode).
    pub inode_cache_hits: AtomicU64,
    /// Number of cache misses (inode).
    pub inode_cache_misses: AtomicU64,
    /// Number of cache hits (block).
    pub block_cache_hits: AtomicU64,
    /// Number of cache misses (block).
    pub block_cache_misses: AtomicU64,
    /// Number of errors encountered.
    pub errors: AtomicU64,
}

impl VolumeStats {
    /// Creates a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a read operation.
    pub fn record_read(&self, bytes: u64) {
        self.read_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records a file open.
    pub fn record_open(&self) {
        self.file_opens.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a file close.
    pub fn record_close(&self) {
        self.file_closes.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a directory listing.
    pub fn record_dir_listing(&self) {
        self.dir_listings.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an inode cache hit.
    pub fn record_inode_cache_hit(&self) {
        self.inode_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an inode cache miss.
    pub fn record_inode_cache_miss(&self) {
        self.inode_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a block cache hit.
    pub fn record_block_cache_hit(&self) {
        self.block_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a block cache miss.
    pub fn record_block_cache_miss(&self) {
        self.block_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Records an error.
    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Gets a snapshot of the current statistics.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            read_ops: self.read_ops.load(Ordering::Relaxed),
            write_ops: self.write_ops.load(Ordering::Relaxed),
            dir_listings: self.dir_listings.load(Ordering::Relaxed),
            file_opens: self.file_opens.load(Ordering::Relaxed),
            file_closes: self.file_closes.load(Ordering::Relaxed),
            inode_cache_hits: self.inode_cache_hits.load(Ordering::Relaxed),
            inode_cache_misses: self.inode_cache_misses.load(Ordering::Relaxed),
            block_cache_hits: self.block_cache_hits.load(Ordering::Relaxed),
            block_cache_misses: self.block_cache_misses.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }

    /// Calculates cache hit rates.
    pub fn cache_hit_rates(&self) -> (f64, f64) {
        let inode_hits = self.inode_cache_hits.load(Ordering::Relaxed) as f64;
        let inode_total = inode_hits + self.inode_cache_misses.load(Ordering::Relaxed) as f64;
        let inode_rate = if inode_total > 0.0 {
            inode_hits / inode_total
        } else {
            0.0
        };

        let block_hits = self.block_cache_hits.load(Ordering::Relaxed) as f64;
        let block_total = block_hits + self.block_cache_misses.load(Ordering::Relaxed) as f64;
        let block_rate = if block_total > 0.0 {
            block_hits / block_total
        } else {
            0.0
        };

        (inode_rate, block_rate)
    }
}

/// A point-in-time snapshot of volume statistics.
#[derive(Debug, Clone)]
pub struct StatsSnapshot {
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub dir_listings: u64,
    pub file_opens: u64,
    pub file_closes: u64,
    pub inode_cache_hits: u64,
    pub inode_cache_misses: u64,
    pub block_cache_hits: u64,
    pub block_cache_misses: u64,
    pub errors: u64,
}

impl std::fmt::Display for StatsSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inode_total = self.inode_cache_hits + self.inode_cache_misses;
        let inode_rate = if inode_total > 0 {
            (self.inode_cache_hits as f64 / inode_total as f64) * 100.0
        } else {
            0.0
        };

        let block_total = self.block_cache_hits + self.block_cache_misses;
        let block_rate = if block_total > 0 {
            (self.block_cache_hits as f64 / block_total as f64) * 100.0
        } else {
            0.0
        };

        write!(
            f,
            "Volume Statistics:\n- Bytes Read: {} ({:.2} MB)\n- Read Operations: {}\n- File \
             Opens: {}\n- File Closes: {}\n- Directory Listings: {}\n- Inode Cache: {}/{} ({:.1}% \
             hit rate)\n- Block Cache: {}/{} ({:.1}% hit rate)\n- Errors: {}",
            self.bytes_read,
            self.bytes_read as f64 / (1024.0 * 1024.0),
            self.read_ops,
            self.file_opens,
            self.file_closes,
            self.dir_listings,
            self.inode_cache_hits,
            inode_total,
            inode_rate,
            self.block_cache_hits,
            block_total,
            block_rate,
            self.errors,
        )
    }
}
