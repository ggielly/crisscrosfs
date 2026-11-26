//! Checked block-device I/O helpers shared by the XFS VFS.

use fs_abstraction::{BlockDevice, FsError, FsResult};
use xfs_rs::btree::BlockReader;

/// Validate a byte range without overflowing or crossing the supplied limit.
pub(crate) fn validate_range(offset: u64, len: usize, limit: u64) -> FsResult<()> {
    let len = u64::try_from(len).map_err(|_| FsError::ArithmeticOverflow)?;
    let end = offset.checked_add(len).ok_or(FsError::ArithmeticOverflow)?;
    if end > limit {
        return Err(FsError::Corrupted);
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes after checking both filesystem and device
/// bounds.
///
/// `limit` is the filesystem size derived from `total_blocks * block_size`.
/// The device size is checked independently so a truncated backing device
/// cannot be mistaken for a short read at run time.
pub(crate) fn read_exact_at(
    device: &dyn BlockDevice,
    offset: u64,
    buf: &mut [u8],
    limit: u64,
) -> FsResult<()> {
    validate_range(offset, buf.len(), limit)?;
    validate_range(offset, buf.len(), device.size())?;

    if buf.is_empty() {
        return Ok(());
    }

    let mut completed = 0usize;
    while completed < buf.len() {
        let current_offset = offset
            .checked_add(completed as u64)
            .ok_or(FsError::ArithmeticOverflow)?;
        let read = device.read_at(current_offset, &mut buf[completed..])?;
        if read == 0 {
            return Err(FsError::Corrupted);
        }
        if read > buf.len() - completed {
            return Err(FsError::SecurityViolation);
        }
        completed += read;
    }
    Ok(())
}

/// Write exactly `data.len()` bytes after checking both filesystem and device
/// bounds.
///
/// Positional writes are allowed to complete partially.  Every retry advances
/// by the number of bytes reported by the device; zero progress is an error and
/// a device that reports more than requested is treated as a contract
/// violation.
#[allow(dead_code)] // Used by the transactional writer once enabled.
pub(crate) fn write_exact_at(
    device: &dyn BlockDevice,
    offset: u64,
    data: &[u8],
    limit: u64,
) -> FsResult<()> {
    validate_range(offset, data.len(), limit)?;
    validate_range(offset, data.len(), device.size())?;

    if data.is_empty() {
        return Ok(());
    }

    let mut completed = 0usize;
    while completed < data.len() {
        let current_offset = offset
            .checked_add(completed as u64)
            .ok_or(FsError::ArithmeticOverflow)?;
        let written = device.write_at(current_offset, &data[completed..])?;
        if written == 0 {
            return Err(FsError::DiskError);
        }
        if written > data.len() - completed {
            return Err(FsError::SecurityViolation);
        }
        completed += written;
    }
    Ok(())
}

/// Compute the filesystem size with checked arithmetic.
pub(crate) fn filesystem_size(total_blocks: u64, block_size: u32) -> FsResult<u64> {
    if block_size == 0 {
        return Err(FsError::Corrupted);
    }
    total_blocks
        .checked_mul(u64::from(block_size))
        .ok_or(FsError::ArithmeticOverflow)
}

/// Adapter used by the bounded `xfs-rs` B+tree walkers.
pub(crate) struct ClosureBlockReader<'a, F: Fn(u64) -> FsResult<Vec<u8>>>(&'a F);

impl<'a, F: Fn(u64) -> FsResult<Vec<u8>>> ClosureBlockReader<'a, F> {
    pub(crate) fn new(reader: &'a F) -> Self {
        Self(reader)
    }
}

impl<F: Fn(u64) -> FsResult<Vec<u8>>> BlockReader for ClosureBlockReader<'_, F> {
    fn read_block(&self, block_num: u64) -> FsResult<Vec<u8>> {
        (self.0)(block_num)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
        RwLock,
    };

    use fs_abstraction::BlockDevice;

    use super::*;

    struct TestDevice {
        data: RwLock<Vec<u8>>,
        max_read: usize,
        max_write: AtomicUsize,
        reads: AtomicUsize,
        writes: AtomicUsize,
    }

    impl BlockDevice for TestDevice {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> FsResult<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            let data = self.data.read().unwrap();
            let available = data.len().saturating_sub(offset);
            let len = buf.len().min(available).min(self.max_read);
            buf[..len].copy_from_slice(&data[offset..offset + len]);
            Ok(len)
        }

        fn write_at(&self, offset: u64, input: &[u8]) -> FsResult<usize> {
            self.writes.fetch_add(1, Ordering::SeqCst);
            let offset = usize::try_from(offset).map_err(|_| FsError::InvalidArgument)?;
            let mut data = self.data.write().unwrap();
            let available = data.len().saturating_sub(offset);
            let len = input
                .len()
                .min(available)
                .min(self.max_write.load(Ordering::SeqCst));
            data[offset..offset + len].copy_from_slice(&input[..len]);
            Ok(len)
        }

        fn size(&self) -> u64 {
            self.data.read().unwrap().len() as u64
        }
    }

    fn device(max_read: usize) -> Arc<TestDevice> {
        Arc::new(TestDevice {
            data: RwLock::new(vec![0xAA; 64]),
            max_read,
            max_write: AtomicUsize::new(usize::MAX),
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
        })
    }

    #[test]
    fn exact_read_retries_partial_reads() {
        let device = device(7);
        let mut buf = [0u8; 8];
        assert_eq!(read_exact_at(device.as_ref(), 0, &mut buf, 64), Ok(()));
        assert_eq!(buf, [0xAA; 8]);
        assert_eq!(device.reads.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn exact_read_rejects_zero_progress() {
        let device = device(0);
        let mut buf = [0u8; 8];
        assert!(matches!(
            read_exact_at(device.as_ref(), 0, &mut buf, 64),
            Err(FsError::Corrupted)
        ));
    }

    #[test]
    fn exact_read_checks_device_and_filesystem_limits_before_io() {
        let device = device(8);
        let mut buf = [0u8; 8];

        assert!(matches!(
            read_exact_at(device.as_ref(), 60, &mut buf, 64),
            Err(FsError::Corrupted)
        ));
        assert!(matches!(
            read_exact_at(device.as_ref(), 56, &mut buf, 60),
            Err(FsError::Corrupted)
        ));
        assert_eq!(device.reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exact_read_rejects_offset_overflow_before_io() {
        let device = device(8);
        let mut buf = [0u8; 8];
        assert!(matches!(
            read_exact_at(device.as_ref(), u64::MAX, &mut buf, u64::MAX),
            Err(FsError::ArithmeticOverflow)
        ));
        assert_eq!(device.reads.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn exact_write_retries_partial_writes() {
        let device = device(8);
        device.max_write.store(3, Ordering::SeqCst);
        write_exact_at(device.as_ref(), 5, b"abcdefgh", 64).unwrap();
        assert_eq!(&device.data.read().unwrap()[5..13], b"abcdefgh");
        assert_eq!(device.writes.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn exact_write_rejects_zero_progress_and_bounds_before_io() {
        let zero_device = device(8);
        zero_device.max_write.store(0, Ordering::SeqCst);
        assert!(matches!(
            write_exact_at(zero_device.as_ref(), 0, b"x", 64),
            Err(FsError::DiskError)
        ));
        assert_eq!(zero_device.writes.load(Ordering::SeqCst), 1);

        let bounded_device = device(8);
        assert!(matches!(
            write_exact_at(bounded_device.as_ref(), 60, b"12345678", 64),
            Err(FsError::Corrupted)
        ));
        assert!(matches!(
            write_exact_at(bounded_device.as_ref(), 56, b"12345678", 60),
            Err(FsError::Corrupted)
        ));
        assert_eq!(bounded_device.writes.load(Ordering::SeqCst), 0);
    }
}
