//! Disk I/O operations for reading raw XFS data.
//!
//! This module provides access to raw disk sectors, either from:
//! - Physical disks (\\.\PhysicalDriveN)
//! - Partitions (\\.\X:)
//! - Image files

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
    sync::{Arc, Mutex},
};

use windows::{
    core::PCWSTR,
    Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            CreateFileW,
            FlushFileBuffers,
            ReadFile,
            SetFilePointerEx,
            WriteFile,
            FILE_BEGIN,
            FILE_FLAGS_AND_ATTRIBUTES,
            FILE_GENERIC_READ,
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            FILE_SHARE_WRITE,
            OPEN_EXISTING,
        },
    },
};

use crate::error::{Result, XfsWinfspError};

fn checked_sector_size(sector_size: u32) -> Result<u64> {
    if !(512..=65_536).contains(&sector_size) || !sector_size.is_power_of_two() {
        return Err(XfsWinfspError::InvalidArgument(format!(
            "Invalid logical sector size: {sector_size}"
        )));
    }
    Ok(u64::from(sector_size))
}

fn validate_raw_io_args(offset: u64, len: usize) -> Result<()> {
    if offset > i64::MAX as u64 {
        return Err(XfsWinfspError::InvalidArgument(
            "Disk offset exceeds the Win32 signed range".to_string(),
        ));
    }
    if len > u32::MAX as usize {
        return Err(XfsWinfspError::InvalidArgument(
            "Win32 I/O buffer exceeds the u32 length range".to_string(),
        ));
    }
    Ok(())
}

/// Trait for reading raw disk/image data.
pub trait DiskReader: fs_abstraction::BlockDevice + Send + Sync {
    /// Read bytes at a specific offset.
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize>;

    /// Get the total size in bytes.
    fn total_size(&self) -> u64;

    /// Get the sector size (typically 512 or 4096).
    fn get_sector_size(&self) -> u32;

    /// Check if this reader also supports writing.
    fn supports_write(&self) -> bool {
        false
    }

    /// Read data with automatic alignment handling.
    ///
    /// This method handles unaligned reads by reading aligned sectors
    /// and extracting the requested portion.
    fn read_unaligned(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let sector = checked_sector_size(self.get_sector_size())?;
        let sector_usize = usize::try_from(sector).map_err(|_| {
            XfsWinfspError::InvalidArgument("Logical sector size does not fit usize".to_string())
        })?;

        // Calculate the aligned range with checked arithmetic. Buffered Win32
        // I/O does not require this alignment, but keeping one aligned range
        // avoids read/modify/write races in the default writer implementation.
        let aligned_offset = offset & !(sector - 1);
        let offset_in_sector = usize::try_from(offset - aligned_offset).map_err(|_| {
            XfsWinfspError::InvalidArgument("Sector offset does not fit usize".to_string())
        })?;
        let requested_end = offset_in_sector.checked_add(size).ok_or_else(|| {
            XfsWinfspError::InvalidArgument("Unaligned read size overflow".to_string())
        })?;
        let aligned_size_u64 = requested_end
            .checked_add(sector_usize - 1)
            .ok_or_else(|| XfsWinfspError::InvalidArgument("Aligned read size overflow".into()))?
            as u64
            / sector
            * sector;
        aligned_offset
            .checked_add(aligned_size_u64)
            .ok_or_else(|| {
                XfsWinfspError::InvalidArgument("Aligned read offset overflow".into())
            })?;

        // Do not allocate beyond a known device size. A short read at EOF is
        // still returned as the available prefix, preserving Read semantics.
        if offset >= self.total_size() || aligned_offset >= self.total_size() {
            return Ok(Vec::new());
        }
        let readable = usize::try_from((self.total_size() - aligned_offset).min(aligned_size_u64))
            .map_err(|_| {
                XfsWinfspError::InvalidArgument("Aligned read size does not fit usize".to_string())
            })?;
        let mut aligned_buffer = vec![0u8; readable];
        let bytes_read = self.read_raw_at(aligned_offset, &mut aligned_buffer)?;
        if bytes_read > aligned_buffer.len() {
            return Err(XfsWinfspError::DiskError(
                "Disk reader returned more bytes than requested".to_string(),
            ));
        }

        if bytes_read < requested_end {
            let available = bytes_read.saturating_sub(offset_in_sector);
            if available == 0 {
                return Ok(Vec::new());
            }
            let to_copy = size.min(available);
            return Ok(aligned_buffer[offset_in_sector..offset_in_sector + to_copy].to_vec());
        }

        Ok(aligned_buffer[offset_in_sector..offset_in_sector + size].to_vec())
    }

    /// Read a single block from disk.
    fn read_block(&self, block_number: u64, block_size: u32) -> Result<Vec<u8>> {
        let offset = block_number
            .checked_mul(block_size as u64)
            .ok_or_else(|| XfsWinfspError::XfsError("Block offset overflow".to_string()))?;

        let mut buffer = vec![0u8; block_size as usize];
        read_exact_at(self, offset, &mut buffer)?;
        Ok(buffer)
    }

    /// Read multiple contiguous blocks.
    fn read_blocks(&self, start_block: u64, block_count: u32, block_size: u32) -> Result<Vec<u8>> {
        let offset = start_block
            .checked_mul(block_size as u64)
            .ok_or_else(|| XfsWinfspError::XfsError("Block offset overflow".to_string()))?;

        let total_size = (block_count as usize)
            .checked_mul(block_size as usize)
            .ok_or_else(|| XfsWinfspError::XfsError("Block size overflow".to_string()))?;

        let mut buffer = vec![0u8; total_size];
        read_exact_at(self, offset, &mut buffer)?;
        Ok(buffer)
    }
}

/// Trait for writing raw disk/image data.
///
/// This extends DiskReader to provide write capabilities.
/// Not all disk readers support writing (e.g., read-only images).
#[allow(dead_code)]
pub(crate) trait DiskWriter: DiskReader {
    /// Write bytes at a specific offset.
    fn write_raw_at(&self, offset: u64, data: &[u8]) -> Result<usize>;

    /// Write data with automatic alignment handling.
    ///
    /// This method handles unaligned writes by:
    /// 1. Reading the affected sectors
    /// 2. Modifying the relevant bytes
    /// 3. Writing the sectors back
    fn write_unaligned(&self, offset: u64, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let sector = checked_sector_size(self.get_sector_size())?;
        let sector_usize = usize::try_from(sector).map_err(|_| {
            XfsWinfspError::InvalidArgument("Logical sector size does not fit usize".to_string())
        })?;
        let data_len = u64::try_from(data.len()).map_err(|_| {
            XfsWinfspError::InvalidArgument("Write size does not fit u64".to_string())
        })?;
        let end = offset
            .checked_add(data_len)
            .ok_or_else(|| XfsWinfspError::InvalidArgument("Write offset overflow".to_string()))?;
        if end > self.total_size() {
            return Err(XfsWinfspError::InvalidArgument(
                "Write extends beyond the device".to_string(),
            ));
        }

        let aligned_offset = offset & !(sector - 1);
        let offset_in_sector = usize::try_from(offset - aligned_offset).map_err(|_| {
            XfsWinfspError::InvalidArgument("Sector offset does not fit usize".to_string())
        })?;
        let requested_end = offset_in_sector.checked_add(data.len()).ok_or_else(|| {
            XfsWinfspError::InvalidArgument("Unaligned write size overflow".to_string())
        })?;
        let aligned_size_u64 = requested_end
            .checked_add(sector_usize - 1)
            .ok_or_else(|| XfsWinfspError::InvalidArgument("Aligned write size overflow".into()))?
            as u64
            / sector
            * sector;
        let aligned_size = usize::try_from(aligned_size_u64).map_err(|_| {
            XfsWinfspError::InvalidArgument("Aligned write size does not fit usize".to_string())
        })?;

        // A read/modify/write must never use zero-filled data after a short
        // read: doing so would destroy the untouched edges of the sector.
        let mut aligned_buffer = vec![0u8; aligned_size];
        read_exact_at(self, aligned_offset, &mut aligned_buffer)?;
        aligned_buffer[offset_in_sector..requested_end].copy_from_slice(data);

        // Positional writes may legally complete partially. Continue until
        // the entire aligned range is persistent before reporting success.
        write_all_at(self, aligned_offset, &aligned_buffer)?;
        Ok(data.len())
    }

    /// Write a single block to disk.
    fn write_block(&self, block_number: u64, block_size: u32, data: &[u8]) -> Result<()> {
        if data.len() != block_size as usize {
            return Err(XfsWinfspError::InvalidArgument(format!(
                "Data size {} doesn't match block size {}",
                data.len(),
                block_size
            )));
        }

        let offset = block_number
            .checked_mul(block_size as u64)
            .ok_or_else(|| XfsWinfspError::XfsError("Block offset overflow".to_string()))?;

        write_all_at(self, offset, data)?;
        Ok(())
    }

    /// Flush any cached writes to disk.
    fn flush_raw(&self) -> Result<()> {
        Ok(()) // Default: no-op
    }
}

/// Read exactly `buffer.len()` bytes, retrying positional short reads.
fn read_exact_at<R: DiskReader + ?Sized>(reader: &R, offset: u64, buffer: &mut [u8]) -> Result<()> {
    let mut completed = 0usize;
    while completed < buffer.len() {
        let current_offset = offset
            .checked_add(completed as u64)
            .ok_or_else(|| XfsWinfspError::DiskError("Read offset overflow".to_string()))?;
        let count = reader.read_raw_at(current_offset, &mut buffer[completed..])?;
        if count == 0 {
            return Err(XfsWinfspError::DiskError(format!(
                "Short read at offset {current_offset}: expected {} bytes, got {completed}",
                buffer.len()
            )));
        }
        if count > buffer.len() - completed {
            return Err(XfsWinfspError::DiskError(
                "Disk reader returned more bytes than requested".to_string(),
            ));
        }
        completed += count;
    }
    Ok(())
}

/// Write the entire buffer, retrying positional partial writes.
#[allow(dead_code)]
fn write_all_at<W: DiskWriter + ?Sized>(writer: &W, offset: u64, buffer: &[u8]) -> Result<()> {
    let mut completed = 0usize;
    while completed < buffer.len() {
        let current_offset = offset
            .checked_add(completed as u64)
            .ok_or_else(|| XfsWinfspError::DiskError("Write offset overflow".to_string()))?;
        let count = writer.write_raw_at(current_offset, &buffer[completed..])?;
        if count == 0 {
            return Err(XfsWinfspError::DiskError(format!(
                "Short write at offset {current_offset}: expected {} bytes, wrote {completed}",
                buffer.len()
            )));
        }
        if count > buffer.len() - completed {
            return Err(XfsWinfspError::DiskError(
                "Disk writer returned more bytes than requested".to_string(),
            ));
        }
        completed += count;
    }
    Ok(())
}

/// Reader for image files (.img, .raw, etc.).
pub struct ImageFileReader {
    file: std::sync::Mutex<File>,
    size: u64,
}

impl ImageFileReader {
    /// Open an image file for reading.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        // Deny write sharing so an external process cannot mutate the image
        // while it is mounted (which would mix metadata generations).
        #[cfg(windows)]
        let file = {
            use std::os::windows::fs::OpenOptionsExt;

            std::fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ.0)
                .open(path.as_ref())?
        };
        #[cfg(not(windows))]
        let file = File::open(path.as_ref())?;
        let size = file.metadata()?.len();

        Ok(Self {
            file: std::sync::Mutex::new(file),
            size,
        })
    }
}

impl DiskReader for ImageFileReader {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(offset))?;
        let bytes_read = file.read(buffer)?;
        Ok(bytes_read)
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn get_sector_size(&self) -> u32 {
        512 // Default for image files
    }
}

// BlockDevice trait implementation for cross-crate compatibility
impl fs_abstraction::BlockDevice for ImageFileReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_abstraction::FsResult<usize> {
        DiskReader::read_raw_at(self, offset, buf).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn size(&self) -> u64 {
        DiskReader::total_size(self)
    }

    fn sector_size(&self) -> u32 {
        DiskReader::get_sector_size(self)
    }
}

/// Read-write accessor for image files (.img, .raw, etc.).
///
/// Unlike ImageFileReader, this opens the file with read-write permissions
/// and implements the DiskWriter trait.
#[allow(dead_code)]
pub(crate) struct ImageFileWriter {
    file: std::sync::Mutex<File>,
    size: u64,
}

#[allow(dead_code)]
impl ImageFileWriter {
    /// Open an image file for reading and writing.
    pub(crate) fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        use std::fs::OpenOptions;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_ref())?;
        let size = file.metadata()?.len();

        Ok(Self {
            file: std::sync::Mutex::new(file),
            size,
        })
    }

    /// Create a new image file with the specified size.
    pub(crate) fn create<P: AsRef<Path>>(path: P, size: u64) -> Result<Self> {
        use std::fs::OpenOptions;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path.as_ref())?;

        // Set the file size
        file.set_len(size)?;

        Ok(Self {
            file: std::sync::Mutex::new(file),
            size,
        })
    }
}

impl DiskReader for ImageFileWriter {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(offset))?;
        let bytes_read = file.read(buffer)?;
        Ok(bytes_read)
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn get_sector_size(&self) -> u32 {
        512 // Default for image files
    }

    fn supports_write(&self) -> bool {
        true
    }
}

impl DiskWriter for ImageFileWriter {
    fn write_raw_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        use std::io::Write;

        let mut file = self.file.lock().unwrap();
        file.seek(SeekFrom::Start(offset))?;
        let bytes_written = file.write(data)?;
        Ok(bytes_written)
    }

    fn flush_raw(&self) -> Result<()> {
        let file = self.file.lock().unwrap();
        file.sync_all()?;
        Ok(())
    }
}

// BlockDevice trait implementation for cross-crate compatibility
impl fs_abstraction::BlockDevice for ImageFileWriter {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_abstraction::FsResult<usize> {
        DiskReader::read_raw_at(self, offset, buf).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> fs_abstraction::FsResult<usize> {
        DiskWriter::write_raw_at(self, offset, data).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn size(&self) -> u64 {
        DiskReader::total_size(self)
    }

    fn sector_size(&self) -> u32 {
        DiskReader::get_sector_size(self)
    }

    fn flush(&self) -> fs_abstraction::FsResult<()> {
        DiskWriter::flush_raw(self).map_err(|_| fs_abstraction::FsError::DiskError)
    }
}

/// Reader for a partition within another disk reader.
/// Wraps another DiskReader and applies an offset.
pub struct PartitionReader {
    inner: Arc<dyn DiskReader>,
    offset: u64,
    size: u64,
}

impl PartitionReader {
    /// Create a new partition reader.
    pub fn new(inner: Arc<dyn DiskReader>, offset: u64, size: u64) -> Self {
        Self {
            inner,
            offset,
            size,
        }
    }
}

impl DiskReader for PartitionReader {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() || offset >= self.size {
            return Ok(0);
        }
        let actual_offset = self.offset.checked_add(offset).ok_or_else(|| {
            XfsWinfspError::DiskError("Partition read offset overflow".to_string())
        })?;

        let max_read = (self.size - offset).min(buffer.len() as u64) as usize;
        self.inner
            .read_raw_at(actual_offset, &mut buffer[..max_read])
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn get_sector_size(&self) -> u32 {
        self.inner.get_sector_size()
    }
}

impl fs_abstraction::BlockDevice for PartitionReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_abstraction::FsResult<usize> {
        DiskReader::read_raw_at(self, offset, buf).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn size(&self) -> u64 {
        DiskReader::total_size(self)
    }

    fn sector_size(&self) -> u32 {
        DiskReader::get_sector_size(self)
    }
}

/// Wraps a DiskWriter and applies an offset for partition access.
#[allow(dead_code)]
pub(crate) struct PartitionWriter {
    inner: Arc<dyn DiskWriter>,
    offset: u64,
    size: u64,
}

#[allow(dead_code)]
impl PartitionWriter {
    /// Create a new partition writer.
    pub(crate) fn new(inner: Arc<dyn DiskWriter>, offset: u64, size: u64) -> Self {
        Self {
            inner,
            offset,
            size,
        }
    }
}

impl DiskReader for PartitionWriter {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if buffer.is_empty() || offset >= self.size {
            return Ok(0);
        }
        let actual_offset = self.offset.checked_add(offset).ok_or_else(|| {
            XfsWinfspError::DiskError("Partition read offset overflow".to_string())
        })?;
        let max_read = (self.size - offset).min(buffer.len() as u64) as usize;
        self.inner
            .read_raw_at(actual_offset, &mut buffer[..max_read])
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn get_sector_size(&self) -> u32 {
        self.inner.get_sector_size()
    }

    fn supports_write(&self) -> bool {
        true
    }
}

impl DiskWriter for PartitionWriter {
    fn write_raw_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        let data_len = u64::try_from(data.len()).map_err(|_| {
            XfsWinfspError::InvalidArgument("Partition write size does not fit u64".to_string())
        })?;
        let end = offset.checked_add(data_len).ok_or_else(|| {
            XfsWinfspError::InvalidArgument("Partition write offset overflow".to_string())
        })?;
        if end > self.size {
            return Err(XfsWinfspError::InvalidArgument(
                "Write extends beyond partition bounds".to_string(),
            ));
        }
        let actual_offset = self.offset.checked_add(offset).ok_or_else(|| {
            XfsWinfspError::DiskError("Partition write offset overflow".to_string())
        })?;
        self.inner.write_raw_at(actual_offset, data)
    }

    fn flush_raw(&self) -> Result<()> {
        self.inner.flush_raw()
    }
}

impl fs_abstraction::BlockDevice for PartitionWriter {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_abstraction::FsResult<usize> {
        DiskReader::read_raw_at(self, offset, buf).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> fs_abstraction::FsResult<usize> {
        DiskWriter::write_raw_at(self, offset, data).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn size(&self) -> u64 {
        DiskReader::total_size(self)
    }

    fn sector_size(&self) -> u32 {
        DiskReader::get_sector_size(self)
    }

    fn flush(&self) -> fs_abstraction::FsResult<()> {
        DiskWriter::flush_raw(self).map_err(|_| fs_abstraction::FsError::DiskError)
    }
}

/// Reader for physical Windows disks.
pub struct PhysicalDiskReader {
    handle: HANDLE,
    size: u64,
    sector_size: u32,
    /// Serialises every operation on the shared handle, including seeks,
    /// reads, retries, and the extended-DASD IOCTL.
    io_lock: Mutex<()>,
}

// SAFETY: HANDLE is an opaque Win32 resource and is not modelled as Send/Sync
// by the windows crate. Every operation using it is protected by `io_lock`;
// construction-time geometry IOCTLs run before the handle is shared, and
// `CloseHandle` runs only from Drop after all shared references are gone.
unsafe impl Send for PhysicalDiskReader {}
unsafe impl Sync for PhysicalDiskReader {}

impl PhysicalDiskReader {
    /// Open a physical disk by number (e.g., 0 for \\.\PhysicalDrive0).
    pub fn open(disk_number: u32) -> Result<Self> {
        let path = format!("\\\\.\\PhysicalDrive{}", disk_number);
        Self::open_by_path(&path)
    }

    /// Open a partition by drive letter (e.g., "D:").
    pub fn open_partition(drive_letter: char) -> Result<Self> {
        if !drive_letter.is_ascii_alphabetic() {
            return Err(XfsWinfspError::InvalidArgument(format!(
                "Partition must be one ASCII drive letter, got {drive_letter:?}"
            )));
        }
        let path = format!("\\\\.\\{}:", drive_letter.to_ascii_uppercase());
        Self::open_by_path(&path)
    }

    /// Open a disk or partition by path.
    pub fn open_by_path(path: &str) -> Result<Self> {
        if path.is_empty() || path.contains('\0') {
            return Err(XfsWinfspError::InvalidArgument(
                "Disk path must be non-empty and contain no NUL bytes".to_string(),
            ));
        }
        tracing::debug!("open_by_path: {}", path);
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        tracing::debug!("Wide path created with {} characters", wide_path.len());

        // Different types of paths may need different flags
        use windows::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_FLAG_RANDOM_ACCESS};

        // Use buffered I/O: unbuffered I/O would require sector-aligned buffer
        // addresses and lengths, but the VFS passes ordinary `Vec<u8>` buffers
        // of arbitrary alignment/length. The OS cache handles alignment for us.
        let flags = if path.contains("HarddiskVolume") {
            tracing::debug!("Detected HarddiskVolume path, using FILE_ATTRIBUTE_NORMAL only");
            FILE_ATTRIBUTE_NORMAL.0
        } else {
            tracing::debug!("Using raw disk access flags");
            let mut f = FILE_ATTRIBUTE_NORMAL.0;
            f |= FILE_FLAG_RANDOM_ACCESS.0;
            f
        };

        tracing::debug!("Attempting to call CreateFileW with flags: 0x{:X}", flags);
        tracing::debug!("Path: {}", path);
        tracing::debug!("Generic read access: 0x{:X}", FILE_GENERIC_READ.0);
        tracing::debug!("Share mode: FILE_SHARE_READ only");

        // Read-only handle and no write sharing: this prevents an external
        // writer from modifying the volume while it is being parsed/mounted,
        // which would otherwise mix old and new metadata.
        let (access, share_mode) = (FILE_GENERIC_READ.0, FILE_SHARE_READ);

        tracing::debug!("Final access rights: 0x{:X}", access);
        tracing::debug!("Final share mode: 0x{:X}", share_mode.0);

        let handle = unsafe {
            let result = CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                access,
                share_mode,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(flags),
                None,
            );

            // Check for error and provide more specific information
            match result {
                Ok(h) => {
                    tracing::debug!("CreateFileW succeeded, handle: {:?}", h);
                    h
                }
                Err(e) => {
                    tracing::error!("CreateFileW failed for path {}: {}", path, e);
                    tracing::error!("Error code: 0x{:X} ({})", e.code().0, e.message());

                    // Special handling for volume access denied errors
                    let error_code = e.code().0 as u32;
                    if error_code == 0x80070005 && path.contains("HarddiskVolume") {
                        tracing::warn!(
                            "Access denied to volume path '{}'. This usually means the volume is \
                             mounted and in use.",
                            path
                        );

                        // Inform the user that mounted volumes typically can't
                        // be accessed directly
                        tracing::warn!("Mounted volumes cannot typically be accessed directly.");
                        tracing::warn!(
                            "Consider unmounting the volume first or using a different approach."
                        );

                        // Return a more specific error message
                        return Err(crate::error::XfsWinfspError::DiskOpenError(format!(
                            "Access denied to mounted volume '{}'. Unmount the volume first or \
                             use a different approach: {}",
                            path, e
                        )));
                    }

                    // Provide specific guidance for common error codes
                    if error_code == 0x80070005 {
                        // ERROR_ACCESS_DENIED
                        tracing::error!("Access denied. This could be due to:");
                        tracing::error!("  - Volume is currently mounted and in use");
                        tracing::error!("  - Another process is accessing the volume");
                        tracing::error!(
                            "  - Insufficient privileges (try running as Administrator)"
                        );
                        tracing::error!("  - Volume shadow copy or other protection mechanism");
                        return Err(crate::error::XfsWinfspError::DiskOpenError(format!(
                            "Access denied opening '{}'. The volume may be in use or protected: {}",
                            path, e
                        )));
                    } else if error_code == 0x80070057 {
                        // ERROR_INVALID_PARAMETER
                        tracing::error!("Invalid parameter. The path format might be incorrect.");
                        return Err(crate::error::XfsWinfspError::DiskOpenError(format!(
                            "Invalid parameter for '{}': {}",
                            path, e
                        )));
                    } else if error_code == 0xC00000AC {
                        // STATUS_ACCESS_DENIED from NT status
                        tracing::error!("NT Status access denied. The volume is likely in use.");
                        return Err(crate::error::XfsWinfspError::DiskOpenError(format!(
                            "NT Status access denied for '{}': {}",
                            path, e
                        )));
                    }

                    return Err(crate::error::XfsWinfspError::DiskOpenError(format!(
                        "Failed to open '{}': {}",
                        path, e
                    )));
                }
            }
        };

        // Geometry is mandatory. Never advertise a fabricated 1 TiB/512-byte
        // device when Windows cannot report the real geometry.
        let (size, sector_size) = match Self::get_disk_geometry(handle) {
            Ok(geometry) => geometry,
            Err(error) => {
                use windows::Win32::Foundation::CloseHandle;
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(error);
            }
        };
        tracing::debug!("Disk size: {}, sector size: {}", size, sector_size);

        Ok(Self {
            handle,
            size,
            sector_size,
            io_lock: Mutex::new(()),
        })
    }

    fn get_disk_geometry(handle: HANDLE) -> Result<(u64, u32)> {
        use windows::Win32::System::{
            Ioctl::{
                DISK_GEOMETRY,
                DISK_GEOMETRY_EX,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                IOCTL_DISK_GET_LENGTH_INFO,
            },
            IO::DeviceIoControl,
        };

        // This runs during construction, before the handle can be shared, so
        // it does not need the instance's I/O mutex.
        let mut geometry_ex: DISK_GEOMETRY_EX = unsafe { std::mem::zeroed() };
        let mut bytes_returned = 0u32;
        let geometry_ex_result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                0,
                Some(&mut geometry_ex as *mut _ as *mut _),
                std::mem::size_of::<DISK_GEOMETRY_EX>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        let size_from_geometry = if geometry_ex_result.is_ok()
            && bytes_returned >= std::mem::size_of::<DISK_GEOMETRY_EX>() as u32
            && geometry_ex.DiskSize > 0
        {
            Some(geometry_ex.DiskSize as u64)
        } else {
            None
        };
        if let (Some(size), Some(sector_size)) = (
            size_from_geometry,
            checked_sector_size(geometry_ex.Geometry.BytesPerSector).ok(),
        ) {
            return Ok((size, sector_size as u32));
        }

        // Some volume handles reject GEOMETRY_EX but still expose the logical
        // sector size through GEOMETRY and the exact byte length separately.
        let mut geometry: DISK_GEOMETRY = unsafe { std::mem::zeroed() };
        bytes_returned = 0;
        let geometry_result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY,
                None,
                0,
                Some(&mut geometry as *mut _ as *mut _),
                std::mem::size_of::<DISK_GEOMETRY>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        let sector_size = if geometry_result.is_ok()
            && bytes_returned >= std::mem::size_of::<DISK_GEOMETRY>() as u32
        {
            checked_sector_size(geometry.BytesPerSector)
                .ok()
                .map(|size| size as u32)
        } else {
            None
        };

        let mut length_info = 0i64;
        bytes_returned = 0;
        let length_result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_LENGTH_INFO,
                None,
                0,
                Some(&mut length_info as *mut _ as *mut _),
                std::mem::size_of::<i64>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };
        let size_from_length = if length_result.is_ok()
            && bytes_returned >= std::mem::size_of::<i64>() as u32
            && length_info > 0
        {
            Some(length_info as u64)
        } else {
            None
        };

        if let (Some(size), Some(sector_size)) = (
            size_from_geometry.or(size_from_length),
            sector_size.or_else(|| {
                checked_sector_size(geometry_ex.Geometry.BytesPerSector)
                    .ok()
                    .map(|size| size as u32)
            }),
        ) {
            return Ok((size, sector_size));
        }

        Err(XfsWinfspError::DiskOpenError(format!(
            "Could not determine the real disk size and logical sector size (size: \
             {size_from_geometry:?}, length: {size_from_length:?}, sector: {sector_size:?})"
        )))
    }
}

impl DiskReader for PhysicalDiskReader {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        tracing::debug!(
            "read_raw_at called: offset={}, buffer_size={}",
            offset,
            buffer.len()
        );
        validate_raw_io_args(offset, buffer.len())?;
        if buffer.is_empty() {
            return Ok(0);
        }

        // Seek + read must be atomic with respect to other readers: the
        // handle's file pointer is shared by every WinFsp worker thread.
        let _guard = self.io_lock.lock().unwrap_or_else(|e| e.into_inner());

        unsafe {
            // For volume handles, we need to use SetFilePointerEx and ReadFile
            // Seek to offset
            let mut new_pos: i64 = 0;
            SetFilePointerEx(self.handle, offset as i64, Some(&mut new_pos), FILE_BEGIN).map_err(
                |e| {
                    tracing::error!("SetFilePointerEx failed: error code 0x{:X}", e.code().0);
                    XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0))
                },
            )?;
            tracing::debug!("Seek successful, new position: {}", new_pos);

            // Read data
            let mut bytes_read: u32 = 0;
            let result = ReadFile(self.handle, Some(buffer), Some(&mut bytes_read), None);

            match result {
                Ok(()) => {
                    tracing::debug!("Read successful: {} bytes read", bytes_read);
                    Ok(bytes_read as usize)
                }
                Err(e) => {
                    tracing::error!("ReadFile failed: error code 0x{:X}", e.code().0);

                    // For volume devices, sometimes we need to use
                    // DeviceIoControl with FSCTL_ALLOW_EXTENDED_DASD_IO to
                    // bypass certain restrictions
                    use windows::Win32::System::{
                        Ioctl::FSCTL_ALLOW_EXTENDED_DASD_IO,
                        IO::DeviceIoControl,
                    };

                    let mut bytes_returned: u32 = 0;
                    let allow_extended_result = DeviceIoControl(
                        self.handle,
                        FSCTL_ALLOW_EXTENDED_DASD_IO,
                        None,
                        0,
                        None,
                        0,
                        Some(&mut bytes_returned),
                        None,
                    );

                    if allow_extended_result.is_ok() {
                        tracing::debug!("Extended DASD I/O allowed, retrying read");

                        // Retry the seek and read
                        SetFilePointerEx(
                            self.handle,
                            offset as i64,
                            Some(&mut new_pos),
                            FILE_BEGIN,
                        )
                        .map_err(|e| {
                            tracing::error!(
                                "Second SetFilePointerEx failed: error code 0x{:X}",
                                e.code().0
                            );
                            XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0))
                        })?;

                        bytes_read = 0;
                        let result_retry =
                            ReadFile(self.handle, Some(buffer), Some(&mut bytes_read), None);
                        match result_retry {
                            Ok(()) => {
                                tracing::debug!("Retry read successful: {} bytes read", bytes_read);
                                Ok(bytes_read as usize)
                            }
                            Err(e_retry) => {
                                tracing::error!(
                                    "Retry ReadFile also failed: error code 0x{:X}",
                                    e_retry.code().0
                                );

                                // Check for specific error codes
                                let error_code = e_retry.code().0 as u32;
                                if error_code == 0x80070057 {
                                    // ERROR_INVALID_PARAMETER
                                    tracing::error!(
                                        "Invalid parameter error when reading from mounted volume."
                                    );
                                    tracing::error!(
                                        "This typically means the volume is mounted and Windows \
                                         restricts direct access."
                                    );
                                    tracing::error!(
                                        "Try using an unmounted volume or a disk image file \
                                         instead."
                                    );
                                }

                                Err(XfsWinfspError::IoError(std::io::Error::from_raw_os_error(
                                    e_retry.code().0,
                                )))
                            }
                        }
                    } else {
                        let dasd_error = allow_extended_result.err().unwrap();
                        tracing::error!(
                            "Failed to enable extended DASD I/O: error code 0x{:X}",
                            dasd_error.code().0
                        );

                        // Check if the failure to enable extended DASD I/O is
                        // due to the volume being mounted
                        let dasd_error_code = dasd_error.code().0 as u32;
                        if dasd_error_code == 0x80070057 {
                            // ERROR_INVALID_PARAMETER
                            tracing::error!("Cannot enable extended DASD I/O on mounted volume.");
                            tracing::error!(
                                "The volume is likely mounted and Windows prevents direct access \
                                 to protect data integrity."
                            );
                            tracing::error!(
                                "To read XFS filesystem, use an unmounted volume or a disk image \
                                 file."
                            );
                        }

                        Err(XfsWinfspError::IoError(std::io::Error::from_raw_os_error(
                            dasd_error.code().0 as i32,
                        )))
                    }
                }
            }
        }
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn get_sector_size(&self) -> u32 {
        self.sector_size
    }
}

impl Drop for PhysicalDiskReader {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

// BlockDevice trait implementation for cross-crate compatibility
impl fs_abstraction::BlockDevice for PhysicalDiskReader {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_abstraction::FsResult<usize> {
        DiskReader::read_raw_at(self, offset, buf).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn size(&self) -> u64 {
        DiskReader::total_size(self)
    }

    fn sector_size(&self) -> u32 {
        DiskReader::get_sector_size(self)
    }
}

/// Read-write accessor for physical disks.
///
/// WARNING: Writing to physical disks can cause data loss!
/// Use with extreme caution.
#[allow(dead_code)]
pub(crate) struct PhysicalDiskWriter {
    handle: HANDLE,
    size: u64,
    sector_size: u32,
    /// Serialises every operation on the shared handle, including seeks,
    /// reads, writes, flushes, and construction-time geometry IOCTLs.
    io_lock: Mutex<()>,
}

// SAFETY: HANDLE is an opaque Win32 resource and is not modelled as Send/Sync
// by the windows crate. Every shared-handle operation (including flush) is
// protected by `io_lock`; geometry IOCTLs run before the handle is shared, and
// `CloseHandle` runs only from Drop after all shared references are gone.
unsafe impl Send for PhysicalDiskWriter {}
unsafe impl Sync for PhysicalDiskWriter {}

#[allow(dead_code)]
impl PhysicalDiskWriter {
    /// Open a physical disk by number for read-write access.
    pub(crate) fn open(disk_number: u32) -> Result<Self> {
        let path = format!("\\\\.\\PhysicalDrive{}", disk_number);
        Self::open_by_path(&path)
    }

    /// Open a partition by drive letter for read-write access.
    pub(crate) fn open_partition(drive_letter: char) -> Result<Self> {
        if !drive_letter.is_ascii_alphabetic() {
            return Err(XfsWinfspError::InvalidArgument(format!(
                "Partition must be one ASCII drive letter, got {drive_letter:?}"
            )));
        }
        let path = format!("\\\\.\\{}:", drive_letter.to_ascii_uppercase());
        Self::open_by_path(&path)
    }

    /// Open a disk or partition by path for read-write access.
    pub(crate) fn open_by_path(path: &str) -> Result<Self> {
        if path.is_empty() || path.contains('\0') {
            return Err(XfsWinfspError::InvalidArgument(
                "Disk path must be non-empty and contain no NUL bytes".to_string(),
            ));
        }
        tracing::debug!("PhysicalDiskWriter::open_by_path: {}", path);
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;

        // Buffered I/O accepts the ordinary, potentially unaligned VFS buffers.
        let flags = FILE_ATTRIBUTE_NORMAL.0;

        // Use GENERIC_READ | GENERIC_WRITE (0x80000000 | 0x40000000 =
        // 0xC0000000) This is different from FILE_GENERIC_READ/WRITE which
        // include additional rights
        const GENERIC_READ: u32 = 0x80000000;
        const GENERIC_WRITE: u32 = 0x40000000;
        let access = GENERIC_READ | GENERIC_WRITE;
        let share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE;

        tracing::debug!(
            "Opening with RW access: 0x{:X}, flags: 0x{:X}",
            access,
            flags
        );

        // Try opening with GENERIC_READ | GENERIC_WRITE first
        let handle = unsafe {
            match CreateFileW(
                PCWSTR(wide_path.as_ptr()),
                access,
                share_mode,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES(flags),
                None,
            ) {
                Ok(h) => h,
                Err(e) => {
                    tracing::warn!(
                        "First attempt failed (0x{:X}), trying with FILE_GENERIC_*",
                        e.code().0
                    );

                    // Fallback: try with FILE_GENERIC_READ | FILE_GENERIC_WRITE
                    match CreateFileW(
                        PCWSTR(wide_path.as_ptr()),
                        FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
                        share_mode,
                        None,
                        OPEN_EXISTING,
                        FILE_FLAGS_AND_ATTRIBUTES(flags),
                        None,
                    ) {
                        Ok(h) => h,
                        Err(e2) => {
                            tracing::error!("All attempts to open '{}' for writing failed", path);
                            tracing::error!("Error 1: 0x{:X} - {}", e.code().0, e.message());
                            tracing::error!("Error 2: 0x{:X} - {}", e2.code().0, e2.message());

                            // Provide helpful error message
                            let msg = if path.contains("PhysicalDrive") {
                                format!(
                                    "Failed to open '{}' for writing. Physical disk access \
                                     requires:\n1. Run as Administrator\n2. The disk should not \
                                     have mounted Windows partitions\n3. Try dismounting all \
                                     partitions on the disk first\nError: {}",
                                    path, e2
                                )
                            } else {
                                format!(
                                    "Failed to open '{}' for writing: {}. Try running as \
                                     Administrator.",
                                    path, e2
                                )
                            };
                            return Err(XfsWinfspError::DiskOpenError(msg));
                        }
                    }
                }
            }
        };

        let (size, sector_size) = match PhysicalDiskReader::get_disk_geometry(handle) {
            Ok(geometry) => geometry,
            Err(error) => {
                use windows::Win32::Foundation::CloseHandle;
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return Err(error);
            }
        };
        tracing::info!(
            "PhysicalDiskWriter opened: size={}, sector_size={}",
            size,
            sector_size
        );

        Ok(Self {
            handle,
            size,
            sector_size,
            io_lock: Mutex::new(()),
        })
    }
}

impl DiskReader for PhysicalDiskWriter {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        validate_raw_io_args(offset, buffer.len())?;
        if buffer.is_empty() {
            return Ok(0);
        }
        let _guard = self.io_lock.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut new_pos: i64 = 0;
            SetFilePointerEx(self.handle, offset as i64, Some(&mut new_pos), FILE_BEGIN).map_err(
                |e| XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0)),
            )?;

            let mut bytes_read: u32 = 0;
            ReadFile(self.handle, Some(buffer), Some(&mut bytes_read), None).map_err(|e| {
                XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0))
            })?;

            Ok(bytes_read as usize)
        }
    }

    fn total_size(&self) -> u64 {
        self.size
    }

    fn get_sector_size(&self) -> u32 {
        self.sector_size
    }

    fn supports_write(&self) -> bool {
        true
    }
}

impl DiskWriter for PhysicalDiskWriter {
    fn write_raw_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
        validate_raw_io_args(offset, data.len())?;
        if data.is_empty() {
            return Ok(0);
        }
        let _guard = self.io_lock.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut new_pos: i64 = 0;
            SetFilePointerEx(self.handle, offset as i64, Some(&mut new_pos), FILE_BEGIN).map_err(
                |e| {
                    tracing::error!("SetFilePointerEx failed: 0x{:X}", e.code().0);
                    XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0))
                },
            )?;

            let mut bytes_written: u32 = 0;
            WriteFile(self.handle, Some(data), Some(&mut bytes_written), None).map_err(|e| {
                tracing::error!("WriteFile failed: 0x{:X}", e.code().0);
                XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0))
            })?;

            tracing::trace!("write_at: offset={} wrote {} bytes", offset, bytes_written);
            Ok(bytes_written as usize)
        }
    }

    fn flush_raw(&self) -> Result<()> {
        let _guard = self.io_lock.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            FlushFileBuffers(self.handle).map_err(|e| {
                XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0))
            })?;
        }
        Ok(())
    }
}

// BlockDevice trait implementation for cross-crate compatibility
impl fs_abstraction::BlockDevice for PhysicalDiskWriter {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> fs_abstraction::FsResult<usize> {
        DiskReader::read_raw_at(self, offset, buf).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn write_at(&self, offset: u64, data: &[u8]) -> fs_abstraction::FsResult<usize> {
        DiskWriter::write_raw_at(self, offset, data).map_err(|_| fs_abstraction::FsError::DiskError)
    }

    fn size(&self) -> u64 {
        DiskReader::total_size(self)
    }

    fn sector_size(&self) -> u32 {
        DiskReader::get_sector_size(self)
    }

    fn flush(&self) -> fs_abstraction::FsResult<()> {
        DiskWriter::flush_raw(self).map_err(|_| fs_abstraction::FsError::DiskError)
    }
}

impl Drop for PhysicalDiskWriter {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        // Flush before closing
        let _ = self.flush_raw();
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

/// Scan for XFS partitions on all physical disks and partitions.
pub fn scan_for_xfs_disks() -> Vec<XfsDiskInfo> {
    let mut results = Vec::new();

    // Scan physical disks 0-15
    for disk_num in 0..16 {
        if let Ok(reader) = PhysicalDiskReader::open(disk_num) {
            if let Some(info) =
                check_disk_for_xfs(&reader, &format!("\\\\.\\PhysicalDrive{}", disk_num))
            {
                results.push(info);
            }
        }
    }

    // Scan partitions (drive letters A-Z)
    for letter in b'A'..=b'Z' {
        let letter = letter as char;
        if let Ok(reader) = PhysicalDiskReader::open_partition(letter) {
            if let Some(info) = check_disk_for_xfs(&reader, &format!("\\\\.\\{}:", letter)) {
                results.push(info);
            }
        }
    }

    // Also scan common volume paths
    for i in 0..32 {
        let volume_path = format!("\\\\.\\HarddiskVolume{}", i);
        if let Ok(reader) = PhysicalDiskReader::open_by_path(&volume_path) {
            if let Some(info) = check_disk_for_xfs(&reader, &volume_path) {
                // Avoid duplicates
                if !results.iter().any(|x| x.disk_path == info.disk_path) {
                    results.push(info);
                }
            }
        }
    }

    results
}

/// Information about a detected XFS disk/partition.
#[derive(Debug, Clone)]
pub struct XfsDiskInfo {
    /// Disk number or path.
    pub disk_path: String,
    /// XFS volume label.
    pub label: String,
    /// XFS UUID.
    pub uuid: String,
    /// Total size in bytes.
    pub size: u64,
    /// Block size.
    pub block_size: u32,
}

fn check_disk_for_xfs(reader: &dyn DiskReader, path: &str) -> Option<XfsDiskInfo> {
    // Read the first sector to check for XFS superblock
    let mut buffer = vec![0u8; 512];
    if reader.read_raw_at(0, &mut buffer).is_err() {
        return None;
    }

    // Check XFS magic number (0x58465342 = "XFSB")
    if buffer.len() >= 4 {
        let magic = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
        if magic == 0x58465342 {
            // Parse more superblock info
            // Block size is at offset 4 (4 bytes, big-endian)
            let block_size = if buffer.len() >= 8 {
                u32::from_be_bytes([buffer[4], buffer[5], buffer[6], buffer[7]])
            } else {
                4096
            };

            // Parse label (offset 108, 12 bytes)
            let label = if buffer.len() >= 120 {
                let label_bytes = &buffer[108..120];
                let len = label_bytes.iter().position(|&b| b == 0).unwrap_or(12);
                String::from_utf8_lossy(&label_bytes[..len]).to_string()
            } else {
                String::new()
            };

            // Parse UUID (offset 32, 16 bytes)
            let uuid = if buffer.len() >= 48 {
                let uuid_bytes = &buffer[32..48];
                format!(
                    "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:\
                     02x}{:02x}{:02x}{:02x}{:02x}",
                    uuid_bytes[0],
                    uuid_bytes[1],
                    uuid_bytes[2],
                    uuid_bytes[3],
                    uuid_bytes[4],
                    uuid_bytes[5],
                    uuid_bytes[6],
                    uuid_bytes[7],
                    uuid_bytes[8],
                    uuid_bytes[9],
                    uuid_bytes[10],
                    uuid_bytes[11],
                    uuid_bytes[12],
                    uuid_bytes[13],
                    uuid_bytes[14],
                    uuid_bytes[15]
                )
            } else {
                String::new()
            };

            return Some(XfsDiskInfo {
                disk_path: path.to_string(),
                label,
                uuid,
                size: reader.total_size(),
                block_size,
            });
        }
    }

    None
}

/// Partition information detected on a disk.
#[derive(Debug, Clone)]
pub struct PartitionInfo {
    pub offset: u64,
    pub size: u64,
    pub partition_type: u8,
}

/// Detect partitions on a disk (MBR or GPT).
pub fn detect_partitions(reader: &dyn DiskReader) -> Result<Vec<PartitionInfo>> {
    let lba_size = checked_sector_size(reader.get_sector_size())?;
    let lba_size_usize = usize::try_from(lba_size).map_err(|_| {
        XfsWinfspError::InvalidArgument("Logical sector size does not fit usize".to_string())
    })?;

    // Read the first logical sector (512 B legacy MBR or 4Kn).
    let mut boot_sector = vec![0u8; lba_size_usize];
    read_exact_at(reader, 0, &mut boot_sector)?;

    // GPT has a protective MBR with signature 0x55AA at offset 510 and an
    // 0xEE entry. Once detected, any malformed GPT metadata is an error rather
    // than a reason to silently interpret the disk as a raw filesystem.
    let mbr_sig = u16::from_le_bytes([boot_sector[510], boot_sector[511]]);
    if mbr_sig == 0xAA55 {
        if boot_sector[450] == 0xEE {
            return read_gpt_partitions(reader);
        }
        return read_mbr_partitions(reader, &boot_sector, lba_size);
    }

    Ok(Vec::new())
}

/// Read MBR partition table.
fn read_mbr_partitions(
    reader: &dyn DiskReader,
    boot_sector: &[u8],
    lba_size: u64,
) -> Result<Vec<PartitionInfo>> {
    let mut partitions = Vec::new();

    // MBR partition table starts at offset 446.
    for i in 0..4 {
        let entry_offset = 446 + (i * 16);
        let entry = &boot_sector[entry_offset..entry_offset + 16];
        let partition_type = entry[4];
        if partition_type == 0 {
            continue;
        }

        let lba_start = u64::from(u32::from_le_bytes([
            entry[8], entry[9], entry[10], entry[11],
        ]));
        let sector_count = u64::from(u32::from_le_bytes([
            entry[12], entry[13], entry[14], entry[15],
        ]));
        if lba_start == 0 || sector_count == 0 {
            return Err(XfsWinfspError::DiskError(format!(
                "Invalid MBR partition {i}: zero LBA or sector count"
            )));
        }

        let offset = lba_start
            .checked_mul(lba_size)
            .ok_or_else(|| XfsWinfspError::DiskError("MBR partition offset overflow".into()))?;
        let size = sector_count
            .checked_mul(lba_size)
            .ok_or_else(|| XfsWinfspError::DiskError("MBR partition size overflow".into()))?;
        offset
            .checked_add(size)
            .filter(|end| *end <= reader.total_size())
            .ok_or_else(|| {
                XfsWinfspError::DiskError(format!("MBR partition {i} extends beyond the disk"))
            })?;

        partitions.push(PartitionInfo {
            offset,
            size,
            partition_type,
        });
    }

    Ok(partitions)
}

const GPT_MAX_ENTRIES: u32 = 128;
/// Bound untrusted entry-size/count multiplication before allocating. Normal
/// GPTs use 16 KiB; 1 MiB still permits unusually large vendor tables.
const GPT_MAX_TABLE_BYTES: usize = 1024 * 1024;
const GPT_HEADER_SIZE: usize = 92;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GptHeader {
    revision: u32,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: [u8; 16],
    partition_entry_lba: u64,
    num_partitions: u32,
    partition_entry_size: u32,
    partition_entries_crc32: u32,
}

fn le_u32(buffer: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        buffer[offset..offset + 4]
            .try_into()
            .expect("validated GPT offset"),
    )
}

fn le_u64(buffer: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        buffer[offset..offset + 8]
            .try_into()
            .expect("validated GPT offset"),
    )
}

fn crc32_update(crc: u32, bytes: &[u8]) -> u32 {
    let mut crc = crc;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    crc
}

fn crc32(bytes: &[u8]) -> u32 {
    !crc32_update(!0, bytes)
}

fn gpt_header_crc32(header: &[u8], header_size: usize) -> u32 {
    // HeaderCRC32 is calculated with its own field set to zero.
    let mut crc = !0;
    crc = crc32_update(crc, &header[..16]);
    crc = crc32_update(crc, &[0; 4]);
    crc = crc32_update(crc, &header[20..header_size]);
    !crc
}

fn parse_gpt_header(
    sector: &[u8],
    expected_current_lba: u64,
    expected_backup_lba: u64,
) -> Result<GptHeader> {
    if sector.len() < GPT_HEADER_SIZE || &sector[..8] != b"EFI PART" {
        return Err(XfsWinfspError::DiskError(
            "Invalid GPT header signature or short header".to_string(),
        ));
    }
    let header_size = le_u32(sector, 12) as usize;
    if header_size < GPT_HEADER_SIZE || header_size > sector.len() {
        return Err(XfsWinfspError::DiskError(
            "Invalid GPT header size".to_string(),
        ));
    }
    let stored_header_crc = le_u32(sector, 16);
    if gpt_header_crc32(sector, header_size) != stored_header_crc {
        return Err(XfsWinfspError::DiskError(
            "GPT header CRC32 mismatch".to_string(),
        ));
    }

    let revision = le_u32(sector, 8);
    if revision != 0x0001_0000 {
        return Err(XfsWinfspError::DiskError(format!(
            "Unsupported GPT header revision 0x{revision:08x}"
        )));
    }
    if le_u64(sector, 24) != expected_current_lba || le_u64(sector, 32) != expected_backup_lba {
        return Err(XfsWinfspError::DiskError(
            "GPT header current/backup LBA mismatch".to_string(),
        ));
    }

    let num_partitions = le_u32(sector, 80);
    let partition_entry_size = le_u32(sector, 84);
    if num_partitions == 0 || num_partitions > GPT_MAX_ENTRIES {
        return Err(XfsWinfspError::DiskError(
            "GPT partition entry count is zero or unreasonably large".to_string(),
        ));
    }
    if partition_entry_size < 128 || partition_entry_size % 8 != 0 {
        return Err(XfsWinfspError::DiskError(
            "Invalid GPT partition entry size".to_string(),
        ));
    }
    let entries_bytes = (num_partitions as usize)
        .checked_mul(partition_entry_size as usize)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT entry table size overflow".into()))?;
    if entries_bytes > GPT_MAX_TABLE_BYTES {
        return Err(XfsWinfspError::DiskError(
            "GPT partition entry table exceeds the allocation limit".to_string(),
        ));
    }

    let first_usable_lba = le_u64(sector, 40);
    let last_usable_lba = le_u64(sector, 48);
    let partition_entry_lba = le_u64(sector, 72);
    if first_usable_lba < 2 || last_usable_lba < first_usable_lba || partition_entry_lba < 2 {
        return Err(XfsWinfspError::DiskError(
            "Invalid GPT usable-LBA or entry-LBA range".to_string(),
        ));
    }
    let mut disk_guid = [0u8; 16];
    disk_guid.copy_from_slice(&sector[56..72]);
    if disk_guid.iter().all(|byte| *byte == 0) {
        return Err(XfsWinfspError::DiskError(
            "GPT disk GUID must not be zero".to_string(),
        ));
    }

    Ok(GptHeader {
        revision,
        backup_lba: le_u64(sector, 32),
        first_usable_lba,
        last_usable_lba,
        disk_guid,
        partition_entry_lba,
        num_partitions,
        partition_entry_size,
        partition_entries_crc32: le_u32(sector, 88),
    })
}

/// Read and validate both GPT headers and both copies of the entry array.
fn read_gpt_partitions(reader: &dyn DiskReader) -> Result<Vec<PartitionInfo>> {
    let lba_size = checked_sector_size(reader.get_sector_size())?;
    let lba_size_usize = usize::try_from(lba_size).map_err(|_| {
        XfsWinfspError::InvalidArgument("Logical sector size does not fit usize".to_string())
    })?;
    let disk_size = reader.total_size();
    let minimum_size = lba_size
        .checked_mul(4)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT disk size overflow".into()))?;
    if disk_size < minimum_size || !disk_size.is_multiple_of(lba_size) {
        return Err(XfsWinfspError::DiskError(
            "Disk size is too small or not a whole number of logical sectors".to_string(),
        ));
    }
    let last_disk_lba = disk_size / lba_size - 1;

    let mut primary_sector = vec![0u8; lba_size_usize];
    read_exact_at(reader, lba_size, &mut primary_sector)?;
    let primary = parse_gpt_header(&primary_sector, 1, last_disk_lba)?;
    if primary.last_usable_lba >= primary.backup_lba {
        return Err(XfsWinfspError::DiskError(
            "GPT usable range overlaps the backup header".to_string(),
        ));
    }

    let entries_bytes = (primary.num_partitions as usize)
        .checked_mul(primary.partition_entry_size as usize)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT entry table size overflow".into()))?;
    let entries_offset = primary
        .partition_entry_lba
        .checked_mul(lba_size)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT entry LBA overflow".into()))?;
    let entries_end = entries_offset
        .checked_add(entries_bytes as u64)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT entry table end overflow".into()))?;
    let first_usable_offset = primary
        .first_usable_lba
        .checked_mul(lba_size)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT usable LBA overflow".into()))?;
    if entries_offset < lba_size.saturating_mul(2)
        || entries_end > first_usable_offset
        || entries_end > disk_size
    {
        return Err(XfsWinfspError::DiskError(
            "GPT entry table overlaps headers, usable space, or the disk boundary".to_string(),
        ));
    }

    let mut entries = vec![0u8; entries_bytes];
    read_exact_at(reader, entries_offset, &mut entries)?;
    if crc32(&entries) != primary.partition_entries_crc32 {
        return Err(XfsWinfspError::DiskError(
            "GPT partition entry CRC32 mismatch".to_string(),
        ));
    }

    // Validate the backup header at the final LBA and its mirrored entry array.
    let backup_offset = last_disk_lba
        .checked_mul(lba_size)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT backup LBA overflow".into()))?;
    let mut backup_sector = vec![0u8; lba_size_usize];
    read_exact_at(reader, backup_offset, &mut backup_sector)?;
    let backup = parse_gpt_header(&backup_sector, last_disk_lba, 1)?;
    if backup.revision != primary.revision
        || backup.disk_guid != primary.disk_guid
        || backup.first_usable_lba != primary.first_usable_lba
        || backup.last_usable_lba != primary.last_usable_lba
        || backup.num_partitions != primary.num_partitions
        || backup.partition_entry_size != primary.partition_entry_size
        || backup.partition_entries_crc32 != primary.partition_entries_crc32
    {
        return Err(XfsWinfspError::DiskError(
            "Primary and backup GPT headers disagree".to_string(),
        ));
    }
    let backup_entries_offset = backup
        .partition_entry_lba
        .checked_mul(lba_size)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT backup entry LBA overflow".into()))?;
    let backup_entries_end = backup_entries_offset
        .checked_add(entries_bytes as u64)
        .ok_or_else(|| XfsWinfspError::DiskError("GPT backup entry end overflow".into()))?;
    let last_usable_end = primary
        .last_usable_lba
        .checked_add(1)
        .and_then(|lba| lba.checked_mul(lba_size))
        .ok_or_else(|| XfsWinfspError::DiskError("GPT usable range overflow".into()))?;
    if backup_entries_offset < last_usable_end || backup_entries_end > backup_offset {
        return Err(XfsWinfspError::DiskError(
            "GPT backup entry table overlaps usable space or its header".to_string(),
        ));
    }
    let mut backup_entries = vec![0u8; entries_bytes];
    read_exact_at(reader, backup_entries_offset, &mut backup_entries)?;
    if crc32(&backup_entries) != backup.partition_entries_crc32 || backup_entries != entries {
        return Err(XfsWinfspError::DiskError(
            "Backup GPT partition entries failed CRC or mirror validation".to_string(),
        ));
    }

    let mut partitions = Vec::with_capacity(primary.num_partitions as usize);
    let entry_size = primary.partition_entry_size as usize;
    for index in 0..primary.num_partitions as usize {
        let entry_offset = index
            .checked_mul(entry_size)
            .ok_or_else(|| XfsWinfspError::DiskError("GPT entry offset overflow".into()))?;
        let entry = &entries[entry_offset..entry_offset + 128];
        if entry[..16].iter().all(|byte| *byte == 0) {
            continue;
        }

        let first_lba = le_u64(entry, 32);
        let last_lba = le_u64(entry, 40);
        if first_lba < primary.first_usable_lba
            || last_lba > primary.last_usable_lba
            || last_lba < first_lba
        {
            return Err(XfsWinfspError::DiskError(format!(
                "GPT partition {index} is outside the usable disk range"
            )));
        }
        let offset = first_lba
            .checked_mul(lba_size)
            .ok_or_else(|| XfsWinfspError::DiskError("GPT partition offset overflow".into()))?;
        let sector_count = last_lba
            .checked_sub(first_lba)
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| XfsWinfspError::DiskError("GPT partition size overflow".into()))?;
        let size = sector_count
            .checked_mul(lba_size)
            .ok_or_else(|| XfsWinfspError::DiskError("GPT partition size overflow".into()))?;
        offset
            .checked_add(size)
            .filter(|end| *end <= disk_size)
            .ok_or_else(|| {
                XfsWinfspError::DiskError(format!("GPT partition {index} extends beyond the disk"))
            })?;

        partitions.push(PartitionInfo {
            offset,
            size,
            partition_type: 0,
        });
    }

    Ok(partitions)
}

/// Try to open an XFS partition from a physical disk.
/// If the disk has partitions, find and wrap the first XFS partition.
pub fn open_disk_with_partitions(disk_number: u32) -> Result<Arc<dyn fs_abstraction::BlockDevice>> {
    let disk = Arc::new(PhysicalDiskReader::open(disk_number)?);

    // Try to detect partitions
    match detect_partitions(disk.as_ref()) {
        Ok(partitions) if !partitions.is_empty() => {
            tracing::debug!(
                "Found {} partition(s) on disk {}",
                partitions.len(),
                disk_number
            );

            // Try each partition to find XFS
            for (i, part) in partitions.iter().enumerate() {
                tracing::debug!(
                    "Partition {}: offset={}, size={}, type=0x{:02x}",
                    i + 1,
                    part.offset,
                    part.size,
                    part.partition_type
                );

                let part_reader =
                    Arc::new(PartitionReader::new(disk.clone(), part.offset, part.size));

                // Check if this partition has XFS magic
                if let Ok(buffer) = part_reader.read_unaligned(0, 4) {
                    if buffer.len() >= 4 {
                        let magic =
                            u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                        if magic == 0x58465342 {
                            tracing::info!("Found XFS partition at partition {}", i + 1);
                            return Ok(part_reader);
                        }
                    }
                }
            }

            // No XFS partition found, return raw disk
            tracing::warn!(
                "No XFS partition found on disk {}, trying raw disk",
                disk_number
            );
            Ok(disk)
        }
        // The guarded arm above handles every non-empty list, so this is the
        // no-partition-table case.
        Ok(_) => {
            tracing::debug!(
                "No partition table detected on disk {}, using raw disk",
                disk_number
            );
            Ok(disk)
        }
        Err(error) => Err(error),
    }
}

/// Try to open an XFS partition from a physical disk with read-write access.
/// If the disk has partitions, find and wrap the first XFS partition.
#[allow(dead_code)]
pub(crate) fn open_disk_with_partitions_rw(
    disk_number: u32,
) -> Result<(Arc<dyn DiskReader>, Arc<dyn DiskWriter>)> {
    let disk = Arc::new(PhysicalDiskWriter::open(disk_number)?);

    // Try to detect partitions (use disk as reader)
    match detect_partitions(disk.as_ref()) {
        Ok(partitions) if !partitions.is_empty() => {
            tracing::debug!(
                "Found {} partition(s) on disk {} (RW mode)",
                partitions.len(),
                disk_number
            );

            // Try each partition to find XFS
            for (i, part) in partitions.iter().enumerate() {
                tracing::debug!(
                    "Partition {}: offset={}, size={}, type=0x{:02x}",
                    i + 1,
                    part.offset,
                    part.size,
                    part.partition_type
                );

                // Check if this partition has XFS magic
                if let Ok(buffer) = disk.read_unaligned(part.offset, 4) {
                    if buffer.len() >= 4 {
                        let magic =
                            u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
                        if magic == 0x58465342 {
                            tracing::info!("Found XFS partition at partition {} (RW mode)", i + 1);
                            let part_writer = Arc::new(PartitionWriter::new(
                                disk.clone() as Arc<dyn DiskWriter>,
                                part.offset,
                                part.size,
                            ));
                            let reader: Arc<dyn DiskReader> = part_writer.clone();
                            let writer: Arc<dyn DiskWriter> = part_writer;
                            return Ok((reader, writer));
                        }
                    }
                }
            }

            // No XFS partition found, return raw disk
            tracing::warn!(
                "No XFS partition found on disk {} (RW mode), trying raw disk",
                disk_number
            );
            let reader: Arc<dyn DiskReader> = disk.clone();
            let writer: Arc<dyn DiskWriter> = disk;
            Ok((reader, writer))
        }
        // The guarded arm above handles every non-empty list, so this is the
        // no-partition-table case.
        Ok(_) => {
            tracing::debug!(
                "No partition table detected on disk {} (RW mode), using raw disk",
                disk_number
            );
            let reader: Arc<dyn DiskReader> = disk.clone();
            let writer: Arc<dyn DiskWriter> = disk;
            Ok((reader, writer))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MemoryDisk {
        data: Mutex<Vec<u8>>,
        sector_size: u32,
        max_read: usize,
    }

    impl MemoryDisk {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data: Mutex::new(data),
                sector_size: 512,
                max_read: usize::MAX,
            }
        }
    }

    impl DiskReader for MemoryDisk {
        fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
            let offset = usize::try_from(offset).map_err(|_| {
                XfsWinfspError::InvalidArgument("Test offset does not fit usize".to_string())
            })?;
            let data = self.data.lock().unwrap();
            if offset >= data.len() || buffer.is_empty() {
                return Ok(0);
            }
            let count = (data.len() - offset).min(buffer.len()).min(self.max_read);
            buffer[..count].copy_from_slice(&data[offset..offset + count]);
            Ok(count)
        }

        fn total_size(&self) -> u64 {
            self.data.lock().unwrap().len() as u64
        }

        fn get_sector_size(&self) -> u32 {
            self.sector_size
        }
    }

    impl fs_abstraction::BlockDevice for MemoryDisk {
        fn read_at(&self, offset: u64, buffer: &mut [u8]) -> fs_abstraction::FsResult<usize> {
            DiskReader::read_raw_at(self, offset, buffer)
                .map_err(|_| fs_abstraction::FsError::DiskError)
        }

        fn size(&self) -> u64 {
            DiskReader::total_size(self)
        }

        fn sector_size(&self) -> u32 {
            DiskReader::get_sector_size(self)
        }
    }

    struct MemoryWriter {
        disk: MemoryDisk,
        max_write: usize,
    }

    impl DiskReader for MemoryWriter {
        fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
            self.disk.read_raw_at(offset, buffer)
        }

        fn total_size(&self) -> u64 {
            self.disk.total_size()
        }

        fn get_sector_size(&self) -> u32 {
            self.disk.get_sector_size()
        }

        fn supports_write(&self) -> bool {
            true
        }
    }

    impl DiskWriter for MemoryWriter {
        fn write_raw_at(&self, offset: u64, data: &[u8]) -> Result<usize> {
            let offset = usize::try_from(offset).map_err(|_| {
                XfsWinfspError::InvalidArgument("Test offset does not fit usize".to_string())
            })?;
            let mut storage = self.disk.data.lock().unwrap();
            if offset >= storage.len() || data.is_empty() {
                return Ok(0);
            }
            let count = (storage.len() - offset).min(data.len()).min(self.max_write);
            storage[offset..offset + count].copy_from_slice(&data[..count]);
            Ok(count)
        }
    }

    impl fs_abstraction::BlockDevice for MemoryWriter {
        fn read_at(&self, offset: u64, buffer: &mut [u8]) -> fs_abstraction::FsResult<usize> {
            DiskReader::read_raw_at(self, offset, buffer)
                .map_err(|_| fs_abstraction::FsError::DiskError)
        }

        fn write_at(&self, offset: u64, data: &[u8]) -> fs_abstraction::FsResult<usize> {
            DiskWriter::write_raw_at(self, offset, data)
                .map_err(|_| fs_abstraction::FsError::DiskError)
        }

        fn size(&self) -> u64 {
            DiskReader::total_size(self)
        }

        fn sector_size(&self) -> u32 {
            DiskReader::get_sector_size(self)
        }
    }

    fn put_u32(buffer: &mut [u8], offset: usize, value: u32) {
        buffer[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buffer: &mut [u8], offset: usize, value: u64) {
        buffer[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn refresh_header_crc(image: &mut [u8], lba: u64) {
        let offset = lba as usize * 512;
        let header_size = le_u32(image, offset + 12) as usize;
        put_u32(image, offset + 16, 0);
        let crc = crc32(&image[offset..offset + header_size]);
        put_u32(image, offset + 16, crc);
    }

    #[allow(clippy::too_many_arguments)]
    fn write_gpt_header(
        image: &mut [u8],
        current_lba: u64,
        backup_lba: u64,
        entries_lba: u64,
        first_usable_lba: u64,
        last_usable_lba: u64,
        num_entries: u32,
        entry_size: u32,
        entries_crc: u32,
    ) {
        let offset = current_lba as usize * 512;
        let header = &mut image[offset..offset + 512];
        header.fill(0);
        header[..8].copy_from_slice(b"EFI PART");
        put_u32(header, 8, 0x0001_0000);
        put_u32(header, 12, GPT_HEADER_SIZE as u32);
        put_u64(header, 24, current_lba);
        put_u64(header, 32, backup_lba);
        put_u64(header, 40, first_usable_lba);
        put_u64(header, 48, last_usable_lba);
        header[56] = 1; // non-zero disk GUID
        put_u64(header, 72, entries_lba);
        put_u32(header, 80, num_entries);
        put_u32(header, 84, entry_size);
        put_u32(header, 88, entries_crc);
        let crc = crc32(&header[..GPT_HEADER_SIZE]);
        put_u32(header, 16, crc);
    }

    fn valid_gpt_image() -> Vec<u8> {
        const SECTORS: usize = 128;
        let mut image = vec![0u8; SECTORS * 512];
        image[510] = 0x55;
        image[511] = 0xAA;
        image[450] = 0xEE;

        let mut entries = vec![0u8; 4 * 128];
        entries[0] = 1; // non-zero partition type GUID
        put_u64(&mut entries, 32, 16);
        put_u64(&mut entries, 40, 31);
        let entries_crc = crc32(&entries);
        image[2 * 512..2 * 512 + entries.len()].copy_from_slice(&entries);
        image[126 * 512..126 * 512 + entries.len()].copy_from_slice(&entries);

        write_gpt_header(&mut image, 1, 127, 2, 6, 125, 4, 128, entries_crc);
        write_gpt_header(&mut image, 127, 1, 126, 6, 125, 4, 128, entries_crc);
        image
    }

    #[test]
    fn test_xfs_magic() {
        let magic = u32::from_be_bytes([0x58u8, 0x46, 0x53, 0x42]);
        assert_eq!(magic, 0x58465342);
    }

    #[test]
    fn unaligned_write_rejects_short_read_without_modifying_data() {
        let original = vec![0xA5; 32];
        let writer = MemoryWriter {
            disk: MemoryDisk::new(original.clone()),
            max_write: usize::MAX,
        };
        let error = DiskWriter::write_unaligned(&writer, 3, b"abc").expect_err("short read");
        assert!(error.to_string().contains("Short read"));
        assert_eq!(*writer.disk.data.lock().unwrap(), original);
    }

    #[test]
    fn unaligned_write_retries_partial_writes_and_preserves_sector_edges() {
        let mut original = vec![0xA5; 1024];
        original[3] = 0;
        original[6] = 0;
        let writer = MemoryWriter {
            disk: MemoryDisk::new(original.clone()),
            max_write: 7,
        };

        let written = DiskWriter::write_unaligned(&writer, 3, b"abc").unwrap();
        assert_eq!(written, 3);
        let data = writer.disk.data.lock().unwrap();
        assert_eq!(&data[3..6], b"abc");
        assert_eq!(&data[..3], &original[..3]);
        assert_eq!(&data[6..], &original[6..]);
    }

    #[test]
    fn unaligned_write_reports_zero_progress() {
        let writer = MemoryWriter {
            disk: MemoryDisk::new(vec![0; 512]),
            max_write: 0,
        };
        let error = DiskWriter::write_unaligned(&writer, 0, b"x").expect_err("zero write");
        assert!(error.to_string().contains("Short write"));
    }

    #[test]
    fn positional_read_helper_retries_short_reads() {
        let disk = MemoryDisk {
            data: Mutex::new(vec![1, 2, 3, 4, 5]),
            sector_size: 512,
            max_read: 2,
        };
        let mut buffer = [0u8; 5];
        read_exact_at(&disk, 0, &mut buffer).unwrap();
        assert_eq!(buffer, [1, 2, 3, 4, 5]);
    }

    #[test]
    fn unaligned_read_returns_available_prefix_at_eof() {
        let disk = MemoryDisk::new(vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        assert_eq!(disk.read_unaligned(8, 4).unwrap(), vec![9, 10]);
    }

    #[test]
    fn valid_gpt_is_accepted() {
        let partitions = detect_partitions(&MemoryDisk::new(valid_gpt_image())).unwrap();
        assert_eq!(partitions.len(), 1);
        assert_eq!(partitions[0].offset, 16 * 512);
        assert_eq!(partitions[0].size, 16 * 512);
    }

    #[test]
    fn gpt_rejects_header_crc_corruption() {
        let mut image = valid_gpt_image();
        image[512 + 20] ^= 1;
        let error = detect_partitions(&MemoryDisk::new(image)).expect_err("bad header CRC");
        assert!(error.to_string().contains("header CRC32"));
    }

    #[test]
    fn gpt_rejects_entry_crc_corruption() {
        let mut image = valid_gpt_image();
        image[2 * 512 + 32] ^= 1;
        let error = detect_partitions(&MemoryDisk::new(image)).expect_err("bad entries CRC");
        assert!(error.to_string().contains("entry CRC32"));
    }

    #[test]
    fn gpt_rejects_missing_or_corrupt_backup_header() {
        let mut image = valid_gpt_image();
        image[127 * 512] = b'X';
        let error = detect_partitions(&MemoryDisk::new(image)).expect_err("bad backup header");
        assert!(error.to_string().contains("GPT header"));
    }

    #[test]
    fn gpt_rejects_excessive_entry_count_before_allocation() {
        let mut image = valid_gpt_image();
        put_u32(&mut image, 512 + 80, GPT_MAX_ENTRIES + 1);
        refresh_header_crc(&mut image, 1);
        let error = detect_partitions(&MemoryDisk::new(image)).expect_err("excessive count");
        assert!(error.to_string().contains("entry count"));
    }

    #[test]
    fn gpt_rejects_excessive_entry_table_allocation() {
        let mut image = valid_gpt_image();
        put_u32(&mut image, 512 + 80, GPT_MAX_ENTRIES);
        put_u32(&mut image, 512 + 84, u32::MAX - 7);
        refresh_header_crc(&mut image, 1);
        let error = detect_partitions(&MemoryDisk::new(image)).expect_err("excessive allocation");
        assert!(error.to_string().contains("allocation limit"));
    }

    #[test]
    fn gpt_rejects_partition_outside_usable_disk_range() {
        let mut image = valid_gpt_image();
        for entries_lba in [2u64, 126u64] {
            let offset = entries_lba as usize * 512;
            put_u64(&mut image, offset + 40, 200);
        }
        let entries_crc = crc32(&image[2 * 512..3 * 512]);
        for header_lba in [1u64, 127u64] {
            let offset = header_lba as usize * 512;
            put_u32(&mut image, offset + 88, entries_crc);
            refresh_header_crc(&mut image, header_lba);
        }
        let error = detect_partitions(&MemoryDisk::new(image)).expect_err("out-of-range partition");
        assert!(error.to_string().contains("outside the usable disk range"));
    }

    #[test]
    fn gpt_rejects_invalid_logical_sector_size() {
        let disk = MemoryDisk {
            data: Mutex::new(valid_gpt_image()),
            sector_size: 513,
            max_read: usize::MAX,
        };
        assert!(detect_partitions(&disk).is_err());
    }

    #[test]
    fn geometry_validation_never_invents_a_default() {
        assert!(checked_sector_size(0).is_err());
        assert!(checked_sector_size(513).is_err());
        assert_eq!(checked_sector_size(512).unwrap(), 512);
        assert_eq!(checked_sector_size(4096).unwrap(), 4096);
    }

    #[test]
    fn crc32_matches_standard_check_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn physical_disk_handles_are_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PhysicalDiskReader>();
        assert_send_sync::<PhysicalDiskWriter>();
    }
}
