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
    sync::Arc,
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
        let sector = self.get_sector_size() as u64;

        // Calculate aligned offset and size
        let aligned_offset = offset & !(sector - 1);
        let offset_in_sector = (offset - aligned_offset) as usize;
        let aligned_size =
            ((offset_in_sector + size + sector as usize - 1) / sector as usize) * sector as usize;

        // Allocate aligned buffer
        let mut aligned_buffer = vec![0u8; aligned_size];

        // Read aligned data
        let bytes_read = self.read_raw_at(aligned_offset, &mut aligned_buffer)?;

        if bytes_read < offset_in_sector + size {
            let available = bytes_read.saturating_sub(offset_in_sector);
            if available == 0 {
                return Ok(Vec::new());
            }
            let to_copy = size.min(available);
            return Ok(aligned_buffer[offset_in_sector..offset_in_sector + to_copy].to_vec());
        }

        // Extract requested portion
        Ok(aligned_buffer[offset_in_sector..offset_in_sector + size].to_vec())
    }

    /// Read a single block from disk.
    fn read_block(&self, block_number: u64, block_size: u32) -> Result<Vec<u8>> {
        let offset = block_number
            .checked_mul(block_size as u64)
            .ok_or_else(|| XfsWinfspError::XfsError("Block offset overflow".to_string()))?;

        let mut buffer = vec![0u8; block_size as usize];
        let bytes_read = self.read_raw_at(offset, &mut buffer)?;

        if bytes_read != block_size as usize {
            return Err(XfsWinfspError::DiskError(format!(
                "Short read: expected {} bytes, got {}",
                block_size, bytes_read
            )));
        }

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
        let bytes_read = self.read_raw_at(offset, &mut buffer)?;

        if bytes_read != total_size {
            return Err(XfsWinfspError::DiskError(format!(
                "Short read: expected {} bytes, got {}",
                total_size, bytes_read
            )));
        }

        Ok(buffer)
    }
}

/// Trait for writing raw disk/image data.
///
/// This extends DiskReader to provide write capabilities.
/// Not all disk readers support writing (e.g., read-only images).
pub trait DiskWriter: DiskReader {
    /// Write bytes at a specific offset.
    fn write_raw_at(&self, offset: u64, data: &[u8]) -> Result<usize>;

    /// Write data with automatic alignment handling.
    ///
    /// This method handles unaligned writes by:
    /// 1. Reading the affected sectors
    /// 2. Modifying the relevant bytes
    /// 3. Writing the sectors back
    fn write_unaligned(&self, offset: u64, data: &[u8]) -> Result<usize> {
        let sector = self.get_sector_size() as u64;

        // Calculate aligned offset and size
        let aligned_offset = offset & !(sector - 1);
        let offset_in_sector = (offset - aligned_offset) as usize;
        let aligned_size = ((offset_in_sector + data.len() + sector as usize - 1)
            / sector as usize)
            * sector as usize;

        // Read existing aligned data
        let mut aligned_buffer = vec![0u8; aligned_size];
        self.read_raw_at(aligned_offset, &mut aligned_buffer)?;

        // Modify the relevant portion
        aligned_buffer[offset_in_sector..offset_in_sector + data.len()].copy_from_slice(data);

        // Write back
        let bytes_written = self.write_raw_at(aligned_offset, &aligned_buffer)?;

        if bytes_written < aligned_size {
            return Err(XfsWinfspError::DiskError(format!(
                "Short write: expected {} bytes, wrote {}",
                aligned_size, bytes_written
            )));
        }

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

        let bytes_written = self.write_raw_at(offset, data)?;

        if bytes_written != block_size as usize {
            return Err(XfsWinfspError::DiskError(format!(
                "Short write: expected {} bytes, wrote {}",
                block_size, bytes_written
            )));
        }

        Ok(())
    }

    /// Flush any cached writes to disk.
    fn flush_raw(&self) -> Result<()> {
        Ok(()) // Default: no-op
    }
}

/// Reader for image files (.img, .raw, etc.).
pub struct ImageFileReader {
    file: std::sync::Mutex<File>,
    size: u64,
}

impl ImageFileReader {
    /// Open an image file for reading.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
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
pub struct ImageFileWriter {
    file: std::sync::Mutex<File>,
    size: u64,
}

impl ImageFileWriter {
    /// Open an image file for reading and writing.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
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
    pub fn create<P: AsRef<Path>>(path: P, size: u64) -> Result<Self> {
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
        // Add partition offset to requested offset
        let actual_offset = self.offset + offset;

        // Ensure we don't read beyond partition bounds
        if offset >= self.size {
            return Ok(0);
        }

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
pub struct PartitionWriter {
    inner: Arc<dyn DiskWriter>,
    offset: u64,
    size: u64,
}

impl PartitionWriter {
    /// Create a new partition writer.
    pub fn new(inner: Arc<dyn DiskWriter>, offset: u64, size: u64) -> Self {
        Self {
            inner,
            offset,
            size,
        }
    }
}

impl DiskReader for PartitionWriter {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let actual_offset = self.offset + offset;
        if offset >= self.size {
            return Ok(0);
        }
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
        let actual_offset = self.offset + offset;
        if offset >= self.size {
            return Err(XfsWinfspError::InvalidArgument(
                "Write beyond partition bounds".to_string(),
            ));
        }
        let max_write = (self.size - offset).min(data.len() as u64) as usize;
        self.inner.write_raw_at(actual_offset, &data[..max_write])
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
}

// SAFETY: HANDLE is Send+Sync safe when used correctly
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
        let path = format!("\\\\.\\{}:", drive_letter);
        Self::open_by_path(&path)
    }

    /// Open a disk or partition by path.
    pub fn open_by_path(path: &str) -> Result<Self> {
        tracing::debug!("open_by_path: {}", path);
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        tracing::debug!("Wide path created with {} characters", wide_path.len());

        // Different types of paths may need different flags
        use windows::Win32::Storage::FileSystem::{
            FILE_ATTRIBUTE_NORMAL,
            FILE_FLAG_NO_BUFFERING,
            FILE_FLAG_RANDOM_ACCESS,
        };

        // For raw disk access, we typically want to avoid buffering
        // But for volume paths, we might need different flags
        let flags = if path.contains("HarddiskVolume") {
            tracing::debug!("Detected HarddiskVolume path, using FILE_ATTRIBUTE_NORMAL only");
            // For volume devices, use simpler flags
            FILE_ATTRIBUTE_NORMAL.0
        } else {
            tracing::debug!("Using raw disk access flags");
            // For physical drives, use flags for raw access
            let mut f = FILE_ATTRIBUTE_NORMAL.0;
            f |= FILE_FLAG_NO_BUFFERING.0;
            f |= FILE_FLAG_RANDOM_ACCESS.0;
            f
        };

        tracing::debug!("Attempting to call CreateFileW with flags: 0x{:X}", flags);
        tracing::debug!("Path: {}", path);
        tracing::debug!("Generic read access: 0x{:X}", FILE_GENERIC_READ.0);
        tracing::debug!(
            "Share mode: READ({}) | WRITE({})",
            FILE_SHARE_READ.0 != 0,
            FILE_SHARE_WRITE.0 != 0
        );

        // For volume access, we might need to use different share modes or access
        // rights Let's try a more permissive approach for volumes
        let (access, share_mode) = (FILE_GENERIC_READ.0, FILE_SHARE_READ | FILE_SHARE_WRITE);

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

                        // Inform the user that mounted volumes typically can't be accessed directly
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

        // Get disk geometry (never fails - uses defaults if needed)
        let (size, sector_size) = Self::get_disk_geometry(handle);
        tracing::debug!("Disk size: {}, sector size: {}", size, sector_size);

        Ok(Self {
            handle,
            size,
            sector_size,
        })
    }

    /// Attempt to map a volume path to a physical disk path.
    /// This is a fallback when direct volume access is denied.
    fn map_volume_to_physical_disk(volume_path: &str) -> Option<String> {
        use windows::Win32::Storage::FileSystem::GetVolumePathNameW;

        // This is a simplified approach - in practice, you'd need to use APIs like:
        // - QueryDosDevice to map drive letters
        // - DeviceIoControl with IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS
        // For now, we'll just try to extract the disk number if it exists in the path

        // If the volume path is like \\?\Volume{GUID}, we could potentially map it
        // But for HarddiskVolume paths, we can try to guess the physical disk

        if let Some(vol_num_str) = volume_path.strip_prefix(r"\\.\HarddiskVolume") {
            if let Ok(vol_num) = vol_num_str.parse::<u32>() {
                // This is a heuristic - in reality, you'd need to query the system
                // to find which physical disk contains this volume
                tracing::debug!("Trying to map HarddiskVolume{} to a physical disk", vol_num);

                // For now, we'll try a few common physical disk numbers
                // In a real implementation, you'd need to use APIs like SetupAPI
                // or WMI to properly map volumes to physical disks
                for disk_num in 0..8 {
                    let physical_path = format!("\\\\.\\PhysicalDrive{}", disk_num);
                    tracing::debug!("Trying physical disk path: {}", physical_path);

                    // We can't directly test here without creating another handle,
                    // so we'll just return the first possibility
                    return Some(physical_path);
                }
            }
        }

        None
    }

    fn get_disk_geometry(handle: HANDLE) -> (u64, u32) {
        use windows::Win32::System::{
            Ioctl::{
                DISK_GEOMETRY_EX,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                IOCTL_DISK_GET_LENGTH_INFO,
            },
            IO::DeviceIoControl,
        };

        let mut geometry: DISK_GEOMETRY_EX = unsafe { std::mem::zeroed() };
        let mut bytes_returned: u32 = 0;

        // Try IOCTL_DISK_GET_DRIVE_GEOMETRY_EX first
        let result = unsafe {
            DeviceIoControl(
                handle,
                IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
                None,
                0,
                Some(&mut geometry as *mut _ as *mut _),
                std::mem::size_of::<DISK_GEOMETRY_EX>() as u32,
                Some(&mut bytes_returned),
                None,
            )
        };

        if result.is_ok() && bytes_returned > 0 {
            let size = geometry.DiskSize as u64;
            let sector_size = if geometry.Geometry.BytesPerSector > 0 {
                geometry.Geometry.BytesPerSector
            } else {
                512
            };
            tracing::debug!("Got geometry via IOCTL_DISK_GET_DRIVE_GEOMETRY_EX");
            return (size, sector_size);
        }

        // Fallback: Try IOCTL_DISK_GET_LENGTH_INFO for volumes
        let mut length_info: i64 = 0;
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

        if length_result.is_ok() && length_info > 0 {
            tracing::debug!("Got length via IOCTL_DISK_GET_LENGTH_INFO");
            return (length_info as u64, 512);
        }

        // Last resort: Use a default size - we'll read until we hit an error
        // This is safe for read-only filesystem drivers
        tracing::warn!("Could not determine disk size, using default");
        (1024 * 1024 * 1024 * 1024, 512) // Default to 1TB, 512-byte sectors
    }
}

impl DiskReader for PhysicalDiskReader {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        tracing::debug!(
            "read_raw_at called: offset={}, buffer_size={}",
            offset,
            buffer.len()
        );
        unsafe {
            // For volume handles, we need to use SetFilePointerEx and ReadFile
            // Seek to offset
            let mut new_pos: i64 = 0;
            SetFilePointerEx(self.handle, offset as i64, Some(&mut new_pos), FILE_BEGIN).map_err(
                |e| {
                    tracing::error!("SetFilePointerEx failed: error code 0x{:X}", e.code().0);
                    XfsWinfspError::IoError(std::io::Error::last_os_error())
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

                    // For volume devices, sometimes we need to use DeviceIoControl with
                    // FSCTL_ALLOW_EXTENDED_DASD_IO to bypass certain
                    // restrictions
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
                            XfsWinfspError::IoError(std::io::Error::last_os_error())
                        })?;

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

                                Err(XfsWinfspError::IoError(std::io::Error::last_os_error()))
                            }
                        }
                    } else {
                        let dasd_error = allow_extended_result.err().unwrap();
                        tracing::error!(
                            "Failed to enable extended DASD I/O: error code 0x{:X}",
                            dasd_error.code().0
                        );

                        // Check if the failure to enable extended DASD I/O is due to the volume
                        // being mounted
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

                        Err(XfsWinfspError::IoError(std::io::Error::last_os_error()))
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
pub struct PhysicalDiskWriter {
    handle: HANDLE,
    size: u64,
    sector_size: u32,
}

// SAFETY: HANDLE is Send+Sync safe when used correctly
unsafe impl Send for PhysicalDiskWriter {}
unsafe impl Sync for PhysicalDiskWriter {}

impl PhysicalDiskWriter {
    /// Open a physical disk by number for read-write access.
    pub fn open(disk_number: u32) -> Result<Self> {
        let path = format!("\\\\.\\PhysicalDrive{}", disk_number);
        Self::open_by_path(&path)
    }

    /// Open a partition by drive letter for read-write access.
    pub fn open_partition(drive_letter: char) -> Result<Self> {
        let path = format!("\\\\.\\{}:", drive_letter);
        Self::open_by_path(&path)
    }

    /// Open a disk or partition by path for read-write access.
    pub fn open_by_path(path: &str) -> Result<Self> {
        tracing::debug!("PhysicalDiskWriter::open_by_path: {}", path);
        let wide_path: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();

        use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL;

        // For physical disks, we need simpler flags
        // FILE_FLAG_NO_BUFFERING requires sector-aligned I/O which can be problematic
        let flags = FILE_ATTRIBUTE_NORMAL.0;

        // Use GENERIC_READ | GENERIC_WRITE (0x80000000 | 0x40000000 = 0xC0000000)
        // This is different from FILE_GENERIC_READ/WRITE which include additional
        // rights
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

        let (size, sector_size) = PhysicalDiskReader::get_disk_geometry(handle);
        tracing::info!(
            "PhysicalDiskWriter opened: size={}, sector_size={}",
            size,
            sector_size
        );

        Ok(Self {
            handle,
            size,
            sector_size,
        })
    }
}

impl DiskReader for PhysicalDiskWriter {
    fn read_raw_at(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        unsafe {
            let mut new_pos: i64 = 0;
            SetFilePointerEx(self.handle, offset as i64, Some(&mut new_pos), FILE_BEGIN).map_err(
                |e| XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0 as i32)),
            )?;

            let mut bytes_read: u32 = 0;
            ReadFile(self.handle, Some(buffer), Some(&mut bytes_read), None).map_err(|e| {
                XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0 as i32))
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
        unsafe {
            let mut new_pos: i64 = 0;
            SetFilePointerEx(self.handle, offset as i64, Some(&mut new_pos), FILE_BEGIN).map_err(
                |e| {
                    tracing::error!("SetFilePointerEx failed: 0x{:X}", e.code().0);
                    XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0 as i32))
                },
            )?;

            let mut bytes_written: u32 = 0;
            WriteFile(self.handle, Some(data), Some(&mut bytes_written), None).map_err(|e| {
                tracing::error!("WriteFile failed: 0x{:X}", e.code().0);
                XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0 as i32))
            })?;

            tracing::trace!("write_at: offset={} wrote {} bytes", offset, bytes_written);
            Ok(bytes_written as usize)
        }
    }

    fn flush_raw(&self) -> Result<()> {
        unsafe {
            FlushFileBuffers(self.handle).map_err(|e| {
                XfsWinfspError::IoError(std::io::Error::from_raw_os_error(e.code().0 as i32))
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
    let mut partitions = Vec::new();

    // Read first sector to detect partition table type
    let mut boot_sector = vec![0u8; 512];
    reader.read_raw_at(0, &mut boot_sector)?;

    // Check for GPT signature
    if boot_sector.len() >= 512 {
        // GPT has a protective MBR with signature 0x55AA at offset 510
        let mbr_sig = u16::from_le_bytes([boot_sector[510], boot_sector[511]]);

        if mbr_sig == 0xAA55 {
            // Check if it's GPT (protective MBR has partition type 0xEE)
            if boot_sector.len() >= 450 && boot_sector[450] == 0xEE {
                // This is GPT - read GPT header from LBA 1
                return read_gpt_partitions(reader);
            } else {
                // This is MBR
                return read_mbr_partitions(reader, &boot_sector);
            }
        }
    }

    Ok(partitions)
}

/// Read MBR partition table.
fn read_mbr_partitions(_reader: &dyn DiskReader, boot_sector: &[u8]) -> Result<Vec<PartitionInfo>> {
    let mut partitions = Vec::new();

    // MBR partition table starts at offset 446
    for i in 0..4 {
        let entry_offset = 446 + (i * 16);
        if entry_offset + 16 > boot_sector.len() {
            break;
        }

        let entry = &boot_sector[entry_offset..entry_offset + 16];
        let partition_type = entry[4];

        // Skip empty partitions
        if partition_type == 0 {
            continue;
        }

        let lba_start = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as u64;
        let sector_count = u32::from_le_bytes([entry[12], entry[13], entry[14], entry[15]]) as u64;

        partitions.push(PartitionInfo {
            offset: lba_start * 512,
            size: sector_count * 512,
            partition_type,
        });
    }

    Ok(partitions)
}

/// Read GPT partition table.
fn read_gpt_partitions(reader: &dyn DiskReader) -> Result<Vec<PartitionInfo>> {
    let mut partitions = Vec::new();

    // Read GPT header from LBA 1
    let mut gpt_header = vec![0u8; 512];
    reader.read_raw_at(512, &mut gpt_header)?;

    // Verify GPT signature "EFI PART"
    if gpt_header.len() >= 8 {
        let sig = &gpt_header[0..8];
        if sig != b"EFI PART" {
            return Ok(partitions);
        }
    }

    // Get partition entry LBA and count
    let partition_entry_lba = if gpt_header.len() >= 80 {
        u64::from_le_bytes([
            gpt_header[72],
            gpt_header[73],
            gpt_header[74],
            gpt_header[75],
            gpt_header[76],
            gpt_header[77],
            gpt_header[78],
            gpt_header[79],
        ])
    } else {
        return Ok(partitions);
    };

    let num_partitions = if gpt_header.len() >= 84 {
        u32::from_le_bytes([
            gpt_header[80],
            gpt_header[81],
            gpt_header[82],
            gpt_header[83],
        ])
    } else {
        return Ok(partitions);
    };

    // Read partition entries (each is 128 bytes)
    let entries_size = (num_partitions as usize) * 128;
    let mut entries = vec![0u8; entries_size];
    reader.read_raw_at(partition_entry_lba * 512, &mut entries)?;

    for i in 0..num_partitions as usize {
        let entry_offset = i * 128;
        if entry_offset + 128 > entries.len() {
            break;
        }

        let entry = &entries[entry_offset..entry_offset + 128];

        // Check if partition type GUID is all zeros (unused entry)
        let is_empty = entry[0..16].iter().all(|&b| b == 0);
        if is_empty {
            continue;
        }

        // Get first and last LBA
        let first_lba = u64::from_le_bytes([
            entry[32], entry[33], entry[34], entry[35], entry[36], entry[37], entry[38], entry[39],
        ]);

        let last_lba = u64::from_le_bytes([
            entry[40], entry[41], entry[42], entry[43], entry[44], entry[45], entry[46], entry[47],
        ]);

        partitions.push(PartitionInfo {
            offset: first_lba * 512,
            size: (last_lba - first_lba + 1) * 512,
            partition_type: 0, // GPT doesn't use a simple type byte
        });
    }

    Ok(partitions)
}

/// Try to open an XFS partition from a physical disk.
/// If the disk has partitions, find and wrap the first XFS partition.
pub fn open_disk_with_partitions(disk_number: u32) -> Result<Arc<dyn DiskReader>> {
    let disk = Arc::new(PhysicalDiskReader::open(disk_number)?) as Arc<dyn DiskReader>;

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
                    Arc::new(PartitionReader::new(disk.clone(), part.offset, part.size))
                        as Arc<dyn DiskReader>;

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
        _ => {
            // No partitions detected or error, try raw disk
            tracing::debug!(
                "No partition table detected on disk {}, using raw disk",
                disk_number
            );
            Ok(disk)
        }
    }
}

/// Try to open an XFS partition from a physical disk with read-write access.
/// If the disk has partitions, find and wrap the first XFS partition.
pub fn open_disk_with_partitions_rw(
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
        _ => {
            // No partitions detected or error, try raw disk
            tracing::debug!(
                "No partition table detected on disk {} (RW mode), using raw disk",
                disk_number
            );
            let reader: Arc<dyn DiskReader> = disk.clone();
            let writer: Arc<dyn DiskWriter> = disk;
            Ok((reader, writer))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xfs_magic() {
        let magic_bytes = [0x58u8, 0x46, 0x53, 0x42];
        let magic = u32::from_be_bytes(magic_bytes);
        assert_eq!(magic, 0x58465342);
    }
}
