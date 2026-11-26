//! Generic VFS context and file handle for WinFsp.
//!
//! This module provides the bridge between the Windows-specific WinFsp
//! callbacks and the generic `VfsFileSystem` trait.

use std::{
    ffi::{c_void, OsStr},
    sync::Arc,
};

use fs_abstraction::{
    error::{FsError, FsResult},
    types::{VfsFileInfo, VfsFileType, VfsTimestamp},
    vfs::VfsFileSystem,
};
use tracing::{debug, error, trace, warn};
use winfsp::{
    filesystem::{
        DirBuffer,
        DirInfo,
        DirMarker,
        FileInfo,
        FileSecurity,
        FileSystemContext,
        OpenFileInfo,
        VolumeInfo,
        WideNameInfo,
    },
    FspError,
    U16CStr,
};

use crate::security::AclMapper;

// Windows file attributes constants
const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;
const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000000C;
const WINDOWS_EPOCH_OFFSET: i64 = 11_644_473_600;
const FILE_TIME_TICKS_PER_SECOND: u64 = 10_000_000;

/// Generic WinFsp file context - stored per open file handle.
///
/// This structure tracks the state of an open file or directory.
pub struct VfsFileHandle {
    /// Inode number.
    pub inode: u64,
    /// Is this a directory?
    pub is_directory: bool,
    /// Directory buffer for enumeration (only used for directories).
    pub dir_buffer: DirBuffer,
}

impl VfsFileHandle {
    /// Create a new file handle.
    pub fn new(inode: u64, is_directory: bool) -> Self {
        Self {
            inode,
            is_directory,
            dir_buffer: DirBuffer::new(),
        }
    }
}

/// Generic WinFsp filesystem context.
///
/// This structure holds the reference to the underlying VFS implementation
/// and shared volume state.
pub struct VfsContext {
    /// The underlying filesystem implementation.
    pub fs: Arc<dyn VfsFileSystem>,
    /// Volume label.
    pub volume_label: String,
    /// Normalized mount root used to confine absolute symbolic links.
    mount_root: String,
    /// Effective mount policy derived from the backend capabilities.
    read_only: bool,
    /// POSIX mode/uid/gid → Windows security descriptor mapper.
    acl_mapper: AclMapper,
}

impl VfsContext {
    /// Create a new VFS context.
    ///
    /// The mount root is required so absolute symbolic links can be qualified
    /// without allowing them to escape the mounted volume.
    pub fn new(
        fs: Arc<dyn VfsFileSystem>,
        volume_label: String,
        mount_root: String,
    ) -> FsResult<Self> {
        let read_only = fs.capabilities().read_only;
        Ok(Self {
            fs,
            volume_label,
            mount_root: normalize_mount_root(&mount_root)?,
            read_only,
            acl_mapper: AclMapper::new(read_only),
        })
    }

    /// Create a context with an explicitly configured ACL mapper (primarily
    /// useful for tests and embedders).
    pub fn with_acl_mapper(
        fs: Arc<dyn VfsFileSystem>,
        volume_label: String,
        mount_root: String,
        acl_mapper: AclMapper,
    ) -> FsResult<Self> {
        let read_only = fs.capabilities().read_only;
        Ok(Self {
            fs,
            volume_label,
            mount_root: normalize_mount_root(&mount_root)?,
            read_only,
            acl_mapper,
        })
    }

    /// Copy a self-relative security descriptor into the WinFsp buffer (if
    /// provided) and return its length.
    fn copy_security_descriptor(
        &self,
        sd: &[u8],
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        let length = sd.len() as u64;
        if let Some(buffer) = security_descriptor {
            if buffer.len() < sd.len() {
                // WinFsp's GetSecurityByName retry loop specifically expects
                // STATUS_BUFFER_OVERFLOW when it should grow the descriptor
                // buffer.
                return Err(FspError::NTSTATUS(0x8000_0005_u32 as i32));
            }
            // SAFETY: WinFsp guarantees the buffer points to at least
            // `buffer.len()` writable bytes of c_void storage.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    sd.as_ptr(),
                    buffer.as_mut_ptr() as *mut u8,
                    sd.len(),
                );
            }
        }
        Ok(length)
    }

    /// Helper: Map VfsFileInfo to WinFsp FileInfo.
    fn fill_file_info(&self, info: &VfsFileInfo, out_info: &mut FileInfo) -> winfsp::Result<()> {
        trace!(
            "fill_file_info: ino={}, dir={}, size={}",
            info.ino,
            info.is_dir(),
            info.size
        );
        *out_info = file_info_from_vfs(info, self.read_only).map_err(|e| self.map_error(e))?;
        Ok(())
    }

    /// Reject mutations when the mounted VFS is read-only.
    fn reject_if_read_only(&self) -> winfsp::Result<()> {
        if self.read_only {
            Err(self.map_error(FsError::ReadOnly))
        } else {
            Ok(())
        }
    }

    /// Helper: Map FsError to FspError.
    fn map_error(&self, e: FsError) -> FspError {
        FspError::NTSTATUS(e.to_ntstatus())
    }
}

impl FileSystemContext for VfsContext {
    type FileContext = VfsFileHandle;

    fn get_security_by_name(
        &self,
        file_name: &U16CStr,
        security_descriptor: Option<&mut [std::ffi::c_void]>,
        reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        // WinFsp's resolver scans intermediate components only. Delegating to
        // it before resolve_path is essential: the XFS VFS does not follow
        // symlinks while traversing paths.
        if let Some(security) = reparse_point_resolver(file_name) {
            return Ok(security);
        }

        let name = file_name.to_string_lossy();
        let ino = self.fs.resolve_path(&name).map_err(|e| self.map_error(e))?;
        let info = self.fs.stat(ino).map_err(|e| self.map_error(e))?;
        let sd = self.acl_mapper.security_descriptor(&info);
        let length = self.copy_security_descriptor(&sd, security_descriptor)?;

        Ok(FileSecurity {
            // A symlink in the final component is not an intermediate reparse.
            reparse: false,
            sz_security_descriptor: length,
            attributes: file_attributes(&info, self.read_only),
        })
    }

    fn open(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: winfsp_sys::FILE_ACCESS_RIGHTS,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        let name = file_name.to_string_lossy();
        debug!("open: '{}', options=0x{:X}", name, create_options);
        match self.fs.resolve_path(&name) {
            Ok(ino) => {
                debug!("open resolved '{}' to ino {}", name, ino);
                match self.fs.stat(ino) {
                    Ok(info) => {
                        self.fill_file_info(&info, file_info.as_mut())?;
                        Ok(VfsFileHandle::new(ino, info.is_dir()))
                    }
                    Err(e) => {
                        error!("open stat failed for ino {}: {:?}", ino, e);
                        Err(self.map_error(e))
                    }
                }
            }
            Err(e) => {
                debug!("open resolve_path failed for '{}': {:?}", name, e);
                Err(self.map_error(e))
            }
        }
    }

    fn close(&self, _context: Self::FileContext) {
        // No-op for now, VfsFileHandle will drop.
    }

    fn get_security(
        &self,
        context: &Self::FileContext,
        security_descriptor: Option<&mut [c_void]>,
    ) -> winfsp::Result<u64> {
        let info = self.fs.stat(context.inode).map_err(|e| self.map_error(e))?;
        let sd = self.acl_mapper.security_descriptor(&info);
        self.copy_security_descriptor(&sd, security_descriptor)
    }

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        match self.fs.stat(context.inode) {
            Ok(info) => {
                self.fill_file_info(&info, file_info)?;
                Ok(())
            }
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn read(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> winfsp::Result<u32> {
        // WinFsp reports EOF as SUCCESS with zero bytes transferred. Some VFS
        // backends instead return FsError::EndOfFile; normalize that here.
        read_byte_count(self.fs.read(context.inode, offset, buffer), buffer.len())
            .map_err(|e| self.map_error(e))
    }

    fn write(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        _constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<u32> {
        self.reject_if_read_only()?;
        let actual_offset = if write_to_eof {
            match self.fs.stat(context.inode) {
                Ok(info) => info.size,
                Err(e) => return Err(self.map_error(e)),
            }
        } else {
            offset
        };

        match self.fs.write(context.inode, actual_offset, buffer) {
            Ok(bytes_written) => {
                let info = self.fs.stat(context.inode).map_err(|e| self.map_error(e))?;
                self.fill_file_info(&info, file_info)?;
                let bytes_written = u32::try_from(bytes_written)
                    .map_err(|_| self.map_error(FsError::ArithmeticOverflow))?;
                if bytes_written as usize > buffer.len() {
                    return Err(self.map_error(FsError::SecurityViolation));
                }
                Ok(bytes_written)
            }
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn create(
        &self,
        file_name: &U16CStr,
        create_options: u32,
        _granted_access: winfsp_sys::FILE_ACCESS_RIGHTS,
        _file_attributes: winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES,
        _security_descriptor: Option<&[std::ffi::c_void]>,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        _extra_buffer_is_reparse_point: bool,
        file_info: &mut OpenFileInfo,
    ) -> winfsp::Result<Self::FileContext> {
        self.reject_if_read_only()?;
        let name = file_name.to_string_lossy();
        debug!("create: '{}', options=0x{:X}", name, create_options);
        let (parent_path, entry_name) = split_path(&name);

        let parent_ino = self.fs.resolve_path(&parent_path).map_err(|e| {
            error!(
                "create resolve_path failed for parent '{}': {:?}",
                parent_path, e
            );
            self.map_error(e)
        })?;

        let is_dir = (create_options & 0x00000001) != 0; // FILE_DIRECTORY_FILE
        debug!(
            "creating {} '{}' in parent {}",
            if is_dir { "DIR" } else { "FILE" },
            entry_name,
            parent_ino
        );

        let result = if is_dir {
            self.fs.create_directory(parent_ino, &entry_name, 0o755)
        } else {
            self.fs.create_file(parent_ino, &entry_name, 0o644)
        };

        match result {
            Ok(info) => {
                debug!("create successful: '{}' -> ino {}", name, info.ino);
                self.fill_file_info(&info, file_info.as_mut())?;
                Ok(VfsFileHandle::new(info.ino, info.is_dir()))
            }
            Err(e) => {
                error!("create failed for '{}': {:?}", name, e);
                Err(self.map_error(e))
            }
        }
    }

    fn overwrite(
        &self,
        context: &Self::FileContext,
        _file_attributes: winfsp_sys::FILE_FLAGS_AND_ATTRIBUTES,
        _replace_file_attributes: bool,
        _allocation_size: u64,
        _extra_buffer: Option<&[u8]>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.reject_if_read_only()?;
        self.fs
            .set_size(context.inode, 0)
            .map_err(|e| self.map_error(e))?;
        let info = self.fs.stat(context.inode).map_err(|e| self.map_error(e))?;
        self.fill_file_info(&info, file_info)
    }

    fn rename(
        &self,
        _context: &Self::FileContext,
        file_name: &winfsp::U16CStr,
        new_file_name: &winfsp::U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        self.reject_if_read_only()?;
        let old_path = file_name.to_string_lossy();
        let new_path = new_file_name.to_string_lossy();

        let (old_parent_path, old_name) = split_path(&old_path);
        let (new_parent_path, new_name) = split_path(&new_path);

        let old_parent = self
            .fs
            .resolve_path(&old_parent_path)
            .map_err(|e| self.map_error(e))?;
        let new_parent = self
            .fs
            .resolve_path(&new_parent_path)
            .map_err(|e| self.map_error(e))?;

        let vfs_flags = fs_abstraction::types::RenameFlags {
            replace_if_exists,
            ..Default::default()
        };

        match self
            .fs
            .rename(old_parent, &old_name, new_parent, &new_name, vfs_flags)
        {
            Ok(()) => Ok(()),
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        _pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if !context.is_directory {
            return Err(winfsp::FspError::WIN32(267)); // ERROR_DIRECTORY
        }

        let reset = marker.is_none();
        let lock = context.dir_buffer.acquire(reset, None)?;

        if reset {
            match self.fs.readdir(context.inode) {
                Ok(entries) => {
                    for entry in entries {
                        let mut di = DirInfo::new();
                        if di.set_name(OsStr::new(&entry.name)).is_err() {
                            continue;
                        }

                        // A directory entry without trustworthy metadata must
                        // not be exposed with zeroed attributes/timestamps.
                        let info = match self.fs.stat(entry.ino) {
                            Ok(info) => info,
                            Err(error) => {
                                trace!("Skipping readdir entry '{}': {:?}", entry.name, error);
                                continue;
                            }
                        };
                        if let Err(error) = self.fill_file_info(&info, di.file_info_mut()) {
                            warn!(
                                "Skipping invalid readdir entry '{}': {:?}",
                                entry.name, error
                            );
                            continue;
                        }

                        if lock.write::<255>(&mut di).is_err() {
                            break;
                        }
                    }
                }
                Err(e) => return Err(self.map_error(e)),
            }
        }

        drop(lock);
        Ok(context.dir_buffer.read(marker, buffer))
    }

    fn get_dir_info_by_name(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        out_dir_info: &mut DirInfo,
    ) -> winfsp::Result<()> {
        let name = file_name.to_string_lossy();
        match self.fs.lookup(context.inode, &name) {
            Ok(info) => {
                out_dir_info.set_name(OsStr::new(&name))?;
                self.fill_file_info(&info, out_dir_info.file_info_mut())?;
                Ok(())
            }
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn cleanup(
        &self,
        context: &Self::FileContext,
        file_name: Option<&winfsp::U16CStr>,
        flags: u32,
    ) {
        // Handle pending delete on close
        const FSP_CLEANUP_DELETE: u32 = 0x01;

        if (flags & FSP_CLEANUP_DELETE) != 0 && !self.read_only {
            if let Some(name) = file_name {
                let path = name.to_string_lossy();
                let (parent_path, entry_name) = split_path(&path);

                if let Ok(parent_ino) = self.fs.resolve_path(&parent_path) {
                    let _ = self.fs.unlink(parent_ino, &entry_name, context.inode);
                }
            }
        }
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        // VfsFileSystem currently exposes only a volume-wide sync operation.
        // Use it for both requests; a file flush must also refresh FileInfo.
        self.fs.sync().map_err(|e| self.map_error(e))?;
        if let Some(context) = context {
            let info = self.fs.stat(context.inode).map_err(|e| self.map_error(e))?;
            self.fill_file_info(&info, file_info)?;
        }
        Ok(())
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> winfsp::Result<()> {
        match self.fs.get_volume_info() {
            Ok(vi) => {
                out_volume_info.total_size = vi.total_bytes;
                out_volume_info.free_size = vi.free_bytes;
                if let Some(label) = &vi.volume_label {
                    out_volume_info.set_volume_label(label);
                }
                Ok(())
            }
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn set_basic_info(
        &self,
        context: &Self::FileContext,
        _file_attributes: u32,
        _creation_time: u64,
        last_access_time: u64,
        last_write_time: u64,
        _last_change_time: u64,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.reject_if_read_only()?;
        let atime = if last_access_time != 0 {
            Some(fs_abstraction::types::VfsTimestamp::from_filetime(
                last_access_time,
            ))
        } else {
            None
        };
        let mtime = if last_write_time != 0 {
            Some(fs_abstraction::types::VfsTimestamp::from_filetime(
                last_write_time,
            ))
        } else {
            None
        };

        self.fs
            .set_times(context.inode, atime, mtime)
            .map_err(|e| self.map_error(e))?;
        let info = self.fs.stat(context.inode).map_err(|e| self.map_error(e))?;
        self.fill_file_info(&info, file_info)
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        self.reject_if_read_only()?;
        self.fs
            .set_size(context.inode, new_size)
            .map_err(|e| self.map_error(e))?;
        let info = self.fs.stat(context.inode).map_err(|e| self.map_error(e))?;
        self.fill_file_info(&info, file_info)
    }

    fn set_delete(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> winfsp::Result<()> {
        self.reject_if_read_only()?;
        // WinFsp handles the delete flag internally; cleanup performs unlink.
        Ok(())
    }

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        _is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        let name = file_name.to_string_lossy();
        let ino = self.fs.resolve_path(&name).map_err(|e| self.map_error(e))?;

        match self.fs.readlink(ino) {
            Ok(target) => {
                let reparse_data = create_symlink_reparse_buffer(&target, &name, &self.mount_root)
                    .map_err(|e| self.map_error(e))?;
                let len = u64::try_from(reparse_data.len())
                    .map_err(|_| self.map_error(FsError::ArithmeticOverflow))?;
                if buffer.len() < reparse_data.len() {
                    return Ok(len);
                }
                buffer[..reparse_data.len()].copy_from_slice(&reparse_data);
                Ok(len)
            }
            Err(FsError::NotSupported) => Err(winfsp::FspError::WIN32(4390)),
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        match self.fs.readlink(context.inode) {
            Ok(target) => {
                let name = file_name.to_string_lossy();
                let reparse_data = create_symlink_reparse_buffer(&target, &name, &self.mount_root)
                    .map_err(|e| self.map_error(e))?;
                let len = u64::try_from(reparse_data.len())
                    .map_err(|_| self.map_error(FsError::ArithmeticOverflow))?;
                if buffer.len() < reparse_data.len() {
                    return Ok(len);
                }
                buffer[..reparse_data.len()].copy_from_slice(&reparse_data);
                Ok(len)
            }
            Err(e) => Err(self.map_error(e)),
        }
    }
}

/// Split a path into parent directory and filename.
fn split_path(path: &str) -> (String, String) {
    let path = path.replace('\\', "/");
    let path = path.trim_start_matches('/');

    if let Some(last_slash) = path.rfind('/') {
        let parent = &path[..last_slash];
        let name = &path[last_slash + 1..];
        (format!("/{}", parent), name.to_string())
    } else {
        ("/".to_string(), path.to_string())
    }
}

/// Convert metadata to WinFsp's FileInfo without unchecked arithmetic.
fn file_info_from_vfs(info: &VfsFileInfo, read_only: bool) -> FsResult<FileInfo> {
    let allocation_size = info
        .blocks
        .checked_mul(512)
        .ok_or(FsError::ArithmeticOverflow)?;
    Ok(FileInfo {
        file_attributes: file_attributes(info, read_only),
        reparse_tag: if info.file_type == VfsFileType::Symlink {
            IO_REPARSE_TAG_SYMLINK
        } else {
            0
        },
        allocation_size,
        file_size: info.size,
        creation_time: checked_filetime(info.crtime.unwrap_or(info.ctime))?,
        last_access_time: checked_filetime(info.atime)?,
        last_write_time: checked_filetime(info.mtime)?,
        change_time: checked_filetime(info.ctime)?,
        index_number: info.ino,
        // WinFsp does not implement hard links and requires this field to be 0.
        hard_links: 0,
        ..FileInfo::default()
    })
}

fn file_attributes(info: &VfsFileInfo, read_only: bool) -> u32 {
    let mut attributes = match info.file_type {
        VfsFileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
        VfsFileType::Symlink => FILE_ATTRIBUTE_REPARSE_POINT,
        _ => FILE_ATTRIBUTE_NORMAL,
    };
    if read_only {
        attributes |= FILE_ATTRIBUTE_READONLY;
    }
    attributes
}

fn checked_filetime(timestamp: VfsTimestamp) -> FsResult<u64> {
    let seconds = timestamp
        .secs
        .checked_add(WINDOWS_EPOCH_OFFSET)
        .ok_or(FsError::ArithmeticOverflow)?;
    if seconds < 0 {
        return Ok(0);
    }
    (seconds as u64)
        .checked_mul(FILE_TIME_TICKS_PER_SECOND)
        .and_then(|ticks| ticks.checked_add(u64::from(timestamp.nsecs / 100)))
        .ok_or(FsError::ArithmeticOverflow)
}

/// Normalize a VFS read result to the WinFsp read contract.
fn read_byte_count(result: FsResult<usize>, buffer_len: usize) -> FsResult<u32> {
    let bytes_read = match result {
        Ok(bytes_read) => bytes_read,
        Err(FsError::EndOfFile) => return Ok(0),
        Err(error) => return Err(error),
    };
    if bytes_read > buffer_len {
        return Err(FsError::SecurityViolation);
    }
    u32::try_from(bytes_read).map_err(|_| FsError::ArithmeticOverflow)
}

fn drive_prefix(path: &str) -> Option<&str> {
    let bytes = path.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        Some(&path[..2])
    } else {
        None
    }
}

fn strip_verbatim_prefix(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix("\\\\?\\") {
        rest
    } else if let Some(rest) = path.strip_prefix("\\??\\") {
        rest
    } else {
        path
    }
}

/// Normalize a drive or UNC mount point without discarding its directory path.
/// Dot components are removed and `..` is clamped at the drive/share root.
fn normalize_mount_root(mount_root: &str) -> FsResult<String> {
    if mount_root.is_empty() || mount_root.contains('\0') {
        return Err(FsError::InvalidPath);
    }
    let normalized = mount_root.replace('/', "\\");

    // `\\?\UNC\server\share\...` is the verbatim spelling of a UNC path.
    let verbatim_unc = normalized
        .strip_prefix("\\\\?\\UNC\\")
        .map(|rest| format!("\\\\{}", rest));
    let path = if let Some(unc) = &verbatim_unc {
        unc.as_str()
    } else {
        strip_verbatim_prefix(&normalized)
    };

    if let Some(drive) = drive_prefix(path) {
        let rest = &path[2..];
        if !rest.is_empty() && !rest.starts_with('\\') {
            return Err(FsError::InvalidPath);
        }
        let components = normalized_components(rest, &[]);
        let drive = drive.to_ascii_uppercase();
        return Ok(if components.is_empty() {
            format!("{}\\", drive)
        } else {
            format!("{}\\{}", drive, components.join("\\"))
        });
    }

    if path.starts_with("\\\\") {
        let parts: Vec<&str> = path.split('\\').filter(|part| !part.is_empty()).collect();
        if parts.len() >= 2 {
            // Normalize only below the share: `..` must never remove the
            // server or share components of the mounted volume.
            let subpath = parts[2..].join("\\");
            let subcomponents = normalized_components(&subpath, &[]);
            let mut root = format!("\\\\{}\\{}", parts[0], parts[1]);
            if !subcomponents.is_empty() {
                root.push('\\');
                root.push_str(&subcomponents.join("\\"));
            }
            return Ok(root);
        }
    }
    Err(FsError::InvalidPath)
}

/// Join normalized path components to a mount root, preserving directory
/// mounts.
fn join_mount_root(mount_root: &str, components: &[String]) -> String {
    if components.is_empty() {
        return mount_root.to_string();
    }
    if mount_root.ends_with('\\') {
        format!("{}{}", mount_root, components.join("\\"))
    } else {
        format!("{}\\{}", mount_root, components.join("\\"))
    }
}

fn strip_mount_root<'a>(path: &'a str, mount_root: &str) -> Option<&'a str> {
    let root = mount_root.trim_end_matches('\\');
    if root.is_empty() {
        return None;
    }
    let prefix = path.get(..root.len())?;
    if !prefix.eq_ignore_ascii_case(root) {
        return None;
    }
    let rest = &path[root.len()..];
    if rest.is_empty() {
        Some("")
    } else if rest.starts_with('\\') {
        // Also canonicalize a trailing separator on the mount root itself.
        Some(rest.trim_start_matches('\\'))
    } else {
        None
    }
}

fn normalized_components(path: &str, base: &[&str]) -> Vec<String> {
    let mut components: Vec<String> = base.iter().map(|part| (*part).to_string()).collect();
    for component in path.split(['\\', '/']) {
        match component {
            "" | "." => {}
            ".." => {
                // Clamp at the volume root; never emit a traversal above it.
                components.pop();
            }
            _ => components.push(component.to_string()),
        }
    }
    components
}

fn link_parent_components(link_name: &str, mount_root: &str) -> Vec<String> {
    let normalized = link_name.replace('/', "\\");
    let without_prefix = strip_verbatim_prefix(&normalized);
    let without_root = strip_mount_root(without_prefix, mount_root).unwrap_or(without_prefix);
    let without_drive = if drive_prefix(without_root).is_some() {
        &without_root[2..]
    } else {
        without_root
    };
    let parent = without_drive
        .trim_end_matches('\\')
        .rsplit_once('\\')
        .map(|(parent, _)| parent)
        .unwrap_or("");

    let mut components = Vec::new();
    for component in parent.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                components.pop();
            }
            _ => components.push(component.to_string()),
        }
    }
    components
}

/// Qualify absolute targets with the mount root and clamp `..` at that root.
/// Relative targets are normalized with knowledge of the link's parent so they
/// cannot traverse above the volume either. Cross-volume and UNC targets fail.
fn symlink_windows_target(
    target: &str,
    link_name: &str,
    mount_root: &str,
) -> FsResult<(String, bool)> {
    if target.is_empty() || target.contains('\0') {
        return Err(FsError::InvalidPath);
    }
    let windows_target = target.replace('/', "\\");

    if windows_target.starts_with("\\\\") {
        let stripped = strip_verbatim_prefix(&windows_target);
        if stripped != windows_target && drive_prefix(stripped).is_some() {
            return symlink_windows_target(stripped, link_name, mount_root);
        }
        return Err(FsError::SecurityViolation);
    }

    if windows_target.contains(':') {
        let drive = drive_prefix(&windows_target).ok_or(FsError::SecurityViolation)?;
        let mount_drive = drive_prefix(mount_root).ok_or(FsError::SecurityViolation)?;
        if !drive.eq_ignore_ascii_case(mount_drive) {
            return Err(FsError::SecurityViolation);
        }
        let rest = &windows_target[2..];
        if !rest.starts_with('\\') {
            return Err(FsError::SecurityViolation); // drive-relative (X:foo)
        }
        // A drive-qualified target already below the mount must not have the
        // mount directory prepended twice. Other same-drive paths are mapped
        // below the mount root so they cannot escape it.
        let components = if let Some(relative) = strip_mount_root(&windows_target, mount_root) {
            normalized_components(relative, &[])
        } else {
            normalized_components(rest, &[])
        };
        return Ok((join_mount_root(mount_root, &components), false));
    }

    if windows_target.starts_with('\\') {
        let components = normalized_components(&windows_target, &[]);
        return Ok((join_mount_root(mount_root, &components), false));
    }

    let parent = link_parent_components(link_name, mount_root);
    let parent_refs: Vec<&str> = parent.iter().map(String::as_str).collect();
    let resolved = normalized_components(&windows_target, &parent_refs);
    let common = parent
        .iter()
        .zip(&resolved)
        .take_while(|(left, right)| left == right)
        .count();
    let up = parent.len() - common;
    let mut relative: Vec<&str> = (0..up).map(|_| "..").collect();
    relative.extend(resolved[common..].iter().map(String::as_str));
    let relative = if relative.is_empty() {
        ".".to_string()
    } else {
        relative.join("\\")
    };
    Ok((relative, true))
}

/// Create a Windows symbolic link reparse buffer from a confined Unix target.
fn create_symlink_reparse_buffer(
    target: &str,
    link_name: &str,
    mount_root: &str,
) -> FsResult<Vec<u8>> {
    let (windows_target, is_relative) = symlink_windows_target(target, link_name, mount_root)?;
    let target_utf16: Vec<u16> = windows_target.encode_utf16().collect();
    let target_bytes_len = target_utf16
        .len()
        .checked_mul(2)
        .ok_or(FsError::StringTooLong)?;
    let target_bytes_len = u16::try_from(target_bytes_len).map_err(|_| FsError::StringTooLong)?;
    let path_buffer_size = target_bytes_len
        .checked_mul(2)
        .ok_or(FsError::StringTooLong)?;
    let reparse_data_length = 12u16
        .checked_add(path_buffer_size)
        .ok_or(FsError::StringTooLong)?;
    let total_size = 8usize
        .checked_add(reparse_data_length as usize)
        .ok_or(FsError::ArithmeticOverflow)?;
    let mut buffer = vec![0u8; total_size];

    let flags: u32 = if is_relative { 1 } else { 0 };
    buffer[0..4].copy_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    buffer[4..6].copy_from_slice(&reparse_data_length.to_le_bytes());
    buffer[8..10].copy_from_slice(&0u16.to_le_bytes());
    buffer[10..12].copy_from_slice(&target_bytes_len.to_le_bytes());
    buffer[12..14].copy_from_slice(&target_bytes_len.to_le_bytes());
    buffer[14..16].copy_from_slice(&target_bytes_len.to_le_bytes());
    buffer[16..20].copy_from_slice(&flags.to_le_bytes());

    let path_start = 20;
    for (index, &ch) in target_utf16.iter().enumerate() {
        let offset = path_start + index * 2;
        buffer[offset..offset + 2].copy_from_slice(&ch.to_le_bytes());
    }
    let print_start = path_start + target_bytes_len as usize;
    for (index, &ch) in target_utf16.iter().enumerate() {
        let offset = print_start + index * 2;
        buffer[offset..offset + 2].copy_from_slice(&ch.to_le_bytes());
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_info(file_type: VfsFileType) -> VfsFileInfo {
        VfsFileInfo {
            ino: 42,
            size: 1234,
            blocks: 3,
            block_size: 4096,
            mode: file_type.to_mode_bits() | 0o644,
            file_type,
            nlink: 7,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            atime: VfsTimestamp::new(0, 123_456_700),
            mtime: VfsTimestamp::new(1, 0),
            ctime: VfsTimestamp::new(2, 0),
            crtime: Some(VfsTimestamp::new(3, 0)),
        }
    }

    fn reparse_target(buffer: &[u8]) -> (String, bool) {
        assert_eq!(
            u32::from_le_bytes(buffer[0..4].try_into().unwrap()),
            IO_REPARSE_TAG_SYMLINK
        );
        let data_len = u16::from_le_bytes(buffer[4..6].try_into().unwrap()) as usize;
        assert_eq!(buffer.len(), 8 + data_len);
        let substitute_len = u16::from_le_bytes(buffer[10..12].try_into().unwrap()) as usize;
        let print_offset = u16::from_le_bytes(buffer[12..14].try_into().unwrap()) as usize;
        let print_len = u16::from_le_bytes(buffer[14..16].try_into().unwrap()) as usize;
        let flags = u32::from_le_bytes(buffer[16..20].try_into().unwrap());
        let start = 20 + print_offset;
        let units: Vec<u16> = buffer[start..start + print_len]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|bytes| u16::from_le_bytes(*bytes))
            .collect();
        assert_eq!(substitute_len, print_len);
        (String::from_utf16_lossy(&units), flags & 1 != 0)
    }

    #[test]
    fn file_info_uses_checked_sizes_and_winfsp_hard_link_policy() {
        let info = file_info_from_vfs(&file_info(VfsFileType::RegularFile), true).unwrap();
        assert_eq!(info.allocation_size, 3 * 512);
        assert_eq!(info.file_size, 1234);
        assert_eq!(info.hard_links, 0);
        assert_eq!(info.index_number, 42);
        assert_eq!(info.reparse_tag, 0);
        assert_eq!(
            info.file_attributes,
            FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_READONLY
        );
        assert_eq!(info.last_access_time, 116_444_736_001_234_567);
    }

    #[test]
    fn file_info_reports_symlink_tag() {
        let info = file_info_from_vfs(&file_info(VfsFileType::Symlink), true).unwrap();
        assert_eq!(info.reparse_tag, IO_REPARSE_TAG_SYMLINK);
        assert_ne!(info.file_attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
    }

    #[test]
    fn file_info_rejects_arithmetic_overflow() {
        let mut metadata = file_info(VfsFileType::RegularFile);
        metadata.blocks = u64::MAX;
        assert_eq!(
            file_info_from_vfs(&metadata, true).unwrap_err(),
            FsError::ArithmeticOverflow
        );

        metadata.blocks = 0;
        metadata.atime.secs = i64::MAX;
        assert_eq!(
            file_info_from_vfs(&metadata, true).unwrap_err(),
            FsError::ArithmeticOverflow
        );
    }

    #[test]
    fn read_eof_is_success_with_zero_bytes() {
        assert_eq!(read_byte_count(Err(FsError::EndOfFile), 4096), Ok(0));
        assert_eq!(read_byte_count(Ok(0), 4096), Ok(0));
        assert_eq!(read_byte_count(Ok(17), 4096), Ok(17));
        assert_eq!(
            read_byte_count(Ok(4097), 4096),
            Err(FsError::SecurityViolation)
        );
    }

    #[test]
    fn mount_roots_are_normalized_without_losing_directory_components() {
        assert_eq!(normalize_mount_root("x:").unwrap(), "X:\\");
        assert_eq!(normalize_mount_root("X:\\").unwrap(), "X:\\");
        assert_eq!(normalize_mount_root("\\\\?\\X:\\").unwrap(), "X:\\");
        assert_eq!(
            normalize_mount_root("C:\\mnt\\xfs").unwrap(),
            "C:\\mnt\\xfs"
        );
        assert_eq!(
            normalize_mount_root("c:/mnt/./xfs/tmp/..").unwrap(),
            "C:\\mnt\\xfs"
        );
        assert_eq!(
            normalize_mount_root("C:\\..\\mnt\\xfs").unwrap(),
            "C:\\mnt\\xfs"
        );
        assert_eq!(
            normalize_mount_root("//server/share/").unwrap(),
            "\\\\server\\share"
        );
        assert_eq!(
            normalize_mount_root("\\\\server\\share\\mnt\\xfs").unwrap(),
            "\\\\server\\share\\mnt\\xfs"
        );
        assert_eq!(
            normalize_mount_root("//server/share/mnt/./xfs/tmp/..").unwrap(),
            "\\\\server\\share\\mnt\\xfs"
        );
        assert_eq!(
            normalize_mount_root("\\\\server\\share\\..\\mnt\\xfs").unwrap(),
            "\\\\server\\share\\mnt\\xfs"
        );
        assert_eq!(
            normalize_mount_root("\\\\?\\UNC\\server\\share\\mnt\\xfs").unwrap(),
            "\\\\server\\share\\mnt\\xfs"
        );
        assert_eq!(normalize_mount_root("relative"), Err(FsError::InvalidPath));
        assert_eq!(
            normalize_mount_root("C:relative"),
            Err(FsError::InvalidPath)
        );
        assert_eq!(
            normalize_mount_root("\\\\server"),
            Err(FsError::InvalidPath)
        );
    }

    #[test]
    fn strip_mount_root_handles_variable_lengths_and_component_boundaries() {
        let drive_root = normalize_mount_root("C:\\mnt\\xfs").unwrap();
        for (path, expected) in [
            ("C:\\mnt\\xfs", Some("")),
            ("C:\\mnt\\xfs\\", Some("")),
            ("c:\\MNT\\XFS\\file", Some("file")),
            (
                "C:\\mnt\\xfs\\a\\much\\longer\\path",
                Some("a\\much\\longer\\path"),
            ),
            ("C:\\mnt", None),
            ("C:\\mnt\\xfs-other\\file", None),
            ("C:mnt\\xfs\\file", None),
        ] {
            assert_eq!(strip_mount_root(path, &drive_root), expected, "{path}");
        }

        let unc_root = normalize_mount_root("\\\\server\\share\\mnt\\xfs").unwrap();
        for (path, expected) in [
            ("\\\\server\\share\\mnt\\xfs", Some("")),
            ("\\\\SERVER\\SHARE\\MNT\\XFS\\file", Some("file")),
            (
                "\\\\server\\share\\mnt\\xfs\\a\\much\\longer\\path",
                Some("a\\much\\longer\\path"),
            ),
            ("\\\\server\\share", None),
            ("\\\\server\\share\\mnt\\xfs-other\\file", None),
            ("\\\\other\\share\\mnt\\xfs\\file", None),
        ] {
            assert_eq!(strip_mount_root(path, &unc_root), expected, "{path}");
        }
    }

    #[test]
    fn absolute_symlinks_are_qualified_and_clamped_to_mount_root() {
        for (target, expected) in [
            ("/var/../data", "X:\\data"),
            ("/../../etc", "X:\\etc"),
            ("/", "X:\\"),
            ("x:/dir/../file", "X:\\file"),
            ("\\\\?\\X:\\dir\\..\\file", "X:\\file"),
        ] {
            let buffer = create_symlink_reparse_buffer(target, "\\dir\\link", "X:\\").unwrap();
            assert_eq!(reparse_target(&buffer), (expected.to_string(), false));
        }
    }

    #[test]
    fn absolute_symlinks_stay_under_directory_mount_root() {
        let mount_root = normalize_mount_root("C:\\mnt\\xfs").unwrap();
        for (target, expected) in [
            ("/", "C:\\mnt\\xfs"),
            ("/var/../data", "C:\\mnt\\xfs\\data"),
            ("/../../etc", "C:\\mnt\\xfs\\etc"),
            ("C:/mnt/xfs/dir/../file", "C:\\mnt\\xfs\\file"),
            ("C:/outside/file", "C:\\mnt\\xfs\\outside\\file"),
        ] {
            let buffer = create_symlink_reparse_buffer(target, "\\dir\\link", &mount_root).unwrap();
            let (resolved, relative) = reparse_target(&buffer);
            assert!(!relative);
            assert_eq!(resolved, expected);
            assert!(
                resolved.eq_ignore_ascii_case(&mount_root)
                    || resolved.get(..mount_root.len()).is_some_and(|prefix| {
                        prefix.eq_ignore_ascii_case(&mount_root)
                            && resolved.as_bytes().get(mount_root.len()) == Some(&b'\\')
                    }),
                "symlink escaped mount root: {resolved}"
            );
        }
    }

    #[test]
    fn absolute_symlinks_stay_under_unc_directory_mount_root() {
        let mount_root = normalize_mount_root("\\\\server\\share\\mnt\\xfs").unwrap();
        let buffer =
            create_symlink_reparse_buffer("/var/../data", "\\dir\\link", &mount_root).unwrap();
        assert_eq!(
            reparse_target(&buffer),
            ("\\\\server\\share\\mnt\\xfs\\data".to_string(), false)
        );
    }

    #[test]
    fn relative_symlinks_cannot_traverse_above_volume_root() {
        for (link, target, expected) in [
            ("\\dir\\link", "../file", "..\\file"),
            ("\\dir\\link", "../../../file", "..\\file"),
            ("\\dir\\sub\\link", "../file", "..\\file"),
            ("\\dir\\link", ".", "."),
            ("\\link", "../../file", "file"),
        ] {
            let buffer = create_symlink_reparse_buffer(target, link, "X:\\").unwrap();
            assert_eq!(reparse_target(&buffer), (expected.to_string(), true));
        }

        let mount_root = normalize_mount_root("C:\\mnt\\xfs").unwrap();
        let buffer =
            create_symlink_reparse_buffer("../file", "C:\\mnt\\xfs\\dir\\link", &mount_root)
                .unwrap();
        assert_eq!(reparse_target(&buffer), ("..\\file".to_string(), true));
    }

    #[test]
    fn cross_volume_and_unc_symlinks_are_rejected() {
        for target in [
            "C:\\secret",
            "X:relative",
            "\\\\server\\share\\file",
            "file:stream",
        ] {
            assert_eq!(
                create_symlink_reparse_buffer(target, "\\link", "X:\\"),
                Err(FsError::SecurityViolation)
            );
        }
    }

    #[test]
    fn oversized_symlink_target_is_an_error_not_a_truncated_buffer() {
        let target = "x".repeat(40_000);
        assert_eq!(
            create_symlink_reparse_buffer(&target, "\\link", "X:\\"),
            Err(FsError::StringTooLong)
        );
    }

    struct TestFs {
        info: VfsFileInfo,
        capabilities: fs_abstraction::FsCapabilities,
        resolves: std::sync::atomic::AtomicUsize,
        syncs: std::sync::atomic::AtomicUsize,
    }

    impl TestFs {
        fn new(file_type: VfsFileType) -> Self {
            Self {
                info: file_info(file_type),
                // Deliberately writable: the mount policy must still force RO.
                capabilities: fs_abstraction::FsCapabilities::writable_linux(),
                resolves: Default::default(),
                syncs: Default::default(),
            }
        }
    }

    impl VfsFileSystem for TestFs {
        fn fs_type(&self) -> &'static str {
            "test"
        }

        fn capabilities(&self) -> &fs_abstraction::FsCapabilities {
            &self.capabilities
        }

        fn root_inode(&self) -> u64 {
            self.info.ino
        }

        fn get_volume_info(&self) -> FsResult<fs_abstraction::types::VfsVolumeInfo> {
            Ok(fs_abstraction::types::VfsVolumeInfo::default())
        }

        fn sync(&self) -> FsResult<()> {
            self.syncs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }

        fn stat(&self, ino: u64) -> FsResult<VfsFileInfo> {
            if ino == self.info.ino {
                Ok(self.info.clone())
            } else {
                Err(FsError::InodeNotFound)
            }
        }

        fn lookup(&self, _parent_ino: u64, _name: &str) -> FsResult<VfsFileInfo> {
            Ok(self.info.clone())
        }

        fn resolve_path(&self, _path: &str) -> FsResult<u64> {
            self.resolves
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(self.info.ino)
        }

        fn read(&self, _ino: u64, _offset: u64, _buf: &mut [u8]) -> FsResult<usize> {
            Err(FsError::EndOfFile)
        }

        fn readdir(&self, _ino: u64) -> FsResult<Vec<fs_abstraction::types::VfsDirEntry>> {
            Ok(Vec::new())
        }

        fn readlink(&self, _ino: u64) -> FsResult<String> {
            Ok("/target".to_string())
        }

        fn invalidate_inode(&self, _ino: u64) {}

        fn invalidate_all_caches(&self) {}
    }

    fn test_context(file_type: VfsFileType) -> (VfsContext, Arc<TestFs>) {
        let fs = Arc::new(TestFs::new(file_type));
        let context = VfsContext::new(fs.clone(), "Test".to_string(), "X:".to_string()).unwrap();
        (context, fs)
    }

    #[test]
    fn security_by_name_uses_resolver_for_intermediate_reparse() {
        use winfsp::U16CString;

        let (context, fs) = test_context(VfsFileType::RegularFile);
        let name = U16CString::from_str("\\dir\\file").unwrap();
        let mut resolver_called = false;
        let security = FileSystemContext::get_security_by_name(&context, &name, None, |_| {
            resolver_called = true;
            Some(FileSecurity {
                reparse: true,
                sz_security_descriptor: 0,
                attributes: FILE_ATTRIBUTE_REPARSE_POINT,
            })
        })
        .unwrap();

        assert!(resolver_called);
        assert!(security.reparse);
        assert_eq!(fs.resolves.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn final_symlink_is_not_reported_as_intermediate_reparse() {
        use winfsp::U16CString;

        let (context, fs) = test_context(VfsFileType::Symlink);
        let name = U16CString::from_str("\\link").unwrap();
        let mut resolver_called = false;
        let security = FileSystemContext::get_security_by_name(&context, &name, None, |_| {
            resolver_called = true;
            None
        })
        .unwrap();

        assert!(resolver_called);
        assert!(!security.reparse);
        assert_ne!(security.attributes & FILE_ATTRIBUTE_REPARSE_POINT, 0);
        assert_eq!(fs.resolves.load(std::sync::atomic::Ordering::SeqCst), 1);
    }
}
