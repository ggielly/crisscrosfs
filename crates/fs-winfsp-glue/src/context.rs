//! Generic VFS context and file handle for WinFsp.
//!
//! This module provides the bridge between the Windows-specific WinFsp
//! callbacks and the generic `VfsFileSystem` trait.

use std::{
    ffi::OsStr,
    sync::{atomic::AtomicU64, Arc},
};

use fs_abstraction::{
    error::FsError,
    types::{VfsFileInfo, VfsFileType},
    vfs::VfsFileSystem,
};
use tracing::{debug, error, trace, warn};
use winfsp::{
    filesystem::{
        DirBuffer, DirInfo, DirMarker, FileInfo, FileSecurity, FileSystemContext, OpenFileInfo,
        VolumeInfo, WideNameInfo,
    },
    FspError, U16CStr,
};

// Windows file attributes constants
const FILE_ATTRIBUTE_READONLY: u32 = 0x00000001;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x00000010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x00000080;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x00000400;

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
}

impl VfsContext {
    /// Create a new VFS context.
    pub fn new(fs: Arc<dyn VfsFileSystem>, volume_label: String) -> Self {
        Self { fs, volume_label }
    }

    /// Helper: Map VfsFileInfo to WinFsp FileInfo.
    fn fill_file_info(&self, info: &VfsFileInfo, out_info: &mut FileInfo) {
        trace!(
            "fill_file_info: ino={}, dir={}, size={}",
            info.ino,
            info.is_dir(),
            info.size
        );
        let mut attributes = match info.file_type {
            VfsFileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
            VfsFileType::Symlink => FILE_ATTRIBUTE_REPARSE_POINT,
            _ => FILE_ATTRIBUTE_NORMAL,
        };

        if self.fs.capabilities().read_only {
            attributes |= FILE_ATTRIBUTE_READONLY;
        }

        out_info.file_attributes = attributes;
        out_info.allocation_size = info.blocks * 512;
        out_info.file_size = info.size;
        out_info.creation_time = info.crtime.unwrap_or(info.ctime).to_filetime();
        out_info.last_access_time = info.atime.to_filetime();
        out_info.last_write_time = info.mtime.to_filetime();
        out_info.change_time = info.ctime.to_filetime();
        out_info.index_number = info.ino;
        out_info.hard_links = info.nlink;
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
        _security_descriptor: Option<&mut [std::ffi::c_void]>,
        _reparse_point_resolver: impl FnOnce(&U16CStr) -> Option<FileSecurity>,
    ) -> winfsp::Result<FileSecurity> {
        let name = file_name.to_string_lossy();
        match self.fs.resolve_path(&name) {
            Ok(ino) => match self.fs.stat(ino) {
                Ok(info) => {
                    let mut attributes = match info.file_type {
                        VfsFileType::Directory => FILE_ATTRIBUTE_DIRECTORY,
                        VfsFileType::Symlink => FILE_ATTRIBUTE_REPARSE_POINT,
                        _ => FILE_ATTRIBUTE_NORMAL,
                    };

                    if self.fs.capabilities().read_only {
                        attributes |= FILE_ATTRIBUTE_READONLY;
                    }

                    Ok(FileSecurity {
                        reparse: info.file_type == VfsFileType::Symlink,
                        sz_security_descriptor: 0,
                        attributes,
                    })
                }
                Err(e) => Err(self.map_error(e)),
            },
            Err(e) => Err(self.map_error(e)),
        }
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
                        self.fill_file_info(&info, file_info.as_mut());
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

    fn get_file_info(
        &self,
        context: &Self::FileContext,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        match self.fs.stat(context.inode) {
            Ok(info) => {
                self.fill_file_info(&info, file_info);
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
        match self.fs.read(context.inode, offset, buffer) {
            Ok(bytes_read) => Ok(bytes_read as u32),
            Err(e) => Err(self.map_error(e)),
        }
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
                // Return updated file info
                if let Ok(info) = self.fs.stat(context.inode) {
                    self.fill_file_info(&info, file_info);
                }
                Ok(bytes_written as u32)
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
                self.fill_file_info(&info, file_info.as_mut());
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
        match self.fs.set_size(context.inode, 0) {
            Ok(()) => {
                if let Ok(info) = self.fs.stat(context.inode) {
                    self.fill_file_info(&info, file_info);
                }
                Ok(())
            }
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn rename(
        &self,
        context: &Self::FileContext,
        file_name: &winfsp::U16CStr,
        new_file_name: &winfsp::U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
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

        let mut vfs_flags = fs_abstraction::types::RenameFlags::default();
        vfs_flags.replace_if_exists = replace_if_exists;

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
                        if let Err(_) = di.set_name(OsStr::new(&entry.name)) {
                            continue;
                        }

                        // Get full info for the entry
                        if let Ok(info) = self.fs.stat(entry.ino) {
                            self.fill_file_info(&info, di.file_info_mut());
                        } else {
                            // Fallback
                            di.file_info_mut().index_number = entry.ino;
                        }

                        if let Err(_) = lock.write::<255>(&mut di) {
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
                if let Err(e) = out_dir_info.set_name(OsStr::new(&name)) {
                    return Err(e.into());
                }
                self.fill_file_info(&info, out_dir_info.file_info_mut());
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

        if (flags & FSP_CLEANUP_DELETE) != 0 {
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
        _file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if let Some(_) = context {
            match self.fs.sync() {
                Ok(()) => Ok(()),
                Err(e) => Err(self.map_error(e)),
            }
        } else {
            Ok(())
        }
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

        match self.fs.set_times(context.inode, atime, mtime) {
            Ok(()) => {
                if let Ok(info) = self.fs.stat(context.inode) {
                    self.fill_file_info(&info, file_info);
                }
                Ok(())
            }
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn set_file_size(
        &self,
        context: &Self::FileContext,
        new_size: u64,
        _set_allocation_size: bool,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        match self.fs.set_size(context.inode, new_size) {
            Ok(()) => {
                if let Ok(info) = self.fs.stat(context.inode) {
                    self.fill_file_info(&info, file_info);
                }
                Ok(())
            }
            Err(e) => Err(self.map_error(e)),
        }
    }

    fn set_delete(
        &self,
        _context: &Self::FileContext,
        _file_name: &U16CStr,
        _delete_file: bool,
    ) -> winfsp::Result<()> {
        // WinFsp handles the delete flag internally.
        // We just return OK to confirm we support it.
        Ok(())
    }

    fn get_reparse_point_by_name(
        &self,
        file_name: &U16CStr,
        is_directory: bool,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        if is_directory {
            return Err(winfsp::FspError::WIN32(4390)); // ERROR_NOT_A_REPARSE_POINT
        }

        let name = file_name.to_string_lossy();
        let ino = self.fs.resolve_path(&name).map_err(|e| self.map_error(e))?;

        match self.fs.readlink(ino) {
            Ok(target) => {
                let reparse_data = create_symlink_reparse_buffer(&target);
                if buffer.len() < reparse_data.len() {
                    return Ok(reparse_data.len() as u64);
                }
                buffer[..reparse_data.len()].copy_from_slice(&reparse_data);
                Ok(reparse_data.len() as u64)
            }
            Err(_) => Err(winfsp::FspError::WIN32(4390)),
        }
    }

    fn get_reparse_point(
        &self,
        context: &Self::FileContext,
        _file_name: &U16CStr,
        buffer: &mut [u8],
    ) -> winfsp::Result<u64> {
        match self.fs.readlink(context.inode) {
            Ok(target) => {
                let reparse_data = create_symlink_reparse_buffer(&target);
                if buffer.len() < reparse_data.len() {
                    return Ok(reparse_data.len() as u64);
                }
                buffer[..reparse_data.len()].copy_from_slice(&reparse_data);
                Ok(reparse_data.len() as u64)
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

/// Create a Windows symbolic link reparse buffer from a Unix symlink target.
fn create_symlink_reparse_buffer(target: &str) -> Vec<u8> {
    const IO_REPARSE_TAG_SYMLINK: u32 = 0xA000000C;
    let mut windows_target = target.replace('/', "\\");
    while windows_target.starts_with(".\\") {
        windows_target = windows_target[2..].to_string();
    }

    let target_utf16: Vec<u16> = windows_target.encode_utf16().collect();
    let target_bytes_len = target_utf16.len() * 2;
    let is_relative = !target.starts_with('/') && !target.contains(':');
    let flags: u32 = if is_relative { 1 } else { 0 };

    let substitute_name_offset: u16 = 0;
    let substitute_name_length: u16 = target_bytes_len as u16;
    let print_name_offset: u16 = substitute_name_length;
    let print_name_length: u16 = target_bytes_len as u16;
    let path_buffer_size = (target_bytes_len * 2) as u16;
    let reparse_data_length: u16 = 12 + path_buffer_size;
    let total_size = 8 + reparse_data_length as usize;
    let mut buffer = vec![0u8; total_size];

    buffer[0..4].copy_from_slice(&IO_REPARSE_TAG_SYMLINK.to_le_bytes());
    buffer[4..6].copy_from_slice(&reparse_data_length.to_le_bytes());
    buffer[8..10].copy_from_slice(&substitute_name_offset.to_le_bytes());
    buffer[10..12].copy_from_slice(&substitute_name_length.to_le_bytes());
    buffer[12..14].copy_from_slice(&print_name_offset.to_le_bytes());
    buffer[14..16].copy_from_slice(&print_name_length.to_le_bytes());
    buffer[16..20].copy_from_slice(&flags.to_le_bytes());

    let path_start = 20;
    for (i, &ch) in target_utf16.iter().enumerate() {
        let offset = path_start + i * 2;
        buffer[offset..offset + 2].copy_from_slice(&ch.to_le_bytes());
    }

    let print_start = path_start + target_bytes_len;
    for (i, &ch) in target_utf16.iter().enumerate() {
        let offset = print_start + i * 2;
        buffer[offset..offset + 2].copy_from_slice(&ch.to_le_bytes());
    }

    buffer
}
