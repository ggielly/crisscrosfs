//! Generic VFS context and file handle for WinFsp.
//!
//! This module provides the bridge between the Windows-specific WinFsp
//! callbacks and the generic `VfsFileSystem` trait.

use std::{
    collections::VecDeque,
    ffi::{c_void, OsStr},
    future::Future,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
        Condvar,
        Mutex,
    },
    task::{Context as TaskContext, Poll, RawWaker, RawWakerVTable, Wake, Waker},
    thread::{self, JoinHandle},
};

use fs_abstraction::{
    error::{FsError, FsResult},
    types::{VfsFileInfo, VfsFileType, VfsTimestamp},
    vfs::VfsFileSystem,
};
use tracing::{debug, error, trace, warn};
use winfsp::{
    filesystem::{
        AsyncFileSystemContext,
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

pub(crate) const DEFAULT_IO_WORKERS: usize = 4;

type BlockingJob = Box<dyn FnOnce() + Send + 'static>;

thread_local! {
    /// True while a future/blocking job is executing on this pool's worker.
    /// Nested spawn_blocking calls run inline instead of queueing behind a
    /// worker that is itself blocked waiting for that job.
    static IN_POOL_WORKER: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

struct BlockingPoolState {
    queue: VecDeque<BlockingJob>,
    stopping: bool,
}

struct BlockingPoolInner {
    state: Mutex<BlockingPoolState>,
    work_available: Condvar,
    workers: Mutex<Vec<JoinHandle<()>>>,
    shutdown_started: AtomicBool,
}

/// Bounded executor for the synchronous VFS API.
///
/// WinFsp's async callbacks return STATUS_PENDING immediately. The VFS and
/// DiskReader traits are synchronous, so their work runs here rather than on a
/// WinFsp dispatcher thread. Shutdown drains accepted work before the host is
/// stopped, which keeps request buffers, file contexts, and the WinFsp object
/// alive until every response has been sent.
pub(crate) struct BlockingIoPool {
    inner: Arc<BlockingPoolInner>,
    shutdown_on_drop: bool,
}

impl Clone for BlockingIoPool {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            shutdown_on_drop: false,
        }
    }
}

impl BlockingIoPool {
    pub(crate) fn new(worker_count: usize) -> FsResult<Self> {
        let worker_count = worker_count.max(1);
        let inner = Arc::new(BlockingPoolInner {
            state: Mutex::new(BlockingPoolState {
                queue: VecDeque::new(),
                stopping: false,
            }),
            work_available: Condvar::new(),
            workers: Mutex::new(Vec::with_capacity(worker_count)),
            shutdown_started: AtomicBool::new(false),
        });
        let mut workers: Vec<JoinHandle<()>> = Vec::with_capacity(worker_count);
        for index in 0..worker_count {
            let worker_inner = inner.clone();
            let worker = thread::Builder::new()
                .name(format!("vfs-blocking-io-{index}"))
                .spawn(move || loop {
                    let job = {
                        let mut state = worker_inner
                            .state
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        while state.queue.is_empty() && !state.stopping {
                            state = worker_inner
                                .work_available
                                .wait(state)
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                        }
                        if state.stopping && state.queue.is_empty() {
                            return;
                        }
                        state.queue.pop_front()
                    };
                    let Some(job) = job else {
                        return;
                    };
                    IN_POOL_WORKER.with(|flag| flag.set(true));
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                    IN_POOL_WORKER.with(|flag| flag.set(false));
                    if let Err(payload) = result {
                        error!(
                            "Blocking VFS I/O worker panicked: {}",
                            crate::winfsp_mount::panic_text(payload.as_ref())
                        );
                    }
                });
            let worker = match worker {
                Ok(worker) => worker,
                Err(error) => {
                    inner
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .stopping = true;
                    inner.work_available.notify_all();
                    for worker in workers {
                        let _ = worker.join();
                    }
                    error!("Cannot spawn VFS I/O worker: {}", error);
                    return Err(FsError::DiskError);
                }
            };
            workers.push(worker);
        }
        *inner
            .workers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = workers;
        Ok(Self {
            inner,
            shutdown_on_drop: true,
        })
    }

    /// Queue a future. If shutdown won the race, return it to the caller so it
    /// can be polled to completion on the dispatcher thread. Our futures then
    /// observe the stopped pool and produce an error response immediately.
    fn spawn_future<F>(&self, future: F) -> std::result::Result<(), F>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.stopping {
            return Err(future);
        }
        state.queue.push_back(Box::new(move || {
            block_on(future);
        }));
        drop(state);
        self.inner.work_available.notify_one();
        Ok(())
    }

    fn spawn_blocking<T, F>(
        &self,
        operation: F,
    ) -> impl Future<Output = FsResult<T>> + Send + 'static
    where
        T: Send + 'static,
        F: FnOnce() -> FsResult<T> + Send + 'static,
    {
        let receiver = if IN_POOL_WORKER.with(|flag| flag.get()) {
            let (sender, receiver) = io_channel::<T>();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
                .unwrap_or_else(|payload| {
                    error!(
                        "VFS I/O operation panicked: {}",
                        crate::winfsp_mount::panic_text(payload.as_ref())
                    );
                    Err(FsError::DiskError)
                });
            sender.complete(result);
            Some(receiver)
        } else {
            let (sender, receiver) = io_channel::<T>();
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.stopping {
                None
            } else {
                state.queue.push_back(Box::new(move || {
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
                    let result = result.unwrap_or_else(|payload| {
                        error!(
                            "VFS I/O operation panicked: {}",
                            crate::winfsp_mount::panic_text(payload.as_ref())
                        );
                        Err(FsError::DiskError)
                    });
                    sender.complete(result);
                }));
                self.inner.work_available.notify_one();
                Some(receiver)
            }
        };
        async move {
            match receiver {
                Some(receiver) => receiver.await,
                None => Err(FsError::DiskError),
            }
        }
    }

    pub(crate) fn shutdown_and_wait(&self) {
        if self.inner.shutdown_started.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.stopping = true;
        }
        self.inner.work_available.notify_all();
        let workers = std::mem::take(
            &mut *self
                .inner
                .workers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        for worker in workers {
            let _ = worker.join();
        }
    }
}

impl Drop for BlockingIoPool {
    fn drop(&mut self) {
        if self.shutdown_on_drop {
            self.shutdown_and_wait();
        }
    }
}

struct IoChannel<T> {
    value: Mutex<Option<FsResult<T>>>,
    closed: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

struct IoChannelSender<T> {
    inner: Arc<IoChannel<T>>,
}

impl<T> IoChannelSender<T> {
    fn complete(self, value: FsResult<T>) {
        *self
            .inner
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(value);
        self.inner.closed.store(true, Ordering::Release);
        if let Some(waker) = self
            .inner
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }
}

impl<T> Drop for IoChannelSender<T> {
    fn drop(&mut self) {
        self.inner.closed.store(true, Ordering::Release);
        if let Some(waker) = self
            .inner
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            waker.wake();
        }
    }
}

struct BlockingIoReceiver<T> {
    inner: Arc<IoChannel<T>>,
}

impl<T> Future for BlockingIoReceiver<T> {
    type Output = FsResult<T>;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<Self::Output> {
        let mut waker = self
            .inner
            .waker
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.inner.closed.load(Ordering::Acquire) {
            drop(waker);
            let value = self
                .inner
                .value
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            return Poll::Ready(value.unwrap_or(Err(FsError::DiskError)));
        }
        // The sender sets `closed` before taking this same waker lock.
        // Therefore either it sees this registration and wakes us, or we
        // observe closed.
        *waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

fn io_channel<T>() -> (IoChannelSender<T>, BlockingIoReceiver<T>) {
    let inner = Arc::new(IoChannel {
        value: Mutex::new(None),
        closed: AtomicBool::new(false),
        waker: Mutex::new(None),
    });
    (
        IoChannelSender {
            inner: inner.clone(),
        },
        BlockingIoReceiver { inner },
    )
}

struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn thread_waker() -> Waker {
    fn clone(raw: *const ()) -> RawWaker {
        unsafe {
            Arc::increment_strong_count(raw as *const ThreadWake);
        }
        RawWaker::new(raw, &WAKER_VTABLE)
    }
    fn wake(raw: *const ()) {
        let waker = unsafe { Arc::from_raw(raw as *const ThreadWake) };
        waker.0.unpark();
    }
    fn wake_by_ref(raw: *const ()) {
        // SAFETY: the raw waker owns one Arc reference for its lifetime.
        let waker = unsafe { &*(raw as *const ThreadWake) };
        waker.0.unpark();
    }
    fn drop_waker(raw: *const ()) {
        // SAFETY: this consumes exactly the reference created by
        // clone/from_raw.
        drop(unsafe { Arc::from_raw(raw as *const ThreadWake) });
    }
    const WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake_by_ref, drop_waker);

    let waker = Arc::new(ThreadWake(thread::current()));
    unsafe {
        Waker::from_raw(RawWaker::new(
            Arc::into_raw(waker) as *const (),
            &WAKER_VTABLE,
        ))
    }
}

/// Minimal block_on for the pool's own channel futures. It is not a general
/// executor: waking always unparks the thread currently running this function.
pub(crate) fn block_on<F: Future>(future: F) -> F::Output {
    let waker = thread_waker();
    let mut context = TaskContext::from_waker(&waker);
    let mut future = std::pin::pin!(future);
    loop {
        match future.as_mut().poll(&mut context) {
            Poll::Ready(output) => return output,
            Poll::Pending => thread::park(),
        }
    }
}

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
    /// Parent inode and name captured at open/create and updated by rename.
    /// Keeping this in the handle avoids re-resolving a mutable parent path.
    identity: Mutex<Option<(u64, String)>>,
}

impl VfsFileHandle {
    /// Create a new file handle.
    pub fn new(inode: u64, is_directory: bool) -> Self {
        Self {
            inode,
            is_directory,
            dir_buffer: DirBuffer::new(),
            identity: Mutex::new(None),
        }
    }

    pub fn with_identity(inode: u64, is_directory: bool, parent: u64, name: String) -> Self {
        Self {
            identity: Mutex::new(Some((parent, name))),
            ..Self::new(inode, is_directory)
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
    /// Number of delete-on-close unlink attempts that failed.
    cleanup_unlink_failures: AtomicU64,
    /// POSIX mode/uid/gid → Windows security descriptor mapper.
    acl_mapper: AclMapper,
    /// Bounded workers used by WinFsp's asynchronous pending responses.
    io_pool: BlockingIoPool,
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
        Self::with_io_pool(
            fs,
            volume_label,
            mount_root,
            AclMapper::new(read_only),
            BlockingIoPool::new(DEFAULT_IO_WORKERS)?,
        )
    }

    /// Create a context with an explicitly configured ACL mapper (primarily
    /// useful for tests and embedders).
    pub fn with_acl_mapper(
        fs: Arc<dyn VfsFileSystem>,
        volume_label: String,
        mount_root: String,
        acl_mapper: AclMapper,
    ) -> FsResult<Self> {
        Self::with_io_pool(
            fs,
            volume_label,
            mount_root,
            acl_mapper,
            BlockingIoPool::new(DEFAULT_IO_WORKERS)?,
        )
    }

    pub(crate) fn with_io_pool(
        fs: Arc<dyn VfsFileSystem>,
        volume_label: String,
        mount_root: String,
        acl_mapper: AclMapper,
        io_pool: BlockingIoPool,
    ) -> FsResult<Self> {
        let read_only = fs.capabilities().read_only;
        Ok(Self {
            fs,
            volume_label,
            mount_root: normalize_mount_root(&mount_root)?,
            read_only,
            cleanup_unlink_failures: AtomicU64::new(0),
            acl_mapper,
            io_pool,
        })
    }

    /// Number of cleanup delete operations that could not be unlinked.
    ///
    /// WinFsp's cleanup callback cannot return an error to the caller, so this
    /// counter records failures that are also emitted through
    /// `tracing::error!`.
    pub fn cleanup_unlink_failures(&self) -> u64 {
        self.cleanup_unlink_failures.load(Ordering::Relaxed)
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

        let ino = self
            .fs
            .resolve_path_wide(file_name.as_slice())
            .map_err(|e| self.map_error(e))?;
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
        let entry_name = file_name_wide(file_name.as_slice());
        let parent_ino = self
            .fs
            .resolve_path_wide(parent_path_wide(file_name.as_slice()))
            .map_err(|e| self.map_error(e))?;
        match self.fs.resolve_path_wide(file_name.as_slice()) {
            Ok(ino) => {
                debug!("open resolved '{}' to ino {}", name, ino);
                match self.fs.stat(ino) {
                    Ok(info) => {
                        self.fill_file_info(&info, file_info.as_mut())?;
                        self.fs.pin_inode(ino).map_err(|e| self.map_error(e))?;
                        Ok(VfsFileHandle::with_identity(
                            ino,
                            info.is_dir(),
                            parent_ino,
                            entry_name,
                        ))
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

    fn close(&self, context: Self::FileContext) {
        // Writable backends may retain delalloc data until flush_file. Close
        // cannot return an error to WinFsp, so surface durability failures in
        // logs before releasing the inode pin. A delete-on-close unlink may
        // intentionally discard those pending writes; its flush can therefore
        // report that the inode is already gone.
        if let Err(error) = self.fs.flush_file(context.inode) {
            error!(
                inode = context.inode,
                %error,
                "flush_file failed during close"
            );
        }
        self.fs.unpin_inode(context.inode);
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
        let result = if write_to_eof {
            // Append must select the offset and write under one backend lock;
            // stat(size) followed by write(offset) loses concurrent appends.
            self.fs.append_with_info(context.inode, buffer)
        } else {
            self.fs.write_with_info(context.inode, offset, buffer)
        };

        match result {
            Ok((bytes_written, info)) => {
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
        let entry_name = file_name_wide(file_name.as_slice());

        let parent_ino = self
            .fs
            .resolve_path_wide(parent_path_wide(file_name.as_slice()))
            .map_err(|e| {
                error!("create resolve_path failed for '{}': {:?}", name, e);
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
                self.fs.pin_inode(info.ino).map_err(|e| self.map_error(e))?;
                Ok(VfsFileHandle::with_identity(
                    info.ino,
                    info.is_dir(),
                    parent_ino,
                    entry_name,
                ))
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
        context: &Self::FileContext,
        file_name: &winfsp::U16CStr,
        new_file_name: &winfsp::U16CStr,
        replace_if_exists: bool,
    ) -> winfsp::Result<()> {
        self.reject_if_read_only()?;
        let new_name = file_name_wide(new_file_name.as_slice());
        let new_parent = self
            .fs
            .resolve_path_wide(parent_path_wide(new_file_name.as_slice()))
            .map_err(|e| self.map_error(e))?;

        // Serialize identity updates with cleanup on this handle. The source
        // parent/name cannot change underneath a delete-on-close operation.
        let mut identity = context
            .identity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (old_parent, old_name) = if let Some((parent, name)) = identity.as_ref() {
            (*parent, name.clone())
        } else {
            let old_name = file_name_wide(file_name.as_slice());
            let parent = self
                .fs
                .resolve_path_wide(parent_path_wide(file_name.as_slice()))
                .map_err(|e| self.map_error(e))?;
            (parent, old_name)
        };

        let vfs_flags = fs_abstraction::types::RenameFlags {
            replace_if_exists,
            ..Default::default()
        };
        self.fs
            .rename(old_parent, &old_name, new_parent, &new_name, vfs_flags)
            .map_err(|e| self.map_error(e))?;
        *identity = Some((new_parent, new_name));
        Ok(())
    }

    fn read_directory(
        &self,
        context: &Self::FileContext,
        pattern: Option<&U16CStr>,
        marker: DirMarker<'_>,
        buffer: &mut [u8],
    ) -> winfsp::Result<u32> {
        if !context.is_directory {
            return Err(winfsp::FspError::WIN32(267)); // ERROR_DIRECTORY
        }

        let reset = marker.is_none();
        let lock = context.dir_buffer.acquire(reset, None)?;

        if reset {
            let entries = self
                .fs
                .readdir(context.inode)
                .map_err(|e| self.map_error(e))?;
            // Batch metadata loading by inode buffer and avoid one VFS call per
            // entry. Filter first so non-matching names cause no inode I/O.
            'fill: for chunk in entries.chunks(256) {
                let mut candidates = Vec::with_capacity(chunk.len());
                for entry in chunk {
                    let wide: Vec<u16> = entry.name.encode_utf16().collect();
                    if !pattern.is_none_or(|pattern| {
                        windows_name_matches(&wide, pattern, self.fs.is_case_insensitive_lookup())
                    }) {
                        continue;
                    }
                    let mut di = DirInfo::new();
                    if di.set_name(OsStr::new(&entry.name)).is_err() {
                        continue;
                    }
                    candidates.push((entry, di));
                }

                let inos: Vec<u64> = candidates.iter().map(|(entry, _)| entry.ino).collect();
                let metadata = self.fs.stat_many(&inos);
                for ((entry, mut di), info) in candidates.into_iter().zip(metadata) {
                    let info = match info {
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
                        break 'fill;
                    }
                }
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
        match self.fs.lookup_wide(context.inode, file_name.as_slice()) {
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
            // Unlink is deliberately before close/flush_file: deleting an open
            // file is allowed to discard its pending delalloc writes. Ordinary
            // close still flushes before unpinning below.
            let Some(name) = file_name else {
                self.cleanup_unlink_failures.fetch_add(1, Ordering::Relaxed);
                error!(
                    inode = context.inode,
                    "cleanup delete requested without a file name"
                );
                return;
            };

            let path = name.to_string_lossy();
            let identity = match context.identity.lock() {
                Ok(identity) => identity,
                Err(_) => {
                    self.cleanup_unlink_failures.fetch_add(1, Ordering::Relaxed);
                    error!(path = %path, inode = context.inode, "cleanup identity lock poisoned");
                    return;
                }
            };
            let unlink_result = if let Some((parent_ino, entry_name)) = identity.as_ref() {
                self.fs.unlink(*parent_ino, entry_name, context.inode)
            } else {
                let entry_name = file_name_wide(name.as_slice());
                self.fs
                    .resolve_path_wide(parent_path_wide(name.as_slice()))
                    .and_then(|parent_ino| self.fs.unlink(parent_ino, &entry_name, context.inode))
            };

            if let Err(error) = unlink_result {
                self.cleanup_unlink_failures.fetch_add(1, Ordering::Relaxed);
                error!(
                    path = %path,
                    inode = context.inode,
                    %error,
                    "cleanup unlink failed"
                );
            }
        }
    }

    fn flush(
        &self,
        context: Option<&Self::FileContext>,
        file_info: &mut FileInfo,
    ) -> winfsp::Result<()> {
        if let Some(context) = context {
            self.fs
                .flush_file(context.inode)
                .map_err(|e| self.map_error(e))?;
            let info = self.fs.stat(context.inode).map_err(|e| self.map_error(e))?;
            self.fill_file_info(&info, file_info)?;
        } else {
            self.fs.sync().map_err(|e| self.map_error(e))?;
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
        let ino = self
            .fs
            .resolve_path_wide(file_name.as_slice())
            .map_err(|e| self.map_error(e))?;

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

impl AsyncFileSystemContext for VfsContext {
    fn read_async(
        &self,
        context: &Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> impl Future<Output = winfsp::Result<u32>> + Send {
        let inode = context.inode;
        let len = buffer.len();
        let fs = self.fs.clone();
        let pool = self.io_pool.clone();
        async move {
            if len == 0 {
                return Ok(0);
            }
            // The worker owns its storage. The WinFsp request buffer is only
            // touched after the worker completes, while the adapter future
            // still owns the request-scoped borrow.
            let mut owned = vec![0u8; len];
            let result = pool
                .spawn_blocking(move || {
                    let count = fs.read(inode, offset, &mut owned)?;
                    Ok((count, owned))
                })
                .await;
            let (count, owned) = result.map_err(|error| self.map_error(error))?;
            let bytes = read_byte_count(Ok(count), len).map_err(|error| self.map_error(error))?;
            buffer[..bytes as usize].copy_from_slice(&owned[..bytes as usize]);
            Ok(bytes)
        }
    }

    fn write_async(
        &self,
        context: &Self::FileContext,
        buffer: &[u8],
        offset: u64,
        write_to_eof: bool,
        constrained_io: bool,
        file_info: &mut FileInfo,
    ) -> impl Future<Output = winfsp::Result<u32>> + Send {
        let inode = context.inode;
        let data = buffer.to_vec();
        let data_len = data.len();
        let fs = self.fs.clone();
        let pool = self.io_pool.clone();
        let read_only = self.read_only;
        async move {
            if read_only {
                return Err(self.map_error(FsError::ReadOnly));
            }
            let result = pool
                .spawn_blocking(move || {
                    if write_to_eof {
                        fs.append_with_info(inode, &data)
                    } else {
                        fs.write_with_info(inode, offset, &data)
                    }
                })
                .await;
            let (bytes_written, info) = result.map_err(|error| self.map_error(error))?;
            self.fill_file_info(&info, file_info)?;
            let bytes_written = u32::try_from(bytes_written)
                .map_err(|_| self.map_error(FsError::ArithmeticOverflow))?;
            if bytes_written as usize > data_len {
                return Err(self.map_error(FsError::SecurityViolation));
            }
            let _ = constrained_io; // WinFsp already enforces transfer limits.
            Ok(bytes_written)
        }
    }

    fn spawn_task(&self, future: impl Future<Output = ()> + Send + 'static) {
        if let Err(future) = self.io_pool.spawn_future(future) {
            // Shutdown may race a final dispatcher callback. Polling the
            // rejected future is non-blocking here: its pool operation returns
            // a shutdown error and the WinFsp adapter still sends a response.
            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| block_on(future))).is_err()
            {
                error!("Pending WinFsp response task panicked during shutdown");
            }
        }
    }
}

/// Split a path into parent directory and filename.
/// Case-sensitive Windows query-directory wildcard matching over UTF-16.
/// `*` and `?` operate on UTF-16 code units, as they do in Win32 file names.
fn windows_name_matches(name: &[u16], pattern: &U16CStr, case_insensitive: bool) -> bool {
    pattern
        .as_slice()
        .split(|&unit| unit == b';' as u16)
        .any(|pattern| wildcard_matches_impl(name, pattern, case_insensitive))
}

#[cfg(test)]
fn wildcard_matches(name: &[u16], pattern: &[u16]) -> bool {
    wildcard_matches_impl(name, pattern, false)
}

fn wildcard_matches_impl(name: &[u16], pattern: &[u16], case_insensitive: bool) -> bool {
    // DOS/XFS compatibility: Windows treats the legacy "*.*" expression as
    // "all names", including names without an extension.
    if pattern == [b'*' as u16, b'.' as u16, b'*' as u16] {
        return true;
    }
    let (mut ni, mut pi) = (0, 0);
    let mut star = None;
    let mut star_match = 0;
    while ni < name.len() {
        if pi < pattern.len()
            && (pattern[pi] == b'?' as u16
                || if case_insensitive {
                    let left = char::from_u32(u32::from(pattern[pi]));
                    let right = char::from_u32(u32::from(name[ni]));
                    match (left, right) {
                        (Some(left), Some(right)) => {
                            let mut left_bytes = [0u8; 4];
                            let mut right_bytes = [0u8; 4];
                            unicase::eq(
                                left.encode_utf8(&mut left_bytes),
                                right.encode_utf8(&mut right_bytes),
                            )
                        }
                        _ => pattern[pi] == name[ni],
                    }
                } else {
                    pattern[pi] == name[ni]
                })
        {
            ni += 1;
            pi += 1;
        } else if pi < pattern.len() && pattern[pi] == b'*' as u16 {
            star = Some(pi);
            pi += 1;
            star_match = ni;
        } else if let Some(star) = star {
            star_match += 1;
            ni = star_match;
            pi = star + 1;
        } else {
            return false;
        }
    }
    while pi < pattern.len() && pattern[pi] == b'*' as u16 {
        pi += 1;
    }
    pi == pattern.len()
}

fn last_separator(path: &[u16]) -> Option<usize> {
    path.iter()
        .rposition(|&unit| unit == b'\\' as u16 || unit == b'/' as u16)
}

fn parent_path_wide(path: &[u16]) -> &[u16] {
    last_separator(path).map_or(&[], |index| &path[..index])
}

fn file_name_wide(path: &[u16]) -> String {
    let start = last_separator(path).map_or(0, |index| index + 1);
    String::from_utf16_lossy(&path[start..])
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
        // The inode number is the stable file ID; expose XFS nlink so tools
        // that understand hard links do not treat every path as a lone link.
        hard_links: info.nlink,
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

    #[test]
    fn directory_pattern_matching_is_case_sensitive_and_handles_wildcards() {
        let name: Vec<u16> = "ReadMe.TXT".encode_utf16().collect();
        assert!(wildcard_matches(
            &name,
            &"*.TXT".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(!wildcard_matches(
            &name,
            &"*.txt".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(wildcard_matches(
            &name,
            &"Read?e.*".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(wildcard_matches(
            &name,
            &"*.*".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(wildcard_matches(
            &"noextension".encode_utf16().collect::<Vec<_>>(),
            &"*.*".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(!wildcard_matches(
            &name,
            &"Other*.TXT".encode_utf16().collect::<Vec<_>>()
        ));
        assert!(wildcard_matches_impl(
            &name,
            &"read*.txt".encode_utf16().collect::<Vec<_>>(),
            true
        ));
    }

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
            posix_acl: None,
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
    fn file_info_uses_checked_sizes_inode_id_and_hard_link_count() {
        let info = file_info_from_vfs(&file_info(VfsFileType::RegularFile), true).unwrap();
        assert_eq!(info.allocation_size, 3 * 512);
        assert_eq!(info.file_size, 1234);
        assert_eq!(info.hard_links, 7);
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
        resolve_error: Option<FsError>,
        unlink_error: Option<FsError>,
        resolves: std::sync::atomic::AtomicUsize,
        unlinks: std::sync::atomic::AtomicUsize,
        syncs: std::sync::atomic::AtomicUsize,
        reads: std::sync::atomic::AtomicUsize,
        writes: std::sync::atomic::AtomicUsize,
        appends: std::sync::atomic::AtomicUsize,
        flushes: std::sync::atomic::AtomicUsize,
        flush_error: Option<FsError>,
        events: Mutex<Vec<&'static str>>,
        read_data: Option<Vec<u8>>,
        read_gate: Option<Arc<(Mutex<bool>, Condvar)>>,
        read_finished: Option<Arc<std::sync::atomic::AtomicUsize>>,
    }

    impl TestFs {
        fn new(file_type: VfsFileType) -> Self {
            Self {
                info: file_info(file_type),
                // Deliberately writable: the mount policy must still force RO.
                capabilities: fs_abstraction::FsCapabilities::writable_linux(),
                resolve_error: None,
                unlink_error: None,
                resolves: Default::default(),
                unlinks: Default::default(),
                syncs: Default::default(),
                reads: Default::default(),
                writes: Default::default(),
                appends: Default::default(),
                flushes: Default::default(),
                flush_error: None,
                events: Default::default(),
                read_data: None,
                read_gate: None,
                read_finished: None,
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

        fn flush_file(&self, _ino: u64) -> FsResult<()> {
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push("flush");
            self.flush_error.map_or(Ok(()), Err)
        }

        fn unpin_inode(&self, _ino: u64) {
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push("unpin");
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
            self.resolve_error.map_or(Ok(self.info.ino), Err)
        }

        fn unlink(&self, _parent_ino: u64, _name: &str, _target_ino: u64) -> FsResult<()> {
            self.unlinks
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.events
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push("unlink");
            self.unlink_error.map_or(Ok(()), Err)
        }

        fn read(&self, _ino: u64, _offset: u64, buf: &mut [u8]) -> FsResult<usize> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if let Some(gate) = &self.read_gate {
                let mut open = gate
                    .0
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                while !*open {
                    open = gate
                        .1
                        .wait(open)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            }
            let result = self
                .read_data
                .as_ref()
                .map_or(Err(FsError::EndOfFile), |data| {
                    let count = buf.len().min(data.len());
                    buf[..count].copy_from_slice(&data[..count]);
                    Ok(count)
                });
            if let Some(finished) = &self.read_finished {
                finished.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            result
        }

        fn write(&self, _ino: u64, _offset: u64, data: &[u8]) -> FsResult<usize> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(data.len())
        }

        fn append_with_info(&self, ino: u64, data: &[u8]) -> FsResult<(usize, VfsFileInfo)> {
            self.appends
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok((data.len(), self.stat(ino)?))
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
    fn blocking_pool_is_bounded_and_drains_accepted_work() {
        use std::{sync::atomic::AtomicUsize, time::Duration};

        let pool = BlockingIoPool::new(2).unwrap();
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let mut receivers = Vec::new();
        for index in 0..24 {
            let active = active.clone();
            let maximum = maximum.clone();
            receivers.push(pool.spawn_blocking(move || {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(2));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(index)
            }));
        }
        pool.shutdown_and_wait();
        for (index, receiver) in receivers.into_iter().enumerate() {
            assert_eq!(block_on(receiver).unwrap(), index);
        }
        assert!(maximum.load(Ordering::SeqCst) <= 2);
        assert!(block_on(pool.spawn_blocking(|| Ok(()))).is_err());
    }

    #[test]
    fn nested_blocking_jobs_on_a_single_worker_do_not_deadlock() {
        let pool = BlockingIoPool::new(1).unwrap();
        let nested_pool = pool.clone();
        let outer = pool
            .spawn_blocking(move || block_on(nested_pool.spawn_blocking(|| Ok::<_, FsError>(42))));
        assert_eq!(block_on(outer), Ok(42));
    }

    #[test]
    fn blocking_pool_converts_worker_panics_into_completed_errors() {
        let pool = BlockingIoPool::new(1).unwrap();
        let operation =
            pool.spawn_blocking(|| -> FsResult<()> { panic!("intentional worker panic") });
        assert_eq!(block_on(operation), Err(FsError::DiskError));
    }

    #[test]
    fn rejected_shutdown_future_can_be_polled_to_completion() {
        let pool = BlockingIoPool::new(1).unwrap();
        pool.shutdown_and_wait();
        let pool_for_future = pool.clone();
        let future = async move {
            assert!(block_on(pool_for_future.spawn_blocking(|| Ok(()))).is_err());
        };
        let future = pool.spawn_future(future).unwrap_err();
        block_on(future);
    }

    #[test]
    fn dropping_async_read_future_never_touches_the_request_buffer() {
        use std::{pin::pin, task::Poll, time::Duration};

        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let finished = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let fs = Arc::new(TestFs {
            read_data: Some(vec![1, 2, 3, 4]),
            read_gate: Some(gate.clone()),
            read_finished: Some(finished.clone()),
            ..TestFs::new(VfsFileType::RegularFile)
        });
        let context = VfsContext::new(fs, "Test".to_string(), "X:".to_string()).unwrap();
        let handle = VfsFileHandle::new(42, false);
        let waker = thread_waker();
        let mut task_context = TaskContext::from_waker(&waker);
        let mut request_buffer = [0xCC; 4];
        {
            let mut future = pin!(AsyncFileSystemContext::read_async(
                &context,
                &handle,
                &mut request_buffer,
                0,
            ));
            assert!(matches!(
                future.as_mut().poll(&mut task_context),
                Poll::Pending
            ));
            // Dropping the future abandons only the receiver. The worker owns
            // a separate Vec and cannot alias or write the WinFsp buffer.
        }
        assert_eq!(request_buffer, [0xCC; 4]);
        *gate
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        gate.1.notify_all();
        for _ in 0..1_000 {
            if finished.load(Ordering::SeqCst) == 1 {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(finished.load(Ordering::SeqCst), 1);
        assert_eq!(request_buffer, [0xCC; 4]);
    }

    #[test]
    fn write_to_eof_uses_atomic_backend_append() {
        let fs = Arc::new(TestFs::new(VfsFileType::RegularFile));
        let context = VfsContext::new(fs.clone(), "Test".to_string(), "X:".to_string()).unwrap();
        let handle = VfsFileHandle::new(fs.info.ino, false);
        let mut info = FileInfo::default();
        assert_eq!(
            FileSystemContext::write(&context, &handle, b"append", 99, true, false, &mut info)
                .unwrap(),
            6
        );
        assert_eq!(fs.appends.load(Ordering::SeqCst), 1);
        assert_eq!(fs.writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn close_flushes_before_unpin_and_logs_without_returning_errors() {
        for flush_error in [None, Some(FsError::PermissionDenied)] {
            let fs = Arc::new(TestFs {
                flush_error,
                ..TestFs::new(VfsFileType::RegularFile)
            });
            let context =
                VfsContext::new(fs.clone(), "Test".to_string(), "X:".to_string()).unwrap();
            FileSystemContext::close(&context, VfsFileHandle::new(fs.info.ino, false));
            assert_eq!(fs.flushes.load(Ordering::SeqCst), 1);
            assert_eq!(*fs.events.lock().unwrap(), ["flush", "unpin"]);
        }
    }

    #[test]
    fn delete_cleanup_unlinks_before_the_close_flush() {
        use winfsp::U16CString;

        let fs = Arc::new(TestFs::new(VfsFileType::RegularFile));
        let context = VfsContext::new(fs.clone(), "Test".to_string(), "X:".to_string()).unwrap();
        let handle = VfsFileHandle::new(fs.info.ino, false);
        let name = U16CString::from_str("\\file").unwrap();
        FileSystemContext::cleanup(&context, &handle, Some(&name), 0x01);
        FileSystemContext::close(&context, handle);
        assert_eq!(*fs.events.lock().unwrap(), ["unlink", "flush", "unpin"]);
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

    #[test]
    fn cleanup_counts_unlink_failures_across_dispatcher_threads() {
        use winfsp::U16CString;

        const FSP_CLEANUP_DELETE: u32 = 0x01;
        const THREADS: usize = 4;
        const ATTEMPTS_PER_THREAD: usize = 25;

        let fs = Arc::new(TestFs {
            unlink_error: Some(FsError::PermissionDenied),
            ..TestFs::new(VfsFileType::RegularFile)
        });
        let context = VfsContext::new(fs.clone(), "Test".to_string(), "X:".to_string()).unwrap();
        let handle = VfsFileHandle::new(fs.info.ino, false);
        let name = U16CString::from_str("\\file.txt").unwrap();

        std::thread::scope(|scope| {
            for _ in 0..THREADS {
                scope.spawn(|| {
                    for _ in 0..ATTEMPTS_PER_THREAD {
                        FileSystemContext::cleanup(
                            &context,
                            &handle,
                            Some(&name),
                            FSP_CLEANUP_DELETE,
                        );
                    }
                });
            }
        });

        assert_eq!(
            fs.unlinks.load(std::sync::atomic::Ordering::SeqCst),
            THREADS * ATTEMPTS_PER_THREAD
        );
        assert_eq!(
            context.cleanup_unlink_failures(),
            (THREADS * ATTEMPTS_PER_THREAD) as u64
        );
    }

    #[test]
    fn cleanup_counts_parent_resolution_and_missing_name_failures() {
        use winfsp::U16CString;

        const FSP_CLEANUP_DELETE: u32 = 0x01;
        let fs = Arc::new(TestFs {
            resolve_error: Some(FsError::NotFound),
            ..TestFs::new(VfsFileType::RegularFile)
        });
        let context = VfsContext::new(fs.clone(), "Test".to_string(), "X:".to_string()).unwrap();
        let handle = VfsFileHandle::new(fs.info.ino, false);
        let name = U16CString::from_str("\\file.txt").unwrap();

        FileSystemContext::cleanup(&context, &handle, Some(&name), FSP_CLEANUP_DELETE);
        FileSystemContext::cleanup(&context, &handle, None, FSP_CLEANUP_DELETE);

        assert_eq!(fs.unlinks.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(context.cleanup_unlink_failures(), 2);
    }
}
