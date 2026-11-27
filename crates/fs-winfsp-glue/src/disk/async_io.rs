//! Windows overlapped disk I/O.
//!
//! Each file handle owns an IOCP and every in-flight ReadFile/WriteFile owns a
//! separately allocated OVERLAPPED. A request may be cancelled or dropped only
//! after its completion packet has been retrieved, so Windows never retains a
//! pointer into freed request or buffer storage.

use std::{
    cell::UnsafeCell,
    collections::HashMap,
    fs::File,
    io,
    os::windows::io::IntoRawHandle,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
        Condvar,
        Mutex,
    },
};

use windows::{
    core::{Error, HRESULT},
    Win32::{
        Foundation::{
            CloseHandle,
            ERROR_HANDLE_EOF,
            ERROR_IO_PENDING,
            ERROR_NOT_FOUND,
            ERROR_OPERATION_ABORTED,
            HANDLE,
            WAIT_TIMEOUT,
        },
        Storage::FileSystem::{FlushFileBuffers, GetFileSizeEx, ReadFile, WriteFile},
        System::IO::{
            CancelIoEx,
            CreateIoCompletionPort,
            GetOverlappedResult,
            GetQueuedCompletionStatus,
            OVERLAPPED,
        },
    },
};

use super::{validate_raw_io_args, Result, XfsWinfspError};

const COMPLETION_POLL_MS: u32 = 10;

fn io_error(error: Error) -> io::Error {
    if error.code() == HRESULT::from_win32(ERROR_OPERATION_ABORTED.0) {
        io::Error::new(io::ErrorKind::Interrupted, error)
    } else {
        io::Error::other(error)
    }
}

fn io_error_from_status(status: i32) -> io::Error {
    io_error(Error::from(HRESULT(status)))
}

fn operation_aborted() -> XfsWinfspError {
    XfsWinfspError::IoError(io::Error::new(
        io::ErrorKind::Interrupted,
        Error::from(HRESULT::from_win32(ERROR_OPERATION_ABORTED.0)),
    ))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IoKind {
    Read,
    Write,
}

struct Completion {
    transferred: u32,
    /// Zero on success, otherwise a Win32 HRESULT from GetOverlappedResult.
    status: i32,
}

struct OperationState {
    // Windows writes the OVERLAPPED while the operation is pending. Rust never
    // reads or writes these fields until the completion packet is retrieved.
    overlapped: UnsafeCell<OVERLAPPED>,
    completion: Mutex<Option<Completion>>,
    completed: Condvar,
}

// SAFETY: each state is used by exactly one outstanding OS operation.
// Completion metadata is separately synchronized and the OVERLAPPED allocation
// remains stable and registered until its packet has been retrieved.
unsafe impl Send for OperationState {}
unsafe impl Sync for OperationState {}

impl OperationState {
    fn new(offset: u64) -> Self {
        let mut overlapped = OVERLAPPED::default();
        // The default initialized the union and this writes its offset arm.
        overlapped.Anonymous.Anonymous.Offset = offset as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        Self {
            overlapped: UnsafeCell::new(overlapped),
            completion: Mutex::new(None),
            completed: Condvar::new(),
        }
    }

    fn overlapped(&self) -> *mut OVERLAPPED {
        self.overlapped.get()
    }

    fn complete(&self, completion: Completion) {
        *self
            .completion
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(completion);
        self.completed.notify_all();
    }

    fn completion(&self) -> Option<Completion> {
        self.completion
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }
}

struct OverlappedFileInner {
    file: HANDLE,
    iocp: HANDLE,
    size: u64,
    pending: Mutex<HashMap<usize, Arc<OperationState>>>,
}

// SAFETY: the Win32 handles are closed only after every Arc clone is gone.
// OVERLAPPED instances are never shared between outstanding OS operations and
// the registry is mutex-protected.
unsafe impl Send for OverlappedFileInner {}
unsafe impl Sync for OverlappedFileInner {}

impl Drop for OverlappedFileInner {
    fn drop(&mut self) {
        // PendingIo and IoCancellation keep this Arc alive until their packet
        // has been consumed, so the registry must be empty at this point.
        debug_assert!(
            self.pending
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_empty(),
            "overlapped file dropped with registered I/O"
        );
        unsafe {
            let _ = CloseHandle(self.file);
            let _ = CloseHandle(self.iocp);
        }
    }
}

/// A Windows file handle opened with FILE_FLAG_OVERLAPPED and associated with
/// its own I/O completion port.
#[derive(Clone)]
pub(crate) struct OverlappedFile {
    inner: Arc<OverlappedFileInner>,
}

impl OverlappedFile {
    /// Take ownership of a handle. On IOCP association failure the handle is
    /// closed here, so callers must not close it again.
    pub(crate) fn from_raw(file: HANDLE) -> Result<Self> {
        let iocp = match unsafe { CreateIoCompletionPort(file, None, 0, 0) } {
            Ok(iocp) => iocp,
            Err(error) => {
                unsafe {
                    let _ = CloseHandle(file);
                }
                return Err(XfsWinfspError::IoError(io_error(error)));
            }
        };
        let mut size = 0i64;
        let size = if unsafe { GetFileSizeEx(file, &mut size) }.is_ok() && size >= 0 {
            size as u64
        } else {
            0
        };
        Ok(Self {
            inner: Arc::new(OverlappedFileInner {
                file,
                iocp,
                size,
                pending: Mutex::new(HashMap::new()),
            }),
        })
    }

    pub(crate) fn from_file(file: File) -> Result<Self> {
        let file = HANDLE(file.into_raw_handle());
        Self::from_raw(file)
    }

    pub(crate) fn handle(&self) -> HANDLE {
        self.inner.file
    }

    pub(crate) fn read_at(&self, offset: u64, len: usize) -> Result<PendingIo> {
        validate_raw_io_args(offset, len)?;
        let len = if self.inner.size == 0 {
            len
        } else {
            usize::try_from(
                self.inner
                    .size
                    .saturating_sub(offset)
                    .min(u64::try_from(len).unwrap_or(u64::MAX)),
            )
            .map_err(|_| {
                XfsWinfspError::InvalidArgument("Read size does not fit usize".to_string())
            })?
        };
        PendingIo::start(IoKind::Read, self.inner.clone(), offset, vec![0; len])
    }

    pub(crate) fn write_at(&self, offset: u64, data: &[u8]) -> Result<PendingIo> {
        validate_raw_io_args(offset, data.len())?;
        PendingIo::start(IoKind::Write, self.inner.clone(), offset, data.to_vec())
    }

    /// Synchronous compatibility path for DiskReader/DiskWriter. The operation
    /// is still queued through the IOCP; this method merely waits for it.
    pub(crate) fn read_sync(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let output = self.read_at(offset, buffer.len())?.wait()?;
        let count = output.len();
        buffer[..count].copy_from_slice(&output);
        Ok(count)
    }

    pub(crate) fn write_sync(&self, offset: u64, data: &[u8]) -> Result<usize> {
        Ok(self.write_at(offset, data)?.wait()?.len())
    }

    pub(crate) fn flush(&self) -> Result<()> {
        unsafe { FlushFileBuffers(self.inner.file) }
            .map_err(|error| XfsWinfspError::IoError(io_error(error)))
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    fn register(&self, state: &Arc<OperationState>) {
        let key = state.overlapped() as usize;
        let old = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, state.clone());
        debug_assert!(old.is_none(), "OVERLAPPED address was reused while pending");
    }

    fn unregister(&self, state: &OperationState) {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&(state.overlapped() as usize));
    }

    fn process_completion(&self, overlapped: *mut OVERLAPPED, fallback_bytes: u32) {
        if overlapped.is_null() {
            return;
        }
        let key = overlapped as usize;
        let state = self
            .inner
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key);
        let Some(state) = state else {
            // A null/unknown packet cannot be dereferenced. No request in this
            // module unregisters before consuming its packet, so this indicates
            // a foreign completion source rather than an owned operation.
            return;
        };

        let mut transferred = 0u32;
        let status =
            unsafe { GetOverlappedResult(self.inner.file, overlapped, &mut transferred, false) }
                .err()
                .map_or(0, |error| error.code().0);
        if transferred == 0 {
            // GetOverlappedResult may leave the output count untouched on an
            // EOF/error completion; GQCS still supplies the transferred count.
            transferred = fallback_bytes;
        }
        state.complete(Completion {
            transferred,
            status,
        });
    }

    fn wait_for(&self, state: &Arc<OperationState>) -> Result<Completion> {
        loop {
            if let Some(completion) = state.completion() {
                return Ok(completion);
            }

            let mut transferred = 0u32;
            let mut key = 0usize;
            let mut overlapped = std::ptr::null_mut();
            let queued = unsafe {
                GetQueuedCompletionStatus(
                    self.inner.iocp,
                    &mut transferred,
                    &mut key,
                    &mut overlapped,
                    COMPLETION_POLL_MS,
                )
            };
            match queued {
                Ok(()) => self.process_completion(overlapped, transferred),
                Err(error) if error.code() == HRESULT::from_win32(WAIT_TIMEOUT.0) => {
                    if let Some(completion) = state.completion() {
                        return Ok(completion);
                    }
                    let completion = state
                        .completion
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let _ = state
                        .completed
                        .wait_timeout(completion, std::time::Duration::from_millis(10));
                }
                Err(_error) if !overlapped.is_null() => {
                    // Some drivers surface the I/O status from GQCS itself but
                    // still provide the completed OVERLAPPED. Consume it so no
                    // registry entry or packet outlives the request.
                    self.process_completion(overlapped, transferred);
                }
                Err(error) => return Err(XfsWinfspError::IoError(io_error(error))),
            }
        }
    }
}

#[derive(Debug)]
enum SubmissionOutcome {
    /// ReadFile/WriteFile returned ERROR_IO_PENDING or immediate success. In
    /// both cases an IOCP completion packet must be retrieved.
    WaitForPacket,
    /// A synchronous error/EOF does not post a packet.
    Immediate(Result<u32>),
}

struct SubmittedChunk {
    state: Arc<OperationState>,
    outcome: Mutex<Option<SubmissionOutcome>>,
}

struct PendingIoState {
    engine: Arc<OverlappedFileInner>,
    kind: IoKind,
    offset: u64,
    buffer: Mutex<Vec<u8>>,
    submitted: Mutex<Option<Arc<SubmittedChunk>>>,
    cancelled: AtomicBool,
    finished: AtomicBool,
    wait_lock: Mutex<()>,
}

/// An already queued positional disk operation.
///
/// `wait` is the synchronous DiskReader compatibility path. Dropping an
/// unfinished request cancels it and drains its completion before releasing the
/// request, OVERLAPPED, or buffer allocation.
pub(crate) struct PendingIo {
    state: Arc<PendingIoState>,
    finished: bool,
}

/// A cloneable cancellation handle for a [`PendingIo`].
#[allow(dead_code)] // Exposed for WinFsp cancellation adapters; Drop also
                    // cancels.
pub(crate) struct IoCancellation {
    state: Arc<PendingIoState>,
}

impl PendingIo {
    fn start(
        kind: IoKind,
        engine: Arc<OverlappedFileInner>,
        offset: u64,
        buffer: Vec<u8>,
    ) -> Result<Self> {
        let state = Arc::new(PendingIoState {
            engine,
            kind,
            offset,
            buffer: Mutex::new(buffer),
            submitted: Mutex::new(None),
            cancelled: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            wait_lock: Mutex::new(()),
        });
        state.submit_next(0)?;
        Ok(Self {
            state,
            finished: false,
        })
    }

    #[allow(dead_code)]
    pub(crate) fn cancellation(&self) -> IoCancellation {
        IoCancellation {
            state: self.state.clone(),
        }
    }

    pub(crate) fn wait(mut self) -> Result<Vec<u8>> {
        let result = self.state.run();
        self.finished = true;
        result
    }
}

impl Drop for PendingIo {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.state.cancel();
            let _ = self.state.run();
        }
    }
}

#[allow(dead_code)]
impl IoCancellation {
    /// Cancel the currently submitted chunk. Chunks not yet submitted observe
    /// the cancellation flag before ReadFile/WriteFile is called.
    pub(crate) fn cancel(&self) -> Result<()> {
        self.state.cancel()
    }
}

impl PendingIoState {
    fn cancel(&self) -> Result<()> {
        if self.finished.load(Ordering::Acquire) {
            return Ok(());
        }
        self.cancelled.store(true, Ordering::Release);
        let submitted = self
            .submitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let Some(submitted) = submitted else {
            return Ok(());
        };
        let overlapped = submitted.state.overlapped();
        match unsafe { CancelIoEx(self.engine.file, Some(overlapped)) } {
            Ok(()) => Ok(()),
            Err(error) if error.code() == HRESULT::from_win32(ERROR_NOT_FOUND.0) => {
                // The operation already completed; its packet still has to be
                // retrieved by run/drop before the state can be released.
                Ok(())
            }
            Err(error) => Err(XfsWinfspError::IoError(io_error(error))),
        }
    }

    fn submit_next(&self, completed: usize) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(operation_aborted());
        }
        let mut buffer = self
            .buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if completed >= buffer.len() {
            return Ok(());
        }
        let offset = self
            .offset
            .checked_add(completed as u64)
            .ok_or_else(|| XfsWinfspError::DiskError("Disk I/O offset overflow".to_string()))?;
        let state = Arc::new(OperationState::new(offset));
        let engine = OverlappedFile {
            inner: self.engine.clone(),
        };
        engine.register(&state);

        let mut transferred = 0u32;
        let remaining = &mut buffer[completed..];
        let result = unsafe {
            match self.kind {
                IoKind::Read => ReadFile(
                    self.engine.file,
                    Some(remaining),
                    Some(&mut transferred),
                    Some(state.overlapped()),
                ),
                IoKind::Write => WriteFile(
                    self.engine.file,
                    Some(remaining),
                    Some(&mut transferred),
                    Some(state.overlapped()),
                ),
            }
        };
        let outcome = match result {
            Err(error) if error.code() == HRESULT::from_win32(ERROR_IO_PENDING.0) => {
                SubmissionOutcome::WaitForPacket
            }
            Err(error)
                if self.kind == IoKind::Read
                    && error.code() == HRESULT::from_win32(ERROR_HANDLE_EOF.0) =>
            {
                engine.unregister(&state);
                // Some drivers report the final partial transfer together with
                // ERROR_HANDLE_EOF. Preserve it; only a zero count means no
                // further data is available.
                SubmissionOutcome::Immediate(Ok(transferred))
            }
            Err(error) => {
                engine.unregister(&state);
                SubmissionOutcome::Immediate(Err(XfsWinfspError::IoError(io_error(error))))
            }
            Ok(()) => SubmissionOutcome::WaitForPacket,
        };
        *self
            .submitted
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(Arc::new(SubmittedChunk {
            state,
            outcome: Mutex::new(Some(outcome)),
        }));
        Ok(())
    }

    fn run(&self) -> Result<Vec<u8>> {
        let _wait = self
            .wait_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let result = self.run_inner();
        self.finished.store(true, Ordering::Release);
        result
    }

    fn run_inner(&self) -> Result<Vec<u8>> {
        let buffer_len = self
            .buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len();
        if self.cancelled.load(Ordering::Acquire)
            && self
                .submitted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_none()
        {
            return Err(operation_aborted());
        }
        let mut completed = 0usize;

        while completed < buffer_len {
            let submitted = self
                .submitted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
                .ok_or_else(|| {
                    XfsWinfspError::DiskError("Disk I/O request was not submitted".to_string())
                })?;
            let outcome = submitted
                .outcome
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
            let transferred = match outcome {
                Some(SubmissionOutcome::Immediate(result)) => result?,
                Some(SubmissionOutcome::WaitForPacket) => {
                    let engine = OverlappedFile {
                        inner: self.engine.clone(),
                    };
                    let completion = engine.wait_for(&submitted.state)?;
                    if completion.status == hresult_from_win32(ERROR_OPERATION_ABORTED.0)
                        && self.cancelled.load(Ordering::Acquire)
                    {
                        return Err(operation_aborted());
                    }
                    let eof = self.kind == IoKind::Read
                        && completion.status == hresult_from_win32(ERROR_HANDLE_EOF.0);
                    if completion.status == 0 || eof {
                        completion.transferred
                    } else {
                        return Err(XfsWinfspError::IoError(io_error_from_status(
                            completion.status,
                        )));
                    }
                }
                None => {
                    return Err(XfsWinfspError::DiskError(
                        "Disk I/O completion was consumed twice".to_string(),
                    ))
                }
            } as usize;
            *self
                .submitted
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            engine_unregister_after_completion(&self.engine, &submitted.state);

            if transferred > buffer_len - completed {
                return Err(XfsWinfspError::DiskError(
                    "Disk I/O returned more bytes than requested".to_string(),
                ));
            }
            completed += transferred;
            if self.cancelled.load(Ordering::Acquire) {
                return Err(operation_aborted());
            }
            if transferred == 0 {
                break;
            }
            if completed < buffer_len {
                self.submit_next(completed)?;
            }
        }
        let buffer = self
            .buffer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok(buffer[..completed].to_vec())
    }
}

const fn hresult_from_win32(error: u32) -> i32 {
    ((error & 0xFFFF) | 0x8007_0000) as i32
}

fn engine_unregister_after_completion(engine: &Arc<OverlappedFileInner>, state: &OperationState) {
    // process_completion normally removes the registry entry. This removal is
    // intentionally idempotent for synchronous errors and test/manual paths.
    engine
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&(state.overlapped() as usize));
}

#[cfg(test)]
mod tests {
    use std::{os::windows::fs::OpenOptionsExt, path::PathBuf};

    use super::*;

    struct TestFile {
        path: PathBuf,
        file: OverlappedFile,
    }

    impl TestFile {
        fn new(size: usize) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("crisscrossfs-iocp-{}-{id}.img", std::process::id()));
            let mut data = vec![0u8; size];
            for (index, byte) in data.iter_mut().enumerate() {
                *byte = index as u8;
            }
            std::fs::write(&path, &data).unwrap();
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(windows::Win32::Storage::FileSystem::FILE_FLAG_OVERLAPPED.0)
                .open(&path)
                .unwrap();
            let file = OverlappedFile::from_file(file).unwrap();
            Self { path, file }
        }
    }

    impl Drop for TestFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn overlapped_encodes_the_full_positional_offset() {
        for (offset, expected_low, expected_high) in [
            (0, 0, 0),
            (u64::from(u32::MAX), u32::MAX, 0),
            (1 << 32, 0, 1),
            (i64::MAX as u64, u32::MAX, 0x7FFF_FFFF),
        ] {
            let state = OperationState::new(offset);
            // SAFETY: new initialized the union's offset arm and no I/O is
            // outstanding on this state.
            let overlapped = unsafe { &*state.overlapped() };
            let (low, high) = unsafe {
                (
                    overlapped.Anonymous.Anonymous.Offset,
                    overlapped.Anonymous.Anonymous.OffsetHigh,
                )
            };
            assert_eq!(low, expected_low);
            assert_eq!(high, expected_high);
            assert_eq!(overlapped.Internal, 0);
            assert_eq!(overlapped.InternalHigh, 0);
        }
    }

    #[test]
    fn requests_queue_before_wait_and_share_completion_retrieval() {
        let image = TestFile::new(64);
        let first = image.file.read_at(3, 11).unwrap();
        let second = image.file.read_at(17, 13).unwrap();
        assert_eq!(image.file.pending_count(), 2);

        // Waiting in reverse submission order exercises one waiter retrieving
        // and publishing another request's completion.
        assert_eq!(
            second.wait().unwrap(),
            (17..30).map(|v| v as u8).collect::<Vec<_>>()
        );
        assert_eq!(
            first.wait().unwrap(),
            (3..14).map(|v| v as u8).collect::<Vec<_>>()
        );
        assert_eq!(image.file.pending_count(), 0);
    }

    #[test]
    fn cancelled_request_never_submits_and_reports_interrupted() {
        let image = TestFile::new(32);
        let request = image.file.read_at(0, 8).unwrap();
        request.cancellation().cancel().unwrap();
        let error = request.wait().unwrap_err();
        assert!(
            matches!(error, XfsWinfspError::IoError(ref error) if error.kind() == io::ErrorKind::Interrupted)
        );
        assert_eq!(image.file.pending_count(), 0);
    }

    #[test]
    fn dropping_queued_requests_drains_overlapped_and_buffers() {
        let image = TestFile::new(64);
        let read = image.file.read_at(0, 16).unwrap();
        let write = image.file.write_at(16, &[0xAA; 16]).unwrap();
        assert_eq!(image.file.pending_count(), 2);
        drop(read);
        drop(write);
        assert_eq!(image.file.pending_count(), 0);

        let mut buffer = [0u8; 16];
        assert_eq!(image.file.read_sync(16, &mut buffer).unwrap(), 16);
        assert_eq!(buffer, [0xAA; 16]);
    }

    #[test]
    fn synchronous_wait_path_preserves_eof_and_positions() {
        let image = TestFile::new(16);
        let mut buffer = [0u8; 8];
        assert_eq!(image.file.read_sync(12, &mut buffer).unwrap(), 4);
        assert_eq!(&buffer[..4], &[12, 13, 14, 15]);
        assert_eq!(image.file.read_sync(16, &mut buffer).unwrap(), 0);
        assert_eq!(image.file.write_sync(2, b"test").unwrap(), 4);
        assert_eq!(image.file.read_sync(2, &mut buffer).unwrap(), 8);
        assert_eq!(&buffer[..4], b"test");
    }
}
