use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

use tracing::{debug, error, info, warn};
use winfsp::{
    host::{DebugMode, FileSystemHost, FileSystemParams, VolumeParams},
    winfsp_init,
};

use crate::{
    context::VfsContext,
    error::{Result, XfsWinfspError},
};

/// Thread-safe shared handle to the live WinFsp host.
///
/// The `Option` is `Some` while the filesystem is running and `None` after
/// `unmount` + `stop` have been called.  Using an `Arc<Mutex<Option<…>>>`
/// instead of a channel lets `MountHandle::stop` drive the WinFsp lifecycle
/// directly, so the blocking `FspFileSystemStopDispatcher` call is explicit
/// in `stop()` / `Drop` rather than hidden inside `thread::join()`.
type SharedHost = Arc<Mutex<Option<FileSystemHost<VfsContext>>>>;

/// Handle to a running mount. Dropping will stop the mount thread.
pub struct MountHandle {
    /// Shared access to the WinFsp host; `stop` takes ownership to drive
    /// shutdown.
    host: SharedHost,
    /// Channel used only to tell the background thread it can exit after the
    /// host has been stopped.  The thread itself does no WinFsp teardown.
    stop_tx: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    mount_point: String,
    filesystem: Option<Arc<dyn fs_abstraction::VfsFileSystem>>,
}

impl MountHandle {
    /// Get the mount point path.
    pub fn mount_point(&self) -> &str {
        &self.mount_point
    }

    /// Check if the mount thread is still alive.
    pub fn is_alive(&self) -> bool {
        self.thread
            .as_ref()
            .map(|t| !t.is_finished())
            .unwrap_or(false)
    }

    /// Stop the mount and wait for the thread to exit.
    pub fn stop(mut self) {
        info!("Stopping mount at {}", self.mount_point);
        self.do_stop();
        info!("Mount stopped: {}", self.mount_point);
    }

    fn do_stop(&mut self) {
        // Take the host out of the shared Arc and stop WinFsp directly.
        // unmount() removes the mount point (no new FS requests accepted),
        // stop() calls FspFileSystemStopDispatcher which blocks until all
        // in-flight dispatcher threads drain.  This blocking happens HERE,
        // in an explicit call — not opaquely inside thread::join().
        if let Ok(mut guard) = self.host.lock() {
            if let Some(mut h) = guard.take() {
                h.unmount();
                h.stop();
                // h is dropped here; FileSystemHost::Drop calls unmount/stop
                // again but FspFileSystemRemoveMountPoint and
                // FspFileSystemStopDispatcher are both safe to call on an
                // already-stopped host (no-ops).
            }
        }
        // Now that WinFsp is stopped, tell the background thread it can exit.
        // The thread is blocked on stop_rx.recv() doing nothing; this unblocks
        // it.
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        // join() returns quickly — the thread has no WinFsp work left to do.
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Some(filesystem) = self.filesystem.take() {
            if let Err(error) = filesystem.shutdown() {
                warn!(
                    "Filesystem shutdown failed at {}: {:?}",
                    self.mount_point, error
                );
            }
        }
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        self.do_stop();
    }
}

/// Start a real foreground mount backed by WinFsp.
///
/// This function initializes WinFsp, creates a `FileSystemHost`, and starts
/// the filesystem dispatcher in a background thread.
///
/// # Arguments
/// * `mount_point` - Drive letter (e.g., "X:") or UNC path for the mount
/// * `fs` - Arc-wrapped VfsFileSystem providing filesystem operations
/// * `debug_enabled` - Enable WinFsp transaction debug output when true
///
/// # Returns
/// A `MountHandle` that can be used to stop the mount, or an error.
pub fn start_mount(
    mount_point: &str,
    fs: Arc<dyn fs_abstraction::VfsFileSystem>,
    debug_enabled: bool,
) -> Result<MountHandle> {
    info!("Starting VFS mount at {}", mount_point);

    // The `winfsp` crate unwraps `GetStdHandle(STD_ERROR_HANDLE)` when its
    // `debug` feature is enabled, and a process without a console (the GUI
    // binary, or the CLI started by a service) has no standard handles at all.
    // That unwrap used to panic the mount thread, which the caller could only
    // observe as "Channel error: receiving on a closed channel".
    ensure_standard_error();

    // Initialize the WinFsp library.  `winfsp_init_or_die()` would terminate
    // the whole process (status 1285) when the DLL cannot be loaded, which in
    // a GUI means the window simply disappears; report it as an error instead.
    winfsp_init().map_err(|_| {
        XfsWinfspError::WinFspError(
            "WinFsp could not be initialized: winfsp-x64.dll was not found. Install WinFsp 2.1 or \
             add its bin directory to PATH."
                .to_string(),
        )
    })?;

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let (ready_tx, ready_rx) = mpsc::channel::<std::result::Result<(), XfsWinfspError>>();

    let mount_point_owned = mount_point.to_string();
    let mount_point_for_handle = mount_point.to_string();
    let filesystem_for_handle = fs.clone();

    // Shared host: populated by the mount thread after dispatcher start,
    // consumed by MountHandle::stop() / Drop to drive shutdown.
    let host_arc: SharedHost = Arc::new(Mutex::new(None));
    let host_arc_for_thread = host_arc.clone();
    let host_arc_for_handle = host_arc.clone();

    let thread = thread::Builder::new()
        .name(format!("vfs-mount-{}", mount_point))
        .spawn(move || {
            let mount_point_for_panic = mount_point_owned.clone();
            let panic_tx = ready_tx.clone();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                run_mount_thread(
                    fs,
                    mount_point_owned,
                    debug_enabled,
                    ready_tx,
                    stop_rx,
                    host_arc_for_thread,
                );
            }));

            if let Err(payload) = outcome {
                let message = panic_text(payload.as_ref());
                error!(
                    "Mount thread panicked for {}: {}",
                    mount_point_for_panic, message
                );
                let _ = panic_tx.send(Err(XfsWinfspError::WinFspError(format!(
                    "Mount thread panicked: {message}"
                ))));
            }
        })
        .map_err(|e| XfsWinfspError::WinFspError(format!("Failed to spawn mount thread: {}", e)))?;

    // Wait for ready or error
    match ready_rx.recv() {
        Ok(Ok(())) => {
            info!("Mount ready: {}", mount_point);
            Ok(MountHandle {
                host: host_arc_for_handle,
                stop_tx: Some(stop_tx),
                thread: Some(thread),
                mount_point: mount_point_for_handle,
                filesystem: Some(filesystem_for_handle),
            })
        }
        Ok(Err(e)) => {
            warn!("Mount failed: {:?}", e);
            Err(e)
        }
        Err(e) => {
            let err = XfsWinfspError::WinFspError(format!("Channel error: {}", e));
            warn!("Mount channel error: {:?}", err);
            Err(err)
        }
    }
}

/// Body of the mount thread: build the WinFsp host and keep it alive until
/// [`MountHandle::stop`] signals shutdown.
///
/// Runs inside `catch_unwind` so a panic is reported to the caller instead of
/// surfacing as a closed channel.
fn run_mount_thread(
    fs: Arc<dyn fs_abstraction::VfsFileSystem>,
    mount_point: String,
    debug_enabled: bool,
    ready_tx: mpsc::Sender<std::result::Result<(), XfsWinfspError>>,
    stop_rx: mpsc::Receiver<()>,
    host_arc: SharedHost,
) {
    // Derive volume geometry/serial from the filesystem instead of
    // hardcoding values that are identical for every mounted volume.
    let vol_info = match fs.get_volume_info() {
        Ok(info) => Some(info),
        Err(error) => {
            warn!(
                "Cannot read volume info; using default geometry: {:?}",
                error
            );
            None
        }
    };
    let volume_label = vol_info
        .as_ref()
        .and_then(|v| v.volume_label.clone())
        .unwrap_or_else(|| "VFS Volume".to_string());
    let block_size = vol_info.as_ref().map_or(4096, |v| v.block_size);
    let (sector_size, sectors_per_allocation_unit) = volume_geometry(block_size);
    if block_size != u32::from(sector_size) * u32::from(sectors_per_allocation_unit) {
        warn!(
            "Invalid XFS block size {}; using 4096-byte allocation units",
            block_size
        );
    }
    let volume_serial = volume_serial_number(vol_info.as_ref().and_then(|v| v.uuid));

    // Build context using the generic VfsContext. The mount root is
    // also the confinement boundary for absolute symlink targets.
    let ctx = match VfsContext::new(fs.clone(), volume_label, mount_point.clone()) {
        Ok(ctx) => ctx,
        Err(error) => {
            let _ = ready_tx.send(Err(XfsWinfspError::from(error)));
            return;
        }
    };

    // Configure volume parameters
    let mut volume_params = VolumeParams::default();
    volume_params.filesystem_name(fs.fs_type());
    volume_params.volume_serial_number(volume_serial);
    volume_params.sector_size(sector_size);
    volume_params.sectors_per_allocation_unit(sectors_per_allocation_unit);
    // WinFsp's mount policy must match the backend exactly.
    volume_params.read_only_volume(fs.capabilities().read_only);
    volume_params.reparse_points(true);
    // ACL modification/persistence is not implemented by the glue.
    volume_params.persistent_acls(false);
    volume_params.case_sensitive_search(true);
    volume_params.case_preserved_names(true);
    volume_params.unicode_on_disk(true);
    volume_params.max_component_length(255);
    volume_params.flush_and_purge_on_cleanup(false);
    volume_params.post_cleanup_when_modified_only(true);

    debug!(
        "FileSystemHost VolumeParams configured (sector_size={}, sectors_per_allocation_unit={}, \
         serial=0x{:08X})",
        sector_size, sectors_per_allocation_unit, volume_serial
    );

    // Only enable WinFsp tracing when the caller asked for it.
    let fs_params = if debug_enabled {
        FileSystemParams::default_params_debug(volume_params, DebugMode::all())
    } else {
        FileSystemParams::default_params(volume_params)
    };
    debug!("FileSystemParams created (debug={})", debug_enabled);

    // Create filesystem host with full options
    match FileSystemHost::new_with_options(fs_params, ctx) {
        Ok(mut host) => {
            debug!("Mounting at: {}", mount_point);

            if let Err(e) = host.mount(&mount_point) {
                let err_msg = format!("Mount failed for {}: {:?}", mount_point, e);
                error!("{}", err_msg);
                let _ = ready_tx.send(Err(XfsWinfspError::WinFspError(err_msg)));
                return;
            }

            info!("Filesystem mounted at {}", mount_point);

            // Start the WinFsp dispatcher.
            // FspFileSystemStartDispatcher spawns worker threads and
            // returns immediately — it is NOT blocking. The dispatcher
            // runs autonomously until FspFileSystemStopDispatcher
            // is called, which happens in MountHandle::stop() / Drop,
            // not here.
            if let Err(e) = host.start() {
                let err_msg = format!("Dispatcher start failed: {:?}", e);
                error!("{}", err_msg);
                let _ = ready_tx.send(Err(XfsWinfspError::WinFspError(err_msg)));
                return;
            }

            // Hand the live host to the shared Arc so MountHandle can
            // stop it. This must happen before signalling ready so the
            // handle is usable as soon as the caller receives it.
            {
                let mut guard = host_arc.lock().unwrap();
                *guard = Some(host);
            }

            info!("WinFsp dispatcher running for {}", mount_point);
            let _ = ready_tx.send(Ok(()));

            // Wait for MountHandle::stop() / Drop to stop the host and
            // then send this signal.  The thread has no more WinFsp
            // work to do.
            let _ = stop_rx.recv();

            info!("Mount thread exiting for {}", mount_point);
        }
        Err(e) => {
            let err_msg = format!("FileSystemHost creation failed: {:?}", e);
            warn!("{}", err_msg);
            let _ = ready_tx.send(Err(XfsWinfspError::WinFspError(err_msg)));
        }
    }
}

/// Make sure the process owns a valid standard-error handle.
///
/// Windowless processes have no console, so `GetStdHandle(STD_ERROR_HANDLE)`
/// fails.  Point stderr at the NUL device instead of leaving it unset: several
/// WinFsp helpers assume a usable handle and panic on `None`.
fn ensure_standard_error() {
    use windows::{
        core::w,
        Win32::{
            Storage::FileSystem::{
                CreateFileW,
                FILE_ATTRIBUTE_NORMAL,
                FILE_GENERIC_WRITE,
                FILE_SHARE_READ,
                FILE_SHARE_WRITE,
                OPEN_EXISTING,
            },
            System::Console::{GetStdHandle, SetStdHandle, STD_ERROR_HANDLE},
        },
    };

    unsafe {
        if let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) {
            if !handle.is_invalid() {
                return;
            }
        }

        let Ok(null) = CreateFileW(
            w!("NUL"),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        ) else {
            return;
        };
        let _ = SetStdHandle(STD_ERROR_HANDLE, null);
    }
}

/// Describe a panic payload captured by `catch_unwind`.
fn panic_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "unknown panic payload".to_string()
    }
}

/// Mount options for configuring the XFS mount.
#[derive(Debug, Clone)]
pub struct XfsMountOptions {
    /// Mount point (drive letter like "X:" or UNC path)
    pub mount_point: String,
    /// Enable debug logging
    pub debug: bool,
    /// Filesystem label override (None = use XFS label)
    pub label_override: Option<String>,
}

impl Default for XfsMountOptions {
    fn default() -> Self {
        Self {
            mount_point: "X:".to_string(),
            debug: false,
            label_override: None,
        }
    }
}

/// Derive WinFsp geometry so the allocation unit equals the XFS block size.
/// WinFsp's sector size remains the conventional 512 bytes; larger XFS blocks
/// are represented by SectorsPerAllocationUnit rather than being clamped.
fn volume_geometry(block_size: u32) -> (u16, u16) {
    if (512..=65_536).contains(&block_size) && block_size.is_power_of_two() {
        (512, (block_size / 512) as u16)
    } else {
        (512, 8) // safe 4096-byte fallback
    }
}

fn volume_serial_number(uuid: Option<[u8; 16]>) -> u32 {
    uuid.map(|uuid| u32::from_be_bytes([uuid[0], uuid[1], uuid[2], uuid[3]]))
        .filter(|serial| *serial != 0)
        .unwrap_or(0x58465342) // "XFSB"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_uses_xfs_block_size_as_allocation_unit() {
        for block_size in [512, 1024, 4096, 8192, 65_536] {
            let (sector_size, sectors_per_unit) = volume_geometry(block_size);
            assert_eq!(sector_size, 512);
            assert_eq!(
                u32::from(sector_size) * u32::from(sectors_per_unit),
                block_size
            );
        }
    }

    #[test]
    fn invalid_geometry_falls_back_without_clamping_valid_blocks() {
        for block_size in [0, 513, 4095, 65_537, u32::MAX] {
            assert_eq!(volume_geometry(block_size), (512, 8));
        }
    }

    #[test]
    fn serial_is_derived_from_uuid_with_nonzero_fallback() {
        let mut uuid = [0u8; 16];
        uuid[..4].copy_from_slice(&0x1234_ABCD_u32.to_be_bytes());
        assert_eq!(volume_serial_number(Some(uuid)), 0x1234_ABCD);
        assert_eq!(volume_serial_number(None), 0x58465342);
        assert_eq!(volume_serial_number(Some([0u8; 16])), 0x58465342);
    }
}
