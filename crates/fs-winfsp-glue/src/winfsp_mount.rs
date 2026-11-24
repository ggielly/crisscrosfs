use std::{
    sync::{mpsc, Arc, Mutex},
    thread,
};

use tracing::{debug, error, info, warn};
use winfsp::{
    host::{DebugMode, FileSystemHost, FileSystemParams, VolumeParams},
    winfsp_init_or_die,
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
    /// Shared access to the WinFsp host; `stop` takes ownership to drive shutdown.
    host: SharedHost,
    /// Channel used only to tell the background thread it can exit after the
    /// host has been stopped.  The thread itself does no WinFsp teardown.
    stop_tx: Option<mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<()>>,
    mount_point: String,
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
        // The thread is blocked on stop_rx.recv() doing nothing; this unblocks it.
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        // join() returns quickly — the thread has no WinFsp work left to do.
        if let Some(t) = self.thread.take() {
            let _ = t.join();
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
///
/// # Returns
/// A `MountHandle` that can be used to stop the mount, or an error.
pub fn start_mount(
    mount_point: &str,
    fs: Arc<dyn fs_abstraction::VfsFileSystem>,
    debug_enabled: bool,
) -> Result<MountHandle> {
    info!("Starting VFS mount at {}", mount_point);

    // Initialize WinFsp library (idempotent, safe to call multiple times)
    winfsp_init_or_die();

    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let (ready_tx, ready_rx) = mpsc::channel::<std::result::Result<(), XfsWinfspError>>();

    let mount_point_owned = mount_point.to_string();
    let mount_point_for_handle = mount_point.to_string();

    // Shared host: populated by the mount thread after dispatcher start,
    // consumed by MountHandle::stop() / Drop to drive shutdown.
    let host_arc: SharedHost = Arc::new(Mutex::new(None));
    let host_arc_for_thread = host_arc.clone();
    let host_arc_for_handle = host_arc.clone();

    let thread = thread::Builder::new()
        .name(format!("vfs-mount-{}", mount_point))
        .spawn(move || {
            info!("Mount thread started for {}", mount_point_owned);

            // Derive volume geometry/serial from the filesystem instead of
            // hardcoding values that are identical for every mounted volume.
            let vol_info = fs.get_volume_info().ok();
            let volume_label = vol_info
                .as_ref()
                .and_then(|v| v.volume_label.clone())
                .unwrap_or_else(|| "VFS Volume".to_string());
            let block_size = vol_info
                .as_ref()
                .map(|v| v.block_size)
                .filter(|b| b.is_power_of_two())
                .unwrap_or(4096);
            let sector_size = block_size.clamp(512, 4096) as u16;
            let volume_serial = vol_info
                .as_ref()
                .and_then(|v| v.uuid)
                .map(|uuid| u32::from_be_bytes([uuid[0], uuid[1], uuid[2], uuid[3]]))
                .filter(|serial| *serial != 0)
                .unwrap_or(0x58465342); // "XFSB"

            // Build context using the new generic VfsContext
            let ctx = VfsContext::new(fs.clone(), volume_label);

            let is_read_only = fs.capabilities().read_only;

            // Configure volume parameters
            let mut volume_params = VolumeParams::default();
            volume_params.filesystem_name(fs.fs_type());
            volume_params.volume_serial_number(volume_serial);
            volume_params.sector_size(sector_size);
            volume_params.sectors_per_allocation_unit(1);
            volume_params.read_only_volume(is_read_only);
            volume_params.case_sensitive_search(true);
            volume_params.case_preserved_names(true);
            volume_params.unicode_on_disk(true);
            volume_params.max_component_length(255);
            volume_params.flush_and_purge_on_cleanup(false);
            volume_params.post_cleanup_when_modified_only(true);

            debug!(
                "FileSystemHost VolumeParams configured (sector_size={}, serial=0x{:08X})",
                sector_size, volume_serial
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
                    debug!("Mounting at: {}", mount_point_owned);

                    if let Err(e) = host.mount(&mount_point_owned) {
                        let err_msg = format!("Mount failed for {}: {:?}", mount_point_owned, e);
                        error!("{}", err_msg);
                        let _ = ready_tx.send(Err(XfsWinfspError::WinFspError(err_msg)));
                        return;
                    }

                    info!("Filesystem mounted at {}", mount_point_owned);

                    // Start the WinFsp dispatcher.  FspFileSystemStartDispatcher spawns
                    // worker threads and returns immediately — it is NOT blocking.
                    // The dispatcher runs autonomously until FspFileSystemStopDispatcher
                    // is called, which happens in MountHandle::stop() / Drop, not here.
                    if let Err(e) = host.start() {
                        let err_msg = format!("Dispatcher start failed: {:?}", e);
                        error!("{}", err_msg);
                        let _ = ready_tx.send(Err(XfsWinfspError::WinFspError(err_msg)));
                        return;
                    }

                    // Hand the live host to the shared Arc so MountHandle can stop it.
                    // This must happen before signalling ready so the handle is usable
                    // as soon as the caller receives it.
                    {
                        let mut guard = host_arc_for_thread.lock().unwrap();
                        *guard = Some(host);
                    }

                    info!("WinFsp dispatcher running for {}", mount_point_owned);
                    let _ = ready_tx.send(Ok(()));

                    // Wait for MountHandle::stop() / Drop to stop the host and then
                    // send this signal.  The thread has no more WinFsp work to do.
                    let _ = stop_rx.recv();

                    info!("Mount thread exiting for {}", mount_point_owned);
                }
                Err(e) => {
                    let err_msg = format!("FileSystemHost creation failed: {:?}", e);
                    warn!("{}", err_msg);
                    let _ = ready_tx.send(Err(XfsWinfspError::WinFspError(err_msg)));
                }
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
