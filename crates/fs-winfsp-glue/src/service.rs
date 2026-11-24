//! Windows Service for automatic XFS disk detection and mounting.
//!
//! This module implements a Windows service that:
//! 1. Scans for XFS partitions/disks at startup
//! 2. Automatically mounts detected XFS filesystems
//! 3. Monitors for new disk arrivals (USB, etc.)

use std::{
    ffi::OsString,
    sync::{mpsc, Arc},
    time::Duration,
};

use tracing::{error, info, warn};
#[cfg(windows)]
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState as WinServiceState,
        ServiceStatus, ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::{
    disk::{scan_for_xfs_disks, PhysicalDiskReader, XfsDiskInfo},
    factory::detect_and_create,
    winfsp_mount::{start_mount, MountHandle},
};

/// Service name as registered with Windows.
pub const SERVICE_NAME: &str = "XfsFilesystemService";

/// Service display name.
pub const SERVICE_DISPLAY_NAME: &str = "XFS Filesystem Service";

/// Service description.
pub const SERVICE_DESCRIPTION: &str = "Automatically detects and mounts XFS filesystems on Windows";

/// Arguments the SCM must pass to the service binary.
pub const SERVICE_LAUNCH_ARGUMENTS: [&str; 2] = ["service", "run"];

/// Currently mounted XFS volumes.
struct MountedVolume {
    disk_info: XfsDiskInfo,
    mount_point: String,
    handle: MountHandle,
}

/// Internal service state.
struct XfsServiceState {
    /// Mounted volumes.
    mounted_volumes: Vec<MountedVolume>,
    /// Shutdown signal sender.
    shutdown_tx: Option<mpsc::Sender<()>>,
}

impl XfsServiceState {
    fn new() -> Self {
        Self {
            mounted_volumes: Vec::new(),
            shutdown_tx: None,
        }
    }
}

#[cfg(windows)]
define_windows_service!(ffi_service_main, service_main);

/// Service main entry point.
#[cfg(windows)]
pub fn service_main(arguments: Vec<OsString>) {
    if let Err(e) = run_service(arguments) {
        error!("Service error: {}", e);
    }
}

/// Run the service.
#[cfg(windows)]
fn run_service(_arguments: Vec<OsString>) -> Result<(), Box<dyn std::error::Error>> {
    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    // Clone for the control handler closure; original stays in state.
    let shutdown_tx_for_handler = shutdown_tx.clone();

    // Create service state
    let mut state = XfsServiceState::new();
    state.shutdown_tx = Some(shutdown_tx);

    // Register service control handler
    let status_handle = service_control_handler::register(
        SERVICE_NAME,
        move |control_event| -> ServiceControlHandlerResult {
            match control_event {
                ServiceControl::Stop | ServiceControl::Shutdown => {
                    info!("Received stop signal");
                    let _ = shutdown_tx_for_handler.send(());
                    ServiceControlHandlerResult::NoError
                }
                ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
                _ => ServiceControlHandlerResult::NotImplemented,
            }
        },
    )?;

    // Set service status to running
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: WinServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("XFS Filesystem Service started");

    // Initial scan for XFS disks
    scan_and_mount(&mut state);

    // Main service loop
    loop {
        match shutdown_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(()) => {
                info!("Shutdown signal received");
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // Periodic rescan for new disks
                scan_and_mount(&mut state);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break;
            }
        }
    }

    // Unmount all volumes
    unmount_all(&mut state);

    // Set service status to stopped
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: WinServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    info!("XFS Filesystem Service stopped");
    Ok(())
}

/// Scan for XFS disks and mount any new ones found.
fn scan_and_mount(state: &mut XfsServiceState) {
    info!("Scanning for XFS filesystems...");

    let xfs_disks = scan_for_xfs_disks();

    for disk_info in xfs_disks {
        // Check if already mounted
        let already_mounted = state
            .mounted_volumes
            .iter()
            .any(|v| v.disk_info.disk_path == disk_info.disk_path);

        if already_mounted {
            continue;
        }

        // Find available mount point
        let mount_point = find_available_mount_point();
        if mount_point.is_none() {
            warn!("No available drive letters for mounting");
            continue;
        }
        let mount_point = mount_point.unwrap();

        info!(
            "Found XFS filesystem on {}, mounting as {}",
            disk_info.disk_path, mount_point
        );

        let device = match PhysicalDiskReader::open_by_path(&disk_info.disk_path) {
            Ok(d) => Arc::new(d),
            Err(e) => {
                error!("Failed to open {}: {:?}", disk_info.disk_path, e);
                continue;
            }
        };

        let fs = match detect_and_create(device, /* read_only = */ true) {
            Ok(fs) => fs,
            Err(e) => {
                error!("Failed to create VFS for {}: {:?}", disk_info.disk_path, e);
                continue;
            }
        };

        let handle = match start_mount(&mount_point, fs, false) {
            Ok(h) => h,
            Err(e) => {
                error!(
                    "Failed to mount {} at {}: {:?}",
                    disk_info.disk_path, mount_point, e
                );
                continue;
            }
        };

        info!("Mounted {} at {}", disk_info.disk_path, mount_point);
        state.mounted_volumes.push(MountedVolume {
            disk_info,
            mount_point,
            handle,
        });
    }
}

/// Unmount all mounted volumes.
fn unmount_all(state: &mut XfsServiceState) {
    for volume in state.mounted_volumes.drain(..) {
        info!(
            "Unmounting {} from {}",
            volume.disk_info.disk_path, volume.mount_point
        );
        volume.handle.stop();
    }
}

/// Find an available drive letter for mounting.
fn find_available_mount_point() -> Option<String> {
    // Check drive letters from X to Z, then A to W
    let letters: Vec<char> = ('X'..='Z').chain('A'..='W').collect();

    for letter in letters {
        let path = format!("{}:\\", letter);
        if !std::path::Path::new(&path).exists() {
            return Some(format!("{}:", letter));
        }
    }

    None
}

/// Install the service.
#[cfg(windows)]
pub fn install_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::OsStr;

    use windows_service::{
        service::{ServiceAccess, ServiceErrorControl, ServiceInfo, ServiceStartType},
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(
        None::<&OsStr>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )?;

    let service_binary = std::env::current_exe()?;

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: service_binary,
        // Must match the Clap hierarchy in main.rs: `xfs-mount service run`.
        // The SCM appends these verbatim to the executable path.
        launch_arguments: SERVICE_LAUNCH_ARGUMENTS
            .iter()
            .map(|arg| OsString::from(arg))
            .collect(),
        dependencies: vec![],
        account_name: None, // Run as LocalSystem
        account_password: None,
    };

    let _service = manager.create_service(&service_info, ServiceAccess::CHANGE_CONFIG)?;

    info!("Service installed successfully");
    Ok(())
}

/// Uninstall the service.
#[cfg(windows)]
pub fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::OsStr;

    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(SERVICE_NAME, ServiceAccess::DELETE)?;
    service.delete()?;

    info!("Service uninstalled successfully");
    Ok(())
}

/// Start the service.
#[cfg(windows)]
pub fn start_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::OsStr;

    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(SERVICE_NAME, ServiceAccess::START)?;
    service.start(&[] as &[&OsStr])?;

    info!("Service started");
    Ok(())
}

/// Stop the service.
#[cfg(windows)]
pub fn stop_service() -> Result<(), Box<dyn std::error::Error>> {
    use std::ffi::OsStr;

    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };

    let manager = ServiceManager::local_computer(None::<&OsStr>, ServiceManagerAccess::CONNECT)?;

    let service = manager.open_service(SERVICE_NAME, ServiceAccess::STOP)?;
    service.stop()?;

    info!("Service stopped");
    Ok(())
}

/// Run the service dispatcher (called from main when running as service).
#[cfg(windows)]
pub fn run_as_service() -> Result<(), Box<dyn std::error::Error>> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{sync::mpsc, time::Duration};

    use super::*;

    #[test]
    fn service_launch_arguments_match_cli() {
        // Regression test for the SCM launch line: Clap expects the
        // `service run` subcommand pair, not a `--service` flag.
        assert_eq!(SERVICE_LAUNCH_ARGUMENTS, ["service", "run"]);
    }

    /// Sending on a cloned Sender delivers to the shared Receiver.
    ///
    /// This is the exact channel pattern used in the Stop/Shutdown SCM
    /// control handler.  A clone of `shutdown_tx` is captured in the
    /// closure; the original goes into `state`.  When the SCM fires the
    /// handler, the clone calls `.send(())`, which must be received by the
    /// `recv_timeout` loop in `run_service`.
    #[test]
    fn cloned_sender_delivers_shutdown_signal() {
        let (tx, rx) = mpsc::channel::<()>();
        let tx_clone = tx.clone();
        // Simulate the handler firing: original tx is alive in state, clone
        // is captured in the closure.
        tx_clone.send(()).unwrap();
        assert!(
            rx.recv_timeout(Duration::from_millis(100)).is_ok(),
            "shutdown signal must be received via the cloned sender"
        );
    }

    /// When all senders are dropped, recv_timeout returns Disconnected, not
    /// Timeout.  The service loop treats both as exit conditions, but this
    /// documents the expected disconnect path (e.g. if the thread panics).
    #[test]
    fn dropped_all_senders_yields_disconnected() {
        let (tx, rx) = mpsc::channel::<()>();
        drop(tx);
        assert!(matches!(
            rx.recv_timeout(Duration::from_millis(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

    /// `find_available_mount_point` must return either `None` or a string of
    /// the form `"X:"` (uppercase letter + colon, no trailing backslash).
    #[test]
    fn available_mount_point_has_correct_format() {
        if let Some(mp) = find_available_mount_point() {
            assert_eq!(mp.len(), 2, "mount point must be exactly 2 chars");
            let letter = mp.chars().next().unwrap();
            assert!(
                letter.is_ascii_uppercase(),
                "mount point letter must be uppercase ASCII, got '{letter}'"
            );
            assert_eq!(&mp[1..], ":", "mount point must end with ':'");
        }
        // None is valid when all 26 drive letters are occupied.
    }
}
