//! XFS Mount CLI - Mount XFS filesystems on Windows.
//!
//! Usage:
//!   xfs-mount mount --disk 1 --mount-point X:
//!   xfs-mount mount --image /path/to/xfs.img --mount-point X:
//!   xfs-mount mount --partition D: --mount-point X:
//!   xfs-mount scan

use std::{
    path::PathBuf,
    sync::{mpsc, Arc},
};

use clap::{Parser, Subcommand};
use fs_abstraction::VfsFileSystem;
use fs_winfsp_glue::{
    disk::{self, scan_for_xfs_disks, ImageFileReader, PhysicalDiskReader},
    error::Result,
    mount::{parse_partition, validate_mount_point, MountOptions, MountSource},
    service,
    winfsp_mount,
    XfsWinfspError,
};
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use xfs_vfs::XfsVfs;

#[derive(Parser)]
#[command(name = "xfs-mount")]
#[command(author = "XFS Development Team")]
#[command(version = "0.1.0")]
#[command(about = "Mount XFS filesystems on Windows", long_about = None)]
struct Cli {
    /// Enable debug output
    #[arg(short = 'D', long, global = true)]
    debug: bool,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Enable colored output for logs
    #[arg(long, global = true)]
    color: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Mount an XFS filesystem
    #[command(group(clap::ArgGroup::new("source").required(true).multiple(false)))]
    Mount {
        /// Physical disk number (0, 1, 2...)
        #[arg(short, long, group = "source", conflicts_with_all = ["image", "partition", "volume"])]
        disk: Option<u32>,

        /// Path to XFS image file
        #[arg(short, long, group = "source", conflicts_with_all = ["disk", "partition", "volume"])]
        image: Option<PathBuf>,

        /// Partition drive letter (e.g., D:)
        #[arg(short, long, group = "source", conflicts_with_all = ["disk", "image", "volume"])]
        partition: Option<String>,

        /// Volume path (e.g., \\.\HarddiskVolume5)
        #[arg(short = 'V', long, group = "source", conflicts_with_all = ["disk", "image", "partition"])]
        volume: Option<String>,

        /// Mount point (drive letter, e.g., X:)
        #[arg(short, long, required = true)]
        mount_point: String,

        /// Reserved write-mode flag (currently rejected: allocation/journal are
        /// incomplete)
        #[arg(long)]
        rw: bool,
    },

    /// Scan for XFS filesystems
    Scan {
        /// Show detailed information
        #[arg(short, long)]
        verbose: bool,
    },

    /// Show information about an XFS filesystem
    #[command(group(clap::ArgGroup::new("source").required(true).multiple(false)))]
    Info {
        /// Physical disk number
        #[arg(short, long, group = "source", conflicts_with = "image")]
        disk: Option<u32>,

        /// Path to XFS image file
        #[arg(short, long, group = "source", conflicts_with = "disk")]
        image: Option<PathBuf>,
    },

    /// List contents of a directory
    #[command(group(clap::ArgGroup::new("source").required(true).multiple(false)))]
    Ls {
        /// Physical disk number
        #[arg(short, long, group = "source", conflicts_with = "image")]
        disk: Option<u32>,

        /// Path to XFS image file
        #[arg(short, long, group = "source", conflicts_with = "disk")]
        image: Option<PathBuf>,

        /// Path within the XFS filesystem
        #[arg(default_value = "/")]
        path: String,
    },

    /// Service management commands
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
}

#[derive(Subcommand)]
enum ServiceAction {
    /// Install the XFS service
    Install,
    /// Uninstall the XFS service
    Uninstall,
    /// Start the XFS service
    Start,
    /// Stop the XFS service
    Stop,
    /// Run as a service (internal use)
    Run,
}

fn main() {
    let cli = Cli::parse();

    // Enable Windows ANSI color support if requested
    if cli.color {
        // Enable global colored logging
        fs_winfsp_glue::colored_log::enable_colors();

        #[cfg(windows)]
        {
            use windows::Win32::System::Console::{
                GetStdHandle,
                SetConsoleMode,
                CONSOLE_MODE,
                ENABLE_VIRTUAL_TERMINAL_PROCESSING,
                STD_ERROR_HANDLE,
                STD_OUTPUT_HANDLE,
            };
            unsafe {
                // Enable ANSI for stdout
                if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
                    let mut mode = CONSOLE_MODE(0);
                    if windows::Win32::System::Console::GetConsoleMode(handle, &mut mode).is_ok() {
                        let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                    }
                }
                // Enable ANSI for stderr (important for our colored logs)
                if let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) {
                    let mut mode = CONSOLE_MODE(0);
                    if windows::Win32::System::Console::GetConsoleMode(handle, &mut mode).is_ok() {
                        let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
                    }
                }
            }
        }
    }

    // Initialize logging based on global debug/verbose flags
    let log_level = if cli.debug {
        Level::TRACE
    } else if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let _subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .with_ansi(cli.color)
        .init();

    let result = match cli.command {
        Commands::Mount {
            disk,
            image,
            partition,
            volume,
            mount_point,
            rw,
        } => resolve_mount_source(disk, image, partition, volume).and_then(|source| {
            let options = MountOptions {
                source,
                mount_point: validate_mount_point(&mount_point)?,
                read_only: !rw,
                debug: cli.debug,
                ..Default::default()
            };
            cmd_mount(options)
        }),

        Commands::Scan { verbose } => cmd_scan(verbose || cli.debug),

        Commands::Info { disk, image } => {
            resolve_read_source(disk, image).and_then(|source| cmd_info(source, cli.debug))
        }

        Commands::Ls { disk, image, path } => {
            resolve_read_source(disk, image).and_then(|source| cmd_ls(source, &path, cli.debug))
        }

        Commands::Service { action } => match action {
            ServiceAction::Install => cmd_service_install(),
            ServiceAction::Uninstall => cmd_service_uninstall(),
            ServiceAction::Start => cmd_service_start(),
            ServiceAction::Stop => cmd_service_stop(),
            ServiceAction::Run => cmd_service_run(),
        },
    };

    if let Err(e) = result {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}

fn resolve_mount_source(
    disk: Option<u32>,
    image: Option<PathBuf>,
    partition: Option<String>,
    volume: Option<String>,
) -> Result<MountSource> {
    if let Some(disk_number) = disk {
        Ok(MountSource::DiskNumber(disk_number))
    } else if let Some(path) = image {
        Ok(MountSource::ImageFile(path))
    } else if let Some(value) = partition {
        Ok(MountSource::Partition(parse_partition(&value)?))
    } else if let Some(path) = volume {
        Ok(MountSource::DiskPath(path))
    } else {
        Err(XfsWinfspError::InvalidArgument(
            "Must specify --disk, --image, --partition, or --volume".to_string(),
        ))
    }
}

fn resolve_read_source(disk: Option<u32>, image: Option<PathBuf>) -> Result<MountSource> {
    if let Some(disk_number) = disk {
        Ok(MountSource::DiskNumber(disk_number))
    } else if let Some(path) = image {
        Ok(MountSource::ImageFile(path))
    } else {
        Err(XfsWinfspError::InvalidArgument(
            "Must specify --disk or --image".to_string(),
        ))
    }
}

/// Open a validated source read-only.
///
/// Disk numbers deliberately use the same GPT-aware resolution for mount,
/// info, and ls. No command path opens a writer: RW remains disabled until the
/// allocator and journal implementation are complete.
fn open_read_only_source(source: &MountSource) -> Result<Arc<dyn fs_abstraction::BlockDevice>> {
    source.validate()?;
    match source {
        MountSource::DiskNumber(number) => disk::open_disk_with_partitions(*number),
        MountSource::ImageFile(path) => Ok(Arc::new(ImageFileReader::open(path)?)),
        MountSource::Partition(letter) => {
            Ok(Arc::new(PhysicalDiskReader::open_partition(*letter)?))
        }
        MountSource::DiskPath(path) => Ok(Arc::new(PhysicalDiskReader::open_by_path(path)?)),
    }
}

/// Mount an XFS filesystem.
fn cmd_mount(options: MountOptions) -> Result<()> {
    info!("Mounting XFS filesystem to {}", options.mount_point);
    tracing::debug!("Mount options: {:?}", options);

    if !options.read_only {
        // The block allocator's mark_allocated() and free_blocks() are stubs
        // that have not been implemented yet.  Allowing write operations would
        // silently reuse blocks that still appear free in the on-disk
        // free-space B+trees, corrupting the filesystem without any error.
        // Refuse here before any device is opened or write path is entered.
        error!(
            "--rw is disabled: the block allocator is not implemented. Write operations would \
             silently corrupt the filesystem by reusing blocks that are already in use. Remove \
             this error once mark_allocated() and free_blocks() in xfs-vfs/src/allocator.rs are \
             fully implemented."
        );
        return Err(XfsWinfspError::WinFspError(
            "--rw is not available: block allocator not implemented (see allocator.rs)".to_string(),
        ));
    }

    options.validate()?;
    let device = open_read_only_source(&options.source)?;

    // Detect and create filesystem
    info!("Detecting filesystem type...");
    let fs = fs_winfsp_glue::factory::detect_and_create(device, true)?;

    // Get volume info for display
    let vol_info = fs.get_volume_info()?;
    info!("XFS VFS opened successfully");
    info!("  Label: {:?}", vol_info.volume_label);
    info!("  Total: {} bytes", vol_info.total_bytes);
    info!("  Block size: {} bytes", vol_info.block_size);
    info!("  Read-only: {}", fs.capabilities().read_only);

    // Start the mount using VFS layer
    let handle: winfsp_mount::MountHandle =
        winfsp_mount::start_mount(&options.mount_point, fs.clone(), options.debug)?;

    // Show volume information
    info!("Volume Information:");
    info!("  Label: {:?}", vol_info.volume_label);
    info!("  Total size: {} bytes", vol_info.total_bytes);
    info!("  Free size: {} bytes", vol_info.free_bytes);
    info!("  Read-only: {}", fs.capabilities().read_only);

    info!("Press Ctrl+C to unmount...");

    // Wait for Ctrl+C then stop the mount
    let (sig_tx, sig_rx) = mpsc::channel::<()>();
    ctrlc::set_handler(move || {
        let _ = sig_tx.send(());
    })
    .map_err(|e| XfsWinfspError::IoError(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

    // Block until signal received
    let _ = sig_rx.recv();

    // Stop the mount
    handle.stop();

    Ok(())
}

/// Scan for XFS filesystems.
fn cmd_scan(verbose: bool) -> Result<()> {
    info!("Scanning for XFS filesystems...");

    let disks = scan_for_xfs_disks();

    if disks.is_empty() {
        info!("No XFS filesystems found.");
        return Ok(());
    }

    info!("Found {} XFS filesystem(s):\n", disks.len());

    for (i, disk) in disks.iter().enumerate() {
        info!("{}. {}", i + 1, disk.disk_path);
        if verbose {
            info!("   Size: {} bytes", disk.size);
            info!("   Block size: {} bytes", disk.block_size);
            if !disk.label.is_empty() {
                info!("   Label: {}", disk.label);
            }
            if !disk.uuid.is_empty() {
                info!("   UUID: {}", disk.uuid);
            }
        }
        info!("");
    }

    Ok(())
}

/// Show XFS filesystem information.
fn cmd_info(source: MountSource, debug: bool) -> Result<()> {
    let reader = open_read_only_source(&source)?;
    let fs = XfsVfs::with_options(reader, true)?;
    let vol_info = fs.get_volume_info()?;

    if debug {
        info!("Debug mode enabled for info command");
    }

    info!("XFS Filesystem Information:");
    info!("  Label: {:?}", vol_info.volume_label);
    info!("  UUID: {:?}", vol_info.uuid);
    info!(
        "  Total size: {} bytes ({:.2} GB)",
        vol_info.total_bytes,
        vol_info.total_bytes as f64 / 1_073_741_824.0
    );
    info!(
        "  Free space: {} bytes ({:.2} GB)",
        vol_info.free_bytes,
        vol_info.free_bytes as f64 / 1_073_741_824.0
    );
    info!("  Block size: {} bytes", vol_info.block_size);
    // info!("  Root inode: {}", fs.root_inode()); // XfsVfs doesn't expose it
    // directly yet, but usually it's 128 or similar

    Ok(())
}

/// List directory contents.
fn cmd_ls(source: MountSource, path: &str, debug: bool) -> Result<()> {
    let reader = open_read_only_source(&source)?;
    let fs = Arc::new(XfsVfs::with_options(reader, true)?);

    if debug {
        info!("Debug mode enabled for ls command");
    }

    let root_ino = fs.resolve_path(path)?;
    let entries = fs.readdir(root_ino)?;

    info!("Contents of {}:", path);
    info!("");

    for entry in entries {
        let type_char = match entry.file_type {
            fs_abstraction::types::VfsFileType::Directory => 'd',
            fs_abstraction::types::VfsFileType::Symlink => 'l',
            fs_abstraction::types::VfsFileType::RegularFile => '-',
            _ => '?',
        };

        info!("{}  {:>10}  {}", type_char, entry.ino, entry.name);
    }

    Ok(())
}

/// Install the service.
fn cmd_service_install() -> Result<()> {
    #[cfg(windows)]
    {
        fs_winfsp_glue::service::install_service()
            .map_err(|e| fs_winfsp_glue::error::XfsWinfspError::WinFspError(e.to_string()))?;
        info!("XFS service installed successfully.");
        info!("Start it with: xfs-mount service start");
    }
    #[cfg(not(windows))]
    {
        info!("Service management is only available on Windows.");
    }
    Ok(())
}

/// Uninstall the service.
fn cmd_service_uninstall() -> Result<()> {
    #[cfg(windows)]
    {
        fs_winfsp_glue::service::uninstall_service()
            .map_err(|e| XfsWinfspError::WinFspError(e.to_string()))?;
        info!("XFS service uninstalled successfully.");
    }
    #[cfg(not(windows))]
    {
        info!("Service management is only available on Windows.");
    }
    Ok(())
}

/// Start the service.
fn cmd_service_start() -> Result<()> {
    #[cfg(windows)]
    {
        service::start_service()
            .map_err(|e: Box<dyn std::error::Error>| XfsWinfspError::WinFspError(e.to_string()))?;
        info!("XFS service started.");
    }
    #[cfg(not(windows))]
    {
        info!("Service management is only available on Windows.");
    }
    Ok(())
}

/// Stop the service.
fn cmd_service_stop() -> Result<()> {
    #[cfg(windows)]
    {
        service::stop_service()
            .map_err(|e: Box<dyn std::error::Error>| XfsWinfspError::WinFspError(e.to_string()))?;
        info!("XFS service stopped.");
    }
    #[cfg(not(windows))]
    {
        info!("Service management is only available on Windows.");
    }
    Ok(())
}

/// Run as a service.
fn cmd_service_run() -> Result<()> {
    #[cfg(windows)]
    {
        service::run_as_service()
            .map_err(|e: Box<dyn std::error::Error>| XfsWinfspError::WinFspError(e.to_string()))?;
    }
    #[cfg(not(windows))]
    {
        info!("Service management is only available on Windows.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cmd_mount` must refuse write mode immediately, before touching any
    /// device, because the block allocator stubs are not implemented.
    ///
    /// Passing a non-existent disk number as source proves the early return
    /// happens *before* device open: if the guard were absent, the call
    /// would fail with a disk-open error instead of the allocator message.
    #[test]
    fn cmd_mount_write_mode_fails_before_device_open() {
        let opts = MountOptions {
            source: MountSource::DiskNumber(u32::MAX), // no such physical disk
            mount_point: "X:".to_string(),
            read_only: false, // request write mode
            ..MountOptions::default()
        };
        let err = cmd_mount(opts).expect_err("--rw must return an error");
        let msg = err.to_string();
        assert!(
            msg.contains("block allocator not implemented"),
            "error must mention the missing allocator, got: {msg}"
        );
    }

    #[test]
    fn partition_source_is_not_truncated_to_its_first_character() {
        assert!(matches!(
            resolve_mount_source(None, None, Some("DD:".to_string()), None),
            Err(XfsWinfspError::InvalidArgument(_))
        ));
        let source = resolve_mount_source(None, None, Some("d:".to_string()), None).unwrap();
        assert!(matches!(source, MountSource::Partition('D')));
    }

    #[test]
    fn cli_requires_exactly_one_source() {
        assert!(Cli::try_parse_from(["xfs-mount", "mount", "--mount-point", "X:"]).is_err());
        assert!(Cli::try_parse_from(["xfs-mount", "info"]).is_err());
        assert!(Cli::try_parse_from(["xfs-mount", "ls", "/"]).is_err());
        assert!(Cli::try_parse_from([
            "xfs-mount",
            "mount",
            "--disk",
            "0",
            "--image",
            "disk.img",
            "--mount-point",
            "X:",
        ])
        .is_err());
    }

    #[test]
    fn service_run_arguments_match_the_cli() {
        let cli = Cli::try_parse_from(["xfs-mount", "service", "run"]).unwrap();
        assert!(matches!(
            cli.command,
            Commands::Service {
                action: ServiceAction::Run
            }
        ));
    }
}
