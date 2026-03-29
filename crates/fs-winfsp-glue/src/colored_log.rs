//! Colored logging helpers for filesystem operations.
//!
//! Provides ANSI color codes and visual patterns for different types of
//! operations.

use std::sync::atomic::{AtomicBool, Ordering};

/// Global flag to enable/disable colored output
static COLOR_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable colored output globally
pub fn enable_colors() {
    COLOR_ENABLED.store(true, Ordering::SeqCst);
}

/// Check if colors are enabled
pub fn colors_enabled() -> bool {
    COLOR_ENABLED.load(Ordering::SeqCst)
}

/// ANSI color codes
pub mod colors {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";

    // File/Directory type colors
    pub const DIR_COLOR: &str = "\x1b[1;34m"; // Bold Blue for directories
    pub const FILE_COLOR: &str = "\x1b[0;37m"; // White for files
    pub const SYMLINK_COLOR: &str = "\x1b[1;36m"; // Bold Cyan for symlinks

    // Operation type colors
    pub const CREATE_COLOR: &str = "\x1b[1;32m"; // Bold Green for create
    pub const DELETE_COLOR: &str = "\x1b[1;31m"; // Bold Red for delete
    pub const RENAME_COLOR: &str = "\x1b[1;35m"; // Bold Magenta for rename
    pub const READ_COLOR: &str = "\x1b[0;36m"; // Cyan for read
    pub const WRITE_COLOR: &str = "\x1b[0;33m"; // Yellow for write
    pub const OPEN_COLOR: &str = "\x1b[0;32m"; // Green for open
    pub const CLOSE_COLOR: &str = "\x1b[0;90m"; // Gray for close

    // Status colors
    pub const SUCCESS_COLOR: &str = "\x1b[1;32m"; // Bold Green
    pub const ERROR_COLOR: &str = "\x1b[1;31m"; // Bold Red
    pub const WARN_COLOR: &str = "\x1b[1;33m"; // Bold Yellow
    pub const INFO_COLOR: &str = "\x1b[0;36m"; // Cyan
}

/// Visual patterns/symbols for operations
pub mod symbols {
    // Operation symbols
    pub const CREATE_DIR: &str = "📁➕"; // Folder + plus
    pub const CREATE_FILE: &str = "📄➕"; // File + plus
    pub const DELETE_DIR: &str = "📁❌"; // Folder + X
    pub const DELETE_FILE: &str = "📄❌"; // File + X
    pub const RENAME: &str = "🔄"; // Refresh symbol
    pub const OPEN_DIR: &str = "📂"; // Open folder
    pub const OPEN_FILE: &str = "📄"; // File
    pub const READ: &str = "👁️"; // Eye for read
    pub const WRITE: &str = "✏️"; // Pencil for write
    pub const CLOSE: &str = "🔒"; // Lock for close
    pub const SUCCESS: &str = "✅"; // Checkmark
    pub const ERROR: &str = "❌"; // X mark
    pub const WARN: &str = "⚠️"; // Warning
    pub const DENIED: &str = "🚫"; // No entry

    // Simple ASCII fallbacks (for terminals without emoji support)
    pub const CREATE_DIR_ASCII: &str = "[+DIR]";
    pub const CREATE_FILE_ASCII: &str = "[+FILE]";
    pub const DELETE_DIR_ASCII: &str = "[-DIR]";
    pub const DELETE_FILE_ASCII: &str = "[-FILE]";
    pub const RENAME_ASCII: &str = "[RENAME]";
    pub const OPEN_DIR_ASCII: &str = "[OPENDIR]";
    pub const OPEN_FILE_ASCII: &str = "[OPEN]";
    pub const READ_ASCII: &str = "[READ]";
    pub const WRITE_ASCII: &str = "[WRITE]";
    pub const CLOSE_ASCII: &str = "[CLOSE]";
}

use colors::*;
use symbols::*;

/// Format a directory path with color
pub fn fmt_dir(path: &str) -> String {
    format!("{}{}{}", DIR_COLOR, path, RESET)
}

/// Format a file path with color
pub fn fmt_file(path: &str) -> String {
    format!("{}{}{}", FILE_COLOR, path, RESET)
}

/// Format a symlink path with color
pub fn fmt_symlink(path: &str) -> String {
    format!("{}{}{}", SYMLINK_COLOR, path, RESET)
}

/// Log a create directory operation
pub fn log_create_dir(path: &str) -> String {
    format!(
        "{}{} CREATE DIR{}: {}{}{}",
        CREATE_COLOR, CREATE_DIR_ASCII, RESET, DIR_COLOR, path, RESET
    )
}

/// Log a create file operation
pub fn log_create_file(path: &str) -> String {
    format!(
        "{}{} CREATE FILE{}: {}{}{}",
        CREATE_COLOR, CREATE_FILE_ASCII, RESET, FILE_COLOR, path, RESET
    )
}

/// Log a delete directory operation
pub fn log_delete_dir(path: &str) -> String {
    format!(
        "{}{} DELETE DIR{}: {}{}{}",
        DELETE_COLOR, DELETE_DIR_ASCII, RESET, DIR_COLOR, path, RESET
    )
}

/// Log a delete file operation  
pub fn log_delete_file(path: &str) -> String {
    format!(
        "{}{} DELETE FILE{}: {}{}{}",
        DELETE_COLOR, DELETE_FILE_ASCII, RESET, FILE_COLOR, path, RESET
    )
}

/// Log a rename operation
pub fn log_rename(old_path: &str, new_path: &str, is_dir: bool) -> String {
    let type_str = if is_dir { "DIR" } else { "FILE" };
    let color = if is_dir { DIR_COLOR } else { FILE_COLOR };
    format!(
        "{}{} RENAME {}{}: {}{}{} -> {}{}{}",
        RENAME_COLOR, RENAME_ASCII, type_str, RESET, color, old_path, RESET, color, new_path, RESET
    )
}

/// Log an open directory operation
pub fn log_open_dir(path: &str) -> String {
    format!(
        "{}{} OPEN DIR{}: {}{}{}",
        OPEN_COLOR, OPEN_DIR_ASCII, RESET, DIR_COLOR, path, RESET
    )
}

/// Log an open file operation
pub fn log_open_file(path: &str) -> String {
    format!(
        "{}{} OPEN FILE{}: {}{}{}",
        OPEN_COLOR, OPEN_FILE_ASCII, RESET, FILE_COLOR, path, RESET
    )
}

/// Log a read operation
pub fn log_read(path: &str, offset: u64, len: usize) -> String {
    format!(
        "{}{} READ{}: {}{}{} offset={} len={}",
        READ_COLOR, READ_ASCII, RESET, FILE_COLOR, path, RESET, offset, len
    )
}

/// Log a write operation
pub fn log_write(path: &str, offset: u64, len: usize) -> String {
    format!(
        "{}{} WRITE{}: {}{}{} offset={} len={}",
        WRITE_COLOR, WRITE_ASCII, RESET, FILE_COLOR, path, RESET, offset, len
    )
}

/// Log a close operation
pub fn log_close(inode: u64, is_dir: bool) -> String {
    let type_str = if is_dir { "DIR" } else { "FILE" };
    format!(
        "{}{} CLOSE {}{}: inode={}",
        CLOSE_COLOR, CLOSE_ASCII, type_str, RESET, inode
    )
}

/// Log success
pub fn log_success(msg: &str) -> String {
    format!("{}{} {}{}", SUCCESS_COLOR, SUCCESS_ASCII, msg, RESET)
}

/// Log error
pub fn log_error(msg: &str) -> String {
    format!("{}{} {}{}", ERROR_COLOR, ERROR_ASCII, msg, RESET)
}

/// Log warning
pub fn log_warn(msg: &str) -> String {
    format!("{}{} {}{}", WARN_COLOR, WARN_ASCII, msg, RESET)
}

/// Log access denied
pub fn log_denied(operation: &str, path: &str) -> String {
    format!(
        "{}{} {} DENIED{}: {}{}{}",
        ERROR_COLOR, DENIED_ASCII, operation, RESET, FILE_COLOR, path, RESET
    )
}

// ASCII symbols for status
const SUCCESS_ASCII: &str = "[OK]";
const ERROR_ASCII: &str = "[ERR]";
const WARN_ASCII: &str = "[WARN]";
const DENIED_ASCII: &str = "[DENIED]";

/// Get current timestamp string
fn timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let millis = now.subsec_millis();
    // Simple timestamp format HH:MM:SS.mmm
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let secs = secs % 60;
    format!("{:02}:{:02}:{:02}.{:03}", hours, mins, secs, millis)
}

/// Print a colored log line directly to stderr (bypasses tracing)
pub fn print_colored(level: &str, msg: &str) {
    use colors::*;
    if colors_enabled() {
        let level_color = match level {
            "DEBUG" => "\x1b[0;36m", // Cyan
            "INFO" => "\x1b[0;32m",  // Green
            "WARN" => "\x1b[0;33m",  // Yellow
            "ERROR" => "\x1b[0;31m", // Red
            "TRACE" => "\x1b[0;90m", // Gray
            _ => RESET,
        };
        eprintln!(
            "\x1b[0;90m{}\x1b[0m {}{}  {}\x1b[0m {}",
            timestamp(),
            level_color,
            level,
            RESET,
            msg
        );
    } else {
        eprintln!("{} {} {}", timestamp(), level, msg);
    }
}

/// Macros for colored logging that bypass tracing
#[macro_export]
macro_rules! clog_debug {
    ($($arg:tt)*) => {
        $crate::colored_log::print_colored("DEBUG", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! clog_info {
    ($($arg:tt)*) => {
        $crate::colored_log::print_colored("INFO", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! clog_warn {
    ($($arg:tt)*) => {
        $crate::colored_log::print_colored("WARN", &format!($($arg)*))
    };
}

#[macro_export]
macro_rules! clog_error {
    ($($arg:tt)*) => {
        $crate::colored_log::print_colored("ERROR", &format!($($arg)*))
    };
}
