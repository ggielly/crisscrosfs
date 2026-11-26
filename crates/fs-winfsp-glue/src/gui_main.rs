//! Windowless entry point for the XFS Mount GUI.
//!
//! This binary is compiled with the `windows` subsystem so double-clicking it
//! from Explorer (or a Start-menu shortcut) opens the GUI without a console
//! window.  The `xfs-mount gui` subcommand runs the exact same front-end with a
//! console attached, which is handy for development.

#![windows_subsystem = "windows"]

fn main() {
    if let Err(error) = fs_winfsp_glue::gui::run(false) {
        // No console here; surface fatal startup failures in a message box.
        fs_winfsp_glue::gui::report_fatal(&error.to_string());
        std::process::exit(1);
    }
}
