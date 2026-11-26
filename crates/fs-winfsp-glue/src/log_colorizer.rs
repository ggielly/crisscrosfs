//! Module for adding visual patterns to log output.
//!
//! This module provides functionality to add visual markers to log messages,
//! making them easier to read and parse visually.

/// Adds a visual pattern to WinFSP log lines to make them stand out
pub struct WinFspLogVisualMarker;

impl WinFspLogVisualMarker {
    /// Adds a visual marker to a single WinFSP log line
    pub fn add_visual_marker(line: &str) -> String {
        // Add 4 white vertical bars at the beginning to make WinFSP logs stand
        // out
        format!("|||| {}", line)
    }
}

/// A utility function to add visual markers to multiple log lines
pub fn add_visual_markers_to_log_lines(lines: &str) -> String {
    lines
        .lines()
        .map(WinFspLogVisualMarker::add_visual_marker)
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_visual_marker() {
        let line = "crisscrossfs[TID=20e8]: FFFFD18C537D5DE0: >>Create IoStatus=0[1]";
        let marked = WinFspLogVisualMarker::add_visual_marker(line);
        assert!(marked.starts_with("|||| "));
        assert!(marked.contains("crisscrossfs[TID=20e8]"));
    }
}
