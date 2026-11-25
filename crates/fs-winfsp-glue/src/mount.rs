//! Mount options and configuration.

use std::path::{Path, PathBuf};

use crate::error::{Result, XfsWinfspError};

/// Options for mounting an XFS filesystem.
#[derive(Debug, Clone)]
pub struct MountOptions {
    /// Source: either a disk number, partition, or image file path.
    pub source: MountSource,
    /// Mount point (drive letter like "X:" or path).
    pub mount_point: String,
    /// Read-only mode (always true for now).
    pub read_only: bool,
    /// Debug mode.
    pub debug: bool,
    /// Volume prefix for WinFsp.
    pub volume_prefix: Option<String>,
    /// File system name shown in Explorer.
    pub filesystem_name: String,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            source: MountSource::DiskNumber(0),
            mount_point: "X:".to_string(),
            read_only: true,
            debug: false,
            volume_prefix: None,
            filesystem_name: "XFS".to_string(),
        }
    }
}

/// Source for mounting.
#[derive(Debug, Clone)]
pub enum MountSource {
    /// Physical disk number (0, 1, 2...).
    DiskNumber(u32),
    /// Drive letter for a partition.
    Partition(char),
    /// Path to disk device.
    DiskPath(String),
    /// Path to image file.
    ImageFile(PathBuf),
}

impl MountSource {
    /// Validate a source before passing it to a disk-opening API.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::DiskNumber(_) => Ok(()),
            Self::Partition(letter) if letter.is_ascii_alphabetic() => Ok(()),
            Self::Partition(letter) => Err(XfsWinfspError::InvalidArgument(format!(
                "Partition must be exactly one ASCII drive letter, got {letter:?}"
            ))),
            Self::DiskPath(path) => validate_non_empty_path(path, "disk path"),
            Self::ImageFile(path) => validate_non_empty_path(path, "image path"),
        }
    }
}

impl MountOptions {
    /// Validate all user-controlled mount inputs.
    ///
    /// Write mode is rejected structurally: the allocator and journal write
    /// paths are not complete yet, so no caller may accidentally enable them.
    pub fn validate(&self) -> Result<()> {
        self.source.validate()?;
        validate_mount_point(&self.mount_point)?;
        if !self.read_only {
            return Err(XfsWinfspError::InvalidArgument(
                "Read-write mounting is disabled".to_string(),
            ));
        }
        Ok(())
    }

    /// Create mount options for a physical disk.
    pub fn disk(disk_number: u32, mount_point: &str) -> Self {
        Self {
            source: MountSource::DiskNumber(disk_number),
            mount_point: mount_point.to_string(),
            ..Default::default()
        }
    }

    /// Create mount options for an image file.
    pub fn image<P: Into<PathBuf>>(path: P, mount_point: &str) -> Self {
        Self {
            source: MountSource::ImageFile(path.into()),
            mount_point: mount_point.to_string(),
            ..Default::default()
        }
    }

    /// Create mount options for a partition.
    pub fn partition(drive_letter: char, mount_point: &str) -> Self {
        Self {
            source: MountSource::Partition(drive_letter),
            mount_point: mount_point.to_string(),
            ..Default::default()
        }
    }
}

/// Parse a partition argument such as `D` or `D:`.
///
/// Only one ASCII letter, with an optional trailing colon, is accepted. In
/// particular, inputs such as `DD:`, `D:\\`, and `1:` must never be truncated
/// to their first character.
pub fn parse_partition(value: &str) -> Result<char> {
    let bytes = value.as_bytes();
    let letter = match bytes {
        [letter] if letter.is_ascii_alphabetic() => *letter,
        [letter, b':'] if letter.is_ascii_alphabetic() => *letter,
        _ => {
            return Err(XfsWinfspError::InvalidArgument(format!(
                "Partition must be exactly one ASCII letter with an optional colon, got {value:?}"
            )))
        }
    };
    Ok((letter as char).to_ascii_uppercase())
}

/// Validate a WinFsp mount point and return its canonical drive-letter form.
///
/// WinFsp accepts either a drive letter (`X:`) or a directory path. A drive
/// letter is normalised to uppercase without a trailing root separator. Paths
/// containing a colon must have a valid ASCII drive prefix; malformed values
/// such as `XX:` or `1:` are rejected rather than handed to WinFsp.
pub fn validate_mount_point(value: &str) -> Result<String> {
    if value.is_empty() || value.contains('\0') {
        return Err(XfsWinfspError::InvalidArgument(
            "Mount point must be a non-empty path without NUL bytes".to_string(),
        ));
    }

    if let Some(colon) = value.find(':') {
        let bytes = value.as_bytes();
        if colon != 1 || !bytes[0].is_ascii_alphabetic() {
            return Err(XfsWinfspError::InvalidArgument(format!(
                "Invalid mount point {value:?}: a drive prefix must be one ASCII letter"
            )));
        }

        let rest = &value[2..];
        if rest.is_empty() {
            return Ok(format!("{}:", (bytes[0] as char).to_ascii_uppercase()));
        }
        if rest.chars().all(|c| c == '\\' || c == '/') {
            return Ok(format!("{}:", (bytes[0] as char).to_ascii_uppercase()));
        }
        if !rest.starts_with('\\') && !rest.starts_with('/') {
            return Err(XfsWinfspError::InvalidArgument(format!(
                "Invalid mount point {value:?}: drive-relative paths are not supported"
            )));
        }
    }

    Ok(value.to_string())
}

fn validate_non_empty_path<P: AsRef<Path>>(path: P, description: &str) -> Result<()> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() || path.to_string_lossy().contains('\0') {
        return Err(XfsWinfspError::InvalidArgument(format!(
            "{description} must be a non-empty path without NUL bytes"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_parser_accepts_exactly_one_ascii_letter() {
        assert_eq!(parse_partition("D").unwrap(), 'D');
        assert_eq!(parse_partition("d:").unwrap(), 'D');
        for invalid in ["", "DD", "DD:", "D:\\", "1:", "é:", " D", "D: "] {
            assert!(parse_partition(invalid).is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn mount_point_validation_normalises_drive_letters() {
        assert_eq!(validate_mount_point("x:").unwrap(), "X:");
        assert_eq!(validate_mount_point("X:\\").unwrap(), "X:");
        assert_eq!(validate_mount_point("X:/").unwrap(), "X:");
        assert_eq!(
            validate_mount_point("C:\\mnt\\xfs").unwrap(),
            "C:\\mnt\\xfs"
        );
        for invalid in ["", "XX:", "1:", "C:relative", "X\0:"] {
            assert!(
                validate_mount_point(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn mount_options_reject_invalid_sources_and_write_mode() {
        assert!(MountOptions::partition('é', "X:").validate().is_err());
        assert!(MountOptions::image("", "X:").validate().is_err());
        let mut options = MountOptions::disk(0, "not-a-drive:");
        assert!(options.validate().is_err());
        options.mount_point = "X:".to_string();
        options.read_only = false;
        assert!(options.validate().is_err());
    }
}
