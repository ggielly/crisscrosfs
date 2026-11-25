//! Path utilities for XFS on Windows.
//!
//! Handles both Windows-style paths (backslash) and Unix-style paths (forward
//! slash).

/// Iterator over components of a path.
///
/// Handles both Windows (`\`) and Unix (`/`) separators.
///
/// # Examples
/// ```
/// use fs_winfsp_glue::path::PathComponents;
/// let path = "\\folder\\subfolder\\file.txt";
/// let components: Vec<_> = PathComponents::new(path).collect();
/// assert_eq!(components, vec!["folder", "subfolder", "file.txt"]);
/// ```
pub struct PathComponents<'a> {
    path: &'a str,
    offset: usize,
}

impl<'a> PathComponents<'a> {
    /// Creates a new path component iterator.
    pub fn new(path: &'a str) -> Self {
        // Skip leading separators
        let mut offset = 0;
        let bytes = path.as_bytes();
        while offset < bytes.len() && (bytes[offset] == b'\\' || bytes[offset] == b'/') {
            offset += 1;
        }
        Self { path, offset }
    }

    /// Creates from a path, normalizing separators.
    pub fn from_windows_path(path: &'a str) -> Self {
        Self::new(path)
    }
}

impl<'a> Iterator for PathComponents<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.path.len() {
            return None;
        }

        let bytes = self.path.as_bytes();
        let start = self.offset;
        let mut end = start;

        // Find next separator
        while end < bytes.len() && bytes[end] != b'\\' && bytes[end] != b'/' {
            end += 1;
        }

        let component = &self.path[start..end];

        // Advance offset past the separator(s)
        self.offset = end;
        while self.offset < bytes.len()
            && (bytes[self.offset] == b'\\' || bytes[self.offset] == b'/')
        {
            self.offset += 1;
        }

        if component.is_empty() && self.offset >= self.path.len() {
            None
        } else {
            Some(component)
        }
    }
}

/// Wide string path iterator (for Windows APIs that use UTF-16).
pub struct WidePathComponents<'a> {
    path: &'a [u16],
    offset: usize,
}

impl<'a> WidePathComponents<'a> {
    /// Creates a new iterator from a wide character slice.
    pub fn new(path: &'a [u16]) -> Self {
        // Skip leading separators
        let mut offset = 0;
        while offset < path.len() && (path[offset] == '\\' as u16 || path[offset] == '/' as u16) {
            offset += 1;
        }
        Self { path, offset }
    }

    /// Converts the component to a String.
    pub fn component_to_string(component: &[u16]) -> String {
        String::from_utf16_lossy(component)
    }
}

impl<'a> Iterator for WidePathComponents<'a> {
    type Item = &'a [u16];

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.path.len() {
            return None;
        }

        let start = self.offset;
        let mut end = start;

        // Find next separator
        while end < self.path.len() && self.path[end] != '\\' as u16 && self.path[end] != '/' as u16
        {
            end += 1;
        }

        let component = &self.path[start..end];

        // Advance offset past the separator(s)
        self.offset = end;
        while self.offset < self.path.len()
            && (self.path[self.offset] == '\\' as u16 || self.path[self.offset] == '/' as u16)
        {
            self.offset += 1;
        }

        if component.is_empty() && self.offset >= self.path.len() {
            None
        } else {
            Some(component)
        }
    }
}

/// Normalizes a path by replacing forward slashes with backslashes.
pub fn normalize_path(path: &str) -> String {
    path.replace('/', "\\")
}

/// Joins path components with backslash separator.
pub fn join_path(components: &[&str]) -> String {
    components.join("\\")
}

/// Gets the parent path (removes the last component).
pub fn parent_path(path: &str) -> Option<&str> {
    let path = path.trim_end_matches(['\\', '/']);
    if path.is_empty() {
        return None;
    }

    // Find last separator
    for (i, c) in path.char_indices().rev() {
        if c == '\\' || c == '/' {
            if i == 0 {
                return Some("\\");
            }
            return Some(&path[..i]);
        }
    }

    None // No parent (root level)
}

/// Gets the file name (last component) from a path.
pub fn file_name(path: &str) -> Option<&str> {
    let path = path.trim_end_matches(['\\', '/']);
    if path.is_empty() {
        return None;
    }

    // Find last separator
    for (i, c) in path.char_indices().rev() {
        if c == '\\' || c == '/' {
            return Some(&path[i + 1..]);
        }
    }

    Some(path) // No separator, whole string is the name
}

/// Checks if a path is absolute (starts with separator or drive letter).
pub fn is_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return false;
    }

    // Starts with separator
    if bytes[0] == b'\\' || bytes[0] == b'/' {
        return true;
    }

    // Windows drive letter (e.g., "C:\")
    if bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
    {
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_components() {
        let path = "\\folder\\subfolder\\file.txt";
        let components: Vec<_> = PathComponents::new(path).collect();
        assert_eq!(components, vec!["folder", "subfolder", "file.txt"]);
    }

    #[test]
    fn test_path_components_forward_slash() {
        let path = "/folder/subfolder/file.txt";
        let components: Vec<_> = PathComponents::new(path).collect();
        assert_eq!(components, vec!["folder", "subfolder", "file.txt"]);
    }

    #[test]
    fn test_path_components_mixed() {
        let path = "\\folder/subfolder\\file.txt";
        let components: Vec<_> = PathComponents::new(path).collect();
        assert_eq!(components, vec!["folder", "subfolder", "file.txt"]);
    }

    #[test]
    fn test_file_name() {
        assert_eq!(file_name("\\folder\\file.txt"), Some("file.txt"));
        assert_eq!(file_name("file.txt"), Some("file.txt"));
        assert_eq!(file_name("\\folder\\"), Some("folder"));
    }

    #[test]
    fn test_parent_path() {
        assert_eq!(parent_path("\\folder\\file.txt"), Some("\\folder"));
        assert_eq!(parent_path("\\folder"), Some("\\"));
        assert_eq!(parent_path("\\"), None);
    }

    #[test]
    fn test_is_absolute() {
        assert!(is_absolute("\\folder"));
        assert!(is_absolute("/folder"));
        assert!(is_absolute("C:\\folder"));
        assert!(!is_absolute("folder"));
        assert!(!is_absolute("folder\\file"));
    }
}
