//! Native file picker for XFS image files.

// Win32 dialog structures are populated field-by-field before the FFI call.
#![allow(clippy::field_reassign_with_default)]

use std::{mem::size_of, path::PathBuf};

use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::HWND,
        UI::Controls::Dialogs::{
            GetOpenFileNameW,
            OFN_EXPLORER,
            OFN_FILEMUSTEXIST,
            OFN_NOCHANGEDIR,
            OFN_PATHMUSTEXIST,
            OPENFILENAMEW,
        },
    },
};

/// Show the common "Open" dialog and return the selected image path.
pub fn pick_xfs_image(owner: HWND) -> Option<PathBuf> {
    let filter: Vec<u16> = "XFS images (*.img;*.raw;*.xfs)\0*.img;*.raw;*.xfs\0All files \
                            (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();
    let title: Vec<u16> = "Select an XFS image file\0".encode_utf16().collect();
    let default_ext: Vec<u16> = "img\0".encode_utf16().collect();

    let mut file = vec![0u16; 1024];

    let mut dialog = OPENFILENAMEW::default();
    dialog.lStructSize = size_of::<OPENFILENAMEW>() as u32;
    dialog.hwndOwner = owner;
    dialog.lpstrFilter = PCWSTR(filter.as_ptr());
    dialog.lpstrFile = PWSTR(file.as_mut_ptr());
    dialog.nMaxFile = file.len() as u32;
    dialog.lpstrTitle = PCWSTR(title.as_ptr());
    dialog.lpstrDefExt = PCWSTR(default_ext.as_ptr());
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;

    let accepted = unsafe { GetOpenFileNameW(&mut dialog) };
    if !accepted.as_bool() {
        return None;
    }

    let length = file.iter().position(|&unit| unit == 0).unwrap_or(0);
    if length == 0 {
        return None;
    }
    Some(PathBuf::from(String::from_utf16_lossy(&file[..length])))
}
