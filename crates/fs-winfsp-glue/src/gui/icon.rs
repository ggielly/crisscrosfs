//! Application icon.
//!
//! The icon is generated at build time by `assets/make-icon.py` into a raw
//! 32x32 BGRA buffer and turned into an `HICON` at runtime with
//! `CreateDIBSection` + `CreateIconIndirect`.  This avoids shipping a resource
//! file and an `rc.exe` build step.

use std::{ffi::c_void, mem::size_of, ptr};

use windows::Win32::{
    Foundation::{BOOL, HANDLE, HINSTANCE},
    Graphics::Gdi::{
        CreateBitmap,
        CreateDIBSection,
        DeleteObject,
        BITMAPINFO,
        BITMAPINFOHEADER,
        BI_RGB,
        DIB_RGB_COLORS,
        HBITMAP,
        HDC,
        HGDIOBJ,
    },
    UI::WindowsAndMessaging::{
        CreateIconIndirect,
        LoadIconW,
        HICON,
        ICONINFO,
        IDI_APPLICATION,
        IDI_WARNING,
    },
};

const ICON_SIZE: i32 = 32;

/// Raw 32x32 RGBA pixels, top-down.
const ICON_RGBA: &[u8] = include_bytes!("../../assets/icon-32.rgba");

/// Build the application icon, falling back to the generic Windows icon.
pub fn app_icon() -> HICON {
    unsafe { build_icon().unwrap_or_else(|_| generic_icon()) }
}

/// Generic fallback icon, also used if the generated icon fails to load.
pub fn generic_icon() -> HICON {
    unsafe { LoadIconW(HINSTANCE(ptr::null_mut()), IDI_APPLICATION).unwrap_or_default() }
}

/// Small system warning icon shown next to the status line when the last mount
/// or unmount left the volume in an inconsistent state.
pub fn warning_icon() -> HICON {
    unsafe { LoadIconW(HINSTANCE(ptr::null_mut()), IDI_WARNING).unwrap_or_else(|_| generic_icon()) }
}

unsafe fn build_icon() -> windows::core::Result<HICON> {
    debug_assert_eq!(ICON_RGBA.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);

    let mut info = BITMAPINFO::default();
    info.bmiHeader.biSize = size_of::<BITMAPINFOHEADER>() as u32;
    info.bmiHeader.biWidth = ICON_SIZE;
    // Negative height selects a top-down DIB, matching the RGBA buffer order.
    info.bmiHeader.biHeight = -ICON_SIZE;
    info.bmiHeader.biPlanes = 1;
    info.bmiHeader.biBitCount = 32;
    info.bmiHeader.biCompression = BI_RGB.0;

    let mut bits: *mut c_void = ptr::null_mut();
    let color: HBITMAP = CreateDIBSection(
        HDC(ptr::null_mut()),
        &info,
        DIB_RGB_COLORS,
        &mut bits,
        HANDLE(ptr::null_mut()),
        0,
    )?;

    if !bits.is_null() {
        ptr::copy_nonoverlapping(ICON_RGBA.as_ptr(), bits as *mut u8, ICON_RGBA.len());
    }

    // An all-zero AND mask; the 32bpp colour bitmap carries the alpha channel.
    let mask = CreateBitmap(ICON_SIZE, ICON_SIZE, 1, 1, None);

    let icon_info = ICONINFO {
        fIcon: BOOL(1),
        xHotspot: 0,
        yHotspot: 0,
        hbmMask: mask,
        hbmColor: color,
    };
    let icon = CreateIconIndirect(&icon_info);

    let _ = DeleteObject(HGDIOBJ(color.0));
    let _ = DeleteObject(HGDIOBJ(mask.0));

    icon
}
