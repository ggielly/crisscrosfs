//! Native Windows front-end for mounting XFS filesystems.
//!
//! Implemented directly on Win32 (User32 + Comctl32) through the `windows`
//! crate: no cross-platform toolkit is involved.  The window lists the XFS
//! volumes found on the machine (plus image files picked by the user), lets the
//! user pick a free drive letter and mount/unmount, and keeps running in the
//! notification area when the window is closed.

mod dialogs;
mod icon;

use std::{ffi::c_void, mem::size_of, thread};

use windows::{
    core::{w, PCWSTR, PWSTR},
    Win32::{
        Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM},
        Graphics::Gdi::{
            CreateFontW,
            CreateSolidBrush,
            DeleteObject,
            CLEARTYPE_QUALITY,
            DEFAULT_CHARSET,
            DEFAULT_PITCH,
            FW_NORMAL,
            HBRUSH,
            HFONT,
        },
        System::LibraryLoader::GetModuleHandleW,
        UI::{
            Controls::{
                InitCommonControlsEx,
                ICC_LISTVIEW_CLASSES,
                INITCOMMONCONTROLSEX,
                LVCFMT_LEFT,
                LVCF_FMT,
                LVCF_TEXT,
                LVCF_WIDTH,
                LVCOLUMNW,
                LVIF_TEXT,
                LVITEMW,
                LVM_DELETEALLITEMS,
                LVM_INSERTCOLUMNW,
                LVM_INSERTITEMW,
                LVM_SETEXTENDEDLISTVIEWSTYLE,
                LVM_SETITEMTEXTW,
                LVS_EX_FULLROWSELECT,
                LVS_REPORT,
                LVS_SINGLESEL,
                NMHDR,
                NM_DBLCLK,
                WC_LISTVIEWW,
            },
            HiDpi::{
                GetDpiForSystem,
                GetDpiForWindow,
                SetProcessDpiAwarenessContext,
                DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
            },
            Input::KeyboardAndMouse::{EnableWindow, SetFocus},
            Shell::{
                ShellExecuteW,
                Shell_NotifyIconW,
                NIF_ICON,
                NIF_MESSAGE,
                NIF_TIP,
                NIM_ADD,
                NIM_DELETE,
                NOTIFYICONDATAW,
            },
            WindowsAndMessaging::{
                AppendMenuW,
                CreatePopupMenu,
                CreateWindowExW,
                DefWindowProcW,
                DestroyIcon,
                DestroyMenu,
                DestroyWindow,
                DispatchMessageW,
                GetClientRect,
                GetCursorPos,
                GetMessageW,
                GetWindowLongPtrW,
                LoadCursorW,
                MessageBoxW,
                MoveWindow,
                PostMessageW,
                PostQuitMessage,
                RegisterClassW,
                SendMessageW,
                SetForegroundWindow,
                SetWindowLongPtrW,
                SetWindowTextW,
                ShowWindow,
                TrackPopupMenu,
                TranslateMessage,
                BS_AUTOCHECKBOX,
                CBS_DROPDOWNLIST,
                CB_ADDSTRING,
                CB_GETCURSEL,
                CB_GETLBTEXT,
                CB_RESETCONTENT,
                CB_SETCURSEL,
                CS_HREDRAW,
                CS_VREDRAW,
                CW_USEDEFAULT,
                GWLP_USERDATA,
                HICON,
                IDC_ARROW,
                MB_ICONERROR,
                MB_OK,
                MF_SEPARATOR,
                MF_STRING,
                SIZE_MINIMIZED,
                SW_HIDE,
                SW_SHOW,
                SW_SHOWNORMAL,
                TPM_BOTTOMALIGN,
                TPM_LEFTALIGN,
                TPM_RIGHTBUTTON,
                WINDOW_EX_STYLE,
                WINDOW_STYLE,
                WM_APP,
                WM_CLOSE,
                WM_COMMAND,
                WM_CONTEXTMENU,
                WM_DESTROY,
                WM_LBUTTONDBLCLK,
                WM_NOTIFY,
                WM_NULL,
                WM_RBUTTONUP,
                WM_SETFONT,
                WM_SIZE,
                WNDCLASSW,
                WS_BORDER,
                WS_CHILD,
                WS_OVERLAPPEDWINDOW,
                WS_TABSTOP,
                WS_VISIBLE,
                WS_VSCROLL,
            },
        },
    },
};

use crate::{
    disk::XfsDiskInfo,
    error::Result,
    factory,
    mount::{MountOptions, MountSource},
    source::{open_source, source_key},
    winfsp_mount::{self, MountHandle},
};

const WM_APP_TRAY: u32 = WM_APP + 1;
const WM_APP_SCAN_DONE: u32 = WM_APP + 2;
const TRAY_ICON_ID: u32 = 1;

const IDC_HINT: i32 = 1001;
const IDC_LIST: i32 = 1002;
const IDC_LABEL: i32 = 1003;
const IDC_DRIVE: i32 = 1004;
const IDC_RW: i32 = 1005;
const IDC_MOUNT: i32 = 1006;
const IDC_UNMOUNT: i32 = 1007;
const IDC_OPEN: i32 = 1008;
const IDC_RESCAN: i32 = 1009;
const IDC_BROWSE: i32 = 1010;
const IDC_STATUS: i32 = 1011;

const IDM_SHOW: usize = 4001;
const IDM_UNMOUNT_ALL: usize = 4002;
const IDM_EXIT: usize = 4003;

/// Launch the GUI.  Blocks until the last window is destroyed.
pub fn run(debug: bool) -> Result<()> {
    unsafe { run_inner(debug) }.map_err(|e| crate::XfsWinfspError::WinFspError(e.to_string()))
}

/// Report a fatal startup error.  Used by the windowless binary, which has no
/// console to print to.
pub fn report_fatal(message: &str) {
    unsafe {
        let text = wide(message);
        let caption = wide("XFS Mount");
        MessageBoxW(
            HWND(std::ptr::null_mut()),
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }
}

unsafe fn run_inner(debug: bool) -> windows::core::Result<()> {
    let init = INITCOMMONCONTROLSEX {
        dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_LISTVIEW_CLASSES,
    };
    let _ = InitCommonControlsEx(&init);

    // Own the scaling ourselves: the layout below multiplies every metric by
    // the window DPI instead of relying on bitmap stretching.
    let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    let system_dpi = GetDpiForSystem().max(96) as i32;

    let module = GetModuleHandleW(None)?;
    let hinstance = HINSTANCE(module.0);
    let icon = icon::app_icon();
    let bg_brush = CreateSolidBrush(COLORREF(0x00F0_F0F0));

    let class_name = w!("XfsMountMainWindow");
    let wc = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(wndproc),
        cbClsExtra: 0,
        cbWndExtra: 0,
        hInstance: hinstance,
        hIcon: icon,
        hCursor: LoadCursorW(None, IDC_ARROW)?,
        hbrBackground: bg_brush,
        lpszMenuName: PCWSTR::null(),
        lpszClassName: class_name,
    };
    if RegisterClassW(&wc) == 0 {
        return Err(windows::core::Error::from_win32());
    }

    let hwnd = CreateWindowExW(
        WINDOW_EX_STYLE(0),
        class_name,
        w!("XFS Mount"),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        820 * system_dpi / 96,
        560 * system_dpi / 96,
        HWND(std::ptr::null_mut()),
        windows::Win32::UI::WindowsAndMessaging::HMENU(std::ptr::null_mut()),
        hinstance,
        None,
    )?;

    let app = Box::new(App::new(hwnd, hinstance, icon, bg_brush, debug));
    let app_ptr = Box::into_raw(app);
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, app_ptr as isize);

    let app = &mut *app_ptr;
    app.build_children()?;
    app.install_tray();
    app.layout();
    app.start_scan();

    let _ = ShowWindow(hwnd, SW_SHOW);
    let _ = SetFocus(hwnd);

    let mut msg = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    while GetMessageW(&mut msg, HWND(std::ptr::null_mut()), 0, 0).as_bool() {
        let _ = TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // The window procedure posted WM_QUIT from WM_DESTROY; reclaim the state.
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
    drop(Box::from_raw(app_ptr));

    Ok(())
}

unsafe fn create_ui_font(dpi: i32) -> HFONT {
    CreateFontW(
        -13 * dpi / 96,
        0,
        0,
        0,
        FW_NORMAL.0 as i32,
        0,
        0,
        0,
        DEFAULT_CHARSET.0 as u32,
        0,
        0,
        CLEARTYPE_QUALITY.0 as u32,
        DEFAULT_PITCH.0 as u32,
        w!("Segoe UI"),
    )
}

struct ActiveMount {
    key: String,
    mount_point: String,
    handle: Option<MountHandle>,
}

/// One row of the volume list.
#[derive(Clone)]
struct Entry {
    source: MountSource,
    detail: String,
    label: String,
    size: u64,
}

struct App {
    hwnd: HWND,
    hinstance: HINSTANCE,
    icon: HICON,
    font: HFONT,
    bg_brush: HBRUSH,
    debug: bool,

    hint: HWND,
    list: HWND,
    label: HWND,
    combo: HWND,
    rw_check: HWND,
    btn_mount: HWND,
    btn_unmount: HWND,
    btn_open: HWND,
    btn_rescan: HWND,
    btn_browse: HWND,
    status: HWND,

    entries: Vec<Entry>,
    mounts: Vec<ActiveMount>,
    scanning: bool,
    tray_added: bool,
    read_write: bool,
    exiting: bool,
}

impl App {
    fn new(hwnd: HWND, hinstance: HINSTANCE, icon: HICON, bg_brush: HBRUSH, debug: bool) -> Self {
        Self {
            hwnd,
            hinstance,
            icon,
            font: HFONT::default(),
            bg_brush,
            debug,
            hint: HWND::default(),
            list: HWND::default(),
            label: HWND::default(),
            combo: HWND::default(),
            rw_check: HWND::default(),
            btn_mount: HWND::default(),
            btn_unmount: HWND::default(),
            btn_open: HWND::default(),
            btn_rescan: HWND::default(),
            btn_browse: HWND::default(),
            status: HWND::default(),
            entries: Vec::new(),
            mounts: Vec::new(),
            scanning: false,
            tray_added: false,
            read_write: false,
            exiting: false,
        }
    }

    // ---------------------------------------------------------------- layout

    unsafe fn build_children(&mut self) -> windows::core::Result<()> {
        let dpi = self.dpi();
        self.font = create_ui_font(dpi);
        let scale = |value: i32| value * dpi / 96;

        self.hint = self.make_child(
            w!("STATIC"),
            w!(
                "Detected XFS volumes. Pick a free drive letter, then Mount. Closing this window \
                 keeps XFS Mount in the notification area."
            ),
            base(0),
            IDC_HINT,
        )?;

        self.list = self.make_child(
            WC_LISTVIEWW,
            PCWSTR::null(),
            base(LVS_REPORT | LVS_SINGLESEL) | WS_BORDER | WS_TABSTOP,
            IDC_LIST,
        )?;

        for (index, (title, width)) in [
            ("Source", 300),
            ("Label", 140),
            ("Size", 90),
            ("Status", 180),
        ]
        .iter()
        .enumerate()
        {
            let mut text = wide(title);
            let mut column = LVCOLUMNW::default();
            column.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_FMT;
            column.fmt = LVCFMT_LEFT;
            column.cx = scale(*width);
            column.pszText = PWSTR(text.as_mut_ptr());
            SendMessageW(
                self.list,
                LVM_INSERTCOLUMNW,
                WPARAM(index),
                LPARAM(&column as *const _ as isize),
            );
        }
        SendMessageW(
            self.list,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            WPARAM(LVS_EX_FULLROWSELECT as usize),
            LPARAM(LVS_EX_FULLROWSELECT as isize),
        );

        self.label = self.make_child(w!("STATIC"), w!("Mount point:"), base(0), IDC_LABEL)?;
        self.combo = self.make_child(
            w!("COMBOBOX"),
            PCWSTR::null(),
            base(CBS_DROPDOWNLIST as u32) | WS_VSCROLL | WS_TABSTOP,
            IDC_DRIVE,
        )?;
        self.rw_check = self.make_child(
            w!("BUTTON"),
            w!("Read-write (image files)"),
            base(BS_AUTOCHECKBOX as u32) | WS_TABSTOP,
            IDC_RW,
        )?;

        self.btn_mount = self.make_button(w!("Mount"), IDC_MOUNT)?;
        self.btn_unmount = self.make_button(w!("Unmount"), IDC_UNMOUNT)?;
        self.btn_open = self.make_button(w!("Open in Explorer"), IDC_OPEN)?;
        self.btn_rescan = self.make_button(w!("Rescan"), IDC_RESCAN)?;
        self.btn_browse = self.make_button(w!("Mount image..."), IDC_BROWSE)?;

        self.status = self.make_child(w!("STATIC"), w!("Ready."), base(0), IDC_STATUS)?;

        Ok(())
    }

    unsafe fn make_child(
        &self,
        class: PCWSTR,
        text: PCWSTR,
        style: WINDOW_STYLE,
        id: i32,
    ) -> windows::core::Result<HWND> {
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class,
            text,
            WS_CHILD | WS_VISIBLE | style,
            0,
            0,
            10,
            10,
            self.hwnd,
            windows::Win32::UI::WindowsAndMessaging::HMENU(id as isize as *mut c_void),
            self.hinstance,
            None,
        )?;
        SendMessageW(hwnd, WM_SETFONT, WPARAM(self.font.0 as usize), LPARAM(1));
        Ok(hwnd)
    }

    unsafe fn make_button(&self, text: PCWSTR, id: i32) -> windows::core::Result<HWND> {
        self.make_child(w!("BUTTON"), text, WS_TABSTOP, id)
    }

    unsafe fn layout(&self) {
        let mut rect = windows::Win32::Foundation::RECT::default();
        if GetClientRect(self.hwnd, &mut rect).is_err() {
            return;
        }
        let dpi = self.dpi();
        let scale = |value: i32| value * dpi / 96;

        let width = rect.right.max(scale(420));
        let height = rect.bottom.max(scale(320));

        let margin = scale(12);
        let content = width - margin * 2;

        move_to(self.hint, margin, scale(8), content, scale(32));
        move_to(
            self.list,
            margin,
            scale(44),
            content,
            height - scale(44) - scale(156),
        );

        let row_y = height - scale(144);
        move_to(self.label, margin, row_y, scale(90), scale(18));
        move_to(self.combo, margin, row_y + scale(20), scale(90), scale(200));
        move_to(
            self.rw_check,
            margin + scale(104),
            row_y + scale(22),
            scale(210),
            scale(22),
        );

        let button_y = height - scale(96);
        move_to(self.btn_mount, margin, button_y, scale(110), scale(30));
        move_to(
            self.btn_unmount,
            margin + scale(118),
            button_y,
            scale(110),
            scale(30),
        );
        move_to(
            self.btn_open,
            margin + scale(236),
            button_y,
            scale(130),
            scale(30),
        );
        move_to(
            self.btn_rescan,
            margin + scale(374),
            button_y,
            scale(90),
            scale(30),
        );
        move_to(
            self.btn_browse,
            margin + scale(472),
            button_y,
            scale(130),
            scale(30),
        );

        move_to(self.status, margin, height - scale(52), content, scale(40));
    }

    // ----------------------------------------------------------------- state

    fn dpi(&self) -> i32 {
        unsafe { GetDpiForWindow(self.hwnd).max(96) as i32 }
    }

    unsafe fn set_status(&self, text: &str) {
        let wide_text = wide(text);
        let _ = SetWindowTextW(self.status, PCWSTR(wide_text.as_ptr()));
    }

    unsafe fn show_error(&self, title: &str, message: &str) {
        let text = wide(message);
        let caption = wide(title);
        MessageBoxW(
            self.hwnd,
            PCWSTR(text.as_ptr()),
            PCWSTR(caption.as_ptr()),
            MB_OK | MB_ICONERROR,
        );
    }

    unsafe fn selected_index(&self) -> Option<usize> {
        let index = SendMessageW(
            self.list,
            windows::Win32::UI::Controls::LVM_GETNEXTITEM,
            WPARAM(usize::MAX),
            LPARAM(2), // LVNI_SELECTED
        )
        .0;
        (index >= 0).then_some(index as usize)
    }

    unsafe fn selected_drive(&self) -> Option<String> {
        let index = SendMessageW(self.combo, CB_GETCURSEL, WPARAM(0), LPARAM(0)).0;
        if index < 0 {
            return None;
        }
        let mut buffer = [0u16; 32];
        let len = SendMessageW(
            self.combo,
            CB_GETLBTEXT,
            WPARAM(index as usize),
            LPARAM(buffer.as_mut_ptr() as isize),
        )
        .0;
        if len <= 0 {
            None
        } else {
            Some(String::from_utf16_lossy(&buffer[..len as usize]))
        }
    }

    unsafe fn refresh_drives(&self) {
        SendMessageW(self.combo, CB_RESETCONTENT, WPARAM(0), LPARAM(0));
        let mask = windows::Win32::Storage::FileSystem::GetLogicalDrives();
        for bit in 0..26u32 {
            if mask & (1 << bit) != 0 {
                continue; // letter already in use
            }
            let letter = (b'A' + bit as u8) as char;
            let mut text = wide(&format!("{letter}:"));
            SendMessageW(
                self.combo,
                CB_ADDSTRING,
                WPARAM(0),
                LPARAM(text.as_mut_ptr() as isize),
            );
        }
        SendMessageW(self.combo, CB_SETCURSEL, WPARAM(0), LPARAM(0));
    }

    unsafe fn populate_list(&self) {
        SendMessageW(self.list, LVM_DELETEALLITEMS, WPARAM(0), LPARAM(0));
        for (index, entry) in self.entries.iter().enumerate() {
            let status = match self
                .mounts
                .iter()
                .find(|m| m.key == source_key(&entry.source))
            {
                Some(mount) => format!("Mounted at {}", mount.mount_point),
                None => String::new(),
            };
            let columns = [
                entry.detail.clone(),
                entry.label.clone(),
                human_size(entry.size),
                status,
            ];
            for (sub, text) in columns.iter().enumerate() {
                let mut buffer = wide(text);
                let mut item = LVITEMW::default();
                item.mask = LVIF_TEXT;
                item.iItem = index as i32;
                item.iSubItem = sub as i32;
                item.pszText = PWSTR(buffer.as_mut_ptr());
                let message = if sub == 0 {
                    LVM_INSERTITEMW
                } else {
                    LVM_SETITEMTEXTW
                };
                SendMessageW(
                    self.list,
                    message,
                    WPARAM(if sub == 0 { 0 } else { index }),
                    LPARAM(&item as *const _ as isize),
                );
            }
        }
    }

    // ------------------------------------------------------------------ scan

    unsafe fn start_scan(&mut self) {
        if self.scanning {
            return;
        }
        self.scanning = true;
        let _ = EnableWindow(self.btn_rescan, false);
        self.set_status("Scanning for XFS volumes...");

        let hwnd = self.hwnd.0 as isize;
        let spawned = thread::Builder::new()
            .name("xfs-gui-scan".to_string())
            .spawn(move || {
                let found = crate::disk::scan_for_xfs_disks();
                let payload = Box::into_raw(Box::new(found)) as isize;
                let hwnd = HWND(hwnd as *mut c_void);
                unsafe {
                    let _ = PostMessageW(hwnd, WM_APP_SCAN_DONE, WPARAM(0), LPARAM(payload));
                }
            });
        if spawned.is_err() {
            self.scanning = false;
            let _ = EnableWindow(self.btn_rescan, true);
            self.set_status("Could not start the volume scan.");
        }
    }

    unsafe fn on_scan_done(&mut self, lparam: LPARAM) {
        let found = *Box::from_raw(lparam.0 as *mut Vec<XfsDiskInfo>);
        self.scanning = false;
        let _ = EnableWindow(self.btn_rescan, true);

        // Keep images the user picked manually; refresh the hardware rows.
        let images: Vec<Entry> = self
            .entries
            .iter()
            .filter(|entry| matches!(entry.source, MountSource::ImageFile(_)))
            .cloned()
            .collect();
        self.entries.clear();

        for info in &found {
            if let Some(source) = source_from_disk_path(&info.disk_path) {
                let detail = describe_source(&source);
                self.entries.push(Entry {
                    source,
                    detail,
                    label: info.label.clone(),
                    size: info.size,
                });
            }
        }
        self.entries.extend(images);

        self.populate_list();
        self.refresh_drives();

        let count = self.entries.len();
        self.set_status(&format!(
            "Found {count} XFS volume{}.",
            if count == 1 { "" } else { "s" }
        ));
    }

    // ----------------------------------------------------------------- mount

    unsafe fn mount_selected(&mut self) {
        let Some(index) = self.selected_index() else {
            self.set_status("Select a volume in the list first.");
            return;
        };
        let Some(entry) = self.entries.get(index).cloned() else {
            return;
        };
        let Some(drive) = self.selected_drive() else {
            self.set_status("No free drive letter is available.");
            return;
        };

        self.mount_entry(&entry, &drive);
    }

    unsafe fn mount_entry(&mut self, entry: &Entry, drive: &str) {
        let read_only = !self.read_write;
        if !read_only && !matches!(entry.source, MountSource::ImageFile(_)) {
            self.set_status("Read-write mounting is only supported for image files.");
            return;
        }

        self.set_status(&format!("Mounting {} at {drive}...", entry.detail));

        let result = (|| -> Result<MountHandle> {
            let options = MountOptions {
                source: entry.source.clone(),
                mount_point: drive.to_string(),
                read_only,
                debug: self.debug,
                ..Default::default()
            };
            options.validate()?;
            let device = open_source(&options.source, options.read_only)?;
            let fs = factory::detect_and_create(device, options.read_only)?;
            winfsp_mount::start_mount(&options.mount_point, fs, options.debug)
        })();

        match result {
            Ok(handle) => {
                self.mounts.push(ActiveMount {
                    key: source_key(&entry.source),
                    mount_point: drive.to_string(),
                    handle: Some(handle),
                });
                self.set_status(&format!(
                    "Mounted {}{} at {drive}.",
                    entry.detail,
                    if entry.label.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", entry.label)
                    }
                ));
                self.refresh_drives();
                self.populate_list();
            }
            Err(error) => {
                self.set_status(&format!("Mount failed: {error}"));
                self.show_error("XFS Mount", &format!("Mount failed:\n\n{error}"));
            }
        }
    }

    unsafe fn unmount_selected(&mut self) {
        if let Some(index) = self.selected_index() {
            if let Some(entry) = self.entries.get(index) {
                let key = source_key(&entry.source);
                if self.unmount_key(&key) {
                    return;
                }
            }
        }
        self.unmount_all();
    }

    unsafe fn unmount_key(&mut self, key: &str) -> bool {
        let Some(position) = self.mounts.iter().position(|mount| mount.key == key) else {
            return false;
        };
        let mut mount = self.mounts.remove(position);
        if let Some(handle) = mount.handle.take() {
            handle.stop();
        }
        self.set_status(&format!("Unmounted {}.", mount.mount_point));
        self.refresh_drives();
        self.populate_list();
        true
    }

    unsafe fn unmount_all(&mut self) {
        if self.mounts.is_empty() {
            self.set_status("Nothing is mounted.");
            return;
        }
        let count = self.mounts.len();
        for mut mount in self.mounts.drain(..) {
            if let Some(handle) = mount.handle.take() {
                handle.stop();
            }
        }
        self.set_status(&format!(
            "Unmounted {count} volume{}.",
            if count == 1 { "" } else { "s" }
        ));
        self.refresh_drives();
        self.populate_list();
    }

    unsafe fn open_selected(&mut self) {
        let Some(index) = self.selected_index() else {
            self.set_status("Select a mounted volume first.");
            return;
        };
        let Some(entry) = self.entries.get(index) else {
            return;
        };
        let key = source_key(&entry.source);
        let Some(mount) = self.mounts.iter().find(|mount| mount.key == key) else {
            self.set_status("That volume is not mounted.");
            return;
        };
        let path = wide(&format!("{}\\", mount.mount_point.trim_end_matches('\\')));
        ShellExecuteW(
            HWND(std::ptr::null_mut()),
            w!("open"),
            PCWSTR(path.as_ptr()),
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );
    }

    unsafe fn browse_image(&mut self) {
        let Some(path) = dialogs::pick_xfs_image(self.hwnd) else {
            return;
        };
        let detail = path.display().to_string();
        let source = MountSource::ImageFile(path);
        if !self
            .entries
            .iter()
            .any(|entry| entry.source_key_eq(&source))
        {
            self.entries.push(Entry {
                source,
                detail: detail.clone(),
                label: String::new(),
                size: std::fs::metadata(&detail)
                    .map(|meta| meta.len())
                    .unwrap_or(0),
            });
        }
        self.populate_list();
        self.set_status(&format!(
            "Selected image {detail}. Choose a drive and click Mount."
        ));
    }

    // ------------------------------------------------------------------ tray

    unsafe fn install_tray(&mut self) {
        let mut data = NOTIFYICONDATAW::default();
        data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.hwnd;
        data.uID = TRAY_ICON_ID;
        data.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        data.uCallbackMessage = WM_APP_TRAY;
        data.hIcon = self.icon;
        fill_wide(&mut data.szTip, "XFS Mount");
        self.tray_added = Shell_NotifyIconW(NIM_ADD, &data).as_bool();
    }

    unsafe fn remove_tray(&mut self) {
        if !self.tray_added {
            return;
        }
        let mut data = NOTIFYICONDATAW::default();
        data.cbSize = size_of::<NOTIFYICONDATAW>() as u32;
        data.hWnd = self.hwnd;
        data.uID = TRAY_ICON_ID;
        let _ = Shell_NotifyIconW(NIM_DELETE, &data);
        self.tray_added = false;
    }

    unsafe fn on_tray(&mut self, lparam: LPARAM) {
        match (lparam.0 as u32) & 0xFFFF {
            WM_RBUTTONUP | WM_CONTEXTMENU => self.show_tray_menu(),
            WM_LBUTTONDBLCLK => self.show_window(),
            _ => {}
        }
    }

    unsafe fn show_tray_menu(&mut self) {
        let Ok(menu) = CreatePopupMenu() else {
            return;
        };
        let _ = AppendMenuW(menu, MF_STRING, IDM_SHOW, w!("Show XFS Mount"));
        let _ = AppendMenuW(menu, MF_STRING, IDM_UNMOUNT_ALL, w!("Unmount all"));
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(menu, MF_STRING, IDM_EXIT, w!("Exit"));

        let mut point = POINT::default();
        let _ = GetCursorPos(&mut point);
        let _ = SetForegroundWindow(self.hwnd);
        let _ = TrackPopupMenu(
            menu,
            TPM_LEFTALIGN | TPM_BOTTOMALIGN | TPM_RIGHTBUTTON,
            point.x,
            point.y,
            0,
            self.hwnd,
            None,
        );
        let _ = PostMessageW(self.hwnd, WM_NULL, WPARAM(0), LPARAM(0));
        let _ = DestroyMenu(menu);
    }

    unsafe fn show_window(&mut self) {
        let _ = ShowWindow(self.hwnd, SW_SHOW);
        let _ = SetForegroundWindow(self.hwnd);
        let _ = SetFocus(self.hwnd);
    }

    // -------------------------------------------------------------- messages

    unsafe fn on_command(&mut self, wparam: WPARAM) {
        let id = (wparam.0 & 0xFFFF) as usize;
        let code = ((wparam.0 >> 16) & 0xFFFF) as u32;

        match id {
            _ if id == IDC_MOUNT as usize => {
                if code == 0 {
                    self.mount_selected();
                }
            }
            _ if id == IDC_UNMOUNT as usize => {
                if code == 0 {
                    self.unmount_selected();
                }
            }
            _ if id == IDC_OPEN as usize => {
                if code == 0 {
                    self.open_selected();
                }
            }
            _ if id == IDC_RESCAN as usize => {
                if code == 0 {
                    self.start_scan();
                }
            }
            _ if id == IDC_BROWSE as usize => {
                if code == 0 {
                    self.browse_image();
                }
            }
            _ if id == IDC_RW as usize => {
                if code == 0 {
                    self.read_write = !self.read_write;
                }
            }
            IDM_SHOW => self.show_window(),
            IDM_UNMOUNT_ALL => {
                self.unmount_all();
                self.show_window();
            }
            IDM_EXIT => {
                self.exiting = true;
                let _ = DestroyWindow(self.hwnd);
            }
            _ => {}
        }
    }

    unsafe fn on_notify(&mut self, lparam: LPARAM) {
        if lparam.0 == 0 {
            return;
        }
        let header = &*(lparam.0 as *const NMHDR);
        if header.idFrom == IDC_LIST as usize && header.code == NM_DBLCLK {
            self.mount_selected();
        }
    }

    unsafe fn on_destroy(&mut self) {
        self.remove_tray();
        for mut mount in self.mounts.drain(..) {
            if let Some(handle) = mount.handle.take() {
                handle.stop();
            }
        }
        PostQuitMessage(0);
    }

    unsafe fn handle(&mut self, msg: u32, wparam: WPARAM, lparam: LPARAM) -> Option<LRESULT> {
        match msg {
            WM_SIZE => {
                if wparam.0 as u32 == SIZE_MINIMIZED {
                    let _ = ShowWindow(self.hwnd, SW_HIDE);
                } else {
                    self.layout();
                }
                Some(LRESULT(0))
            }
            WM_CLOSE => {
                if self.exiting {
                    None
                } else {
                    let _ = ShowWindow(self.hwnd, SW_HIDE);
                    Some(LRESULT(0))
                }
            }
            WM_COMMAND => {
                self.on_command(wparam);
                Some(LRESULT(0))
            }
            WM_NOTIFY => {
                self.on_notify(lparam);
                Some(LRESULT(0))
            }
            WM_APP_TRAY => {
                self.on_tray(lparam);
                Some(LRESULT(0))
            }
            WM_APP_SCAN_DONE => {
                self.on_scan_done(lparam);
                Some(LRESULT(0))
            }
            WM_DESTROY => {
                self.on_destroy();
                Some(LRESULT(0))
            }
            _ => None,
        }
    }
}

impl Entry {
    fn source_key_eq(&self, other: &MountSource) -> bool {
        source_key(&self.source) == source_key(other)
    }
}

impl Drop for App {
    fn drop(&mut self) {
        unsafe {
            self.remove_tray();
            for mut mount in self.mounts.drain(..) {
                if let Some(handle) = mount.handle.take() {
                    handle.stop();
                }
            }
            let _ = DestroyIcon(self.icon);
            let _ = DeleteObject(windows::Win32::Graphics::Gdi::HGDIOBJ(self.font.0));
            let _ = DeleteObject(windows::Win32::Graphics::Gdi::HGDIOBJ(self.bg_brush.0));
        }
    }
}

unsafe extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let pointer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut App;
    if !pointer.is_null() {
        let app = &mut *pointer;
        if let Some(result) = app.handle(msg, wparam, lparam) {
            return result;
        }
    }
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

// ------------------------------------------------------------------- helpers

fn base(bits: u32) -> WINDOW_STYLE {
    WINDOW_STYLE(bits)
}

unsafe fn move_to(hwnd: HWND, x: i32, y: i32, width: i32, height: i32) {
    let _ = MoveWindow(hwnd, x, y, width, height, true);
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

fn fill_wide(destination: &mut [u16], text: &str) {
    let encoded: Vec<u16> = text.encode_utf16().collect();
    let count = encoded.len().min(destination.len().saturating_sub(1));
    destination[..count].copy_from_slice(&encoded[..count]);
    if count < destination.len() {
        destination[count] = 0;
    }
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn source_from_disk_path(path: &str) -> Option<MountSource> {
    if let Some(number) = path.strip_prefix(r"\\.\PhysicalDrive") {
        return number.parse().ok().map(MountSource::DiskNumber);
    }
    if let Some(rest) = path.strip_prefix(r"\\.\") {
        let upper = rest.to_ascii_uppercase();
        if upper.len() == 2 && upper.ends_with(':') {
            let letter = upper.chars().next()?;
            if letter.is_ascii_alphabetic() {
                return Some(MountSource::Partition(letter));
            }
        }
        return Some(MountSource::DiskPath(path.to_string()));
    }
    None
}

fn describe_source(source: &MountSource) -> String {
    match source {
        MountSource::DiskNumber(number) => format!("Physical disk {number}"),
        MountSource::Partition(letter) => format!("Partition {letter}:"),
        MountSource::DiskPath(path) => path.clone(),
        MountSource::ImageFile(path) => path.display().to_string(),
    }
}
