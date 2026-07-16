use crate::guest_memory::{
    checked_field_address, read_bytes as read_guest_bytes, read_i32 as read_guest_i32,
    read_u32 as read_guest_u32, read_u64 as read_guest_u64, write_bytes as write_guest_bytes,
    write_i32 as write_guest_i32, write_u32 as write_guest_u32, write_u64 as write_guest_u64,
};
use crate::guest_string::{
    read_ansi_lossy as read_guest_ansi_lossy, read_utf16_lossy as read_guest_utf16_lossy,
    write_ansi_c_string as write_guest_ansi_c_string, write_fixed_ansi as write_guest_fixed_ansi,
    write_fixed_utf16 as write_guest_fixed_utf16,
    write_utf16_c_string as write_guest_utf16_c_string,
};

use crate::{
    GuestCallbackRequest, MessageQueueIdlePolicy, QueuedWindowMessage, TimerRecord,
    WinApiControlSignal, WinApiHandlerResult, WinApiState, WindowClassRecord, WindowRecord,
    WindowsHookRecord,
};
use anyhow::{Context, Result};

const FAKE_ICON_HANDLE: u64 = 0x0000_0000_6600_0001;
const FAKE_CURSOR_HANDLE: u64 = 0x0000_0000_6600_0002;
const IDOK: u64 = 1;

const WM_MDICREATE: u32 = 0x0220;
const FAKE_MONITOR_HANDLE: u64 = 0x0000_0000_6600_0010;
const DISPLAY_DEVICE_ATTACHED_TO_DESKTOP: u32 = 0x0000_0001;
const DISPLAY_DEVICE_PRIMARY_DEVICE: u32 = 0x0000_0004;
const FAKE_WINDOW_HANDLE: u64 = 0x0000_0000_6600_0100;
const FAKE_DEVICE_CONTEXT_HANDLE: u64 = 0x0000_0000_6600_0200;
const FAKE_IMAGE_HANDLE: u64 = 0x0000_0000_6600_0300;
const FAKE_DESKTOP_WINDOW_HANDLE: u64 = 0x0000_0000_6600_0110;
const FAKE_SYSTEM_COLOR_BRUSH_BASE: u64 = 0x0000_0000_6601_0000;
const FAKE_PROCESS_ID: u32 = 1;
const FAKE_THREAD_ID: u64 = 1;

const DIALOG_BASE_UNIT_X: u32 = 8;
const DIALOG_BASE_UNIT_Y: u32 = 16;

const WM_QUIT: u32 = 0x0012;

const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const WM_DEADCHAR: u32 = 0x0103;
const WM_SYSKEYDOWN: u32 = 0x0104;
const WM_SYSKEYUP: u32 = 0x0105;
const WM_SYSCHAR: u32 = 0x0106;
const WM_SYSDEADCHAR: u32 = 0x0107;

/// Handles `USER32.dll!GetAsyncKeyState`.
pub fn handle_get_async_key_state(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _virtual_key = engine
        .read_rcx()
        .context("failed to read RCX for GetAsyncKeyState")?;

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from GetAsyncKeyState")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

fn write_fake_monitor_info(
    engine: &mut dyn wie_cpu::CpuEngine,
    monitor_info_ptr: u64,
) -> Result<()> {
    if monitor_info_ptr == 0 {
        return Ok(());
    }

    // MONITORINFO:
    // DWORD cbSize;    offset 0
    // RECT  rcMonitor; offset 4
    // RECT  rcWork;    offset 20
    // DWORD dwFlags;   offset 36
    //
    // MONITORINFOEXA/W has the same prefix plus device name after offset 40.
    write_guest_u32(engine, monitor_info_ptr, 40)?;

    // rcMonitor = { left: 0, top: 0, right: 1024, bottom: 768 }
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 4, "rcMonitor.left")?,
        0,
    )?;
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 8, "rcMonitor.top")?,
        0,
    )?;
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 12, "rcMonitor.right")?,
        1024,
    )?;
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 16, "rcMonitor.bottom")?,
        768,
    )?;

    // rcWork = { left: 0, top: 0, right: 1024, bottom: 728 }
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 20, "rcWork.left")?,
        0,
    )?;
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 24, "rcWork.top")?,
        0,
    )?;
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 28, "rcWork.right")?,
        1024,
    )?;
    write_guest_i32(
        engine,
        checked_field_address(monitor_info_ptr, 32, "rcWork.bottom")?,
        728,
    )?;

    // MONITORINFOF_PRIMARY
    write_guest_u32(
        engine,
        checked_field_address(monitor_info_ptr, 36, "dwFlags")?,
        1,
    )?;

    Ok(())
}

/// Handles `USER32.dll!PeekMessageA`.
pub fn handle_peek_message_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let message_address = engine
        .read_rcx()
        .context("failed to read RCX for PeekMessageA")?;

    let window_filter = engine
        .read_rdx()
        .context("failed to read RDX for PeekMessageA")?;

    let minimum_message_raw = engine
        .read_r8()
        .context("failed to read R8 for PeekMessageA")?;

    let maximum_message_raw = engine
        .read_r9()
        .context("failed to read R9 for PeekMessageA")?;

    let w_remove_msg = engine.read_rsp().ok()
        .and_then(|rsp| read_guest_u32(engine, rsp.wrapping_add(0x28)).ok())
        .unwrap_or(0);

    let minimum_message = u32::try_from(minimum_message_raw & u64::from(u32::MAX))
        .context("PeekMessageA minimum message does not fit u32")?;

    let maximum_message = u32::try_from(maximum_message_raw & u64::from(u32::MAX))
        .context("PeekMessageA maximum message does not fit u32")?;

    let matches_filter = |queued: &QueuedWindowMessage| -> bool {
        let window_matches = window_filter == 0 || queued.window_handle == window_filter;
        let message_matches = if minimum_message == 0 && maximum_message == 0 {
            true
        } else {
            queued.message >= minimum_message && queued.message <= maximum_message
        };
        window_matches && message_matches
    };

    let matching_index = state.message_queue.iter().position(matches_filter);

    let return_value = if let Some(index) = matching_index {
        let queued = if w_remove_msg != 0 {
            // PM_REMOVE: remove from queue.
            state.message_queue.remove(index)
        } else {
            // PM_NOREMOVE: leave in queue.
            state.message_queue[index].clone()
        };
        write_message_structure(engine, message_address, &queued)?;
        1
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from PeekMessageA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!LoadIconA`.
pub fn handle_load_icon_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _instance_handle = engine
        .read_rcx()
        .context("failed to read RCX for LoadIconA")?;

    let _icon_name = engine
        .read_rdx()
        .context("failed to read RDX for LoadIconA")?;

    let return_address = engine
        .return_from_win64_api(FAKE_ICON_HANDLE)
        .context("failed to return from LoadIconA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_ICON_HANDLE,
    })
}

/// Handles `USER32.dll!LoadCursorA`.
pub fn handle_load_cursor_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _instance_handle = engine
        .read_rcx()
        .context("failed to read RCX for LoadCursorA")?;

    let _cursor_name = engine
        .read_rdx()
        .context("failed to read RDX for LoadCursorA")?;

    let return_address = engine
        .return_from_win64_api(FAKE_CURSOR_HANDLE)
        .context("failed to return from LoadCursorA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_CURSOR_HANDLE,
    })
}

/// Handles `USER32.dll!RegisterClassExW`.
pub fn handle_register_class_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_class_ptr = engine
        .read_rcx()
        .context("failed to read RCX for RegisterClassExW")?;

    let return_value = if window_class_ptr == 0 {
        0
    } else {
        /*
         * WNDCLASSEXW on Win64:
         * +0x00 UINT      cbSize
         * +0x04 UINT      style
         * +0x08 WNDPROC   lpfnWndProc
         * +0x10 INT       cbClsExtra
         * +0x14 INT       cbWndExtra
         * +0x18 HINSTANCE hInstance
         * +0x20 HICON     hIcon
         * +0x28 HCURSOR   hCursor
         * +0x30 HBRUSH    hbrBackground
         * +0x38 LPCWSTR   lpszMenuName
         * +0x40 LPCWSTR   lpszClassName
         * +0x48 HICON     hIconSm
         */

        let style = read_guest_u32(
            engine,
            checked_field_address(window_class_ptr, 4, "WNDCLASSEXW.style")?,
        )
        .context("failed to read WNDCLASSEXW.style")?;

        let window_proc = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 8, "WNDCLASSEXW.lpfnWndProc")?,
        )
        .context("failed to read WNDCLASSEXW.lpfnWndProc")?;

        let instance_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 24, "WNDCLASSEXW.hInstance")?,
        )
        .context("failed to read WNDCLASSEXW.hInstance")?;

        let icon_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 32, "WNDCLASSEXW.hIcon")?,
        )
        .context("failed to read WNDCLASSEXW.hIcon")?;

        let cursor_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 40, "WNDCLASSEXW.hCursor")?,
        )
        .context("failed to read WNDCLASSEXW.hCursor")?;

        let background_brush = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 48, "WNDCLASSEXW.hbrBackground")?,
        )
        .context("failed to read WNDCLASSEXW.hbrBackground")?;

        let class_name_ptr = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 64, "WNDCLASSEXW.lpszClassName")?,
        )
        .context("failed to read WNDCLASSEXW.lpszClassName")?;

        let small_icon_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 72, "WNDCLASSEXW.hIconSm")?,
        )
        .context("failed to read WNDCLASSEXW.hIconSm")?;

        let class_name = read_guest_utf16_lossy(engine, class_name_ptr, 256)
            .context("failed to read RegisterClassExW class name")?;

        register_window_class(
            state,
            WindowClassRecord {
                atom: 0,
                class_name,
                window_proc,
                style,
                instance_handle,
                icon_handle,
                cursor_handle,
                background_brush,
                small_icon_handle,
                unicode: true,
            },
        )?
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from RegisterClassExW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!RegisterClassExA`.
pub fn handle_register_class_ex_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_class_ptr = engine
        .read_rcx()
        .context("failed to read RCX for RegisterClassExA")?;

    let return_value = if window_class_ptr == 0 {
        0
    } else {
        let style = read_guest_u32(
            engine,
            checked_field_address(window_class_ptr, 4, "WNDCLASSEXA.style")?,
        )
        .context("failed to read WNDCLASSEXA.style")?;

        let window_proc = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 8, "WNDCLASSEXA.lpfnWndProc")?,
        )
        .context("failed to read WNDCLASSEXA.lpfnWndProc")?;

        let instance_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 24, "WNDCLASSEXA.hInstance")?,
        )
        .context("failed to read WNDCLASSEXA.hInstance")?;

        let icon_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 32, "WNDCLASSEXA.hIcon")?,
        )
        .context("failed to read WNDCLASSEXA.hIcon")?;

        let cursor_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 40, "WNDCLASSEXA.hCursor")?,
        )
        .context("failed to read WNDCLASSEXA.hCursor")?;

        let background_brush = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 48, "WNDCLASSEXA.hbrBackground")?,
        )
        .context("failed to read WNDCLASSEXA.hbrBackground")?;

        let class_name_ptr = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 64, "WNDCLASSEXA.lpszClassName")?,
        )
        .context("failed to read WNDCLASSEXA.lpszClassName")?;

        let small_icon_handle = read_guest_u64(
            engine,
            checked_field_address(window_class_ptr, 72, "WNDCLASSEXA.hIconSm")?,
        )
        .context("failed to read WNDCLASSEXA.hIconSm")?;

        let class_name = read_guest_ansi_lossy(engine, class_name_ptr, 256)
            .context("failed to read RegisterClassExA class name")?;

        register_window_class(
            state,
            WindowClassRecord {
                atom: 0,
                class_name,
                window_proc,
                style,
                instance_handle,
                icon_handle,
                cursor_handle,
                background_brush,
                small_icon_handle,
                unicode: false,
            },
        )?
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from RegisterClassExA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!MessageBoxW`.
pub fn handle_message_box_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for MessageBoxW")?;

    let text_ptr = engine
        .read_rdx()
        .context("failed to read RDX for MessageBoxW")?;

    let caption_ptr = engine
        .read_r8()
        .context("failed to read R8 for MessageBoxW")?;

    let _message_box_type = engine
        .read_r9()
        .context("failed to read R9 for MessageBoxW")?;

    let text = read_guest_utf16_lossy(engine, text_ptr, 1024)
        .context("failed to read MessageBoxW text")?;

    let caption = read_guest_utf16_lossy(engine, caption_ptr, 256)
        .context("failed to read MessageBoxW caption")?;

    tracing::info!(caption = %caption, text = %text, "MessageBoxW");

    let return_address = engine
        .return_from_win64_api(IDOK)
        .context("failed to return from MessageBoxW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: IDOK,
    })
}

/// Handles `USER32.dll!MessageBoxA`.
pub fn handle_message_box_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for MessageBoxA")?;

    let text_ptr = engine
        .read_rdx()
        .context("failed to read RDX for MessageBoxA")?;

    let caption_ptr = engine
        .read_r8()
        .context("failed to read R8 for MessageBoxA")?;

    let _message_box_type = engine
        .read_r9()
        .context("failed to read R9 for MessageBoxA")?;

    let text =
        read_guest_ansi_lossy(engine, text_ptr, 1024).context("failed to read MessageBoxA text")?;

    let caption = read_guest_ansi_lossy(engine, caption_ptr, 256)
        .context("failed to read MessageBoxA caption")?;

    tracing::info!(caption = %caption, text = %text, "MessageBoxA");

    let return_address = engine
        .return_from_win64_api(IDOK)
        .context("failed to return from MessageBoxA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: IDOK,
    })
}

/// Handles dynamic `USER32.dll!SetProcessDPIAware`.
pub fn handle_set_process_dpi_aware(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from SetProcessDPIAware")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles dynamic `USER32.dll!TrackMouseEvent`.
pub fn handle_track_mouse_event(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _track_mouse_event_ptr = engine
        .read_rcx()
        .context("failed to read RCX for TrackMouseEvent")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from TrackMouseEvent")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `USER32.dll!GetCursorPos`.
pub fn handle_get_cursor_pos(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let point_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetCursorPos")?;

    if point_ptr != 0 {
        // POINT:
        // LONG x; offset 0
        // LONG y; offset 4
        write_guest_i32(engine, point_ptr, 0)?;
        write_guest_i32(engine, checked_field_address(point_ptr, 4, "POINT.y")?, 0)?;
    }

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from GetCursorPos")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `USER32.dll!ClipCursor` (accept clip rect or release when NULL).
pub fn handle_clip_cursor(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let rect_ptr = engine
        .read_rcx()
        .context("failed to read RCX for ClipCursor")?;

    // No host cursor clipping; always succeed so editor drag paths continue.
    tracing::debug!(rect_ptr, "ClipCursor");

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from ClipCursor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `USER32.dll!GetClipCursor`.
pub fn handle_get_clip_cursor(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let rect_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetClipCursor")?;

    let success = rect_ptr != 0;
    if success {
        // Full desktop-ish clip rect.
        write_window_rect(engine, rect_ptr, 0, 0, 1920, 1080)?;
    }

    let return_value = u64::from(success);
    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetClipCursor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!CallMsgFilterA/W`.
///
/// Returns FALSE so the message continues through the normal dispatch path
/// (no installed WH_MSGFILTER/WH_SYSMSGFILTER hooks).
pub fn handle_call_msg_filter(
    engine: &mut dyn wie_cpu::CpuEngine,
    api_name: &str,
) -> Result<WinApiHandlerResult> {
    let _msg_ptr = engine
        .read_rcx()
        .with_context(|| format!("failed to read RCX for {api_name}"))?;
    let _code = engine
        .read_rdx()
        .with_context(|| format!("failed to read RDX for {api_name}"))?;

    let return_address = engine
        .return_from_win64_api(0)
        .with_context(|| format!("failed to return from {api_name}"))?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

fn fake_system_metric(metric_index: u64) -> u64 {
    match metric_index {
        // SM_CXSCREEN / SM_CXFULLSCREEN
        0 | 16 => 1024,

        // SM_CYSCREEN
        1 => 768,

        // SM_CXVSCROLL / SM_CYHSCROLL
        2 | 3 => 17,

        // SM_CYCAPTION
        4 => 23,

        // SM_CXBORDER / SM_CYBORDER / SM_MOUSEPRESENT / SM_CMONITORS
        5 | 6 | 19 | 80 => 1,

        // SM_CXDLGFRAME / SM_CYDLGFRAME / SM_CXFRAME / SM_CYFRAME /
        // SM_CXDOUBLECLK / SM_CYDOUBLECLK
        7 | 8 | 32 | 33 | 36 | 37 => 4,

        // SM_CXICON / SM_CYICON / SM_CXCURSOR / SM_CYCURSOR
        11..=14 => 32,

        // SM_CYMENU
        15 => 20,

        // SM_CYFULLSCREEN
        17 => 728,

        // SM_CXMIN / SM_CXMINTRACK
        28 | 34 => 112,

        // SM_CYMIN / SM_CYMINTRACK
        29 | 35 => 27,

        // SM_CXSIZE / SM_CYSIZE
        30 | 31 => 18,

        // SM_CXICONSPACING / SM_CYICONSPACING
        38 | 39 => 75,

        // Unknown and zero-valued metrics.
        _ => 0,
    }
}

/// Handles `USER32.dll!GetSystemMetrics`.
pub fn handle_get_system_metrics(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let metric_index = engine
        .read_rcx()
        .context("failed to read RCX for GetSystemMetrics")?;

    let return_value = fake_system_metric(metric_index);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetSystemMetrics")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles dynamic `USER32.dll!MonitorFromWindow`.
pub fn handle_monitor_from_window(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for MonitorFromWindow")?;

    let _flags = engine
        .read_rdx()
        .context("failed to read RDX for MonitorFromWindow")?;

    let return_address = engine
        .return_from_win64_api(FAKE_MONITOR_HANDLE)
        .context("failed to return from MonitorFromWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_MONITOR_HANDLE,
    })
}

/// Handles dynamic `USER32.dll!GetMonitorInfoA`.
pub fn handle_get_monitor_info_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let monitor_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetMonitorInfoA")?;

    let monitor_info_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetMonitorInfoA")?;

    let success = monitor_handle == FAKE_MONITOR_HANDLE && monitor_info_ptr != 0;

    if success {
        write_fake_monitor_info(engine, monitor_info_ptr)?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetMonitorInfoA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles dynamic `USER32.dll!GetMonitorInfoW`.
pub fn handle_get_monitor_info_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let monitor_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetMonitorInfoW")?;

    let monitor_info_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetMonitorInfoW")?;

    let success = monitor_handle == FAKE_MONITOR_HANDLE && monitor_info_ptr != 0;

    if success {
        write_fake_monitor_info(engine, monitor_info_ptr)?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetMonitorInfoW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles dynamic `USER32.dll!MonitorFromRect`.
pub fn handle_monitor_from_rect(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _rect_ptr = engine
        .read_rcx()
        .context("failed to read RCX for MonitorFromRect")?;

    let _flags = engine
        .read_rdx()
        .context("failed to read RDX for MonitorFromRect")?;

    let return_address = engine
        .return_from_win64_api(FAKE_MONITOR_HANDLE)
        .context("failed to return from MonitorFromRect")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_MONITOR_HANDLE,
    })
}

/// Handles dynamic `USER32.dll!MonitorFromPoint`.
pub fn handle_monitor_from_point(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _point_low = engine
        .read_rcx()
        .context("failed to read RCX for MonitorFromPoint")?;

    let _flags = engine
        .read_rdx()
        .context("failed to read RDX for MonitorFromPoint")?;

    let return_address = engine
        .return_from_win64_api(FAKE_MONITOR_HANDLE)
        .context("failed to return from MonitorFromPoint")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_MONITOR_HANDLE,
    })
}

/// Handles dynamic `USER32.dll!EnumDisplayMonitors`.
pub fn handle_enum_display_monitors(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _device_context = engine
        .read_rcx()
        .context("failed to read RCX for EnumDisplayMonitors")?;

    let _clip_rect_ptr = engine
        .read_rdx()
        .context("failed to read RDX for EnumDisplayMonitors")?;

    let _callback_ptr = engine
        .read_r8()
        .context("failed to read R8 for EnumDisplayMonitors")?;

    let _callback_data = engine
        .read_r9()
        .context("failed to read R9 for EnumDisplayMonitors")?;

    // First-pass behavior:
    // report success, but do not call the callback yet.
    //
    // If Lunar Magic later depends on the callback being invoked, we will need
    // to emulate a Win64 callback call into guest code with:
    //   callback(fake_monitor, fake_hdc, rect_ptr, data)
    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from EnumDisplayMonitors")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles dynamic `USER32.dll!EnumDisplayDevicesA`.
pub fn handle_enum_display_devices_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _device_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for EnumDisplayDevicesA")?;

    let device_index = engine
        .read_rdx()
        .context("failed to read RDX for EnumDisplayDevicesA")?;

    let display_device_ptr = engine
        .read_r8()
        .context("failed to read R8 for EnumDisplayDevicesA")?;

    let _flags = engine
        .read_r9()
        .context("failed to read R9 for EnumDisplayDevicesA")?;

    let success = device_index == 0 && display_device_ptr != 0;

    if success {
        // DISPLAY_DEVICEA:
        // DWORD cb;                 offset 0
        // CHAR  DeviceName[32];     offset 4
        // CHAR  DeviceString[128];  offset 36
        // DWORD StateFlags;         offset 164
        // CHAR  DeviceID[128];      offset 168
        // CHAR  DeviceKey[128];     offset 296
        write_guest_u32(engine, display_device_ptr, 424)?;

        write_guest_fixed_ansi(
            engine,
            checked_field_address(display_device_ptr, 4, "DeviceName")?,
            32,
            b"\\\\.\\DISPLAY1",
        )?;

        write_guest_fixed_ansi(
            engine,
            checked_field_address(display_device_ptr, 36, "DeviceString")?,
            128,
            b"Generic Display",
        )?;

        write_guest_u32(
            engine,
            checked_field_address(display_device_ptr, 164, "StateFlags")?,
            DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE,
        )?;

        write_guest_fixed_ansi(
            engine,
            checked_field_address(display_device_ptr, 168, "DeviceID")?,
            128,
            b"MONITOR\\WIE\\DISPLAY1",
        )?;

        write_guest_fixed_ansi(
            engine,
            checked_field_address(display_device_ptr, 296, "DeviceKey")?,
            128,
            b"\\Registry\\Machine\\System\\CurrentControlSet\\Enum\\DISPLAY\\WIE",
        )?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from EnumDisplayDevicesA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles dynamic `USER32.dll!EnumDisplayDevicesW`.
pub fn handle_enum_display_devices_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _device_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for EnumDisplayDevicesW")?;

    let device_index = engine
        .read_rdx()
        .context("failed to read RDX for EnumDisplayDevicesW")?;

    let display_device_ptr = engine
        .read_r8()
        .context("failed to read R8 for EnumDisplayDevicesW")?;

    let _flags = engine
        .read_r9()
        .context("failed to read R9 for EnumDisplayDevicesW")?;

    let success = device_index == 0 && display_device_ptr != 0;

    if success {
        // DISPLAY_DEVICEW:
        // DWORD cb;                 offset 0
        // WCHAR DeviceName[32];     offset 4
        // WCHAR DeviceString[128];  offset 68
        // DWORD StateFlags;         offset 324
        // WCHAR DeviceID[128];      offset 328
        // WCHAR DeviceKey[128];     offset 584
        write_guest_u32(engine, display_device_ptr, 840)?;

        write_guest_fixed_utf16(
            engine,
            checked_field_address(display_device_ptr, 4, "DeviceName")?,
            32,
            "\\\\.\\DISPLAY1",
        )?;

        write_guest_fixed_utf16(
            engine,
            checked_field_address(display_device_ptr, 68, "DeviceString")?,
            128,
            "Generic Display",
        )?;

        write_guest_u32(
            engine,
            checked_field_address(display_device_ptr, 324, "StateFlags")?,
            DISPLAY_DEVICE_ATTACHED_TO_DESKTOP | DISPLAY_DEVICE_PRIMARY_DEVICE,
        )?;

        write_guest_fixed_utf16(
            engine,
            checked_field_address(display_device_ptr, 328, "DeviceID")?,
            128,
            "MONITOR\\WIE\\DISPLAY1",
        )?;

        write_guest_fixed_utf16(
            engine,
            checked_field_address(display_device_ptr, 584, "DeviceKey")?,
            128,
            "\\Registry\\Machine\\System\\CurrentControlSet\\Enum\\DISPLAY\\WIE",
        )?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from EnumDisplayDevicesW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetWindowRect`.
pub fn handle_get_window_rect(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetWindowRect")?;

    let rect_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetWindowRect")?;

    let window = find_window(state, window_handle);
    let success = window.is_some() && rect_ptr != 0;

    if let Some(window) = window.filter(|_| rect_ptr != 0) {
        let right = window
            .x
            .checked_add(window.width)
            .context("GetWindowRect right coordinate overflow")?;

        let bottom = window
            .y
            .checked_add(window.height)
            .context("GetWindowRect bottom coordinate overflow")?;

        write_window_rect(engine, rect_ptr, window.x, window.y, right, bottom)
            .context("failed to write GetWindowRect RECT")?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetWindowRect")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles dynamic `USER32.dll!GetDpiForWindow`.
pub fn handle_get_dpi_for_window(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetDpiForWindow")?;

    // Standard 100% Windows DPI.
    let return_value = 96;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetDpiForWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!PostMessageA`.
pub fn handle_post_message_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for PostMessageA")?;

    let message_raw = engine
        .read_rdx()
        .context("failed to read RDX for PostMessageA")?;

    let word_parameter = engine
        .read_r8()
        .context("failed to read R8 for PostMessageA")?;

    let long_parameter = engine
        .read_r9()
        .context("failed to read R9 for PostMessageA")?;

    let message = u32::try_from(message_raw & u64::from(u32::MAX))
        .context("PostMessageA message does not fit u32")?;

    let valid_window = window_handle == 0 || window_handle == FAKE_WINDOW_HANDLE;

    if valid_window {
        let time = state.next_message_time;

        state.next_message_time = state
            .next_message_time
            .checked_add(1)
            .context("PostMessageA timestamp overflow")?;

        state.message_queue.push(QueuedWindowMessage {
            window_handle,
            message,
            word_parameter,
            long_parameter,
            time,
            point_x: 0,
            point_y: 0,
        });
    }

    let return_value = u64::from(valid_window);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from PostMessageA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn scale_system_metric_for_dpi(base_value: u64, dpi: u64) -> Result<u64> {
    if dpi == 0 {
        return Ok(base_value);
    }

    // Floor-scale: base * dpi / 96 (Win32 DPI convention).
    let product = base_value
        .checked_mul(dpi)
        .context("GetSystemMetricsForDpi multiplication overflow")?;
    Ok(product.checked_div(96).unwrap_or(0))
}

/// Handles dynamic `USER32.dll!GetSystemMetricsForDpi`.
pub fn handle_get_system_metrics_for_dpi(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let metric_index = engine
        .read_rcx()
        .context("failed to read RCX for GetSystemMetricsForDpi")?;

    let dpi = engine
        .read_rdx()
        .context("failed to read RDX for GetSystemMetricsForDpi")?;

    let base_value = fake_system_metric(metric_index);
    let return_value = scale_system_metric_for_dpi(base_value, dpi)?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetSystemMetricsForDpi")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles dynamic `USER32.dll!AdjustWindowRectExForDpi`.
pub fn handle_adjust_window_rect_ex_for_dpi(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let rect_ptr = engine
        .read_rcx()
        .context("failed to read RCX for AdjustWindowRectExForDpi")?;

    let _style = engine
        .read_rdx()
        .context("failed to read RDX for AdjustWindowRectExForDpi")?;

    let _has_menu = engine
        .read_r8()
        .context("failed to read R8 for AdjustWindowRectExForDpi")?;

    let _extended_style = engine
        .read_r9()
        .context("failed to read R9 for AdjustWindowRectExForDpi")?;

    // The fifth argument, dpi, is on the Win64 stack. For now the fake desktop
    // uses 96 DPI, so preserving the supplied client rectangle is sufficient.
    let return_value = u64::from(rect_ptr != 0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from AdjustWindowRectExForDpi")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetWindowPos`.
pub fn handle_set_window_pos(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetWindowPos")?;

    let _insert_after = engine
        .read_rdx()
        .context("failed to read RDX for SetWindowPos")?;

    let _x = engine
        .read_r8()
        .context("failed to read R8 for SetWindowPos")?;

    let _y = engine
        .read_r9()
        .context("failed to read R9 for SetWindowPos")?;

    // Remaining Win64 arguments are width, height and flags on the stack.
    // For now the compatibility harness accepts the requested placement
    // without maintaining a full window manager.
    let return_value = 1;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetWindowPos")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetDC`.
pub fn handle_get_dc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine.read_rcx().context("failed to read RCX for GetDC")?;

    let return_address = engine
        .return_from_win64_api(FAKE_DEVICE_CONTEXT_HANDLE)
        .context("failed to return from GetDC")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_DEVICE_CONTEXT_HANDLE,
    })
}

/// Handles `USER32.dll!SendMessageA`.
pub fn handle_send_message_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    handle_send_message(engine, state, false, "SendMessageA")
}

/// Handles `USER32.dll!SendMessageW`.
pub fn handle_send_message_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    handle_send_message(engine, state, true, "SendMessageW")
}

fn handle_send_message(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    prefer_unicode: bool,
    api_name: &str,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .with_context(|| format!("failed to read RCX for {api_name}"))?;

    let message_raw = engine
        .read_rdx()
        .with_context(|| format!("failed to read RDX for {api_name}"))?;

    let word_parameter = engine
        .read_r8()
        .with_context(|| format!("failed to read R8 for {api_name}"))?;

    let long_parameter = engine
        .read_r9()
        .with_context(|| format!("failed to read R9 for {api_name}"))?;

    let message = u32::try_from(message_raw & u64::from(u32::MAX))
        .with_context(|| format!("{api_name} message does not fit u32"))?;

    // MDI client windows have no guest WndProc; WM_MDICREATE is handled here.
    if message == WM_MDICREATE {
        let child = create_mdi_child_from_struct(engine, state, long_parameter, prefer_unicode)
            .with_context(|| format!("failed to handle WM_MDICREATE in {api_name}"))?;

        let return_address = engine
            .return_from_win64_api(child)
            .with_context(|| format!("failed to return from {api_name} WM_MDICREATE"))?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: child,
        });
    }

    if let Some(target_window) = find_window(state, window_handle)
        && target_window.window_proc != 0
    {
        // Synchronous send: do not return yet; runtime bridges into WndProc.
        let unicode = if prefer_unicode {
            true
        } else {
            target_window.unicode
        };

        return Err(WinApiControlSignal::GuestCallbackRequested {
            request: GuestCallbackRequest {
                callback_address: target_window.window_proc,
                window_handle,
                message,
                word_parameter,
                long_parameter,
                unicode,
            },
        }
        .into());
    }

    let return_address = engine
        .return_from_win64_api(0)
        .with_context(|| format!("failed to return from {api_name}"))?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `USER32.dll!ReleaseDC`.
pub fn handle_release_dc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for ReleaseDC")?;

    let _device_context_handle = engine
        .read_rdx()
        .context("failed to read RDX for ReleaseDC")?;

    // ReleaseDC returns 1 when the device context was released.
    let return_value = 1;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ReleaseDC")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!LoadImageA`.
pub fn handle_load_image_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_load_image(engine, "LoadImageA")
}

/// Handles `USER32.dll!LoadImageW`.
pub fn handle_load_image_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_load_image(engine, "LoadImageW")
}

fn handle_load_image(
    engine: &mut dyn wie_cpu::CpuEngine,
    api_name: &str,
) -> Result<WinApiHandlerResult> {
    let _instance_handle = engine
        .read_rcx()
        .with_context(|| format!("failed to read RCX for {api_name}"))?;

    let _image_name_ptr = engine
        .read_rdx()
        .with_context(|| format!("failed to read RDX for {api_name}"))?;

    let _image_type = engine
        .read_r8()
        .with_context(|| format!("failed to read R8 for {api_name}"))?;

    let _desired_width = engine
        .read_r9()
        .with_context(|| format!("failed to read R9 for {api_name}"))?;

    // Win64 arguments 5 and 6 are desired height and load flags.
    // For bootstrap purposes, return a stable non-null image handle.
    let return_address = engine
        .return_from_win64_api(FAKE_IMAGE_HANDLE)
        .with_context(|| format!("failed to return from {api_name}"))?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_IMAGE_HANDLE,
    })
}

/// Handles `USER32.dll!SetWindowLongPtrW`.
pub fn handle_set_window_long_ptr_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetWindowLongPtrW")?;

    let index_raw = engine
        .read_rdx()
        .context("failed to read RDX for SetWindowLongPtrW")?;

    let new_value = engine
        .read_r8()
        .context("failed to read R8 for SetWindowLongPtrW")?;

    let previous_value = set_window_long_ptr_value(
        window_handle,
        index_raw,
        new_value,
        state,
        "SetWindowLongPtrW",
    )?;

    let return_address = engine
        .return_from_win64_api(previous_value)
        .context("failed to return from SetWindowLongPtrW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: previous_value,
    })
}

/// Handles `USER32.dll!DestroyIcon`.
pub fn handle_destroy_icon(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let icon_handle = engine
        .read_rcx()
        .context("failed to read RCX for DestroyIcon")?;

    let return_value = u64::from(icon_handle != 0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from DestroyIcon")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!IsWindow`.
pub fn handle_is_window(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for IsWindow")?;

    let return_value = u64::from(window_handle == FAKE_WINDOW_HANDLE);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IsWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!IsWindowVisible`.
pub fn handle_is_window_visible(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for IsWindowVisible")?;

    let return_value = u64::from(window_handle == FAKE_WINDOW_HANDLE);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IsWindowVisible")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!IsWindowEnabled`.
pub fn handle_is_window_enabled(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for IsWindowEnabled")?;

    let return_value = u64::from(window_handle == FAKE_WINDOW_HANDLE);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IsWindowEnabled")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetParent`.
pub fn handle_get_parent(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetParent")?;

    // The current fake top-level window has no parent.
    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetParent")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetActiveWindow`.
pub fn handle_get_active_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = state.active_window_handle;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetActiveWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetForegroundWindow`.
pub fn handle_get_foreground_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = state.foreground_window_handle;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetForegroundWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!ShowWindow`.
pub fn handle_show_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for ShowWindow")?;

    let show_command = engine
        .read_rdx()
        .context("failed to read RDX for ShowWindow")?;

    let previously_visible = state.window_visible;

    if window_handle == FAKE_WINDOW_HANDLE {
        // SW_HIDE is zero. Other commands make the window visible in the
        // current single-window model.
        state.window_visible = show_command != 0;
    }

    let return_value = u64::from(previously_visible);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ShowWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!EnableWindow`.
pub fn handle_enable_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for EnableWindow")?;

    let enable_raw = engine
        .read_rdx()
        .context("failed to read RDX for EnableWindow")?;

    let previously_disabled = !state.window_enabled;

    if window_handle == FAKE_WINDOW_HANDLE {
        state.window_enabled = enable_raw != 0;
    }

    // EnableWindow returns nonzero when the window was previously disabled.
    let return_value = u64::from(previously_disabled);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from EnableWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetForegroundWindow`.
pub fn handle_set_foreground_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetForegroundWindow")?;

    let success = window_handle == FAKE_WINDOW_HANDLE;

    if success {
        state.foreground_window_handle = window_handle;
        state.active_window_handle = window_handle;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetForegroundWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetActiveWindow`.
pub fn handle_set_active_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetActiveWindow")?;

    let previous_window = state.active_window_handle;

    if window_handle == 0 || window_handle == FAKE_WINDOW_HANDLE {
        state.active_window_handle = window_handle;
    }

    let return_address = engine
        .return_from_win64_api(previous_window)
        .context("failed to return from SetActiveWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: previous_window,
    })
}

/// Handles `USER32.dll!SetFocus`.
pub fn handle_set_focus(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetFocus")?;

    let previous_window = state.focus_window_handle;

    if window_handle == 0 || window_handle == FAKE_WINDOW_HANDLE {
        state.focus_window_handle = window_handle;
    }

    let return_address = engine
        .return_from_win64_api(previous_window)
        .context("failed to return from SetFocus")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: previous_window,
    })
}

/// Handles `USER32.dll!GetFocus`.
pub fn handle_get_focus(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = state.focus_window_handle;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFocus")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetCapture`.
pub fn handle_set_capture(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetCapture")?;

    let previous_window = state.capture_window_handle;

    if window_handle == FAKE_WINDOW_HANDLE {
        state.capture_window_handle = window_handle;
    }

    let return_address = engine
        .return_from_win64_api(previous_window)
        .context("failed to return from SetCapture")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: previous_window,
    })
}

/// Handles `USER32.dll!GetCapture`.
pub fn handle_get_capture(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = state.capture_window_handle;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetCapture")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!ReleaseCapture`.
pub fn handle_release_capture(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    state.capture_window_handle = 0;

    let return_value = 1;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ReleaseCapture")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetCursor`.
pub fn handle_set_cursor(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let cursor_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetCursor")?;

    let previous_cursor = state.cursor_handle;
    state.cursor_handle = cursor_handle;

    let return_address = engine
        .return_from_win64_api(previous_cursor)
        .context("failed to return from SetCursor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: previous_cursor,
    })
}

fn low_i32(value: u64, name: &str) -> Result<i32> {
    let low_value = value & u64::from(u32::MAX);

    let low = u32::try_from(low_value).with_context(|| format!("{name} does not fit u32"))?;

    Ok(i32::from_ne_bytes(low.to_ne_bytes()))
}

fn write_window_rect(
    engine: &mut dyn wie_cpu::CpuEngine,
    rect_ptr: u64,
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
) -> Result<()> {
    write_guest_i32(engine, rect_ptr, left)?;

    write_guest_i32(engine, checked_field_address(rect_ptr, 4, "RECT.top")?, top)?;

    write_guest_i32(
        engine,
        checked_field_address(rect_ptr, 8, "RECT.right")?,
        right,
    )?;

    write_guest_i32(
        engine,
        checked_field_address(rect_ptr, 12, "RECT.bottom")?,
        bottom,
    )?;

    Ok(())
}

fn write_ansi_window_text(
    engine: &mut dyn wie_cpu::CpuEngine,
    buffer_ptr: u64,
    max_characters: u64,
    text: &str,
) -> Result<u64> {
    let capacity =
        usize::try_from(max_characters).context("ANSI window text capacity does not fit usize")?;

    let copied = write_guest_ansi_c_string(engine, buffer_ptr, capacity, text)
        .context("failed to write ANSI window text")?;

    u64::try_from(copied).context("ANSI window text length does not fit u64")
}

fn write_wide_window_text(
    engine: &mut dyn wie_cpu::CpuEngine,
    buffer_ptr: u64,
    max_characters: u64,
    text: &str,
) -> Result<u64> {
    let capacity =
        usize::try_from(max_characters).context("wide window text capacity does not fit usize")?;

    let copied = write_guest_utf16_c_string(engine, buffer_ptr, capacity, text)
        .context("failed to write wide window text")?;

    u64::try_from(copied).context("wide window text length does not fit u64")
}

/// Handles `USER32.dll!UpdateWindow`.
pub fn handle_update_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for UpdateWindow")?;

    let success = is_known_window(state, window_handle);

    if success {
        state.window_invalidated = false;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from UpdateWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!InvalidateRect`.
pub fn handle_invalidate_rect(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for InvalidateRect")?;

    let _rect_ptr = engine
        .read_rdx()
        .context("failed to read RDX for InvalidateRect")?;

    let _erase_background = engine
        .read_r8()
        .context("failed to read R8 for InvalidateRect")?;

    let success = window_handle == 0 || is_known_window(state, window_handle);

    if success {
        state.window_invalidated = true;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from InvalidateRect")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!BeginPaint`.
///
/// Fills `PAINTSTRUCT` with a fake HDC and client rect; real painting is stubbed.
pub fn handle_begin_paint(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for BeginPaint")?;

    let paint_ptr = engine
        .read_rdx()
        .context("failed to read RDX for BeginPaint")?;

    let known = is_known_window(state, window_handle);
    let return_value = if known && paint_ptr != 0 {
        let (width, height) = window_client_size(state, window_handle);

        // PAINTSTRUCT (Win64):
        // HDC  hdc;           0
        // BOOL fErase;        8
        // RECT rcPaint;       12  (left, top, right, bottom)
        // BOOL fRestore;      28
        // BOOL fIncUpdate;    32
        // BYTE rgbReserved[32]; 36
        write_guest_u64(engine, paint_ptr, FAKE_DEVICE_CONTEXT_HANDLE)?;
        write_guest_u32(engine, checked_field_address(paint_ptr, 8, "fErase")?, 1)?;
        write_guest_i32(
            engine,
            checked_field_address(paint_ptr, 12, "rcPaint.left")?,
            0,
        )?;
        write_guest_i32(
            engine,
            checked_field_address(paint_ptr, 16, "rcPaint.top")?,
            0,
        )?;
        write_guest_i32(
            engine,
            checked_field_address(paint_ptr, 20, "rcPaint.right")?,
            width,
        )?;
        write_guest_i32(
            engine,
            checked_field_address(paint_ptr, 24, "rcPaint.bottom")?,
            height,
        )?;
        write_guest_u32(engine, checked_field_address(paint_ptr, 28, "fRestore")?, 0)?;
        write_guest_u32(
            engine,
            checked_field_address(paint_ptr, 32, "fIncUpdate")?,
            0,
        )?;
        // rgbReserved left zeroed by guest or ignored.

        tracing::debug!(window_handle, width, height, "BeginPaint");
        FAKE_DEVICE_CONTEXT_HANDLE
    } else {
        tracing::debug!(window_handle, paint_ptr, known, "BeginPaint rejected");
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from BeginPaint")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!EndPaint`.
pub fn handle_end_paint(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for EndPaint")?;

    let _paint_ptr = engine
        .read_rdx()
        .context("failed to read RDX for EndPaint")?;

    let success = is_known_window(state, window_handle);
    if success {
        state.window_invalidated = false;
    }

    let return_value = u64::from(success);
    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from EndPaint")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!RedrawWindow`.
pub fn handle_redraw_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for RedrawWindow")?;

    let _update_rect_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RedrawWindow")?;

    let _update_region = engine
        .read_r8()
        .context("failed to read R8 for RedrawWindow")?;

    let _flags = engine
        .read_r9()
        .context("failed to read R9 for RedrawWindow")?;

    let success = window_handle == 0 || window_handle == FAKE_WINDOW_HANDLE;

    if success {
        state.window_invalidated = false;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from RedrawWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetWindowTextA`.
pub fn handle_set_window_text_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetWindowTextA")?;

    let text_ptr = engine
        .read_rdx()
        .context("failed to read RDX for SetWindowTextA")?;

    let success = window_handle == FAKE_WINDOW_HANDLE && text_ptr != 0;

    if success {
        state.window_title = read_guest_ansi_lossy(engine, text_ptr, 32_768)
            .context("failed to read SetWindowTextA text")?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetWindowTextA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetWindowTextW`.
pub fn handle_set_window_text_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetWindowTextW")?;

    let text_ptr = engine
        .read_rdx()
        .context("failed to read RDX for SetWindowTextW")?;

    let success = window_handle == FAKE_WINDOW_HANDLE && text_ptr != 0;

    if success {
        state.window_title = read_guest_utf16_lossy(engine, text_ptr, 32_768)
            .context("failed to read SetWindowTextW text")?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetWindowTextW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetWindowTextA`.
pub fn handle_get_window_text_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetWindowTextA")?;

    let buffer_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetWindowTextA")?;

    let max_characters = engine
        .read_r8()
        .context("failed to read R8 for GetWindowTextA")?;

    let return_value = if window_handle == FAKE_WINDOW_HANDLE {
        write_ansi_window_text(engine, buffer_ptr, max_characters, &state.window_title)?
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetWindowTextA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetWindowTextW`.
pub fn handle_get_window_text_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetWindowTextW")?;

    let buffer_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetWindowTextW")?;

    let max_characters = engine
        .read_r8()
        .context("failed to read R8 for GetWindowTextW")?;

    let return_value = if window_handle == FAKE_WINDOW_HANDLE {
        write_wide_window_text(engine, buffer_ptr, max_characters, &state.window_title)?
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetWindowTextW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetClientRect`.
pub fn handle_get_client_rect(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetClientRect")?;

    let rect_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetClientRect")?;

    let success = is_known_window(state, window_handle) && rect_ptr != 0;

    if success {
        let (width, height) = window_client_size(state, window_handle);
        write_window_rect(engine, rect_ptr, 0, 0, width, height)?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetClientRect")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!MoveWindow`.
pub fn handle_move_window(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for MoveWindow")?;

    let x_raw = engine
        .read_rdx()
        .context("failed to read RDX for MoveWindow")?;

    let y_raw = engine
        .read_r8()
        .context("failed to read R8 for MoveWindow")?;

    let width_raw = engine
        .read_r9()
        .context("failed to read R9 for MoveWindow")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for MoveWindow")?;

    let height_arg_address = rsp
        .checked_add(0x28)
        .context("MoveWindow height argument address overflow")?;

    let repaint_arg_address = rsp
        .checked_add(0x30)
        .context("MoveWindow repaint argument address overflow")?;

    let height_raw = read_guest_u64(engine, height_arg_address)?;
    let repaint_raw = read_guest_u64(engine, repaint_arg_address)?;

    let success = window_handle == FAKE_WINDOW_HANDLE;

    if success {
        state.window_x = low_i32(x_raw, "MoveWindow x")?;
        state.window_y = low_i32(y_raw, "MoveWindow y")?;
        state.window_width = low_i32(width_raw, "MoveWindow width")?;
        state.window_height = low_i32(height_raw, "MoveWindow height")?;

        if repaint_raw != 0 {
            state.window_invalidated = false;
        }
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from MoveWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!ScreenToClient`.
pub fn handle_screen_to_client(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for ScreenToClient")?;

    let point_ptr = engine
        .read_rdx()
        .context("failed to read RDX for ScreenToClient")?;

    let success = window_handle == FAKE_WINDOW_HANDLE && point_ptr != 0;

    if success {
        let x = read_guest_i32(engine, point_ptr)?;

        let y_address = checked_field_address(point_ptr, 4, "POINT.y")?;

        let y = read_guest_i32(engine, y_address)?;

        let client_x = x
            .checked_sub(state.window_x)
            .context("ScreenToClient x coordinate overflow")?;

        let client_y = y
            .checked_sub(state.window_y)
            .context("ScreenToClient y coordinate overflow")?;

        write_guest_i32(engine, point_ptr, client_x)?;
        write_guest_i32(engine, y_address, client_y)?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ScreenToClient")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!ClientToScreen`.
pub fn handle_client_to_screen(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for ClientToScreen")?;

    let point_ptr = engine
        .read_rdx()
        .context("failed to read RDX for ClientToScreen")?;

    let success = window_handle == FAKE_WINDOW_HANDLE && point_ptr != 0;

    if success {
        let x = read_guest_i32(engine, point_ptr)?;

        let y_address = checked_field_address(point_ptr, 4, "POINT.y")?;

        let y = read_guest_i32(engine, y_address)?;

        let screen_x = x
            .checked_add(state.window_x)
            .context("ClientToScreen x coordinate overflow")?;

        let screen_y = y
            .checked_add(state.window_y)
            .context("ClientToScreen y coordinate overflow")?;

        write_guest_i32(engine, point_ptr, screen_x)?;
        write_guest_i32(engine, y_address, screen_y)?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from ClientToScreen")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetDesktopWindow`.
pub fn handle_get_desktop_window(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(FAKE_DESKTOP_WINDOW_HANDLE)
        .context("failed to return from GetDesktopWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_DESKTOP_WINDOW_HANDLE,
    })
}

/// Handles `USER32.dll!GetSysColor`.
pub fn handle_get_sys_color(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let color_index = engine
        .read_rcx()
        .context("failed to read RCX for GetSysColor")?;

    let return_value = match color_index {
        // Black-like colors:
        // COLOR_BACKGROUND, COLOR_WINDOWFRAME,
        // COLOR_MENUTEXT, COLOR_WINDOWTEXT,
        // COLOR_CAPTIONTEXT, COLOR_BTNTEXT.
        1 | 6 | 7..=9 | 18 => 0x0000_0000,

        // Accent colors:
        // COLOR_ACTIVECAPTION, COLOR_HIGHLIGHT.
        2 | 13 => 0x00d7_7830,

        // COLOR_INACTIVECAPTION.
        3 => 0x00bf_bfbf,

        // White-like colors:
        // COLOR_WINDOW, COLOR_HIGHLIGHTTEXT.
        5 | 14 => 0x00ff_ffff,

        // COLOR_ACTIVEBORDER, COLOR_INACTIVEBORDER.
        10 | 11 => 0x00b4_b4b4,

        // COLOR_APPWORKSPACE.
        12 => 0x00ab_abab,

        // COLOR_BTNSHADOW.
        16 => 0x00a0_a0a0,

        // COLOR_GRAYTEXT.
        17 => 0x006d_6d6d,

        // COLOR_SCROLLBAR.
        0 => 0x00c8_c8c8,

        // COLOR_MENU, COLOR_BTNFACE and neutral fallback.
        _ => 0x00f0_f0f0,
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetSysColor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetSysColorBrush`.
pub fn handle_get_sys_color_brush(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let color_index = engine
        .read_rcx()
        .context("failed to read RCX for GetSysColorBrush")?;

    let return_value = FAKE_SYSTEM_COLOR_BRUSH_BASE
        .checked_add(color_index)
        .context("GetSysColorBrush handle overflow")?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetSysColorBrush")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetDialogBaseUnits`.
pub fn handle_get_dialog_base_units(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_value = u64::from(DIALOG_BASE_UNIT_X | (DIALOG_BASE_UNIT_Y << 16));

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetDialogBaseUnits")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetRect`.
pub fn handle_set_rect(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let rect_ptr = engine
        .read_rcx()
        .context("failed to read RCX for SetRect")?;

    let left_raw = engine
        .read_rdx()
        .context("failed to read RDX for SetRect")?;

    let top_raw = engine.read_r8().context("failed to read R8 for SetRect")?;

    let right_raw = engine.read_r9().context("failed to read R9 for SetRect")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for SetRect")?;

    let bottom_address = rsp
        .checked_add(0x28)
        .context("SetRect bottom argument address overflow")?;

    let bottom_raw = read_guest_u64(engine, bottom_address)?;

    let success = rect_ptr != 0;

    if success {
        write_window_rect(
            engine,
            rect_ptr,
            low_i32(left_raw, "SetRect left")?,
            low_i32(top_raw, "SetRect top")?,
            low_i32(right_raw, "SetRect right")?,
            low_i32(bottom_raw, "SetRect bottom")?,
        )?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetRect")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!IsIconic`.
pub fn handle_is_iconic(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for IsIconic")?;

    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IsIconic")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!IsZoomed`.
pub fn handle_is_zoomed(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for IsZoomed")?;

    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IsZoomed")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetWindowThreadProcessId`.
pub fn handle_get_window_thread_process_id(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetWindowThreadProcessId")?;

    let process_id_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetWindowThreadProcessId")?;

    let valid_window =
        window_handle == FAKE_WINDOW_HANDLE || window_handle == FAKE_DESKTOP_WINDOW_HANDLE;

    if valid_window && process_id_ptr != 0 {
        write_guest_u32(engine, process_id_ptr, FAKE_PROCESS_ID)?;
    }

    let return_value = if valid_window { FAKE_THREAD_ID } else { 0 };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetWindowThreadProcessId")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetDlgCtrlID`.
pub fn handle_get_dlg_ctrl_id(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetDlgCtrlID")?;

    // The current single-window model has no child-control identifier.
    let return_value = if window_handle == FAKE_WINDOW_HANDLE {
        0
    } else {
        u64::from(u32::MAX)
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetDlgCtrlID")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetCursor`.
pub fn handle_get_cursor(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = state.cursor_handle;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetCursor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!IsChild`.
pub fn handle_is_child(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _parent_handle = engine
        .read_rcx()
        .context("failed to read RCX for IsChild")?;

    let _child_handle = engine
        .read_rdx()
        .context("failed to read RDX for IsChild")?;

    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IsChild")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetWindow`.
pub fn handle_get_window(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetWindow")?;

    let _command = engine
        .read_rdx()
        .context("failed to read RDX for GetWindow")?;

    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetWindow")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetKeyboardState`.
pub fn handle_set_keyboard_state(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let keyboard_state_ptr = engine
        .read_rcx()
        .context("failed to read RCX for SetKeyboardState")?;

    let success = keyboard_state_ptr != 0;

    if success {
        read_guest_bytes(engine, keyboard_state_ptr, &mut state.keyboard_state)
            .context("failed to read SetKeyboardState buffer")?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetKeyboardState")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetKeyboardState`.
pub fn handle_get_keyboard_state(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let keyboard_state_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetKeyboardState")?;

    let success = keyboard_state_ptr != 0;

    if success {
        write_guest_bytes(engine, keyboard_state_ptr, &state.keyboard_state)
            .context("failed to write GetKeyboardState buffer")?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetKeyboardState")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!GetKeyState`.
pub fn handle_get_key_state(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let virtual_key_raw = engine
        .read_rcx()
        .context("failed to read RCX for GetKeyState")?;

    let virtual_key = usize::try_from(virtual_key_raw & 0xff)
        .context("GetKeyState virtual key does not fit usize")?;

    let key_state = state.keyboard_state.get(virtual_key).copied().unwrap_or(0);

    // WinAPI uses the high bit of SHORT to indicate a pressed key.
    let return_value = if (key_state & 0x80) != 0 {
        u64::from(0x8000_u16)
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetKeyState")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!MapVirtualKeyA`.
pub fn handle_map_virtual_key_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let code = engine
        .read_rcx()
        .context("failed to read RCX for MapVirtualKeyA")?;

    let map_type = engine
        .read_rdx()
        .context("failed to read RDX for MapVirtualKeyA")?;

    let code_low = code & u64::from(u32::MAX);

    let return_value = match map_type {
        // MAPVK_VK_TO_VSC / MAPVK_VSC_TO_VK / MAPVK_VSC_TO_VK_EX
        0 | 1 | 3 | 4 => code_low,

        // MAPVK_VK_TO_CHAR: approximate printable ASCII keys.
        2 if (0x20..=0x7e).contains(&code_low) => code_low,

        _ => 0,
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from MapVirtualKeyA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn window_long_ptr_index(index_raw: u64, api_name: &str) -> Result<i64> {
    let index_low = u32::try_from(index_raw)
        .with_context(|| format!("{api_name} index does not fit in u32"))?;

    Ok(i64::from(i32::from_ne_bytes(index_low.to_ne_bytes())))
}

fn get_window_long_ptr_value(
    window_handle: u64,
    index_raw: u64,
    state: &WinApiState,
    api_name: &str,
) -> Result<u64> {
    let index = window_long_ptr_index(index_raw, api_name)?;

    Ok(state
        .window_long_ptr_values
        .iter()
        .find(|(stored_window, stored_index, _)| {
            *stored_window == window_handle && *stored_index == index
        })
        .map_or(0, |(_, _, value)| *value))
}

fn set_window_long_ptr_value(
    window_handle: u64,
    index_raw: u64,
    new_value: u64,
    state: &mut WinApiState,
    api_name: &str,
) -> Result<u64> {
    let index = window_long_ptr_index(index_raw, api_name)?;

    let previous_value = state
        .window_long_ptr_values
        .iter()
        .find(|(stored_window, stored_index, _)| {
            *stored_window == window_handle && *stored_index == index
        })
        .map_or(0, |(_, _, value)| *value);

    if let Some(entry) =
        state
            .window_long_ptr_values
            .iter_mut()
            .find(|(stored_window, stored_index, _)| {
                *stored_window == window_handle && *stored_index == index
            })
    {
        entry.2 = new_value;
    } else {
        state
            .window_long_ptr_values
            .push((window_handle, index, new_value));
    }

    Ok(previous_value)
}

/// Handles `USER32.dll!GetWindowLongPtrA`.
pub fn handle_get_window_long_ptr_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetWindowLongPtrA")?;

    let index_raw = engine
        .read_rdx()
        .context("failed to read RDX for GetWindowLongPtrA")?;

    let value = get_window_long_ptr_value(window_handle, index_raw, state, "GetWindowLongPtrA")?;

    let return_address = engine
        .return_from_win64_api(value)
        .context("failed to return from GetWindowLongPtrA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

/// Handles `USER32.dll!GetWindowLongPtrW`.
pub fn handle_get_window_long_ptr_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetWindowLongPtrW")?;

    let index_raw = engine
        .read_rdx()
        .context("failed to read RDX for GetWindowLongPtrW")?;

    let value = get_window_long_ptr_value(window_handle, index_raw, state, "GetWindowLongPtrW")?;

    let return_address = engine
        .return_from_win64_api(value)
        .context("failed to return from GetWindowLongPtrW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

/// Handles `USER32.dll!SetWindowLongPtrA`.
pub fn handle_set_window_long_ptr_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetWindowLongPtrA")?;

    let index_raw = engine
        .read_rdx()
        .context("failed to read RDX for SetWindowLongPtrA")?;

    let new_value = engine
        .read_r8()
        .context("failed to read R8 for SetWindowLongPtrA")?;

    let previous_value = set_window_long_ptr_value(
        window_handle,
        index_raw,
        new_value,
        state,
        "SetWindowLongPtrA",
    )?;

    let return_address = engine
        .return_from_win64_api(previous_value)
        .context("failed to return from SetWindowLongPtrA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: previous_value,
    })
}

/// Handles `USER32.dll!SetTimer`.
pub fn handle_set_timer(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetTimer")?;

    let requested_timer_id = engine
        .read_rdx()
        .context("failed to read RDX for SetTimer")?;

    let interval_raw = engine.read_r8().context("failed to read R8 for SetTimer")?;

    let callback_address = engine.read_r9().context("failed to read R9 for SetTimer")?;

    let valid_window = window_handle == 0 || window_handle == FAKE_WINDOW_HANDLE;

    let interval_low = interval_raw & u64::from(u32::MAX);

    let interval_ms = u32::try_from(interval_low).context("SetTimer interval does not fit u32")?;

    let return_value = if valid_window {
        let timer_id = if requested_timer_id == 0 {
            let generated_id = state.next_timer_id;

            state.next_timer_id = state
                .next_timer_id
                .checked_add(1)
                .context("SetTimer identifier overflow")?;

            generated_id
        } else {
            requested_timer_id
        };

        if let Some(timer) = state
            .timers
            .iter_mut()
            .find(|timer| timer.window_handle == window_handle && timer.timer_id == timer_id)
        {
            timer.interval_ms = interval_ms;
            timer.callback_address = callback_address;
        } else {
            state.timers.push(TimerRecord {
                window_handle,
                timer_id,
                interval_ms,
                callback_address,
            });
        }

        timer_id
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetTimer")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!KillTimer`.
pub fn handle_kill_timer(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for KillTimer")?;

    let timer_id = engine
        .read_rdx()
        .context("failed to read RDX for KillTimer")?;

    let existed = state
        .timers
        .iter()
        .any(|timer| timer.window_handle == window_handle && timer.timer_id == timer_id);

    if existed {
        state
            .timers
            .retain(|timer| timer.window_handle != window_handle || timer.timer_id != timer_id);
    }

    let return_value = u64::from(existed);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from KillTimer")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!AdjustWindowRectEx`.
pub fn handle_adjust_window_rect_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let rect_ptr = engine
        .read_rcx()
        .context("failed to read RCX for AdjustWindowRectEx")?;

    let _style = engine
        .read_rdx()
        .context("failed to read RDX for AdjustWindowRectEx")?;

    let has_menu = engine
        .read_r8()
        .context("failed to read R8 for AdjustWindowRectEx")?;

    let _extended_style = engine
        .read_r9()
        .context("failed to read R9 for AdjustWindowRectEx")?;

    let success = rect_ptr != 0;

    if success {
        let left = read_guest_i32(engine, rect_ptr)?;

        let top_address = checked_field_address(rect_ptr, 4, "RECT.top")?;
        let right_address = checked_field_address(rect_ptr, 8, "RECT.right")?;
        let bottom_address = checked_field_address(rect_ptr, 12, "RECT.bottom")?;

        let top = read_guest_i32(engine, top_address)?;
        let right = read_guest_i32(engine, right_address)?;
        let bottom = read_guest_i32(engine, bottom_address)?;

        // Approximate classic non-client metrics:
        // 8 px frame on each side, 31 px caption,
        // and another 20 px when a menu is present.
        let menu_height = if has_menu != 0 { 20 } else { 0 };

        let adjusted_left = left
            .checked_sub(8)
            .context("AdjustWindowRectEx left overflow")?;

        let adjusted_top = top
            .checked_sub(31)
            .and_then(|value| value.checked_sub(menu_height))
            .context("AdjustWindowRectEx top overflow")?;

        let adjusted_right = right
            .checked_add(8)
            .context("AdjustWindowRectEx right overflow")?;

        let adjusted_bottom = bottom
            .checked_add(8)
            .context("AdjustWindowRectEx bottom overflow")?;

        write_window_rect(
            engine,
            rect_ptr,
            adjusted_left,
            adjusted_top,
            adjusted_right,
            adjusted_bottom,
        )?;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from AdjustWindowRectEx")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!SetWindowsHookExW`.
pub fn handle_set_windows_hook_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let hook_type_raw = engine
        .read_rcx()
        .context("failed to read RCX for SetWindowsHookExW")?;

    let callback_address = engine
        .read_rdx()
        .context("failed to read RDX for SetWindowsHookExW")?;

    let module_handle = engine
        .read_r8()
        .context("failed to read R8 for SetWindowsHookExW")?;

    let thread_id_raw = engine
        .read_r9()
        .context("failed to read R9 for SetWindowsHookExW")?;

    let hook_type = low_i32(hook_type_raw, "SetWindowsHookExW hook type")?;

    let thread_id_low = thread_id_raw & u64::from(u32::MAX);
    let thread_id = u32::try_from(thread_id_low)
        .context("SetWindowsHookExW thread identifier does not fit u32")?;

    let return_value = if callback_address == 0 {
        0
    } else {
        let handle = state.next_windows_hook_handle;

        state.next_windows_hook_handle = state
            .next_windows_hook_handle
            .checked_add(1)
            .context("SetWindowsHookExW handle overflow")?;

        state.windows_hooks.push(WindowsHookRecord {
            handle,
            hook_type,
            callback_address,
            module_handle,
            thread_id,
        });

        handle
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetWindowsHookExW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!UnhookWindowsHookEx`.
pub fn handle_unhook_windows_hook_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let hook_handle = engine
        .read_rcx()
        .context("failed to read RCX for UnhookWindowsHookEx")?;

    let existed = state
        .windows_hooks
        .iter()
        .any(|hook| hook.handle == hook_handle);

    if existed {
        state
            .windows_hooks
            .retain(|hook| hook.handle != hook_handle);
    }

    let return_value = u64::from(existed);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from UnhookWindowsHookEx")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!CallNextHookEx`.
pub fn handle_call_next_hook_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _hook_handle = engine
        .read_rcx()
        .context("failed to read RCX for CallNextHookEx")?;

    let _code = engine
        .read_rdx()
        .context("failed to read RDX for CallNextHookEx")?;

    let _word_parameter = engine
        .read_r8()
        .context("failed to read R8 for CallNextHookEx")?;

    let _long_parameter = engine
        .read_r9()
        .context("failed to read R9 for CallNextHookEx")?;

    // There is currently no host-side hook chain after the guest hook.
    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from CallNextHookEx")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!EnableMenuItem`.
pub fn handle_enable_menu_item(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let menu_handle = engine
        .read_rcx()
        .context("failed to read RCX for EnableMenuItem")?;

    let item_raw = engine
        .read_rdx()
        .context("failed to read RDX for EnableMenuItem")?;

    let flags_raw = engine
        .read_r8()
        .context("failed to read R8 for EnableMenuItem")?;

    let item = u32::try_from(item_raw & u64::from(u32::MAX))
        .context("EnableMenuItem item does not fit u32")?;

    let flags = u32::try_from(flags_raw & u64::from(u32::MAX))
        .context("EnableMenuItem flags do not fit u32")?;

    let previous_flags = state
        .menu_item_states
        .iter()
        .find(|(stored_menu, stored_item, _)| *stored_menu == menu_handle && *stored_item == item)
        .map_or(u32::MAX, |(_, _, stored_flags)| *stored_flags);

    if let Some(entry) = state
        .menu_item_states
        .iter_mut()
        .find(|(stored_menu, stored_item, _)| *stored_menu == menu_handle && *stored_item == item)
    {
        entry.2 = flags;
    } else {
        state.menu_item_states.push((menu_handle, item, flags));
    }

    let return_value = u64::from(previous_flags);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from EnableMenuItem")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!CheckMenuItem`.
pub fn handle_check_menu_item(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let menu_handle = engine
        .read_rcx()
        .context("failed to read RCX for CheckMenuItem")?;

    let item_raw = engine
        .read_rdx()
        .context("failed to read RDX for CheckMenuItem")?;

    let flags_raw = engine
        .read_r8()
        .context("failed to read R8 for CheckMenuItem")?;

    let item = u32::try_from(item_raw & u64::from(u32::MAX))
        .context("CheckMenuItem item does not fit u32")?;

    let flags = u32::try_from(flags_raw & u64::from(u32::MAX))
        .context("CheckMenuItem flags do not fit u32")?;

    let previous_flags = state
        .menu_item_check_states
        .iter()
        .find(|(stored_menu, stored_item, _)| *stored_menu == menu_handle && *stored_item == item)
        .map_or(u32::MAX, |(_, _, stored_flags)| *stored_flags);

    if let Some(entry) = state
        .menu_item_check_states
        .iter_mut()
        .find(|(stored_menu, stored_item, _)| *stored_menu == menu_handle && *stored_item == item)
    {
        entry.2 = flags;
    } else {
        state
            .menu_item_check_states
            .push((menu_handle, item, flags));
    }

    let return_value = u64::from(previous_flags);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from CheckMenuItem")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn write_message_structure(
    engine: &mut dyn wie_cpu::CpuEngine,
    message_address: u64,
    message: &QueuedWindowMessage,
) -> Result<()> {
    write_guest_u64(engine, message_address, message.window_handle)
        .context("failed to write MSG.hwnd")?;

    write_guest_u32(
        engine,
        checked_field_address(message_address, 8, "MSG.message")?,
        message.message,
    )
    .context("failed to write MSG.message")?;

    // Bytes 12..16 are alignment padding on Win64.
    write_guest_u32(
        engine,
        checked_field_address(message_address, 12, "MSG alignment padding")?,
        0,
    )
    .context("failed to clear MSG alignment padding")?;

    write_guest_u64(
        engine,
        checked_field_address(message_address, 16, "MSG.wParam")?,
        message.word_parameter,
    )
    .context("failed to write MSG.wParam")?;

    write_guest_u64(
        engine,
        checked_field_address(message_address, 24, "MSG.lParam")?,
        message.long_parameter,
    )
    .context("failed to write MSG.lParam")?;

    write_guest_u32(
        engine,
        checked_field_address(message_address, 32, "MSG.time")?,
        message.time,
    )
    .context("failed to write MSG.time")?;

    write_guest_i32(
        engine,
        checked_field_address(message_address, 36, "MSG.pt.x")?,
        message.point_x,
    )
    .context("failed to write MSG.pt.x")?;

    write_guest_i32(
        engine,
        checked_field_address(message_address, 40, "MSG.pt.y")?,
        message.point_y,
    )
    .context("failed to write MSG.pt.y")?;

    // MSG.lPrivate on modern Win64 layouts.
    write_guest_u32(
        engine,
        checked_field_address(message_address, 44, "MSG.lPrivate")?,
        0,
    )
    .context("failed to clear MSG.lPrivate")?;

    Ok(())
}

/// Handles `USER32.dll!GetMessageA`.
pub fn handle_get_message_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let message_address = engine
        .read_rcx()
        .context("failed to read RCX for GetMessageA")?;

    let window_filter = engine
        .read_rdx()
        .context("failed to read RDX for GetMessageA")?;

    let minimum_message_raw = engine
        .read_r8()
        .context("failed to read R8 for GetMessageA")?;

    let maximum_message_raw = engine
        .read_r9()
        .context("failed to read R9 for GetMessageA")?;

    let minimum_message = u32::try_from(minimum_message_raw & u64::from(u32::MAX))
        .context("GetMessageA minimum message does not fit u32")?;

    let maximum_message = u32::try_from(maximum_message_raw & u64::from(u32::MAX))
        .context("GetMessageA maximum message does not fit u32")?;

    let matches_filter = |queued: &QueuedWindowMessage| -> bool {
        let window_matches = window_filter == 0 || queued.window_handle == window_filter;

        let message_matches = if minimum_message == 0 && maximum_message == 0 {
            true
        } else {
            queued.message >= minimum_message && queued.message <= maximum_message
        };

        window_matches && message_matches
    };

    let matching_index = state.message_queue.iter().position(matches_filter);

    let return_value = if message_address == 0 {
        // GetMessage returns -1 on failure.
        u64::from(u32::MAX)
    } else if let Some(index) = matching_index {
        let queued = state.message_queue.remove(index);

        write_message_structure(engine, message_address, &queued)?;

        u64::from(queued.message != WM_QUIT)
    } else {
        match state.message_queue_idle_policy {
            MessageQueueIdlePolicy::ExitOnIdle => {
                /*
                 * Regression mode: represent an empty queue as a synthetic
                 * WM_QUIT so the guest performs its normal teardown.
                 */
                let quit_message = QueuedWindowMessage {
                    window_handle: 0,
                    message: WM_QUIT,
                    word_parameter: 0,
                    long_parameter: 0,
                    time: state.next_message_time,
                    point_x: 0,
                    point_y: 0,
                };

                state.next_message_time = state
                    .next_message_time
                    .checked_add(1)
                    .context("GetMessageA timestamp overflow")?;

                write_message_structure(engine, message_address, &quit_message)?;

                0
            }

            MessageQueueIdlePolicy::YieldOnIdle => {
                return Err(WinApiControlSignal::WaitingForMessage.into());
            }
        }
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetMessageA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!TranslateMessage`.
pub fn handle_translate_message(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let message_address = engine
        .read_rcx()
        .context("failed to read RCX for TranslateMessage")?;

    let translated = if message_address == 0 {
        false
    } else {
        let message_field_address = checked_field_address(message_address, 8, "MSG.message")?;

        let message = crate::guest_memory::read_u32(engine, message_field_address)
            .context("failed to read MSG.message for TranslateMessage")?;

        matches!(
            message,
            WM_KEYDOWN
                | WM_KEYUP
                | WM_CHAR
                | WM_DEADCHAR
                | WM_SYSKEYDOWN
                | WM_SYSKEYUP
                | WM_SYSCHAR
                | WM_SYSDEADCHAR
        )
    };

    let return_value = u64::from(translated);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from TranslateMessage")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Neutral default message handler used by several USER32 `Def*Proc` APIs.
fn handle_default_window_procedure(
    engine: &mut dyn wie_cpu::CpuEngine,
    api_name: &str,
) -> Result<WinApiHandlerResult> {
    // hwnd / msg / wParam / lParam (and optional extra args) are ignored.
    // Returning 0 is the usual default for unhandled messages in stubs.
    let return_address = engine
        .return_from_win64_api(0)
        .with_context(|| format!("failed to return from {api_name}"))?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `USER32.dll!DefWindowProcA`.
pub fn handle_def_window_proc_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_default_window_procedure(engine, "DefWindowProcA")
}

/// Handles `USER32.dll!DefWindowProcW`.
pub fn handle_def_window_proc_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_default_window_procedure(engine, "DefWindowProcW")
}

/// Handles `USER32.dll!DefFrameProcA`.
pub fn handle_def_frame_proc_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_default_window_procedure(engine, "DefFrameProcA")
}

/// Handles `USER32.dll!DefFrameProcW`.
pub fn handle_def_frame_proc_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_default_window_procedure(engine, "DefFrameProcW")
}

/// Handles `USER32.dll!DefMDIChildProcA`.
pub fn handle_def_mdi_child_proc_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_default_window_procedure(engine, "DefMDIChildProcA")
}

/// Handles `USER32.dll!DefMDIChildProcW`.
pub fn handle_def_mdi_child_proc_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_default_window_procedure(engine, "DefMDIChildProcW")
}

fn allocate_menu_handle(state: &mut WinApiState) -> Result<u64> {
    let handle = state.next_menu_handle;
    state.next_menu_handle = state
        .next_menu_handle
        .checked_add(1)
        .context("menu handle allocator overflow")?;
    Ok(handle)
}

fn handle_menu_success(
    engine: &mut dyn wie_cpu::CpuEngine,
    api_name: &str,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(1)
        .with_context(|| format!("failed to return from {api_name}"))?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `USER32.dll!CreateMenu`.
pub fn handle_create_menu(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = allocate_menu_handle(state)?;
    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from CreateMenu")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// Handles `USER32.dll!CreatePopupMenu`.
pub fn handle_create_popup_menu(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = allocate_menu_handle(state)?;
    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from CreatePopupMenu")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// Handles `USER32.dll!AppendMenuA`.
pub fn handle_append_menu_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "AppendMenuA")
}

/// Handles `USER32.dll!AppendMenuW`.
pub fn handle_append_menu_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "AppendMenuW")
}

/// Handles `USER32.dll!SetMenu`.
pub fn handle_set_menu(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "SetMenu")
}

/// Handles `USER32.dll!DestroyMenu`.
pub fn handle_destroy_menu(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "DestroyMenu")
}

/// Handles `USER32.dll!RemoveMenu`.
pub fn handle_remove_menu(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "RemoveMenu")
}

/// Handles `USER32.dll!DeleteMenu`.
pub fn handle_delete_menu(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "DeleteMenu")
}

/// Handles `USER32.dll!ModifyMenuA`.
pub fn handle_modify_menu_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "ModifyMenuA")
}

/// Handles `USER32.dll!ModifyMenuW`.
pub fn handle_modify_menu_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "ModifyMenuW")
}

/// Handles `USER32.dll!GetSystemMenu`.
pub fn handle_get_system_menu(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = allocate_menu_handle(state)?;
    let return_address = engine
        .return_from_win64_api(handle)
        .context("failed to return from GetSystemMenu")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// Handles `USER32.dll!TrackPopupMenu`.
pub fn handle_track_popup_menu(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // No item selected.
    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from TrackPopupMenu")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `USER32.dll!GetMenuItemInfoA`.
pub fn handle_get_menu_item_info_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "GetMenuItemInfoA")
}

/// Handles `USER32.dll!GetMenuItemInfoW`.
pub fn handle_get_menu_item_info_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "GetMenuItemInfoW")
}

/// Handles `USER32.dll!SetMenuItemInfoA`.
pub fn handle_set_menu_item_info_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "SetMenuItemInfoA")
}

/// Handles `USER32.dll!SetMenuItemInfoW`.
pub fn handle_set_menu_item_info_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "SetMenuItemInfoW")
}

/// Handles `USER32.dll!CheckMenuRadioItem`.
pub fn handle_check_menu_radio_item(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    handle_menu_success(engine, "CheckMenuRadioItem")
}

/// Handles `USER32.dll!SetScrollInfo`.
///
/// Accepts the call and returns `nPos` (or `nMax` if position is absent) so
/// scroll-range setup during level-editor open does not abort the guest.
pub fn handle_set_scroll_info(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let window_handle = engine
        .read_rcx()
        .context("failed to read RCX for SetScrollInfo")?;

    let bar = engine
        .read_rdx()
        .context("failed to read RDX for SetScrollInfo")?;

    let scroll_info_ptr = engine
        .read_r8()
        .context("failed to read R8 for SetScrollInfo")?;

    let _redraw = engine
        .read_r9()
        .context("failed to read R9 for SetScrollInfo")?;

    // SCROLLINFO (Win64):
    // UINT cbSize;    0
    // UINT fMask;     4
    // int  nMin;      8
    // int  nMax;      12
    // UINT nPage;     16
    // int  nPos;      20
    // int  nTrackPos; 24
    let return_value = if scroll_info_ptr != 0 {
        let n_pos = read_guest_i32(
            engine,
            checked_field_address(scroll_info_ptr, 20, "SCROLLINFO.nPos")?,
        )
        .unwrap_or(0);
        // Win32 returns the current scroll-box position after the update.
        // Bitcast i32 → u32 (two's complement), then zero-extend to RAX.
        u64::from(u32::from_le_bytes(n_pos.to_le_bytes()))
    } else {
        0
    };

    tracing::debug!(
        window_handle,
        bar,
        scroll_info_ptr,
        return_value,
        "SetScrollInfo"
    );

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetScrollInfo")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `USER32.dll!ScrollWindowEx` (no-op success stub).
pub fn handle_scroll_window_ex(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _hwnd = engine
        .read_rcx()
        .context("failed to read RCX for ScrollWindowEx")?;

    // Returns TRUE on success.
    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from ScrollWindowEx")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `USER32.dll!ScrollDC` (no-op success stub; no real pixel scroll).
pub fn handle_scroll_dc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _hdc = engine
        .read_rcx()
        .context("failed to read RCX for ScrollDC")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from ScrollDC")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `USER32.dll!DispatchMessageA`.
pub fn handle_dispatch_message_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let message_address = engine
        .read_rcx()
        .context("failed to read RCX for DispatchMessageA")?;

    if message_address == 0 {
        let return_address = engine
            .return_from_win64_api(0)
            .context("failed to return from DispatchMessageA")?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    /*
     * MSG on Win64:
     *
     * +0x00 HWND   hwnd
     * +0x08 UINT   message
     * +0x10 WPARAM wParam
     * +0x18 LPARAM lParam
     * +0x20 DWORD  time
     * +0x24 POINT  pt
     */

    let window_handle = read_guest_u64(engine, message_address)
        .context("failed to read MSG.hwnd for DispatchMessageA")?;

    let message_field_address = checked_field_address(message_address, 8, "MSG.message")?;

    let message = read_guest_u32(engine, message_field_address)
        .context("failed to read MSG.message for DispatchMessageA")?;

    let word_parameter_address = checked_field_address(message_address, 16, "MSG.wParam")?;

    let word_parameter = read_guest_u64(engine, word_parameter_address)
        .context("failed to read MSG.wParam for DispatchMessageA")?;

    let long_parameter_address = checked_field_address(message_address, 24, "MSG.lParam")?;

    let long_parameter = read_guest_u64(engine, long_parameter_address)
        .context("failed to read MSG.lParam for DispatchMessageA")?;

    let target_window = state
        .windows
        .iter()
        .find(|window| window.handle == window_handle);

    /*
     * Thread messages have hwnd == NULL and therefore no target WndProc.
     * Runtime-owned system controls currently also have window_proc == 0.
     * Both cases retain the old neutral DispatchMessageA behavior.
     */
    let Some(target_window) = target_window else {
        let return_address = engine
            .return_from_win64_api(0)
            .context("failed to return from DispatchMessageA")?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    };

    if target_window.window_proc == 0 {
        let return_address = engine
            .return_from_win64_api(0)
            .context("failed to return from DispatchMessageA")?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    /*
     * Do not return from DispatchMessageA yet.
     *
     * RIP and RSP remain at the fake DispatchMessageA entry, while the
     * runtime prepares to execute the guest WndProc. A later callback bridge
     * will invoke the callback and finally complete DispatchMessageA with the
     * callback's LRESULT.
     */
    Err(WinApiControlSignal::GuestCallbackRequested {
        request: GuestCallbackRequest {
            callback_address: target_window.window_proc,
            window_handle,
            message,
            word_parameter,
            long_parameter,
            unicode: target_window.unicode,
        },
    }
    .into())
}

fn register_window_class(state: &mut WinApiState, mut record: WindowClassRecord) -> Result<u64> {
    if record.class_name.is_empty() || record.window_proc == 0 {
        return Ok(0);
    }

    if let Some(existing) = state.window_classes.iter().find(|existing| {
        existing.class_name.eq_ignore_ascii_case(&record.class_name)
            && existing.unicode == record.unicode
    }) {
        return Ok(u64::from(existing.atom));
    }

    let atom = state.next_window_class_atom;

    if atom == 0 {
        return Ok(0);
    }

    state.next_window_class_atom = state
        .next_window_class_atom
        .checked_add(1)
        .context("window class atom overflow")?;

    record.atom = atom;
    state.window_classes.push(record);

    Ok(u64::from(atom))
}

#[derive(Debug)]
struct CreateWindowRequest {
    class_identifier: WindowClassIdentifier,
    title: String,
    style: u32,
    extended_style: u32,
    parent_handle: u64,
    menu_handle: u64,
    instance_handle: u64,
    x: i32,
    y: i32,
    width: i32,
    height: i32,
}

#[derive(Debug)]
enum WindowClassIdentifier {
    Atom(u16),
    Name(String),
}

fn read_window_class_identifier_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    value: u64,
) -> Result<WindowClassIdentifier> {
    if value == 0 {
        return Ok(WindowClassIdentifier::Name(String::new()));
    }

    if let Ok(atom) = u16::try_from(value) {
        return Ok(WindowClassIdentifier::Atom(atom));
    }

    let name = read_guest_ansi_lossy(engine, value, 256)
        .context("failed to read ANSI window class name")?;

    Ok(WindowClassIdentifier::Name(name))
}

fn read_window_class_identifier_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    value: u64,
) -> Result<WindowClassIdentifier> {
    if value == 0 {
        return Ok(WindowClassIdentifier::Name(String::new()));
    }

    if let Ok(atom) = u16::try_from(value) {
        return Ok(WindowClassIdentifier::Atom(atom));
    }

    let name = read_guest_utf16_lossy(engine, value, 256)
        .context("failed to read Unicode window class name")?;

    Ok(WindowClassIdentifier::Name(name))
}

fn window_class_identifier_matches(
    record: &WindowClassRecord,
    identifier: &WindowClassIdentifier,
) -> bool {
    match identifier {
        WindowClassIdentifier::Atom(atom) => record.atom == *atom,

        WindowClassIdentifier::Name(name) => record.class_name.eq_ignore_ascii_case(name),
    }
}

fn find_window_class<'a>(
    state: &'a WinApiState,
    identifier: &WindowClassIdentifier,
    unicode: bool,
) -> Option<&'a WindowClassRecord> {
    state
        .window_classes
        .iter()
        .find(|record| {
            record.unicode == unicode && window_class_identifier_matches(record, identifier)
        })
        .or_else(|| {
            state
                .window_classes
                .iter()
                .find(|record| window_class_identifier_matches(record, identifier))
        })
}

fn create_window_record(
    state: &mut WinApiState,
    request: CreateWindowRequest,
    unicode: bool,
) -> Result<(u64, u64, bool)> {
    let registered_class = find_window_class(state, &request.class_identifier, unicode).cloned();

    let handle = state.next_window_handle;

    if handle == 0 {
        return Ok((0, 0, unicode));
    }

    state.next_window_handle = state
        .next_window_handle
        .checked_add(1)
        .context("fake window handle overflow")?;

    let (class_atom, class_name, window_proc, class_unicode) =
        if let Some(window_class) = registered_class {
            (
                window_class.atom,
                window_class.class_name,
                window_class.window_proc,
                window_class.unicode,
            )
        } else {
            let class_name = match request.class_identifier {
                WindowClassIdentifier::Atom(atom) => {
                    format!("#{atom}")
                }

                WindowClassIdentifier::Name(name) => name,
            };

            /*
             * Classes supplied by USER32, COMCTL32 and other system
             * components are not registered by the guest application.
             * They still receive runtime-owned HWND records, but have no
             * guest WndProc callback.
             */
            (0, class_name, 0, unicode)
        };

    state.windows.push(WindowRecord {
        handle,
        class_atom,
        class_name,
        window_proc,
        unicode: class_unicode,
        title: request.title,
        style: request.style,
        extended_style: request.extended_style,
        parent_handle: request.parent_handle,
        menu_handle: request.menu_handle,
        instance_handle: request.instance_handle,
        x: request.x,
        y: request.y,
        width: request.width,
        height: request.height,
        visible: false,
        enabled: true,
    });

    Ok((handle, window_proc, class_unicode))
}

fn create_mdi_child_from_struct(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    create_struct_ptr: u64,
    unicode: bool,
) -> Result<u64> {
    if create_struct_ptr == 0 {
        return Ok(0);
    }

    // MDICREATESTRUCTA/W on Win64:
    // +0x00 szClass
    // +0x08 szTitle
    // +0x10 hOwner
    // +0x18 x
    // +0x1c y
    // +0x20 cx
    // +0x24 cy
    // +0x28 style
    // +0x30 lParam
    let class_ptr = read_guest_u64(engine, create_struct_ptr)
        .context("failed to read MDICREATESTRUCT.szClass")?;
    let title_ptr = read_guest_u64(
        engine,
        checked_field_address(create_struct_ptr, 8, "MDICREATESTRUCT.szTitle")?,
    )?;
    let owner = read_guest_u64(
        engine,
        checked_field_address(create_struct_ptr, 16, "MDICREATESTRUCT.hOwner")?,
    )?;
    let x = read_guest_i32(
        engine,
        checked_field_address(create_struct_ptr, 24, "MDICREATESTRUCT.x")?,
    )?;
    let y = read_guest_i32(
        engine,
        checked_field_address(create_struct_ptr, 28, "MDICREATESTRUCT.y")?,
    )?;
    let cx = read_guest_i32(
        engine,
        checked_field_address(create_struct_ptr, 32, "MDICREATESTRUCT.cx")?,
    )?;
    let cy = read_guest_i32(
        engine,
        checked_field_address(create_struct_ptr, 36, "MDICREATESTRUCT.cy")?,
    )?;
    let style = read_guest_u32(
        engine,
        checked_field_address(create_struct_ptr, 40, "MDICREATESTRUCT.style")?,
    )?;

    let class_identifier = if unicode {
        read_window_class_identifier_w(engine, class_ptr)?
    } else {
        read_window_class_identifier_a(engine, class_ptr)?
    };

    let title = if title_ptr == 0 {
        String::new()
    } else if unicode {
        read_guest_utf16_lossy(engine, title_ptr, 512)?
    } else {
        read_guest_ansi_lossy(engine, title_ptr, 512)?
    };

    let (handle, _window_proc, _class_unicode) = create_window_record(
        state,
        CreateWindowRequest {
            class_identifier,
            title,
            style,
            extended_style: 0,
            parent_handle: 0,
            menu_handle: 0,
            instance_handle: owner,
            x,
            y,
            width: cx,
            height: cy,
        },
        unicode,
    )?;

    Ok(handle)
}

fn find_window(state: &WinApiState, handle: u64) -> Option<&WindowRecord> {
    state.windows.iter().find(|window| window.handle == handle)
}

fn is_known_window(state: &WinApiState, handle: u64) -> bool {
    if handle == 0 {
        return false;
    }
    handle == FAKE_WINDOW_HANDLE
        || handle == FAKE_DESKTOP_WINDOW_HANDLE
        || find_window(state, handle).is_some()
        || state.active_window_handle == handle
        || state.foreground_window_handle == handle
}

fn window_client_size(state: &WinApiState, handle: u64) -> (i32, i32) {
    if let Some(window) = find_window(state, handle) {
        let width = if window.width > 0 {
            window.width
        } else {
            state.window_width
        };
        let height = if window.height > 0 {
            window.height
        } else {
            state.window_height
        };
        return (width.max(1), height.max(1));
    }
    (state.window_width.max(1), state.window_height.max(1))
}
