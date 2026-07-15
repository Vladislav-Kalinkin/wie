//! Shared guest WndProc enter/leave helpers (session + dual-trace).

use anyhow::{Context, Result};
use wie_cpu::CpuEngine;
use wie_winapi::GuestCallbackRequest;

/// Set up Win64 frame + args and transfer control to a guest WndProc.
///
/// Returns the outer API `RSP` (to restore on trampoline return).
///
/// Stack below the original host-API frame:
/// ```text
/// [dispatch_rsp]      return address of outer API caller
/// [dispatch_rsp-8]    alignment padding
/// [dispatch_rsp-0x28] 32-byte shadow space
/// [dispatch_rsp-0x30] trampoline return address  ← new RSP / WndProc entry
/// ```
pub(crate) fn install_guest_callback_frame(
    engine: &mut dyn CpuEngine,
    request: &GuestCallbackRequest,
    trampoline: u64,
) -> Result<u64> {
    let dispatch_rsp = engine
        .read_rsp()
        .context("failed to read RSP before guest callback")?;

    // 0x30 keeps WndProc entry RSP ≡ 8 (mod 16) when the outer API entry
    // was itself 8-aligned, matching the Win64 ABI.
    let frame_rsp = dispatch_rsp
        .checked_sub(0x30)
        .context("guest callback stack frame underflow")?;

    engine
        .mem_write(frame_rsp, &trampoline.to_le_bytes())
        .context("failed to write guest callback trampoline return address")?;

    let shadow_address = frame_rsp
        .checked_add(8)
        .context("guest callback shadow space address overflow")?;

    engine
        .mem_write(shadow_address, &[0_u8; 0x20])
        .context("failed to clear guest callback shadow space")?;

    engine
        .write_rsp(frame_rsp)
        .context("failed to set RSP for guest callback")?;
    engine
        .write_rcx(request.window_handle)
        .context("failed to set RCX (hwnd) for guest callback")?;
    engine
        .write_rdx(u64::from(request.message))
        .context("failed to set RDX (message) for guest callback")?;
    engine
        .write_r8(request.word_parameter)
        .context("failed to set R8 (wParam) for guest callback")?;
    engine
        .write_r9(request.long_parameter)
        .context("failed to set R9 (lParam) for guest callback")?;
    engine
        .write_rip(request.callback_address)
        .context("failed to set RIP for guest callback")?;

    Ok(dispatch_rsp)
}

/// CreateWindowEx returns the HWND unless WM_CREATE returned -1.
#[must_use]
pub(crate) fn create_window_return_value(lresult: u64, create_window_hwnd: Option<u64>) -> u64 {
    if let Some(hwnd) = create_window_hwnd {
        // Truncate to 32-bit signed LRESULT for WM_CREATE convention.
        let low = u32::try_from(lresult & 0xffff_ffff).unwrap_or(0);
        let create_status = i32::from_ne_bytes(low.to_ne_bytes());
        if create_status == -1 {
            0
        } else {
            hwnd
        }
    } else {
        lresult
    }
}

/// Restore outer API frame and return from the host API after WndProc finishes.
///
/// Returns `(return_value, return_address)`.
pub(crate) fn finish_guest_callback(
    engine: &mut dyn CpuEngine,
    dispatch_rsp: u64,
    create_window_hwnd: Option<u64>,
) -> Result<(u64, u64)> {
    let lresult = engine
        .read_rax()
        .context("failed to read LRESULT from guest callback")?;
    let return_value = create_window_return_value(lresult, create_window_hwnd);

    engine
        .write_rsp(dispatch_rsp)
        .context("failed to restore RSP for outer API completion")?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from outer API after guest callback")?;

    Ok((return_value, return_address))
}

/// Whether the outer API is CreateWindowEx* (return HWND after callback).
#[must_use]
pub(crate) fn create_window_hwnd_for_outer(outer_name: &str, window_handle: u64) -> Option<u64> {
    if outer_name.eq_ignore_ascii_case("CreateWindowExA")
        || outer_name.eq_ignore_ascii_case("CreateWindowExW")
    {
        Some(window_handle)
    } else {
        None
    }
}
