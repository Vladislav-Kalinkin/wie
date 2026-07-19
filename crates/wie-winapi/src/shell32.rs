//! Minimal `shell32.dll` stubs (folder paths / browse UI) for CLI tools.

use crate::guest_string::write_utf16_c_string;
use crate::{WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

/// `S_OK` / success for SH* path APIs that return HRESULT.
const S_OK: u64 = 0;
/// `E_FAIL` for optional shell UI we do not implement.
const E_FAIL: u64 = 0x8000_4005;

fn ret(engine: &mut dyn wie_cpu::CpuEngine, value: u64) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(value)
        .context("shell32 return")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

/// Soft dispatch for `shell32.dll`.
pub fn dispatch_shell32(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
    name: &str,
) -> Result<Option<WinApiHandlerResult>> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "shgetfolderpathw" => Ok(Some(handle_sh_get_folder_path_w(engine)?)),
        "shgetpathfromidlistw" => Ok(Some(handle_sh_get_path_from_id_list_w(engine)?)),
        "shbrowseforfolderw" => Ok(Some(handle_sh_browse_for_folder_w(engine)?)),
        _ => Ok(None),
    }
}

/// `HRESULT SHGetFolderPathW(hwnd, csidl, hToken, dwFlags, pszPath)`
///
/// Fills a fixed bottle-friendly path under `C:\Users\WIE\…` style so tools
/// that only need a writable home directory keep going.
fn handle_sh_get_folder_path_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _hwnd = engine.read_rcx()?;
    let csidl = engine.read_rdx()? & 0xffff_ffff;
    let _token = engine.read_r8()?;
    let _flags = engine.read_r9()?;
    let mut path_ptr_bytes = [0_u8; 8];
    let rsp = engine.read_rsp()?;
    engine.mem_read(rsp.wrapping_add(0x28), &mut path_ptr_bytes)?;
    let path_ptr = u64::from_le_bytes(path_ptr_bytes);

    // Common CSIDL values → synthetic bottle paths (MAX_PATH buffer expected).
    // `csidl` already masked to low 32 bits (u64).
    let path = match csidl {
        0x00 => r"C:\Users\WIE\Desktop",          // CSIDL_DESKTOP
        0x05 => r"C:\Users\WIE\Documents",        // CSIDL_PERSONAL / My Documents
        0x1a => r"C:\Users\WIE\AppData\Roaming",  // CSIDL_APPDATA
        0x1c => r"C:\Users\WIE\AppData\Local",    // CSIDL_LOCAL_APPDATA
        0x23 => r"C:\ProgramData",                // CSIDL_COMMON_APPDATA
        0x24 => r"C:\Windows",                    // CSIDL_WINDOWS
        0x25 => r"C:\Windows\System32",           // CSIDL_SYSTEM
        0x26 => r"C:\Program Files",              // CSIDL_PROGRAM_FILES
        0x2a => r"C:\Program Files\Common Files", // CSIDL_PROGRAM_FILES_COMMON
        // CSIDL_PROFILE (0x28) and unknown → user home.
        _ => r"C:\Users\WIE",
    };

    if path_ptr != 0 {
        write_utf16_c_string(engine, path_ptr, 260, path)?;
    }
    ret(engine, S_OK)
}

/// `BOOL SHGetPathFromIDListW(pidl, pszPath)` — no real PIDLs; fail cleanly.
fn handle_sh_get_path_from_id_list_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _pidl = engine.read_rcx()?;
    let path_ptr = engine.read_rdx()?;
    if path_ptr != 0 {
        write_utf16_c_string(engine, path_ptr, 260, "")?;
    }
    ret(engine, 0) // FALSE
}

/// `PIDLIST_ABSOLUTE SHBrowseForFolderW(lpbi)` — no UI; return NULL.
fn handle_sh_browse_for_folder_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _lpbi = engine.read_rcx()?;
    let _ = E_FAIL;
    ret(engine, 0)
}
