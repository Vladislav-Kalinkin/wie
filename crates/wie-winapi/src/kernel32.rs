use crate::guest_memory::{
    checked_address, checked_field_address, read_u16 as read_guest_u16, read_u64 as read_guest_u64,
    write_u16 as write_guest_u16, write_u32 as write_guest_u32, write_u64 as write_guest_u64,
};
use crate::guest_string::{
    read_ansi_lossy as read_guest_ansi_lossy, read_utf16_lossy as read_guest_utf16_lossy,
    write_utf16_units as write_guest_utf16_units,
};
use crate::{FindHandle, FlsSlot, GlobalAtomRecord, OpenGuestFile, ResourceRecord, WinApiState};
use anyhow::{Context, Result};
use std::path::Path;

const FIXED_SYSTEM_FILETIME: u64 = 133_485_408_000_000_000;
const FAKE_CURRENT_PROCESS_ID: u64 = 0x1234;
const FIXED_TICK_COUNT: u64 = 12_345;
const FIXED_PERFORMANCE_COUNTER: u64 = 1_000_000;
const FLS_OUT_OF_INDEXES: u64 = 0xffff_ffff;
const STD_INPUT_HANDLE_ID: u32 = 0xffff_fff6;
const STD_OUTPUT_HANDLE_ID: u32 = 0xffff_fff5;
const STD_ERROR_HANDLE_ID: u32 = 0xffff_fff4;

/// Fake console handles returned by `GetStdHandle` (Microsoft Learn std ids).
const FAKE_STDIN_HANDLE: u64 = 0x0000_0000_6000_0001;
const FAKE_STDOUT_HANDLE: u64 = 0x0000_0000_6000_0002;
const FAKE_STDERR_HANDLE: u64 = 0x0000_0000_6000_0003;

#[inline]
fn is_console_output_handle(handle: u64) -> bool {
    matches!(handle, FAKE_STDOUT_HANDLE | FAKE_STDERR_HANDLE)
}

/// Host console write for `WriteFile` on stdout/stderr (Microsoft Learn: valid on console handles).
#[cfg(unix)]
fn write_host_console_handle(handle: u64, bytes: &[u8]) {
    let fd = if handle == FAKE_STDOUT_HANDLE {
        libc::STDOUT_FILENO
    } else {
        libc::STDERR_FILENO
    };
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let Some(chunk) = bytes.get(offset..) else {
            break;
        };
        // SAFETY: host stdout/stderr fd; `chunk` is a live contiguous buffer.
        #[expect(unsafe_code)]
        let n = unsafe { libc::write(fd, chunk.as_ptr().cast::<libc::c_void>(), chunk.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        offset = offset.saturating_add(usize::try_from(n).unwrap_or(0));
    }
}

#[cfg(not(unix))]
fn write_host_console_handle(handle: u64, bytes: &[u8]) {
    use std::io::Write;
    if handle == FAKE_STDOUT_HANDLE {
        drop(std::io::stdout().write_all(bytes));
    } else if handle == FAKE_STDERR_HANDLE {
        drop(std::io::stderr().write_all(bytes));
    }
}

/// Cap for a single host console line fill (safety against huge pastes).
const MAX_HOST_STDIN_LINE: usize = 64 * 1024;

/// Read one line from host stdin (through `\n` or EOF), capped at
/// [`MAX_HOST_STDIN_LINE`].
///
/// Models Microsoft Learn default console line input (`ENABLE_LINE_INPUT`):
/// `ReadFile` on a console handle does not complete until a carriage return
/// is entered. On Unix hosts we treat `\n` as the line terminator.
///
/// Returns:
/// - `Ok(Some(bytes))` — non-empty fill (may omit `\n` if cap hit first)
/// - `Ok(None)` — host EOF with no bytes
/// - `Err(_)` — host I/O error
fn read_host_console_stdin_line() -> std::io::Result<Option<Vec<u8>>> {
    use std::io::Read;

    let mut out = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    let mut stdin = std::io::stdin().lock();
    loop {
        if out.len() >= MAX_HOST_STDIN_LINE {
            break;
        }
        if stdin.read(&mut byte)? == 0 {
            break;
        }
        out.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
    }
    if out.is_empty() {
        Ok(None)
    } else {
        Ok(Some(out))
    }
}

/// When the inject/live buffer is empty and live mode is on, block on host
/// stdin for one line and store it in `state.stdin_bytes`.
///
/// Returns `Ok(true)` if bytes were stored, `Ok(false)` on host EOF,
/// `Err(())` on host I/O failure (caller sets `ERROR_READ_FAULT`).
fn refill_stdin_from_host(state: &mut WinApiState) -> Result<bool, ()> {
    match read_host_console_stdin_line() {
        Ok(None) => Ok(false),
        Ok(Some(line)) => {
            state.stdin_bytes = line;
            state.stdin_cursor = 0;
            Ok(true)
        }
        Err(_) => Err(()),
    }
}

const FILE_TYPE_UNKNOWN: u64 = 0x0000;
const FILE_TYPE_DISK: u64 = 0x0001;
const FILE_TYPE_CHAR: u64 = 0x0002;

const ANSI_CODE_PAGE: u64 = 1252;
const OEM_CODE_PAGE: u64 = 437;

const CT_CTYPE1: u64 = 1;

const C1_UPPER: u16 = 0x0001;
const C1_LOWER: u16 = 0x0002;
const C1_DIGIT: u16 = 0x0004;
const C1_SPACE: u16 = 0x0008;
const C1_PUNCT: u16 = 0x0010;
const C1_CNTRL: u16 = 0x0020;
const C1_BLANK: u16 = 0x0040;
const C1_XDIGIT: u16 = 0x0080;
const C1_ALPHA: u16 = 0x0100;

const HEAP_SIZE_FAILURE: u64 = u64::MAX;
/// `HEAP_ZERO_MEMORY` (heapapi.h / Microsoft Learn).
const HEAP_ZERO_MEMORY: u64 = 0x0000_0008;

const FAKE_KERNEL32_MODULE: u64 = 0x0000_0000_6100_0000;
const FAKE_USER32_MODULE: u64 = 0x0000_0000_6100_1000;
const FAKE_GDI32_MODULE: u64 = 0x0000_0000_6100_2000;
const FAKE_COMCTL32_MODULE: u64 = 0x0000_0000_6100_3000;
const FAKE_ADVAPI32_MODULE: u64 = 0x0000_0000_6100_4000;
const FAKE_SHELL32_MODULE: u64 = 0x0000_0000_6100_5000;
const FAKE_COMDLG32_MODULE: u64 = 0x0000_0000_6100_6000;
const FAKE_WINMM_MODULE: u64 = 0x0000_0000_6100_7000;
const FAKE_GENERIC_MODULE: u64 = 0x0000_0000_610f_0000;

const INVALID_FILE_ATTRIBUTES: u64 = 0xffff_ffff;
const FILE_ATTRIBUTE_DIRECTORY: u64 = 0x0000_0010;
const FILE_ATTRIBUTE_ARCHIVE: u64 = 0x0000_0020;

const INVALID_HANDLE_VALUE: u64 = u64::MAX;
const ERROR_NO_MORE_FILES: u32 = 18;

const FAKE_RESOURCE_DATA_BASE: u64 = 0x0000_0000_6400_0000;
const FAKE_RESOURCE_SIZE: u32 = 16;
const FAKE_RESOURCE_BYTES: [u8; 16] = [
    0x4c, 0x4d, 0x52, 0x53, // "WIERS"
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const LANG_EN_US: u64 = 0x0409;

const ERROR_INVALID_HANDLE: u32 = 6;
const ERROR_INVALID_PARAMETER: u32 = 87;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
/// Win32 `ERROR_READ_FAULT` — host console stdin I/O failure.
const ERROR_READ_FAULT: u32 = 30;

const TIME_ZONE_ID_UNKNOWN: u64 = 0;
const TIME_ZONE_ID_INVALID: u64 = 0xffff_ffff;

const FILE_BEGIN: u64 = 0;
const FILE_CURRENT: u64 = 1;
const FILE_END: u64 = 2;
const INVALID_SET_FILE_POINTER: u64 = 0xffff_ffff;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
const ERROR_ACCESS_DENIED: u32 = 5;
/// CreateFile CREATE_NEW when the file already exists (Microsoft Learn).
const ERROR_FILE_EXISTS: u32 = 80;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;
const ERROR_ALREADY_EXISTS: u32 = 183;
const ERROR_DIR_NOT_EMPTY: u32 = 145;

// CreateFile disposition values.
const CREATE_NEW: u64 = 1;
const CREATE_ALWAYS: u64 = 2;
const OPEN_EXISTING: u64 = 3;
const OPEN_ALWAYS: u64 = 4;
const TRUNCATE_EXISTING: u64 = 5;

/// Result returned by a WinAPI handler.
#[derive(Debug, Clone, Copy)]
pub struct WinApiHandlerResult {
    /// Address where emulation should resume.
    pub return_address: u64,

    /// Value written into `RAX`.
    pub return_value: u64,
}

fn low_u32(value: u64, context_name: &str) -> Result<u32> {
    u32::try_from(value & 0xffff_ffff)
        .with_context(|| format!("{context_name} low u32 conversion failed"))
}

/// Guest OS identity shared by `GetVersion` / `GetVersionEx*`.
const GUEST_OS_MAJOR: u32 = 10;
const GUEST_OS_MINOR: u32 = 0;
const GUEST_OS_BUILD: u32 = 19045;
const GUEST_OS_PLATFORM_NT: u32 = 2;

/// Packed `GetVersion` DWORD for the emulated OS (NT bit set in high word).
#[must_use]
fn packed_get_version() -> u64 {
    // Low byte major, next minor, high word build; bit 31 set ⇒ Windows NT family.
    let packed = GUEST_OS_MAJOR | (GUEST_OS_MINOR << 8) | (GUEST_OS_BUILD << 16) | 0x8000_0000;
    u64::from(packed)
}

/// Handles `KERNEL32.dll!GetVersion` (legacy packed DWORD).
pub fn handle_get_version(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let return_value = packed_get_version();
    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetVersion")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetVersionExA`.
pub fn handle_get_version_ex_a(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let version_info_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetVersionExA")?;

    if version_info_ptr == 0 {
        let return_address = engine
            .return_from_win64_api(0)
            .context("failed to return FALSE from GetVersionExA")?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    let major_version = GUEST_OS_MAJOR;
    let minor_version = GUEST_OS_MINOR;
    let build_number = GUEST_OS_BUILD;
    let platform_id = GUEST_OS_PLATFORM_NT;

    // OSVERSIONINFOA:
    // DWORD dwOSVersionInfoSize; offset 0
    // DWORD dwMajorVersion;      offset 4
    // DWORD dwMinorVersion;      offset 8
    // DWORD dwBuildNumber;       offset 12
    // DWORD dwPlatformId;        offset 16
    let major_version_address = checked_field_address(version_info_ptr, 4, "dwMajorVersion")?;
    let minor_version_address = checked_field_address(version_info_ptr, 8, "dwMinorVersion")?;
    let build_number_address = checked_field_address(version_info_ptr, 12, "dwBuildNumber")?;
    let platform_id_address = checked_field_address(version_info_ptr, 16, "dwPlatformId")?;

    write_guest_u32(engine, major_version_address, major_version)?;
    write_guest_u32(engine, minor_version_address, minor_version)?;
    write_guest_u32(engine, build_number_address, build_number)?;
    write_guest_u32(engine, platform_id_address, platform_id)?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return TRUE from GetVersionExA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!GetModuleHandleA`.
///
/// `lpModuleName == NULL` returns the main module image base from the PE
/// (`WinApiEnvironment::image_base`), not a hardcoded Lunar Magic address.
/// Handles `KERNEL32.dll!GetModuleHandleA`.
///
/// Microsoft Learn: `lpModuleName == NULL` → handle of the calling process's
/// `.exe`. Named module must already be loaded; otherwise returns `NULL`.
pub fn handle_get_module_handle_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let module_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetModuleHandleA")?;

    let return_value = if module_name_ptr == 0 {
        state.last_error = 0;
        environment.image_base
    } else {
        let module_name = read_ansi_string_from_cpu(engine, module_name_ptr, 260)?;
        let handle = resolve_loaded_module_handle(&module_name, environment.image_base, state);
        if handle == 0 {
            state.last_error = ERROR_MOD_NOT_FOUND;
        } else {
            state.last_error = 0;
        }
        handle
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetModuleHandleA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetModuleHandleW`.
pub fn handle_get_module_handle_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let module_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetModuleHandleW")?;

    let return_value = if module_name_ptr == 0 {
        state.last_error = 0;
        environment.image_base
    } else {
        let module_name = read_guest_utf16_lossy(engine, module_name_ptr, 260)?;
        let handle = resolve_loaded_module_handle(&module_name, environment.image_base, state);
        if handle == 0 {
            state.last_error = ERROR_MOD_NOT_FOUND;
        } else {
            state.last_error = 0;
        }
        handle
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetModuleHandleW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!lstrlenW`.
pub fn handle_lstrlen_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let s = engine
        .read_rcx()
        .context("failed to read RCX for lstrlenW")?;
    let return_value = if s == 0 {
        0_u64
    } else {
        let mut len = 0_u64;
        loop {
            let mut buf = [0_u8; 2];
            engine.mem_read(s.wrapping_add(len.saturating_mul(2)), &mut buf)?;
            if u16::from_le_bytes(buf) == 0 {
                break;
            }
            len = len.saturating_add(1);
            if len > 1_000_000 {
                break;
            }
        }
        len
    };
    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from lstrlenW")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!lstrcpyW` — copy wide string; returns dest.
pub fn handle_lstrcpy_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let dest = engine
        .read_rcx()
        .context("failed to read RCX for lstrcpyW")?;
    let src = engine
        .read_rdx()
        .context("failed to read RDX for lstrcpyW")?;
    if dest != 0 && src != 0 {
        let mut offset = 0_u64;
        loop {
            let mut buf = [0_u8; 2];
            engine.mem_read(src.wrapping_add(offset), &mut buf)?;
            engine.mem_write(dest.wrapping_add(offset), &buf)?;
            if u16::from_le_bytes(buf) == 0 {
                break;
            }
            offset = offset.saturating_add(2);
            if offset > 2_000_000 {
                break;
            }
        }
    }
    let return_address = engine
        .return_from_win64_api(dest)
        .context("failed to return from lstrcpyW")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: dest,
    })
}

/// Handles `KERNEL32.dll!lstrcatW` — append wide string; returns dest.
pub fn handle_lstrcat_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let dest = engine
        .read_rcx()
        .context("failed to read RCX for lstrcatW")?;
    let src = engine
        .read_rdx()
        .context("failed to read RDX for lstrcatW")?;
    if dest != 0 && src != 0 {
        // Find end of dest.
        let mut dest_end = 0_u64;
        loop {
            let mut buf = [0_u8; 2];
            engine.mem_read(dest.wrapping_add(dest_end), &mut buf)?;
            if u16::from_le_bytes(buf) == 0 {
                break;
            }
            dest_end = dest_end.saturating_add(2);
            if dest_end > 2_000_000 {
                break;
            }
        }
        let mut offset = 0_u64;
        loop {
            let mut buf = [0_u8; 2];
            engine.mem_read(src.wrapping_add(offset), &mut buf)?;
            engine.mem_write(dest.wrapping_add(dest_end).wrapping_add(offset), &buf)?;
            if u16::from_le_bytes(buf) == 0 {
                break;
            }
            offset = offset.saturating_add(2);
            if offset > 2_000_000 {
                break;
            }
        }
    }
    let return_address = engine
        .return_from_win64_api(dest)
        .context("failed to return from lstrcatW")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: dest,
    })
}

/// Handles `KERNEL32.dll!GetCommandLineA`.
pub fn handle_get_command_line_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    command_line_ptr: u64,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(command_line_ptr)
        .context("failed to return from GetCommandLineA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: command_line_ptr,
    })
}

/// Handles `KERNEL32.dll!GetCommandLineW`.
pub fn handle_get_command_line_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    command_line_ptr: u64,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(command_line_ptr)
        .context("failed to return from GetCommandLineW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: command_line_ptr,
    })
}

/// Handles `KERNEL32.dll!GetTickCount`.
pub fn handle_get_tick_count(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(FIXED_TICK_COUNT)
        .context("failed to return from GetTickCount")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FIXED_TICK_COUNT,
    })
}

/// Handles `KERNEL32.dll!QueryPerformanceCounter`.
pub fn handle_query_performance_counter(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let counter_ptr = engine
        .read_rcx()
        .context("failed to read RCX for QueryPerformanceCounter")?;

    if counter_ptr != 0 {
        write_guest_u64(engine, counter_ptr, FIXED_PERFORMANCE_COUNTER)?;
    }

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from QueryPerformanceCounter")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

fn low_u32_to_i32(value: u64, context_name: &str) -> Result<i32> {
    let low = u32::try_from(value & 0xffff_ffff)
        .with_context(|| format!("{context_name} low u32 conversion failed"))?;

    Ok(i32::from_ne_bytes(low.to_ne_bytes()))
}

fn read_utf16_units(
    engine: &mut dyn wie_cpu::CpuEngine,
    wide_ptr: u64,
    wide_len_raw: u64,
) -> Result<Vec<u16>> {
    if wide_ptr == 0 {
        return Ok(Vec::new());
    }

    let wide_len_i32 = low_u32_to_i32(wide_len_raw, "WideCharToMultiByte cchWideChar")?;

    if wide_len_i32 == -1 {
        read_null_terminated_utf16_units(engine, wide_ptr)
    } else {
        let wide_len =
            usize::try_from(wide_len_i32).context("negative UTF-16 length is not supported")?;

        read_fixed_utf16_units(engine, wide_ptr, wide_len)
    }
}

fn read_null_terminated_utf16_units(
    engine: &mut dyn wie_cpu::CpuEngine,
    wide_ptr: u64,
) -> Result<Vec<u16>> {
    const MAX_UNITS: usize = 32_768;

    let mut units = Vec::new();

    for index in 0..MAX_UNITS {
        let offset = u64::try_from(index)
            .context("UTF-16 index does not fit u64")?
            .checked_mul(2)
            .context("UTF-16 offset overflow")?;

        let address = checked_address(wide_ptr, offset, "UTF-16 NUL scan")?;
        let unit = read_guest_u16(engine, address)?;

        units.push(unit);

        if unit == 0 {
            return Ok(units);
        }
    }

    anyhow::bail!("unterminated UTF-16 string")
}

fn read_fixed_utf16_units(
    engine: &mut dyn wie_cpu::CpuEngine,
    wide_ptr: u64,
    wide_len: usize,
) -> Result<Vec<u16>> {
    let mut units = Vec::with_capacity(wide_len);

    for index in 0..wide_len {
        let offset = u64::try_from(index)
            .context("UTF-16 index does not fit u64")?
            .checked_mul(2)
            .context("UTF-16 offset overflow")?;

        let address = checked_address(wide_ptr, offset, "fixed UTF-16 read")?;
        units.push(read_guest_u16(engine, address)?);
    }

    Ok(units)
}

fn classify_ctype1(unit: u16) -> u16 {
    let Some(ch) = char::from_u32(u32::from(unit)) else {
        return 0;
    };

    if ch == '\0' {
        return C1_CNTRL;
    }

    let mut flags = 0_u16;

    if ch.is_uppercase() {
        flags |= C1_UPPER | C1_ALPHA;
    }

    if ch.is_lowercase() {
        flags |= C1_LOWER | C1_ALPHA;
    }

    if ch.is_alphabetic() && (flags & C1_ALPHA) == 0 {
        flags |= C1_ALPHA;
    }

    if ch.is_ascii_digit() {
        flags |= C1_DIGIT;
    }

    if ch.is_ascii_hexdigit() {
        flags |= C1_XDIGIT;
    }

    if ch.is_whitespace() {
        flags |= C1_SPACE;
    }

    if ch == ' ' || ch == '\t' {
        flags |= C1_BLANK;
    }

    if ch.is_control() {
        flags |= C1_CNTRL;
    }

    if ch.is_ascii_punctuation() {
        flags |= C1_PUNCT;
    }

    flags
}

fn read_multibyte_bytes(
    engine: &mut dyn wie_cpu::CpuEngine,
    input_ptr: u64,
    input_len_raw: u64,
) -> Result<Vec<u8>> {
    if input_ptr == 0 {
        return Ok(Vec::new());
    }

    let input_len_i32 = low_u32_to_i32(input_len_raw, "MultiByteToWideChar cbMultiByte")?;

    if input_len_i32 == -1 {
        read_null_terminated_bytes(engine, input_ptr)
    } else {
        let input_len =
            usize::try_from(input_len_i32).context("negative multibyte length is not supported")?;

        read_fixed_bytes(engine, input_ptr, input_len)
    }
}

fn read_null_terminated_bytes(
    engine: &mut dyn wie_cpu::CpuEngine,
    input_ptr: u64,
) -> Result<Vec<u8>> {
    const MAX_BYTES: usize = 32_768;

    let mut bytes = Vec::new();

    for index in 0..MAX_BYTES {
        let offset = u64::try_from(index).context("byte index does not fit u64")?;
        let address = checked_address(input_ptr, offset, "multibyte NUL scan")?;

        let mut byte = [0_u8; 1];
        engine
            .mem_read(address, &mut byte)
            .context("failed to read multibyte byte")?;

        bytes.push(byte[0]);

        if byte[0] == 0 {
            return Ok(bytes);
        }
    }

    anyhow::bail!("unterminated multibyte string")
}

fn read_fixed_bytes(
    engine: &mut dyn wie_cpu::CpuEngine,
    input_ptr: u64,
    input_len: usize,
) -> Result<Vec<u8>> {
    let mut bytes = vec![0_u8; input_len];

    engine
        .mem_read(input_ptr, &mut bytes)
        .context("failed to read fixed multibyte bytes")?;

    Ok(bytes)
}

/// Copy a NUL-terminated ANSI path into a guest buffer.
///
/// Returns `(chars_written_or_nSize, truncated)` per Microsoft Learn
/// `GetModuleFileNameA` semantics.
fn copy_path_a_to_guest_buffer(
    engine: &mut dyn wie_cpu::CpuEngine,
    source_ptr: u64,
    dest_ptr: u64,
    dest_len: u64,
) -> Result<(u64, bool)> {
    if dest_ptr == 0 || dest_len == 0 {
        return Ok((0, false));
    }

    let dest_len_usize =
        usize::try_from(dest_len).context("guest buffer length does not fit usize")?;

    // Read full source path (bounded) including room to detect truncation.
    let mut source_bytes = Vec::new();
    let max_scan = dest_len_usize.saturating_add(1).max(1);
    for index in 0..max_scan {
        let index_u64 = u64::try_from(index).context("guest string index does not fit u64")?;
        let source_address = checked_address(source_ptr, index_u64, "guest source string")?;
        let mut byte = [0_u8; 1];
        engine
            .mem_read(source_address, &mut byte)
            .context("failed to read guest source string byte")?;
        if byte[0] == 0 {
            break;
        }
        source_bytes.push(byte[0]);
    }

    let path_len = source_bytes.len();
    // Need room for path + NUL. If dest_len is too small, truncate and NUL-terminate.
    let truncated = path_len >= dest_len_usize;
    if truncated {
        let keep = dest_len_usize.saturating_sub(1);
        let mut out = source_bytes.get(..keep).unwrap_or(&[]).to_vec();
        out.push(0);
        engine
            .mem_write(dest_ptr, &out)
            .context("failed to write truncated guest path")?;
        Ok((dest_len, true))
    } else {
        let mut out = source_bytes;
        out.push(0);
        engine
            .mem_write(dest_ptr, &out)
            .context("failed to write guest path")?;
        let written = u64::try_from(path_len).context("path length does not fit u64")?;
        Ok((written, false))
    }
}

/// Copy a NUL-terminated UTF-16 path into a guest buffer (WCHAR units).
fn copy_path_w_to_guest_buffer(
    engine: &mut dyn wie_cpu::CpuEngine,
    source_ptr: u64,
    dest_ptr: u64,
    dest_len: u64,
) -> Result<(u64, bool)> {
    if dest_ptr == 0 || dest_len == 0 {
        return Ok((0, false));
    }

    let dest_len_usize =
        usize::try_from(dest_len).context("wide guest buffer length does not fit usize")?;

    let mut units = Vec::new();
    let max_scan = dest_len_usize.saturating_add(1).max(1);
    for index in 0..max_scan {
        let index_u64 = u64::try_from(index).context("wide guest string index does not fit u64")?;
        let source_offset = index_u64
            .checked_mul(2)
            .context("wide guest string source offset overflow")?;
        let source_address =
            checked_address(source_ptr, source_offset, "wide guest source string")?;
        let unit = read_guest_u16(engine, source_address)?;
        if unit == 0 {
            break;
        }
        units.push(unit);
    }

    let path_len = units.len();
    let truncated = path_len >= dest_len_usize;
    if truncated {
        let keep = dest_len_usize.saturating_sub(1);
        let mut out_units = units.get(..keep).unwrap_or(&[]).to_vec();
        out_units.push(0);
        let byte_cap = out_units.len().saturating_mul(2);
        let mut bytes = Vec::with_capacity(byte_cap);
        for unit in out_units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        engine
            .mem_write(dest_ptr, &bytes)
            .context("failed to write truncated wide guest path")?;
        Ok((dest_len, true))
    } else {
        let mut out_units = units;
        out_units.push(0);
        let byte_cap = out_units.len().saturating_mul(2);
        let mut bytes = Vec::with_capacity(byte_cap);
        for unit in out_units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        engine
            .mem_write(dest_ptr, &bytes)
            .context("failed to write wide guest path")?;
        let written = u64::try_from(path_len).context("wide path length does not fit u64")?;
        Ok((written, false))
    }
}

fn normalize_module_name(name: &str) -> String {
    name.trim()
        .trim_matches('"')
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn is_main_module_name(state: &WinApiState, name: &str) -> bool {
    let norm = normalize_module_name(name);
    if norm.is_empty() {
        return true;
    }
    let main = normalize_module_name(&state.main_module_file_name);
    norm == main || paths_match_guest(name, &state.main_module_path)
}

/// Whether `path` refers to the loaded main PE (any basename/path form).
fn is_main_module_path(state: &WinApiState, path: &str) -> bool {
    paths_match_guest(path, &state.main_module_path)
        || guest_basename(path).eq_ignore_ascii_case(&state.main_module_file_name)
}

/// Resolve a module that is considered already loaded (`GetModuleHandle*`).
///
/// Microsoft Learn: returns `NULL` when the named module is not in the process.
fn resolve_loaded_module_handle(name: &str, main_image_base: u64, state: &WinApiState) -> u64 {
    if is_main_module_name(state, name) {
        return main_image_base;
    }
    match normalize_module_name(name).as_str() {
        "kernel32.dll" => FAKE_KERNEL32_MODULE,
        "user32.dll" => FAKE_USER32_MODULE,
        "gdi32.dll" => FAKE_GDI32_MODULE,
        "comctl32.dll" => FAKE_COMCTL32_MODULE,
        "advapi32.dll" => FAKE_ADVAPI32_MODULE,
        "shell32.dll" => FAKE_SHELL32_MODULE,
        "comdlg32.dll" => FAKE_COMDLG32_MODULE,
        "winmm.dll" => FAKE_WINMM_MODULE,
        // Not pre-loaded: GetModuleHandle must return NULL (LoadLibrary is separate).
        _ => 0,
    }
}

/// Resolve or synthesize a module handle for `LoadLibrary*` (prototype always “loads”).
fn load_module_handle(name: &str, main_image_base: u64, state: &WinApiState) -> u64 {
    let loaded = resolve_loaded_module_handle(name, main_image_base, state);
    if loaded != 0 {
        loaded
    } else if name.trim().is_empty() {
        0
    } else {
        FAKE_GENERIC_MODULE
    }
}

/// Write an unlocked `RTL_CRITICAL_SECTION` (Win64 layout) at `critical_section_ptr`.
fn write_critical_section_unlocked(
    engine: &mut dyn wie_cpu::CpuEngine,
    critical_section_ptr: u64,
    spin_count: u64,
) -> Result<()> {
    // RTL_CRITICAL_SECTION on Win64:
    // +0x00 DebugInfo      pointer
    // +0x08 LockCount      LONG, initialized to -1 (unlocked)
    // +0x0c RecursionCount LONG
    // +0x10 OwningThread   HANDLE
    // +0x18 LockSemaphore  HANDLE
    // +0x20 SpinCount      ULONG_PTR
    write_guest_u64(
        engine,
        checked_field_address(critical_section_ptr, 0, "DebugInfo")?,
        0,
    )?;
    write_guest_u32(
        engine,
        checked_field_address(critical_section_ptr, 8, "LockCount")?,
        u32::MAX,
    )?;
    write_guest_u32(
        engine,
        checked_field_address(critical_section_ptr, 12, "RecursionCount")?,
        0,
    )?;
    write_guest_u64(
        engine,
        checked_field_address(critical_section_ptr, 16, "OwningThread")?,
        0,
    )?;
    write_guest_u64(
        engine,
        checked_field_address(critical_section_ptr, 24, "LockSemaphore")?,
        0,
    )?;
    write_guest_u64(
        engine,
        checked_field_address(critical_section_ptr, 32, "SpinCount")?,
        spin_count,
    )?;
    Ok(())
}

fn read_ansi_string_from_cpu(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    max_len: usize,
) -> Result<String> {
    // Byte-at-a-time: bulk reads of MAX_PATH-sized buffers fail when the string
    // sits near the end of a mapped PE page (common for freestanding micros).
    read_guest_ansi_lossy(engine, address, max_len)
}

fn read_wide_string_from_cpu(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    max_units: usize,
) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }

    let mut units = Vec::new();

    for index in 0..max_units {
        let index_u64 = u64::try_from(index).context("wide string index does not fit u64")?;
        let offset = index_u64
            .checked_mul(2)
            .context("wide string offset overflow")?;
        let unit_address = checked_address(address, offset, "wide string read")?;
        let unit = read_guest_u16(engine, unit_address)?;

        if unit == 0 {
            break;
        }

        units.push(unit);
    }

    String::from_utf16(&units).context("wide string is not valid UTF-16")
}

fn file_attributes_for_path(state: &WinApiState, path: &str) -> u64 {
    let normalized = path.trim();
    if normalized.is_empty() {
        return INVALID_FILE_ATTRIBUTES;
    }

    let mounts_ref: Vec<(String, std::path::PathBuf)> = state
        .host_file_mounts
        .iter()
        .map(|m| (m.guest_path.clone(), m.host_path.clone()))
        .collect();
    let virtuals_ref: Vec<(String, usize)> = state
        .virtual_files
        .iter()
        .map(|v| (v.guest_path.clone(), v.bytes.len()))
        .collect();
    let ctx = crate::vfs::ResolveCtx {
        volumes: &state.volumes,
        main_module_path: &state.main_module_path,
        main_module_file_name: &state.main_module_file_name,
        host_file_mounts: &mounts_ref,
        virtual_files: &virtuals_ref,
        synthetic_dirs: crate::vfs::DEFAULT_SYNTHETIC_DIRS,
    };

    let st = crate::vfs::stat_path(&ctx, normalized);
    match st.kind {
        crate::vfs::PathKind::NotFound => INVALID_FILE_ATTRIBUTES,
        crate::vfs::PathKind::Directory => u64::from(st.attributes),
        crate::vfs::PathKind::File => {
            if ctx.path_is_main_module(normalized) {
                FILE_ATTRIBUTE_ARCHIVE
            } else {
                u64::from(st.attributes).max(FILE_ATTRIBUTE_ARCHIVE)
            }
        }
    }
}

/// Collect dir entries for a Find pattern (dir + mask).
fn collect_find_entries(state: &WinApiState, full_pattern: &str) -> Vec<crate::vfs::DirEntry> {
    let mounts_ref: Vec<(String, std::path::PathBuf)> = state
        .host_file_mounts
        .iter()
        .map(|m| (m.guest_path.clone(), m.host_path.clone()))
        .collect();
    let virtuals_ref: Vec<(String, usize)> = state
        .virtual_files
        .iter()
        .map(|v| (v.guest_path.clone(), v.bytes.len()))
        .collect();
    let ctx = crate::vfs::ResolveCtx {
        volumes: &state.volumes,
        main_module_path: &state.main_module_path,
        main_module_file_name: &state.main_module_file_name,
        host_file_mounts: &mounts_ref,
        virtual_files: &virtuals_ref,
        synthetic_dirs: crate::vfs::DEFAULT_SYNTHETIC_DIRS,
    };
    let (dir, mask) = crate::vfs::split_find_pattern(full_pattern);
    crate::vfs::list_dir_filtered(&ctx, &dir, &mask)
}

/// Write shared `WIN32_FIND_DATA{A,W}` header fields (not the name).
///
/// Layout (minwinbase.h) — **not** `BY_HANDLE_FILE_INFORMATION`:
/// ```text
/// 0  dwFileAttributes
/// 4  ftCreationTime / 12 ftLastAccessTime / 20 ftLastWriteTime
/// 28 nFileSizeHigh / 32 nFileSizeLow
/// 36 dwReserved0 / 40 dwReserved1
/// 44 cFileName[MAX_PATH]
/// ```
fn write_find_data_common(
    engine: &mut dyn wie_cpu::CpuEngine,
    find_data_ptr: u64,
    attributes: u32,
    file_size: u64,
) -> Result<()> {
    if find_data_ptr == 0 {
        return Ok(());
    }

    let attributes_address =
        checked_field_address(find_data_ptr, 0, "WIN32_FIND_DATA.dwFileAttributes")?;
    let creation_time_address =
        checked_field_address(find_data_ptr, 4, "WIN32_FIND_DATA.ftCreationTime")?;
    let last_access_time_address =
        checked_field_address(find_data_ptr, 12, "WIN32_FIND_DATA.ftLastAccessTime")?;
    let last_write_time_address =
        checked_field_address(find_data_ptr, 20, "WIN32_FIND_DATA.ftLastWriteTime")?;
    let file_size_high_address =
        checked_field_address(find_data_ptr, 28, "WIN32_FIND_DATA.nFileSizeHigh")?;
    let file_size_low_address =
        checked_field_address(find_data_ptr, 32, "WIN32_FIND_DATA.nFileSizeLow")?;
    let reserved0_address =
        checked_field_address(find_data_ptr, 36, "WIN32_FIND_DATA.dwReserved0")?;
    let reserved1_address =
        checked_field_address(find_data_ptr, 40, "WIN32_FIND_DATA.dwReserved1")?;

    write_guest_u32(engine, attributes_address, attributes)?;
    write_guest_u64(engine, creation_time_address, FIXED_SYSTEM_FILETIME)?;
    write_guest_u64(engine, last_access_time_address, FIXED_SYSTEM_FILETIME)?;
    write_guest_u64(engine, last_write_time_address, FIXED_SYSTEM_FILETIME)?;
    write_guest_u32(
        engine,
        file_size_high_address,
        u32::try_from(file_size >> 32).unwrap_or(0),
    )?;
    write_guest_u32(
        engine,
        file_size_low_address,
        u32::try_from(file_size & 0xffff_ffff).unwrap_or(0),
    )?;
    write_guest_u32(engine, reserved0_address, 0)?;
    write_guest_u32(engine, reserved1_address, 0)?;

    Ok(())
}

fn write_find_data_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    find_data_ptr: u64,
    file_name: &str,
    attributes: u32,
    file_size: u64,
) -> Result<()> {
    write_find_data_common(engine, find_data_ptr, attributes, file_size)?;

    if find_data_ptr == 0 {
        return Ok(());
    }

    // cFileName is at offset 44 (after dwReserved1), not 48.
    let file_name_address = checked_field_address(find_data_ptr, 44, "WIN32_FIND_DATAW.cFileName")?;
    // cAlternateFileName[14] starts at 44 + MAX_PATH*2 = 564.
    let alt_name_address =
        checked_field_address(find_data_ptr, 564, "WIN32_FIND_DATAW.cAlternateFileName")?;

    let mut bytes = Vec::new();
    for unit in file_name.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    engine
        .mem_write(file_name_address, &bytes)
        .context("failed to write WIN32_FIND_DATAW.cFileName")?;
    write_guest_u16(engine, alt_name_address, 0)?;

    Ok(())
}

fn write_find_data_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    find_data_ptr: u64,
    file_name: &str,
    attributes: u32,
    file_size: u64,
) -> Result<()> {
    write_find_data_common(engine, find_data_ptr, attributes, file_size)?;

    if find_data_ptr == 0 {
        return Ok(());
    }

    // Same header as W; cFileName is CHAR[MAX_PATH] at offset 44.
    let file_name_address = checked_field_address(find_data_ptr, 44, "WIN32_FIND_DATAA.cFileName")?;
    let alt_name_address =
        checked_field_address(find_data_ptr, 304, "WIN32_FIND_DATAA.cAlternateFileName")?;

    let mut bytes = crate::vfs::encode_acp(file_name);
    bytes.push(0);

    engine
        .mem_write(file_name_address, &bytes)
        .context("failed to write WIN32_FIND_DATAA.cFileName")?;
    engine
        .mem_write(alt_name_address, &[0_u8])
        .context("failed to write WIN32_FIND_DATAA.cAlternateFileName")?;

    Ok(())
}

fn create_fake_resource_record(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<ResourceRecord> {
    let handle = state.next_resource_handle;
    state.next_resource_handle = state
        .next_resource_handle
        .checked_add(1)
        .context("resource handle overflow")?;

    let index = u64::try_from(state.resources.len()).context("resource index does not fit u64")?;
    let data_offset = index
        .checked_mul(0x100)
        .context("resource data offset overflow")?;

    let data_ptr = FAKE_RESOURCE_DATA_BASE
        .checked_add(data_offset)
        .context("resource data pointer overflow")?;

    engine
        .mem_write(data_ptr, &FAKE_RESOURCE_BYTES)
        .context("failed to write fake resource bytes")?;

    // For this compatibility harness, make the loaded resource handle pointer-like.
    // Some old Win32-style code uses the result of LoadResource directly as data.
    let loaded_handle = data_ptr;

    let record = ResourceRecord {
        handle,
        loaded_handle,
        data_ptr,
        size: FAKE_RESOURCE_SIZE,
    };

    state.resources.push(record.clone());

    Ok(record)
}

fn find_resource_by_handle(state: &WinApiState, handle: u64) -> Option<&ResourceRecord> {
    state
        .resources
        .iter()
        .find(|resource| resource.handle == handle || resource.loaded_handle == handle)
}

/// Handles `KERNEL32.dll!GetStartupInfoA`.
pub fn handle_get_startup_info_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let startup_info_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetStartupInfoA")?;

    if startup_info_ptr != 0 {
        let cb_address = checked_field_address(startup_info_ptr, 0, "cb")?;
        let flags_address = checked_field_address(startup_info_ptr, 60, "dwFlags")?;
        let show_window_address = checked_field_address(startup_info_ptr, 64, "wShowWindow")?;

        // STARTUPINFOA on Win64 is 104 bytes.
        write_guest_u32(engine, cb_address, 104)?;
        write_guest_u32(engine, flags_address, 0)?;
        write_guest_u16(engine, show_window_address, 1)?;
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from GetStartupInfoA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!GetProcessHeap`.
pub fn handle_get_process_heap(
    engine: &mut dyn wie_cpu::CpuEngine,
    process_heap_handle: u64,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(process_heap_handle)
        .context("failed to return from GetProcessHeap")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: process_heap_handle,
    })
}

/// Handles `KERNEL32.dll!GetSystemTimeAsFileTime`.
pub fn handle_get_system_time_as_file_time(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let filetime_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetSystemTimeAsFileTime")?;

    if filetime_ptr != 0 {
        let low_address = checked_field_address(filetime_ptr, 0, "dwLowDateTime")?;
        let high_address = checked_field_address(filetime_ptr, 4, "dwHighDateTime")?;

        let low = u32::try_from(FIXED_SYSTEM_FILETIME & 0xffff_ffff)
            .context("FILETIME low part does not fit u32")?;
        let high = u32::try_from(FIXED_SYSTEM_FILETIME >> 32)
            .context("FILETIME high part does not fit u32")?;

        write_guest_u32(engine, low_address, low)?;
        write_guest_u32(engine, high_address, high)?;
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from GetSystemTimeAsFileTime")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!GetCurrentProcessId`.
pub fn handle_get_current_process_id(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(FAKE_CURRENT_PROCESS_ID)
        .context("failed to return from GetCurrentProcessId")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_CURRENT_PROCESS_ID,
    })
}

/// Handles `KERNEL32.dll!GetCurrentThreadId`.
///
/// Returns the active guest TID from [`crate::ThreadState`] (primary `0x5678`
/// until MT.2 spawns workers).
pub fn handle_get_current_thread_id(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let tid = u64::from(state.threads.current_tid());
    let return_address = engine
        .return_from_win64_api(tid)
        .context("failed to return from GetCurrentThreadId")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: tid,
    })
}

/// Handles `KERNEL32.dll!HeapAlloc`.
///
/// Microsoft Learn (`heapapi.h`):
/// - success → pointer to allocated block (at least `dwBytes`)
/// - failure → `NULL` (does not call `SetLastError`)
/// - `HEAP_ZERO_MEMORY` zeros the block
/// - `dwBytes == 0` allocates a zero-length item and still returns a valid pointer
///   (same practical behaviour as the Windows process heap / CRT `malloc(0)`)
pub fn handle_heap_alloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let heap_handle = engine.read_rcx()?;
    let flags = engine.read_rdx()?;
    let size = engine.read_r8()?;

    let return_value = if heap_handle == 0 {
        0
    } else {
        // Zero-byte requests still need a live block (round-up in GuestHeap).
        let alloc_size = if size == 0 { 1 } else { size };
        let addr = state.heap.alloc_coherent(engine, alloc_size);
        if addr != 0 && (flags & HEAP_ZERO_MEMORY) != 0 {
            let zero_len = state.heap.size_of(addr).unwrap_or(alloc_size);
            if let Ok(len) = usize::try_from(zero_len) {
                let zeros = vec![0_u8; len];
                engine.mem_write(addr, &zeros)?;
            }
        }
        addr
    };

    let return_address = engine.return_from_win64_api(return_value)?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!HeapFree`.
///
/// Microsoft Learn: `lpMem` may be `NULL` (no-op, success). Double-free /
/// unknown pointer fails with a non-zero last-error in this emulator
/// (`ERROR_INVALID_HANDLE`) so freestanding tests can detect the failure.
pub fn handle_heap_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _heap_handle = engine.read_rcx()?;
    let _flags = engine.read_rdx()?;
    let memory = engine.read_r8()?;

    let ok = memory == 0 || state.heap.free_coherent(engine, memory);
    let return_value = if ok {
        1
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        0
    };

    let return_address = engine.return_from_win64_api(return_value)?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!HeapReAlloc`.
///
/// Microsoft Learn: preserves contents; failure leaves the original block valid
/// and returns `NULL`. `dwBytes == 0` is treated as free + `NULL` (common Windows
/// process-heap behaviour used by the micro-suite).
pub fn handle_heap_realloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let heap_handle = engine.read_rcx()?;
    let flags = engine.read_rdx()?;
    let memory = engine.read_r8()?;
    let new_size = engine.read_r9()?;

    let return_value = if heap_handle == 0 || memory == 0 {
        0
    } else if new_size == 0 {
        let _ = state.heap.free_coherent(engine, memory);
        0
    } else if let Some(same) = state.heap.try_realloc_in_place(memory, new_size) {
        // In-place only succeeds when the block already fits; no new bytes to zero.
        same
    } else {
        let old_size = state
            .heap
            .size_of(memory)
            .or_else(|| {
                let mut hb = [0_u8; 8];
                engine
                    .mem_read(memory.wrapping_sub(8), &mut hb)
                    .ok()
                    .map(|()| u64::from_le_bytes(hb))
            })
            .unwrap_or(0);
        let new_addr = state.heap.alloc_coherent(engine, new_size);
        if new_addr == 0 {
            // Failure must leave the original block live (Microsoft Learn).
            0
        } else {
            let copy_len = usize::try_from(old_size.min(new_size)).unwrap_or(0);
            if copy_len > 0 {
                let mut bytes = vec![0_u8; copy_len];
                engine.mem_read(memory, &mut bytes)?;
                engine.mem_write(new_addr, &bytes)?;
            }
            if (flags & HEAP_ZERO_MEMORY) != 0 && new_size > old_size {
                let zero_start = old_size;
                let zero_len = usize::try_from(new_size.saturating_sub(old_size)).unwrap_or(0);
                if zero_len > 0 {
                    let zeros = vec![0_u8; zero_len];
                    engine.mem_write(new_addr.wrapping_add(zero_start), &zeros)?;
                }
            }
            let _ = state.heap.free_coherent(engine, memory);
            new_addr
        }
    };

    let return_address = engine.return_from_win64_api(return_value)?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!HeapCreate`.
pub fn handle_heap_create(
    engine: &mut dyn wie_cpu::CpuEngine,
    process_heap_handle: u64,
) -> Result<WinApiHandlerResult> {
    let _options = engine
        .read_rcx()
        .context("failed to read RCX for HeapCreate")?;

    let _initial_size = engine
        .read_rdx()
        .context("failed to read RDX for HeapCreate")?;

    let _maximum_size = engine
        .read_r8()
        .context("failed to read R8 for HeapCreate")?;

    let return_address = engine
        .return_from_win64_api(process_heap_handle)
        .context("failed to return from HeapCreate")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: process_heap_handle,
    })
}

/// Handles `KERNEL32.dll!HeapSetInformation`.
pub fn handle_heap_set_information(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _heap_handle = engine
        .read_rcx()
        .context("failed to read RCX for HeapSetInformation")?;

    let _heap_information_class = engine
        .read_rdx()
        .context("failed to read RDX for HeapSetInformation")?;

    let _heap_information = engine
        .read_r8()
        .context("failed to read R8 for HeapSetInformation")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from HeapSetInformation")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!InitializeCriticalSection`.
pub fn handle_initialize_critical_section(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let critical_section_ptr = engine
        .read_rcx()
        .context("failed to read RCX for InitializeCriticalSection")?;

    if critical_section_ptr != 0 {
        write_critical_section_unlocked(engine, critical_section_ptr, 0)?;
    }

    // void return; RAX is unused but cleared for determinism.
    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from InitializeCriticalSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!EnterCriticalSection` (reentrant; blocks when needed).
///
/// Guest `RTL_CRITICAL_SECTION` layout (Win64) written by Initialize*:
/// `LockCount` (-1 unlocked), `RecursionCount`, `OwningThread` (guest TID).
///
/// Contended path: returns [`crate::WinApiControlSignal::HostPark`] so the
/// session drops the shared CPU lock and waits on the CS condvar (MT.3).
pub fn handle_enter_critical_section(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let cs = engine
        .read_rcx()
        .context("failed to read RCX for EnterCriticalSection")?;

    if cs != 0 {
        match try_enter_critical_section_guest(engine, cs, state.threads.current_tid())? {
            EnterCsResult::Acquired => {}
            EnterCsResult::NeedPark => {
                return Err(crate::WinApiControlSignal::HostPark {
                    reason: crate::HostParkReason::CriticalSection { cs },
                }
                .into());
            }
        }
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from EnterCriticalSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!LeaveCriticalSection`.
pub fn handle_leave_critical_section(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let cs = engine
        .read_rcx()
        .context("failed to read RCX for LeaveCriticalSection")?;

    if cs != 0 {
        let unlocked = leave_critical_section_guest(engine, cs, state.threads.current_tid())?;
        if unlocked {
            // Wake one host waiter (if any) parked on this CS.
            if let Some(q) = state.sync.cs_waiters.get(&cs) {
                q.notify_one();
            }
        }
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from LeaveCriticalSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!DeleteCriticalSection`.
///
/// Zeros the CS fields. Calling Delete while owned is undefined on Windows;
/// we still clear so a subsequent Initialize can reuse the memory.
pub fn handle_delete_critical_section(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let cs = engine
        .read_rcx()
        .context("failed to read RCX for DeleteCriticalSection")?;

    if cs != 0 {
        write_critical_section_unlocked(engine, cs, 0)?;
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from DeleteCriticalSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Result of a non-blocking CS enter attempt.
enum EnterCsResult {
    Acquired,
    NeedPark,
}

/// Try enter (or re-enter) a guest critical section for `owner_tid`.
fn try_enter_critical_section_guest(
    engine: &mut dyn wie_cpu::CpuEngine,
    cs: u64,
    owner_tid: u32,
) -> Result<EnterCsResult> {
    let lock_va = checked_field_address(cs, 8, "LockCount")?;
    let recursion_va = checked_field_address(cs, 12, "RecursionCount")?;
    let owner_va = checked_field_address(cs, 16, "OwningThread")?;

    let owning = read_guest_u64(engine, owner_va).unwrap_or(0);
    let me = u64::from(owner_tid);

    // Unlocked or recursive re-enter by owner.
    if owning == 0 || owning == me {
        let recursion = if owning == 0 {
            1_u32
        } else {
            let prev = read_guest_u32_cs(engine, recursion_va).unwrap_or(0);
            prev.saturating_add(1)
        };
        let lock_count = if owning == 0 {
            0_u32
        } else {
            let prev = read_guest_u32_cs(engine, lock_va).unwrap_or(0);
            prev.saturating_add(1)
        };
        write_guest_u32(engine, lock_va, lock_count)?;
        write_guest_u32(engine, recursion_va, recursion)?;
        write_guest_u64(engine, owner_va, me)?;
        return Ok(EnterCsResult::Acquired);
    }

    // Contended: park host (session waits on CS queue, then retries Enter).
    Ok(EnterCsResult::NeedPark)
}

/// Leave a guest critical section owned by `owner_tid`.
///
/// Returns `true` if the CS became fully unlocked (wake one waiter).
fn leave_critical_section_guest(
    engine: &mut dyn wie_cpu::CpuEngine,
    cs: u64,
    owner_tid: u32,
) -> Result<bool> {
    let lock_va = checked_field_address(cs, 8, "LockCount")?;
    let recursion_va = checked_field_address(cs, 12, "RecursionCount")?;
    let owner_va = checked_field_address(cs, 16, "OwningThread")?;

    let owning = read_guest_u64(engine, owner_va).unwrap_or(0);
    let me = u64::from(owner_tid);
    if owning != me {
        // Windows: leaving a CS you do not own is undefined; ignore.
        return Ok(false);
    }

    let recursion = read_guest_u32_cs(engine, recursion_va).unwrap_or(1);
    if recursion <= 1 {
        write_guest_u32(engine, lock_va, u32::MAX)?; // -1 unlocked
        write_guest_u32(engine, recursion_va, 0)?;
        write_guest_u64(engine, owner_va, 0)?;
        Ok(true)
    } else {
        let lock = read_guest_u32_cs(engine, lock_va).unwrap_or(1);
        write_guest_u32(engine, lock_va, lock.saturating_sub(1))?;
        write_guest_u32(engine, recursion_va, recursion.saturating_sub(1))?;
        Ok(false)
    }
}

fn read_guest_u32_cs(engine: &mut dyn wie_cpu::CpuEngine, va: u64) -> Option<u32> {
    let mut b = [0_u8; 4];
    engine.mem_read(va, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

/// Publish one FLS slot into the guest table used by in-guest `FlsGetValue`.
fn publish_fls_slot(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    index: u32,
    value: u64,
) {
    let table = state.guest_fls_table_va;
    if table == 0 || index >= 256 {
        return;
    }
    let va = table.saturating_add(u64::from(index).saturating_mul(8));
    drop(engine.mem_write(va, &value.to_le_bytes()));
}

/// Handles `KERNEL32.dll!FlsAlloc`.
pub fn handle_fls_alloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _callback = engine
        .read_rcx()
        .context("failed to read RCX for FlsAlloc")?;

    let index = state.next_fls_index;

    let return_value = if index == u32::MAX {
        FLS_OUT_OF_INDEXES
    } else {
        state.next_fls_index = index.checked_add(1).context("FLS index overflow")?;

        state.fls_slots.push(FlsSlot { index, value: 0 });
        publish_fls_slot(engine, state, index, 0);

        u64::from(index)
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FlsAlloc")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FlsFree`.
pub fn handle_fls_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let index_raw = engine
        .read_rcx()
        .context("failed to read RCX for FlsFree")?;

    let index = u32::try_from(index_raw).context("FlsFree index does not fit u32")?;

    state.fls_slots.retain(|slot| slot.index != index);
    publish_fls_slot(engine, state, index, 0);

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from FlsFree")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!FlsSetValue`.
pub fn handle_fls_set_value(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let index_raw = engine
        .read_rcx()
        .context("failed to read RCX for FlsSetValue")?;

    let value = engine
        .read_rdx()
        .context("failed to read RDX for FlsSetValue")?;

    let index = u32::try_from(index_raw).context("FlsSetValue index does not fit u32")?;

    if let Some(slot) = state.fls_slots.iter_mut().find(|slot| slot.index == index) {
        slot.value = value;
    } else {
        state.fls_slots.push(FlsSlot { index, value });
    }
    publish_fls_slot(engine, state, index, value);

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from FlsSetValue")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!FlsGetValue`.
pub fn handle_fls_get_value(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let index_raw = engine
        .read_rcx()
        .context("failed to read RCX for FlsGetValue")?;

    let index = u32::try_from(index_raw).context("FlsGetValue index does not fit u32")?;

    let return_value = state
        .fls_slots
        .iter()
        .find(|slot| slot.index == index)
        .map_or(0, |slot| slot.value);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FlsGetValue")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetStdHandle`.
pub fn handle_get_std_handle(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let std_handle_id_raw = engine
        .read_rcx()
        .context("failed to read RCX for GetStdHandle")?;

    let std_handle_id = low_u32(std_handle_id_raw, "GetStdHandle id")?;

    let return_value = match std_handle_id {
        STD_INPUT_HANDLE_ID => FAKE_STDIN_HANDLE,
        STD_OUTPUT_HANDLE_ID => FAKE_STDOUT_HANDLE,
        STD_ERROR_HANDLE_ID => FAKE_STDERR_HANDLE,
        // Microsoft Learn: invalid standard device → INVALID_HANDLE_VALUE.
        _ => INVALID_HANDLE_VALUE,
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetStdHandle")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFileType`.
pub fn handle_get_file_type(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for GetFileType")?;

    let return_value = match handle {
        FAKE_STDIN_HANDLE | FAKE_STDOUT_HANDLE | FAKE_STDERR_HANDLE => FILE_TYPE_CHAR,
        _ if is_open_file_handle(state, handle) => FILE_TYPE_DISK,
        _ => FILE_TYPE_UNKNOWN,
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFileType")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetHandleCount`.
pub fn handle_set_handle_count(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let handle_count = engine
        .read_rcx()
        .context("failed to read RCX for SetHandleCount")?;

    let return_address = engine
        .return_from_win64_api(handle_count)
        .context("failed to return from SetHandleCount")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle_count,
    })
}

/// Handles `KERNEL32.dll!GetEnvironmentStringsW`.
pub fn handle_get_environment_strings_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment_strings_w_ptr: u64,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(environment_strings_w_ptr)
        .context("failed to return from GetEnvironmentStringsW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: environment_strings_w_ptr,
    })
}

/// Handles `KERNEL32.dll!FreeEnvironmentStringsW`.
pub fn handle_free_environment_strings_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _environment_block = engine
        .read_rcx()
        .context("failed to read RCX for FreeEnvironmentStringsW")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from FreeEnvironmentStringsW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!WideCharToMultiByte`.
pub fn handle_wide_char_to_multi_byte(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let code_page = engine
        .read_rcx()
        .context("failed to read RCX for WideCharToMultiByte")?;

    let _flags = engine
        .read_rdx()
        .context("failed to read RDX for WideCharToMultiByte")?;

    let wide_ptr = engine
        .read_r8()
        .context("failed to read R8 for WideCharToMultiByte")?;

    let wide_len_raw = engine
        .read_r9()
        .context("failed to read R9 for WideCharToMultiByte")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for WideCharToMultiByte")?;

    let out_ptr_address = checked_address(rsp, 0x28, "WideCharToMultiByte lpMultiByteStr")?;
    let out_len_address = checked_address(rsp, 0x30, "WideCharToMultiByte cbMultiByte")?;

    let out_ptr = read_guest_u64(engine, out_ptr_address)?;
    let out_len = read_guest_u64(engine, out_len_address)?;

    let units = read_utf16_units(engine, wide_ptr, wide_len_raw)?;
    let cp = u32::try_from(code_page & 0xffff_ffff).unwrap_or(crate::vfs::CP_ACP);
    let bytes = crate::vfs::wide_to_multibyte(cp, &units)
        .ok_or_else(|| anyhow::anyhow!("WideCharToMultiByte invalid UTF-16"))?;

    let required_size =
        u64::try_from(bytes.len()).context("WideCharToMultiByte result length does not fit u64")?;

    let return_value = if out_ptr == 0 || out_len == 0 {
        required_size
    } else {
        let out_len_usize = usize::try_from(out_len)
            .context("WideCharToMultiByte output size does not fit usize")?;

        if out_len_usize < bytes.len() {
            0
        } else {
            engine
                .mem_write(out_ptr, &bytes)
                .context("failed to write WideCharToMultiByte output")?;

            required_size
        }
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from WideCharToMultiByte")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetLastError`.
pub fn handle_get_last_error(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = u64::from(state.last_error);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetLastError")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetLastError`.
pub fn handle_set_last_error(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let error_raw = engine
        .read_rcx()
        .context("failed to read RCX for SetLastError")?;

    let error =
        u32::try_from(error_raw & 0xffff_ffff).context("SetLastError value does not fit u32")?;

    state.last_error = error;

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from SetLastError")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!GetACP`.
pub fn handle_get_acp(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(ANSI_CODE_PAGE)
        .context("failed to return from GetACP")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: ANSI_CODE_PAGE,
    })
}

/// Handles `KERNEL32.dll!GetOEMCP`.
pub fn handle_get_oem_cp(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(OEM_CODE_PAGE)
        .context("failed to return from GetOEMCP")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: OEM_CODE_PAGE,
    })
}

/// Handles `KERNEL32.dll!GetCPInfo`.
pub fn handle_get_cp_info(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _code_page = engine
        .read_rcx()
        .context("failed to read RCX for GetCPInfo")?;

    let cp_info_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetCPInfo")?;

    if cp_info_ptr != 0 {
        let max_char_size_address = checked_field_address(cp_info_ptr, 0, "MaxCharSize")?;
        let default_char_address = checked_field_address(cp_info_ptr, 4, "DefaultChar")?;
        let lead_byte_address = checked_field_address(cp_info_ptr, 6, "LeadByte")?;

        write_guest_u32(engine, max_char_size_address, 1)?;
        engine
            .mem_write(default_char_address, &[b'?', 0])
            .context("failed to write CPINFO DefaultChar")?;
        engine
            .mem_write(lead_byte_address, &[0_u8; 12])
            .context("failed to write CPINFO LeadByte")?;
    }

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from GetCPInfo")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!IsValidCodePage`.
pub fn handle_is_valid_code_page(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let code_page = engine
        .read_rcx()
        .context("failed to read RCX for IsValidCodePage")?;

    let return_value = match code_page {
        0 | 437 | 1252 | 1200 | 65001 => 1,
        _ => 0,
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from IsValidCodePage")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetStringTypeW`.
pub fn handle_get_string_type_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let info_type = engine
        .read_rcx()
        .context("failed to read RCX for GetStringTypeW")?;

    let source_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetStringTypeW")?;

    let source_len_raw = engine
        .read_r8()
        .context("failed to read R8 for GetStringTypeW")?;

    let char_type_ptr = engine
        .read_r9()
        .context("failed to read R9 for GetStringTypeW")?;

    let return_value = if source_ptr == 0 || char_type_ptr == 0 {
        0
    } else {
        let units = read_utf16_units(engine, source_ptr, source_len_raw)?;

        for (index, unit) in units.iter().enumerate() {
            let index_u64 =
                u64::try_from(index).context("GetStringTypeW index does not fit u64")?;
            let offset = index_u64
                .checked_mul(2)
                .context("GetStringTypeW output offset overflow")?;
            let output_address = checked_address(char_type_ptr, offset, "GetStringTypeW output")?;

            let flags = if info_type == CT_CTYPE1 {
                classify_ctype1(*unit)
            } else {
                0
            };

            write_guest_u16(engine, output_address, flags)?;
        }

        1
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetStringTypeW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!MultiByteToWideChar`.
///
/// Lean host path (also fallback for guest SBCS helper). Single-byte code pages
/// use zero-extend (matches guest accelerator); others use UTF-8 lossy.
pub fn handle_multi_byte_to_wide_char(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let code_page = engine.read_rcx()?;
    let _flags = engine.read_rdx()?;
    let input_ptr = engine.read_r8()?;
    let input_len_raw = engine.read_r9()?;

    let rsp = engine.read_rsp()?;
    let output_ptr = read_guest_u64(
        engine,
        checked_address(rsp, 0x28, "MultiByteToWideChar lpWideCharStr")?,
    )?;
    let output_len = read_guest_u64(
        engine,
        checked_address(rsp, 0x30, "MultiByteToWideChar cchWideChar")?,
    )?;

    let input_bytes = read_multibyte_bytes(engine, input_ptr, input_len_raw)?;
    let cp = u32::try_from(code_page & 0xffff_ffff).unwrap_or(0);
    let units = crate::vfs::multibyte_to_wide(cp, &input_bytes);

    let required_units =
        u64::try_from(units.len()).context("MultiByteToWideChar unit length does not fit u64")?;

    let return_value = if output_ptr == 0 || output_len == 0 {
        required_units
    } else {
        let output_len_usize = usize::try_from(output_len)
            .context("MultiByteToWideChar output size does not fit usize")?;
        if output_len_usize < units.len() {
            0
        } else {
            // Bulk LE write without per-unit extend_from_slice.
            let mut output_bytes = vec![0_u8; units.len().saturating_mul(2)];
            for (i, unit) in units.iter().enumerate() {
                let o = i.saturating_mul(2);
                let end = o.saturating_add(2);
                if let Some(dst) = output_bytes.get_mut(o..end) {
                    dst.copy_from_slice(&unit.to_le_bytes());
                }
            }
            engine
                .mem_write(output_ptr, &output_bytes)
                .context("failed to write MultiByteToWideChar output")?;
            required_units
        }
    };

    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Zero-extend each byte to UTF-16 (SBCS / Latin-1 identity).
/// Handles `KERNEL32.dll!LCMapStringW`.
pub fn handle_lc_map_string_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _locale = engine
        .read_rcx()
        .context("failed to read RCX for LCMapStringW")?;

    let _map_flags = engine
        .read_rdx()
        .context("failed to read RDX for LCMapStringW")?;

    let source_ptr = engine
        .read_r8()
        .context("failed to read R8 for LCMapStringW")?;

    let source_len_raw = engine
        .read_r9()
        .context("failed to read R9 for LCMapStringW")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for LCMapStringW")?;

    let dest_ptr_address = checked_address(rsp, 0x28, "LCMapStringW lpDestStr")?;
    let dest_len_address = checked_address(rsp, 0x30, "LCMapStringW cchDest")?;

    let dest_ptr = read_guest_u64(engine, dest_ptr_address)?;
    let dest_len = read_guest_u64(engine, dest_len_address)?;

    let source_units = read_utf16_units(engine, source_ptr, source_len_raw)?;
    let required_units =
        u64::try_from(source_units.len()).context("LCMapStringW result length does not fit u64")?;

    let return_value = if dest_ptr == 0 || dest_len == 0 {
        required_units
    } else {
        let dest_len_usize =
            usize::try_from(dest_len).context("LCMapStringW output size does not fit usize")?;

        if dest_len_usize < source_units.len() {
            0
        } else {
            let output_byte_len = source_units
                .len()
                .checked_mul(2)
                .context("LCMapStringW output byte length overflow")?;

            let mut output_bytes = Vec::with_capacity(output_byte_len);

            for unit in &source_units {
                output_bytes.extend_from_slice(&unit.to_le_bytes());
            }

            engine
                .mem_write(dest_ptr, &output_bytes)
                .context("failed to write LCMapStringW output")?;

            required_units
        }
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LCMapStringW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetModuleFileNameA`.
///
/// Microsoft Learn: returns character count excluding NUL. If the buffer is too
/// small, the path is truncated (NUL-terminated), the return value is `nSize`,
/// and last-error is `ERROR_INSUFFICIENT_BUFFER`.
pub fn handle_get_module_file_name_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    module_file_name_a_ptr: u64,
) -> Result<WinApiHandlerResult> {
    let _module_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetModuleFileNameA")?;

    let buffer_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetModuleFileNameA")?;

    let buffer_len = engine
        .read_r8()
        .context("failed to read R8 for GetModuleFileNameA")?;

    let (return_value, truncated) =
        copy_path_a_to_guest_buffer(engine, module_file_name_a_ptr, buffer_ptr, buffer_len)?;

    state.last_error = if truncated {
        ERROR_INSUFFICIENT_BUFFER
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetModuleFileNameA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetModuleFileNameW`.
pub fn handle_get_module_file_name_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    module_file_name_w_ptr: u64,
) -> Result<WinApiHandlerResult> {
    let _module_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetModuleFileNameW")?;

    let buffer_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetModuleFileNameW")?;

    let buffer_len = engine
        .read_r8()
        .context("failed to read R8 for GetModuleFileNameW")?;

    let (return_value, truncated) =
        copy_path_w_to_guest_buffer(engine, module_file_name_w_ptr, buffer_ptr, buffer_len)?;

    state.last_error = if truncated {
        ERROR_INSUFFICIENT_BUFFER
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetModuleFileNameW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetUnhandledExceptionFilter`.
pub fn handle_set_unhandled_exception_filter(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _filter_ptr = engine
        .read_rcx()
        .context("failed to read RCX for SetUnhandledExceptionFilter")?;

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from SetUnhandledExceptionFilter")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!HeapSize`.
pub fn handle_heap_size(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let _heap_handle = engine.read_rcx()?;
    let _flags = engine.read_rdx()?;
    let memory = engine.read_r8()?;

    let return_value = state
        .heap
        .size_of(memory)
        .or_else(|| {
            if memory == 0 {
                return None;
            }
            let mut hb = [0_u8; 8];
            engine
                .mem_read(memory.wrapping_sub(8), &mut hb)
                .ok()
                .map(|()| u64::from_le_bytes(hb))
                .filter(|&s| s != 0)
        })
        .unwrap_or(HEAP_SIZE_FAILURE);

    let return_address = engine.return_from_win64_api(return_value)?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!LoadLibraryA`.
///
/// Microsoft Learn: empty / NULL name fails with `ERROR_MOD_NOT_FOUND`.
pub fn handle_load_library_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let library_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for LoadLibraryA")?;

    let return_value = if library_name_ptr == 0 {
        state.last_error = ERROR_MOD_NOT_FOUND;
        0
    } else {
        let library_name = read_ansi_string_from_cpu(engine, library_name_ptr, 260)?;
        let handle = load_module_handle(&library_name, environment.image_base, state);
        if handle == 0 {
            state.last_error = ERROR_MOD_NOT_FOUND;
        } else {
            state.last_error = 0;
        }
        handle
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LoadLibraryA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!LoadLibraryW`.
pub fn handle_load_library_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let library_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for LoadLibraryW")?;

    let return_value = if library_name_ptr == 0 {
        state.last_error = ERROR_MOD_NOT_FOUND;
        0
    } else {
        let library_name = read_wide_string_from_cpu(engine, library_name_ptr, 260)?;
        let handle = load_module_handle(&library_name, environment.image_base, state);
        if handle == 0 {
            state.last_error = ERROR_MOD_NOT_FOUND;
        } else {
            state.last_error = 0;
        }
        handle
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LoadLibraryW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FreeLibrary`.
pub fn handle_free_library(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let module_handle = engine
        .read_rcx()
        .context("failed to read RCX for FreeLibrary")?;

    // Return TRUE if handle is non-zero (valid-looking module handle).
    let return_value = u64::from(module_handle != 0);
    state.last_error = if module_handle == 0 {
        ERROR_INVALID_HANDLE
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FreeLibrary")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetProcAddress`.
///
/// Microsoft Learn: returns the export address, or `NULL` if not found
/// (`GetLastError` → `ERROR_PROC_NOT_FOUND`). Does **not** abort the process.
pub fn handle_get_proc_address(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let module_handle = engine
        .read_rcx()
        .context("failed to read RCX for GetProcAddress")?;

    let proc_name_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetProcAddress")?;

    // Microsoft Learn: if `lpProcName` is an ordinal, the high bits are zero
    // (MAKEINTRESOURCE). We treat small pointers as ordinals.
    let proc_name = if proc_name_ptr <= 0xffff {
        format!("ORDINAL {proc_name_ptr:#x}")
    } else {
        read_guest_ansi_lossy(engine, proc_name_ptr, 256)
            .context("failed to read GetProcAddress proc name")?
    };

    let name_key = proc_name.to_ascii_lowercase();

    let return_value = if module_handle == 0 {
        state.last_error = ERROR_MOD_NOT_FOUND;
        0
    } else if let Some(cached) = state.get_proc_address_cache.get_mut(&name_key) {
        cached.hit_count = cached.hit_count.saturating_add(1);
        state.last_error = 0;
        cached.address
    } else if let Some(address) = crate::dynamic_apis::resolve_get_proc_address(&proc_name) {
        state.get_proc_address_cache.insert(
            name_key,
            crate::GetProcAddressCacheEntry {
                name: proc_name.clone().into(),
                module_handle,
                address,
                hit_count: 1,
            },
        );
        state.last_error = 0;
        address
    } else {
        // Docs: return NULL, set last error — do not fail the API dispatch.
        state.last_error = ERROR_PROC_NOT_FOUND;
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetProcAddress")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFileAttributesA`.
pub fn handle_get_file_attributes_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetFileAttributesA")?;

    let path = read_ansi_string_from_cpu(engine, path_ptr, 1024)?;
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_path = resolve_full_windows_path(&cwd, &path);
    let return_value = file_attributes_for_path(state, &full_path);
    if return_value == INVALID_FILE_ATTRIBUTES {
        state.last_error = ERROR_FILE_NOT_FOUND;
    } else {
        state.last_error = 0;
    }

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFileAttributesA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFileAttributesW`.
pub fn handle_get_file_attributes_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetFileAttributesW")?;

    let path = read_wide_string_from_cpu(engine, path_ptr, 1024)?;
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_path = resolve_full_windows_path(&cwd, &path);
    let return_value = file_attributes_for_path(state, &full_path);
    if return_value == INVALID_FILE_ATTRIBUTES {
        state.last_error = ERROR_FILE_NOT_FOUND;
    } else {
        state.last_error = 0;
    }

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFileAttributesW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FindFirstFileW`.
pub fn handle_find_first_file_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let pattern_ptr = engine
        .read_rcx()
        .context("failed to read RCX for FindFirstFileW")?;

    let find_data_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FindFirstFileW")?;

    let pattern = read_wide_string_from_cpu(engine, pattern_ptr, 1024)?;
    let return_value = finish_find_first(engine, state, &pattern, find_data_ptr, true)?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FindFirstFileW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FindFirstFileA`.
pub fn handle_find_first_file_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let pattern_ptr = engine
        .read_rcx()
        .context("failed to read RCX for FindFirstFileA")?;

    let find_data_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FindFirstFileA")?;

    let pattern = read_ansi_string_from_cpu(engine, pattern_ptr, 1024)?;
    let return_value = finish_find_first(engine, state, &pattern, find_data_ptr, false)?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FindFirstFileA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_find_first(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    pattern: &str,
    find_data_ptr: u64,
    unicode: bool,
) -> Result<u64> {
    if pattern.trim().is_empty() {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(INVALID_HANDLE_VALUE);
    }

    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_pattern = resolve_full_windows_path(&cwd, pattern);
    let mut entries = collect_find_entries(state, &full_pattern);
    if entries.is_empty() {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return Ok(INVALID_HANDLE_VALUE);
    }

    let first = entries.remove(0);
    if unicode {
        write_find_data_w(
            engine,
            find_data_ptr,
            &first.name,
            first.attributes,
            first.size,
        )?;
    } else {
        write_find_data_a(
            engine,
            find_data_ptr,
            &first.name,
            first.attributes,
            first.size,
        )?;
    }

    let handle = state.next_find_handle;
    state.next_find_handle = state
        .next_find_handle
        .checked_add(1)
        .context("find handle overflow")?;

    state.find_handles.push(FindHandle {
        handle,
        pattern: full_pattern,
        remaining: entries,
    });
    state.last_error = 0;
    Ok(handle)
}

/// Handles `KERNEL32.dll!FindNextFileW`.
pub fn handle_find_next_file_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let find_handle = engine
        .read_rcx()
        .context("failed to read RCX for FindNextFileW")?;

    let find_data_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FindNextFileW")?;

    let return_value = finish_find_next(engine, state, find_handle, find_data_ptr, true)?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FindNextFileW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FindNextFileA`.
pub fn handle_find_next_file_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let find_handle = engine
        .read_rcx()
        .context("failed to read RCX for FindNextFileA")?;

    let find_data_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FindNextFileA")?;

    let return_value = finish_find_next(engine, state, find_handle, find_data_ptr, false)?;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FindNextFileA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_find_next(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    find_handle: u64,
    find_data_ptr: u64,
    unicode: bool,
) -> Result<u64> {
    let Some(slot) = state
        .find_handles
        .iter_mut()
        .find(|h| h.handle == find_handle)
    else {
        state.last_error = ERROR_INVALID_HANDLE;
        return Ok(0);
    };

    if slot.remaining.is_empty() {
        state.last_error = ERROR_NO_MORE_FILES;
        return Ok(0);
    }

    let next = slot.remaining.remove(0);
    if unicode {
        write_find_data_w(
            engine,
            find_data_ptr,
            &next.name,
            next.attributes,
            next.size,
        )?;
    } else {
        write_find_data_a(
            engine,
            find_data_ptr,
            &next.name,
            next.attributes,
            next.size,
        )?;
    }
    state.last_error = 0;
    Ok(1)
}

/// Handles `KERNEL32.dll!FindClose`.
pub fn handle_find_close(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let find_handle = engine
        .read_rcx()
        .context("failed to read RCX for FindClose")?;

    state
        .find_handles
        .retain(|handle| handle.handle != find_handle);

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from FindClose")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!LoadLibraryExA`.
pub fn handle_load_library_ex_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let library_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for LoadLibraryExA")?;

    let _file_handle = engine
        .read_rdx()
        .context("failed to read RDX for LoadLibraryExA")?;

    let _flags = engine
        .read_r8()
        .context("failed to read R8 for LoadLibraryExA")?;

    let library_name = read_ansi_string_from_cpu(engine, library_name_ptr, 260)?;
    let return_value = load_module_handle(&library_name, environment.image_base, state);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LoadLibraryExA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!LoadLibraryExW`.
pub fn handle_load_library_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let library_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for LoadLibraryExW")?;

    let _file_handle = engine
        .read_rdx()
        .context("failed to read RDX for LoadLibraryExW")?;

    let _flags = engine
        .read_r8()
        .context("failed to read R8 for LoadLibraryExW")?;

    let library_name = read_wide_string_from_cpu(engine, library_name_ptr, 260)?;
    let return_value = load_module_handle(&library_name, environment.image_base, state);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LoadLibraryExW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FindResourceA`.
pub fn handle_find_resource_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _module_handle = engine
        .read_rcx()
        .context("failed to read RCX for FindResourceA")?;

    let _name = engine
        .read_rdx()
        .context("failed to read RDX for FindResourceA")?;

    let _resource_type = engine
        .read_r8()
        .context("failed to read R8 for FindResourceA")?;

    let record = create_fake_resource_record(engine, state)?;

    let return_address = engine
        .return_from_win64_api(record.handle)
        .context("failed to return from FindResourceA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: record.handle,
    })
}

/// Handles `KERNEL32.dll!LoadResource`.
pub fn handle_load_resource(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let _module_handle = engine
        .read_rcx()
        .context("failed to read RCX for LoadResource")?;

    let resource_handle = engine
        .read_rdx()
        .context("failed to read RDX for LoadResource")?;

    let return_value = find_resource_by_handle(state, resource_handle)
        .map_or(0, |resource| resource.loaded_handle);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LoadResource")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!LockResource`.
pub fn handle_lock_resource(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let resource_handle = engine
        .read_rcx()
        .context("failed to read RCX for LockResource")?;

    let return_value =
        find_resource_by_handle(state, resource_handle).map_or(0, |resource| resource.data_ptr);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LockResource")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SizeofResource`.
pub fn handle_sizeof_resource(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let _module_handle = engine
        .read_rcx()
        .context("failed to read RCX for SizeofResource")?;

    let resource_handle = engine
        .read_rdx()
        .context("failed to read RDX for SizeofResource")?;

    let return_value = find_resource_by_handle(state, resource_handle)
        .map_or(0, |resource| u64::from(resource.size));

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SizeofResource")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetSystemDefaultLangID`.
pub fn handle_get_system_default_lang_id(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(LANG_EN_US)
        .context("failed to return from GetSystemDefaultLangID")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: LANG_EN_US,
    })
}

/// Handles `KERNEL32.dll!GetUserDefaultLangID`.
pub fn handle_get_user_default_lang_id(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(LANG_EN_US)
        .context("failed to return from GetUserDefaultLangID")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: LANG_EN_US,
    })
}

/// Handles `KERNEL32.dll!GlobalMemoryStatus`.
pub fn handle_global_memory_status(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let memory_status_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GlobalMemoryStatus")?;

    if memory_status_ptr != 0 {
        // MEMORYSTATUS on Win64:
        // DWORD  dwLength;          offset 0
        // DWORD  dwMemoryLoad;      offset 4
        // SIZE_T dwTotalPhys;       offset 8
        // SIZE_T dwAvailPhys;       offset 16
        // SIZE_T dwTotalPageFile;   offset 24
        // SIZE_T dwAvailPageFile;   offset 32
        // SIZE_T dwTotalVirtual;    offset 40
        // SIZE_T dwAvailVirtual;    offset 48

        let length_address = checked_field_address(memory_status_ptr, 0, "dwLength")?;
        let memory_load_address = checked_field_address(memory_status_ptr, 4, "dwMemoryLoad")?;
        let total_phys_address = checked_field_address(memory_status_ptr, 8, "dwTotalPhys")?;
        let avail_phys_address = checked_field_address(memory_status_ptr, 16, "dwAvailPhys")?;
        let total_page_file_address =
            checked_field_address(memory_status_ptr, 24, "dwTotalPageFile")?;
        let avail_page_file_address =
            checked_field_address(memory_status_ptr, 32, "dwAvailPageFile")?;
        let total_virtual_address = checked_field_address(memory_status_ptr, 40, "dwTotalVirtual")?;
        let avail_virtual_address = checked_field_address(memory_status_ptr, 48, "dwAvailVirtual")?;

        write_guest_u32(engine, length_address, 56)?;
        write_guest_u32(engine, memory_load_address, 25)?;

        write_guest_u64(engine, total_phys_address, 8_u64 * 1024 * 1024 * 1024)?;
        write_guest_u64(engine, avail_phys_address, 6_u64 * 1024 * 1024 * 1024)?;
        write_guest_u64(engine, total_page_file_address, 16_u64 * 1024 * 1024 * 1024)?;
        write_guest_u64(engine, avail_page_file_address, 12_u64 * 1024 * 1024 * 1024)?;
        write_guest_u64(engine, total_virtual_address, 128_u64 * 1024 * 1024 * 1024)?;
        write_guest_u64(engine, avail_virtual_address, 120_u64 * 1024 * 1024 * 1024)?;
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from GlobalMemoryStatus")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!GetLocalTime`.
pub fn handle_get_local_time(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let system_time_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetLocalTime")?;

    if system_time_ptr != 0 {
        // SYSTEMTIME:
        // WORD wYear;         offset 0
        // WORD wMonth;        offset 2
        // WORD wDayOfWeek;    offset 4
        // WORD wDay;          offset 6
        // WORD wHour;         offset 8
        // WORD wMinute;       offset 10
        // WORD wSecond;       offset 12
        // WORD wMilliseconds; offset 14

        let year_address = checked_field_address(system_time_ptr, 0, "wYear")?;
        let month_address = checked_field_address(system_time_ptr, 2, "wMonth")?;
        let day_of_week_address = checked_field_address(system_time_ptr, 4, "wDayOfWeek")?;
        let day_address = checked_field_address(system_time_ptr, 6, "wDay")?;
        let hour_address = checked_field_address(system_time_ptr, 8, "wHour")?;
        let minute_address = checked_field_address(system_time_ptr, 10, "wMinute")?;
        let second_address = checked_field_address(system_time_ptr, 12, "wSecond")?;
        let milliseconds_address = checked_field_address(system_time_ptr, 14, "wMilliseconds")?;

        // Deterministic fake local time.
        write_guest_u16(engine, year_address, 2026)?;
        write_guest_u16(engine, month_address, 7)?;
        write_guest_u16(engine, day_of_week_address, 4)?;
        write_guest_u16(engine, day_address, 9)?;
        write_guest_u16(engine, hour_address, 12)?;
        write_guest_u16(engine, minute_address, 0)?;
        write_guest_u16(engine, second_address, 0)?;
        write_guest_u16(engine, milliseconds_address, 0)?;
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from GetLocalTime")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!CreateFileW`.
pub fn handle_create_file_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let file_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for CreateFileW")?;

    let desired_access = engine
        .read_rdx()
        .context("failed to read RDX for CreateFileW")?;

    let _share_mode = engine
        .read_r8()
        .context("failed to read R8 for CreateFileW")?;

    let _security_attributes = engine
        .read_r9()
        .context("failed to read R9 for CreateFileW")?;

    let file_name = if file_name_ptr == 0 {
        String::new()
    } else {
        read_wide_string_from_cpu(engine, file_name_ptr, 32_768)
            .context("failed to read CreateFileW file name")?
    };

    // 5th arg (CreationDisposition) lives at [RSP+0x28] at Win64 API entry.
    let creation_disposition =
        read_create_file_stack_u32(engine, 0x28).map_or(OPEN_EXISTING, u64::from);

    let return_value = finish_create_file(
        engine,
        state,
        &file_name,
        desired_access,
        creation_disposition,
        "CreateFileW",
    );

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from CreateFileW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!CreateFileA`.
pub fn handle_create_file_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let file_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for CreateFileA")?;

    let desired_access = engine
        .read_rdx()
        .context("failed to read RDX for CreateFileA")?;

    let _share_mode = engine
        .read_r8()
        .context("failed to read R8 for CreateFileA")?;

    let _security_attributes = engine
        .read_r9()
        .context("failed to read R9 for CreateFileA")?;

    let file_name = if file_name_ptr == 0 {
        String::new()
    } else {
        read_ansi_string_from_cpu(engine, file_name_ptr, 32_768)
            .context("failed to read CreateFileA file name")?
    };

    let creation_disposition =
        read_create_file_stack_u32(engine, 0x28).map_or(OPEN_EXISTING, u64::from);

    let return_value = finish_create_file(
        engine,
        state,
        &file_name,
        desired_access,
        creation_disposition,
        "CreateFileA",
    );

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from CreateFileA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_create_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    file_name: &str,
    desired_access: u64,
    creation_disposition: u64,
    api_name: &str,
) -> u64 {
    let return_value =
        match open_or_create_guest_path(state, file_name, desired_access, creation_disposition) {
            Ok(OpenFileOutcome::Handle(handle)) => {
                state.last_error = 0;
                handle
            }
            Ok(OpenFileOutcome::HandleCreated(handle)) => {
                // OPEN_ALWAYS / CREATE_ALWAYS created a new file (docs: GetLastError may be 0).
                state.last_error = 0;
                handle
            }
            Ok(OpenFileOutcome::HandleExists(handle)) => {
                // Microsoft Learn: CREATE_ALWAYS / OPEN_ALWAYS set ERROR_ALREADY_EXISTS
                // when the named file already existed.
                if creation_disposition == CREATE_ALWAYS || creation_disposition == OPEN_ALWAYS {
                    state.last_error = ERROR_ALREADY_EXISTS;
                } else {
                    state.last_error = 0;
                }
                handle
            }
            Err(win_error) => {
                tracing::debug!(
                    path = %file_name,
                    desired_access,
                    creation_disposition,
                    win_error,
                    "{api_name} open failed"
                );
                state.last_error = win_error;
                INVALID_HANDLE_VALUE
            }
        };

    if return_value != INVALID_HANDLE_VALUE {
        tracing::debug!(
            path = %file_name,
            desired_access,
            creation_disposition,
            handle = return_value,
            "{api_name}"
        );
        let _ = crate::guest_io_host::register_open_file(engine, state, return_value).ok();
    }

    return_value
}

/// Handles `KERNEL32.dll!CloseHandle`.
///
/// Microsoft Learn: success → nonzero; failure → zero + last-error.
/// `NULL` / `INVALID_HANDLE_VALUE` fail with `ERROR_INVALID_HANDLE`.
/// Open guest files are flushed to the virtual store / bottle host path.
pub fn handle_close_handle(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for CloseHandle")?;

    let return_value = if handle == 0 || handle == INVALID_HANDLE_VALUE {
        state.last_error = ERROR_INVALID_HANDLE;
        0
    } else if is_open_file_handle(state, handle) {
        // Flush written bytes to virtual store and/or bottle host path.
        if let Some(open_file) = find_open_file(state, handle) {
            let path = open_file.path.clone();
            sync_open_bytes_to_virtual(state, &path, handle);
        }
        persist_open_file_to_host(state, handle);
        let _ = crate::guest_io_host::unregister_open_file(engine, state, handle).ok();
        state.open_files.remove(&handle);
        state.last_error = 0;
        1
    } else if state.sync.objects.remove(&handle).is_some() {
        // Thread / event kernel handles (object may still be live via Arc).
        state.last_error = 0;
        1
    } else {
        // Console / module / other fake kernel objects: accept and no-op so
        // CRT and UI stubs that close non-file handles keep working.
        state.last_error = 0;
        1
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from CloseHandle")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFileInformationByHandle`.
pub fn handle_get_file_information_by_handle(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for GetFileInformationByHandle")?;

    let info_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetFileInformationByHandle")?;

    let open_file = find_open_file(state, handle);
    let success = open_file.is_some() && info_ptr != 0;

    if let Some(open_file) = open_file.filter(|_| info_ptr != 0) {
        // BY_HANDLE_FILE_INFORMATION:
        // DWORD    dwFileAttributes;     offset 0
        // FILETIME ftCreationTime;       offset 4
        // FILETIME ftLastAccessTime;     offset 12
        // FILETIME ftLastWriteTime;      offset 20
        // DWORD    dwVolumeSerialNumber; offset 28
        // DWORD    nFileSizeHigh;        offset 32
        // DWORD    nFileSizeLow;         offset 36
        // DWORD    nNumberOfLinks;       offset 40
        // DWORD    nFileIndexHigh;       offset 44
        // DWORD    nFileIndexLow;        offset 48

        let attributes_address = checked_field_address(info_ptr, 0, "dwFileAttributes")?;
        let creation_time_address = checked_field_address(info_ptr, 4, "ftCreationTime")?;
        let last_access_time_address = checked_field_address(info_ptr, 12, "ftLastAccessTime")?;
        let last_write_time_address = checked_field_address(info_ptr, 20, "ftLastWriteTime")?;
        let volume_serial_address = checked_field_address(info_ptr, 28, "dwVolumeSerialNumber")?;
        let file_size_high_address = checked_field_address(info_ptr, 32, "nFileSizeHigh")?;
        let file_size_low_address = checked_field_address(info_ptr, 36, "nFileSizeLow")?;
        let number_of_links_address = checked_field_address(info_ptr, 40, "nNumberOfLinks")?;
        let file_index_high_address = checked_field_address(info_ptr, 44, "nFileIndexHigh")?;
        let file_index_low_address = checked_field_address(info_ptr, 48, "nFileIndexLow")?;

        let file_size = open_file.size();

        write_guest_u32(
            engine,
            attributes_address,
            u32::try_from(FILE_ATTRIBUTE_ARCHIVE).unwrap_or(0x20),
        )?;
        write_guest_u64(engine, creation_time_address, FIXED_SYSTEM_FILETIME)?;
        write_guest_u64(engine, last_access_time_address, FIXED_SYSTEM_FILETIME)?;
        write_guest_u64(engine, last_write_time_address, FIXED_SYSTEM_FILETIME)?;
        write_guest_u32(engine, volume_serial_address, 0x1234_abcd)?;
        let file_size_high =
            u32::try_from(file_size >> 32).context("open file size high does not fit u32")?;

        let file_size_low = u32::try_from(file_size & 0xffff_ffff)
            .context("open file size low does not fit u32")?;

        write_guest_u32(engine, file_size_high_address, file_size_high)?;
        write_guest_u32(engine, file_size_low_address, file_size_low)?;
        write_guest_u32(engine, number_of_links_address, 1)?;
        write_guest_u32(engine, file_index_high_address, 0)?;
        write_guest_u32(engine, file_index_low_address, 1)?;

        state.last_error = 0;
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFileInformationByHandle")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn guest_basename(path: &str) -> &str {
    crate::vfs::guest_basename(path)
}

/// Full path equality (case-insensitive). Used for FS identity.
fn paths_match_guest(requested: &str, candidate: &str) -> bool {
    crate::vfs::paths_equal_ci(requested, candidate)
}

fn find_open_file(state: &WinApiState, handle: u64) -> Option<&OpenGuestFile> {
    state.open_files.get(&handle)
}

fn find_open_file_mut(state: &mut WinApiState, handle: u64) -> Option<&mut OpenGuestFile> {
    state.open_files.get_mut(&handle)
}

fn is_open_file_handle(state: &WinApiState, handle: u64) -> bool {
    state.open_files.contains_key(&handle)
}

/// Opens a guest path using the same resolution rules as `CreateFile*`.
///
/// Returns the new handle on success.
pub fn open_guest_path(state: &mut WinApiState, guest_path: &str) -> Result<u64> {
    match open_or_create_guest_path(state, guest_path, 0, OPEN_EXISTING) {
        Ok(
            OpenFileOutcome::Handle(handle)
            | OpenFileOutcome::HandleExists(handle)
            | OpenFileOutcome::HandleCreated(handle),
        ) => Ok(handle),
        Err(code) => anyhow::bail!("open_guest_path failed: win32 error {code}"),
    }
}

/// Result of a successful `CreateFile` open (handle + existence semantics for last-error).
enum OpenFileOutcome {
    /// Opened or created; last-error should be 0.
    Handle(u64),
    /// Opened a file that already existed (OPEN_ALWAYS / CREATE_ALWAYS overwrite).
    HandleExists(u64),
    /// Created a new file (OPEN_ALWAYS / CREATE_NEW / CREATE_ALWAYS on new path).
    HandleCreated(u64),
}

/// Open/create using Microsoft Learn disposition rules (clean room).
///
/// Relative paths (`.\\file`, `subdir\\file`, `\\rooted`) are resolved against
/// the process current directory before open (same idea as `GetFullPathName`).
///
/// Returns `Err(Win32 error code)` on failure (not an anyhow chain).
fn open_or_create_guest_path(
    state: &mut WinApiState,
    guest_path: &str,
    _desired_access: u64,
    creation_disposition: u64,
) -> std::result::Result<OpenFileOutcome, u32> {
    if guest_path.is_empty() {
        return Err(ERROR_PATH_NOT_FOUND);
    }

    // Keep volumes.bottle_root in sync with legacy field.
    if state.volumes.bottle_root != state.bottle_root {
        state.volumes.bottle_root = state.bottle_root.clone();
    }

    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_path = resolve_full_windows_path(&cwd, guest_path);

    let bottle_host = crate::vfs::guest_path_to_host(&state.volumes, &full_path).map(|m| m.host);
    let existed = guest_path_exists(state, &full_path);

    match creation_disposition {
        CREATE_NEW => {
            if existed {
                return Err(ERROR_FILE_EXISTS);
            }
            let handle = create_new_guest_file(state, &full_path, bottle_host.as_ref())?;
            Ok(OpenFileOutcome::HandleCreated(handle))
        }
        CREATE_ALWAYS => {
            let handle = if existed {
                open_existing_guest_file(state, &full_path, bottle_host.as_ref(), true)?
            } else {
                create_new_guest_file(state, &full_path, bottle_host.as_ref())?
            };
            Ok(if existed {
                OpenFileOutcome::HandleExists(handle)
            } else {
                OpenFileOutcome::HandleCreated(handle)
            })
        }
        OPEN_EXISTING => {
            if !existed {
                return Err(ERROR_FILE_NOT_FOUND);
            }
            let handle = open_existing_guest_file(state, &full_path, bottle_host.as_ref(), false)?;
            Ok(OpenFileOutcome::Handle(handle))
        }
        OPEN_ALWAYS => {
            if existed {
                let handle =
                    open_existing_guest_file(state, &full_path, bottle_host.as_ref(), false)?;
                Ok(OpenFileOutcome::HandleExists(handle))
            } else {
                let handle = create_new_guest_file(state, &full_path, bottle_host.as_ref())?;
                Ok(OpenFileOutcome::HandleCreated(handle))
            }
        }
        TRUNCATE_EXISTING => {
            if !existed {
                return Err(ERROR_FILE_NOT_FOUND);
            }
            let handle = open_existing_guest_file(state, &full_path, bottle_host.as_ref(), true)?;
            Ok(OpenFileOutcome::Handle(handle))
        }
        _ => {
            // Unknown disposition — fail closed.
            Err(ERROR_INVALID_PARAMETER)
        }
    }
}

fn open_existing_guest_file(
    state: &mut WinApiState,
    guest_path: &str,
    bottle_host: Option<&std::path::PathBuf>,
    truncate: bool,
) -> std::result::Result<u64, u32> {
    let host_path = bottle_host.cloned().or_else(|| {
        state
            .host_file_mounts
            .iter()
            .find(|m| paths_match_guest(guest_path, &m.guest_path))
            .map(|m| m.host_path.clone())
    });

    // Large host files: stream without loading into RAM.
    if let Some(ref host) = host_path
        && !is_main_module_path(state, guest_path)
        && let Ok(meta) = std::fs::metadata(host)
        && meta.is_file()
        && meta.len() > crate::vfs::BUFFER_SIZE_THRESHOLD
    {
        if truncate {
            drop(crate::vfs::host_set_len(host, 0));
        }
        return allocate_open_file_ex(state, guest_path, Vec::new(), Some(host.clone()), true)
            .map_err(|_| ERROR_FILE_NOT_FOUND);
    }

    let mut bytes =
        resolve_guest_file_bytes(state, guest_path).map_err(|_| ERROR_FILE_NOT_FOUND)?;
    if truncate {
        bytes.clear();
    }
    allocate_open_file(state, guest_path, bytes, host_path).map_err(|_| ERROR_FILE_NOT_FOUND)
}

fn create_new_guest_file(
    state: &mut WinApiState,
    guest_path: &str,
    bottle_host: Option<&std::path::PathBuf>,
) -> std::result::Result<u64, u32> {
    if let Some(host) = bottle_host {
        if let Some(parent) = host.parent() {
            std::fs::create_dir_all(parent).map_err(|_| ERROR_PATH_NOT_FOUND)?;
        }
        std::fs::write(host, []).map_err(|_| ERROR_PATH_NOT_FOUND)?;
        // Host-backed creates always stream: a new archive starts at size 0, so the
        // size-threshold check would otherwise keep the entire growing file in RAM
        // (7za compression of hundreds of MiB was a classic progressive host-RSS leak).
        return allocate_open_file_ex(state, guest_path, Vec::new(), Some(host.clone()), true)
            .map_err(|_| ERROR_PATH_NOT_FOUND);
    }

    // No bottle: keep an in-memory virtual file (session-only).
    ensure_virtual_file(state, guest_path);
    allocate_open_file(state, guest_path, Vec::new(), None).map_err(|_| ERROR_PATH_NOT_FOUND)
}

fn ensure_virtual_file(state: &mut WinApiState, guest_path: &str) {
    if state
        .virtual_files
        .iter()
        .any(|entry| paths_match_guest(guest_path, &entry.guest_path))
    {
        return;
    }

    state.virtual_files.push(crate::VirtualGuestFile {
        guest_path: guest_path.to_owned(),
        bytes: Vec::new(),
    });
}

fn resolve_guest_file_bytes(state: &WinApiState, guest_path: &str) -> Result<Vec<u8>> {
    if is_main_module_path(state, guest_path) {
        return Ok(state.executable_file_bytes.clone());
    }

    if let Some(mount) = state
        .host_file_mounts
        .iter()
        .find(|mount| paths_match_guest(guest_path, &mount.guest_path))
    {
        return std::fs::read(&mount.host_path).with_context(|| {
            format!(
                "failed to read mounted host file {} for guest path {guest_path}",
                mount.host_path.display()
            )
        });
    }

    if let Some(map) = crate::vfs::guest_path_to_host(&state.volumes, guest_path)
        && map.host.is_file()
    {
        return std::fs::read(&map.host).with_context(|| {
            format!(
                "failed to read volume file {} for guest path {guest_path}",
                map.host.display()
            )
        });
    }

    if let Some(virtual_file) = state
        .virtual_files
        .iter()
        .find(|entry| paths_match_guest(guest_path, &entry.guest_path))
    {
        return Ok(virtual_file.bytes.clone());
    }

    // Allow opening by host absolute path when the guest happens to pass it
    // (useful for ad-hoc testing).
    let as_path = Path::new(guest_path);
    if as_path.is_absolute() && as_path.is_file() {
        return std::fs::read(as_path)
            .with_context(|| format!("failed to read host path {guest_path}"));
    }

    anyhow::bail!("guest file not found: {guest_path}")
}

fn read_create_file_stack_u32(engine: &mut dyn wie_cpu::CpuEngine, offset: u64) -> Result<u32> {
    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for CreateFile stack arg")?;

    let address = rsp
        .checked_add(offset)
        .context("CreateFile stack arg address overflow")?;

    let mut bytes = [0_u8; 4];
    engine
        .mem_read(address, &mut bytes)
        .context("failed to read CreateFile stack arg")?;

    Ok(u32::from_le_bytes(bytes))
}

fn allocate_open_file(
    state: &mut WinApiState,
    path: &str,
    bytes: Vec<u8>,
    host_path: Option<std::path::PathBuf>,
) -> Result<u64> {
    allocate_open_file_ex(state, path, bytes, host_path, false)
}

fn allocate_open_file_ex(
    state: &mut WinApiState,
    path: &str,
    bytes: Vec<u8>,
    host_path: Option<std::path::PathBuf>,
    force_stream: bool,
) -> Result<u64> {
    let handle = state.next_file_handle;

    state.next_file_handle = state
        .next_file_handle
        .checked_add(1)
        .context("guest file handle allocator overflow")?;

    let size_u64 = if force_stream {
        host_path
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .map_or(0, |m| m.len())
    } else {
        u64::try_from(bytes.len()).unwrap_or(0)
    };
    // Stream large host-backed files; keep small files fully buffered for guest I/O accel.
    let streaming = force_stream
        || (host_path.is_some()
            && size_u64 > crate::vfs::BUFFER_SIZE_THRESHOLD
            && !is_main_module_path(state, path));
    let bytes = if streaming { Vec::new() } else { bytes };

    state.open_files.insert(
        handle,
        OpenGuestFile {
            handle,
            path: path.to_owned(),
            bytes,
            cursor: 0,
            host_path,
            streaming,
            guest_data_va: None,
            guest_slot_index: None,
        },
    );

    // Keep legacy single-handle fields in sync when opening the main executable.
    if is_main_module_path(state, path) {
        state.executable_file_cursor = 0;
    }

    Ok(handle)
}

/// Flush open-file buffer to bottle/mount host path when present (buffered only).
fn persist_open_file_to_host(state: &WinApiState, handle: u64) {
    let Some(open_file) = find_open_file(state, handle) else {
        return;
    };
    if open_file.streaming {
        return;
    }
    let Some(host_path) = open_file.host_path.as_ref() else {
        return;
    };
    if let Some(parent) = host_path.parent() {
        drop(std::fs::create_dir_all(parent));
    }
    if let Err(error) = std::fs::write(host_path, &open_file.bytes) {
        tracing::debug!(
            handle,
            path = %host_path.display(),
            error = %error,
            "failed to persist open file to host"
        );
    }
}

/// If a buffered host-backed file has grown past [`crate::vfs::BUFFER_SIZE_THRESHOLD`],
/// spill once to disk and switch to streaming so further writes do not retain a full
/// in-memory copy (and do not clone it into `virtual_files` on every close).
fn maybe_promote_open_file_to_streaming(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    handle: u64,
) {
    let host_path = {
        let Some(open_file) = find_open_file(state, handle) else {
            return;
        };
        if open_file.streaming {
            return;
        }
        let size_u64 = u64::try_from(open_file.bytes.len()).unwrap_or(0);
        if size_u64 <= crate::vfs::BUFFER_SIZE_THRESHOLD {
            return;
        }
        let Some(host) = open_file.host_path.as_ref() else {
            return;
        };
        host.clone()
    };
    if let Some(parent) = host_path.parent() {
        drop(std::fs::create_dir_all(parent));
    }
    {
        let Some(open_file) = find_open_file(state, handle) else {
            return;
        };
        if let Err(error) = std::fs::write(&host_path, &open_file.bytes) {
            tracing::debug!(
                handle,
                path = %host_path.display(),
                error = %error,
                "failed to spill buffered file to host for streaming promote"
            );
            return;
        }
    }
    // Drop any guest I/O mirror (streaming stays on host path only).
    let _ = crate::guest_io_host::unregister_open_file(engine, state, handle).ok();
    if let Some(open_file) = find_open_file_mut(state, handle) {
        open_file.bytes.clear();
        open_file.bytes.shrink_to_fit();
        open_file.streaming = true;
    }
}

/// Mounts a host file into the guest path namespace.
pub fn mount_host_file(
    state: &mut WinApiState,
    guest_path: &str,
    host_path: impl AsRef<Path>,
) -> Result<()> {
    let host_path = host_path.as_ref();

    if !host_path.is_file() {
        anyhow::bail!(
            "host file does not exist or is not a regular file: {}",
            host_path.display()
        );
    }

    // Replace existing mount for the same guest path.
    state
        .host_file_mounts
        .retain(|mount| !paths_match_guest(guest_path, &mount.guest_path));

    state.host_file_mounts.push(crate::HostFileMount {
        guest_path: guest_path.to_owned(),
        host_path: host_path.to_path_buf(),
    });

    Ok(())
}

/// Whether a **file** exists at the guest path (for CreateFile open dispositions).
fn guest_path_exists(state: &WinApiState, path: &str) -> bool {
    if is_main_module_path(state, path) {
        return true;
    }
    if state
        .host_file_mounts
        .iter()
        .any(|mount| paths_match_guest(path, &mount.guest_path))
    {
        return true;
    }
    if state
        .virtual_files
        .iter()
        .any(|entry| paths_match_guest(path, &entry.guest_path))
    {
        return true;
    }
    if let Some(map) = crate::vfs::guest_path_to_host(&state.volumes, path) {
        return map.host.is_file();
    }
    false
}

fn guest_dir_exists(state: &WinApiState, path: &str) -> bool {
    let attrs = file_attributes_for_path(state, path);
    attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0
}

/// Handles `KERNEL32.dll!FileTimeToLocalFileTime`.
pub fn handle_file_time_to_local_file_time(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let input_file_time_ptr = engine
        .read_rcx()
        .context("failed to read RCX for FileTimeToLocalFileTime")?;

    let output_file_time_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FileTimeToLocalFileTime")?;

    let success = input_file_time_ptr != 0 && output_file_time_ptr != 0;

    if success {
        let mut bytes = [0_u8; 8];

        engine
            .mem_read(input_file_time_ptr, &mut bytes)
            .context("failed to read input FILETIME")?;

        engine
            .mem_write(output_file_time_ptr, &bytes)
            .context("failed to write output FILETIME")?;

        state.last_error = 0;
    } else {
        state.last_error = ERROR_INVALID_PARAMETER;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FileTimeToLocalFileTime")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FileTimeToSystemTime`.
pub fn handle_file_time_to_system_time(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let input_file_time_ptr = engine
        .read_rcx()
        .context("failed to read RCX for FileTimeToSystemTime")?;

    let system_time_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FileTimeToSystemTime")?;

    let success = input_file_time_ptr != 0 && system_time_ptr != 0;

    if success {
        // SYSTEMTIME:
        // WORD wYear;         offset 0
        // WORD wMonth;        offset 2
        // WORD wDayOfWeek;    offset 4
        // WORD wDay;          offset 6
        // WORD wHour;         offset 8
        // WORD wMinute;       offset 10
        // WORD wSecond;       offset 12
        // WORD wMilliseconds; offset 14

        let year_address = checked_field_address(system_time_ptr, 0, "wYear")?;
        let month_address = checked_field_address(system_time_ptr, 2, "wMonth")?;
        let day_of_week_address = checked_field_address(system_time_ptr, 4, "wDayOfWeek")?;
        let day_address = checked_field_address(system_time_ptr, 6, "wDay")?;
        let hour_address = checked_field_address(system_time_ptr, 8, "wHour")?;
        let minute_address = checked_field_address(system_time_ptr, 10, "wMinute")?;
        let second_address = checked_field_address(system_time_ptr, 12, "wSecond")?;
        let milliseconds_address = checked_field_address(system_time_ptr, 14, "wMilliseconds")?;

        // Deterministic fake converted time.
        write_guest_u16(engine, year_address, 2026)?;
        write_guest_u16(engine, month_address, 7)?;
        write_guest_u16(engine, day_of_week_address, 4)?;
        write_guest_u16(engine, day_address, 9)?;
        write_guest_u16(engine, hour_address, 12)?;
        write_guest_u16(engine, minute_address, 0)?;
        write_guest_u16(engine, second_address, 0)?;
        write_guest_u16(engine, milliseconds_address, 0)?;

        state.last_error = 0;
    } else {
        state.last_error = ERROR_INVALID_PARAMETER;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FileTimeToSystemTime")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetTimeZoneInformation`.
pub fn handle_get_time_zone_information(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let time_zone_info_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetTimeZoneInformation")?;

    let success = time_zone_info_ptr != 0;

    if success {
        // TIME_ZONE_INFORMATION:
        // LONG       Bias;              offset 0
        // WCHAR      StandardName[32];  offset 4
        // SYSTEMTIME StandardDate;      offset 68
        // LONG       StandardBias;      offset 84
        // WCHAR      DaylightName[32];  offset 88
        // SYSTEMTIME DaylightDate;      offset 152
        // LONG       DaylightBias;      offset 168

        let bias_address = checked_field_address(time_zone_info_ptr, 0, "Bias")?;
        let standard_name_address = checked_field_address(time_zone_info_ptr, 4, "StandardName")?;
        let standard_date_address = checked_field_address(time_zone_info_ptr, 68, "StandardDate")?;
        let standard_bias_address = checked_field_address(time_zone_info_ptr, 84, "StandardBias")?;
        let daylight_name_address = checked_field_address(time_zone_info_ptr, 88, "DaylightName")?;
        let daylight_date_address = checked_field_address(time_zone_info_ptr, 152, "DaylightDate")?;
        let daylight_bias_address = checked_field_address(time_zone_info_ptr, 168, "DaylightBias")?;

        let empty_name = [0_u8; 64];
        let empty_system_time = [0_u8; 16];

        // Deterministic UTC-like fake timezone:
        // Bias = 0, no daylight/standard transition dates.
        write_guest_u32(engine, bias_address, 0)?;
        engine
            .mem_write(standard_name_address, &empty_name)
            .context("failed to write TIME_ZONE_INFORMATION StandardName")?;
        engine
            .mem_write(standard_date_address, &empty_system_time)
            .context("failed to write TIME_ZONE_INFORMATION StandardDate")?;
        write_guest_u32(engine, standard_bias_address, 0)?;
        engine
            .mem_write(daylight_name_address, &empty_name)
            .context("failed to write TIME_ZONE_INFORMATION DaylightName")?;
        engine
            .mem_write(daylight_date_address, &empty_system_time)
            .context("failed to write TIME_ZONE_INFORMATION DaylightDate")?;
        write_guest_u32(engine, daylight_bias_address, 0)?;

        state.last_error = 0;
    } else {
        state.last_error = ERROR_INVALID_PARAMETER;
    }

    let return_value = if success {
        TIME_ZONE_ID_UNKNOWN
    } else {
        TIME_ZONE_ID_INVALID
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetTimeZoneInformation")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFileTime`.
pub fn handle_get_file_time(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for GetFileTime")?;

    let creation_time_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetFileTime")?;

    let last_access_time_ptr = engine
        .read_r8()
        .context("failed to read R8 for GetFileTime")?;

    let last_write_time_ptr = engine
        .read_r9()
        .context("failed to read R9 for GetFileTime")?;

    let success = is_open_file_handle(state, handle);

    if success {
        if creation_time_ptr != 0 {
            write_guest_u64(engine, creation_time_ptr, FIXED_SYSTEM_FILETIME)?;
        }

        if last_access_time_ptr != 0 {
            write_guest_u64(engine, last_access_time_ptr, FIXED_SYSTEM_FILETIME)?;
        }

        if last_write_time_ptr != 0 {
            write_guest_u64(engine, last_write_time_ptr, FIXED_SYSTEM_FILETIME)?;
        }

        state.last_error = 0;
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFileTime")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetFilePointer`.
pub fn handle_set_file_pointer(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for SetFilePointer")?;

    let distance_low = engine
        .read_rdx()
        .context("failed to read RDX for SetFilePointer")?;

    let distance_high_ptr = engine
        .read_r8()
        .context("failed to read R8 for SetFilePointer")?;

    let move_method = engine
        .read_r9()
        .context("failed to read R9 for SetFilePointer")?;

    let valid_method =
        move_method == FILE_BEGIN || move_method == FILE_CURRENT || move_method == FILE_END;

    let return_value = if !is_open_file_handle(state, handle) {
        state.last_error = ERROR_INVALID_HANDLE;
        INVALID_SET_FILE_POINTER
    } else if !valid_method {
        state.last_error = ERROR_INVALID_PARAMETER;
        INVALID_SET_FILE_POINTER
    } else {
        let low_u32 = u32::try_from(distance_low & 0xffff_ffff)
            .context("SetFilePointer low distance does not fit u32")?;
        let signed_low = i64::from(i32::from_ne_bytes(low_u32.to_ne_bytes()));

        let (new_cursor, path) = {
            let open_file = find_open_file_mut(state, handle)
                .context("open file vanished during SetFilePointer")?;

            let file_size = open_file.size();
            let path = open_file.path.clone();

            let base = if move_method == FILE_BEGIN {
                0_i64
            } else if move_method == FILE_CURRENT {
                i64::try_from(open_file.cursor).context("file cursor does not fit i64")?
            } else {
                i64::try_from(file_size).context("file size does not fit i64")?
            };

            let new_position = base
                .checked_add(signed_low)
                .context("SetFilePointer result overflow")?;

            if new_position < 0 {
                (None, path)
            } else {
                let new_cursor =
                    u64::try_from(new_position).context("new file cursor does not fit u64")?;
                open_file.cursor = new_cursor;
                (Some(new_cursor), path)
            }
        };

        if let Some(new_cursor) = new_cursor {
            if is_main_module_path(state, &path) {
                state.executable_file_cursor = new_cursor;
            }

            if distance_high_ptr != 0 {
                let high = u32::try_from(new_cursor >> 32)
                    .context("new file cursor high does not fit u32")?;
                write_guest_u32(engine, distance_high_ptr, high)?;
            }

            state.last_error = 0;
            let _ = crate::guest_io_host::sync_slot_from_host(engine, state, handle).ok();
            new_cursor & 0xffff_ffff
        } else {
            state.last_error = ERROR_INVALID_PARAMETER;
            INVALID_SET_FILE_POINTER
        }
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetFilePointer")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFileSize`.
pub fn handle_get_file_size(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for GetFileSize")?;

    let file_size_high_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetFileSize")?;

    let return_value = if let Some(open_file) = find_open_file(state, handle) {
        let file_size = open_file.size();

        let file_size_high =
            u32::try_from(file_size >> 32).context("open file size high does not fit u32")?;

        let file_size_low = u32::try_from(file_size & 0xffff_ffff)
            .context("open file size low does not fit u32")?;

        if file_size_high_ptr != 0 {
            write_guest_u32(engine, file_size_high_ptr, file_size_high)?;
        }

        state.last_error = 0;

        u64::from(file_size_low)
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        0xffff_ffff
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFileSize")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles dynamic `KERNEL32.dll!EncodePointer`.
pub fn handle_encode_pointer(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let pointer = engine
        .read_rcx()
        .context("failed to read RCX for EncodePointer")?;

    let return_address = engine
        .return_from_win64_api(pointer)
        .context("failed to return from EncodePointer")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: pointer,
    })
}

/// Handles dynamic `KERNEL32.dll!DecodePointer`.
pub fn handle_decode_pointer(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let pointer = engine
        .read_rcx()
        .context("failed to read RCX for DecodePointer")?;

    let return_address = engine
        .return_from_win64_api(pointer)
        .context("failed to return from DecodePointer")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: pointer,
    })
}

/// Handles dynamic `KERNEL32.dll!InitializeCriticalSectionAndSpinCount`.
///
/// Microsoft Learn: returns nonzero on success; stores the spin count in the CS.
pub fn handle_initialize_critical_section_and_spin_count(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let critical_section_ptr = engine
        .read_rcx()
        .context("failed to read RCX for InitializeCriticalSectionAndSpinCount")?;

    let spin_count = engine
        .read_rdx()
        .context("failed to read RDX for InitializeCriticalSectionAndSpinCount")?;

    if critical_section_ptr != 0 {
        write_critical_section_unlocked(engine, critical_section_ptr, spin_count)?;
    }

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from InitializeCriticalSectionAndSpinCount")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!ReadFile`.
///
/// Microsoft Learn: valid on disk and console handles. Console stdin is served
/// from `WinApiState::stdin_bytes` (host inject and/or live host line-fill when
/// `stdin_mode` is `LiveHost`). Default console line input: a live fill blocks
/// until `\n` or EOF. Success with 0 bytes means EOF.
pub fn handle_read_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let buffer_ptr = engine.read_rdx()?;
    let bytes_to_read = engine.read_r8()?;
    let bytes_read_ptr = engine.read_r9()?;

    // Microsoft Learn: sets *lpNumberOfBytesRead to zero before any work/error check.
    if bytes_read_ptr != 0 {
        write_guest_u32(engine, bytes_read_ptr, 0)?;
    }

    if buffer_ptr == 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    // Console stdin: inject buffer, then optional live host line-fill.
    if handle == FAKE_STDIN_HANDLE {
        let requested =
            usize::try_from(bytes_to_read).context("ReadFile byte count does not fit usize")?;

        let mut available = state.stdin_bytes.len().saturating_sub(state.stdin_cursor);
        if available == 0 && state.stdin_mode == crate::GuestStdinMode::LiveHost {
            match refill_stdin_from_host(state) {
                Ok(true) => {
                    available = state.stdin_bytes.len().saturating_sub(state.stdin_cursor);
                }
                Ok(false) => {
                    // Host EOF → success with 0 bytes (already zeroed count).
                    state.last_error = 0;
                    let return_address = engine.return_from_win64_api(1)?;
                    return Ok(WinApiHandlerResult {
                        return_address,
                        return_value: 1,
                    });
                }
                Err(()) => {
                    state.last_error = ERROR_READ_FAULT;
                    let return_address = engine.return_from_win64_api(0)?;
                    return Ok(WinApiHandlerResult {
                        return_address,
                        return_value: 0,
                    });
                }
            }
        }

        let read_len = requested.min(available);
        if read_len > 0 {
            let end = state
                .stdin_cursor
                .checked_add(read_len)
                .context("ReadFile stdin end overflow")?;
            let data = state
                .stdin_bytes
                .get(state.stdin_cursor..end)
                .context("ReadFile stdin slice out of range")?;
            engine
                .mem_write(buffer_ptr, data)
                .context("failed to write ReadFile stdin bytes")?;
            state.stdin_cursor = end;
            if bytes_read_ptr != 0 {
                let read_len_u32 =
                    u32::try_from(read_len).context("ReadFile byte count does not fit u32")?;
                write_guest_u32(engine, bytes_read_ptr, read_len_u32)?;
            }
        }
        // available == 0 && InjectOnly → inject exhausted → EOF (0 bytes, success).
        state.last_error = 0;
        let return_address = engine.return_from_win64_api(1)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 1,
        });
    }

    // Console stdout/stderr are not readable.
    if is_console_output_handle(handle) {
        state.last_error = ERROR_INVALID_HANDLE;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    let success = is_open_file_handle(state, handle);

    if success {
        let _ = crate::guest_io_host::sync_host_cursor_from_guest(engine, state, handle).ok();
        let requested =
            usize::try_from(bytes_to_read).context("ReadFile byte count does not fit usize")?;

        let streaming = find_open_file(state, handle).is_some_and(|f| f.streaming);
        if streaming {
            let (host_path, cursor_before, path) = {
                let open_file =
                    find_open_file(state, handle).context("open file vanished during ReadFile")?;
                (
                    open_file.host_path.clone(),
                    open_file.cursor,
                    open_file.path.clone(),
                )
            };
            let Some(host) = host_path else {
                state.last_error = ERROR_INVALID_HANDLE;
                let return_address = engine.return_from_win64_api(0)?;
                return Ok(WinApiHandlerResult {
                    return_address,
                    return_value: 0,
                });
            };
            let mut data = vec![0_u8; requested];
            let n = crate::vfs::host_read_at(&host, cursor_before, &mut data).unwrap_or(0);
            data.truncate(n);
            engine
                .mem_write(buffer_ptr, &data)
                .context("failed to write ReadFile stream bytes")?;
            if let Some(open_file) = find_open_file_mut(state, handle) {
                open_file.cursor = cursor_before.saturating_add(u64::try_from(n).unwrap_or(0));
            }
            if bytes_read_ptr != 0 {
                write_guest_u32(engine, bytes_read_ptr, u32::try_from(n).unwrap_or(0))?;
            }
            if is_main_module_path(state, &path) {
                state.executable_file_cursor =
                    cursor_before.saturating_add(u64::try_from(n).unwrap_or(0));
            }
            state.last_error = 0;
        } else {
            // Phase 1: advance cursor and capture slice bounds without cloning the path/body.
            let (start, end, cursor_after, is_exe) = {
                let (cursor_usize, end, cursor_after, path_for_exe) = {
                    let open_file = find_open_file_mut(state, handle)
                        .context("open file vanished during ReadFile")?;

                    let cursor_before = open_file.cursor;
                    let cursor_usize =
                        usize::try_from(cursor_before).context("file cursor does not fit usize")?;
                    let available = open_file.bytes.len().saturating_sub(cursor_usize);
                    let read_len = requested.min(available);
                    let end = cursor_usize
                        .checked_add(read_len)
                        .context("ReadFile end offset overflow")?;
                    let read_len_u64 =
                        u64::try_from(read_len).context("ReadFile byte count does not fit u64")?;
                    open_file.cursor = cursor_before
                        .checked_add(read_len_u64)
                        .context("ReadFile cursor overflow")?;
                    (cursor_usize, end, open_file.cursor, open_file.path.clone())
                };
                let is_exe = is_main_module_path(state, &path_for_exe);
                (cursor_usize, end, cursor_after, is_exe)
            };

            // Phase 2: immutable borrow for zero-copy mem_write of the file slice.
            {
                let open_file = find_open_file(state, handle)
                    .context("open file vanished during ReadFile write")?;
                let data = open_file
                    .bytes
                    .get(start..end)
                    .context("ReadFile slice out of range")?;
                engine
                    .mem_write(buffer_ptr, data)
                    .context("failed to write ReadFile bytes")?;

                let read_len_u32 =
                    u32::try_from(data.len()).context("ReadFile byte count does not fit u32")?;
                if bytes_read_ptr != 0 {
                    write_guest_u32(engine, bytes_read_ptr, read_len_u32)?;
                }
            }

            if is_exe {
                state.executable_file_cursor = cursor_after;
            }

            state.last_error = 0;
            let _ = crate::guest_io_host::sync_slot_from_host(engine, state, handle).ok();
        }
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
    }

    let return_value = u64::from(success);
    let return_address = engine.return_from_win64_api(return_value)?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!WriteFile`.
///
/// Microsoft Learn: valid on disk and console handles. Stdout/stderr write to the
/// host console; stdin is not writable.
pub fn handle_write_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for WriteFile")?;

    let buffer_ptr = engine
        .read_rdx()
        .context("failed to read RDX for WriteFile")?;

    let bytes_to_write = engine
        .read_r8()
        .context("failed to read R8 for WriteFile")?;

    let bytes_written_ptr = engine
        .read_r9()
        .context("failed to read R9 for WriteFile")?;

    // Mirror ReadFile: zero the optional out-count before validation.
    if bytes_written_ptr != 0 {
        write_guest_u32(engine, bytes_written_ptr, 0)?;
    }

    if buffer_ptr == 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    // Console stdout/stderr → host console.
    if is_console_output_handle(handle) {
        let write_len =
            usize::try_from(bytes_to_write).context("WriteFile byte count does not fit usize")?;
        let mut data = vec![0_u8; write_len];
        if write_len > 0 {
            engine
                .mem_read(buffer_ptr, &mut data)
                .context("failed to read WriteFile console buffer")?;
        }
        write_host_console_handle(handle, &data);
        if bytes_written_ptr != 0 {
            let write_len_u32 =
                u32::try_from(write_len).context("WriteFile byte count does not fit u32")?;
            write_guest_u32(engine, bytes_written_ptr, write_len_u32)?;
        }
        state.last_error = 0;
        let return_address = engine.return_from_win64_api(1)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 1,
        });
    }

    // Console stdin is not writable.
    if handle == FAKE_STDIN_HANDLE {
        state.last_error = ERROR_INVALID_HANDLE;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    let success = is_open_file_handle(state, handle);

    if success {
        let write_len =
            usize::try_from(bytes_to_write).context("WriteFile byte count does not fit usize")?;

        let mut data = vec![0_u8; write_len];
        if write_len > 0 {
            engine
                .mem_read(buffer_ptr, &mut data)
                .context("failed to read WriteFile source buffer")?;
        }

        let streaming = find_open_file(state, handle).is_some_and(|f| f.streaming);
        let (path, cursor_before, cursor_after, file_size) = if streaming {
            let open_file =
                find_open_file(state, handle).context("open file vanished during WriteFile")?;
            let host = open_file
                .host_path
                .clone()
                .ok_or_else(|| anyhow::anyhow!("streaming file missing host_path"))?;
            let cursor_before = open_file.cursor;
            let path = open_file.path.clone();
            crate::vfs::host_write_at(&host, cursor_before, &data)
                .map_err(|e| anyhow::anyhow!("host WriteFile: {e}"))?;
            let write_len_u64 =
                u64::try_from(write_len).context("WriteFile byte count does not fit u64")?;
            let cursor_after = cursor_before
                .checked_add(write_len_u64)
                .context("WriteFile cursor overflow")?;
            if let Some(open_file) = find_open_file_mut(state, handle) {
                open_file.cursor = cursor_after;
            }
            let file_size = find_open_file(state, handle).map_or(0, OpenGuestFile::size);
            (path, cursor_before, cursor_after, file_size)
        } else {
            let open_file =
                find_open_file_mut(state, handle).context("open file vanished during WriteFile")?;

            let cursor_before = open_file.cursor;
            let path = open_file.path.clone();

            let cursor_usize =
                usize::try_from(cursor_before).context("file cursor does not fit usize")?;

            let end = cursor_usize
                .checked_add(write_len)
                .context("WriteFile end offset overflow")?;

            if end > open_file.bytes.len() {
                open_file.bytes.resize(end, 0);
            }

            open_file
                .bytes
                .get_mut(cursor_usize..end)
                .context("WriteFile slice out of range")?
                .copy_from_slice(&data);

            let write_len_u64 =
                u64::try_from(write_len).context("WriteFile byte count does not fit u64")?;

            open_file.cursor = cursor_before
                .checked_add(write_len_u64)
                .context("WriteFile cursor overflow")?;

            let cursor_after = open_file.cursor;
            let file_size = u64::try_from(open_file.bytes.len()).unwrap_or(0);
            (path, cursor_before, cursor_after, file_size)
        };

        // Do **not** full-clone / full-rewrite the file on every WriteFile.
        // That was O(n²) host I/O and a 2× temporary RAM spike while the archive
        // grew (classic progressive leak during 7za create). Buffered host files
        // spill once when they cross the streaming threshold; durable flush is
        // CloseHandle / FlushFileBuffers / SetEndOfFile.
        if !streaming {
            maybe_promote_open_file_to_streaming(engine, state, handle);
        }

        if is_main_module_path(state, &path) {
            state.executable_file_cursor = cursor_after;
        }

        let write_len_u32 =
            u32::try_from(write_len).context("WriteFile byte count does not fit u32")?;

        if bytes_written_ptr != 0 {
            write_guest_u32(engine, bytes_written_ptr, write_len_u32)?;
        }

        tracing::debug!(
            handle,
            buffer = buffer_ptr,
            requested = bytes_to_write,
            cursor_before,
            actual_write = write_len,
            cursor_after,
            file_size,
            path = %path,
            "WriteFile"
        );

        state.last_error = 0;
    } else {
        tracing::debug!(
            handle,
            buffer = buffer_ptr,
            requested = bytes_to_write,
            "WriteFile invalid handle"
        );
        state.last_error = ERROR_INVALID_HANDLE;
    }

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from WriteFile")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Copies the open handle's buffer into `virtual_files` for the same path.
///
/// **Host-backed / streaming files are never mirrored.** Bottle volume paths
/// (WIE_ROOT / drive-D) used to land here on every CloseHandle because they are
/// not `host_file_mounts` entries — so opening+closing every source file during
/// a 7za scan permanently retained full contents in `virtual_files` (session-long
/// RAM growth proportional to scanned data).
fn sync_open_bytes_to_virtual(state: &mut WinApiState, path: &str, handle: u64) {
    let Some(open_file) = find_open_file(state, handle) else {
        return;
    };
    // Host path or streaming ⇒ content lives on disk; never retain a second copy.
    if open_file.host_path.is_some() || open_file.streaming {
        return;
    }
    if is_main_module_path(state, path) {
        return;
    }
    // Volume-mapped paths without an open host_path still must not accumulate.
    if crate::vfs::guest_path_to_host(&state.volumes, path).is_some() {
        return;
    }
    if state
        .host_file_mounts
        .iter()
        .any(|mount| paths_match_guest(path, &mount.guest_path))
    {
        return;
    }

    let bytes = open_file.bytes.clone();

    if let Some(virtual_file) = state
        .virtual_files
        .iter_mut()
        .find(|entry| paths_match_guest(path, &entry.guest_path))
    {
        virtual_file.bytes = bytes;
        return;
    }

    // Pure in-session virtual files only (no bottle/mount/volume backing).
    state.virtual_files.push(crate::VirtualGuestFile {
        guest_path: path.to_owned(),
        bytes,
    });
}

/// Handles `KERNEL32.dll!GetCurrentDirectoryW`.
///
/// Microsoft Learn return value:
/// - success: number of characters written **excluding** the terminating NUL
/// - buffer too small: required size **including** the terminating NUL
/// - size query: `lpBuffer == NULL` and `nBufferLength == 0` → required size with NUL
/// - failure: zero (not used for the insufficient-buffer case)
pub fn handle_get_current_directory_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let buffer_length = engine
        .read_rcx()
        .context("failed to read RCX for GetCurrentDirectoryW")?;

    let buffer_ptr = engine
        .read_rdx()
        .context("failed to read RDX for GetCurrentDirectoryW")?;

    let directory = state.current_directory_wide.clone();

    let character_count = u64::try_from(directory.len())
        .context("fake current directory length does not fit in u64")?;

    let required_with_nul = character_count
        .checked_add(1)
        .context("GetCurrentDirectoryW required size overflow")?;

    // Need nBufferLength > character_count so there is room for the NUL.
    let return_value = if buffer_ptr == 0 || buffer_length == 0 || buffer_length <= character_count
    {
        required_with_nul
    } else {
        let mut encoded = directory;
        encoded.push(0);

        let byte_len = encoded
            .len()
            .checked_mul(std::mem::size_of::<u16>())
            .context("GetCurrentDirectoryW byte length overflow")?;

        let mut bytes = Vec::with_capacity(byte_len);

        for code_unit in encoded {
            bytes.extend_from_slice(&code_unit.to_le_bytes());
        }

        engine
            .mem_write(buffer_ptr, &bytes)
            .context("failed to write GetCurrentDirectoryW buffer")?;

        character_count
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetCurrentDirectoryW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetCurrentDirectoryW`.
pub fn handle_set_current_directory_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let directory_ptr = engine
        .read_rcx()
        .context("failed to read RCX for SetCurrentDirectoryW")?;

    let success = if directory_ptr == 0 {
        state.last_error = ERROR_PATH_NOT_FOUND;
        false
    } else {
        let directory = read_wide_string_from_cpu(engine, directory_ptr, 32_768)
            .context("failed to read SetCurrentDirectoryW path")?;

        if directory.is_empty() {
            state.last_error = ERROR_PATH_NOT_FOUND;
            false
        } else {
            // Relative directory names resolve against the current directory (MSDN).
            let cwd = String::from_utf16_lossy(&state.current_directory_wide);
            let full = resolve_full_windows_path(&cwd, &directory);
            if guest_dir_exists(state, &full) {
                state.current_directory_wide = full.encode_utf16().collect();
                // Keep guest cwd blob in sync when stubs are installed (best-effort).
                state.last_error = 0;
                true
            } else {
                state.last_error = ERROR_PATH_NOT_FOUND;
                false
            }
        }
    };

    let return_value = u64::from(success);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetCurrentDirectoryW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetCurrentProcess`.
pub fn handle_get_current_process(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    // Windows pseudohandle for the current process: (HANDLE)-1.
    let return_value = u64::MAX;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetCurrentProcess")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

// ─── Soft console / process helpers for real CLI tools (7za) ────────────────

const FIXED_PERFORMANCE_FREQUENCY: u64 = 10_000_000;
const ENABLE_PROCESSED_INPUT: u32 = 0x0001;
const ENABLE_LINE_INPUT: u32 = 0x0002;
const ENABLE_ECHO_INPUT: u32 = 0x0004;
const ENABLE_PROCESSED_OUTPUT: u32 = 0x0001;
const ENABLE_WRAP_AT_EOL_OUTPUT: u32 = 0x0002;
const DEFAULT_CONSOLE_MODE_IN: u32 = ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT;
const DEFAULT_CONSOLE_MODE_OUT: u32 = ENABLE_PROCESSED_OUTPUT | ENABLE_WRAP_AT_EOL_OUTPUT;

fn ret_bool_true(engine: &mut dyn wie_cpu::CpuEngine, api: &str) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(1)
        .with_context(|| format!("failed to return from {api}"))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

fn ret_u64(
    engine: &mut dyn wie_cpu::CpuEngine,
    value: u64,
    api: &str,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(value)
        .with_context(|| format!("failed to return from {api}"))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

/// `BOOL SetConsoleCtrlHandler(PHANDLER_ROUTINE, BOOL)` — accept, ignore handler.
pub fn handle_set_console_ctrl_handler(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _handler = engine.read_rcx().context("SetConsoleCtrlHandler RCX")?;
    let _add = engine.read_rdx().context("SetConsoleCtrlHandler RDX")?;
    ret_bool_true(engine, "SetConsoleCtrlHandler")
}

/// `BOOL GetConsoleMode(HANDLE, LPDWORD)`.
pub fn handle_get_console_mode(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx().context("GetConsoleMode RCX")?;
    let mode_ptr = engine.read_rdx().context("GetConsoleMode RDX")?;
    if mode_ptr == 0 {
        return ret_u64(engine, 0, "GetConsoleMode");
    }
    let mode = if handle == FAKE_STDIN_HANDLE {
        DEFAULT_CONSOLE_MODE_IN
    } else {
        DEFAULT_CONSOLE_MODE_OUT
    };
    write_guest_u32(engine, mode_ptr, mode)?;
    ret_bool_true(engine, "GetConsoleMode")
}

/// `BOOL SetConsoleMode(HANDLE, DWORD)`.
pub fn handle_set_console_mode(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _handle = engine.read_rcx().context("SetConsoleMode RCX")?;
    let _mode = engine.read_rdx().context("SetConsoleMode RDX")?;
    ret_bool_true(engine, "SetConsoleMode")
}

/// `BOOL GetConsoleScreenBufferInfo(HANDLE, PCONSOLE_SCREEN_BUFFER_INFO)`.
pub fn handle_get_console_screen_buffer_info(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _handle = engine
        .read_rcx()
        .context("GetConsoleScreenBufferInfo RCX")?;
    let info_ptr = engine
        .read_rdx()
        .context("GetConsoleScreenBufferInfo RDX")?;
    if info_ptr == 0 {
        return ret_u64(engine, 0, "GetConsoleScreenBufferInfo");
    }
    // CONSOLE_SCREEN_BUFFER_INFO is 22 bytes; pad to 24 so short stacks stay safe.
    // COORD dwSize {X,Y} at 0; COORD dwCursorPosition at 4; WORD wAttributes at 8;
    // SMALL_RECT srWindow at 10; COORD dwMaximumWindowSize at 18.
    let mut buf = [0_u8; 24];
    // dwSize = 80 x 25
    buf[0..2].copy_from_slice(&80_u16.to_le_bytes());
    buf[2..4].copy_from_slice(&25_u16.to_le_bytes());
    // wAttributes = 0x07 (gray on black)
    buf[8..10].copy_from_slice(&0x0007_u16.to_le_bytes());
    // srWindow: Left=0 Top=0 Right=79 Bottom=24
    buf[10..12].copy_from_slice(&0_u16.to_le_bytes());
    buf[12..14].copy_from_slice(&0_u16.to_le_bytes());
    buf[14..16].copy_from_slice(&79_u16.to_le_bytes());
    buf[16..18].copy_from_slice(&24_u16.to_le_bytes());
    // dwMaximumWindowSize
    buf[18..20].copy_from_slice(&80_u16.to_le_bytes());
    buf[20..22].copy_from_slice(&25_u16.to_le_bytes());
    engine
        .mem_write(info_ptr, &buf)
        .context("GetConsoleScreenBufferInfo write")?;
    ret_bool_true(engine, "GetConsoleScreenBufferInfo")
}

/// `VOID SetFileApisToOEM(void)`.
pub fn handle_set_file_apis_to_oem(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    ret_u64(engine, 0, "SetFileApisToOEM")
}

/// `BOOL QueryPerformanceFrequency(LARGE_INTEGER*)`.
pub fn handle_query_performance_frequency(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let ptr = engine.read_rcx().context("QueryPerformanceFrequency RCX")?;
    if ptr != 0 {
        write_guest_u64(engine, ptr, FIXED_PERFORMANCE_FREQUENCY)?;
    }
    ret_bool_true(engine, "QueryPerformanceFrequency")
}

/// `VOID GetSystemInfo(LPSYSTEM_INFO)`.
pub fn handle_get_system_info(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let ptr = engine.read_rcx().context("GetSystemInfo RCX")?;
    if ptr != 0 {
        // SYSTEM_INFO on x64 (48 bytes):
        // union { DWORD dwOemId; struct { WORD wProcessorArchitecture; WORD wReserved; } }
        // DWORD dwPageSize;
        // LPVOID lpMinimumApplicationAddress;
        // LPVOID lpMaximumApplicationAddress;
        // DWORD_PTR dwActiveProcessorMask;
        // DWORD dwNumberOfProcessors;
        // DWORD dwProcessorType;
        // DWORD dwAllocationGranularity;
        // WORD wProcessorLevel;
        // WORD wProcessorRevision;
        let mut buf = [0_u8; 48];
        // wProcessorArchitecture = 9 (PROCESSOR_ARCHITECTURE_AMD64)
        buf[0..2].copy_from_slice(&9_u16.to_le_bytes());
        // dwPageSize = 0x1000
        buf[4..8].copy_from_slice(&0x1000_u32.to_le_bytes());
        // min app address 0x10000
        buf[8..16].copy_from_slice(&0x1_0000_u64.to_le_bytes());
        // max app address
        buf[16..24].copy_from_slice(&0x0000_7fff_ffff_ffff_u64.to_le_bytes());
        // active processor mask = 1
        buf[24..32].copy_from_slice(&1_u64.to_le_bytes());
        // number of processors = 1
        buf[32..36].copy_from_slice(&1_u32.to_le_bytes());
        // processor type = 8664
        buf[36..40].copy_from_slice(&8664_u32.to_le_bytes());
        // allocation granularity = 0x10000
        buf[40..44].copy_from_slice(&0x1_0000_u32.to_le_bytes());
        // level / revision
        buf[44..46].copy_from_slice(&6_u16.to_le_bytes());
        buf[46..48].copy_from_slice(&0x3c03_u16.to_le_bytes());
        engine.mem_write(ptr, &buf).context("GetSystemInfo write")?;
    }
    ret_u64(engine, 0, "GetSystemInfo")
}

/// `BOOL IsProcessorFeaturePresent(DWORD)`.
pub fn handle_is_processor_feature_present(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let feature = low_u32(engine.read_rcx()?, "IsProcessorFeaturePresent")?;
    // Advertise a few common x64 features as present; unknown → FALSE.
    // 0=floating point, 6=compare exchange double, 7=MMX, 8=XMMI (SSE),
    // 10=3DNow, 13=SSE2, 14=SSE3, 21=NX, 23=RDTSC, 25=compare exchange 128.
    let present = matches!(feature, 0 | 6 | 7 | 8 | 10 | 13 | 14 | 21 | 23 | 25);
    ret_u64(engine, u64::from(present), "IsProcessorFeaturePresent")
}

/// `BOOL GlobalMemoryStatusEx(LPMEMORYSTATUSEX)`.
pub fn handle_global_memory_status_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let ptr = engine.read_rcx().context("GlobalMemoryStatusEx RCX")?;
    if ptr == 0 {
        return ret_u64(engine, 0, "GlobalMemoryStatusEx");
    }
    // Read dwLength from guest (caller must set it); we fill the rest.
    let length = {
        let mut b = [0_u8; 4];
        engine.mem_read(ptr, &mut b)?;
        u32::from_le_bytes(b)
    };
    if length < 64 {
        return ret_u64(engine, 0, "GlobalMemoryStatusEx");
    }
    // MEMORYSTATUSEX: dwLength@0, dwMemoryLoad@4, ullTotalPhys@8, ullAvailPhys@16,
    // ullTotalPageFile@24, ullAvailPageFile@32, ullTotalVirtual@40, ullAvailVirtual@48,
    // ullAvailExtendedVirtual@56.
    write_guest_u32(engine, ptr, 64)?;
    write_guest_u32(engine, ptr.wrapping_add(4), 25)?;
    write_guest_u64(engine, ptr.wrapping_add(8), 8_u64 * 1024 * 1024 * 1024)?;
    write_guest_u64(engine, ptr.wrapping_add(16), 6_u64 * 1024 * 1024 * 1024)?;
    write_guest_u64(engine, ptr.wrapping_add(24), 16_u64 * 1024 * 1024 * 1024)?;
    write_guest_u64(engine, ptr.wrapping_add(32), 12_u64 * 1024 * 1024 * 1024)?;
    write_guest_u64(engine, ptr.wrapping_add(40), 128_u64 * 1024 * 1024 * 1024)?;
    write_guest_u64(engine, ptr.wrapping_add(48), 120_u64 * 1024 * 1024 * 1024)?;
    write_guest_u64(engine, ptr.wrapping_add(56), 0)?;
    ret_bool_true(engine, "GlobalMemoryStatusEx")
}

/// `BOOL GetProcessTimes(HANDLE, LPFILETIME×4)`.
pub fn handle_get_process_times(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _process = engine.read_rcx().context("GetProcessTimes RCX")?;
    let creation = engine.read_rdx().context("GetProcessTimes RDX")?;
    let exit_t = engine.read_r8().context("GetProcessTimes R8")?;
    let kernel = engine.read_r9().context("GetProcessTimes R9")?;
    let rsp = engine.read_rsp().context("GetProcessTimes RSP")?;
    let user = read_guest_u64(
        engine,
        checked_address(rsp, 0x28, "GetProcessTimes lpUserTime")?,
    )?;
    // Fixed synthetic times (100-ns ticks).
    if creation != 0 {
        write_guest_u64(engine, creation, FIXED_SYSTEM_FILETIME)?;
    }
    if exit_t != 0 {
        write_guest_u64(engine, exit_t, 0)?;
    }
    if kernel != 0 {
        write_guest_u64(engine, kernel, 10_000_000)?;
    }
    if user != 0 {
        write_guest_u64(engine, user, 20_000_000)?;
    }
    ret_bool_true(engine, "GetProcessTimes")
}

/// `SIZE_T GetLargePageMinimum(void)` — 0 = large pages unavailable.
pub fn handle_get_large_page_minimum(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    ret_u64(engine, 0, "GetLargePageMinimum")
}

/// `BOOL GetProcessAffinityMask(HANDLE, PDWORD_PTR, PDWORD_PTR)`.
pub fn handle_get_process_affinity_mask(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _process = engine.read_rcx()?;
    let proc_mask = engine.read_rdx()?;
    let sys_mask = engine.read_r8()?;
    if proc_mask != 0 {
        write_guest_u64(engine, proc_mask, 1)?;
    }
    if sys_mask != 0 {
        write_guest_u64(engine, sys_mask, 1)?;
    }
    ret_bool_true(engine, "GetProcessAffinityMask")
}

/// `BOOL SetProcessAffinityMask(HANDLE, DWORD_PTR)`.
pub fn handle_set_process_affinity_mask(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _process = engine.read_rcx()?;
    let _mask = engine.read_rdx()?;
    ret_bool_true(engine, "SetProcessAffinityMask")
}

/// `DWORD_PTR SetThreadAffinityMask(HANDLE, DWORD_PTR)` — return previous mask.
pub fn handle_set_thread_affinity_mask(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _thread = engine.read_rcx()?;
    let _mask = engine.read_rdx()?;
    ret_u64(engine, 1, "SetThreadAffinityMask")
}

/// `LONG CompareFileTime(const FILETIME*, const FILETIME*)`.
pub fn handle_compare_file_time(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let a = engine.read_rcx()?;
    let b = engine.read_rdx()?;
    let ta = if a == 0 {
        0
    } else {
        read_guest_u64(engine, a)?
    };
    let tb = if b == 0 {
        0
    } else {
        read_guest_u64(engine, b)?
    };
    let cmp: i32 = match ta.cmp(&tb) {
        std::cmp::Ordering::Less => -1,
        std::cmp::Ordering::Equal => 0,
        std::cmp::Ordering::Greater => 1,
    };
    ret_u64(
        engine,
        u64::from_ne_bytes(i64::from(cmp).to_ne_bytes()),
        "CompareFileTime",
    )
}

/// `BOOL LocalFileTimeToFileTime(const FILETIME*, LPFILETIME)`.
pub fn handle_local_file_time_to_file_time(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let local = engine.read_rcx()?;
    let file = engine.read_rdx()?;
    if local == 0 || file == 0 {
        return ret_u64(engine, 0, "LocalFileTimeToFileTime");
    }
    // Prototype: treat local == UTC (no timezone conversion).
    let t = read_guest_u64(engine, local)?;
    write_guest_u64(engine, file, t)?;
    ret_bool_true(engine, "LocalFileTimeToFileTime")
}

/// `BOOL FileTimeToDosDateTime(const FILETIME*, LPWORD, LPWORD)`.
pub fn handle_file_time_to_dos_date_time(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let ft = engine.read_rcx()?;
    let date_ptr = engine.read_rdx()?;
    let time_ptr = engine.read_r8()?;
    if ft == 0 {
        return ret_u64(engine, 0, "FileTimeToDosDateTime");
    }
    // Fixed DOS date/time: 2026-07-19 12:00:00 → rough encoding.
    // DOS date: day + (month<<5) + ((year-1980)<<9)
    // 2026-07-19 → DOS date word; noon → DOS time word.
    let dos_date: u16 = 0x5c_f3; // precomputed: day|month<<5|(year-1980)<<9
    let dos_time: u16 = 0x60_00; // hour 12 << 11
    if date_ptr != 0 {
        write_guest_u16(engine, date_ptr, dos_date)?;
    }
    if time_ptr != 0 {
        write_guest_u16(engine, time_ptr, dos_time)?;
    }
    ret_bool_true(engine, "FileTimeToDosDateTime")
}

/// `BOOL DosDateTimeToFileTime(WORD, WORD, LPFILETIME)`.
pub fn handle_dos_date_time_to_file_time(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _date = engine.read_rcx()?;
    let _time = engine.read_rdx()?;
    let ft = engine.read_r8()?;
    if ft == 0 {
        return ret_u64(engine, 0, "DosDateTimeToFileTime");
    }
    write_guest_u64(engine, ft, FIXED_SYSTEM_FILETIME)?;
    ret_bool_true(engine, "DosDateTimeToFileTime")
}

/// Fake free/total disk sizes for `GetDiskFreeSpace*`.
const FAKE_DISK_GIB: u64 = 1024 * 1024 * 1024;
/// ~100 GiB of 4 KiB clusters (8 sectors × 512).
const FAKE_DISK_CLUSTERS: u32 = 26_214_400;
/// Drive string payload: `C:\` + NUL + final NUL (TCHARs).
const LOGICAL_DRIVE_TCHARS: u32 = 4;

/// `BOOL GetDiskFreeSpaceExW(LPCWSTR, PULARGE_INTEGER×3)`.
pub fn handle_get_disk_free_space_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _path = engine.read_rcx()?;
    let free_caller = engine.read_rdx()?;
    let total = engine.read_r8()?;
    let free_total = engine.read_r9()?;
    if free_caller != 0 {
        write_guest_u64(engine, free_caller, 50 * FAKE_DISK_GIB)?;
    }
    if total != 0 {
        write_guest_u64(engine, total, 100 * FAKE_DISK_GIB)?;
    }
    if free_total != 0 {
        write_guest_u64(engine, free_total, 50 * FAKE_DISK_GIB)?;
    }
    ret_bool_true(engine, "GetDiskFreeSpaceExW")
}

/// `BOOL GetDiskFreeSpaceW(LPCWSTR, LPDWORD×4)`.
pub fn handle_get_disk_free_space_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _path = engine.read_rcx()?;
    let spc = engine.read_rdx()?; // sectors per cluster
    let bps = engine.read_r8()?; // bytes per sector
    let free_clusters = engine.read_r9()?;
    let rsp = engine.read_rsp()?;
    let total_clusters = read_guest_u64(
        engine,
        checked_address(rsp, 0x28, "GetDiskFreeSpaceW total")?,
    )?;
    if spc != 0 {
        write_guest_u32(engine, spc, 8)?;
    }
    if bps != 0 {
        write_guest_u32(engine, bps, 512)?;
    }
    let half = FAKE_DISK_CLUSTERS.wrapping_shr(1);
    if free_clusters != 0 {
        write_guest_u32(engine, free_clusters, half)?;
    }
    if total_clusters != 0 {
        write_guest_u32(engine, total_clusters, FAKE_DISK_CLUSTERS)?;
    }
    ret_bool_true(engine, "GetDiskFreeSpaceW")
}

/// `DWORD GetLogicalDriveStringsW(DWORD, LPWSTR)` — report `C:\`.
pub fn handle_get_logical_drive_strings_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let n_buffer = low_u32(engine.read_rcx()?, "GetLogicalDriveStringsW nBufferLength")?;
    let buffer = engine.read_rdx()?;
    if buffer == 0 || n_buffer == 0 || n_buffer < LOGICAL_DRIVE_TCHARS {
        return ret_u64(
            engine,
            u64::from(LOGICAL_DRIVE_TCHARS),
            "GetLogicalDriveStringsW",
        );
    }
    // C : \ \0 + extra terminator WCHAR
    let bytes: [u8; 10] = [
        0x43, 0x00, // C
        0x3A, 0x00, // :
        0x5C, 0x00, // \
        0x00, 0x00, // NUL
        0x00, 0x00, // final NUL
    ];
    engine
        .mem_write(buffer, &bytes)
        .context("GetLogicalDriveStringsW write")?;
    ret_u64(
        engine,
        u64::from(LOGICAL_DRIVE_TCHARS),
        "GetLogicalDriveStringsW",
    )
}

/// `BOOL SetFileAttributesW(LPCWSTR, DWORD)`.
pub fn handle_set_file_attributes_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _path = engine.read_rcx()?;
    let _attrs = engine.read_rdx()?;
    // Best-effort success (VFS does not track Win32 attributes yet).
    ret_bool_true(engine, "SetFileAttributesW")
}

/// `BOOL SetFileTime(HANDLE, const FILETIME*, const FILETIME*, const FILETIME*)`.
pub fn handle_set_file_time(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _handle = engine.read_rcx()?;
    let _creation = engine.read_rdx()?;
    let _access = engine.read_r8()?;
    let _write = engine.read_r9()?;
    ret_bool_true(engine, "SetFileTime")
}

/// Minimal `FormatMessageW` — empty string / return 0 for now.
pub fn handle_format_message_w(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _flags = engine.read_rcx()?;
    let _source = engine.read_rdx()?;
    let _message_id = engine.read_r8()?;
    let _language_id = engine.read_r9()?;
    // Buffer args ignored; report 0 characters written.
    ret_u64(engine, 0, "FormatMessageW")
}

/// `DWORD ResumeThread(HANDLE)` — start a `CREATE_SUSPENDED` worker.
pub fn handle_resume_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    // Previous suspend count: 1 if we had it suspended, 0 if already running, -1 on error.
    if let Some(spawn) = state.sync.suspended_spawns.remove(&handle) {
        state.sync.pending_spawns.push(spawn);
        state.last_error = 0;
        return ret_u64(engine, 1, "ResumeThread");
    }
    if state.sync.thread_by_handle(handle).is_some() {
        // Already running (or finished) — suspend count was 0.
        state.last_error = 0;
        return ret_u64(engine, 0, "ResumeThread");
    }
    state.last_error = ERROR_INVALID_HANDLE;
    // `(DWORD)-1`
    ret_u64(engine, u64::from(u32::MAX), "ResumeThread")
}

/// `HANDLE CreateSemaphoreA/W(...)` — counting semaphore waitable.
pub fn handle_create_semaphore(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _attrs = engine.read_rcx()?;
    let initial_raw = engine.read_rdx()?;
    let maximum_raw = engine.read_r8()?;
    let _name = engine.read_r9()?; // named: ignore (anonymous only)
    let initial = i32::from_le_bytes(
        u32::try_from(initial_raw & 0xffff_ffff)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    let maximum = i32::from_le_bytes(
        u32::try_from(maximum_raw & 0xffff_ffff)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    if maximum <= 0 || initial < 0 || initial > maximum {
        state.last_error = ERROR_INVALID_PARAMETER;
        return ret_u64(engine, 0, "CreateSemaphore");
    }
    let (handle, _) = state.sync.register_semaphore(initial, maximum);
    state.last_error = 0;
    ret_u64(engine, handle, "CreateSemaphore")
}

/// `BOOL ReleaseSemaphore(HANDLE, LONG, LPLONG)`.
pub fn handle_release_semaphore(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let release_raw = engine.read_rdx()?;
    let prev_out = engine.read_r8()?;
    let release = i32::from_le_bytes(
        u32::try_from(release_raw & 0xffff_ffff)
            .unwrap_or(0)
            .to_le_bytes(),
    );
    let Some(crate::KernelObject::Semaphore(sem)) = state.sync.object(handle).cloned() else {
        state.last_error = ERROR_INVALID_HANDLE;
        return ret_u64(engine, 0, "ReleaseSemaphore");
    };
    if let Some(prev) = sem.release(release) {
        if prev_out != 0 {
            let prev_u = u32::from_ne_bytes(prev.to_ne_bytes());
            write_guest_u32(engine, prev_out, prev_u)?;
        }
        state.last_error = 0;
        ret_u64(engine, 1, "ReleaseSemaphore")
    } else {
        state.last_error = ERROR_TOO_MANY_POSTS;
        ret_u64(engine, 0, "ReleaseSemaphore")
    }
}

/// `HANDLE OpenEventW(DWORD, BOOL, LPCWSTR)`.
pub fn handle_open_event(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _access = engine.read_rcx()?;
    let _inherit = engine.read_rdx()?;
    let _name = engine.read_r9().or_else(|_| engine.read_r8())?;
    // Named events not supported yet.
    state.last_error = ERROR_FILE_NOT_FOUND;
    ret_u64(engine, 0, "OpenEventW")
}

/// `DWORD WaitForMultipleObjects(...)` — wait-all / any on kernel waitables.
pub fn handle_wait_for_multiple_objects(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let count = low_u32(engine.read_rcx()?, "WaitForMultipleObjects count")?;
    let handles_ptr = engine.read_rdx()?;
    let wait_all = (engine.read_r8()? & 0xffff_ffff) != 0;
    let timeout_raw = engine.read_r9()?;
    let timeout_ms = u32::try_from(timeout_raw & u64::from(u32::MAX)).unwrap_or(0);

    let count_usize = usize::try_from(count).unwrap_or(usize::MAX);
    if count == 0 || handles_ptr == 0 || count_usize > crate::MAXIMUM_WAIT_OBJECTS {
        state.last_error = ERROR_INVALID_PARAMETER;
        return ret_u64(
            engine,
            u64::from(crate::WAIT_FAILED),
            "WaitForMultipleObjects",
        );
    }

    let mut handles = Vec::with_capacity(count_usize);
    for i in 0..count {
        let ha = handles_ptr.wrapping_add(u64::from(i).wrapping_mul(8));
        handles.push(read_guest_u64(engine, ha)?);
    }

    // Fast path: already satisfied (no host park).
    if let Some(targets) = state.sync.wait_targets(&handles) {
        let result = crate::wait_multiple(&targets, wait_all, 0);
        if result != crate::WAIT_TIMEOUT {
            state.last_error = 0;
            return ret_u64(engine, u64::from(result), "WaitForMultipleObjects");
        }
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        return ret_u64(
            engine,
            u64::from(crate::WAIT_FAILED),
            "WaitForMultipleObjects",
        );
    }

    if timeout_ms == 0 {
        state.last_error = 0;
        return ret_u64(
            engine,
            u64::from(crate::WAIT_TIMEOUT),
            "WaitForMultipleObjects",
        );
    }

    // Stash args per waiter TID; HostPark reason stays small/Copy.
    let waiter = state.threads.current_tid();
    state.sync.multi_wait.insert(
        waiter,
        crate::sync_obj::MultiWaitRequest {
            handles,
            wait_all,
            timeout_ms,
        },
    );
    Err(crate::WinApiControlSignal::HostPark {
        reason: crate::HostParkReason::WaitMultiple,
    }
    .into())
}

/// `BOOL MoveFileWithProgressW` — alias MoveFileW semantics.
pub fn handle_move_file_with_progress_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    // Same first two args as MoveFileW (existing/new).
    handle_move_file_w(engine, state)
}

/// `BOOL CreateHardLinkW` — not supported; return FALSE.
pub fn handle_create_hard_link_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _ = (engine.read_rcx()?, engine.read_rdx()?, engine.read_r8()?);
    state.last_error = 1; // ERROR_INVALID_FUNCTION-ish
    ret_u64(engine, 0, "CreateHardLinkW")
}

/// `HANDLE FindFirstStreamW` — no alternate streams.
pub fn handle_find_first_stream_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _ = (engine.read_rcx()?, engine.read_rdx()?, engine.read_r8()?);
    state.last_error = 38; // ERROR_HANDLE_EOF
    ret_u64(engine, u64::MAX, "FindFirstStreamW") // INVALID_HANDLE_VALUE
}

/// `BOOL FindNextStreamW`.
pub fn handle_find_next_stream_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _ = (engine.read_rcx()?, engine.read_rdx()?);
    state.last_error = 38;
    ret_u64(engine, 0, "FindNextStreamW")
}

/// `BOOL DeviceIoControl` — unsupported; return FALSE.
pub fn handle_device_io_control(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _ = (
        engine.read_rcx()?,
        engine.read_rdx()?,
        engine.read_r8()?,
        engine.read_r9()?,
    );
    state.last_error = 1;
    ret_u64(engine, 0, "DeviceIoControl")
}

/// `LPVOID MapViewOfFile` — not supported yet.
pub fn handle_map_view_of_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _ = (
        engine.read_rcx()?,
        engine.read_rdx()?,
        engine.read_r8()?,
        engine.read_r9()?,
    );
    state.last_error = 8; // ERROR_NOT_ENOUGH_MEMORY
    ret_u64(engine, 0, "MapViewOfFile")
}

/// `BOOL UnmapViewOfFile`.
pub fn handle_unmap_view_of_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _base = engine.read_rcx()?;
    ret_bool_true(engine, "UnmapViewOfFile")
}

/// `HANDLE OpenFileMappingW` — not found.
pub fn handle_open_file_mapping(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _ = (engine.read_rcx()?, engine.read_rdx()?, engine.read_r8()?);
    state.last_error = 2; // ERROR_FILE_NOT_FOUND
    ret_u64(engine, 0, "OpenFileMapping")
}

/// Extra KERNEL32 exports used by CRT / modern PE (not yet in dense WinApiId table).
pub fn dispatch_kernel32_extra(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &mut WinApiState,
    name: &str,
) -> Result<Option<WinApiHandlerResult>> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "virtualalloc" => Ok(Some(handle_virtual_alloc(engine, state)?)),
        "virtualfree" => Ok(Some(handle_virtual_free(engine, state)?)),
        "virtualprotect" => Ok(Some(handle_virtual_protect(engine, state)?)),
        "virtualquery" => Ok(Some(handle_virtual_query(engine, state)?)),
        "flushinstructioncache" => Ok(Some(handle_flush_instruction_cache(engine, state)?)),
        "tlsgetvalue" => Ok(Some(handle_tls_get_value(engine, state)?)),
        "tlssetvalue" => Ok(Some(handle_tls_set_value(engine, state)?)),
        "tlsalloc" => Ok(Some(handle_tls_alloc(engine, state)?)),
        "tlsfree" => Ok(Some(handle_tls_free(engine, state)?)),
        // MT.2 / MT.3
        "createthread" => Ok(Some(handle_create_thread(engine, state)?)),
        "exitthread" => Ok(Some(handle_exit_thread(engine, state)?)),
        "getexitcodethread" => Ok(Some(handle_get_exit_code_thread(engine, state)?)),
        "waitforsingleobject" => Ok(Some(handle_wait_for_single_object(engine, state)?)),
        "createeventa" | "createeventw" => Ok(Some(handle_create_event(engine, state)?)),
        "setevent" => Ok(Some(handle_set_event(engine, state)?)),
        "resetevent" => Ok(Some(handle_reset_event(engine, state)?)),
        "getcurrentthread" => Ok(Some(handle_get_current_thread(engine)?)),
        // MT.4 Interlocked* (host atomics on soft-translated guest memory)
        "interlockedincrement" => Ok(Some(handle_interlocked_increment(engine)?)),
        "interlockeddecrement" => Ok(Some(handle_interlocked_decrement(engine)?)),
        "interlockedexchange" => Ok(Some(handle_interlocked_exchange(engine)?)),
        "interlockedcompareexchange" => Ok(Some(handle_interlocked_compare_exchange(engine)?)),
        "interlockedexchangeadd" => Ok(Some(handle_interlocked_exchange_add(engine)?)),
        "interlockedincrement64" => Ok(Some(handle_interlocked_increment64(engine)?)),
        "interlockeddecrement64" => Ok(Some(handle_interlocked_decrement64(engine)?)),
        "interlockedexchange64" => Ok(Some(handle_interlocked_exchange64(engine)?)),
        "interlockedcompareexchange64" => Ok(Some(handle_interlocked_compare_exchange64(engine)?)),
        "interlockedexchangeadd64" => Ok(Some(handle_interlocked_exchange_add64(engine)?)),
        // Real-tool surface (7z / CRT-linked PE)
        "getversion" => Ok(Some(handle_get_version(engine)?)),
        "getmodulehandlew" => Ok(Some(handle_get_module_handle_w(
            engine,
            environment,
            state,
        )?)),
        "lstrlenw" => Ok(Some(handle_lstrlen_w(engine)?)),
        "lstrcpyw" => Ok(Some(handle_lstrcpy_w(engine)?)),
        "lstrcatw" => Ok(Some(handle_lstrcat_w(engine)?)),
        // Console / process identity (7za CLI startup)
        "setconsolectrlhandler" => Ok(Some(handle_set_console_ctrl_handler(engine)?)),
        "getconsolemode" => Ok(Some(handle_get_console_mode(engine)?)),
        "setconsolemode" => Ok(Some(handle_set_console_mode(engine)?)),
        "getconsolescreenbufferinfo" => Ok(Some(handle_get_console_screen_buffer_info(engine)?)),
        "setfileapistooem" => Ok(Some(handle_set_file_apis_to_oem(engine)?)),
        "queryperformancefrequency" => Ok(Some(handle_query_performance_frequency(engine)?)),
        "getsysteminfo" => Ok(Some(handle_get_system_info(engine)?)),
        "isprocessorfeaturepresent" => Ok(Some(handle_is_processor_feature_present(engine)?)),
        "globalmemorystatusex" => Ok(Some(handle_global_memory_status_ex(engine)?)),
        "getprocesstimes" => Ok(Some(handle_get_process_times(engine)?)),
        "getlargepageminimum" => Ok(Some(handle_get_large_page_minimum(engine)?)),
        "getprocessaffinitymask" => Ok(Some(handle_get_process_affinity_mask(engine)?)),
        "setprocessaffinitymask" => Ok(Some(handle_set_process_affinity_mask(engine)?)),
        "setthreadaffinitymask" => Ok(Some(handle_set_thread_affinity_mask(engine)?)),
        "comparefiletime" => Ok(Some(handle_compare_file_time(engine)?)),
        "localfiletimetofiletime" => Ok(Some(handle_local_file_time_to_file_time(engine)?)),
        "filetimetodosdatetime" => Ok(Some(handle_file_time_to_dos_date_time(engine)?)),
        "dosdatetimetofiletime" => Ok(Some(handle_dos_date_time_to_file_time(engine)?)),
        "getdiskfreespaceexw" => Ok(Some(handle_get_disk_free_space_ex_w(engine, state)?)),
        "getdiskfreespacew" => Ok(Some(handle_get_disk_free_space_w(engine, state)?)),
        "getlogicaldrivestringsw" => Ok(Some(handle_get_logical_drive_strings_w(engine)?)),
        "setfileattributesw" => Ok(Some(handle_set_file_attributes_w(engine, state)?)),
        "setfiletime" => Ok(Some(handle_set_file_time(engine, state)?)),
        "formatmessagew" => Ok(Some(handle_format_message_w(engine)?)),
        "resumethread" => Ok(Some(handle_resume_thread(engine, state)?)),
        "createsemaphorew" | "createsemaphorea" => {
            Ok(Some(handle_create_semaphore(engine, state)?))
        }
        "releasesemaphore" => Ok(Some(handle_release_semaphore(engine, state)?)),
        "openeventw" | "openeventa" => Ok(Some(handle_open_event(engine, state)?)),
        "waitformultipleobjects" => Ok(Some(handle_wait_for_multiple_objects(engine, state)?)),
        "movefilewithprogressw" => Ok(Some(handle_move_file_with_progress_w(engine, state)?)),
        "createhardlinkw" => Ok(Some(handle_create_hard_link_w(engine, state)?)),
        "duplicatehandle" => Ok(Some(handle_duplicate_handle(engine, state)?)),
        "getthreadpriority" => Ok(Some(handle_get_thread_priority(engine, state)?)),
        "raiseexception" => Ok(Some(handle_raise_exception(engine, state)?)),
        "rtlcapturecontext" => Ok(Some(handle_rtl_capture_context(engine, state)?)),
        "rtlunwindex" => Ok(Some(handle_rtl_unwind_ex(engine, state)?)),
        "findfirststreamw" => Ok(Some(handle_find_first_stream_w(engine, state)?)),
        "findnextstreamw" => Ok(Some(handle_find_next_stream_w(engine, state)?)),
        "deviceiocontrol" => Ok(Some(handle_device_io_control(engine, state)?)),
        "mapviewoffile" => Ok(Some(handle_map_view_of_file(engine, state)?)),
        "unmapviewoffile" => Ok(Some(handle_unmap_view_of_file(engine, state)?)),
        "openfilemappingw" | "openfilemappinga" => {
            Ok(Some(handle_open_file_mapping(engine, state)?))
        }
        _ => Ok(None),
    }
}

/// Default worker stack size when `dwStackSize == 0`.
///
/// Matches the common Windows default commit size (1 MiB) rather than a tiny
/// micro-test stack — real PE tools (compressors, CRT workers) need room.
const DEFAULT_WORKER_STACK: usize = 0x10_0000;
/// Guest VA region for worker stacks (distinct from primary stack at 0x2000_0000).
const WORKER_STACK_REGION_BASE: u64 = 0x0000_0000_2200_0000;
const WORKER_STACK_STRIDE: u64 = 0x0000_0000_0020_0000;

const CREATE_SUSPENDED: u32 = 0x4;
const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;

/// Default max guest worker threads (`CreateThread`), overridable by env.
const DEFAULT_MT_MAX_THREADS: u32 = 64;

/// `WIE_MT=0` kills multi-thread spawn (ST-only). Unset / other = enabled.
fn mt_create_thread_enabled() -> bool {
    !matches!(
        std::env::var("WIE_MT"),
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off")
    )
}

/// Cap on live + pending worker TIDs (`WIE_MT_MAX_THREADS`, default 64).
fn mt_max_worker_threads() -> u32 {
    std::env::var("WIE_MT_MAX_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_MT_MAX_THREADS)
}

// ─── MT.4 Interlocked* (host atomics on soft-translated memory) ─────────────

/// Truncate a Win64 register operand to signed LONG (low 32 bits).
#[inline]
fn trunc_i32(reg: u64) -> i32 {
    i32::from_le_bytes(u32::try_from(reg & 0xffff_ffff).unwrap_or(0).to_le_bytes())
}

/// Sign-extend LONG result into RAX (Windows x64 calling convention for LONG).
#[inline]
fn i32_to_rax(v: i32) -> u64 {
    // Preserve full sign-extended bit pattern in the 64-bit register.
    u64::from_le_bytes(i64::from(v).to_le_bytes())
}

/// Bitcast i64 result into RAX.
#[inline]
fn i64_to_rax(v: i64) -> u64 {
    u64::from_le_bytes(v.to_le_bytes())
}

/// Perform an aligned `i32` RMW via host `AtomicI32` when soft-translate works;
/// otherwise fall back to non-atomic mem_read/mem_write (correct under process
/// engine lock; still used for unaligned / non-span cases).
fn interlocked_i32(
    engine: &mut dyn wie_cpu::CpuEngine,
    addr: u64,
    op: impl FnOnce(&std::sync::atomic::AtomicI32) -> i32,
    slow: impl FnOnce(i32) -> i32,
) -> Result<i32> {
    if addr == 0 {
        anyhow::bail!("Interlocked* null destination");
    }
    // Fast path: 4-byte aligned host span → true host atomic (ARM LDXR/STXR).
    if addr.is_multiple_of(4)
        && let Some(host) = engine.host_span(addr, 4, true)
    {
        // SAFETY: host_span checked SPC+arena; guest VA alignment implies host
        // alignment for soft-translate (offset preserved). Pointer lives while
        // GuestMemory (engine) is borrowed exclusively here.
        #[expect(unsafe_code, clippy::cast_ptr_alignment)]
        let atom = unsafe { &*(host.cast::<std::sync::atomic::AtomicI32>()) };
        return Ok(op(atom));
    }
    // Slow path: emulate via ordinary guest load/store.
    let mut bytes = [0_u8; 4];
    engine
        .mem_read(addr, &mut bytes)
        .context("Interlocked* slow-path read")?;
    let old = i32::from_le_bytes(bytes);
    let new = slow(old);
    engine
        .mem_write(addr, &new.to_le_bytes())
        .context("Interlocked* slow-path write")?;
    Ok(new)
}

/// Like [`interlocked_i32`] but the return value may be the *previous* value
/// (Exchange / ExchangeAdd / CompareExchange).
fn interlocked_i32_prev(
    engine: &mut dyn wie_cpu::CpuEngine,
    addr: u64,
    op: impl FnOnce(&std::sync::atomic::AtomicI32) -> i32,
    slow: impl FnOnce(i32) -> (i32 /*prev*/, i32 /*new*/),
) -> Result<i32> {
    if addr == 0 {
        anyhow::bail!("Interlocked* null destination");
    }
    if addr.is_multiple_of(4)
        && let Some(host) = engine.host_span(addr, 4, true)
    {
        #[expect(unsafe_code, clippy::cast_ptr_alignment)]
        let atom = unsafe { &*(host.cast::<std::sync::atomic::AtomicI32>()) };
        return Ok(op(atom));
    }
    let mut bytes = [0_u8; 4];
    engine
        .mem_read(addr, &mut bytes)
        .context("Interlocked* slow-path read")?;
    let old = i32::from_le_bytes(bytes);
    let (prev, new) = slow(old);
    engine
        .mem_write(addr, &new.to_le_bytes())
        .context("Interlocked* slow-path write")?;
    Ok(prev)
}

fn interlocked_i64(
    engine: &mut dyn wie_cpu::CpuEngine,
    addr: u64,
    op: impl FnOnce(&std::sync::atomic::AtomicI64) -> i64,
    slow: impl FnOnce(i64) -> i64,
) -> Result<i64> {
    if addr == 0 {
        anyhow::bail!("Interlocked*64 null destination");
    }
    if addr.is_multiple_of(8)
        && let Some(host) = engine.host_span(addr, 8, true)
    {
        #[expect(unsafe_code, clippy::cast_ptr_alignment)]
        let atom = unsafe { &*(host.cast::<std::sync::atomic::AtomicI64>()) };
        return Ok(op(atom));
    }
    let mut bytes = [0_u8; 8];
    engine
        .mem_read(addr, &mut bytes)
        .context("Interlocked*64 slow-path read")?;
    let old = i64::from_le_bytes(bytes);
    let new = slow(old);
    engine
        .mem_write(addr, &new.to_le_bytes())
        .context("Interlocked*64 slow-path write")?;
    Ok(new)
}

fn interlocked_i64_prev(
    engine: &mut dyn wie_cpu::CpuEngine,
    addr: u64,
    op: impl FnOnce(&std::sync::atomic::AtomicI64) -> i64,
    slow: impl FnOnce(i64) -> (i64, i64),
) -> Result<i64> {
    if addr == 0 {
        anyhow::bail!("Interlocked*64 null destination");
    }
    if addr.is_multiple_of(8)
        && let Some(host) = engine.host_span(addr, 8, true)
    {
        #[expect(unsafe_code, clippy::cast_ptr_alignment)]
        let atom = unsafe { &*(host.cast::<std::sync::atomic::AtomicI64>()) };
        return Ok(op(atom));
    }
    let mut bytes = [0_u8; 8];
    engine
        .mem_read(addr, &mut bytes)
        .context("Interlocked*64 slow-path read")?;
    let old = i64::from_le_bytes(bytes);
    let (prev, new) = slow(old);
    engine
        .mem_write(addr, &new.to_le_bytes())
        .context("Interlocked*64 slow-path write")?;
    Ok(prev)
}

/// `InterlockedIncrement` — returns **new** value (Microsoft Learn).
fn handle_interlocked_increment(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx().context("InterlockedIncrement RCX")?;
    let new = interlocked_i32(
        engine,
        addr,
        |a| a.fetch_add(1, Ordering::SeqCst).wrapping_add(1),
        |old| old.wrapping_add(1),
    )?;
    let return_address = engine.return_from_win64_api(i32_to_rax(new))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i32_to_rax(new),
    })
}

/// `InterlockedDecrement` — returns **new** value.
fn handle_interlocked_decrement(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx().context("InterlockedDecrement RCX")?;
    let new = interlocked_i32(
        engine,
        addr,
        |a| a.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1),
        |old| old.wrapping_sub(1),
    )?;
    let return_address = engine.return_from_win64_api(i32_to_rax(new))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i32_to_rax(new),
    })
}

/// `InterlockedExchange` — returns **previous** value.
fn handle_interlocked_exchange(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx().context("InterlockedExchange RCX")?;
    // RDX carries the new LONG (low 32 bits).
    let value = trunc_i32(engine.read_rdx()?);
    let prev = interlocked_i32_prev(
        engine,
        addr,
        |a| a.swap(value, Ordering::SeqCst),
        |old| (old, value),
    )?;
    let return_address = engine.return_from_win64_api(i32_to_rax(prev))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i32_to_rax(prev),
    })
}

/// `InterlockedCompareExchange(dest, exchange, comparand)` — returns previous.
///
/// Win64: RCX=dest, RDX=exchange, R8=comparand.
fn handle_interlocked_compare_exchange(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx()?;
    let exchange = trunc_i32(engine.read_rdx()?);
    let comparand = trunc_i32(engine.read_r8()?);
    let prev = interlocked_i32_prev(
        engine,
        addr,
        |a| match a.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(v) | Err(v) => v,
        },
        |old| {
            if old == comparand {
                (old, exchange)
            } else {
                (old, old)
            }
        },
    )?;
    let return_address = engine.return_from_win64_api(i32_to_rax(prev))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i32_to_rax(prev),
    })
}

/// `InterlockedExchangeAdd` — returns **previous** value.
fn handle_interlocked_exchange_add(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx()?;
    let addend = trunc_i32(engine.read_rdx()?);
    let prev = interlocked_i32_prev(
        engine,
        addr,
        |a| a.fetch_add(addend, Ordering::SeqCst),
        |old| (old, old.wrapping_add(addend)),
    )?;
    let return_address = engine.return_from_win64_api(i32_to_rax(prev))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i32_to_rax(prev),
    })
}

fn handle_interlocked_increment64(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx()?;
    let new = interlocked_i64(
        engine,
        addr,
        |a| a.fetch_add(1, Ordering::SeqCst).wrapping_add(1),
        |old| old.wrapping_add(1),
    )?;
    let return_address = engine.return_from_win64_api(i64_to_rax(new))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i64_to_rax(new),
    })
}

fn handle_interlocked_decrement64(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx()?;
    let new = interlocked_i64(
        engine,
        addr,
        |a| a.fetch_sub(1, Ordering::SeqCst).wrapping_sub(1),
        |old| old.wrapping_sub(1),
    )?;
    let return_address = engine.return_from_win64_api(i64_to_rax(new))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i64_to_rax(new),
    })
}

fn handle_interlocked_exchange64(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx()?;
    let value = i64::from_le_bytes(engine.read_rdx()?.to_le_bytes());
    let prev = interlocked_i64_prev(
        engine,
        addr,
        |a| a.swap(value, Ordering::SeqCst),
        |old| (old, value),
    )?;
    let return_address = engine.return_from_win64_api(i64_to_rax(prev))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i64_to_rax(prev),
    })
}

/// `InterlockedCompareExchange64(dest, exchange, comparand)`.
///
/// Win64: RCX=dest, RDX=exchange, R8=comparand (all 64-bit).
fn handle_interlocked_compare_exchange64(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx()?;
    let exchange = i64::from_le_bytes(engine.read_rdx()?.to_le_bytes());
    let comparand = i64::from_le_bytes(engine.read_r8()?.to_le_bytes());
    let prev = interlocked_i64_prev(
        engine,
        addr,
        |a| match a.compare_exchange(comparand, exchange, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(v) | Err(v) => v,
        },
        |old| {
            if old == comparand {
                (old, exchange)
            } else {
                (old, old)
            }
        },
    )?;
    let return_address = engine.return_from_win64_api(i64_to_rax(prev))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i64_to_rax(prev),
    })
}

fn handle_interlocked_exchange_add64(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    use std::sync::atomic::Ordering;
    let addr = engine.read_rcx()?;
    let addend = i64::from_le_bytes(engine.read_rdx()?.to_le_bytes());
    let prev = interlocked_i64_prev(
        engine,
        addr,
        |a| a.fetch_add(addend, Ordering::SeqCst),
        |old| (old, old.wrapping_add(addend)),
    )?;
    let return_address = engine.return_from_win64_api(i64_to_rax(prev))?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: i64_to_rax(prev),
    })
}

/// `CreateThread` — allocate stack/TID/handle and queue a host spawn (MT.2).
fn handle_create_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _security = engine.read_rcx()?;
    let stack_size_raw = engine.read_rdx()?;
    let start = engine.read_r8()?;
    let param = engine.read_r9()?;
    let flags = read_create_file_stack_u32(engine, 0x28).unwrap_or(0);
    let tid_out = read_stack_u64(engine, 0x30).unwrap_or(0);

    let handle = create_guest_thread(engine, state, stack_size_raw, start, param, flags, tid_out)?;
    let return_address = engine.return_from_win64_api(handle)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// Shared guest-thread spawn for `CreateThread` and CRT `_beginthreadex`.
///
/// Returns the kernel handle, or `0` with `state.last_error` set on failure.
/// Does **not** pop the Win64 API frame (caller completes the return).
pub fn create_guest_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    stack_size_raw: u64,
    start: u64,
    param: u64,
    flags: u32,
    tid_out: u64,
) -> Result<u64> {
    if !mt_create_thread_enabled() {
        state.last_error = ERROR_NOT_SUPPORTED_MT;
        return Ok(0);
    }

    if start == 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        return Ok(0);
    }

    // Cap workers: by_tid includes primary; count pending + suspended too.
    let live_workers = state
        .threads
        .by_tid
        .len()
        .saturating_sub(1)
        .saturating_add(state.sync.pending_spawns.len())
        .saturating_add(state.sync.suspended_spawns.len());
    let max = usize::try_from(mt_max_worker_threads()).unwrap_or(64);
    if live_workers >= max {
        state.last_error = ERROR_NOT_ENOUGH_MEMORY;
        return Ok(0);
    }

    let stack_size = if stack_size_raw == 0 {
        DEFAULT_WORKER_STACK
    } else {
        usize::try_from(stack_size_raw).unwrap_or(DEFAULT_WORKER_STACK)
    };
    // Align up to page.
    let stack_size = stack_size.saturating_add(0xfff) & !0xfff;
    let stack_size = stack_size.max(0x1000);

    let slot = state.sync.next_stack_slot;
    state.sync.next_stack_slot = slot.saturating_add(1);
    let stack_base = WORKER_STACK_REGION_BASE
        .saturating_add(u64::from(slot).saturating_mul(WORKER_STACK_STRIDE));

    let alloc = engine.virtual_alloc(
        stack_base,
        stack_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    );
    let stack_base = if let Ok(va) = alloc {
        va
    } else {
        // Fallback: map with mem_map if VirtualAlloc path rejects fixed VA.
        if engine
            .mem_map(
                stack_base,
                stack_size,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .is_err()
        {
            state.last_error = ERROR_NOT_ENOUGH_MEMORY;
            return Ok(0);
        }
        stack_base
    };

    let stack_top = stack_base.saturating_add(u64::try_from(stack_size).unwrap_or(0));
    let aligned_top = stack_top & !0xF_u64;
    // At ThreadProc entry: [RSP]=retaddr, RSP%16==8 (as after CALL).
    // Retaddr 0 → worker loop treats RIP=0 as natural exit (exit code from RAX).
    let entry_rsp = aligned_top.saturating_sub(8);
    drop(engine.mem_write(entry_rsp, &0_u64.to_le_bytes()));

    let tid = state.threads.alloc_worker();
    let mut ctx = wie_cpu::ThreadContext::new();
    // RCX = lpParameter, RSP = entry, RIP = start
    if let Some(slot) = ctx.gpr.get_mut(1) {
        *slot = param;
    }
    if let Some(slot) = ctx.gpr.get_mut(4) {
        *slot = entry_rsp;
    }
    ctx.rip = start;

    let (handle, _obj) = state.sync.register_thread(tid, ctx);
    let spawn = crate::PendingSpawn {
        tid,
        handle,
        start_address: start,
        parameter: param,
        stack_base,
        stack_size,
    };
    if (flags & CREATE_SUSPENDED) != 0 {
        state.sync.suspended_spawns.insert(handle, spawn);
    } else {
        state.sync.pending_spawns.push(spawn);
    }

    if tid_out != 0 {
        drop(engine.mem_write(tid_out, &tid.to_le_bytes()));
    }

    state.last_error = 0;
    Ok(handle)
}

const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// `ERROR_NOT_SUPPORTED` — used when `WIE_MT=0` refuses `CreateThread`.
const ERROR_NOT_SUPPORTED_MT: u32 = 50;
/// `ERROR_TOO_MANY_POSTS` — semaphore release would exceed maximum.
const ERROR_TOO_MANY_POSTS: u32 = 298;

fn read_stack_u64(engine: &mut dyn wie_cpu::CpuEngine, offset: u64) -> Result<u64> {
    let rsp = engine.read_rsp()?;
    let address = rsp
        .checked_add(offset)
        .context("stack arg address overflow")?;
    let mut bytes = [0_u8; 8];
    engine.mem_read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

/// `ExitThread` — mark thread finished and signal worker loop to stop.
fn handle_exit_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let code_raw = engine.read_rcx()?;
    let code = u32::try_from(code_raw & u64::from(u32::MAX)).unwrap_or(0);
    let tid = state.threads.current_tid();
    // Find thread object by tid.
    for obj in state.sync.objects.values() {
        if let crate::KernelObject::Thread(t) = obj
            && t.tid == tid
        {
            t.finish(code);
            break;
        }
    }
    // Primary ExitThread: treat as process exit of this code for simplicity.
    if tid == crate::PRIMARY_THREAD_ID {
        // Still return control signal so runtime can tear down.
        return Err(crate::WinApiControlSignal::ExitThread { code }.into());
    }
    Err(crate::WinApiControlSignal::ExitThread { code }.into())
}

/// `GetExitCodeThread`.
fn handle_get_exit_code_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let out_ptr = engine.read_rdx()?;
    let code = if let Some(t) = state.sync.thread_by_handle(handle) {
        t.exit_code.load(std::sync::atomic::Ordering::Acquire)
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    };
    if out_ptr != 0 {
        drop(engine.mem_write(out_ptr, &code.to_le_bytes()));
    }
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(1)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// `WaitForSingleObject` — thread, event, or semaphore (MT.2/3).
fn handle_wait_for_single_object(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let timeout_raw = engine.read_rdx()?;
    let timeout_ms = u32::try_from(timeout_raw & u64::from(u32::MAX)).unwrap_or(0);

    // Fast path: already signaled — no park.
    match state.sync.object(handle) {
        Some(crate::KernelObject::Thread(t)) => {
            if t.is_finished() {
                state.last_error = 0;
                let return_address =
                    engine.return_from_win64_api(u64::from(crate::WAIT_OBJECT_0))?;
                return Ok(WinApiHandlerResult {
                    return_address,
                    return_value: u64::from(crate::WAIT_OBJECT_0),
                });
            }
        }
        Some(crate::KernelObject::Event(e)) => {
            if e.wait(0) {
                state.last_error = 0;
                let return_address =
                    engine.return_from_win64_api(u64::from(crate::WAIT_OBJECT_0))?;
                return Ok(WinApiHandlerResult {
                    return_address,
                    return_value: u64::from(crate::WAIT_OBJECT_0),
                });
            }
        }
        Some(crate::KernelObject::Semaphore(s)) => {
            if s.try_acquire() {
                state.last_error = 0;
                let return_address =
                    engine.return_from_win64_api(u64::from(crate::WAIT_OBJECT_0))?;
                return Ok(WinApiHandlerResult {
                    return_address,
                    return_value: u64::from(crate::WAIT_OBJECT_0),
                });
            }
        }
        None => {
            state.last_error = ERROR_INVALID_HANDLE;
            let return_address = engine.return_from_win64_api(u64::from(crate::WAIT_FAILED))?;
            return Ok(WinApiHandlerResult {
                return_address,
                return_value: u64::from(crate::WAIT_FAILED),
            });
        }
    }

    // Need to park host (drop CPU) then wait.
    Err(crate::WinApiControlSignal::HostPark {
        reason: crate::HostParkReason::WaitObject { handle, timeout_ms },
    }
    .into())
}

/// Resolve a waitable handle to a detachable target (wait **outside** process locks).
pub fn resolve_wait_target(
    state: &WinApiState,
    handle: u64,
) -> Option<crate::sync_obj::WaitTarget> {
    state.sync.wait_target(handle)
}

/// Clone the CS wait queue for parking **outside** process locks.
pub fn resolve_cs_queue(
    state: &mut WinApiState,
    cs: u64,
) -> std::sync::Arc<crate::sync_obj::CsWaitQueue> {
    state.sync.cs_queue(cs)
}

/// `CreateEventA/W`.
fn handle_create_event(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _security = engine.read_rcx()?;
    let manual = engine.read_rdx()? != 0;
    let initial = engine.read_r8()? != 0;
    let _name = engine.read_r9()?; // named events: ignore (anonymous only)

    let (handle, _) = state.sync.register_event(manual, initial);
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(handle)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: handle,
    })
}

/// `DuplicateHandle` — duplicate a kernel handle.
///
/// Pseudohandles (`GetCurrentProcess`, `GetCurrentThread`) are resolved to
/// real kernel object handles.  Unknown handles are rejected with
/// `ERROR_INVALID_HANDLE`.  `DUPLICATE_CLOSE_SOURCE` closes the source after
/// duplication.
fn handle_duplicate_handle(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    // RCX = hSourceProcessHandle
    // RDX = hSourceHandle
    // R8  = hTargetProcessHandle
    // R9  = lpTargetHandle (guest pointer for the duplicated handle)
    // [RSP+0x28] = dwDesiredAccess
    // [RSP+0x30] = bInheritHandle
    // [RSP+0x38] = dwOptions
    let _source_proc = engine.read_rcx()?;
    let source_handle = engine.read_rdx()?;
    let _target_proc = engine.read_r8()?;
    let target_handle_ptr = engine.read_r9()?;

    // Read dwOptions from the guest stack to honour DUPLICATE_CLOSE_SOURCE.
    let rsp = engine.read_rsp()?;
    let mut opt_bytes = [0_u8; 4];
    let close_source = if engine.mem_read(rsp.wrapping_add(0x38), &mut opt_bytes).is_ok() {
        let opts = u32::from_le_bytes(opt_bytes);
        (opts & 0x1) != 0 // DUPLICATE_CLOSE_SOURCE = 0x1
    } else {
        false
    };

    // Resolve pseudohandles to real kernel objects.
    // Windows: (HANDLE)-1 = GetCurrentProcess, (HANDLE)-2 = GetCurrentThread.
    // Both are resolved to a ThreadObject for the calling thread.  WIE does
    // not model process kernel objects — all handles map to threads.
    let tid = if source_handle == u64::MAX || source_handle == u64::MAX - 1 {
        // Pseudohandle → resolve the current TID.  For GetCurrentProcess we
        // use the primary TID since there is no process object.
        state.threads.current_tid()
    } else {
        // Real kernel handle — skip resolution, lookup directly below.
        let obj = state.sync.objects.get(&source_handle).cloned();
        if let Some(obj) = obj {
            let new_handle = state.sync.next_handle;
            state.sync.next_handle = state.sync.next_handle.wrapping_add(4);
            state.sync.objects.insert(new_handle, obj.clone());
            if close_source {
                state.sync.objects.remove(&source_handle);
            }
            engine.mem_write(target_handle_ptr, &new_handle.to_le_bytes())?;
            state.last_error = 0;
            let return_address = engine.return_from_win64_api(1)?;
            return Ok(WinApiHandlerResult {
                return_address,
                return_value: 1,
            });
        }
        state.last_error = ERROR_INVALID_HANDLE;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    };

    // Pseudohandle path: find or create the ThreadObject for `tid`.
    let source_obj = state
        .sync
        .objects
        .values()
        .find_map(|obj| match obj {
            crate::KernelObject::Thread(t) if t.tid == tid => Some(obj.clone()),
            _ => None,
        })
        .unwrap_or_else(|| {
            let (_, th) = state.sync.register_thread(tid, Default::default());
            crate::KernelObject::Thread(th)
        });

    let new_handle = state.sync.next_handle;
    state.sync.next_handle = state.sync.next_handle.wrapping_add(4);
    state.sync.objects.insert(new_handle, source_obj);

    // Honour DUPLICATE_CLOSE_SOURCE: close the source handle after duplication.
    if close_source && source_handle != u64::MAX && source_handle != u64::MAX - 1 {
        state.sync.objects.remove(&source_handle);
    }

    engine.mem_write(target_handle_ptr, &new_handle.to_le_bytes())?;
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(1)?; // TRUE
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// `GetThreadPriority` → THREAD_PRIORITY_NORMAL (0).
///
/// No priority model — all guest threads run at the same host priority.
/// Validates the handle: returns `THREAD_PRIORITY_ERROR_RETURN` with
/// `ERROR_INVALID_HANDLE` for garbage values.
fn handle_get_thread_priority(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let h_thread = engine.read_rcx()?;

    // Pseudohandle CURRENT_THREAD (-2), or a real kernel handle.
    let valid = h_thread == u64::MAX - 1 || state.sync.objects.contains_key(&h_thread);

    if !valid {
        state.last_error = ERROR_INVALID_HANDLE;
        // THREAD_PRIORITY_ERROR_RETURN = MAXLONG (0x7FFFFFFF)
        let return_address = engine.return_from_win64_api(0x7FFF_FFFF)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0x7FFF_FFFF,
        });
    }

    let return_address = engine.return_from_win64_api(0)?; // THREAD_PRIORITY_NORMAL
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// `RaiseException` — start exception processing.
///
/// Two-pass dispatch for the Itanium ABI (Mingw-w64 uses this via
/// `__gxx_personality_seh0`).  Pass 1 searches for a handler; pass 2
/// unwinds to it, running destructors along the way.
/// `RaiseException` — start exception processing.
///
/// Two-pass dispatch for the Itanium ABI (Mingw-w64 uses this via
/// `__gxx_personality_seh0`).  Pass 1 searches for a handler; pass 2
/// unwinds to it, running destructors along the way.
pub(crate) fn handle_raise_exception(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    // Itanium ABI disposition codes (Mingw-w64 personality return values).
    const URC_CONTINUE_UNWIND: u32 = 0;
    const URC_HANDLER_FOUND: u32 = 1;
    const URC_INSTALL_CONTEXT: u32 = 2;

    let exception_record_ptr = engine.read_rcx()?;

    // Snapshot current guest state.  RIP is inside the RaiseException stub.
    // The throw site is the caller — read the return address from [RSP].
    let tctx = engine.snapshot_thread_context();
    let rsp = engine.read_rsp()?;
    let mut ra_buf = [0_u8; 8];
    engine
        .mem_read(rsp, &mut ra_buf)
        .map_err(|e| anyhow::anyhow!("RaiseException: failed to read return address from stack: {e}"))?;
    let throw_rip = u64::from_le_bytes(ra_buf);
    let throw_rsp = rsp.saturating_add(8);

    let engine_ptr: *mut dyn wie_cpu::CpuEngine = engine;
    let mut read_mem = |va: u64, buf: &mut [u8]| {
        #[expect(unsafe_code)]
        unsafe { (*engine_ptr).mem_read(va, buf).map_err(|_| ()) }
    };

    // Helper: call the personality function with proper SEH ABI.
    // SEH ABI (__gxx_personality_seh0 on Mingw-w64):
    //   RCX = EXCEPTION_RECORD*
    //   RDX = EstablisherFrame
    //   R8  = CONTEXT*
    //   R9  = DISPATCHER_CONTEXT*
    // DISPATCHER_CONTEXT.HandlerData must point to the LSDA/gcc_except_table
    // for the personality to find catch handlers.
    let mut call_personality = |handler_va: u64,
                                ctx: &crate::exception::UnwindContext,
                                flags: u32,
                                handler_data: u32,
                                image_base: u64,
                                func_entry: &crate::exception::RuntimeFunction|
     -> Result<u32> {
        // Write EXCEPTION_RECORD.ExceptionFlags = flags (0 = search, 1 = unwind).
        engine.mem_write(exception_record_ptr.saturating_add(4), &flags.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write exception flags: {e}"))?;

        let saved_rsp = engine.read_rsp()?;
        let stack_frame = saved_rsp.saturating_sub(0x400);
        let exc_rec_ptr  = stack_frame;
        let ctx_ptr      = stack_frame.saturating_add(0x100);
        let func_entry_ptr = stack_frame.saturating_add(0x200);
        let disp_ctx_ptr = stack_frame.saturating_add(0x240);

        // 1. Copy EXCEPTION_RECORD to guest stack.
        let mut exc_buf = vec![0u8; 0x100];
        engine.mem_read(exception_record_ptr, &mut exc_buf)
            .map_err(|e| anyhow::anyhow!("failed to read exception record: {e}"))?;
        engine.mem_write(exc_rec_ptr, &exc_buf)
            .map_err(|e| anyhow::anyhow!("failed to write exception record: {e}"))?;

        // 2. Write CONTEXT64 at ctx_ptr (real Windows offsets).
        let mut cbuf = [0u8; 0x200];
        cbuf[0..4].copy_from_slice(&0x0010_001Fu32.to_le_bytes()); // CONTEXT_ALL
        let off = |r: usize| -> usize {
            // GPR base at 0x78 in CONTEXT64.
            0x78 + r * 8
        };
        cbuf[off(0)..off(0)+8].copy_from_slice(&ctx.gpr[0].to_le_bytes());   // Rax
        cbuf[off(3)..off(3)+8].copy_from_slice(&ctx.gpr[3].to_le_bytes());   // Rbx
        cbuf[off(4)..off(4)+8].copy_from_slice(&ctx.rsp.to_le_bytes());       // Rsp
        cbuf[off(5)..off(5)+8].copy_from_slice(&ctx.gpr[5].to_le_bytes());   // Rbp
        cbuf[off(6)..off(6)+8].copy_from_slice(&ctx.gpr[6].to_le_bytes());   // Rsi
        cbuf[off(7)..off(7)+8].copy_from_slice(&ctx.gpr[7].to_le_bytes());   // Rdi
        for r in 8..16 {
            cbuf[off(r)..off(r)+8].copy_from_slice(&ctx.gpr[r].to_le_bytes());
        }
        // Rip at offset 0xF8
        cbuf[0xF8..0x100].copy_from_slice(&ctx.rip.to_le_bytes());
        engine.mem_write(ctx_ptr, &cbuf)
            .map_err(|e| anyhow::anyhow!("failed to write context: {e}"))?;

        // 3. Write RUNTIME_FUNCTION at func_entry_ptr in guest memory.
        engine.mem_write(func_entry_ptr, &func_entry.begin_address.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write func_entry: {e}"))?;
        engine.mem_write(func_entry_ptr.saturating_add(4), &func_entry.end_address.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write func_entry: {e}"))?;
        engine.mem_write(func_entry_ptr.saturating_add(8), &func_entry.unwind_data.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write func_entry: {e}"))?;

        // 4. Write DISPATCHER_CONTEXT at disp_ctx_ptr.
        let mut dcbuf = [0u8; 0x40];
        // +0x00: ControlPc = ctx.rip
        dcbuf[0x00..0x08].copy_from_slice(&ctx.rip.to_le_bytes());
        // +0x08: ImageBase
        dcbuf[0x08..0x10].copy_from_slice(&image_base.to_le_bytes());
        // +0x10: FunctionEntry (guest pointer)
        dcbuf[0x10..0x18].copy_from_slice(&func_entry_ptr.to_le_bytes());
        // +0x18: EstablisherFrame
        dcbuf[0x18..0x20].copy_from_slice(&ctx.gpr[5].to_le_bytes()); // RBP
        // +0x20: TargetIp (filled by personality)
        // +0x28: ContextRecord
        dcbuf[0x28..0x30].copy_from_slice(&ctx_ptr.to_le_bytes());
        // +0x30: LanguageHandler
        dcbuf[0x30..0x38].copy_from_slice(&handler_va.to_le_bytes());
        // +0x38: HandlerData = guest VA of the LSDA (.gcc_except_table entry).
        let hdata_va = (image_base + 0x20000).saturating_add(u64::from(handler_data));
        dcbuf[0x38..0x40].copy_from_slice(&hdata_va.to_le_bytes());
        engine.mem_write(disp_ctx_ptr, &dcbuf)
            .map_err(|e| anyhow::anyhow!("failed to write dispatcher context: {e}"))?;

        // 5. Set registers for SEH ABI call.
        engine.write_rcx(exc_rec_ptr)?;
        engine.write_rdx(ctx.gpr[5])?;   // EstablisherFrame = RBP
        engine.write_r8(ctx_ptr)?;
        engine.write_r9(disp_ctx_ptr)?;
        // Push a fake return address in the stop bitmap range so the
        // personality can `ret` normally — run_until_stop will stop there.
        let personality_ret_va = crate::fake_va::FAKE_API_BASE;
        let call_rsp = stack_frame.saturating_sub(8);  // after-call RSP (return addr at [RSP])
        engine.mem_write(call_rsp, &personality_ret_va.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write personality return address: {e}"))?;
        engine.write_rsp(call_rsp)?;
        engine.write_rip(handler_va)?;

        engine.run_until_stop(handler_va, 0, 0, 100_000, 0, 0)
            .map_err(|e| anyhow::anyhow!("personality function failed: {e}"))?;
        engine.read_rax().map(|v| v as u32)
            .map_err(|e| anyhow::anyhow!("failed to read personality disposition: {e}"))
    };

    // ── Pass 1: search for a handler ──────────────────────────────────
    let mut ctx = crate::exception::UnwindContext {
        rip: throw_rip,
        rsp: throw_rsp,
        gpr: tctx.gpr,
        xmm: tctx.xmm,
    };

    // Diagnostic: report table coverage.
    let table_count = state.sync.function_tables.len();
    let total_entries: usize = state.sync.function_tables.values().map(|v| v.len()).sum();
    tracing::info!(tables = table_count, entries = total_entries, throw_rip = format_args!("{:#x}", throw_rip), "RaiseException dispatch");

    let mut handler_found: Option<(u64, u32, u64, crate::exception::RuntimeFunction, crate::exception::UnwindContext)> = None;

    tracing::info!(pass = 1, throw_rip = format_args!("{:#x}", throw_rip), "starting search pass");
    for _frame in 0..64 {
        let entry = match crate::exception::lookup_function_entry(&state.sync, ctx.rip) {
            Some(e) => e,
            None => {
                let mut rip_buf = [0u8; 8];
                if read_mem(ctx.rsp, &mut rip_buf).is_err() {
                    tracing::warn!(pass = 1, frame = _frame, rip = format_args!("{:#x}", ctx.rip), rsp = format_args!("{:#x}", ctx.rsp), "blind unwind: failed to read return address");
                    break;
                }
                let blind_rip = u64::from_le_bytes(rip_buf);
                tracing::info!(pass = 1, frame = _frame, from_rip = format_args!("{:#x}", ctx.rip), to_rip = format_args!("{:#x}", blind_rip), rsp = format_args!("{:#x}", ctx.rsp), "blind unwind");
                ctx.rip = blind_rip;
                ctx.rsp = ctx.rsp.saturating_add(8);
                continue;
            }
        };
        let result = match crate::exception::virtual_unwind(&mut read_mem, entry.image_base, entry.entry, ctx) {
            Ok(r) => r, Err(_) => break,
        };
        tracing::info!(
            frame = _frame,
            rip = format_args!("{:#x}", ctx.rip),
            caller_rip = format_args!("{:#x}", result.ctx.rip),
            has_handler = result.handler_rva.is_some(),
            handler = result.handler_rva.map_or(0, |h| h),
            "search pass frame"
        );
        if let (Some(handler_rva), Some(handler_data)) = (result.handler_rva, result.handler_data) {
            let handler_va = entry.image_base.saturating_add(u64::from(handler_rva));
            tracing::info!(frame = _frame, handler_va = format_args!("{:#x}", handler_va), handler_data = format_args!("{:#x}", handler_data), "calling personality");
            let disp = call_personality(handler_va, &ctx, 0, handler_data, entry.image_base, entry.entry);
            tracing::info!(frame = _frame, disposition = ?disp, "personality search result");
            match disp {
                Ok(URC_HANDLER_FOUND) => {
                    handler_found = Some((handler_va, handler_data, entry.image_base, *entry.entry, ctx));
                    break;
                }
                Ok(URC_CONTINUE_UNWIND) => { /* keep searching */ }
                Err(e) => { anyhow::bail!("personality error during search: {e}"); }
                _ => { break; }
            }
        }
        ctx = result.ctx;
    }

    let Some((handler_va, handler_data, image_base, func_entry, catch_ctx)) = handler_found else {
        anyhow::bail!("RaiseException: no handler found (throw_rip={:#x})", throw_rip);
    };

    // ── Pass 2: unwind to the handler (run destructors) ───────────────
    let mut ctx2 = crate::exception::UnwindContext {
        rip: throw_rip,
        rsp: throw_rsp,
        gpr: tctx.gpr,
        xmm: tctx.xmm,
    };
    tracing::info!(
        pass = 2,
        catch_rip = format_args!("{:#x}", catch_ctx.rip),
        "starting unwind pass"
    );
    for _frame in 0..64 {
        tracing::info!(pass = 2, frame = _frame, rip = format_args!("{:#x}", ctx2.rip), "unwind step");
        if ctx2.rip == catch_ctx.rip {
            // At the catching frame — call personality with unwind + handler flags.
            // EXCEPTION_UNWINDING (0x1) | EXCEPTION_EXECUTE_HANDLER (0x4) = 5
            // EXECUTE_HANDLER is bit 2 (not bit 1).  Without it the personality
            // won't install the landing pad.
            let disposition = call_personality(handler_va, &catch_ctx, 5, handler_data, image_base, &func_entry);
            tracing::info!(pass = 2, disposition = ?disposition, "personality returned at handler frame");
            match disposition {
            Ok(URC_INSTALL_CONTEXT) | Ok(URC_HANDLER_FOUND) => {
                // Personality said handler found but never sets TargetIp/CONTEXT.Rip.
                // Always parse the LSDA directly to find the landing pad.
                let lsda = (image_base + 0x20000).saturating_add(u64::from(handler_data));
                let func_begin = catch_ctx.rip & !0xFFF;
                let landing = crate::exception::find_landing_pad(
                    &mut read_mem, lsda, image_base, func_begin, func_begin + 0x1000, catch_ctx.rip,
                );
                let (catch_rip, catch_rsp) = match landing {
                    Some((lp_va, _)) => (lp_va, catch_ctx.rsp),
                    None => anyhow::bail!("RaiseException: landing pad not found"),
                };
                tracing::info!(catch_rip = format_args!("{:#x}", catch_rip), "installing catch context via LSDA");
                engine.write_rip(catch_rip)?;
                engine.write_rsp(catch_rsp)?;
                return Ok(WinApiHandlerResult { return_address: catch_rip, return_value: 0 });
            }
            Ok(URC_CONTINUE_UNWIND) => { /* done */ break; }
            Err(e) => anyhow::bail!("personality error during unwind: {e}"),
            _ => break,
        }
        }

        let entry = match crate::exception::lookup_function_entry(&state.sync, ctx2.rip) {
            Some(e) => e, None => {
                let mut rip_buf = [0u8; 8];
                if read_mem(ctx2.rsp, &mut rip_buf).is_err() { break; }
                ctx2.rip = u64::from_le_bytes(rip_buf);
                ctx2.rsp = ctx2.rsp.saturating_add(8);
                continue;
            }
        };
        let result = match crate::exception::virtual_unwind(&mut read_mem, entry.image_base, entry.entry, ctx2) {
            Ok(r) => r, Err(_) => break,
        };
        if let (Some(handler_rva), Some(hdata)) = (result.handler_rva, result.handler_data) {
            let hva = entry.image_base.saturating_add(u64::from(handler_rva));
            tracing::info!(pass = 2, frame = _frame, handler = format_args!("{:#x}", hva), "calling personality for cleanup");
            match call_personality(hva, &ctx2, 1, hdata, entry.image_base, entry.entry) {
                Ok(URC_CONTINUE_UNWIND) => { /* destructor ran, continue */ }
                Err(e) => anyhow::bail!("personality error during cleanup: {e}"),
                _ => { /* ignore other codes during unwind */ }
            }
        }
        ctx2 = result.ctx;
        tracing::info!(pass = 2, next_rip = format_args!("{:#x}", ctx2.rip), "unwound to caller");
    }

    anyhow::bail!("RaiseException: unwind pass failed to reach handler")
}

fn handle_rtl_capture_context(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let ctx_ptr = engine.read_rcx()?;
    if ctx_ptr == 0 {
        let return_address = engine.return_from_win64_api(0)
            .context("RtlCaptureContext: return failed")?;
        return Ok(WinApiHandlerResult { return_address, return_value: 0 });
    }

    let tctx = engine.snapshot_thread_context();
    use anyhow::Context;
    // Write CONTEXT64 at ctx_ptr.
    let mut cbuf = [0u8; 0x200];
    // ContextFlags at +0x30
    cbuf[0x30..0x34].copy_from_slice(&0x0010_001Fu32.to_le_bytes());
    // GPRs at +0x78..+0xF8 (Rax..R15, then Rip at +0xF8)
    for reg in 0..16 {
        let off = 0x78 + reg * 8;
        cbuf[off..off + 8].copy_from_slice(&tctx.gpr[reg].to_le_bytes());
    }
    cbuf[0xF8..0x100].copy_from_slice(&tctx.rip.to_le_bytes());
    // Rflags at +0x44
    cbuf[0x44..0x4C].copy_from_slice(&tctx.rflags.to_le_bytes());
    // XMM registers at +0x100 (128-bit each, XMM0..XMM15)
    for i in 0..16 {
        let off = 0x100 + i * 16;
        cbuf[off..off + 16].copy_from_slice(&tctx.xmm[i].to_le_bytes());
    }
    engine.mem_write(ctx_ptr, &cbuf)
        .context("RtlCaptureContext: failed to write context")?;
    let return_address = engine.return_from_win64_api(0)
        .context("RtlCaptureContext: return failed")?;
    Ok(WinApiHandlerResult { return_address, return_value: 0 })
}

/// `RtlUnwindEx` — forced stack unwinding.
///
/// Called by `__cxa_end_catch` during catch block cleanup.  WIE's
/// `handle_raise_exception` already performed the full unwind, so
/// this is a no-op stub — just return 0 (success).
///
/// RCX = TargetFrame (frame to unwind to, NULL = all)
/// RDX = TargetIp    (landing pad after unwind)
/// R8  = ExceptionRecord
/// R9  = ReturnValue
fn handle_rtl_unwind_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    use anyhow::Context;
    let return_address = engine.return_from_win64_api(0)
        .context("RtlUnwindEx: return failed")?;
    Ok(WinApiHandlerResult { return_address, return_value: 0 })
}

/// `SetEvent`.
fn handle_set_event(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let ok = match state.sync.object(handle) {
        Some(crate::KernelObject::Event(e)) => {
            e.set();
            true
        }
        _ => false,
    };
    if ok {
        state.last_error = 0;
        let return_address = engine.return_from_win64_api(1)?;
        Ok(WinApiHandlerResult {
            return_address,
            return_value: 1,
        })
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        let return_address = engine.return_from_win64_api(0)?;
        Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        })
    }
}

/// `ResetEvent`.
fn handle_reset_event(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let ok = match state.sync.object(handle) {
        Some(crate::KernelObject::Event(e)) => {
            e.reset();
            true
        }
        _ => false,
    };
    if ok {
        state.last_error = 0;
        let return_address = engine.return_from_win64_api(1)?;
        Ok(WinApiHandlerResult {
            return_address,
            return_value: 1,
        })
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        let return_address = engine.return_from_win64_api(0)?;
        Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        })
    }
}

/// `GetCurrentThread` — pseudo-handle `-2` (Microsoft Learn).
fn handle_get_current_thread(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // CURRENT_THREAD_PSEUDO_HANDLE = (HANDLE)-2
    let return_value = u64::MAX - 1;
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// `FlushInstructionCache(hProcess, lpBaseAddress, dwSize)`.
///
/// Microsoft Learn: after patching code, flush so subsequent fetches see new
/// bytes. WIE maps this to selective JIT Ready invalidation (Phase 7).
/// `dwSize == 0` flushes the whole process instruction cache.
fn handle_flush_instruction_cache(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _process = engine
        .read_rcx()
        .context("failed to read RCX for FlushInstructionCache")?;
    let base = engine
        .read_rdx()
        .context("failed to read RDX for FlushInstructionCache")?;
    let size = engine
        .read_r8()
        .context("failed to read R8 for FlushInstructionCache")?;
    let size_usize = usize::try_from(size).unwrap_or(usize::MAX);
    if size_usize == usize::MAX && size != 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }
    match engine.flush_instruction_cache(base, size_usize) {
        Ok(()) => {
            state.last_error = 0;
            let return_address = engine.return_from_win64_api(1)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 1,
            })
        }
        Err(e) => {
            state.last_error = wie_cpu::win32_from_cpu_error(&e).unwrap_or(ERROR_INVALID_PARAMETER);
            let return_address = engine.return_from_win64_api(0)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 0,
            })
        }
    }
}

/// `VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect)`.
fn handle_virtual_alloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let addr = engine.read_rcx()?;
    let size = engine.read_rdx()?;
    let alloc_type = u32::try_from(engine.read_r8()? & 0xffff_ffff).unwrap_or(0);
    let protect = u32::try_from(engine.read_r9()? & 0xffff_ffff).unwrap_or(0);
    let size_usize = usize::try_from(size).unwrap_or(usize::MAX);
    if size_usize == usize::MAX {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }
    match engine.virtual_alloc(addr, size_usize, alloc_type, protect) {
        Ok(base) => {
            state.last_error = 0;
            tracing::debug!(addr, size, alloc_type, protect, base, "VirtualAlloc ok");
            let return_address = engine.return_from_win64_api(base)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: base,
            })
        }
        Err(e) => {
            state.last_error = wie_cpu::win32_from_cpu_error(&e).unwrap_or(ERROR_INVALID_PARAMETER);
            tracing::debug!(
                addr,
                size,
                alloc_type,
                protect,
                error = %e,
                last_error = state.last_error,
                "VirtualAlloc failed"
            );
            let return_address = engine.return_from_win64_api(0)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 0,
            })
        }
    }
}

/// `VirtualFree(lpAddress, dwSize, dwFreeType)`.
fn handle_virtual_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let addr = engine.read_rcx()?;
    let size = engine.read_rdx()?;
    let free_type = u32::try_from(engine.read_r8()? & 0xffff_ffff).unwrap_or(0);
    let size_usize = usize::try_from(size).unwrap_or(usize::MAX);
    if size_usize == usize::MAX {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }
    match engine.virtual_free(addr, size_usize, free_type) {
        Ok(()) => {
            state.last_error = 0;
            let return_address = engine.return_from_win64_api(1)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 1,
            })
        }
        Err(e) => {
            state.last_error = wie_cpu::win32_from_cpu_error(&e).unwrap_or(ERROR_INVALID_PARAMETER);
            let return_address = engine.return_from_win64_api(0)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 0,
            })
        }
    }
}

/// `VirtualProtect` — Microsoft Learn: `lpflOldProtect` must be non-NULL or the
/// call fails. Real page protection via guest PageMap (Phase 3).
fn handle_virtual_protect(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let addr = engine.read_rcx()?;
    let size = engine.read_rdx()?;
    let new_protect = u32::try_from(engine.read_r8()? & 0xffff_ffff).unwrap_or(0);
    let old_prot = engine.read_r9()?;
    // Microsoft Learn: if lpflOldProtect is NULL or invalid, the function fails.
    if old_prot == 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }
    let size_usize = usize::try_from(size).unwrap_or(usize::MAX);
    if size_usize == 0 || size_usize == usize::MAX {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }
    match engine.virtual_protect(addr, size_usize, new_protect) {
        Ok(old) => {
            write_guest_u32(engine, old_prot, old)?;
            state.last_error = 0;
            let return_address = engine.return_from_win64_api(1)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 1,
            })
        }
        Err(e) => {
            state.last_error = wie_cpu::win32_from_cpu_error(&e).unwrap_or(ERROR_INVALID_PARAMETER);
            let return_address = engine.return_from_win64_api(0)?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 0,
            })
        }
    }
}

/// `VirtualQuery` — fill real `MEMORY_BASIC_INFORMATION` from PageMap / VAD.
fn handle_virtual_query(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let address = engine.read_rcx()?;
    let buffer = engine.read_rdx()?;
    let length = engine.read_r8()?;

    if buffer == 0 || length < 48 {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    let mbi = engine.virtual_query(address);
    let bytes = mbi.to_bytes();
    engine.mem_write(buffer, &bytes)?;
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(48)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 48,
    })
}

fn handle_tls_get_value(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let index = engine.read_rcx()? & 0xffff_ffff;
    let idx = usize::try_from(index).unwrap_or(usize::MAX);
    // Microsoft: invalid index → 0 and last-error ERROR_INVALID_PARAMETER (87).
    let allocated = usize::try_from(state.threads.tls_index_count).unwrap_or(0);
    if idx >= allocated {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }
    state.threads.grow_active_tls_to_process_count();
    let value = state
        .threads
        .active
        .tls_values
        .get(idx)
        .copied()
        .unwrap_or(0);
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

fn handle_tls_set_value(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let index = engine.read_rcx()? & 0xffff_ffff;
    let value = engine.read_rdx()?;
    let idx = usize::try_from(index).unwrap_or(usize::MAX);
    let allocated = usize::try_from(state.threads.tls_index_count).unwrap_or(0);
    if idx >= allocated {
        state.last_error = ERROR_INVALID_PARAMETER;
        let return_address = engine.return_from_win64_api(0)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }
    state.threads.grow_active_tls_to_process_count();
    if let Some(slot) = state.threads.active.tls_values.get_mut(idx) {
        *slot = value;
        state.last_error = 0;
        let return_address = engine.return_from_win64_api(1)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 1,
        });
    }
    state.last_error = ERROR_INVALID_PARAMETER;
    let return_address = engine.return_from_win64_api(0)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

fn handle_tls_alloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    // Process-wide index space; value storage is per active guest thread.
    let index = u64::from(state.threads.tls_index_count);
    state.threads.tls_index_count = state.threads.tls_index_count.saturating_add(1);
    state.threads.grow_active_tls_to_process_count();
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(index)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: index,
    })
}

fn handle_tls_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let index_raw = engine.read_rcx()?;
    let index = usize::try_from(index_raw).unwrap_or(usize::MAX);
    // Clear active thread value; index remains allocated (Windows does not reuse
    // TLS indices after TlsFree in a way micros depend on — zero is enough).
    if let Some(slot) = state.threads.active.tls_values.get_mut(index) {
        *slot = 0;
    }
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(1)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!Sleep`.
///
/// Idle policy (Phase 6 — see [`crate::idle`]):
/// - `Sleep(0)` always yields the host thread (`yield_now`).
/// - `Sleep(n>0)`: **no-op** under `WIE_IDLE=yield|busy` (micros); parks under
///   `WIE_IDLE=park` or legacy `WIE_HOST_SLEEP=1` (capped by `WIE_IDLE_CAP_MS`).
///
/// Not planted as an in-guest stub — side effects depend on host idle policy.
pub fn handle_sleep(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let milliseconds = engine.read_rcx().context("failed to read RCX for Sleep")?;
    let low32 = milliseconds & u64::from(u32::MAX);

    let policy = crate::idle::IdlePolicy::from_env();
    crate::idle::apply_sleep(policy, low32);

    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from Sleep")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn allocate_fake_heap_block(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    size: u64,
) -> u64 {
    state.heap.alloc_coherent(engine, size)
}

/// Handles `KERNEL32.dll!LocalAlloc`.
pub fn handle_local_alloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _flags = engine
        .read_rcx()
        .context("failed to read RCX for LocalAlloc")?;

    let size = engine
        .read_rdx()
        .context("failed to read RDX for LocalAlloc")?;

    let return_value = allocate_fake_heap_block(engine, state, size);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LocalAlloc")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!LocalFree`.
pub fn handle_local_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let memory = engine
        .read_rcx()
        .context("failed to read RCX for LocalFree")?;

    if memory == 0 {
        let return_address = engine
            .return_from_win64_api(0)
            .context("failed to return from LocalFree")?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    let existed = state.heap.free_coherent(engine, memory);

    // LocalFree returns NULL on success and the original handle on failure.
    let return_value = if existed { 0 } else { memory };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from LocalFree")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GlobalAlloc`.
pub fn handle_global_alloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _flags = engine
        .read_rcx()
        .context("failed to read RCX for GlobalAlloc")?;

    let size = engine
        .read_rdx()
        .context("failed to read RDX for GlobalAlloc")?;

    let return_value = allocate_fake_heap_block(engine, state, size);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GlobalAlloc")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GlobalFree`.
pub fn handle_global_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let memory = engine
        .read_rcx()
        .context("failed to read RCX for GlobalFree")?;

    if memory == 0 {
        let return_address = engine
            .return_from_win64_api(0)
            .context("failed to return from GlobalFree")?;

        return Ok(WinApiHandlerResult {
            return_address,
            return_value: 0,
        });
    }

    let existed = state.heap.free_coherent(engine, memory);

    // GlobalFree returns NULL on success and the original handle on failure.
    let return_value = if existed { 0 } else { memory };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GlobalFree")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GlobalLock`.
pub fn handle_global_lock(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let memory = engine
        .read_rcx()
        .context("failed to read RCX for GlobalLock")?;

    let return_value = if state.heap.is_live(memory) {
        memory
    } else {
        0
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GlobalLock")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GlobalUnlock`.
pub fn handle_global_unlock(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let memory = engine
        .read_rcx()
        .context("failed to read RCX for GlobalUnlock")?;

    let existed = state.heap.is_live(memory);

    state.last_error = if existed { 0 } else { ERROR_INVALID_HANDLE };

    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GlobalUnlock")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GlobalSize`.
pub fn handle_global_size(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let memory = engine
        .read_rcx()
        .context("failed to read RCX for GlobalSize")?;

    let return_value = state.heap.size_of(memory).unwrap_or(0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GlobalSize")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!MulDiv`.
pub fn handle_mul_div(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let number_raw = engine.read_rcx().context("failed to read RCX for MulDiv")?;

    let numerator_raw = engine.read_rdx().context("failed to read RDX for MulDiv")?;

    let denominator_raw = engine.read_r8().context("failed to read R8 for MulDiv")?;

    let number = i64::from(low_u32_to_i32(number_raw, "MulDiv number")?);
    let numerator = i64::from(low_u32_to_i32(numerator_raw, "MulDiv numerator")?);
    let denominator = i64::from(low_u32_to_i32(denominator_raw, "MulDiv denominator")?);

    let result = if denominator == 0 {
        -1_i64
    } else {
        number
            .checked_mul(numerator)
            .and_then(|product| product.checked_div(denominator))
            .unwrap_or(-1)
    };

    let result_i32 = i32::try_from(result).unwrap_or(-1);
    let result_u32 = u32::from_ne_bytes(result_i32.to_ne_bytes());
    let return_value = u64::from(result_u32);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from MulDiv")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GlobalAddAtomA`.
pub fn handle_global_add_atom_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GlobalAddAtomA")?;

    let return_value = if name_ptr == 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        0
    } else {
        let name = read_ansi_string_from_cpu(engine, name_ptr, 255)
            .context("failed to read GlobalAddAtomA name")?;

        if name.is_empty() {
            state.last_error = ERROR_INVALID_PARAMETER;
            0
        } else if let Some(existing) = state
            .global_atoms
            .iter()
            .find(|record| record.name.eq_ignore_ascii_case(&name))
        {
            state.last_error = 0;
            u64::from(existing.atom)
        } else {
            let atom = state.next_global_atom;

            state.next_global_atom = state
                .next_global_atom
                .checked_add(1)
                .context("global atom identifier overflow")?;

            state.global_atoms.push(GlobalAtomRecord { atom, name });
            state.last_error = 0;

            u64::from(atom)
        }
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GlobalAddAtomA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GlobalDeleteAtom`.
pub fn handle_global_delete_atom(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let atom_raw = engine
        .read_rcx()
        .context("failed to read RCX for GlobalDeleteAtom")?;

    let atom_low = atom_raw & u64::from(u16::MAX);
    let atom = u16::try_from(atom_low).context("GlobalDeleteAtom identifier does not fit u16")?;

    let existed = state.global_atoms.iter().any(|record| record.atom == atom);

    if existed {
        state.global_atoms.retain(|record| record.atom != atom);

        state.last_error = 0;
    } else {
        state.last_error = ERROR_INVALID_PARAMETER;
    }

    // GlobalDeleteAtom returns zero on success, otherwise the original atom.
    let return_value = if existed { 0 } else { u64::from(atom) };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GlobalDeleteAtom")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Resolve a Windows path against the process current directory.
fn resolve_full_windows_path(current_directory: &str, input_path: &str) -> String {
    crate::vfs::resolve_full_windows_path(current_directory, input_path)
}

#[cfg(test)]
fn normalize_windows_path_components(path: &str) -> String {
    crate::vfs::normalize_windows_path_components(path)
}

/// Handles `KERNEL32.dll!GetFullPathNameW`.
pub fn handle_get_full_path_name_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let input_path_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetFullPathNameW")?;

    let buffer_characters_raw = engine
        .read_rdx()
        .context("failed to read RDX for GetFullPathNameW")?;

    let output_buffer_ptr = engine
        .read_r8()
        .context("failed to read R8 for GetFullPathNameW")?;

    let file_part_ptr_ptr = engine
        .read_r9()
        .context("failed to read R9 for GetFullPathNameW")?;

    let return_value = if input_path_ptr == 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        0
    } else {
        let input_path = read_guest_utf16_lossy(engine, input_path_ptr, 32_768)
            .context("failed to read GetFullPathNameW input path")?;

        if input_path.is_empty() {
            state.last_error = ERROR_INVALID_PARAMETER;
            0
        } else {
            let current_directory = String::from_utf16_lossy(&state.current_directory_wide);

            let full_path = resolve_full_windows_path(&current_directory, &input_path);

            let path_units = full_path.encode_utf16().collect::<Vec<_>>();

            let path_length = path_units.len();

            let required_with_null = path_length
                .checked_add(1)
                .context("GetFullPathNameW required length overflow")?;

            let buffer_characters = usize::try_from(buffer_characters_raw)
                .context("GetFullPathNameW buffer size does not fit usize")?;

            if output_buffer_ptr == 0 || buffer_characters < required_with_null {
                if file_part_ptr_ptr != 0 {
                    write_guest_u64(engine, file_part_ptr_ptr, 0)?;
                }

                state.last_error = 0;

                u64::try_from(required_with_null)
                    .context("GetFullPathNameW required length does not fit u64")?
            } else {
                let mut terminated_units = path_units;
                terminated_units.push(0);

                write_guest_utf16_units(engine, output_buffer_ptr, &terminated_units)?;

                if file_part_ptr_ptr != 0 {
                    let file_component_offset = full_path
                        .rfind('\\')
                        .map_or(0, |separator_index| separator_index.saturating_add(1));

                    let prefix_units = full_path
                        .get(..file_component_offset)
                        .unwrap_or_default()
                        .encode_utf16()
                        .count();

                    let byte_offset = prefix_units
                        .checked_mul(std::mem::size_of::<u16>())
                        .context("GetFullPathNameW file-part byte offset overflow")?;

                    let byte_offset_u64 = u64::try_from(byte_offset)
                        .context("GetFullPathNameW file-part offset does not fit u64")?;

                    let file_part_ptr = output_buffer_ptr
                        .checked_add(byte_offset_u64)
                        .context("GetFullPathNameW file-part pointer overflow")?;

                    write_guest_u64(engine, file_part_ptr_ptr, file_part_ptr)?;
                }

                state.last_error = 0;

                u64::try_from(path_length)
                    .context("GetFullPathNameW result length does not fit u64")?
            }
        }
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetFullPathNameW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFullPathNameA`.
pub fn handle_get_full_path_name_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let input_path_ptr = engine.read_rcx()?;
    let buffer_characters_raw = engine.read_rdx()?;
    let output_buffer_ptr = engine.read_r8()?;
    let file_part_ptr_ptr = engine.read_r9()?;

    let return_value = if input_path_ptr == 0 {
        state.last_error = ERROR_INVALID_PARAMETER;
        0
    } else {
        let input_path = read_ansi_string_from_cpu(engine, input_path_ptr, 32_768)?;
        if input_path.is_empty() {
            state.last_error = ERROR_INVALID_PARAMETER;
            0
        } else {
            let current_directory = String::from_utf16_lossy(&state.current_directory_wide);
            let full_path = resolve_full_windows_path(&current_directory, &input_path);
            let path_bytes = crate::vfs::encode_acp(&full_path);
            let path_length = path_bytes.len();
            let required_with_null = path_length.saturating_add(1);
            let buffer_characters = usize::try_from(buffer_characters_raw).unwrap_or(0);
            if output_buffer_ptr == 0 || buffer_characters < required_with_null {
                if file_part_ptr_ptr != 0 {
                    write_guest_u64(engine, file_part_ptr_ptr, 0)?;
                }
                state.last_error = 0;
                u64::try_from(required_with_null).unwrap_or(0)
            } else {
                let mut out = path_bytes;
                out.push(0);
                engine.mem_write(output_buffer_ptr, &out)?;
                if file_part_ptr_ptr != 0 {
                    let file_off = full_path.rfind('\\').map_or(0, |i| i.saturating_add(1));
                    let file_part_ptr =
                        output_buffer_ptr.saturating_add(u64::try_from(file_off).unwrap_or(0));
                    write_guest_u64(engine, file_part_ptr_ptr, file_part_ptr)?;
                }
                state.last_error = 0;
                u64::try_from(path_length).unwrap_or(0)
            }
        }
    };

    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetCurrentDirectoryA`.
pub fn handle_get_current_directory_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let buffer_length = engine.read_rcx()?;
    let buffer_ptr = engine.read_rdx()?;
    let directory = String::from_utf16_lossy(&state.current_directory_wide);
    let bytes = crate::vfs::encode_acp(&directory);
    let character_count = u64::try_from(bytes.len()).unwrap_or(0);
    let required_with_nul = character_count.saturating_add(1);
    let return_value = if buffer_ptr == 0 || buffer_length == 0 || buffer_length <= character_count
    {
        required_with_nul
    } else {
        let mut out = bytes;
        out.push(0);
        engine.mem_write(buffer_ptr, &out)?;
        character_count
    };
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetCurrentDirectoryA`.
pub fn handle_set_current_directory_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let directory_ptr = engine.read_rcx()?;
    let success = if directory_ptr == 0 {
        state.last_error = ERROR_PATH_NOT_FOUND;
        false
    } else {
        let directory = read_ansi_string_from_cpu(engine, directory_ptr, 32_768)?;
        if directory.is_empty() {
            state.last_error = ERROR_PATH_NOT_FOUND;
            false
        } else {
            let cwd = String::from_utf16_lossy(&state.current_directory_wide);
            let full = resolve_full_windows_path(&cwd, &directory);
            if guest_dir_exists(state, &full) {
                state.current_directory_wide = full.encode_utf16().collect();
                state.last_error = 0;
                true
            } else {
                state.last_error = ERROR_PATH_NOT_FOUND;
                false
            }
        }
    };
    let return_value = u64::from(success);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_create_directory(state: &mut WinApiState, path: &str) -> u64 {
    if path.is_empty() {
        state.last_error = ERROR_PATH_NOT_FOUND;
        return 0;
    }
    if state.volumes.bottle_root != state.bottle_root {
        state.volumes.bottle_root = state.bottle_root.clone();
    }
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full = resolve_full_windows_path(&cwd, path);
    if guest_dir_exists(state, &full) {
        state.last_error = ERROR_ALREADY_EXISTS;
        return 0;
    }
    let Some(map) = crate::vfs::guest_path_to_host(&state.volumes, &full) else {
        state.last_error = ERROR_PATH_NOT_FOUND;
        return 0;
    };
    if crate::vfs::mkdir_host(&map.host).is_ok() {
        state.last_error = 0;
        1
    } else {
        state.last_error = ERROR_PATH_NOT_FOUND;
        0
    }
}

/// Handles `KERNEL32.dll!CreateDirectoryW`.
pub fn handle_create_directory_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_wide_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let return_value = finish_create_directory(state, &path);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!CreateDirectoryA`.
pub fn handle_create_directory_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_ansi_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let return_value = finish_create_directory(state, &path);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_delete_file(state: &mut WinApiState, path: &str) -> u64 {
    if path.is_empty() {
        state.last_error = ERROR_PATH_NOT_FOUND;
        return 0;
    }
    if state.volumes.bottle_root != state.bottle_root {
        state.volumes.bottle_root = state.bottle_root.clone();
    }
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full = resolve_full_windows_path(&cwd, path);
    state
        .virtual_files
        .retain(|v| !paths_match_guest(&full, &v.guest_path));
    if let Some(map) = crate::vfs::guest_path_to_host(&state.volumes, &full) {
        if crate::vfs::remove_file_host(&map.host).is_ok() {
            state.last_error = 0;
            return 1;
        }
        state.last_error = ERROR_FILE_NOT_FOUND;
        return 0;
    }
    state.last_error = ERROR_FILE_NOT_FOUND;
    0
}

/// Handles `KERNEL32.dll!DeleteFileW`.
pub fn handle_delete_file_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_wide_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let return_value = finish_delete_file(state, &path);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!DeleteFileA`.
pub fn handle_delete_file_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_ansi_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let return_value = finish_delete_file(state, &path);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_remove_directory(state: &mut WinApiState, path: &str) -> u64 {
    if path.is_empty() {
        state.last_error = ERROR_PATH_NOT_FOUND;
        return 0;
    }
    if state.volumes.bottle_root != state.bottle_root {
        state.volumes.bottle_root = state.bottle_root.clone();
    }
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full = resolve_full_windows_path(&cwd, path);
    let Some(map) = crate::vfs::guest_path_to_host(&state.volumes, &full) else {
        state.last_error = ERROR_PATH_NOT_FOUND;
        return 0;
    };
    match crate::vfs::remove_dir_host(&map.host) {
        Ok(()) => {
            state.last_error = 0;
            1
        }
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            state.last_error = ERROR_DIR_NOT_EMPTY;
            0
        }
        Err(_) => {
            state.last_error = ERROR_PATH_NOT_FOUND;
            0
        }
    }
}

/// Handles `KERNEL32.dll!RemoveDirectoryW`.
pub fn handle_remove_directory_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_wide_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let return_value = finish_remove_directory(state, &path);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!RemoveDirectoryA`.
pub fn handle_remove_directory_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_ansi_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let return_value = finish_remove_directory(state, &path);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_move_file(state: &mut WinApiState, from: &str, to: &str) -> u64 {
    if from.is_empty() || to.is_empty() {
        state.last_error = ERROR_PATH_NOT_FOUND;
        return 0;
    }
    if state.volumes.bottle_root != state.bottle_root {
        state.volumes.bottle_root = state.bottle_root.clone();
    }
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_from = resolve_full_windows_path(&cwd, from);
    let full_to = resolve_full_windows_path(&cwd, to);
    let Some(src) = crate::vfs::guest_path_to_host(&state.volumes, &full_from) else {
        state.last_error = ERROR_FILE_NOT_FOUND;
        return 0;
    };
    let Some(dst) = crate::vfs::guest_path_to_host(&state.volumes, &full_to) else {
        state.last_error = ERROR_PATH_NOT_FOUND;
        return 0;
    };
    if crate::vfs::rename_host(&src.host, &dst.host).is_ok() {
        state.last_error = 0;
        1
    } else {
        state.last_error = ERROR_ACCESS_DENIED;
        0
    }
}

fn temp_name_id_u32(id: u64) -> u32 {
    u32::try_from(id & 0xffff_ffff).unwrap_or(0)
}

/// Handles `KERNEL32.dll!MoveFileW`.
pub fn handle_move_file_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let from_ptr = engine.read_rcx()?;
    let to_ptr = engine.read_rdx()?;
    let from = if from_ptr == 0 {
        String::new()
    } else {
        read_wide_string_from_cpu(engine, from_ptr, 32_768)?
    };
    let to = if to_ptr == 0 {
        String::new()
    } else {
        read_wide_string_from_cpu(engine, to_ptr, 32_768)?
    };
    let return_value = finish_move_file(state, &from, &to);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!MoveFileA`.
pub fn handle_move_file_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let from_ptr = engine.read_rcx()?;
    let to_ptr = engine.read_rdx()?;
    let from = if from_ptr == 0 {
        String::new()
    } else {
        read_ansi_string_from_cpu(engine, from_ptr, 32_768)?
    };
    let to = if to_ptr == 0 {
        String::new()
    } else {
        read_ansi_string_from_cpu(engine, to_ptr, 32_768)?
    };
    let return_value = finish_move_file(state, &from, &to);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetTempPathW`.
pub fn handle_get_temp_path_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let buffer_len = engine.read_rcx()?;
    let buffer_ptr = engine.read_rdx()?;
    // Trailing backslash per Microsoft Learn.
    let temp = format!("{}\\", crate::vfs::GUEST_TEMP_PATH.trim_end_matches('\\'));
    let units: Vec<u16> = temp.encode_utf16().collect();
    let required = u64::try_from(units.len().saturating_add(1)).unwrap_or(0);
    let return_value = if buffer_ptr == 0 || buffer_len < required {
        required
    } else {
        let mut terminated = units;
        terminated.push(0);
        write_guest_utf16_units(engine, buffer_ptr, &terminated)?;
        u64::try_from(terminated.len().saturating_sub(1)).unwrap_or(0)
    };
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetTempPathA`.
pub fn handle_get_temp_path_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let buffer_len = engine.read_rcx()?;
    let buffer_ptr = engine.read_rdx()?;
    let temp = format!("{}\\", crate::vfs::GUEST_TEMP_PATH.trim_end_matches('\\'));
    let bytes = crate::vfs::encode_acp(&temp);
    let required = u64::try_from(bytes.len().saturating_add(1)).unwrap_or(0);
    let return_value = if buffer_ptr == 0 || buffer_len < required {
        required
    } else {
        let mut out = bytes;
        out.push(0);
        engine.mem_write(buffer_ptr, &out)?;
        u64::try_from(out.len().saturating_sub(1)).unwrap_or(0)
    };
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetTempFileNameW` (unique name under path; creates 0-byte file).
pub fn handle_get_temp_file_name_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let prefix_ptr = engine.read_rdx()?;
    let unique = engine.read_r8()?;
    let buffer_ptr = engine.read_r9()?;
    let path = if path_ptr == 0 {
        crate::vfs::GUEST_TEMP_PATH.to_owned()
    } else {
        read_wide_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let prefix = if prefix_ptr == 0 {
        "WIE".to_owned()
    } else {
        read_wide_string_from_cpu(engine, prefix_ptr, 16)?
    };
    let prefix: String = prefix.chars().take(3).collect();
    let id = if unique == 0 {
        state.tick_count = state.tick_count.wrapping_add(1);
        state.tick_count
    } else {
        unique
    };
    let id_u32 = temp_name_id_u32(id);
    let name = format!(
        "{}\\{}{:04X}.tmp",
        path.trim_end_matches('\\'),
        prefix,
        id_u32
    );
    finish_create_file_create_only(state, &name);
    if buffer_ptr != 0 {
        let mut units: Vec<u16> = name.encode_utf16().collect();
        units.push(0);
        write_guest_utf16_units(engine, buffer_ptr, &units)?;
    }
    state.last_error = 0;
    let return_value = u64::from(id_u32).max(1);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn finish_create_file_create_only(state: &mut WinApiState, guest_path: &str) {
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full = resolve_full_windows_path(&cwd, guest_path);
    if state.volumes.bottle_root != state.bottle_root {
        state.volumes.bottle_root = state.bottle_root.clone();
    }
    if let Some(map) = crate::vfs::guest_path_to_host(&state.volumes, &full) {
        drop(crate::vfs::create_host_file(&map.host));
    } else {
        ensure_virtual_file(state, &full);
    }
}

/// Handles `KERNEL32.dll!GetTempFileNameA`.
pub fn handle_get_temp_file_name_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let prefix_ptr = engine.read_rdx()?;
    let unique = engine.read_r8()?;
    let buffer_ptr = engine.read_r9()?;
    let path = if path_ptr == 0 {
        crate::vfs::GUEST_TEMP_PATH.to_owned()
    } else {
        read_ansi_string_from_cpu(engine, path_ptr, 32_768)?
    };
    let prefix = if prefix_ptr == 0 {
        "WIE".to_owned()
    } else {
        read_ansi_string_from_cpu(engine, prefix_ptr, 16)?
    };
    let prefix: String = prefix.chars().take(3).collect();
    let id = if unique == 0 {
        state.tick_count = state.tick_count.wrapping_add(1);
        state.tick_count
    } else {
        unique
    };
    let id_u32 = temp_name_id_u32(id);
    let name = format!(
        "{}\\{}{:04X}.tmp",
        path.trim_end_matches('\\'),
        prefix,
        id_u32
    );
    finish_create_file_create_only(state, &name);
    if buffer_ptr != 0 {
        let mut out = crate::vfs::encode_acp(&name);
        out.push(0);
        engine.mem_write(buffer_ptr, &out)?;
    }
    state.last_error = 0;
    let return_value = u64::from(id_u32).max(1);
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetDriveTypeW`.
pub fn handle_get_drive_type_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_wide_string_from_cpu(engine, path_ptr, 16)?
    };
    let return_value = u64::from(crate::vfs::get_drive_type(&state.volumes, &path));
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetDriveTypeA`.
pub fn handle_get_drive_type_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine.read_rcx()?;
    let path = if path_ptr == 0 {
        String::new()
    } else {
        read_ansi_string_from_cpu(engine, path_ptr, 16)?
    };
    let return_value = u64::from(crate::vfs::get_drive_type(&state.volumes, &path));
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetLogicalDrives`.
pub fn handle_get_logical_drives(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let return_value = u64::from(crate::vfs::logical_drives_mask(&state.volumes));
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetSystemDirectoryW`.
pub fn handle_get_system_directory_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    write_fixed_dir_w(engine, crate::vfs::GUEST_SYSTEM_DIR)
}

/// Handles `KERNEL32.dll!GetSystemDirectoryA`.
pub fn handle_get_system_directory_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    write_fixed_dir_a(engine, crate::vfs::GUEST_SYSTEM_DIR)
}

/// Handles `KERNEL32.dll!GetWindowsDirectoryW`.
pub fn handle_get_windows_directory_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    write_fixed_dir_w(engine, crate::vfs::GUEST_WINDOWS_DIR)
}

/// Handles `KERNEL32.dll!GetWindowsDirectoryA`.
pub fn handle_get_windows_directory_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    write_fixed_dir_a(engine, crate::vfs::GUEST_WINDOWS_DIR)
}

fn write_fixed_dir_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    dir: &str,
) -> Result<WinApiHandlerResult> {
    let buffer_len = engine.read_rcx()?;
    let buffer_ptr = engine.read_rdx()?;
    let units: Vec<u16> = dir.encode_utf16().collect();
    let required = u64::try_from(units.len().saturating_add(1)).unwrap_or(0);
    let return_value = if buffer_ptr == 0 || buffer_len < required {
        required
    } else {
        let mut t = units;
        t.push(0);
        write_guest_utf16_units(engine, buffer_ptr, &t)?;
        u64::try_from(t.len().saturating_sub(1)).unwrap_or(0)
    };
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn write_fixed_dir_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    dir: &str,
) -> Result<WinApiHandlerResult> {
    let buffer_len = engine.read_rcx()?;
    let buffer_ptr = engine.read_rdx()?;
    let bytes = crate::vfs::encode_acp(dir);
    let required = u64::try_from(bytes.len().saturating_add(1)).unwrap_or(0);
    let return_value = if buffer_ptr == 0 || buffer_len < required {
        required
    } else {
        let mut out = bytes;
        out.push(0);
        engine.mem_write(buffer_ptr, &out)?;
        u64::try_from(out.len().saturating_sub(1)).unwrap_or(0)
    };
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!GetFileSizeEx`.
pub fn handle_get_file_size_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let size_ptr = engine.read_rdx()?;
    let return_value = if let Some(open_file) = find_open_file(state, handle) {
        if size_ptr != 0 {
            write_guest_u64(engine, size_ptr, open_file.size())?;
        }
        state.last_error = 0;
        1
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        0
    };
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetFilePointerEx`.
pub fn handle_set_file_pointer_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    // Win64: DistanceToMove is LARGE_INTEGER by value in RDX (signed 64-bit).
    let distance_raw = engine.read_rdx()?;
    let distance = i64::from_le_bytes(distance_raw.to_le_bytes());
    let move_method = engine.read_r8()?;
    let new_pos_ptr = engine.read_r9()?;

    let valid_method =
        move_method == FILE_BEGIN || move_method == FILE_CURRENT || move_method == FILE_END;
    let return_value = if !is_open_file_handle(state, handle) {
        state.last_error = ERROR_INVALID_HANDLE;
        0
    } else if !valid_method {
        state.last_error = ERROR_INVALID_PARAMETER;
        0
    } else {
        let open_file = find_open_file_mut(state, handle)
            .context("open file vanished during SetFilePointerEx")?;
        let file_size = open_file.size();
        let base = if move_method == FILE_BEGIN {
            0_i64
        } else if move_method == FILE_CURRENT {
            i64::try_from(open_file.cursor).unwrap_or(0)
        } else {
            i64::try_from(file_size).unwrap_or(0)
        };
        let new_position = base.saturating_add(distance);
        if new_position < 0 {
            state.last_error = ERROR_INVALID_PARAMETER;
            0
        } else {
            let new_cursor = u64::try_from(new_position).unwrap_or(0);
            open_file.cursor = new_cursor;
            if new_pos_ptr != 0 {
                write_guest_u64(engine, new_pos_ptr, new_cursor)?;
            }
            state.last_error = 0;
            1
        }
    };
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!SetEndOfFile`.
pub fn handle_set_end_of_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let return_value = if is_open_file_handle(state, handle) {
        let (streaming, host, cursor, path) = {
            let f = find_open_file(state, handle).context("open file vanished")?;
            (f.streaming, f.host_path.clone(), f.cursor, f.path.clone())
        };
        if streaming {
            if let Some(host) = host {
                drop(crate::vfs::host_set_len(&host, cursor));
            }
        } else {
            if let Some(f) = find_open_file_mut(state, handle) {
                let len = usize::try_from(cursor).unwrap_or(0);
                f.bytes.resize(len, 0);
            }
            sync_open_bytes_to_virtual(state, &path, handle);
            persist_open_file_to_host(state, handle);
        }
        state.last_error = 0;
        1
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        0
    };
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FlushFileBuffers`.
pub fn handle_flush_file_buffers(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let return_value = if is_open_file_handle(state, handle) {
        persist_open_file_to_host(state, handle);
        state.last_error = 0;
        1
    } else {
        state.last_error = ERROR_INVALID_HANDLE;
        0
    };
    let return_address = engine.return_from_win64_api(return_value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

#[cfg(test)]
mod path_resolve_tests {
    use super::{normalize_windows_path_components, resolve_full_windows_path};

    #[test]
    fn relative_dot_slash_against_cwd() {
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r".\config.ini"),
            r"C:\App\config.ini"
        );
    }

    #[test]
    fn relative_bare_name() {
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r"config.ini"),
            r"C:\App\config.ini"
        );
    }

    #[test]
    fn relative_dotdot() {
        assert_eq!(
            resolve_full_windows_path(r"C:\App\data", r"..\config.ini"),
            r"C:\App\config.ini"
        );
    }

    #[test]
    fn rooted_on_current_drive() {
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r"\Windows\win.ini"),
            r"C:\Windows\win.ini"
        );
    }

    #[test]
    fn absolute_unchanged_after_normalize() {
        assert_eq!(
            resolve_full_windows_path(r"C:\App", r"D:\other\file.txt"),
            r"D:\other\file.txt"
        );
    }

    #[test]
    fn collapses_dot_components() {
        assert_eq!(
            normalize_windows_path_components(r"C:\App\.\sub\..\x.txt"),
            r"C:\App\x.txt"
        );
    }
}
