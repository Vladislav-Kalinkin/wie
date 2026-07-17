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
const FAKE_CURRENT_THREAD_ID: u64 = 0x5678;
const FIXED_TICK_COUNT: u64 = 12_345;
const FIXED_PERFORMANCE_COUNTER: u64 = 1_000_000;
const FLS_OUT_OF_INDEXES: u64 = 0xffff_ffff;
const STD_INPUT_HANDLE_ID: u32 = 0xffff_fff6;
const STD_OUTPUT_HANDLE_ID: u32 = 0xffff_fff5;
const STD_ERROR_HANDLE_ID: u32 = 0xffff_fff4;

const FAKE_STDIN_HANDLE: u64 = 0x0000_0000_6000_0001;
const FAKE_STDOUT_HANDLE: u64 = 0x0000_0000_6000_0002;
const FAKE_STDERR_HANDLE: u64 = 0x0000_0000_6000_0003;

const FILE_TYPE_UNKNOWN: u64 = 0x0000;
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
const ERROR_FILE_NOT_FOUND_U32: u32 = 2;

const FAKE_RESOURCE_DATA_BASE: u64 = 0x0000_0000_6400_0000;
const FAKE_RESOURCE_SIZE: u32 = 16;
const FAKE_RESOURCE_BYTES: [u8; 16] = [
    0x4c, 0x4d, 0x52, 0x53, // "WIERS"
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const LANG_EN_US: u64 = 0x0409;

const FILE_TYPE_DISK: u64 = 1;

const STD_INPUT_HANDLE_VALUE: u64 = 0x0000_0000_6000_0001;
const STD_OUTPUT_HANDLE_VALUE: u64 = 0x0000_0000_6000_0002;
const STD_ERROR_HANDLE_VALUE: u64 = 0x0000_0000_6000_0003;
const ERROR_INVALID_HANDLE: u32 = 6;
const FILE_ATTRIBUTE_ARCHIVE_U32: u32 = 0x20;
const ERROR_INVALID_PARAMETER: u32 = 87;

const TIME_ZONE_ID_UNKNOWN: u64 = 0;
const TIME_ZONE_ID_INVALID: u64 = 0xffff_ffff;

const FILE_BEGIN: u64 = 0;
const FILE_CURRENT: u64 = 1;
const FILE_END: u64 = 2;
const INVALID_SET_FILE_POINTER: u64 = 0xffff_ffff;

const ERROR_FILE_NOT_FOUND: u32 = 2;
const ERROR_PATH_NOT_FOUND: u32 = 3;
/// CreateFile CREATE_NEW when the file already exists (Microsoft Learn).
const ERROR_FILE_EXISTS: u32 = 80;
const ERROR_MOD_NOT_FOUND: u32 = 126;
const ERROR_PROC_NOT_FOUND: u32 = 127;
const ERROR_ALREADY_EXISTS: u32 = 183;

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

    let major_version = 10_u32;
    let minor_version = 0_u32;
    let build_number = 19045_u32;
    let platform_id = 2_u32;

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
pub fn handle_get_module_handle_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let module_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetModuleHandleA")?;

    let return_value = if module_name_ptr == 0 {
        environment.image_base
    } else {
        let module_name = read_ansi_string_from_cpu(engine, module_name_ptr, 260)?;
        resolve_module_handle(&module_name, environment.image_base, state)
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from GetModuleHandleA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
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

fn utf16_units_to_multibyte(units: &[u16]) -> Result<Vec<u8>> {
    let has_nul = units.last().is_some_and(|unit| *unit == 0);
    let text_units = if has_nul {
        units
            .get(..units.len().saturating_sub(1))
            .context("failed to slice UTF-16 units")?
    } else {
        units
    };

    let text = String::from_utf16(text_units).context("invalid UTF-16 input")?;
    let mut bytes = text.into_bytes();

    if has_nul {
        bytes.push(0);
    }

    Ok(bytes)
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

fn multibyte_bytes_to_utf16_units(bytes: &[u8]) -> Result<Vec<u16>> {
    let has_nul = bytes.last().is_some_and(|byte| *byte == 0);
    let text_bytes = if has_nul {
        bytes
            .get(..bytes.len().saturating_sub(1))
            .context("failed to slice multibyte bytes")?
    } else {
        bytes
    };

    let text = String::from_utf8_lossy(text_bytes);
    let mut units: Vec<u16> = text.encode_utf16().collect();

    if has_nul {
        units.push(0);
    }

    Ok(units)
}

fn copy_bytes_to_guest_buffer(
    engine: &mut dyn wie_cpu::CpuEngine,
    source_ptr: u64,
    dest_ptr: u64,
    dest_len: u64,
) -> Result<u64> {
    if dest_ptr == 0 || dest_len == 0 {
        return Ok(0);
    }

    let dest_len_usize =
        usize::try_from(dest_len).context("guest buffer length does not fit usize")?;

    let mut source_bytes = Vec::new();

    for index in 0..dest_len_usize {
        let index_u64 = u64::try_from(index).context("guest string index does not fit u64")?;
        let source_address = checked_address(source_ptr, index_u64, "guest source string")?;

        let mut byte = [0_u8; 1];
        engine
            .mem_read(source_address, &mut byte)
            .context("failed to read guest source string byte")?;

        source_bytes.push(byte[0]);

        if byte[0] == 0 {
            break;
        }
    }

    let bytes_to_write = if source_bytes.len() > dest_len_usize {
        source_bytes
            .get(..dest_len_usize)
            .context("failed to slice guest output bytes")?
    } else {
        source_bytes.as_slice()
    };

    engine
        .mem_write(dest_ptr, bytes_to_write)
        .context("failed to write guest buffer")?;

    let written_without_nul = bytes_to_write
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes_to_write.len());

    u64::try_from(written_without_nul).context("written byte count does not fit u64")
}

fn copy_wide_string_to_guest_buffer(
    engine: &mut dyn wie_cpu::CpuEngine,
    source_ptr: u64,
    dest_ptr: u64,
    dest_len: u64,
) -> Result<u64> {
    if dest_ptr == 0 || dest_len == 0 {
        return Ok(0);
    }

    let dest_len_usize =
        usize::try_from(dest_len).context("wide guest buffer length does not fit usize")?;

    let mut output_bytes = Vec::new();
    let mut written_units = 0_u64;

    for index in 0..dest_len_usize {
        let index_u64 = u64::try_from(index).context("wide guest string index does not fit u64")?;
        let source_offset = index_u64
            .checked_mul(2)
            .context("wide guest string source offset overflow")?;

        let source_address =
            checked_address(source_ptr, source_offset, "wide guest source string")?;
        let unit = read_guest_u16(engine, source_address)?;

        output_bytes.extend_from_slice(&unit.to_le_bytes());

        if unit == 0 {
            break;
        }

        written_units = written_units
            .checked_add(1)
            .context("wide guest written unit count overflow")?;
    }

    engine
        .mem_write(dest_ptr, &output_bytes)
        .context("failed to write wide guest buffer")?;

    Ok(written_units)
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

fn resolve_module_handle(name: &str, main_image_base: u64, state: &WinApiState) -> u64 {
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
        _ => FAKE_GENERIC_MODULE,
    }
}

fn fake_module_handle_for_name(name: &str, main_image_base: u64, state: &WinApiState) -> u64 {
    resolve_module_handle(name, main_image_base, state)
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

fn fake_file_attributes_for_path(state: &WinApiState, path: &str) -> u64 {
    let normalized = path.trim();

    if normalized.is_empty() {
        return INVALID_FILE_ATTRIBUTES;
    }

    if normalized.ends_with('\\') || normalized.ends_with('/') {
        return FILE_ATTRIBUTE_DIRECTORY;
    }

    let lower = normalized.to_ascii_lowercase();

    if lower.ends_with(':')
        || lower.contains("\\windows")
        || lower.contains("/windows")
        || lower.contains("\\temp")
        || lower.contains("/temp")
    {
        return FILE_ATTRIBUTE_DIRECTORY;
    }

    if guest_path_exists(state, normalized) {
        return FILE_ATTRIBUTE_ARCHIVE;
    }

    // Keep historical permissive behavior for bootstrap probes of unknown paths.
    FILE_ATTRIBUTE_ARCHIVE
}

fn fake_find_file_name_for_pattern(pattern: &str) -> String {
    let trimmed = pattern.trim();

    if trimmed.is_empty() {
        return String::new();
    }

    let normalized = trimmed.replace('\\', "/");

    if normalized.ends_with("/*") || normalized.ends_with("/*.*") {
        return ".".to_owned();
    }

    normalized
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(".")
        .to_owned()
}

fn write_find_data_common(
    engine: &mut dyn wie_cpu::CpuEngine,
    find_data_ptr: u64,
    attributes: u32,
) -> Result<()> {
    if find_data_ptr == 0 {
        return Ok(());
    }

    let attributes_address =
        checked_field_address(find_data_ptr, 0, "WIN32_FIND_DATA.dwFileAttributes")?;
    let file_size_high_address =
        checked_field_address(find_data_ptr, 28, "WIN32_FIND_DATA.nFileSizeHigh")?;
    let file_size_low_address =
        checked_field_address(find_data_ptr, 32, "WIN32_FIND_DATA.nFileSizeLow")?;

    write_guest_u32(engine, attributes_address, attributes)?;
    write_guest_u32(engine, file_size_high_address, 0)?;
    write_guest_u32(engine, file_size_low_address, 0)?;

    Ok(())
}

fn write_find_data_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    find_data_ptr: u64,
    file_name: &str,
    attributes: u32,
) -> Result<()> {
    write_find_data_common(engine, find_data_ptr, attributes)?;

    if find_data_ptr == 0 {
        return Ok(());
    }

    // WIN32_FIND_DATAW.cFileName offset is 44.
    let file_name_address = checked_field_address(find_data_ptr, 44, "WIN32_FIND_DATAW.cFileName")?;

    let mut bytes = Vec::new();
    for unit in file_name.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    engine
        .mem_write(file_name_address, &bytes)
        .context("failed to write WIN32_FIND_DATAW.cFileName")?;

    Ok(())
}

fn write_find_data_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    find_data_ptr: u64,
    file_name: &str,
    attributes: u32,
) -> Result<()> {
    write_find_data_common(engine, find_data_ptr, attributes)?;

    if find_data_ptr == 0 {
        return Ok(());
    }

    // WIN32_FIND_DATAA.cFileName offset is also 44.
    let file_name_address = checked_field_address(find_data_ptr, 44, "WIN32_FIND_DATAA.cFileName")?;

    let mut bytes = file_name.as_bytes().to_vec();
    bytes.push(0);

    engine
        .mem_write(file_name_address, &bytes)
        .context("failed to write WIN32_FIND_DATAA.cFileName")?;

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
pub fn handle_get_current_thread_id(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(FAKE_CURRENT_THREAD_ID)
        .context("failed to return from GetCurrentThreadId")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: FAKE_CURRENT_THREAD_ID,
    })
}

/// Handles `KERNEL32.dll!HeapAlloc`.
pub fn handle_heap_alloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let heap_handle = engine.read_rcx()?;
    let _flags = engine.read_rdx()?;
    let size = engine.read_r8()?;

    let return_value = if heap_handle == 0 {
        0
    } else {
        state.heap.alloc_coherent(engine, size)
    };

    let return_address = engine.return_from_win64_api(return_value)?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!HeapFree`.
pub fn handle_heap_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _heap_handle = engine.read_rcx()?;
    let _flags = engine.read_rdx()?;
    let memory = engine.read_r8()?;

    // Windows HeapFree returns TRUE even for some invalid frees; free if live.
    if memory != 0 {
        let _ = state.heap.free_coherent(engine, memory);
    }

    let return_address = engine.return_from_win64_api(1)?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `KERNEL32.dll!HeapReAlloc`.
pub fn handle_heap_realloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let heap_handle = engine.read_rcx()?;
    let _flags = engine.read_rdx()?;
    let memory = engine.read_r8()?;
    let new_size = engine.read_r9()?;

    let return_value = if heap_handle == 0 || memory == 0 || new_size == 0 {
        0
    } else if let Some(same) = state.heap.try_realloc_in_place(memory, new_size) {
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
            0
        } else {
            let copy_len = usize::try_from(old_size.min(new_size)).unwrap_or(0);
            if copy_len > 0 {
                let mut bytes = vec![0_u8; copy_len];
                engine.mem_read(memory, &mut bytes)?;
                engine.mem_write(new_addr, &bytes)?;
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
        // RTL_CRITICAL_SECTION on Win64:
        // +0x00 DebugInfo      pointer
        // +0x08 LockCount      LONG, initialized to -1
        // +0x0c RecursionCount LONG
        // +0x10 OwningThread   HANDLE
        // +0x18 LockSemaphore  HANDLE
        // +0x20 SpinCount      ULONG_PTR
        let debug_info_address = checked_field_address(critical_section_ptr, 0, "DebugInfo")?;
        let lock_count_address = checked_field_address(critical_section_ptr, 8, "LockCount")?;
        let recursion_count_address =
            checked_field_address(critical_section_ptr, 12, "RecursionCount")?;
        let owning_thread_address =
            checked_field_address(critical_section_ptr, 16, "OwningThread")?;
        let lock_semaphore_address =
            checked_field_address(critical_section_ptr, 24, "LockSemaphore")?;
        let spin_count_address = checked_field_address(critical_section_ptr, 32, "SpinCount")?;

        write_guest_u64(engine, debug_info_address, 0)?;
        write_guest_u32(engine, lock_count_address, u32::MAX)?;
        write_guest_u32(engine, recursion_count_address, 0)?;
        write_guest_u64(engine, owning_thread_address, 0)?;
        write_guest_u64(engine, lock_semaphore_address, 0)?;
        write_guest_u64(engine, spin_count_address, 0)?;
    }

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from InitializeCriticalSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!EnterCriticalSection`.
pub fn handle_enter_critical_section(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _critical_section_ptr = engine
        .read_rcx()
        .context("failed to read RCX for EnterCriticalSection")?;

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
) -> Result<WinApiHandlerResult> {
    let _critical_section_ptr = engine
        .read_rcx()
        .context("failed to read RCX for LeaveCriticalSection")?;

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from LeaveCriticalSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Handles `KERNEL32.dll!DeleteCriticalSection`.
pub fn handle_delete_critical_section(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _critical_section_ptr = engine
        .read_rcx()
        .context("failed to read RCX for DeleteCriticalSection")?;

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from DeleteCriticalSection")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
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
        _ => 0,
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
        STD_INPUT_HANDLE_VALUE | STD_OUTPUT_HANDLE_VALUE | STD_ERROR_HANDLE_VALUE => FILE_TYPE_CHAR,
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
    let _code_page = engine
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
    let bytes = utf16_units_to_multibyte(&units)?;

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
    let sbcs = matches!(code_page & 0xffff_ffff, 0 | 1 | 2 | 3 | 437 | 1252);
    let units = if sbcs {
        multibyte_bytes_to_utf16_sbcs(&input_bytes)
    } else {
        multibyte_bytes_to_utf16_units(&input_bytes)?
    };

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
fn multibyte_bytes_to_utf16_sbcs(bytes: &[u8]) -> Vec<u16> {
    bytes.iter().map(|b| u16::from(*b)).collect()
}

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
pub fn handle_get_module_file_name_a(
    engine: &mut dyn wie_cpu::CpuEngine,
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

    let return_value =
        copy_bytes_to_guest_buffer(engine, module_file_name_a_ptr, buffer_ptr, buffer_len)?;

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

    let return_value =
        copy_wide_string_to_guest_buffer(engine, module_file_name_w_ptr, buffer_ptr, buffer_len)?;

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
pub fn handle_load_library_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: crate::WinApiEnvironment,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let library_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for LoadLibraryA")?;

    let library_name = read_ansi_string_from_cpu(engine, library_name_ptr, 260)?;
    let return_value = fake_module_handle_for_name(&library_name, environment.image_base, state);

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
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let library_name_ptr = engine
        .read_rcx()
        .context("failed to read RCX for LoadLibraryW")?;

    let library_name = read_wide_string_from_cpu(engine, library_name_ptr, 260)?;
    let return_value = fake_module_handle_for_name(&library_name, environment.image_base, state);

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
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetFileAttributesA")?;

    let path = read_ansi_string_from_cpu(engine, path_ptr, 1024)?;
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_path = resolve_full_windows_path(&cwd, &path);
    let return_value = fake_file_attributes_for_path(state, &full_path);

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
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let path_ptr = engine
        .read_rcx()
        .context("failed to read RCX for GetFileAttributesW")?;

    let path = read_wide_string_from_cpu(engine, path_ptr, 1024)?;
    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_path = resolve_full_windows_path(&cwd, &path);
    let return_value = fake_file_attributes_for_path(state, &full_path);

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

    let return_value = if pattern.trim().is_empty() {
        state.last_error = ERROR_FILE_NOT_FOUND_U32;
        INVALID_HANDLE_VALUE
    } else {
        let file_name = fake_find_file_name_for_pattern(&pattern);
        let attributes_u64 = fake_file_attributes_for_path(state, &pattern);
        let attributes = u32::try_from(attributes_u64 & 0xffff_ffff)
            .context("FindFirstFileW attributes do not fit u32")?;

        write_find_data_w(engine, find_data_ptr, &file_name, attributes)?;

        let handle = state.next_find_handle;
        state.next_find_handle = state
            .next_find_handle
            .checked_add(1)
            .context("find handle overflow")?;

        state.find_handles.push(FindHandle {
            handle,
            pattern,
            consumed: true,
        });

        state.last_error = 0;
        handle
    };

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

    let return_value = if pattern.trim().is_empty() {
        state.last_error = ERROR_FILE_NOT_FOUND_U32;
        INVALID_HANDLE_VALUE
    } else {
        let file_name = fake_find_file_name_for_pattern(&pattern);
        let attributes_u64 = fake_file_attributes_for_path(state, &pattern);
        let attributes = u32::try_from(attributes_u64 & 0xffff_ffff)
            .context("FindFirstFileA attributes do not fit u32")?;

        write_find_data_a(engine, find_data_ptr, &file_name, attributes)?;

        let handle = state.next_find_handle;
        state.next_find_handle = state
            .next_find_handle
            .checked_add(1)
            .context("find handle overflow")?;

        state.find_handles.push(FindHandle {
            handle,
            pattern,
            consumed: true,
        });

        state.last_error = 0;
        handle
    };

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from FindFirstFileA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Handles `KERNEL32.dll!FindNextFileW`.
pub fn handle_find_next_file_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let find_handle = engine
        .read_rcx()
        .context("failed to read RCX for FindNextFileW")?;

    let _find_data_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FindNextFileW")?;

    let valid = state.find_handles.iter().any(|h| h.handle == find_handle);
    state.last_error = if valid {
        ERROR_NO_MORE_FILES
    } else {
        ERROR_INVALID_HANDLE
    };

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from FindNextFileW")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
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

    let _find_data_ptr = engine
        .read_rdx()
        .context("failed to read RDX for FindNextFileA")?;

    let valid = state.find_handles.iter().any(|h| h.handle == find_handle);
    state.last_error = if valid {
        ERROR_NO_MORE_FILES
    } else {
        ERROR_INVALID_HANDLE
    };

    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from FindNextFileA")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
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
    let return_value = fake_module_handle_for_name(&library_name, environment.image_base, state);

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
    let return_value = fake_module_handle_for_name(&library_name, environment.image_base, state);

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
pub fn handle_close_handle(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine
        .read_rcx()
        .context("failed to read RCX for CloseHandle")?;

    // Flush written bytes to virtual store and/or bottle host path.
    if let Some(open_file) = find_open_file(state, handle) {
        let path = open_file.path.clone();
        sync_open_bytes_to_virtual(state, &path, handle);
    }
    persist_open_file_to_host(state, handle);

    let _ = crate::guest_io_host::unregister_open_file(engine, state, handle).ok();
    state.open_files.remove(&handle);

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from CloseHandle")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
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

        let file_size =
            u64::try_from(open_file.bytes.len()).context("open file size does not fit u64")?;

        write_guest_u32(engine, attributes_address, FILE_ATTRIBUTE_ARCHIVE_U32)?;
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

fn normalize_guest_path(path: &str) -> String {
    path.trim()
        .trim_matches('"')
        .replace('/', "\\")
        .to_ascii_lowercase()
}

fn guest_basename(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

fn paths_match_guest(requested: &str, candidate: &str) -> bool {
    let requested_norm = normalize_guest_path(requested);
    let candidate_norm = normalize_guest_path(candidate);

    requested_norm == candidate_norm
        || guest_basename(&requested_norm) == guest_basename(&candidate_norm)
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

    let cwd = String::from_utf16_lossy(&state.current_directory_wide);
    let full_path = resolve_full_windows_path(&cwd, guest_path);

    let bottle_host = state
        .bottle_root
        .as_ref()
        .and_then(|root| crate::guest_path_to_host(root, &full_path));
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
    let mut bytes =
        resolve_guest_file_bytes(state, guest_path).map_err(|_| ERROR_FILE_NOT_FOUND)?;
    if truncate {
        bytes.clear();
    }
    let host_path = bottle_host.cloned().or_else(|| {
        state
            .host_file_mounts
            .iter()
            .find(|m| paths_match_guest(guest_path, &m.guest_path))
            .map(|m| m.host_path.clone())
    });
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
        return allocate_open_file(state, guest_path, Vec::new(), Some(host.clone()))
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

    if let Some(root) = state.bottle_root.as_ref()
        && let Some(host) = crate::guest_path_to_host(root, guest_path)
        && host.is_file()
    {
        return std::fs::read(&host).with_context(|| {
            format!(
                "failed to read bottle file {} for guest path {guest_path}",
                host.display()
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
    let handle = state.next_file_handle;

    state.next_file_handle = state
        .next_file_handle
        .checked_add(1)
        .context("guest file handle allocator overflow")?;

    state.open_files.insert(
        handle,
        OpenGuestFile {
            handle,
            path: path.to_owned(),
            bytes,
            cursor: 0,
            host_path,
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

/// Flush open-file buffer to bottle/mount host path when present.
fn persist_open_file_to_host(state: &WinApiState, handle: u64) {
    let Some(open_file) = find_open_file(state, handle) else {
        return;
    };
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
    if let Some(root) = state.bottle_root.as_ref()
        && let Some(host) = crate::guest_path_to_host(root, path)
        && host.is_file()
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
    let as_path = Path::new(path);
    as_path.is_absolute() && as_path.is_file()
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

            let file_size =
                u64::try_from(open_file.bytes.len()).context("open file size does not fit u64")?;
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
        let file_size =
            u64::try_from(open_file.bytes.len()).context("open file size does not fit u64")?;

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
pub fn handle_initialize_critical_section_and_spin_count(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let critical_section_ptr = engine
        .read_rcx()
        .context("failed to read RCX for InitializeCriticalSectionAndSpinCount")?;

    let _spin_count = engine
        .read_rdx()
        .context("failed to read RDX for InitializeCriticalSectionAndSpinCount")?;

    if critical_section_ptr != 0 {
        // RTL_CRITICAL_SECTION approximation:
        // DebugInfo      offset 0
        // LockCount      offset 8
        // RecursionCount offset 12
        // OwningThread   offset 16
        // LockSemaphore  offset 24
        // SpinCount      offset 32
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
            0,
        )?;
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
pub fn handle_read_file(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let handle = engine.read_rcx()?;
    let buffer_ptr = engine.read_rdx()?;
    let bytes_to_read = engine.read_r8()?;
    let bytes_read_ptr = engine.read_r9()?;

    let success = buffer_ptr != 0 && is_open_file_handle(state, handle);

    if success {
        let _ = crate::guest_io_host::sync_host_cursor_from_guest(engine, state, handle).ok();
        // Phase 1: advance cursor and capture slice bounds without cloning the path/body.
        let (start, end, cursor_after, is_exe) = {
            let (cursor_usize, end, cursor_after, path_for_exe) = {
                let open_file = find_open_file_mut(state, handle)
                    .context("open file vanished during ReadFile")?;

                let cursor_before = open_file.cursor;
                let cursor_usize =
                    usize::try_from(cursor_before).context("file cursor does not fit usize")?;
                let requested = usize::try_from(bytes_to_read)
                    .context("ReadFile byte count does not fit usize")?;
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
    } else {
        if bytes_read_ptr != 0 {
            write_guest_u32(engine, bytes_read_ptr, 0)?;
        }
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

    let success = buffer_ptr != 0 && is_open_file_handle(state, handle);

    if success {
        let write_len =
            usize::try_from(bytes_to_write).context("WriteFile byte count does not fit usize")?;

        let mut data = vec![0_u8; write_len];
        if write_len > 0 {
            engine
                .mem_read(buffer_ptr, &mut data)
                .context("failed to read WriteFile source buffer")?;
        }

        let (path, cursor_before, cursor_after, file_size) = {
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
            let file_size = open_file.bytes.len();
            (path, cursor_before, cursor_after, file_size)
        };

        // Persist writes into the virtual-file store and bottle host path.
        sync_open_bytes_to_virtual(state, &path, handle);
        persist_open_file_to_host(state, handle);

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

        if bytes_written_ptr != 0 {
            write_guest_u32(engine, bytes_written_ptr, 0)?;
        }

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
fn sync_open_bytes_to_virtual(state: &mut WinApiState, path: &str, handle: u64) {
    let Some(bytes) = find_open_file(state, handle).map(|file| file.bytes.clone()) else {
        return;
    };

    if let Some(virtual_file) = state
        .virtual_files
        .iter_mut()
        .find(|entry| paths_match_guest(path, &entry.guest_path))
    {
        virtual_file.bytes = bytes;
        return;
    }

    // Host-mounted files stay host-backed on re-open; still keep a virtual overlay so
    // same-session re-opens of written companions work if mount is absent.
    if !state
        .host_file_mounts
        .iter()
        .any(|mount| paths_match_guest(path, &mount.guest_path))
        && !is_main_module_path(state, path)
    {
        state.virtual_files.push(crate::VirtualGuestFile {
            guest_path: path.to_owned(),
            bytes,
        });
    }
}

/// Handles `KERNEL32.dll!GetCurrentDirectoryW`.
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

    let return_value = if buffer_length == 0 || buffer_ptr == 0 || buffer_length <= character_count
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
            state.current_directory_wide = full.encode_utf16().collect();
            state.last_error = 0;
            true
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

/// Extra KERNEL32 exports used by CRT / modern PE (not yet in dense WinApiId table).
pub fn dispatch_kernel32_extra(
    engine: &mut dyn wie_cpu::CpuEngine,
    _environment: crate::WinApiEnvironment,
    state: &mut WinApiState,
    name: &str,
) -> Result<Option<WinApiHandlerResult>> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "virtualprotect" => Ok(Some(handle_virtual_protect(engine, state)?)),
        "virtualquery" => Ok(Some(handle_virtual_query(engine, state)?)),
        "tlsgetvalue" => Ok(Some(handle_tls_get_value(engine, state)?)),
        "tlssetvalue" => Ok(Some(handle_tls_set_value(engine, state)?)),
        "tlsalloc" => Ok(Some(handle_tls_alloc(engine, state)?)),
        "tlsfree" => Ok(Some(handle_tls_free(engine, state)?)),
        _ => Ok(None),
    }
}

/// `VirtualProtect` — accept and report success (no real page protection model yet).
fn handle_virtual_protect(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _addr = engine.read_rcx()?;
    let _size = engine.read_rdx()?;
    let _new = engine.read_r8()?;
    let old_prot = engine.read_r9()?;
    if old_prot != 0 {
        // PAGE_EXECUTE_READWRITE
        write_guest_u32(engine, old_prot, 0x40)?;
    }
    state.last_error = 0;
    let return_address = engine.return_from_win64_api(1)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// `VirtualQuery` — fill a minimal `MEMORY_BASIC_INFORMATION` for mapped ranges.
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

    // MEMORY_BASIC_INFORMATION (x64): BaseAddress, AllocationBase, AllocationProtect,
    // RegionSize, State, Protect, Type — 7×u64/u32 layout simplified as zeros + committed.
    let page_base = address & !0xfff;
    let mut mbi = [0_u8; 48];
    mbi[0..8].copy_from_slice(&page_base.to_le_bytes());
    mbi[8..16].copy_from_slice(&page_base.to_le_bytes());
    mbi[16..20].copy_from_slice(&0x40_u32.to_le_bytes()); // AllocationProtect
    mbi[24..32].copy_from_slice(&0x1000_u64.to_le_bytes()); // RegionSize
    mbi[32..36].copy_from_slice(&0x1000_u32.to_le_bytes()); // MEM_COMMIT
    mbi[36..40].copy_from_slice(&0x40_u32.to_le_bytes()); // Protect
    mbi[40..44].copy_from_slice(&0x20000_u32.to_le_bytes()); // MEM_PRIVATE
    engine.mem_write(buffer, &mbi)?;
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
    let value = state
        .tls_slots
        .get(usize::try_from(index).unwrap_or(usize::MAX))
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
    if idx >= state.tls_slots.len() {
        state.tls_slots.resize(idx.saturating_add(1), 0);
    }
    if let Some(slot) = state.tls_slots.get_mut(idx) {
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
    let index = u64::try_from(state.tls_slots.len()).unwrap_or(u64::MAX);
    state.tls_slots.push(0);
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
    if let Some(slot) = state.tls_slots.get_mut(index) {
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
/// Idle policy:
/// - `Sleep(0)` always yields the host thread (`yield_now`) — cheap cooperative park.
/// - Non-zero sleeps: by default a **no-op** so smokes/diff-traces stay deterministic
///   and fast. Set `WIE_HOST_SLEEP=1` to park the host thread for up to 60s
///   (interactive / idle CPU).
pub fn handle_sleep(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let milliseconds = engine.read_rcx().context("failed to read RCX for Sleep")?;
    let low32 = milliseconds & u64::from(u32::MAX);

    if low32 == 0 {
        // Guest idle spin: park briefly so a tight Sleep(0) loop does not burn a core.
        std::thread::yield_now();
    } else if host_sleep_enabled() {
        // INFINITE / huge values: cap so the host cannot hang forever.
        let ms = low32.min(60_000);
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }

    let return_value = 0;

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from Sleep")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

/// Whether `Sleep(n>0)` should block the host thread (`WIE_HOST_SLEEP=1`).
fn host_sleep_enabled() -> bool {
    std::env::var_os("WIE_HOST_SLEEP").is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
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

fn normalize_windows_path_separators(path: &str) -> String {
    path.chars()
        .map(|character| if character == '/' { '\\' } else { character })
        .collect()
}

fn is_windows_absolute_path(path: &str) -> bool {
    let bytes = path.as_bytes();

    let has_drive_prefix = bytes.get(1).is_some_and(|value| *value == b':')
        && bytes.get(2).is_some_and(|value| *value == b'\\');

    let has_unc_prefix = bytes.first() == Some(&b'\\') && bytes.get(1) == Some(&b'\\');

    has_drive_prefix || has_unc_prefix
}

fn join_windows_path(base: &str, relative: &str) -> String {
    let mut joined = base.trim_end_matches('\\').to_owned();

    if !joined.is_empty() {
        joined.push('\\');
    }

    joined.push_str(relative);
    joined
}

fn normalize_windows_path_components(path: &str) -> String {
    let normalized = normalize_windows_path_separators(path);

    let mut prefix = String::new();
    let mut remainder = normalized.as_str();

    let bytes = normalized.as_bytes();

    if bytes.get(1).is_some_and(|value| *value == b':') {
        if let Some(drive) = normalized.get(..2) {
            prefix.push_str(drive);
        }

        remainder = normalized.get(2..).unwrap_or_default();

        if remainder.starts_with('\\') {
            prefix.push('\\');
            remainder = remainder.trim_start_matches('\\');
        }
    } else if normalized.starts_with("\\\\") {
        prefix.push_str("\\\\");
        remainder = normalized.strip_prefix("\\\\").unwrap_or_default();
    }

    let mut components = Vec::<String>::new();

    for component in remainder.split('\\') {
        match component {
            "" | "." => {}
            ".." => {
                let _removed = components.pop();
            }
            _ => components.push(component.to_owned()),
        }
    }

    let mut result = prefix;

    for component in components {
        if !result.is_empty() && !result.ends_with('\\') {
            result.push('\\');
        }

        result.push_str(&component);
    }

    result
}

/// Resolve a Windows path against the process current directory.
///
/// Clean room (Microsoft Learn path forms):
/// - Absolute: `C:\…`, `\\server\share\…`
/// - Drive-relative / relative: `file`, `.\file`, `subdir\file`, `..\file`
/// - Rooted on current drive: `\file` → `{drive}:\file`
fn resolve_full_windows_path(current_directory: &str, input_path: &str) -> String {
    let normalized_input = normalize_windows_path_separators(input_path);
    let cwd = normalize_windows_path_separators(current_directory);

    let combined = if is_windows_absolute_path(&normalized_input) {
        normalized_input
    } else if normalized_input.starts_with('\\') {
        // `\foo` is rooted on the current drive (not a UNC path — those start with `\\`).
        let drive = cwd
            .get(..2)
            .filter(|d| d.as_bytes().get(1) == Some(&b':'))
            .unwrap_or("C:");
        format!("{drive}{normalized_input}")
    } else {
        join_windows_path(&cwd, &normalized_input)
    };

    normalize_windows_path_components(&combined)
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
