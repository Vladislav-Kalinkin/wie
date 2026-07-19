use crate::guest_memory::{
    checked_address, read_u64 as read_guest_u64, write_u32 as write_guest_u32,
    write_u64 as write_guest_u64,
};
use crate::guest_string::{
    read_ansi_lossy as read_guest_ansi_lossy, read_utf16_lossy as read_guest_utf16_lossy,
};
use crate::{RegistryKey, WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

const ERROR_SUCCESS: u64 = 0;
const ERROR_FILE_NOT_FOUND: u64 = 2;
const REG_CREATED_NEW_KEY: u32 = 1;
const REG_OPENED_EXISTING_KEY: u32 = 2;

/// Handles `ADVAPI32.dll!RegCreateKeyExA`.
pub fn handle_reg_create_key_ex_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let parent_key = engine
        .read_rcx()
        .context("failed to read RCX for RegCreateKeyExA")?;

    let subkey_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegCreateKeyExA")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for RegCreateKeyExA")?;

    let phk_result_address = checked_address(rsp, 0x40, "RegCreateKeyExA phkResult")?;
    let disposition_address = checked_address(rsp, 0x48, "RegCreateKeyExA lpdwDisposition")?;

    let phk_result = read_guest_u64(engine, phk_result_address)?;
    let disposition_ptr = read_guest_u64(engine, disposition_address)?;

    let subkey = read_optional_ansi_string(engine, subkey_ptr)?;

    let (handle, disposition) = open_or_create_registry_key(state, parent_key, subkey)?;

    if phk_result != 0 {
        write_guest_u64(engine, phk_result, handle)?;
    }

    if disposition_ptr != 0 {
        write_guest_u32(engine, disposition_ptr, disposition)?;
    }

    return_status(engine, ERROR_SUCCESS)
}

/// Handles `ADVAPI32.dll!RegOpenKeyExA`.
pub fn handle_reg_open_key_ex_a(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let parent_key = engine
        .read_rcx()
        .context("failed to read RCX for RegOpenKeyExA")?;

    let subkey_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegOpenKeyExA")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for RegOpenKeyExA")?;

    let phk_result_address = checked_address(rsp, 0x30, "RegOpenKeyExA phkResult")?;
    let phk_result = read_guest_u64(engine, phk_result_address)?;

    let subkey = read_optional_ansi_string(engine, subkey_ptr)?;
    let (handle, _disposition) = open_or_create_registry_key(state, parent_key, subkey)?;

    if phk_result != 0 {
        write_guest_u64(engine, phk_result, handle)?;
    }

    return_status(engine, ERROR_SUCCESS)
}

/// Handles `ADVAPI32.dll!RegOpenKeyExW`.
pub fn handle_reg_open_key_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let parent_key = engine
        .read_rcx()
        .context("failed to read RCX for RegOpenKeyExW")?;

    let subkey_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegOpenKeyExW")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for RegOpenKeyExW")?;

    let phk_result_address = checked_address(rsp, 0x30, "RegOpenKeyExW phkResult")?;
    let phk_result = read_guest_u64(engine, phk_result_address)?;

    let subkey = read_optional_utf16_string(engine, subkey_ptr)?;
    let (handle, _disposition) = open_or_create_registry_key(state, parent_key, subkey)?;

    if phk_result != 0 {
        write_guest_u64(engine, phk_result, handle)?;
    }

    return_status(engine, ERROR_SUCCESS)
}

/// Handles `ADVAPI32.dll!RegCreateKeyExW`.
pub fn handle_reg_create_key_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let parent_key = engine
        .read_rcx()
        .context("failed to read RCX for RegCreateKeyExW")?;

    let subkey_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegCreateKeyExW")?;

    let rsp = engine
        .read_rsp()
        .context("failed to read RSP for RegCreateKeyExW")?;

    let phk_result_address = checked_address(rsp, 0x40, "RegCreateKeyExW phkResult")?;
    let disposition_address = checked_address(rsp, 0x48, "RegCreateKeyExW lpdwDisposition")?;

    let phk_result = read_guest_u64(engine, phk_result_address)?;
    let disposition_ptr = read_guest_u64(engine, disposition_address)?;

    let subkey = read_optional_utf16_string(engine, subkey_ptr)?;
    let (handle, disposition) = open_or_create_registry_key(state, parent_key, subkey)?;

    if phk_result != 0 {
        write_guest_u64(engine, phk_result, handle)?;
    }

    if disposition_ptr != 0 {
        write_guest_u32(engine, disposition_ptr, disposition)?;
    }

    return_status(engine, ERROR_SUCCESS)
}

/// Soft-dispatch path for ADVAPI32 exports not yet in the dense `WinApiId` table.
pub fn dispatch_advapi32_extra(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    name: &str,
) -> Result<Option<WinApiHandlerResult>> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "regopenkeyexw" => Ok(Some(handle_reg_open_key_ex_w(engine, state)?)),
        "regcreatekeyexw" => Ok(Some(handle_reg_create_key_ex_w(engine, state)?)),
        "openprocesstoken" => Ok(Some(handle_open_process_token(engine, state)?)),
        "adjusttokenprivileges" => Ok(Some(handle_adjust_token_privileges(engine)?)),
        "lookupprivilegevaluew" | "lookupprivilegevaluea" => {
            Ok(Some(handle_lookup_privilege_value(engine)?))
        }
        "systemfunction036" => Ok(Some(handle_system_function036(engine)?)),
        "getfilesecurityw" | "getfilesecuritya" => Ok(Some(handle_get_file_security(engine)?)),
        "setfilesecurityw" | "setfilesecuritya" => Ok(Some(handle_set_file_security(engine)?)),
        _ => Ok(None),
    }
}

const FAKE_PROCESS_TOKEN: u64 = 0x0000_0000_7000_0001;

/// `BOOL OpenProcessToken(HANDLE ProcessHandle, DWORD DesiredAccess, PHANDLE TokenHandle)`.
fn handle_open_process_token(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _process = engine
        .read_rcx()
        .context("OpenProcessToken RCX")?;
    let _access = engine
        .read_rdx()
        .context("OpenProcessToken RDX")?;
    let token_out = engine
        .read_r8()
        .context("OpenProcessToken R8")?;
    if token_out != 0 {
        write_guest_u64(engine, token_out, FAKE_PROCESS_TOKEN)?;
    }
    state.last_error = 0;
    return_bool(engine, true)
}

/// `BOOL AdjustTokenPrivileges(...)` — succeed without changing privileges.
fn handle_adjust_token_privileges(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _token = engine.read_rcx()?;
    let _disable_all = engine.read_rdx()?;
    let _new_state = engine.read_r8()?;
    let _buf_len = engine.read_r9()?;
    return_bool(engine, true)
}

/// `BOOL LookupPrivilegeValueW(LPCWSTR, LPCWSTR, PLUID)`.
fn handle_lookup_privilege_value(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _system = engine.read_rcx()?;
    let _name = engine.read_rdx()?;
    let luid = engine.read_r8()?;
    if luid != 0 {
        // LUID is 8 bytes (LowPart + HighPart).
        write_guest_u64(engine, luid, 0x20)?; // arbitrary Se* privilege id
    }
    return_bool(engine, true)
}

/// `BOOLEAN SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength)` (RtlGenRandom).
fn handle_system_function036(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let buf = engine.read_rcx()?;
    let len = engine.read_rdx()? & 0xffff_ffff;
    let len_usize = usize::try_from(len).unwrap_or(0);
    if buf != 0 && len_usize > 0 {
        // Deterministic pseudo-random fill (not crypto-grade; enough for 7z nonces).
        let mut bytes = vec![0_u8; len_usize];
        let mut state = 0x00c0_ffee_u64;
        for b in &mut bytes {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1);
            *b = u8::try_from((state >> 33) & 0xff).unwrap_or(0);
        }
        engine
            .mem_write(buf, &bytes)
            .context("SystemFunction036 write")?;
    }
    // BOOLEAN TRUE
    return_bool(engine, true)
}

/// Minimal security descriptor size claim for `GetFileSecurity*`.
const FAKE_SD_NEED: u32 = 20;

/// `BOOL GetFileSecurityW(...)` — report not enough buffer / fail soft.
fn handle_get_file_security(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _path = engine.read_rcx()?;
    let _si = engine.read_rdx()?;
    let sd = engine.read_r8()?;
    let len = engine.read_r9()? & 0xffff_ffff;
    let rsp = engine.read_rsp()?;
    let needed_ptr = read_guest_u64(
        engine,
        checked_address(rsp, 0x28, "GetFileSecurity length needed")?,
    )?;
    if needed_ptr != 0 {
        write_guest_u32(engine, needed_ptr, FAKE_SD_NEED)?;
    }
    if sd != 0 && len >= u64::from(FAKE_SD_NEED) {
        // Zeroed SD stub.
        let need = usize::try_from(FAKE_SD_NEED).unwrap_or(20);
        let zeros = vec![0_u8; need];
        engine.mem_write(sd, &zeros)?;
        return return_bool(engine, true);
    }
    return_bool(engine, false)
}

/// `BOOL SetFileSecurityW(...)` — accept.
fn handle_set_file_security(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _path = engine.read_rcx()?;
    let _si = engine.read_rdx()?;
    let _sd = engine.read_r8()?;
    return_bool(engine, true)
}

fn return_bool(engine: &mut dyn wie_cpu::CpuEngine, ok: bool) -> Result<WinApiHandlerResult> {
    let v = u64::from(ok);
    let return_address = engine
        .return_from_win64_api(v)
        .context("failed to return BOOL from ADVAPI32")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: v,
    })
}

/// Handles `ADVAPI32.dll!RegQueryValueExA`.
pub fn handle_reg_query_value_ex_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _key = engine
        .read_rcx()
        .context("failed to read RCX for RegQueryValueExA")?;
    let _value_name_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegQueryValueExA")?;

    return_status(engine, ERROR_FILE_NOT_FOUND)
}

/// Handles `ADVAPI32.dll!RegQueryValueExW`.
pub fn handle_reg_query_value_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _key = engine
        .read_rcx()
        .context("failed to read RCX for RegQueryValueExW")?;
    let _value_name_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegQueryValueExW")?;

    return_status(engine, ERROR_FILE_NOT_FOUND)
}

/// Handles `ADVAPI32.dll!RegSetValueExA`.
pub fn handle_reg_set_value_ex_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _key = engine
        .read_rcx()
        .context("failed to read RCX for RegSetValueExA")?;
    let _value_name_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegSetValueExA")?;

    return_status(engine, ERROR_SUCCESS)
}

/// Handles `ADVAPI32.dll!RegSetValueExW`.
pub fn handle_reg_set_value_ex_w(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _key = engine
        .read_rcx()
        .context("failed to read RCX for RegSetValueExW")?;
    let _value_name_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegSetValueExW")?;

    return_status(engine, ERROR_SUCCESS)
}

/// Handles `ADVAPI32.dll!RegDeleteValueA`.
pub fn handle_reg_delete_value_a(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _key = engine
        .read_rcx()
        .context("failed to read RCX for RegDeleteValueA")?;
    let _value_name_ptr = engine
        .read_rdx()
        .context("failed to read RDX for RegDeleteValueA")?;

    return_status(engine, ERROR_FILE_NOT_FOUND)
}

/// Handles `ADVAPI32.dll!RegCloseKey`.
pub fn handle_reg_close_key(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _key = engine
        .read_rcx()
        .context("failed to read RCX for RegCloseKey")?;

    return_status(engine, ERROR_SUCCESS)
}

/// Handles `ADVAPI32.dll!InitializeSecurityDescriptor`.
pub fn handle_initialize_security_descriptor(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let security_descriptor_ptr = engine
        .read_rcx()
        .context("failed to read RCX for InitializeSecurityDescriptor")?;

    if security_descriptor_ptr != 0 {
        // Minimal SECURITY_DESCRIPTOR-like marker. Enough for code that only
        // expects the call to succeed.
        write_guest_u32(engine, security_descriptor_ptr, 1)?;
    }

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from InitializeSecurityDescriptor")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
    })
}

/// Handles `ADVAPI32.dll!SetSecurityDescriptorDacl`.
pub fn handle_set_security_descriptor_dacl(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let security_descriptor_ptr = engine
        .read_rcx()
        .context("failed to read RCX for SetSecurityDescriptorDacl")?;
    let _dacl_present = engine
        .read_rdx()
        .context("failed to read RDX for SetSecurityDescriptorDacl")?;
    let _dacl_ptr = engine
        .read_r8()
        .context("failed to read R8 for SetSecurityDescriptorDacl")?;
    let _dacl_defaulted = engine
        .read_r9()
        .context("failed to read R9 for SetSecurityDescriptorDacl")?;

    let return_value = u64::from(security_descriptor_ptr != 0);

    let return_address = engine
        .return_from_win64_api(return_value)
        .context("failed to return from SetSecurityDescriptorDacl")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value,
    })
}

fn open_or_create_registry_key(
    state: &mut WinApiState,
    parent: u64,
    subkey: String,
) -> Result<(u64, u32)> {
    if let Some(existing) = state
        .registry_keys
        .iter()
        .find(|key| key.parent == parent && key.subkey == subkey)
    {
        return Ok((existing.handle, REG_OPENED_EXISTING_KEY));
    }

    let handle = state.next_registry_key_handle;
    state.next_registry_key_handle = state
        .next_registry_key_handle
        .checked_add(1)
        .context("registry key handle overflow")?;

    state.registry_keys.push(RegistryKey {
        handle,
        parent,
        subkey,
    });

    Ok((handle, REG_CREATED_NEW_KEY))
}

fn return_status(engine: &mut dyn wie_cpu::CpuEngine, status: u64) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(status)
        .context("failed to return registry status")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: status,
    })
}

fn read_optional_ansi_string(engine: &mut dyn wie_cpu::CpuEngine, address: u64) -> Result<String> {
    if address == 0 {
        Ok(String::new())
    } else {
        read_guest_ansi_lossy(engine, address, 1024)
    }
}

fn read_optional_utf16_string(engine: &mut dyn wie_cpu::CpuEngine, address: u64) -> Result<String> {
    if address == 0 {
        Ok(String::new())
    } else {
        read_guest_utf16_lossy(engine, address, 1024)
    }
}
