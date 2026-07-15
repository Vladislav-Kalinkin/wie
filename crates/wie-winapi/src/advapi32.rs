use crate::guest_memory::{
    checked_address, read_u64 as read_guest_u64, write_u32 as write_guest_u32,
    write_u64 as write_guest_u64,
};
use crate::guest_string::read_ansi_lossy as read_guest_ansi_lossy;
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
pub fn handle_reg_close_key(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
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
    let _security_descriptor_ptr = engine
        .read_rcx()
        .context("failed to read RCX for SetSecurityDescriptorDacl")?;

    let return_address = engine
        .return_from_win64_api(1)
        .context("failed to return from SetSecurityDescriptorDacl")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: 1,
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

fn return_status(
    engine: &mut dyn wie_cpu::CpuEngine,
    status: u64,
) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(status)
        .context("failed to return registry status")?;

    Ok(WinApiHandlerResult {
        return_address,
        return_value: status,
    })
}

fn read_optional_ansi_string(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
) -> Result<String> {
    if address == 0 {
        Ok(String::new())
    } else {
        read_guest_ansi_lossy(engine, address, 1024)
    }
}
