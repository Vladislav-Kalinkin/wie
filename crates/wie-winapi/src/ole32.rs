//! Minimal `ole32.dll` stubs for COM-touching CLI tools (e.g. 7-Zip).

use crate::{WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

/// `S_OK`
const S_OK: u64 = 0;
/// `S_FALSE` — COM already initialized on this thread (acceptable).
#[allow(dead_code)]
const S_FALSE: u64 = 1;
/// `REGDB_E_CLASSNOTREG` — class not registered (no real COM servers).
const REGDB_E_CLASSNOTREG: u64 = 0x8004_0154;

fn ret(engine: &mut dyn wie_cpu::CpuEngine, value: u64) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(value)
        .context("ole32 return")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

/// Soft dispatch for `ole32.dll` exports used by real tools.
pub fn dispatch_ole32(
    engine: &mut dyn wie_cpu::CpuEngine,
    _state: &mut WinApiState,
    name: &str,
) -> Result<Option<WinApiHandlerResult>> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "coinitialize" => Ok(Some(handle_co_initialize(engine)?)),
        "coinitializeex" => Ok(Some(handle_co_initialize_ex(engine)?)),
        "couninitialize" => Ok(Some(handle_co_uninitialize(engine)?)),
        "cocreateinstance" => Ok(Some(handle_co_create_instance(engine)?)),
        _ => Ok(None),
    }
}

/// `HRESULT CoInitialize(LPVOID pvReserved)`
fn handle_co_initialize(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _reserved = engine.read_rcx()?;
    ret(engine, S_OK)
}

/// `HRESULT CoInitializeEx(LPVOID, DWORD)`
fn handle_co_initialize_ex(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _reserved = engine.read_rcx()?;
    let _coinit = engine.read_rdx()?;
    ret(engine, S_OK)
}

/// `void CoUninitialize(void)`
fn handle_co_uninitialize(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    ret(engine, 0)
}

/// `HRESULT CoCreateInstance(rclsid, pUnkOuter, dwClsContext, riid, ppv)`
///
/// No in-process COM servers in WIE yet — always `REGDB_E_CLASSNOTREG` and
/// zero `*ppv` so callers take the non-COM path.
fn handle_co_create_instance(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _clsid = engine.read_rcx()?;
    let _outer = engine.read_rdx()?;
    let _ctx = engine.read_r8()?;
    let _iid = engine.read_r9()?;
    // 5th arg on stack: void **ppv
    let rsp = engine.read_rsp()?;
    // Win64: home space 0x20 + return addr already consumed by call; at entry
    // after `return_from` setup the 5th param is at [rsp+0x28] from caller's view.
    // Handler is entered with RSP still pointing at return address (standard
    // our API stop convention matches other stack-arg handlers).
    let mut ppv_bytes = [0_u8; 8];
    // After call, [RSP]=retaddr, shadow 0x20, 5th at RSP+0x28.
    engine.mem_read(rsp.wrapping_add(0x28), &mut ppv_bytes)?;
    let ppv = u64::from_le_bytes(ppv_bytes);
    if ppv != 0 {
        engine.mem_write(ppv, &0_u64.to_le_bytes())?;
    }
    ret(engine, REGDB_E_CLASSNOTREG)
}
