//! Minimal `OLEAUT32` surface for real tools (7za BSTR helpers).
//!
//! Clean-room stubs for ordinal imports used by MSVC-linked CLI tools.

use crate::{WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

/// Soft-dispatch path for OLEAUT32 (name or `ORDINAL N`).
pub fn dispatch_oleaut32(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    name: &str,
) -> Result<Option<WinApiHandlerResult>> {
    let n = name.to_ascii_lowercase();
    // Map well-known ordinals to handlers (Microsoft OLEAUT32 export ordinals).
    let key = match n.as_str() {
        "sysallocstring" | "ordinal 2" => "sysallocstring",
        "sysreallocstring" | "ordinal 3" => "sysreallocstring",
        "sysallocstringlen" | "ordinal 4" => "sysallocstringlen",
        "sysreallocstringlen" | "ordinal 5" => "sysreallocstringlen",
        "sysfreestring" | "ordinal 6" => "sysfreestring",
        "sysstringlen" | "ordinal 7" => "sysstringlen",
        "sysstringbyteslen" | "ordinal 8" => "sysstringbyteslen",
        "variantclear" | "ordinal 9" => "variantclear",
        "variantcopy" | "ordinal 10" => "variantcopy",
        other => other,
    };
    match key {
        "sysallocstring" => Ok(Some(handle_sys_alloc_string(engine, state)?)),
        "sysallocstringlen" | "sysreallocstring" | "sysreallocstringlen" => {
            Ok(Some(handle_sys_alloc_string_len(engine, state)?))
        }
        "sysfreestring" => Ok(Some(handle_sys_free_string(engine, state)?)),
        "sysstringlen" => Ok(Some(handle_sys_string_len(engine)?)),
        "sysstringbyteslen" => Ok(Some(handle_sys_string_byte_len(engine)?)),
        "variantclear" => Ok(Some(handle_variant_clear(engine)?)),
        "variantcopy" => Ok(Some(handle_variant_copy(engine)?)),
        _ => Ok(None),
    }
}

fn ret(engine: &mut dyn wie_cpu::CpuEngine, value: u64) -> Result<WinApiHandlerResult> {
    let return_address = engine
        .return_from_win64_api(value)
        .context("OLEAUT32 return")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

/// BSTR layout: 4-byte length prefix (byte count), then UTF-16 data + 2-byte NUL.
fn alloc_bstr(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    units: &[u16],
) -> Result<u64> {
    let byte_len = u32::try_from(units.len().saturating_mul(2)).unwrap_or(0);
    // header(4) + data + NUL(2) + slop
    let total = 4_u64
        .saturating_add(u64::from(byte_len))
        .saturating_add(2)
        .saturating_add(8);
    let raw = state.heap.alloc_coherent(engine, total);
    if raw == 0 {
        return Ok(0);
    }
    let data = raw.wrapping_add(4);
    engine.mem_write(data.wrapping_sub(4), &byte_len.to_le_bytes())?;
    let mut bytes = Vec::with_capacity(units.len().saturating_mul(2).saturating_add(2));
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    bytes.extend_from_slice(&0_u16.to_le_bytes());
    engine.mem_write(data, &bytes)?;
    Ok(data)
}

/// `BSTR SysAllocString(const OLECHAR*)`.
fn handle_sys_alloc_string(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let src = engine.read_rcx()?;
    if src == 0 {
        return ret(engine, 0);
    }
    let mut units = Vec::new();
    let mut i = 0_u64;
    loop {
        let mut b = [0_u8; 2];
        engine.mem_read(src.wrapping_add(i.wrapping_mul(2)), &mut b)?;
        let w = u16::from_le_bytes(b);
        if w == 0 {
            break;
        }
        units.push(w);
        i = i.saturating_add(1);
        if i > 1_000_000 {
            break;
        }
    }
    let bstr = alloc_bstr(engine, state, &units)?;
    ret(engine, bstr)
}

/// `BSTR SysAllocStringLen(const OLECHAR*, UINT)`.
fn handle_sys_alloc_string_len(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let src = engine.read_rcx()?;
    let len = engine.read_rdx()? & 0xffff_ffff;
    let n = usize::try_from(len).unwrap_or(0);
    let mut units = vec![0_u16; n];
    if src != 0 && n > 0 {
        for (i, u) in units.iter_mut().enumerate() {
            let mut b = [0_u8; 2];
            let off = u64::try_from(i).unwrap_or(0).wrapping_mul(2);
            engine.mem_read(src.wrapping_add(off), &mut b)?;
            *u = u16::from_le_bytes(b);
        }
    }
    let bstr = alloc_bstr(engine, state, &units)?;
    ret(engine, bstr)
}

/// `void SysFreeString(BSTR)`.
fn handle_sys_free_string(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let bstr = engine.read_rcx()?;
    if bstr != 0 {
        // Free the allocation that includes the 4-byte length prefix.
        let _ = state.heap.free_coherent(engine, bstr.wrapping_sub(4));
    }
    ret(engine, 0)
}

/// `UINT SysStringLen(BSTR)`.
fn handle_sys_string_len(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let bstr = engine.read_rcx()?;
    if bstr == 0 {
        return ret(engine, 0);
    }
    let mut len_bytes = [0_u8; 4];
    engine.mem_read(bstr.wrapping_sub(4), &mut len_bytes)?;
    let byte_len = u32::from_le_bytes(len_bytes);
    ret(engine, u64::from(byte_len.wrapping_shr(1)))
}

/// `UINT SysStringByteLen(BSTR)`.
fn handle_sys_string_byte_len(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let bstr = engine.read_rcx()?;
    if bstr == 0 {
        return ret(engine, 0);
    }
    let mut len_bytes = [0_u8; 4];
    engine.mem_read(bstr.wrapping_sub(4), &mut len_bytes)?;
    ret(engine, u64::from(u32::from_le_bytes(len_bytes)))
}

/// `HRESULT VariantClear(VARIANTARG*)` — mark empty.
fn handle_variant_clear(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let pvar = engine.read_rcx()?;
    if pvar != 0 {
        // VARIANT: vt at offset 0 (2 bytes). VT_EMPTY = 0.
        engine.mem_write(pvar, &[0_u8; 16])?;
    }
    ret(engine, 0) // S_OK
}

/// `HRESULT VariantCopy(VARIANTARG* dest, const VARIANTARG* src)` — shallow memcpy 16 bytes.
fn handle_variant_copy(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let dest = engine.read_rcx()?;
    let src = engine.read_rdx()?;
    if dest != 0 && src != 0 {
        let mut buf = [0_u8; 16];
        engine.mem_read(src, &mut buf)?;
        engine.mem_write(dest, &buf)?;
    }
    ret(engine, 0)
}
