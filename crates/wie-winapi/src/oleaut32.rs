//! Minimal `OLEAUT32` surface for real tools (7za BSTR helpers).
//!
//! Clean-room stubs for ordinal imports used by MSVC-linked CLI tools.
//!
//! **Critical:** `VariantCopy` must deep-copy `VT_BSTR`. A shallow 24-byte memcpy
//! makes `CPropVariant::InternalCopy` share one BSTR; the source destructor then
//! frees it and leaves a dangling pointer in the destination — 7za method props
//! with non-numeric values (`-md=64k`, `-m0=Copy`, …) throw `E_INVALIDARG`.

use crate::{WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

/// `VARENUM` / `VARTYPE` for BSTR (owned resource — must deep-copy).
const VT_BSTR: u16 = 8;

/// Soft-dispatch path for OLEAUT32 (name or `ORDINAL N`).
pub fn dispatch_oleaut32(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    name: &str,
) -> Result<Option<WinApiHandlerResult>> {
    let n = name.to_ascii_lowercase();
    // OLEAUT32 export ordinals (Wine / Windows): 2 Alloc, 4 AllocLen, 6 Free,
    // 7 StringLen, 8 VariantInit, 9 VariantClear, 10 VariantCopy, 11 CopyInd.
    // SysStringByteLen is ordinal **149**, not 8.
    let key = match n.as_str() {
        "sysallocstring" | "ordinal 2" => "sysallocstring",
        "sysreallocstring" | "ordinal 3" => "sysreallocstring",
        "sysallocstringlen" | "ordinal 4" | "sysallocstringbytelen" | "ordinal 150" => {
            "sysallocstringlen"
        }
        "sysreallocstringlen" | "ordinal 5" => "sysreallocstringlen",
        "sysfreestring" | "ordinal 6" => "sysfreestring",
        "sysstringlen" | "ordinal 7" => "sysstringlen",
        "variantinit" | "ordinal 8" => "variantinit",
        "variantclear" | "ordinal 9" => "variantclear",
        // Ordinal 11 = VariantCopyInd; deep-copy path is enough for current guests.
        "variantcopy" | "ordinal 10" | "variantcopyind" | "ordinal 11" => "variantcopy",
        "sysstringbytelen" | "ordinal 149" => "sysstringbyteslen",
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
        "variantinit" => Ok(Some(handle_variant_init(engine)?)),
        "variantclear" => Ok(Some(handle_variant_clear(engine, state)?)),
        "variantcopy" => Ok(Some(handle_variant_copy(engine, state)?)),
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

/// `void VariantInit(VARIANTARG*)` — set VT_EMPTY.
fn handle_variant_init(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let pvar = engine.read_rcx()?;
    if pvar != 0 {
        engine.mem_write(pvar, &[0_u8; 24])?;
    }
    ret(engine, 0)
}

/// x64 `VARIANT` / `PROPVARIANT` payload size (vt + reserved + union).
const VARIANT_SIZE: usize = 24;
/// Offset of the union (`bstrVal`, `ulVal`, …) on x64.
const VARIANT_DATA_OFF: u64 = 8;

fn read_vt(engine: &mut dyn wie_cpu::CpuEngine, pvar: u64) -> Result<u16> {
    let mut vt_bytes = [0_u8; 2];
    engine.mem_read(pvar, &mut vt_bytes)?;
    Ok(u16::from_le_bytes(vt_bytes))
}

fn read_bstr_field(engine: &mut dyn wie_cpu::CpuEngine, pvar: u64) -> Result<u64> {
    let mut b = [0_u8; 8];
    engine.mem_read(pvar.wrapping_add(VARIANT_DATA_OFF), &mut b)?;
    Ok(u64::from_le_bytes(b))
}

fn free_bstr_if_any(engine: &mut dyn wie_cpu::CpuEngine, state: &mut WinApiState, bstr: u64) {
    if bstr != 0 {
        let _ = state.heap.free_coherent(engine, bstr.wrapping_sub(4));
    }
}

/// Clear a guest `VARIANT` in place (shared by `VariantClear` and `VariantCopy`).
fn variant_clear_at(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    pvar: u64,
) -> Result<()> {
    if pvar == 0 {
        return Ok(());
    }
    let vt = read_vt(engine, pvar)?;
    if vt == VT_BSTR {
        let bstr = read_bstr_field(engine, pvar)?;
        free_bstr_if_any(engine, state, bstr);
    }
    engine.mem_write(pvar, &[0_u8; VARIANT_SIZE])?;
    Ok(())
}

/// Deep-copy a BSTR (length prefix + UTF-16 payload), or 0 for null source.
fn dup_bstr(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    src_bstr: u64,
) -> Result<u64> {
    if src_bstr == 0 {
        return Ok(0);
    }
    let mut len_bytes = [0_u8; 4];
    engine.mem_read(src_bstr.wrapping_sub(4), &mut len_bytes)?;
    let byte_len = u32::from_le_bytes(len_bytes);
    let n_units = usize::try_from(byte_len.wrapping_shr(1)).unwrap_or(0);
    let mut units = vec![0_u16; n_units];
    for (i, u) in units.iter_mut().enumerate() {
        let mut b = [0_u8; 2];
        let off = u64::try_from(i).unwrap_or(0).wrapping_mul(2);
        engine.mem_read(src_bstr.wrapping_add(off), &mut b)?;
        *u = u16::from_le_bytes(b);
    }
    alloc_bstr(engine, state, &units)
}

/// `HRESULT VariantClear(VARIANTARG*)` — free owned resources and set `VT_EMPTY`.
fn handle_variant_clear(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let pvar = engine.read_rcx()?;
    variant_clear_at(engine, state, pvar)?;
    ret(engine, 0) // S_OK
}

/// `HRESULT VariantCopy(VARIANTARG* dest, const VARIANTARG* src)`.
///
/// Must **deep-copy** `VT_BSTR` (and clear `dest` first). Shallow memcpy is wrong:
/// 7-Zip `CPropVariant::InternalCopy` relies on this for method property values.
fn handle_variant_copy(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let dest = engine.read_rcx()?;
    let src = engine.read_rdx()?;
    if dest == 0 || src == 0 {
        // Real OLEAUT32 returns `E_INVALIDARG` for null pointers.
        return ret(engine, 0x8007_0057);
    }
    if dest == src {
        return ret(engine, 0);
    }

    let src_vt = read_vt(engine, src)?;

    // Free any resources currently owned by dest.
    variant_clear_at(engine, state, dest)?;

    if src_vt == VT_BSTR {
        let src_bstr = read_bstr_field(engine, src)?;
        let new_bstr = dup_bstr(engine, state, src_bstr)?;
        if src_bstr != 0 && new_bstr == 0 {
            // Out of memory.
            return ret(engine, 0x8007_000E);
        }
        // vt = VT_BSTR, reserved zeros, bstrVal = new_bstr
        engine.mem_write(dest, &VT_BSTR.to_le_bytes())?;
        engine.mem_write(dest.wrapping_add(2), &[0_u8; 6])?;
        engine.mem_write(dest.wrapping_add(VARIANT_DATA_OFF), &new_bstr.to_le_bytes())?;
        // Zero high padding of the 24-byte VARIANT if any remainder exists.
        // Data field is 8 bytes at +8; total 16 used + 8 pad already covered by clear.
        return ret(engine, 0);
    }

    // Simple / non-owning types: bitwise copy of the 24-byte x64 VARIANT.
    // (VT_EMPTY, integers, bool, R8, FILETIME-as-i64, etc.)
    let mut buf = [0_u8; VARIANT_SIZE];
    engine.mem_read(src, &mut buf)?;
    engine.mem_write(dest, &buf)?;
    ret(engine, 0)
}
