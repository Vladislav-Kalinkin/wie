//! Dispatch for Mingw runtime DLLs (libwinpthread-1, libstdc++-6).
//!
//! When a PE dynamically links against these DLLs, their exports are
//! patched to fake VAs and dispatched here.  Simple stubs suffice for
//! most functions since WIE manages the runtime environment directly.

use crate::{WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

/// Dispatch `libwinpthread-1.dll` exports.  All functions return 0 (success).
pub fn dispatch_pthread(
    engine: &mut dyn wie_cpu::CpuEngine,
    name: &str,
) -> Result<WinApiHandlerResult> {
    let _ = name; // unused — all pthread stubs return success
    let return_address = engine
        .return_from_win64_api(0)
        .context("failed to return from pthread function")?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: 0,
    })
}

/// Dispatch `libstdc++-6.dll` exports (C++ runtime).
pub fn dispatch_stdcpp(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    name: &str,
) -> Result<WinApiHandlerResult> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        // __cxa_allocate_exception(size) → guest heap alloc
        "__cxa_allocate_exception" => {
            let size = engine.read_rcx()?;
            let addr = state.heap.alloc_coherent(engine, size.max(1));
            let return_address = engine
                .return_from_win64_api(addr)
                .context("failed to return from __cxa_allocate_exception")?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: addr,
            })
        }
        // __cxa_free_exception(ptr) → guest heap free
        "__cxa_free_exception" => {
            let ptr = engine.read_rcx()?;
            if ptr != 0 {
                state.heap.free_coherent(engine, ptr);
            }
            let return_address = engine
                .return_from_win64_api(0)
                .context("failed to return from __cxa_free_exception")?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 0,
            })
        }
        // __cxa_begin_catch / __cxa_end_catch → no-ops inside the catch block
        "__cxa_begin_catch" | "__cxa_end_catch" => {
            let return_address = engine
                .return_from_win64_api(0)
                .context("failed to return from __cxa_{begin,end}_catch")?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 0,
            })
        }
        // __cxa_throw(obj, typeinfo, destructor) — must NOT return.
        // Build an EXCEPTION_RECORD and dispatch via handle_raise_exception.
        "__cxa_throw" => {
            let exc_obj = engine.read_rcx()?; // save before clobbering
            let typeinfo = engine.read_rdx()?;
            let _destructor = engine.read_r8()?;
            // Construct EXCEPTION_RECORD at a scratch area on the guest stack.
            let rip = engine.read_rip()?;
            let rsp = engine.read_rsp()?;
            let rec = rsp.saturating_sub(0x100);
            engine
                .mem_write(rec, &0xE06D_7363_u32.to_le_bytes())
                .context("exc code")?;
            engine
                .mem_write(rec.saturating_add(4), &0_u32.to_le_bytes())
                .context("exc flags")?;
            engine
                .mem_write(rec.saturating_add(8), &[0u8; 8])
                .context("exc record")?;
            engine
                .mem_write(rec.saturating_add(16), &rip.to_le_bytes())
                .context("exc addr")?;
            engine
                .mem_write(rec.saturating_add(24), &3_u32.to_le_bytes())
                .context("num params")?;
            engine
                .mem_write(rec.saturating_add(32), &0x1993_0522_u64.to_le_bytes())
                .context("param0")?;
            engine
                .mem_write(rec.saturating_add(40), &exc_obj.to_le_bytes())
                .context("param1")?;
            engine
                .mem_write(rec.saturating_add(48), &typeinfo.to_le_bytes())
                .context("param2")?;

            // Set RCX to point to the record and dispatch.
            engine.write_rcx(rec)?;
            crate::kernel32::handle_raise_exception(engine, state)
        }
        // Generic fallback: stub (return success).
        _ => {
            let return_address = engine
                .return_from_win64_api(0)
                .context("failed to return from libstdc++ function")?;
            Ok(WinApiHandlerResult {
                return_address,
                return_value: 0,
            })
        }
    }
}
