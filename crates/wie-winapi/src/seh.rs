//! SEH exception dispatcher for Win64.
//!
//! Two-pass dispatch model:
//! - Pass 1 (search): walk the stack, find a frame with a matching handler
//! - Pass 2 (unwind): walk from throw site to handler, restore nonvolatiles,
//!   install landing pad
//!
//! Supports:
//! - **Mingw / Itanium LSDA** (host parse of call-site table)
//! - **MSVC FuncInfo** (host parse for `_CxxThrowException` / 7za path)

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use crate::exception::{self, UnwindContext};
use crate::msvc_eh;
use crate::{WinApiHandlerResult, WinApiState};
use anyhow::Result;
use wie_cpu::ThreadContext;

/// Guest memory reader: `fn(guest_va, buffer) -> Result<(), ()>`.
type MemRead<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), ()> + 'a;

const MAX_FRAMES: usize = 64;

/// Handler frame discovered during pass 1.
struct HandlerFound {
    landing_pad: u64,
    /// Register state of the catching frame (at the control PC inside it).
    catch_ctx: UnwindContext,
    /// Optional exception object to surface for the catch (MSVC / Mingw).
    exception_object: Option<u64>,
}

/// Optional C++ throw payload attached to a dispatch (MSVC `_CxxThrowException`).
#[derive(Debug, Clone, Copy, Default)]
pub struct ThrowPayload {
    pub exception_object: u64,
    pub throw_info: u64,
}

// ═══════════════════════════════════════════════════════════════════════
// Entry points
// ═══════════════════════════════════════════════════════════════════════

/// `RaiseException` entry: throw site = return address of the API call.
pub fn dispatch_exception(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    dispatch_exception_with_payload(engine, state, ThrowPayload::default())
}

/// Dispatch with an optional C++ throw payload (MSVC path).
pub fn dispatch_exception_with_payload(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    payload: ThrowPayload,
) -> Result<WinApiHandlerResult> {
    let tctx = engine.snapshot_thread_context();
    let rsp = engine.read_rsp()?;
    let mut ra_buf = [0u8; 8];
    engine
        .mem_read(rsp, &mut ra_buf)
        .map_err(|e| anyhow::anyhow!("RaiseException: failed to read return address: {e}"))?;
    let throw_rip = u64::from_le_bytes(ra_buf);
    let throw_rsp = rsp.saturating_add(8);

    let handler = search(engine, state, &tctx, throw_rip, throw_rsp, payload)?;
    install(engine, state, &tctx, throw_rip, throw_rsp, &handler)
}

/// `RtlUnwindEx`-style forced unwind to `target_ip` (and optional target frame RSP).
///
/// Walks from the caller's frame, restoring nonvolatiles each step. Stops when
/// the establisher RSP matches `target_frame_rsp`, or the walk is exhausted.
/// Then sets RIP to `target_ip` (if non-zero) and RAX to `return_value`.
pub fn forced_unwind_to(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    target_ip: u64,
    target_frame_rsp: Option<u64>,
    return_value: u64,
) -> Result<WinApiHandlerResult> {
    // No target: behave as a successful no-op return (legacy `__cxa_end_catch` path).
    if target_ip == 0 && target_frame_rsp.is_none() {
        let return_address = engine.return_from_win64_api(return_value)?;
        return Ok(WinApiHandlerResult {
            return_address,
            return_value,
        });
    }

    let tctx = engine.snapshot_thread_context();
    let rsp = engine.read_rsp()?;
    let mut ra_buf = [0u8; 8];
    engine
        .mem_read(rsp, &mut ra_buf)
        .map_err(|e| anyhow::anyhow!("RtlUnwindEx: failed to read return address: {e}"))?;
    let start_rip = u64::from_le_bytes(ra_buf);
    let start_rsp = rsp.saturating_add(8);

    let mut frame = new_ctx(start_rip, start_rsp, &tctx);
    for _ in 0..MAX_FRAMES {
        if target_frame_rsp.is_some_and(|r| frame.rsp == r) {
            break;
        }
        let mut read = |va: u64, buf: &mut [u8]| engine.mem_read(va, buf).map_err(|_e| ());
        let (unwound, _) = unwind_one(&mut read, state, &frame)?;
        if unwound.ctx.rip == 0 {
            break;
        }
        frame = unwound.ctx;
        if target_frame_rsp.is_some_and(|r| frame.rsp == r) {
            break;
        }
        if target_ip != 0 && frame.rip == target_ip {
            break;
        }
    }

    let mut final_ctx = tctx;
    final_ctx.gpr = frame.gpr;
    final_ctx.xmm = frame.xmm;
    final_ctx.rip = if target_ip != 0 { target_ip } else { frame.rip };
    final_ctx.gpr[4] = frame.rsp; // UWOP: 4 = RSP
    engine.restore_thread_context(&final_ctx);
    engine.write_rip(final_ctx.rip)?;
    engine.write_rsp(frame.rsp)?;
    engine.write_rax(return_value)?;
    Ok(WinApiHandlerResult {
        return_address: final_ctx.rip,
        return_value,
    })
}

// ═══════════════════════════════════════════════════════════════════════
// Pass 1 — Search
// ═══════════════════════════════════════════════════════════════════════

fn search(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    tctx: &ThreadContext,
    throw_rip: u64,
    throw_rsp: u64,
    payload: ThrowPayload,
) -> Result<HandlerFound> {
    let mut read = |va: u64, buf: &mut [u8]| engine.mem_read(va, buf).map_err(|_e| ());
    let mut frame = new_ctx(throw_rip, throw_rsp, tctx);

    for i in 0..MAX_FRAMES {
        tracing::debug!(
            frame = i,
            rip = format_args!("{:#x}", frame.rip),
            "seh search frame"
        );
        let (unwound, handler_data) = unwind_one(&mut read, state, &frame)?;

        if let Some(hdata) = handler_data
            && let Some(lp) = resolve_landing_pad(&mut read, frame.rip, &unwound, hdata, payload)
        {
            tracing::debug!(
                frame = i,
                landing_pad = format_args!("{:#x}", lp),
                "seh found landing pad"
            );
            return Ok(HandlerFound {
                landing_pad: lp,
                catch_ctx: frame,
                exception_object: if payload.exception_object != 0 {
                    Some(payload.exception_object)
                } else {
                    None
                },
            });
        }
        frame = unwound.ctx;
        if frame.rip == 0 || frame.rsp == 0 {
            break;
        }
    }
    Err(anyhow::anyhow!(
        "RaiseException: no handler found (throw_rip={throw_rip:#x}, \
         pExceptionObject={:#x})",
        payload.exception_object
    ))
}

// ═══════════════════════════════════════════════════════════════════════
// Pass 2 — Install
// ═══════════════════════════════════════════════════════════════════════

/// Unwind from the throw site to the handler frame, restore nonvolatiles,
/// then jump to the landing pad.
fn install(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    tctx: &ThreadContext,
    throw_rip: u64,
    throw_rsp: u64,
    handler: &HandlerFound,
) -> Result<WinApiHandlerResult> {
    let mut frame = new_ctx(throw_rip, throw_rsp, tctx);

    for _ in 0..MAX_FRAMES {
        if frame_matches_catch(&frame, &handler.catch_ctx) {
            apply_catch_context(engine, handler, &frame)?;
            return Ok(WinApiHandlerResult {
                return_address: handler.landing_pad,
                return_value: handler.exception_object.unwrap_or(0), // Option::unwrap_or, not Result
            });
        }

        let next;
        {
            let mut read = |va: u64, buf: &mut [u8]| engine.mem_read(va, buf).map_err(|_e| ());
            let (unwound, _) = unwind_one(&mut read, state, &frame)?;
            next = unwound.ctx;
        }
        frame = next;
    }
    Err(anyhow::anyhow!(
        "RaiseException: unwind pass failed to reach handler (landing={:#x})",
        handler.landing_pad
    ))
}

fn frame_matches_catch(frame: &UnwindContext, catch: &UnwindContext) -> bool {
    frame.rip == catch.rip && frame.rsp == catch.rsp
}

fn apply_catch_context(
    engine: &mut dyn wie_cpu::CpuEngine,
    handler: &HandlerFound,
    frame: &UnwindContext,
) -> Result<()> {
    let mut tctx = engine.snapshot_thread_context();
    // Nonvolatiles from the unwound catch frame; keep RFLAGS from the throw path.
    tctx.gpr = frame.gpr;
    tctx.xmm = frame.xmm;
    tctx.rip = handler.landing_pad;
    // UWOP register index 4 is RSP.
    tctx.gpr[4] = frame.rsp;
    engine.restore_thread_context(&tctx);
    engine.write_rip(handler.landing_pad)?;
    engine.write_rsp(frame.rsp)?;
    // Surface exception object in RAX (Mingw landing pads / simple MSVC paths).
    if let Some(obj) = handler.exception_object {
        engine.write_rax(obj)?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════
// Unwind one frame
// ═══════════════════════════════════════════════════════════════════════

struct Unwound {
    ctx: UnwindContext,
    image_base: u64,
    entry: exception::RuntimeFunction,
    unwind_va: u64,
}

fn unwind_one(
    read_mem: &mut MemRead<'_>,
    state: &WinApiState,
    current: &UnwindContext,
) -> Result<(Unwound, Option<u32>)> {
    let Some(entry) = exception::lookup_function_entry(&state.sync, current.rip) else {
        let mut buf = [0u8; 8];
        read_mem(current.rsp, &mut buf)
            .map_err(|()| anyhow::anyhow!("leaf unwind: stack unreadable at {:#x}", current.rsp))?; // MemRead uses Result<(), ()>
        let caller = UnwindContext {
            rip: u64::from_le_bytes(buf),
            rsp: current.rsp.saturating_add(8),
            gpr: current.gpr,
            xmm: current.xmm,
        };
        return Ok((
            Unwound {
                ctx: caller,
                image_base: 0,
                entry: dummy_entry(),
                unwind_va: 0,
            },
            None,
        ));
    };
    let unwind_va = entry
        .image_base
        .saturating_add(u64::from(entry.entry.unwind_data));
    let result = exception::virtual_unwind(read_mem, entry.image_base, entry.entry, *current)
        .map_err(|()| anyhow::anyhow!("virtual_unwind failed at rip={:#x}", current.rip))?;
    Ok((
        Unwound {
            ctx: result.ctx,
            image_base: entry.image_base,
            entry: *entry.entry,
            unwind_va,
        },
        result.handler_data,
    ))
}

fn dummy_entry() -> exception::RuntimeFunction {
    exception::RuntimeFunction {
        begin_address: 0,
        end_address: 0,
        unwind_data: 0,
    }
}

fn new_ctx(rip: u64, rsp: u64, tctx: &ThreadContext) -> UnwindContext {
    let mut gpr = tctx.gpr;
    gpr[4] = rsp; // keep RSP coherent for UWOP / FP math
    UnwindContext {
        rip,
        rsp,
        gpr,
        xmm: tctx.xmm,
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Landing pad resolution (Mingw LSDA + MSVC FuncInfo)
// ═══════════════════════════════════════════════════════════════════════

fn resolve_landing_pad(
    read_mem: &mut MemRead<'_>,
    control_pc: u64,
    unwound: &Unwound,
    language_data: u32,
    payload: ThrowPayload,
) -> Option<u64> {
    if unwound.image_base == 0 || unwound.unwind_va == 0 {
        return None;
    }
    let func_start = unwound.entry.begin_va(unwound.image_base);
    let func_end = unwound.entry.end_va(unwound.image_base);
    let candidates =
        exception::language_data_candidates(unwound.image_base, unwound.unwind_va, language_data);

    let msvc_throw = payload.throw_info != 0 || payload.exception_object != 0;
    let in_image = |va: u64| -> bool {
        // Require a non-zero module base and a landing pad inside a 64 MiB window
        // of that image (7za / micros are far smaller). Rejects stack VAs (~0x20xx_xxxx).
        unwound.image_base != 0
            && va >= unwound.image_base
            && va < unwound.image_base.saturating_add(64 * 1024 * 1024)
            && va >= func_start.saturating_sub(0x10_0000) // near this module's code
    };

    // MSVC `_CxxThrowException` path: prefer FuncInfo. Trying LSDA first is unsafe
    // because random language-data bytes can look like a call-site table and yield
    // a bogus "landing pad" (observed as a stack VA under 7za).
    if msvc_throw {
        for &fi_va in &candidates {
            if let Some(c) =
                msvc_eh::find_msvc_catch(read_mem, unwound.image_base, fi_va, control_pc, true)
                && in_image(c.landing_pad)
            {
                return Some(c.landing_pad);
            }
        }
        // Do not fall through to LSDA for MSVC throws — false positives jump to stack.
        return None;
    }

    // Mingw / Itanium LSDA call-site table.
    for &lsda_va in &candidates {
        if let Some((lp, _)) = exception::find_landing_pad(
            read_mem,
            lsda_va,
            unwound.image_base,
            func_start,
            func_end,
            control_pc,
        ) && lp != 0
            && in_image(lp)
        {
            return Some(lp);
        }
    }

    for &fi_va in &candidates {
        if let Some(c) =
            msvc_eh::find_msvc_catch(read_mem, unwound.image_base, fi_va, control_pc, false)
            && in_image(c.landing_pad)
        {
            return Some(c.landing_pad);
        }
    }

    None
}
