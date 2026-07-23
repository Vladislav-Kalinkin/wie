//! SEH exception dispatcher for Win64.
//!
//! Two-pass dispatch model:
//! - Pass 1 (search): walk the stack, find a frame with a matching handler
//! - Pass 2 (unwind): walk from throw site to handler, install landing pad
//!
//! Designed for readability and safety: each function has a single
//! responsibility, the state is threaded explicitly, and error paths
//! are minimal.

use crate::{WinApiHandlerResult, WinApiState};
use anyhow::Result;
use wie_cpu::ThreadContext;
use crate::exception::{self, UnwindContext};

/// Guest memory reader: `fn(guest_va, buffer) -> Result<(), ()>`.
type MemRead<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), ()> + 'a;

const MAX_FRAMES: usize = 64;

/// Handler frame discovered during pass 1.
#[allow(dead_code)]
struct HandlerFound {
    landing_pad: u64,
    catch_ctx: UnwindContext,
    handler_data: u32,
    image_base: u64,
    func_entry: exception::RuntimeFunction,
}

// ═══════════════════════════════════════════════════════════════════════
// Entry point
// ═══════════════════════════════════════════════════════════════════════

pub fn dispatch_exception(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
) -> Result<WinApiHandlerResult> {
    let tctx = engine.snapshot_thread_context();
    let rsp = engine.read_rsp()?;
    let mut ra_buf = [0u8; 8];
    engine.mem_read(rsp, &mut ra_buf)
        .map_err(|e| anyhow::anyhow!("RaiseException: failed to read return address: {e}"))?;
    let throw_rip = u64::from_le_bytes(ra_buf);
    let throw_rsp = rsp.saturating_add(8);

    let handler = search(engine, state, &tctx, throw_rip, throw_rsp)?;
    install(engine, state, &tctx, throw_rip, throw_rsp, handler)
}

// ═══════════════════════════════════════════════════════════════════════
// Pass 1 — Search
// ═══════════════════════════════════════════════════════════════════════

/// Walk the stack looking for a frame with a matching catch handler.
/// Returns the handler frame info and the landing pad address.
fn search(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    tctx: &ThreadContext,
    throw_rip: u64,
    throw_rsp: u64,
) -> Result<HandlerFound> {
    let mut read = |va: u64, buf: &mut [u8]| engine.mem_read(va, buf).map_err(|_| ());
    let mut frame = new_ctx(throw_rip, throw_rsp, tctx);

    for i in 0..MAX_FRAMES {
        tracing::info!(frame = i, rip = format_args!("{:#x}", frame.rip), "search frame");
        let (unwound, handler_data) = unwind_one(&mut read, state, &mut frame)?;

        if let Some(hdata) = handler_data {
            tracing::info!(frame = i, hdata, "frame has handler, checking LSDA");
            if let Some(lp) = resolve_landing_pad(&mut read, frame.rip, &unwound, hdata) {
                tracing::info!(frame = i, landing_pad = format_args!("{:#x}", lp), "found landing pad!");
                return Ok(HandlerFound {
                    landing_pad: lp,
                    catch_ctx: frame,
                    handler_data: hdata,
                    image_base: unwound.image_base,
                    func_entry: unwound.entry,
                });
            }
        }
        frame = unwound.ctx;
    }
    Err(anyhow::anyhow!("RaiseException: no handler found (throw_rip={:#x})", throw_rip))
}

// ═══════════════════════════════════════════════════════════════════════
// Pass 2 — Install
// ═══════════════════════════════════════════════════════════════════════

/// Unwind from the throw site to the handler frame, then jump to the
/// landing pad (catch block).
fn install(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    tctx: &ThreadContext,
    throw_rip: u64,
    throw_rsp: u64,
    handler: HandlerFound,
) -> Result<WinApiHandlerResult> {
    let mut frame = new_ctx(throw_rip, throw_rsp, tctx);

    for _ in 0..MAX_FRAMES {
        if frame.rip == handler.catch_ctx.rip {
            // Drop the stack frame — we're jumping past all of it.
            engine.write_rip(handler.landing_pad)?;
            engine.write_rsp(handler.catch_ctx.rsp)?;
            return Ok(WinApiHandlerResult {
                return_address: handler.landing_pad,
                return_value: 0,
            });
        }

        // Unwind one frame: mem_read is scoped to this block so the
        // mutable engine borrow for the final write_rip above doesn't conflict.
        let next_rip;
        let next_rsp;
        {
            let mut read = |va: u64, buf: &mut [u8]| engine.mem_read(va, buf).map_err(|_| ());
            let (unwound, _) = unwind_one(&mut read, state, &mut frame)?;
            next_rip = unwound.ctx.rip;
            next_rsp = unwound.ctx.rsp;
        }
        frame.rip = next_rip;
        frame.rsp = next_rsp;
    }
    Err(anyhow::anyhow!("RaiseException: unwind pass failed to reach handler"))
}

// ═══════════════════════════════════════════════════════════════════════
// Unwind one frame
// ═══════════════════════════════════════════════════════════════════════

/// Unwind a single stack frame.  Returns the caller's context and any
/// handler data if the frame has a registered exception handler.
///
/// If the frame has no `.pdata` entry (leaf function), it blindly pops
/// the return address from the stack.
struct Unwound {
    ctx: UnwindContext,
    image_base: u64,
    entry: exception::RuntimeFunction,
}

fn unwind_one(
    read_mem: &mut MemRead<'_>,
    state: &WinApiState,
    current: &mut UnwindContext,
) -> Result<(Unwound, Option<u32>)> {
    let entry = match exception::lookup_function_entry(&state.sync, current.rip) {
        Some(e) => e,
        None => {
            let mut buf = [0u8; 8];
            read_mem(current.rsp, &mut buf)
                .map_err(|_| anyhow::anyhow!("leaf unwind: stack unreadable at {:#x}", current.rsp))?;
            let caller = UnwindContext {
                rip: u64::from_le_bytes(buf),
                rsp: current.rsp + 8,
                gpr: current.gpr,
                xmm: current.xmm,
            };
            return Ok((Unwound { ctx: caller, image_base: 0, entry: dummy_entry() }, None));
        }
    };
    let result = exception::virtual_unwind(read_mem, entry.image_base, entry.entry, *current)
        .map_err(|_| anyhow::anyhow!("virtual_unwind failed at rip={:#x}", current.rip))?;
    Ok((Unwound {
        ctx: result.ctx,
        image_base: entry.image_base,
        entry: *entry.entry,
    }, result.handler_data))
}

fn dummy_entry() -> exception::RuntimeFunction {
    exception::RuntimeFunction {
        begin_address: 0, end_address: 0, unwind_data: 0,
    }
}

fn new_ctx(rip: u64, rsp: u64, tctx: &ThreadContext) -> UnwindContext {
    UnwindContext { rip, rsp, gpr: tctx.gpr, xmm: tctx.xmm }
}

// ═══════════════════════════════════════════════════════════════════════
// Landing pad resolution
// ═══════════════════════════════════════════════════════════════════════

/// Try to find the landing pad (catch block address) by parsing the
/// Itanium LSDA for the given frame.
fn resolve_landing_pad(
    read_mem: &mut MemRead<'_>,
    control_pc: u64,
    unwound: &Unwound,
    handler_data: u32,
) -> Option<u64> {
    let unwind_va = unwound.image_base.saturating_add(u64::from(unwound.entry.unwind_data));
    let lsda_va = unwind_va.saturating_add(u64::from(handler_data));
    let func_start = unwound.entry.begin_va(unwound.image_base);
    let func_end   = unwound.entry.end_va(unwound.image_base);

    exception::find_landing_pad(read_mem, lsda_va, unwound.image_base, func_start, func_end, control_pc)
        .map(|(lp, _)| lp)
}
