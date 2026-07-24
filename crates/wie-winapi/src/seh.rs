//! SEH exception dispatcher for Win64.
//!
//! Two-pass dispatch model:
//! - Pass 1 (search): walk the stack, find a frame with a matching handler
//! - Pass 2 (unwind): UnwindMap cleanups (guest calls) + MSVC catch funclet CALL
//!
//! MSVC x64 catch handlers are **funclets**: they are CALLed with
//! `RDX = EstablisherFrame`, return a continuation IP in **RAX**, and `ret`.
//! Jumping into them directly makes `ret` pop garbage (observed as RIP=HRESULT).
//!
//! Supports:
//! - **Mingw / Itanium LSDA** (host parse of call-site table)
//! - **MSVC FuncInfo** (host parse for `_CxxThrowException` / 7za path)

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use crate::exception::{self, UnwindContext};
use crate::fake_va::seh_continue_trampoline_va;
use crate::msvc_eh::{self, MsvcCatch};
use crate::{WinApiHandlerResult, WinApiState};
use anyhow::Result;
use wie_cpu::ThreadContext;

/// Guest memory reader: `fn(guest_va, buffer) -> Result<(), ()>`.
type MemRead<'a> = dyn FnMut(u64, &mut [u8]) -> Result<(), ()> + 'a;

const MAX_FRAMES: usize = 64;

/// Optional C++ throw payload attached to a dispatch.
///
/// - **MSVC** (`_CxxThrowException`): `exception_object` + `throw_info` (ThrowInfo VA).
/// - **GCC/Mingw** (`_Unwind_RaiseException` / `RaiseException(0x20474343)`):
///   `exception_object` is the `_Unwind_Exception*` (ExceptionInformation[0]);
///   `gcc_throw` is set; typeinfo is read from the `__cxa_exception` header.
#[derive(Debug, Clone, Copy, Default)]
pub struct ThrowPayload {
    pub exception_object: u64,
    pub throw_info: u64,
    /// GCC/libstdc++ SEH exception (`ExceptionCode == 0x2047_4343`).
    pub gcc_throw: bool,
}

/// GCC `RaiseException` code: `' GCC'` (`0x20474343`).
pub const GCC_EXCEPTION_CODE: u32 = 0x2047_4343;
/// MSVC C++ exception code: `'msc' | 0xE000_0000`.
pub const MSVC_EXCEPTION_CODE: u32 = 0xE06D_7363;

/// Offset from `_Unwind_Exception*` back to the `__cxa_exception.exceptionType`
/// pointer as laid out by current libstdc++ (object at header+0x40, type at object-0x90
/// → type at header−0x50). Clean-room from public layout / binary observation.
const GCC_TYPEINFO_FROM_UNWIND_HDR: u64 = 0x50;
/// `adjustedPtr` sits immediately before `_Unwind_Exception` (see `__cxa_begin_catch`
/// reading `-8(%header)` on this mingw libstdc++).
const GCC_ADJUSTED_PTR_FROM_UNWIND_HDR: u64 = 8;
/// Thrown object storage is immediately after `_Unwind_Exception` (0x40 bytes) on
/// this libstdc++ (`__cxa_throw` uses `lea -0x40(%object)` for the header).
const GCC_OBJECT_FROM_UNWIND_HDR: u64 = 0x40;

/// One step of the SEH continuation machine (guest-callable).
#[derive(Debug, Clone)]
pub enum SehStep {
    /// Call a guest UnwindMap action with `RDX = establisher`.
    Action { target: u64, establisher: u64 },
    /// Call an MSVC catch funclet; on return, jump to RAX (continuation).
    MsvcCatch {
        handler: u64,
        establisher: u64,
        frame_rsp: u64,
        gpr: [u64; 16],
        xmm: [u128; 16],
        catch: MsvcCatch,
        exception_object: u64,
        image_base: u64,
        throw_info: u64,
    },
    /// Direct transfer (Mingw / Itanium landing pad).
    Jump {
        rip: u64,
        rsp: u64,
        gpr: [u64; 16],
        xmm: [u128; 16],
        /// Exception pointer for RAX (`_Unwind_Exception*` or object).
        rax: Option<u64>,
        /// Handler switch value for RDX (Itanium landing-pad selector).
        rdx: Option<u64>,
    },
}

/// In-progress SEH cleanup / catch sequence stored on [`WinApiState`].
#[derive(Debug, Clone)]
pub struct SehPending {
    /// Remaining steps (front = next).
    pub steps: Vec<SehStep>,
    /// After a catch funclet returns, treat RAX as continuation IP.
    pub expect_catch_return: bool,
    /// After an Itanium cleanup landing pad, guest calls `_Unwind_Resume` /
    /// `RtlUnwindEx` — continue with the next pending step.
    pub expect_cleanup_resume: bool,
}

// ═══════════════════════════════════════════════════════════════════════
// Entry points
// ═══════════════════════════════════════════════════════════════════════

/// `RaiseException` entry: throw site = return address of the API call.
///
/// Win64 ABI of `RaiseException` (kernel32):
/// ```text
/// RCX = dwExceptionCode
/// RDX = dwExceptionFlags
/// R8  = nNumberOfArguments
/// R9  = lpArguments  (ULONG_PTR*)
/// ```
///
/// Also accepts the internal/MSVC-style convention used by our
/// `_CxxThrowException` stub: RCX = `EXCEPTION_RECORD*` with code at `*RCX`
/// (high dword of code is never a canonical user VA, so we disambiguate).
pub fn dispatch_exception(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let payload = read_raise_exception_payload(engine).unwrap_or_default();
    dispatch_exception_with_payload(engine, state, payload)
}

/// Recover C++ throw payload from `RaiseException` register arguments.
fn read_raise_exception_payload(engine: &mut dyn wie_cpu::CpuEngine) -> Result<ThrowPayload> {
    let rcx = engine.read_rcx()?;
    let r8 = engine.read_r8()?;
    let r9 = engine.read_r9()?;

    // Path A: standard WinAPI — RCX is the exception code (32-bit value).
    if rcx == u64::from(GCC_EXCEPTION_CODE) {
        let exc = read_arg_slot(engine, r9, 0).unwrap_or(0);
        tracing::debug!(
            exc = format_args!("{exc:#x}"),
            n = r8,
            "seh GCC RaiseException (WinAPI args)"
        );
        return Ok(ThrowPayload {
            exception_object: exc,
            throw_info: 0,
            gcc_throw: true,
        });
    }
    if rcx == u64::from(MSVC_EXCEPTION_CODE) {
        // Guest CRT may call RaiseException(0xE06D7363, flags, 3, &info).
        let obj = read_arg_slot(engine, r9, 1).unwrap_or(0);
        let ti = read_arg_slot(engine, r9, 2).unwrap_or(0);
        // Some layouts put magic in [0], object in [1], ThrowInfo in [2].
        let (exception_object, throw_info) = if ti != 0 {
            (obj, ti)
        } else {
            // Fallback: [0]=obj [1]=throwinfo
            (
                read_arg_slot(engine, r9, 0).unwrap_or(0),
                read_arg_slot(engine, r9, 1).unwrap_or(0),
            )
        };
        return Ok(ThrowPayload {
            exception_object,
            throw_info,
            gcc_throw: false,
        });
    }

    // Path B: RCX points at an EXCEPTION_RECORD (our `_CxxThrowException` stub
    // and some internal paths). Codes live in the low 32 bits at *RCX.
    if rcx >= 0x10000 {
        let mut code_buf = [0u8; 4];
        if engine.mem_read(rcx, &mut code_buf).is_ok() {
            let code = u32::from_le_bytes(code_buf);
            if code == GCC_EXCEPTION_CODE {
                let mut info0 = [0u8; 8];
                // ExceptionInformation[0] at +32
                if engine.mem_read(rcx.saturating_add(32), &mut info0).is_ok() {
                    let exc = u64::from_le_bytes(info0);
                    return Ok(ThrowPayload {
                        exception_object: exc,
                        throw_info: 0,
                        gcc_throw: true,
                    });
                }
            }
            if code == MSVC_EXCEPTION_CODE {
                let mut info1 = [0u8; 8];
                let mut info2 = [0u8; 8];
                if engine.mem_read(rcx.saturating_add(40), &mut info1).is_ok()
                    && engine.mem_read(rcx.saturating_add(48), &mut info2).is_ok()
                {
                    return Ok(ThrowPayload {
                        exception_object: u64::from_le_bytes(info1),
                        throw_info: u64::from_le_bytes(info2),
                        gcc_throw: false,
                    });
                }
            }
        }
    }

    Ok(ThrowPayload::default())
}

fn read_arg_slot(engine: &mut dyn wie_cpu::CpuEngine, args_base: u64, index: u64) -> Option<u64> {
    if args_base == 0 {
        return None;
    }
    let mut buf = [0u8; 8];
    engine
        .mem_read(args_base.saturating_add(index.saturating_mul(8)), &mut buf)
        .ok()?;
    Some(u64::from_le_bytes(buf))
}

/// Read `std::type_info*` from a GCC `__cxa_exception` given its `_Unwind_Exception*`.
fn gcc_thrown_typeinfo_from_mem(read_mem: &mut MemRead<'_>, unwind_exception: u64) -> Option<u64> {
    if unwind_exception == 0 {
        return None;
    }
    let type_slot = unwind_exception.saturating_sub(GCC_TYPEINFO_FROM_UNWIND_HDR);
    let mut buf = [0u8; 8];
    read_mem(type_slot, &mut buf).ok()?;
    let ti = u64::from_le_bytes(buf);
    if ti == 0 { None } else { Some(ti) }
}

/// Dispatch with an optional C++ throw payload (MSVC path).
pub fn dispatch_exception_with_payload(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
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

    let (handler, steps) = search_and_plan(engine, state, &tctx, throw_rip, throw_rsp, payload)?;
    begin_or_finish(engine, state, &handler, steps, payload)
}

/// Continue a pending SEH sequence after a guest UnwindMap action or catch funclet returns.
pub fn continue_pending(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let mut pending = state
        .seh_pending
        .take()
        .ok_or_else(|| anyhow::anyhow!("SEH continue trampoline with no pending work"))?;

    if pending.expect_catch_return {
        // MSVC catch funclet returned: RAX = continuation IP inside the catching function.
        let cont = engine.read_rax()?;
        pending.expect_catch_return = false;
        if cont == 0 || cont >= 0x8000_0000_0000 {
            state.seh_pending = Some(pending);
            return Err(anyhow::anyhow!(
                "MSVC catch funclet returned invalid continuation RAX={cont:#x}"
            ));
        }
        tracing::debug!(
            cont = format_args!("{cont:#x}"),
            "seh catch funclet continuation"
        );
        // RSP after catch ret is already the frame RSP (funclet epilogue + ret).
        engine.write_rip(cont)?;
        if pending.steps.is_empty() {
            return Ok(WinApiHandlerResult {
                return_address: cont,
                return_value: 0,
            });
        }
        // Unusual: more steps after catch — keep going.
        state.seh_pending = Some(pending);
        return run_next_step(engine, state);
    }

    if pending.expect_cleanup_resume {
        pending.expect_cleanup_resume = false;
        tracing::debug!(
            remaining = pending.steps.len(),
            "seh cleanup _Unwind_Resume → next step"
        );
        state.seh_pending = Some(pending);
        return run_next_step(engine, state);
    }

    state.seh_pending = Some(pending);
    run_next_step(engine, state)
}

/// True when a cleanup landing pad is in progress and `_Unwind_Resume`/`RtlUnwindEx`
/// should drain the next [`SehPending`] step instead of a generic forced unwind.
#[must_use]
pub fn has_cleanup_resume(state: &WinApiState) -> bool {
    state
        .seh_pending
        .as_ref()
        .is_some_and(|p| p.expect_cleanup_resume && !p.steps.is_empty())
}

/// `RtlUnwindEx`-style forced unwind to `target_ip` (and optional target frame RSP).
///
/// When an Itanium cleanup pad left [`SehPending::expect_cleanup_resume`], drain
/// the next planned step (usually the real catch) instead of a blind unwind.
pub fn forced_unwind_to(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    target_ip: u64,
    target_frame_rsp: Option<u64>,
    return_value: u64,
) -> Result<WinApiHandlerResult> {
    if has_cleanup_resume(state) {
        return continue_pending(engine, state);
    }
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
    final_ctx.gpr[4] = frame.rsp;
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
// Pass 1 — Search + plan pass-2 steps
// ═══════════════════════════════════════════════════════════════════════

struct HandlerFound {
    landing_pad: u64,
    catch_ctx: UnwindContext,
    exception_object: Option<u64>,
    msvc: Option<MsvcCatch>,
    image_base: u64,
    /// Itanium landing-pad switch value (RDX); `None` for MSVC funclets.
    switch_value: Option<u64>,
}

fn search_and_plan(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &WinApiState,
    tctx: &ThreadContext,
    throw_rip: u64,
    throw_rsp: u64,
    payload: ThrowPayload,
) -> Result<(HandlerFound, Vec<SehStep>)> {
    let mut read = |va: u64, buf: &mut [u8]| engine.mem_read(va, buf).map_err(|_e| ());
    let mut frame = new_ctx(throw_rip, throw_rsp, tctx);
    let mut action_steps: Vec<SehStep> = Vec::new();
    let thrown_typeinfo = if payload.gcc_throw {
        gcc_thrown_typeinfo_from_mem(&mut read, payload.exception_object)
    } else {
        None
    };

    for i in 0..MAX_FRAMES {
        tracing::debug!(
            frame = i,
            rip = format_args!("{:#x}", frame.rip),
            "seh search frame"
        );
        let (unwound, handler_data) = unwind_one(&mut read, state, &frame)?;

        if let Some(hdata) = handler_data
            && let Some(resolved) = resolve_landing_pad(
                &mut read,
                frame.rip,
                &unwound,
                hdata,
                payload,
                thrown_typeinfo,
            )
        {
            tracing::debug!(
                frame = i,
                landing_pad = format_args!("{:#x}", resolved.landing_pad),
                disp_catch_obj = resolved.msvc.as_ref().map_or(0, |m| m.disp_catch_obj),
                switch = resolved.switch_value.unwrap_or(0),
                "seh found landing pad"
            );

            // Catch-frame UnwindMap: destroy locals with state > try_low.
            if let Some(msvc) = resolved.msvc {
                let acts = msvc_eh::collect_unwind_actions(
                    &mut read,
                    unwound.image_base,
                    msvc.func_info.unwind_map_rva,
                    msvc.func_info.max_state,
                    msvc.state,
                    msvc.try_low,
                );
                for a in acts {
                    action_steps.push(SehStep::Action {
                        target: unwound.image_base.saturating_add(u64::from(a)),
                        establisher: frame.rsp,
                    });
                }
            }

            let handler = HandlerFound {
                landing_pad: resolved.landing_pad,
                catch_ctx: frame,
                exception_object: if payload.exception_object != 0 {
                    Some(payload.exception_object)
                } else {
                    None
                },
                msvc: resolved.msvc,
                image_base: unwound.image_base,
                switch_value: resolved.switch_value,
            };
            return Ok((handler, action_steps));
        }

        // Intermediate frame: MSVC UnwindMap actions and/or Mingw cleanup pads.
        if let Some(hdata) = handler_data {
            let candidates = exception::language_data_candidates(
                unwound.image_base,
                unwound.unwind_va,
                hdata,
                unwound.exception_data_va,
            );
            let mut saw_msvc = false;
            for &fi_va in &candidates {
                if let Some(info) = msvc_eh::parse_func_info(&mut read, fi_va) {
                    if let Some(st) =
                        msvc_eh::state_for_ip(&mut read, unwound.image_base, &info, frame.rip)
                    {
                        let acts = msvc_eh::collect_unwind_actions(
                            &mut read,
                            unwound.image_base,
                            info.unwind_map_rva,
                            info.max_state,
                            st,
                            -1,
                        );
                        for a in acts {
                            action_steps.push(SehStep::Action {
                                target: unwound.image_base.saturating_add(u64::from(a)),
                                establisher: frame.rsp,
                            });
                        }
                    }
                    saw_msvc = true;
                    break;
                }
            }
            if !saw_msvc {
                // Mingw intermediate cleanup landing pad (action_index == 0).
                let func_start = unwound.entry.begin_va(unwound.image_base);
                for &lsda_va in &candidates {
                    if let Some(c) = exception::find_cleanup_landing_pad(
                        &mut read,
                        lsda_va,
                        unwound.image_base,
                        func_start,
                        frame.rip,
                    ) {
                        action_steps.push(SehStep::Jump {
                            rip: c.landing_pad,
                            rsp: frame.rsp,
                            gpr: frame.gpr,
                            xmm: frame.xmm,
                            rax: if payload.exception_object != 0 {
                                Some(payload.exception_object)
                            } else {
                                None
                            },
                            rdx: Some(0),
                        });
                        break;
                    }
                }
            }
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

struct ResolvedPad {
    landing_pad: u64,
    msvc: Option<MsvcCatch>,
    switch_value: Option<u64>,
}

fn begin_or_finish(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    handler: &HandlerFound,
    mut action_steps: Vec<SehStep>,
    payload: ThrowPayload,
) -> Result<WinApiHandlerResult> {
    // Append terminal transfer step.
    if let Some(msvc) = handler.msvc {
        let obj = handler.exception_object.unwrap_or(0);
        action_steps.push(SehStep::MsvcCatch {
            handler: handler.landing_pad,
            establisher: handler.catch_ctx.rsp,
            frame_rsp: handler.catch_ctx.rsp,
            gpr: handler.catch_ctx.gpr,
            xmm: handler.catch_ctx.xmm,
            catch: msvc,
            exception_object: obj,
            image_base: handler.image_base,
            throw_info: payload.throw_info,
        });
    } else {
        action_steps.push(SehStep::Jump {
            rip: handler.landing_pad,
            rsp: handler.catch_ctx.rsp,
            gpr: handler.catch_ctx.gpr,
            xmm: handler.catch_ctx.xmm,
            rax: handler.exception_object,
            rdx: handler.switch_value,
        });
    }

    state.seh_pending = Some(SehPending {
        steps: action_steps,
        expect_catch_return: false,
        expect_cleanup_resume: false,
    });
    run_next_step(engine, state)
}

fn run_next_step(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let pending = state
        .seh_pending
        .as_mut()
        .ok_or_else(|| anyhow::anyhow!("SEH run_next_step with empty pending"))?;

    if pending.steps.is_empty() {
        state.seh_pending = None;
        return Err(anyhow::anyhow!("SEH pending queue empty"));
    }

    let step = pending.steps.remove(0);
    match step {
        SehStep::Action {
            target,
            establisher,
        } => {
            tracing::debug!(
                target = format_args!("{target:#x}"),
                establisher = format_args!("{establisher:#x}"),
                "seh UnwindMap action call"
            );
            setup_guest_call(engine, target, establisher)?;
            Ok(WinApiHandlerResult {
                return_address: target,
                return_value: 0,
            })
        }
        SehStep::MsvcCatch {
            handler,
            establisher,
            frame_rsp,
            gpr,
            xmm,
            catch,
            exception_object,
            image_base,
            throw_info,
        } => {
            // Restore catch-frame nonvolatiles, place object, CALL funclet.
            let mut tctx = engine.snapshot_thread_context();
            tctx.gpr = gpr;
            tctx.xmm = xmm;
            tctx.gpr[4] = frame_rsp;
            tctx.rip = handler;
            engine.restore_thread_context(&tctx);
            engine.write_rsp(frame_rsp)?;
            engine.write_rdx(establisher)?;
            if exception_object != 0 {
                place_msvc_catch_object(
                    engine,
                    establisher,
                    image_base,
                    &catch,
                    exception_object,
                    throw_info,
                )?;
            }
            pending.expect_catch_return = true;
            tracing::debug!(
                handler = format_args!("{handler:#x}"),
                establisher = format_args!("{establisher:#x}"),
                "seh MSVC catch funclet call"
            );
            setup_guest_call(engine, handler, establisher)?;
            Ok(WinApiHandlerResult {
                return_address: handler,
                return_value: exception_object,
            })
        }
        SehStep::Jump {
            rip,
            rsp,
            gpr,
            xmm,
            rax,
            rdx,
        } => {
            // Intermediate cleanup pads end in `_Unwind_Resume`; keep remaining
            // steps and mark expect_cleanup_resume so RtlUnwindEx continues us.
            let more = !pending.steps.is_empty();
            if more {
                pending.expect_cleanup_resume = true;
            }
            // Drop the borrow before clearing pending on the terminal jump.
            let cleanup_resume = more;
            if !more {
                state.seh_pending = None;
            }
            let mut tctx = engine.snapshot_thread_context();
            tctx.gpr = gpr;
            tctx.xmm = xmm;
            tctx.gpr[4] = rsp;
            tctx.rip = rip;
            engine.restore_thread_context(&tctx);
            engine.write_rip(rip)?;
            engine.write_rsp(rsp)?;
            if let Some(exc) = rax {
                // Personality normally sets `__cxa_exception.adjustedPtr` to the
                // (possibly base-adjusted) thrown object before entering the pad.
                let object = exc.saturating_add(GCC_OBJECT_FROM_UNWIND_HDR);
                let adj_slot = exc.saturating_sub(GCC_ADJUSTED_PTR_FROM_UNWIND_HDR);
                if let Err(e) = engine.mem_write(adj_slot, &object.to_le_bytes()) {
                    tracing::warn!(
                        slot = format_args!("{adj_slot:#x}"),
                        "seh GCC adjustedPtr write failed: {e}"
                    );
                }
                engine.write_rax(exc)?;
            }
            if let Some(sv) = rdx {
                engine.write_rdx(sv)?;
            }
            tracing::debug!(
                rip = format_args!("{rip:#x}"),
                rsp = format_args!("{rsp:#x}"),
                rax = format_args!("{:#x}", rax.unwrap_or(0)),
                rdx = format_args!("{:#x}", rdx.unwrap_or(0)),
                cleanup_resume,
                "seh Itanium landing pad jump"
            );
            Ok(WinApiHandlerResult {
                return_address: rip,
                return_value: rax.unwrap_or(0),
            })
        }
    }
}

/// Set up a Win64 CALL to `target` with `RDX = establisher`.
///
/// Return address is the SEH continue trampoline. Entry RSP ≡ 8 (mod 16).
fn setup_guest_call(
    engine: &mut dyn wie_cpu::CpuEngine,
    target: u64,
    establisher: u64,
) -> Result<()> {
    let cont = seh_continue_trampoline_va();
    // Use stack below current RSP; keep 32-byte shadow above the RA slot
    // (higher addresses) by only placing the RA at rsp_entry.
    let mut rsp = engine.read_rsp()?;
    // Ensure entry RSP % 16 == 8 (post-CALL alignment).
    rsp = rsp.saturating_sub(8);
    if rsp & 0xf != 8 {
        rsp = rsp.saturating_sub(8);
    }
    engine
        .mem_write(rsp, &cont.to_le_bytes())
        .map_err(|e| anyhow::anyhow!("SEH call RA write: {e}"))?;
    engine.write_rsp(rsp)?;
    engine.write_rdx(establisher)?;
    engine.write_rip(target)?;
    Ok(())
}

fn place_msvc_catch_object(
    engine: &mut dyn wie_cpu::CpuEngine,
    establisher: u64,
    image_base: u64,
    msvc: &MsvcCatch,
    exception_object: u64,
    throw_info: u64,
) -> Result<()> {
    let Some(slot) = msvc_eh::catch_object_address(establisher, msvc) else {
        return Ok(());
    };

    if msvc_eh::catch_is_reference(msvc.adjectives) || msvc.type_rva == 0 {
        engine
            .mem_write(slot, &exception_object.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("MSVC catch object (ref) write at {slot:#x}: {e}"))?;
        tracing::debug!(
            slot = format_args!("{slot:#x}"),
            obj = format_args!("{exception_object:#x}"),
            "seh MSVC catch object pointer placed"
        );
        return Ok(());
    }

    let mut read = |va: u64, buf: &mut [u8]| engine.mem_read(va, buf).map_err(|_e| ());
    let size = msvc_eh::throw_object_size(&mut read, image_base, throw_info).unwrap_or(0);
    let copy_len = usize::try_from(size).unwrap_or(0);
    let copy_len = if copy_len > 0 && copy_len <= 256 {
        copy_len
    } else {
        0
    };
    if copy_len > 0 {
        let mut buf = vec![0u8; copy_len];
        engine
            .mem_read(exception_object, &mut buf)
            .map_err(|e| anyhow::anyhow!("MSVC catch object read: {e}"))?;
        engine
            .mem_write(slot, &buf)
            .map_err(|e| anyhow::anyhow!("MSVC catch object (value) write at {slot:#x}: {e}"))?;
    } else {
        engine
            .mem_write(slot, &exception_object.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("MSVC catch object (ptr fallback) at {slot:#x}: {e}"))?;
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
    exception_data_va: Option<u64>,
}

fn unwind_one(
    read_mem: &mut MemRead<'_>,
    state: &WinApiState,
    current: &UnwindContext,
) -> Result<(Unwound, Option<u32>)> {
    let Some(entry) = exception::lookup_function_entry(&state.sync, current.rip) else {
        let mut buf = [0u8; 8];
        read_mem(current.rsp, &mut buf)
            .map_err(|()| anyhow::anyhow!("leaf unwind: stack unreadable at {:#x}", current.rsp))?;
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
                exception_data_va: None,
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
            exception_data_va: result.exception_data_va,
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
    gpr[4] = rsp;
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
    thrown_typeinfo: Option<u64>,
) -> Option<ResolvedPad> {
    if unwound.image_base == 0 || unwound.unwind_va == 0 {
        return None;
    }
    let func_start = unwound.entry.begin_va(unwound.image_base);
    let func_end = unwound.entry.end_va(unwound.image_base);
    let candidates = exception::language_data_candidates(
        unwound.image_base,
        unwound.unwind_va,
        language_data,
        unwound.exception_data_va,
    );

    // MSVC FuncInfo path only for real `_CxxThrowException` (ThrowInfo present).
    let msvc_throw = !payload.gcc_throw && payload.throw_info != 0;

    let in_image = |va: u64| -> bool {
        unwound.image_base != 0
            && va >= unwound.image_base
            && va < unwound.image_base.saturating_add(64 * 1024 * 1024)
            && va >= func_start.saturating_sub(0x10_0000)
    };

    if msvc_throw {
        for &fi_va in &candidates {
            if let Some(c) = msvc_eh::find_msvc_catch(
                read_mem,
                unwound.image_base,
                fi_va,
                control_pc,
                payload.throw_info,
            ) && in_image(c.landing_pad)
            {
                return Some(ResolvedPad {
                    landing_pad: c.landing_pad,
                    msvc: Some(c),
                    switch_value: None,
                });
            }
        }
        return None;
    }

    // Mingw / Itanium LSDA (embedded ExceptionData or relocated pointer).
    for &lsda_va in &candidates {
        if let Some(m) = exception::find_landing_pad_ex(
            read_mem,
            lsda_va,
            unwound.image_base,
            func_start,
            control_pc,
            thrown_typeinfo,
        ) && m.landing_pad != 0
            && in_image(m.landing_pad)
        {
            return Some(ResolvedPad {
                landing_pad: m.landing_pad,
                msvc: None,
                switch_value: Some(m.switch_value.cast_unsigned()),
            });
        }
        // Retry without type filter if typed match failed (allows catch-all-only tables).
        if thrown_typeinfo.is_some()
            && let Some(m) = exception::find_landing_pad_ex(
                read_mem,
                lsda_va,
                unwound.image_base,
                func_start,
                control_pc,
                None,
            )
            && m.landing_pad != 0
            && in_image(m.landing_pad)
            && m.switch_value == 0
        {
            // Only accept untyped retry when the match is catch-all.
            return Some(ResolvedPad {
                landing_pad: m.landing_pad,
                msvc: None,
                switch_value: Some(0),
            });
        }
        let _ = func_end;
    }

    // Fallback: MSVC FuncInfo without ThrowInfo (catch-all only).
    if !payload.gcc_throw {
        for &fi_va in &candidates {
            if let Some(c) =
                msvc_eh::find_msvc_catch(read_mem, unwound.image_base, fi_va, control_pc, 0)
                && in_image(c.landing_pad)
            {
                return Some(ResolvedPad {
                    landing_pad: c.landing_pad,
                    msvc: Some(c),
                    switch_value: None,
                });
            }
        }
    }

    None
}
