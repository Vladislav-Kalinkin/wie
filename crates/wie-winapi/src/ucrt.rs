//! Host-side UCRT / `api-ms-win-crt-*` API set for PE64 CRT-linked programs.
//!
//! Clean room: implement enough of the Universal CRT surface that a normal
//! mingw/MSVC CRT startup + `main` can run. Not a port of Wine/ReactOS UCRT.
//!
//! API set DLLs (`api-ms-win-crt-stdio-l1-1-0.dll`, …) are Windows forwarders to
//! `ucrtbase.dll`; we treat them as one dispatch namespace by export name.

use crate::{WinApiEnvironment, WinApiHandlerResult, WinApiState};
use anyhow::{Context, Result};

/// Guest VA base for synthetic CRT objects (FILE cookies, env pointers, etc.).
const ACMDLN_PTR_SLOT: u64 = CRT_GUEST_BASE + 0x328;
const CRT_GUEST_BASE: u64 = 0x0000_0000_6800_0000;
const FILE_STDIN: u64 = CRT_GUEST_BASE;
const FILE_STDOUT: u64 = CRT_GUEST_BASE + 0x100;
const FILE_STDERR: u64 = CRT_GUEST_BASE + 0x200;
const ENVIRON_PTR_SLOT: u64 = CRT_GUEST_BASE + 0x300;
const ARGV_PTR_SLOT: u64 = CRT_GUEST_BASE + 0x308;
const ARGC_SLOT: u64 = CRT_GUEST_BASE + 0x310;
const COMMODE_SLOT: u64 = CRT_GUEST_BASE + 0x318;
const FMODE_SLOT: u64 = CRT_GUEST_BASE + 0x320;

/// Whether `library` is a UCRT API-set or `ucrtbase`.
#[must_use]
pub fn is_ucrt_library(library: &str) -> bool {
    let l = library.to_ascii_lowercase();
    l.starts_with("api-ms-win-crt-") || l == "ucrtbase.dll" || l == "msvcrt.dll"
}

/// Dispatch a UCRT export by name (case-insensitive).
pub fn dispatch_ucrt(
    engine: &mut dyn wie_cpu::CpuEngine,
    environment: WinApiEnvironment,
    state: &mut WinApiState,
    name: &str,
) -> Result<WinApiHandlerResult> {
    let n = name.to_ascii_lowercase();
    match n.as_str() {
        "__acrt_iob_func" => handle_acrt_iob_func(engine),
        "fwrite" => handle_fwrite(engine),
        "fflush" => handle_fflush(engine),
        "setvbuf" => handle_setvbuf(engine),
        "__stdio_common_vfprintf" => handle_stdio_common_vfprintf(engine),
        "malloc" => handle_malloc(engine, state),
        "calloc" => handle_calloc(engine, state),
        "free" => handle_free(engine, state),
        "_set_new_mode" => handle_set_new_mode(engine),
        "__p__environ" => handle_p_environ(engine),
        "__p__acmdln" => handle_p_acmdln(engine),
        "__p___argc" => handle_p_argc(engine),
        "__p___argv" => handle_p_argv(engine),
        "__p__commode" => handle_p_commode(engine),
        "__p__fmode" => handle_p_fmode(engine),
        "_configthreadlocale" => handle_config_thread_locale(engine),
        "__setusermatherr" => handle_set_user_matherr(engine),
        "__c_specific_handler" => handle_c_specific_handler(engine),
        "memcpy" => handle_memcpy(engine),
        "strlen" => handle_strlen(engine),
        "strncmp" => handle_strncmp(engine),
        "_initterm" => handle_initterm(engine),
        "_initterm_e" => handle_initterm_e(engine),
        "_configure_narrow_argv" => handle_configure_narrow_argv(engine),
        "_initialize_narrow_environment" => handle_initialize_narrow_environment(engine),
        "_crt_atexit" => handle_crt_atexit(engine),
        "_set_app_type" => handle_set_app_type(engine),
        "_set_invalid_parameter_handler" => handle_set_invalid_parameter_handler(engine),
        "_cexit" => handle_cexit(engine),
        "signal" => handle_signal(engine),
        // exit / _exit / abort: marked exit_process in hooks; still provide handler body
        // in case traits path misses API-set library names.
        "exit" | "_exit" => handle_exit_like(engine, environment),
        "abort" => handle_abort(engine),
        _ => anyhow::bail!("unsupported UCRT export: {name}"),
    }
}

fn ret(engine: &mut dyn wie_cpu::CpuEngine, value: u64) -> Result<WinApiHandlerResult> {
    let return_address = engine.return_from_win64_api(value)?;
    Ok(WinApiHandlerResult {
        return_address,
        return_value: value,
    })
}

/// Bitcast a CRT `int` status into RAX without `as` (sign-preserving via `i64`).
#[inline]
fn i32_status_to_u64(v: i32) -> u64 {
    // i32 → i64 sign-extends; `from_ne_bytes` reinterprets bits (same as `as u64` on two's complement).
    u64::from_ne_bytes(i64::from(v).to_ne_bytes())
}

/// `__acrt_iob_func(ix)` → `FILE*` for stdin/stdout/stderr.
fn handle_acrt_iob_func(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let ix = engine.read_rcx()? & 0xffff_ffff;
    let ptr = match ix {
        0 => FILE_STDIN,
        1 => FILE_STDOUT,
        2 => FILE_STDERR,
        _ => 0,
    };
    ret(engine, ptr)
}

fn handle_fwrite(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let buf = engine.read_rcx()?;
    let size = engine.read_rdx()?;
    let count = engine.read_r8()?;
    let stream = engine.read_r9()?;

    if size == 0 || count == 0 {
        return ret(engine, 0);
    }
    let total = size.saturating_mul(count);
    let total_usize = usize::try_from(total).unwrap_or(0);
    let mut bytes = vec![0_u8; total_usize];
    if total_usize > 0 && buf != 0 {
        engine
            .mem_read(buf, &mut bytes)
            .context("fwrite guest buffer")?;
    }

    // Host stdout/stderr for console programs (independent CRT expects console I/O).
    // Fast-path: direct `libc::write` — skips Rust stdio mutex (matches JIT helper).
    if stream == FILE_STDOUT || stream == FILE_STDERR {
        write_host_console(stream, &bytes);
    }

    ret(engine, count)
}

fn handle_fflush(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _stream = engine.read_rcx()?;
    // Console I/O uses unbuffered `libc::write`; no userspace buffer / no stdio lock.
    ret(engine, 0)
}

/// Host console write without `std::io::{stdout,stderr}` lock (hot CRT path).
#[cfg(unix)]
fn write_host_console(stream: u64, bytes: &[u8]) {
    let fd = if stream == FILE_STDOUT {
        libc::STDOUT_FILENO
    } else {
        // FILE_STDERR (caller already filtered).
        libc::STDERR_FILENO
    };
    write_all_fd(fd, bytes);
}

/// Write the full buffer to `fd`, retrying EINTR; give up on other errors.
#[cfg(unix)]
fn write_all_fd(fd: libc::c_int, bytes: &[u8]) {
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let Some(chunk) = bytes.get(offset..) else {
            break;
        };
        // SAFETY: `chunk` is a valid contiguous slice; write does not retain the pointer.
        // Hot path: avoid `std::io` mutex on every guest `fwrite` to stdout/stderr.
        #[expect(unsafe_code)]
        let n = unsafe { libc::write(fd, chunk.as_ptr().cast::<libc::c_void>(), chunk.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        if n == 0 {
            break;
        }
        offset = offset.saturating_add(usize::try_from(n).unwrap_or(0));
    }
}

#[cfg(not(unix))]
fn write_host_console(stream: u64, bytes: &[u8]) {
    use std::io::Write;
    if stream == FILE_STDOUT {
        drop(std::io::stdout().write_all(bytes));
    } else if stream == FILE_STDERR {
        drop(std::io::stderr().write_all(bytes));
    }
}

fn handle_setvbuf(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _stream = engine.read_rcx()?;
    let _buf = engine.read_rdx()?;
    let _mode = engine.read_r8()?;
    let _size = engine.read_r9()?;
    ret(engine, 0)
}

/// Minimal stub: treat as success / no output formatting for CRT init paths.
fn handle_stdio_common_vfprintf(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    // Signature is options, FILE*, format, locale, va_list — ignore and return 0 chars.
    ret(engine, 0)
}

fn handle_malloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let size = engine.read_rcx()?;
    let ptr = if size == 0 {
        0
    } else {
        state.heap.alloc_coherent(engine, size)
    };
    ret(engine, ptr)
}

fn handle_calloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let n = engine.read_rcx()?;
    let size = engine.read_rdx()?;
    let total = n.saturating_mul(size);
    let ptr = if total == 0 {
        0
    } else {
        let p = state.heap.alloc_coherent(engine, total);
        if p != 0 {
            let len = usize::try_from(total).unwrap_or(0);
            let zeros = vec![0_u8; len];
            engine.mem_write(p, &zeros)?;
        }
        p
    };
    ret(engine, ptr)
}

fn handle_free(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let ptr = engine.read_rcx()?;
    if ptr != 0 {
        let _ = state.heap.free_coherent(engine, ptr);
    }
    ret(engine, 0)
}

fn handle_set_new_mode(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _mode = engine.read_rcx()?;
    ret(engine, 0)
}

fn handle_p_environ(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // char*** — point at a slot holding NULL (empty environment block list).
    engine.mem_write(ENVIRON_PTR_SLOT, &0_u64.to_le_bytes())?;
    ret(engine, ENVIRON_PTR_SLOT)
}

fn handle_p_acmdln(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    engine.mem_write(ACMDLN_PTR_SLOT, &0_u64.to_le_bytes())?;
    ret(engine, ACMDLN_PTR_SLOT)
}

fn handle_p_argc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    engine.mem_write(ARGC_SLOT, &1_u32.to_le_bytes())?;
    ret(engine, ARGC_SLOT)
}

fn handle_p_argv(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // char*** — empty/single NULL argv for now.
    engine.mem_write(ARGV_PTR_SLOT, &0_u64.to_le_bytes())?;
    ret(engine, ARGV_PTR_SLOT)
}

fn handle_p_commode(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    engine.mem_write(COMMODE_SLOT, &0_u32.to_le_bytes())?;
    ret(engine, COMMODE_SLOT)
}

fn handle_p_fmode(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    engine.mem_write(FMODE_SLOT, &0_u32.to_le_bytes())?;
    ret(engine, FMODE_SLOT)
}

fn handle_config_thread_locale(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _ = engine.read_rcx()?;
    ret(engine, 0)
}

fn handle_set_user_matherr(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _ = engine.read_rcx()?;
    ret(engine, 0)
}

fn handle_c_specific_handler(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // Exception filter: continue search.
    ret(engine, 1)
}

fn handle_memcpy(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let dest = engine.read_rcx()?;
    let src = engine.read_rdx()?;
    let n = engine.read_r8()?;
    let n_usize = usize::try_from(n).unwrap_or(0);
    if n_usize > 0 && dest != 0 && src != 0 {
        let mut buf = vec![0_u8; n_usize];
        engine.mem_read(src, &mut buf)?;
        engine.mem_write(dest, &buf)?;
    }
    ret(engine, dest)
}

fn handle_strlen(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let s = engine.read_rcx()?;
    if s == 0 {
        return ret(engine, 0);
    }
    let mut len = 0_u64;
    loop {
        let mut b = [0_u8; 1];
        engine.mem_read(s.wrapping_add(len), &mut b)?;
        if b[0] == 0 {
            break;
        }
        len = len.saturating_add(1);
        if len > 1_000_000 {
            break;
        }
    }
    ret(engine, len)
}

fn handle_strncmp(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let a = engine.read_rcx()?;
    let b = engine.read_rdx()?;
    let n = engine.read_r8()?;
    let n_usize = usize::try_from(n).unwrap_or(0);
    let mut result: i32 = 0;
    for i in 0..n_usize {
        let mut ba = [0_u8; 1];
        let mut bb = [0_u8; 1];
        engine.mem_read(a.wrapping_add(u64::try_from(i).unwrap_or(0)), &mut ba)?;
        engine.mem_read(b.wrapping_add(u64::try_from(i).unwrap_or(0)), &mut bb)?;
        if ba[0] != bb[0] {
            result = i32::from(ba[0]).wrapping_sub(i32::from(bb[0]));
            break;
        }
        if ba[0] == 0 {
            break;
        }
    }
    ret(engine, i32_status_to_u64(result))
}

/// `_initterm(first, last)` — call void (*)() for each non-null entry in [first, last).
///
/// v0: **no-op**. Calling guest constructors requires a full call bridge; empty/noncritical
/// `.CRT` sections still allow simple `main` programs. Tighten when a CRT PE needs ctors.
fn handle_initterm(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _first = engine.read_rcx()?;
    let _last = engine.read_rdx()?;
    ret(engine, 0)
}

/// `_initterm_e` — same as `_initterm` but entries return `int`; non-zero aborts.
/// v0: no-op success (return 0).
fn handle_initterm_e(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _first = engine.read_rcx()?;
    let _last = engine.read_rdx()?;
    ret(engine, 0)
}

fn handle_configure_narrow_argv(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _mode = engine.read_rcx()?;
    ret(engine, 0)
}

fn handle_initialize_narrow_environment(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    ret(engine, 0)
}

fn handle_crt_atexit(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _fn = engine.read_rcx()?;
    ret(engine, 0)
}

fn handle_set_app_type(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _t = engine.read_rcx()?;
    ret(engine, 0)
}

fn handle_set_invalid_parameter_handler(
    engine: &mut dyn wie_cpu::CpuEngine,
) -> Result<WinApiHandlerResult> {
    let _h = engine.read_rcx()?;
    ret(engine, 0)
}

fn handle_cexit(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    ret(engine, 0)
}

fn handle_signal(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _sig = engine.read_rcx()?;
    let _handler = engine.read_rdx()?;
    ret(engine, 0)
}

fn handle_exit_like(
    engine: &mut dyn wie_cpu::CpuEngine,
    _environment: WinApiEnvironment,
) -> Result<WinApiHandlerResult> {
    // Should be intercepted via exit_process trait; if not, still return.
    let code = engine.read_rcx()?;
    ret(engine, code)
}

fn handle_abort(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    ret(engine, 3)
}
