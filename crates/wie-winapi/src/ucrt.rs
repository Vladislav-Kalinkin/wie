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

/// Guest VA for legacy `msvcrt` **data** imports (`_fmode`, `_commode`, `_acmdln`).
///
/// These are not callable: the IAT slot must hold the address of the variable so
/// guest code can `mov` through it. Returns `None` for ordinary function exports.
#[must_use]
pub fn crt_data_import_va(name: &str) -> Option<u64> {
    match name.to_ascii_lowercase().as_str() {
        "_fmode" => Some(FMODE_SLOT),
        "_commode" => Some(COMMODE_SLOT),
        "_acmdln" => Some(ACMDLN_PTR_SLOT),
        // Legacy msvcrt: `FILE _iob[]` / `char **__initenv`.
        // Point `_iob` at stdin cookie; fputs/fputc treat nearby streams as console.
        "_iob" => Some(FILE_STDIN),
        "__initenv" => Some(ENVIRON_PTR_SLOT),
        _ => None,
    }
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
        "__c_specific_handler" | "__cxxframehandler" => handle_c_specific_handler(engine),
        "memcpy" | "memmove" => handle_memcpy(engine),
        "memcmp" => handle_memcmp(engine),
        "memset" => handle_memset(engine),
        "strlen" => handle_strlen(engine),
        "strncmp" => handle_strncmp(engine),
        "_initterm" => handle_initterm(engine),
        "_initterm_e" => handle_initterm_e(engine),
        "_configure_narrow_argv" => handle_configure_narrow_argv(engine),
        "_initialize_narrow_environment" => handle_initialize_narrow_environment(engine),
        "_crt_atexit" => handle_crt_atexit(engine),
        // UCRT: `_set_app_type`; legacy msvcrt: `__set_app_type`.
        "_set_app_type" | "__set_app_type" => handle_set_app_type(engine),
        "_set_invalid_parameter_handler" => handle_set_invalid_parameter_handler(engine),
        // Legacy msvcrt CRT startup / teardown.
        "getenv" => handle_getenv(engine),
        "__getmainargs" => handle_getmainargs(engine),
        "_xcptfilter" => handle_xcpt_filter(engine),
        "_cexit" | "_c_exit" => handle_cexit(engine),
        "signal" => handle_signal(engine),
        // exit / _exit / abort: marked exit_process in hooks; still provide handler body
        // in case traits path misses API-set library names.
        "exit" | "_exit" => handle_exit_like(engine, environment),
        "abort" => handle_abort(engine),
        // Legacy msvcrt used heavily by standalone 7za / MSVC CRT apps.
        "realloc" => handle_realloc(engine, state),
        "_isatty" => handle_isatty(engine),
        "_get_osfhandle" => handle_get_osfhandle(engine),
        "fputc" => handle_fputc(engine),
        "fputs" => handle_fputs(engine),
        "fgetc" => handle_fgetc(engine),
        "strcmp" => handle_strcmp(engine),
        "wcscmp" => handle_wcscmp(engine),
        "wcsstr" => handle_wcsstr(engine),
        "_onexit" | "__dllonexit" => handle_onexit(engine),
        "_beginthreadex" => handle_begin_thread_ex(engine, state),
        "_endthreadex" => handle_end_thread_ex(engine, state),
        "_purecall" => handle_purecall(engine),
        // MSVC C++ mangled names (matched after to_ascii_lowercase).
        "?terminate@@yaxxz" => handle_terminate_cxx(engine),
        "??1type_info@@ueaa@xz" => handle_type_info_dtor(engine),
        "_cxxthrowexception" => handle_cxx_throw_exception(engine, state),
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
    // Slot is filled at session start (points at GetCommandLineA buffer).
    ret(engine, ACMDLN_PTR_SLOT)
}

fn handle_p_argc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // Slot is filled at session start from guest argv.
    ret(engine, ARGC_SLOT)
}

fn handle_p_argv(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // Slot holds char** filled at session start.
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

fn handle_memcmp(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let a = engine.read_rcx()?;
    let b = engine.read_rdx()?;
    let n = engine.read_r8()?;
    let n_usize = usize::try_from(n).unwrap_or(0);
    if n_usize == 0 || a == 0 || b == 0 {
        return ret(engine, 0);
    }
    let mut ba = vec![0_u8; n_usize];
    let mut bb = vec![0_u8; n_usize];
    engine.mem_read(a, &mut ba)?;
    engine.mem_read(b, &mut bb)?;
    let mut result: i32 = 0;
    for (xa, xb) in ba.iter().zip(bb.iter()) {
        if xa != xb {
            result = i32::from(*xa).wrapping_sub(i32::from(*xb));
            break;
        }
    }
    ret(engine, i32_status_to_u64(result))
}

fn handle_memset(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let dest = engine.read_rcx()?;
    let c = engine.read_rdx()? & 0xff;
    let n = engine.read_r8()?;
    let n_usize = usize::try_from(n).unwrap_or(0);
    if n_usize > 0 && dest != 0 {
        let buf = vec![u8::try_from(c).unwrap_or(0); n_usize];
        engine.mem_write(dest, &buf)?;
    }
    ret(engine, dest)
}

/// Legacy msvcrt `__getmainargs(argc*, argv**, env**, doWildcard, startupinfo*)`.
///
/// Fills caller out-params from the CRT page prepared at session start.
fn handle_getenv(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // `getenv(const char* name)` → returns NULL (variable not found).
    // The C++ runtime checks for debug/env flags during startup; returning
    // NULL is safe — no deployment expects these to be set.
    ret(engine, 0)
}

fn handle_getmainargs(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let argc_ptr = engine.read_rcx()?;
    let argv_ptr = engine.read_rdx()?;
    let env_ptr = engine.read_r8()?;
    let _do_wildcard = engine.read_r9()?;
    // 5th arg on stack is ignored (startupinfo*).

    if argc_ptr != 0 {
        let mut argc_bytes = [0_u8; 4];
        engine
            .mem_read(ARGC_SLOT, &mut argc_bytes)
            .context("__getmainargs read argc slot")?;
        engine
            .mem_write(argc_ptr, &argc_bytes)
            .context("__getmainargs write *argc")?;
    }
    if argv_ptr != 0 {
        // *argv = char** table (same layout as __p___argv materialization).
        const ARGV_TABLE: u64 = CRT_GUEST_BASE + 0x400;
        engine
            .mem_write(argv_ptr, &ARGV_TABLE.to_le_bytes())
            .context("__getmainargs write *argv")?;
    }
    if env_ptr != 0 {
        // Empty environment: ENVIRON_PTR_SLOT holds a single NULL char* terminator.
        engine
            .mem_write(ENVIRON_PTR_SLOT, &0_u64.to_le_bytes())
            .context("__getmainargs zero env list")?;
        engine
            .mem_write(env_ptr, &ENVIRON_PTR_SLOT.to_le_bytes())
            .context("__getmainargs write *env")?;
    }
    ret(engine, 0)
}

/// `_XcptFilter` — SEH filter; continue search (no host exception model).
fn handle_xcpt_filter(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _xcptnum = engine.read_rcx()?;
    let _info = engine.read_rdx()?;
    // EXCEPTION_CONTINUE_SEARCH
    ret(engine, 0)
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

/// CRT `realloc(ptr, size)`.
fn handle_realloc(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let ptr = engine.read_rcx()?;
    let new_size = engine.read_rdx()?;
    if ptr == 0 {
        let p = if new_size == 0 {
            0
        } else {
            state.heap.alloc_coherent(engine, new_size)
        };
        return ret(engine, p);
    }
    if new_size == 0 {
        let _ = state.heap.free_coherent(engine, ptr);
        return ret(engine, 0);
    }
    if let Some(same) = state.heap.try_realloc_in_place(ptr, new_size) {
        return ret(engine, same);
    }
    let old_size = state
        .heap
        .size_of(ptr)
        .or_else(|| {
            let mut hb = [0_u8; 8];
            engine
                .mem_read(ptr.wrapping_sub(8), &mut hb)
                .ok()
                .map(|()| u64::from_le_bytes(hb))
        })
        .unwrap_or(0);
    let new_addr = state.heap.alloc_coherent(engine, new_size);
    if new_addr == 0 {
        return ret(engine, 0);
    }
    let copy_len = usize::try_from(old_size.min(new_size)).unwrap_or(0);
    if copy_len > 0 {
        let mut bytes = vec![0_u8; copy_len];
        engine.mem_read(ptr, &mut bytes)?;
        engine.mem_write(new_addr, &bytes)?;
    }
    let _ = state.heap.free_coherent(engine, ptr);
    ret(engine, new_addr)
}

/// `_isatty(fd)` — treat 0/1/2 as console TTYs.
fn handle_isatty(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let fd = engine.read_rcx()? & 0xffff_ffff;
    let is_tty = (0..=2).contains(&fd);
    ret(engine, u64::from(is_tty))
}

/// `_get_osfhandle(fd)` → fake console HANDLE for std streams.
fn handle_get_osfhandle(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let fd = engine.read_rcx()? & 0xffff_ffff;
    // Align with kernel32 fake std handles.
    let handle = match fd {
        0 => 0x0000_0000_6000_0001_u64, // stdin
        1 => 0x0000_0000_6000_0002_u64, // stdout
        2 => 0x0000_0000_6000_0003_u64, // stderr
        _ => u64::MAX,                  // INVALID_HANDLE_VALUE
    };
    ret(engine, handle)
}

/// `fputc(c, stream)`.
fn handle_fputc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let c = engine.read_rcx()? & 0xff;
    let stream = engine.read_rdx()?;
    let ch = u8::try_from(c).unwrap_or(0);
    if stream == FILE_STDOUT || stream == FILE_STDERR {
        write_host_console(stream, &[ch]);
        return ret(engine, u64::from(ch));
    }
    if stream == FILE_STDIN {
        return ret(engine, u64::from(u32::MAX)); // EOF
    }
    // Unknown FILE* — still echo to stdout (best-effort for &_iob[1] offsets).
    write_host_console(FILE_STDOUT, &[ch]);
    ret(engine, u64::from(ch))
}

/// `fputs(s, stream)`.
fn handle_fputs(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let s = engine.read_rcx()?;
    let stream = engine.read_rdx()?;
    if s == 0 {
        return ret(engine, u64::from(u32::MAX)); // EOF
    }
    let mut bytes = Vec::new();
    let mut off = 0_u64;
    loop {
        let mut b = [0_u8; 1];
        engine.mem_read(s.wrapping_add(off), &mut b)?;
        if b[0] == 0 {
            break;
        }
        bytes.push(b[0]);
        off = off.saturating_add(1);
        if off > 1_000_000 {
            break;
        }
    }
    let out = if stream == FILE_STDERR {
        FILE_STDERR
    } else {
        FILE_STDOUT
    };
    write_host_console(out, &bytes);
    ret(engine, 0) // non-negative = success
}

/// `fgetc(stream)` — EOF for empty stdin inject.
fn handle_fgetc(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let _stream = engine.read_rcx()?;
    ret(engine, u64::from(u32::MAX)) // EOF
}

/// `strcmp(a, b)`.
fn handle_strcmp(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let a = engine.read_rcx()?;
    let b = engine.read_rdx()?;
    if a == 0 || b == 0 {
        let r = match (a, b) {
            (0, 0) => 0_i32,
            (0, _) => -1,
            _ => 1,
        };
        return ret(engine, i32_status_to_u64(r));
    }
    let mut i = 0_u64;
    loop {
        let mut ba = [0_u8; 1];
        let mut bb = [0_u8; 1];
        engine.mem_read(a.wrapping_add(i), &mut ba)?;
        engine.mem_read(b.wrapping_add(i), &mut bb)?;
        if ba[0] != bb[0] {
            let r = i32::from(ba[0]).wrapping_sub(i32::from(bb[0]));
            return ret(engine, i32_status_to_u64(r));
        }
        if ba[0] == 0 {
            return ret(engine, 0);
        }
        i = i.saturating_add(1);
        if i > 1_000_000 {
            return ret(engine, 0);
        }
    }
}

/// `wcscmp(a, b)`.
fn handle_wcscmp(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let a = engine.read_rcx()?;
    let b = engine.read_rdx()?;
    if a == 0 || b == 0 {
        let r = match (a, b) {
            (0, 0) => 0_i32,
            (0, _) => -1,
            _ => 1,
        };
        return ret(engine, i32_status_to_u64(r));
    }
    let mut i = 0_u64;
    loop {
        let mut ba = [0_u8; 2];
        let mut bb = [0_u8; 2];
        let off = i.wrapping_mul(2);
        engine.mem_read(a.wrapping_add(off), &mut ba)?;
        engine.mem_read(b.wrapping_add(off), &mut bb)?;
        let wa = u16::from_le_bytes(ba);
        let wb = u16::from_le_bytes(bb);
        if wa != wb {
            let r = i32::from(wa).wrapping_sub(i32::from(wb));
            return ret(engine, i32_status_to_u64(r));
        }
        if wa == 0 {
            return ret(engine, 0);
        }
        i = i.saturating_add(1);
        if i > 1_000_000 {
            return ret(engine, 0);
        }
    }
}

/// `wcsstr(haystack, needle)` — return pointer to first match or NULL.
fn handle_wcsstr(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let hay = engine.read_rcx()?;
    let needle = engine.read_rdx()?;
    if hay == 0 || needle == 0 {
        return ret(engine, 0);
    }
    // Read needle
    let mut ndl = Vec::new();
    let mut i = 0_u64;
    loop {
        let mut b = [0_u8; 2];
        engine.mem_read(needle.wrapping_add(i.wrapping_mul(2)), &mut b)?;
        let w = u16::from_le_bytes(b);
        if w == 0 {
            break;
        }
        ndl.push(w);
        i = i.saturating_add(1);
        if i > 100_000 {
            break;
        }
    }
    if ndl.is_empty() {
        return ret(engine, hay);
    }
    // Scan haystack
    let mut hay_units = Vec::new();
    i = 0;
    loop {
        let mut b = [0_u8; 2];
        engine.mem_read(hay.wrapping_add(i.wrapping_mul(2)), &mut b)?;
        let w = u16::from_le_bytes(b);
        if w == 0 {
            break;
        }
        hay_units.push(w);
        i = i.saturating_add(1);
        if i > 1_000_000 {
            break;
        }
    }
    if let Some(pos) = hay_units
        .windows(ndl.len())
        .position(|w| w == ndl.as_slice())
    {
        let addr = hay.wrapping_add(u64::try_from(pos).unwrap_or(0).wrapping_mul(2));
        return ret(engine, addr);
    }
    ret(engine, 0)
}

/// `_onexit` / `__dllonexit` — accept callback, return it (success).
fn handle_onexit(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let func = engine.read_rcx()?;
    // Return the function pointer to indicate registration success (MSVC CRT contract).
    ret(engine, func)
}

/// `_beginthreadex` — same worker spawn path as `CreateThread` (MSVC CRT).
///
/// ABI (x64): security, stack_size, start, arg, initflag, thrdaddr — identical
/// layout to `CreateThread` for the args we care about.
fn handle_begin_thread_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let _security = engine.read_rcx()?;
    let stack_size = engine.read_rdx()?;
    let start = engine.read_r8()?;
    let arg = engine.read_r9()?;
    // Stack: [rsp+0x28]=initflag, [rsp+0x30]=thrdaddr (after home space).
    let flags = read_stack_u32(engine, 0x28).unwrap_or(0);
    let tid_out = read_stack_u64(engine, 0x30).unwrap_or(0);
    let handle = crate::kernel32::create_guest_thread(
        engine, state, stack_size, start, arg, flags, tid_out,
    )?;
    ret(engine, handle)
}

/// `_endthreadex` — terminate the current guest worker (like `ExitThread`).
fn handle_end_thread_ex(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let code_raw = engine.read_rcx()?;
    let code = u32::try_from(code_raw & u64::from(u32::MAX)).unwrap_or(0);
    let tid = state.threads.current_tid();
    for obj in state.sync.objects.values() {
        if let crate::KernelObject::Thread(t) = obj
            && t.tid == tid
        {
            t.finish(code);
            break;
        }
    }
    Err(crate::WinApiControlSignal::ExitThread { code }.into())
}

fn read_stack_u32(engine: &mut dyn wie_cpu::CpuEngine, offset: u64) -> Result<u32> {
    let rsp = engine.read_rsp()?;
    let address = rsp
        .checked_add(offset)
        .context("_beginthreadex stack arg overflow")?;
    let mut bytes = [0_u8; 4];
    engine.mem_read(address, &mut bytes)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_stack_u64(engine: &mut dyn wie_cpu::CpuEngine, offset: u64) -> Result<u64> {
    let rsp = engine.read_rsp()?;
    let address = rsp
        .checked_add(offset)
        .context("_beginthreadex stack arg overflow")?;
    let mut bytes = [0_u8; 8];
    engine.mem_read(address, &mut bytes)?;
    Ok(u64::from_le_bytes(bytes))
}

fn handle_purecall(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    // Pure virtual call — abort-like.
    ret(engine, 0)
}

fn handle_terminate_cxx(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    ret(engine, 0)
}

fn handle_type_info_dtor(engine: &mut dyn wie_cpu::CpuEngine) -> Result<WinApiHandlerResult> {
    let this = engine.read_rcx()?;
    ret(engine, this)
}

/// `_CxxThrowException(pExceptionObject, pThrowInfo)` — MSVC C++ throw.
///
/// Builds the usual MSVC EH `EXCEPTION_RECORD` payload and enters the shared
/// two-pass SEH dispatcher (host FuncInfo / LSDA search + register restore).
fn handle_cxx_throw_exception(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
) -> Result<WinApiHandlerResult> {
    let pexception_object = engine.read_rcx()?;
    let pthrow_info = engine.read_rdx()?;
    tracing::debug!(
        pexception_object = format_args!("{pexception_object:#x}"),
        pthrow_info = format_args!("{pthrow_info:#x}"),
        "msvcrt!_CxxThrowException → SEH dispatch"
    );
    // Scratch EXCEPTION_RECORD below the current stack (host-side only; the
    // dispatcher uses the throw payload + stack walk, not this buffer for control).
    let rsp = engine.read_rsp()?;
    let rec = rsp.saturating_sub(0x100);
    let rip = engine.read_rip()?;
    // ExceptionCode = 0xE06D7363 ('msc' | 0xE0000000)
    engine.mem_write(rec, &0xE06D_7363_u32.to_le_bytes())?;
    engine.mem_write(rec.saturating_add(4), &1_u32.to_le_bytes())?; // noncontinuable
    engine.mem_write(rec.saturating_add(8), &[0u8; 8])?;
    engine.mem_write(rec.saturating_add(16), &rip.to_le_bytes())?;
    engine.mem_write(rec.saturating_add(24), &4_u32.to_le_bytes())?; // NumberParameters
    // Parameters[0] = EH magic, [1] = object, [2] = ThrowInfo, [3] = image base (0)
    engine.mem_write(rec.saturating_add(32), &0x1993_0520_u64.to_le_bytes())?;
    engine.mem_write(rec.saturating_add(40), &pexception_object.to_le_bytes())?;
    engine.mem_write(rec.saturating_add(48), &pthrow_info.to_le_bytes())?;
    engine.mem_write(rec.saturating_add(56), &0_u64.to_le_bytes())?;
    engine.write_rcx(rec)?;

    crate::seh::dispatch_exception_with_payload(
        engine,
        state,
        crate::seh::ThrowPayload {
            exception_object: pexception_object,
            throw_info: pthrow_info,
        },
    )
    .map_err(|e| {
        anyhow::anyhow!(
            "msvcrt!_CxxThrowException: {e}; pExceptionObject={pexception_object:#x} \
             pThrowInfo={pthrow_info:#x}; if this is std::bad_alloc after process-heap OOM, \
             try WIE_PROCESS_HEAP_MB=1024"
        )
    })
}
