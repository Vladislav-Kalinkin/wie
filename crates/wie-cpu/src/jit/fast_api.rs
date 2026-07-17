//! Direct host implementations of hot UCRT imports for the Cranelift JIT.
//!
//! When a guest `call` resolves to one of these fake-API VAs, the lowerer emits a
//! Cranelift `call` to a host helper instead of exiting to the runtime host-stop
//! loop (saves most of the CRT startup / `printf` path stops).
//!
//! Clippy cast/index allows are inherited from `jit/mod.rs`.

use super::lower::JitCtx;
use crate::mem::GuestMemory;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

/// Which UCRT/CRT import to accelerate from JIT code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum FastApiKind {
    Malloc,
    Free,
    Memcpy,
    Strlen,
    AcrtIobFunc,
    Fwrite,
    Fflush,
}

impl FastApiKind {
    /// Map an export name (case-insensitive) to a fast-path kind.
    #[must_use]
    pub fn from_export_name(name: &str) -> Option<Self> {
        let n = name.as_bytes();
        // Fast path without allocation: common CRT names are ASCII.
        let eq = |a: &str| name.eq_ignore_ascii_case(a);
        if eq("malloc") {
            Some(Self::Malloc)
        } else if eq("free") {
            Some(Self::Free)
        } else if eq("memcpy") {
            Some(Self::Memcpy)
        } else if eq("strlen") {
            Some(Self::Strlen)
        } else if eq("__acrt_iob_func") {
            Some(Self::AcrtIobFunc)
        } else if eq("fwrite") {
            Some(Self::Fwrite)
        } else if eq("fflush") {
            Some(Self::Fflush)
        } else {
            let _ = n;
            None
        }
    }

    /// Cranelift import symbol name.
    #[must_use]
    pub const fn symbol(self) -> &'static str {
        match self {
            Self::Malloc => "wie_ucrt_malloc",
            Self::Free => "wie_ucrt_free",
            Self::Memcpy => "wie_ucrt_memcpy",
            Self::Strlen => "wie_ucrt_strlen",
            Self::AcrtIobFunc => "wie_ucrt_iob",
            Self::Fwrite => "wie_ucrt_fwrite",
            Self::Fflush => "wie_ucrt_fflush",
        }
    }
}

/// Guest heap layout for JIT `malloc`/`free` (matches guest HeapAlloc control block).
#[derive(Debug, Clone, Copy, Default)]
pub struct JitHeapLayout {
    pub ctrl_va: u64,
    pub base: u64,
    pub end: u64,
}

/// Configuration installed by the runtime after fake-API table build.
#[derive(Debug, Clone, Default)]
pub struct JitFastPathConfig {
    pub heap: JitHeapLayout,
    /// Fake-API guest VA → kind.
    pub by_va: HashMap<u64, FastApiKind>,
}

// Process-wide heap layout for host helpers (set once per session).
static HEAP_CTRL: AtomicU64 = AtomicU64::new(0);
static HEAP_BASE: AtomicU64 = AtomicU64::new(0);
static HEAP_END: AtomicU64 = AtomicU64::new(0);

/// Must match `wie_winapi::ucrt` FILE* cookies.
const FILE_STDIN: u64 = 0x0000_0000_6800_0000;
const FILE_STDOUT: u64 = FILE_STDIN + 0x100;
const FILE_STDERR: u64 = FILE_STDIN + 0x200;

/// Size classes — keep in lockstep with `wie_winapi::guest_heap`.
const SIZE_CLASSES: [u64; 24] = [
    16, 32, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096, 6144, 8192,
    12288, 16384, 24576, 32768, 49152, 65536,
];
const LARGE_THRESHOLD: u64 = 65_536;

/// Install heap layout for JIT UCRT helpers (and optionally the VA map is kept on `JitCpu`).
pub(super) fn install_heap_layout(heap: JitHeapLayout) {
    HEAP_CTRL.store(heap.ctrl_va, Ordering::Relaxed);
    HEAP_BASE.store(heap.base, Ordering::Relaxed);
    HEAP_END.store(heap.end, Ordering::Relaxed);
}

fn heap_layout() -> JitHeapLayout {
    JitHeapLayout {
        ctrl_va: HEAP_CTRL.load(Ordering::Relaxed),
        base: HEAP_BASE.load(Ordering::Relaxed),
        end: HEAP_END.load(Ordering::Relaxed),
    }
}

fn mem_mut(ctx: &mut JitCtx) -> &mut GuestMemory {
    // SAFETY: `mem` is set by `run_compiled` for the duration of the block.
    unsafe { &mut *ctx.mem }
}

fn read_u64(mem: &GuestMemory, va: u64) -> Option<u64> {
    let mut b = [0_u8; 8];
    mem.read(va, &mut b).ok()?;
    Some(u64::from_le_bytes(b))
}

fn write_u64(mem: &mut GuestMemory, va: u64, value: u64) -> bool {
    mem.write(va, &value.to_le_bytes()).is_ok()
}

fn round_up_size(size: u64) -> u64 {
    let size = size.max(1);
    if size <= LARGE_THRESHOLD {
        for &c in &SIZE_CLASSES {
            if size <= c {
                return c;
            }
        }
        LARGE_THRESHOLD
    } else {
        size.wrapping_add(15) & !15_u64
    }
}

fn size_class_index(size: u64) -> usize {
    for (i, &c) in SIZE_CLASSES.iter().enumerate() {
        if size <= c {
            return i;
        }
    }
    SIZE_CLASSES.len() - 1
}

fn head_va(ctrl: u64, class: usize) -> u64 {
    ctrl.wrapping_add(8)
        .wrapping_add(u64::try_from(class).unwrap_or(0).wrapping_mul(8))
}

/// `malloc(size)` — freelist / bump via guest heap control block.
pub(super) unsafe extern "C" fn wie_ucrt_malloc(ctx: *mut JitCtx, size: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if ctx.fault != 0 {
        return 0;
    }
    if size == 0 {
        return 0;
    }
    let heap = heap_layout();
    if heap.ctrl_va == 0 || heap.base == 0 || heap.end <= heap.base {
        return 0;
    }
    let mem = mem_mut(ctx);
    let rounded = round_up_size(size);
    if rounded == 0 || rounded > LARGE_THRESHOLD {
        // Large: bump only (rare for CRT hello paths).
        return bump_alloc(mem, &heap, rounded);
    }
    let class = size_class_index(rounded);
    let hva = head_va(heap.ctrl_va, class);
    if let Some(head) = read_u64(mem, hva)
        && head != 0
        && head >= heap.base
        && head < heap.end
    {
        let next = read_u64(mem, head).unwrap_or(0);
        if !write_u64(mem, hva, next) {
            return 0;
        }
        let _ = write_u64(mem, head.wrapping_sub(8), rounded);
        return head;
    }
    bump_alloc(mem, &heap, rounded)
}

fn bump_alloc(mem: &mut GuestMemory, heap: &JitHeapLayout, rounded: u64) -> u64 {
    let Some(mut bump) = read_u64(mem, heap.ctrl_va) else {
        return 0;
    };
    if bump < heap.base {
        bump = heap.base;
    }
    let pre = bump.wrapping_add(8);
    let payload = pre.wrapping_add(15) & !15_u64;
    let end = payload.wrapping_add(rounded);
    if payload < heap.base || end > heap.end || end < payload {
        return 0;
    }
    if !write_u64(mem, heap.ctrl_va, end) {
        return 0;
    }
    let _ = write_u64(mem, payload.wrapping_sub(8), rounded);
    payload
}

/// `free(ptr)`.
pub(super) unsafe extern "C" fn wie_ucrt_free(ctx: *mut JitCtx, ptr: u64) {
    let ctx = unsafe { &mut *ctx };
    if ctx.fault != 0 || ptr == 0 {
        return;
    }
    let heap = heap_layout();
    if heap.ctrl_va == 0 {
        return;
    }
    if ptr < heap.base || ptr >= heap.end {
        return;
    }
    let mem = mem_mut(ctx);
    let Some(size) = read_u64(mem, ptr.wrapping_sub(8)) else {
        return;
    };
    if size == 0 || size > LARGE_THRESHOLD {
        return;
    }
    let class = size_class_index(size);
    let hva = head_va(heap.ctrl_va, class);
    let old = read_u64(mem, hva).unwrap_or(0);
    let _ = write_u64(mem, ptr, old);
    let _ = write_u64(mem, hva, ptr);
}

/// `memcpy(dest, src, n)` → dest.
pub(super) unsafe extern "C" fn wie_ucrt_memcpy(
    ctx: *mut JitCtx,
    dest: u64,
    src: u64,
    n: u64,
) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if ctx.fault != 0 {
        return dest;
    }
    let n_usize = usize::try_from(n).unwrap_or(0);
    if n_usize == 0 || dest == 0 || src == 0 {
        return dest;
    }
    let mem = mem_mut(ctx);
    // Chunk to bound stack; prefer page-sized buffers.
    let mut remaining = n_usize;
    let mut d = dest;
    let mut s = src;
    let mut buf = [0_u8; 4096];
    while remaining > 0 {
        let chunk = remaining.min(buf.len());
        if mem.read(s, &mut buf[..chunk]).is_err() {
            ctx.fault = 1;
            ctx.fault_addr = s;
            ctx.fault_size = u64::try_from(chunk).unwrap_or(0);
            ctx.fault_access = 0;
            return dest;
        }
        if mem.write(d, &buf[..chunk]).is_err() {
            ctx.fault = 1;
            ctx.fault_addr = d;
            ctx.fault_size = u64::try_from(chunk).unwrap_or(0);
            ctx.fault_access = 1;
            return dest;
        }
        d = d.wrapping_add(u64::try_from(chunk).unwrap_or(0));
        s = s.wrapping_add(u64::try_from(chunk).unwrap_or(0));
        remaining -= chunk;
    }
    dest
}

/// `strlen(s)`.
pub(super) unsafe extern "C" fn wie_ucrt_strlen(ctx: *mut JitCtx, s: u64) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if ctx.fault != 0 || s == 0 {
        return 0;
    }
    let mem = mem_mut(ctx);
    let mut len = 0_u64;
    loop {
        let mut b = [0_u8; 1];
        if mem.read(s.wrapping_add(len), &mut b).is_err() {
            ctx.fault = 1;
            ctx.fault_addr = s.wrapping_add(len);
            ctx.fault_size = 1;
            ctx.fault_access = 0;
            return len;
        }
        if b[0] == 0 {
            return len;
        }
        len = len.saturating_add(1);
        if len > 1_000_000 {
            return len;
        }
    }
}

/// `__acrt_iob_func(ix)` → FILE*.
pub(super) extern "C" fn wie_ucrt_iob(ix: u64) -> u64 {
    match ix & 0xffff_ffff {
        0 => FILE_STDIN,
        1 => FILE_STDOUT,
        2 => FILE_STDERR,
        _ => 0,
    }
}

/// `fwrite(buf, size, count, stream)` → count written (or 0).
pub(super) unsafe extern "C" fn wie_ucrt_fwrite(
    ctx: *mut JitCtx,
    buf: u64,
    size: u64,
    count: u64,
    stream: u64,
) -> u64 {
    let ctx = unsafe { &mut *ctx };
    if ctx.fault != 0 {
        return 0;
    }
    if size == 0 || count == 0 {
        return 0;
    }
    let total = size.saturating_mul(count);
    let total_usize = usize::try_from(total).unwrap_or(0);
    if total_usize == 0 {
        return 0;
    }
    let mem = mem_mut(ctx);
    let mut bytes = vec![0_u8; total_usize];
    if buf != 0 && mem.read(buf, &mut bytes).is_err() {
        ctx.fault = 1;
        ctx.fault_addr = buf;
        ctx.fault_size = total;
        ctx.fault_access = 0;
        return 0;
    }
    // Fast-path: direct libc::write for stdout/stderr — skips Rust stdio mutex.
    if stream == FILE_STDOUT || stream == FILE_STDERR {
        write_host_console(stream, &bytes);
    }
    count
}

/// `fflush(stream)` → 0.
///
/// Console I/O uses unbuffered `libc::write`, so there is no userspace buffer to
/// flush and no Rust `stdout` mutex to take.
pub(super) extern "C" fn wie_ucrt_fflush(_stream: u64) -> u64 {
    0
}

/// Host console write without `std::io::{stdout,stderr}` lock.
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
        // SAFETY: `fd` is a host stdout/stderr descriptor; `chunk` is a live buffer.
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

/// FILE* constants for IR inlining of `__acrt_iob_func`.
#[inline]
pub(super) const fn file_cookie(ix: u64) -> u64 {
    match ix {
        0 => FILE_STDIN,
        1 => FILE_STDOUT,
        2 => FILE_STDERR,
        _ => 0,
    }
}
