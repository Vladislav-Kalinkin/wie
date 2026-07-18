//! WIE CPU abstraction: backends implement [`CpuEngine`].
//!
//! - **Default:** [`JitCpu`] (Cranelift hybrid + iced fallback).
//! - **`WIE_CPU=iced`:** [`IcedCpu`] iced-x86 interpreter.
//!
//! Scope: **x86-64 only** (no i386). Universal PE64 — no per-EXE cheats.
//! Unicorn has been removed; see git history for the former reference backend.

use thiserror::Error;

mod exec;
mod iced_cpu;
mod jit;
mod mem;
mod regs;

pub use iced_cpu::IcedCpu;
pub use jit::{FastApiKind, JitCpu, JitFastPathConfig, JitHeapLayout, JitStats};
/// Windows `PAGE_*` constants and software access checks (Phase 3).
pub use mem::protect;
pub use mem::{
    ERROR_INVALID_ADDRESS, ERROR_INVALID_PARAMETER, ERROR_NOT_ENOUGH_MEMORY,
    GUEST_ALLOC_GRANULARITY, GuestMemBackend, GuestRegion, HashMapBackend, HybridBackend,
    MEM_COMMIT, MEM_DECOMMIT, MEM_FREE, MEM_IMAGE, MEM_PRIVATE, MEM_RELEASE, MEM_RESERVE, MemType,
    MemoryBasicInformation, MmapArenaBackend, PAGE_SIZE, PAGE_SIZE_USIZE, PageMap, PageRun,
    PageState, RegionKind, RegionTable, VadNode, VadTable, align_down, align_up,
    win32_from_cpu_error,
};
pub use regs::RegFile;

/// Memory protection flags for [`CpuEngine::mem_map`] (Unicorn-compatible r/w/x bits).
///
/// Convert to Windows `PAGE_*` via [`mem::protect::page_protect_from_rwx`].
pub mod perm {
    /// Read bit.
    pub const READ: u32 = 1;
    /// Write bit.
    pub const WRITE: u32 = 2;
    /// Execute bit.
    pub const EXEC: u32 = 4;
    /// Read + write + execute.
    pub const ALL: u32 = READ | WRITE | EXEC;
}

/// Re-export for call sites that used the old Unicorn-shaped name.
pub const PROT_ALL: u32 = perm::ALL;

/// Result of stopping on a code-hook / stop-bitmap hit.
#[derive(Debug, Clone, Copy, Default)]
pub struct CodeHookOutcome {
    /// Whether a host-stop address was hit.
    pub hit: bool,
    /// Hit guest address.
    pub address: u64,
    /// Instruction size (if known); may be 0 for interpreter stops.
    pub size: u32,
}

/// Invalid guest memory access diagnostics (demand-paging / faults).
#[derive(Debug, Clone, Copy, Default)]
pub struct InvalidMemoryAccess {
    /// Whether an invalid access was observed.
    pub hit: bool,
    /// Access type (backend-specific; 0 if unused).
    pub access_type: i32,
    /// Faulting address.
    pub address: u64,
    /// Access size.
    pub size: i32,
    /// Write value when applicable.
    pub value: i64,
}

/// Backend-neutral CPU / memory errors.
#[derive(Debug, Error)]
pub enum CpuError {
    /// Interpreter / JIT failure message.
    #[error("{0}")]
    Message(String),
}

/// Outcome of running until a code hook or stop condition.
#[derive(Debug, Clone, Copy)]
pub struct RunUntilHook {
    /// Code hook hit (fake API / trampoline).
    pub code: CodeHookOutcome,
    /// Invalid memory diagnostics (if any).
    pub invalid_memory: InvalidMemoryAccess,
}

/// Minimal CPU + guest memory surface used by WIE runtime and WinAPI.
///
/// Object-safe so the session can hold `Box<dyn CpuEngine>`.
pub trait CpuEngine {
    /// Map a guest VA range.
    ///
    /// # Errors
    /// Backend mapping failure.
    fn mem_map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError>;

    /// Write guest memory.
    ///
    /// # Errors
    /// Unmapped / backend write failure.
    fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError>;

    /// Read guest memory.
    ///
    /// # Errors
    /// Unmapped / backend read failure.
    fn mem_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError>;

    /// Install persistent code + invalid-memory hooks for the fake-API range.
    ///
    /// # Errors
    /// Hook registration failure.
    fn install_runtime_hooks(
        &mut self,
        hook_begin: u64,
        hook_end: u64,
        stop_bitmap: Vec<u8>,
    ) -> Result<(), CpuError>;

    /// Configure JIT direct-UCRT / heap fast path (no-op for non-JIT backends).
    fn configure_jit_fast_path(&mut self, _cfg: JitFastPathConfig) {}

    /// Eagerly compile guest code at `address` into the JIT cache.
    /// No-op for non-JIT backends or when the block is not compilable.
    fn precompile_at(&mut self, _address: u64) {}

    /// Snapshot of CPU/JIT diagnostics (empty for non-JIT backends).
    fn cpu_stats(&self) -> Option<JitStats> {
        None
    }

    /// Active guest memory storage backend name (`hash` / `mmap` / `hybrid`).
    fn mem_backend_name(&self) -> &'static str {
        "hash"
    }

    /// Register a named guest VA region (stack, heap, image, …).
    /// Used by the region table (Phase 1); no-op if the backend ignores it.
    fn register_region(&mut self, _region: mem::GuestRegion) {}

    /// Look up the named region containing `va`, if any.
    fn find_region(&self, _va: u64) -> Option<mem::GuestRegion> {
        None
    }

    /// `VirtualAlloc` — reserve and/or commit private guest pages.
    ///
    /// # Errors
    /// Invalid flags/address or out of guest VA (`CpuError` carries `win32(N):` prefix).
    fn virtual_alloc(
        &mut self,
        _addr: u64,
        _size: usize,
        _alloc_type: u32,
        _protect: u32,
    ) -> Result<u64, CpuError> {
        Err(CpuError::Message(
            "win32(120): VirtualAlloc not implemented".into(),
        ))
    }

    /// `VirtualFree` — decommit or release.
    ///
    /// # Errors
    /// Invalid free type / address.
    fn virtual_free(&mut self, _addr: u64, _size: usize, _free_type: u32) -> Result<(), CpuError> {
        Err(CpuError::Message(
            "win32(120): VirtualFree not implemented".into(),
        ))
    }

    /// `VirtualProtect` — change page protect; returns previous protect of the first page.
    ///
    /// # Errors
    /// Non-committed range, cross-allocation, or unsupported protect.
    fn virtual_protect(
        &mut self,
        _addr: u64,
        _size: usize,
        _new_protect: u32,
    ) -> Result<u32, CpuError> {
        Err(CpuError::Message(
            "win32(120): VirtualProtect not implemented".into(),
        ))
    }

    /// `VirtualQuery` — describe the page state at `addr`.
    fn virtual_query(&self, addr: u64) -> MemoryBasicInformation {
        MemoryBasicInformation {
            base_address: addr & !0xfff,
            allocation_base: 0,
            allocation_protect: 0,
            region_size: PAGE_SIZE,
            state: MEM_FREE,
            protect: 0,
            type_: 0,
        }
    }

    /// `FlushInstructionCache` — drop JIT Ready blocks for `[addr, addr+size)`.
    ///
    /// Microsoft Learn: after software patches code, flush so the CPU fetches
    /// the new bytes. Under WIE this means selective JIT invalidation (soft
    /// translate); host I-cache for Cranelift output is unrelated.
    ///
    /// When `size == 0`, flush the entire process instruction cache (all Ready).
    /// Default: success no-op (non-JIT backends).
    ///
    /// # Errors
    /// Backend-specific (normally never).
    fn flush_instruction_cache(&mut self, _addr: u64, _size: usize) -> Result<(), CpuError> {
        Ok(())
    }

    /// Map a PE image range as `MEM_IMAGE` (committed) with Unicorn-style `perms`.
    ///
    /// Default: same as [`Self::mem_map`] (private).
    ///
    /// # Errors
    /// Backend mapping failure.
    fn mem_map_image(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        self.mem_map(address, size, perms)
    }

    /// Run until a stop-bitmap hit, invalid memory, or instruction budget.
    ///
    /// # Errors
    /// Emulation backend failure.
    fn run_until_stop(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
        hook_begin: u64,
        hook_end: u64,
    ) -> Result<RunUntilHook, CpuError>;

    /// Win64: pop return address, set `RAX`, set `RIP` to return.
    ///
    /// # Errors
    /// Register/stack failure.
    fn return_from_win64_api(&mut self, rax: u64) -> Result<u64, CpuError>;

    /// # Errors
    fn read_rip(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn write_rip(&mut self, value: u64) -> Result<(), CpuError>;
    /// # Errors
    fn read_rsp(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn write_rsp(&mut self, value: u64) -> Result<(), CpuError>;
    /// # Errors
    fn read_rax(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn write_rax(&mut self, value: u64) -> Result<(), CpuError>;
    /// # Errors
    fn read_rcx(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn write_rcx(&mut self, value: u64) -> Result<(), CpuError>;
    /// # Errors
    fn read_rdx(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn write_rdx(&mut self, value: u64) -> Result<(), CpuError>;
    /// # Errors
    fn read_r8(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn write_r8(&mut self, value: u64) -> Result<(), CpuError>;
    /// # Errors
    fn read_r9(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn write_r9(&mut self, value: u64) -> Result<(), CpuError>;
    /// # Errors
    fn read_rbx(&mut self) -> Result<u64, CpuError>;
    /// # Errors
    fn read_r12(&mut self) -> Result<u64, CpuError>;
}

impl CpuEngine for Box<dyn CpuEngine> {
    fn mem_map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        (**self).mem_map(address, size, perms)
    }
    fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        (**self).mem_write(address, bytes)
    }
    fn mem_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        (**self).mem_read(address, bytes)
    }
    fn virtual_alloc(
        &mut self,
        addr: u64,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64, CpuError> {
        (**self).virtual_alloc(addr, size, alloc_type, protect)
    }
    fn virtual_free(&mut self, addr: u64, size: usize, free_type: u32) -> Result<(), CpuError> {
        (**self).virtual_free(addr, size, free_type)
    }
    fn virtual_protect(
        &mut self,
        addr: u64,
        size: usize,
        new_protect: u32,
    ) -> Result<u32, CpuError> {
        (**self).virtual_protect(addr, size, new_protect)
    }
    fn virtual_query(&self, addr: u64) -> MemoryBasicInformation {
        (**self).virtual_query(addr)
    }
    fn flush_instruction_cache(&mut self, addr: u64, size: usize) -> Result<(), CpuError> {
        (**self).flush_instruction_cache(addr, size)
    }
    fn mem_map_image(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        (**self).mem_map_image(address, size, perms)
    }
    fn install_runtime_hooks(
        &mut self,
        hook_begin: u64,
        hook_end: u64,
        stop_bitmap: Vec<u8>,
    ) -> Result<(), CpuError> {
        (**self).install_runtime_hooks(hook_begin, hook_end, stop_bitmap)
    }
    fn configure_jit_fast_path(&mut self, cfg: JitFastPathConfig) {
        (**self).configure_jit_fast_path(cfg);
    }
    fn precompile_at(&mut self, address: u64) {
        (**self).precompile_at(address);
    }
    fn cpu_stats(&self) -> Option<JitStats> {
        (**self).cpu_stats()
    }
    fn mem_backend_name(&self) -> &'static str {
        (**self).mem_backend_name()
    }
    fn register_region(&mut self, region: mem::GuestRegion) {
        (**self).register_region(region);
    }
    fn find_region(&self, va: u64) -> Option<mem::GuestRegion> {
        (**self).find_region(va)
    }
    fn run_until_stop(
        &mut self,
        begin: u64,
        until: u64,
        timeout: u64,
        count: usize,
        hook_begin: u64,
        hook_end: u64,
    ) -> Result<RunUntilHook, CpuError> {
        (**self).run_until_stop(begin, until, timeout, count, hook_begin, hook_end)
    }
    fn return_from_win64_api(&mut self, rax: u64) -> Result<u64, CpuError> {
        (**self).return_from_win64_api(rax)
    }
    fn read_rip(&mut self) -> Result<u64, CpuError> {
        (**self).read_rip()
    }
    fn write_rip(&mut self, value: u64) -> Result<(), CpuError> {
        (**self).write_rip(value)
    }
    fn read_rsp(&mut self) -> Result<u64, CpuError> {
        (**self).read_rsp()
    }
    fn write_rsp(&mut self, value: u64) -> Result<(), CpuError> {
        (**self).write_rsp(value)
    }
    fn read_rax(&mut self) -> Result<u64, CpuError> {
        (**self).read_rax()
    }
    fn write_rax(&mut self, value: u64) -> Result<(), CpuError> {
        (**self).write_rax(value)
    }
    fn read_rcx(&mut self) -> Result<u64, CpuError> {
        (**self).read_rcx()
    }
    fn write_rcx(&mut self, value: u64) -> Result<(), CpuError> {
        (**self).write_rcx(value)
    }
    fn read_rdx(&mut self) -> Result<u64, CpuError> {
        (**self).read_rdx()
    }
    fn write_rdx(&mut self, value: u64) -> Result<(), CpuError> {
        (**self).write_rdx(value)
    }
    fn read_r8(&mut self) -> Result<u64, CpuError> {
        (**self).read_r8()
    }
    fn write_r8(&mut self, value: u64) -> Result<(), CpuError> {
        (**self).write_r8(value)
    }
    fn read_r9(&mut self) -> Result<u64, CpuError> {
        (**self).read_r9()
    }
    fn write_r9(&mut self, value: u64) -> Result<(), CpuError> {
        (**self).write_r9(value)
    }
    fn read_rbx(&mut self) -> Result<u64, CpuError> {
        (**self).read_rbx()
    }
    fn read_r12(&mut self) -> Result<u64, CpuError> {
        (**self).read_r12()
    }
}

/// Active backend name (env `WIE_CPU`, default **`jit`**).
///
/// - `jit` — hybrid Cranelift block JIT + iced fallback (**default**)
/// - `iced` — iced-x86 interpreter
#[must_use]
pub fn active_backend_name() -> &'static str {
    match std::env::var("WIE_CPU") {
        Ok(v) if v.eq_ignore_ascii_case("iced") => "iced",
        Ok(v) if v.eq_ignore_ascii_case("jit") => "jit",
        _ => "jit",
    }
}

/// Open the CPU backend selected by `WIE_CPU` (default: **jit**).
///
/// # Errors
/// Backend open failure.
pub fn open_default_cpu() -> Result<Box<dyn CpuEngine>, CpuError> {
    let name = active_backend_name();
    tracing::info!(backend = name, "opening WIE CPU backend");
    match name {
        "iced" => Ok(Box::new(IcedCpu::open_x86_64())),
        _ => Ok(Box::new(JitCpu::open_x86_64())),
    }
}

/// Process CPU times for `RUSAGE_SELF` in microseconds `(user, sys)`.
///
/// Used by CLI wall/CPU reports.
#[must_use]
#[cfg(unix)]
pub fn process_cpu_times_us() -> (u64, u64) {
    // SAFETY: getrusage(RUSAGE_SELF) with a valid rusage pointer is well-defined.
    #[expect(unsafe_code)]
    unsafe {
        let mut usage: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, &raw mut usage) != 0 {
            return (0, 0);
        }
        let user = timeval_to_us(usage.ru_utime);
        let sys = timeval_to_us(usage.ru_stime);
        (user, sys)
    }
}

#[cfg(not(unix))]
#[must_use]
pub fn process_cpu_times_us() -> (u64, u64) {
    (0, 0)
}

#[cfg(unix)]
fn timeval_to_us(tv: libc::timeval) -> u64 {
    let sec = u64::try_from(tv.tv_sec.max(0)).unwrap_or(0);
    let usec = u64::try_from(tv.tv_usec.max(0)).unwrap_or(0);
    sec.saturating_mul(1_000_000).saturating_add(usec)
}
