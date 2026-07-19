//! WIE runtime: PE64 userspace execution, WinAPI, and tracing.
//!
//! CPU backends: see [`wie_cpu`] and `docs/WIE.md` (Cranelift JIT default; iced interpreter).

mod guest_callback;
mod guest_heap_accel;
mod guest_io;
mod guest_mbwc;
mod guest_rewire;
mod guest_stubs;
mod hooks;
mod memory;
mod mt_runtime;
mod session;
mod trace;

pub use hooks::RuntimeFakeApiEntry;
pub use memory::{
    CALLBACK_RETURN_TRAMPOLINE_VA, DEFAULT_LAYOUT, ENTRY_TRACE_INSTRUCTION_BUDGET,
    ENTRY_TRACE_NO_HOOK_SLICE_LIMIT, FAKE_API_BASE, FAKE_API_SIZE, FAKE_RESOURCE_DATA_BASE,
    FAKE_RESOURCE_DATA_SIZE, FAKE_TEB_LOW_BASE, FAKE_TEB_LOW_SIZE, FAST_API_STUB_BASE,
    FAST_API_STUB_SIZE, FAST_VOID_RETURN_STUB_VA, PROCESS_HEAP_BASE, PROCESS_HEAP_HANDLE,
    PROCESS_HEAP_SHADOW_BASE, PROCESS_HEAP_SHADOW_DELTA, PROCESS_HEAP_SIZE, RuntimeMemoryLayout,
};
pub use session::{RuntimeProfile, RuntimeSession, SessionOptions};
pub use trace::{
    EntryTraceEvent, EntryTraceSummary, EntryTraceTermination, MicroRunOptions, MicroRunSummary,
    RuntimeRunSummary, entry_trace, run_micro_exe, run_micro_exe_with_options,
    run_micro_exe_with_root, run_persistent_until_yield,
};
pub use wie_cpu::{CpuEngine, CpuError, IcedCpu, JitCpu, active_backend_name, open_default_cpu};
pub use wie_winapi::{FileDialogPolicy, IdleContext, IdlePolicy};
