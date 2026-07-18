//! Entry-point tracing summaries and persistent smoke-test entry points.

use std::sync::Arc;

use crate::session::{RuntimeProfile, RuntimeSession};
use anyhow::Result;

/// One API event observed during entry-point tracing.
#[derive(Debug, Clone)]
pub struct EntryTraceEvent {
    /// Event index.
    pub index: usize,

    /// Imported library name.
    pub library: Arc<str>,

    /// Imported function name.
    pub name: Arc<str>,

    /// Fake API address hit by Unicorn.
    pub fake_target_va: u64,

    /// Whether the call was handled.
    pub handled: bool,

    /// Handler return value, if handled.
    pub return_value: Option<u64>,

    /// Address where execution resumed after handled API.
    pub return_address: Option<u64>,
}

/// Result of controlled entry-point tracing.
#[derive(Debug, Clone)]
pub struct EntryTraceSummary {
    /// PE entry point.
    pub entry_point_va: u64,

    /// Initial stack pointer.
    pub initial_rsp: u64,

    /// Trace events.
    pub events: Vec<EntryTraceEvent>,

    /// Reason why tracing stopped.
    pub termination: EntryTraceTermination,

    /// Final `RIP`.
    pub final_rip: u64,

    /// Final `RSP`.
    pub final_rsp: u64,

    pub profile: Option<RuntimeProfile>,
}

/// Result of running a persistent runtime session until it yields or stops.
#[derive(Debug, Clone)]
pub struct RuntimeRunSummary {
    /// API events observed during this run segment.
    pub events: Vec<EntryTraceEvent>,

    /// Reason why this run segment stopped.
    pub termination: EntryTraceTermination,

    /// Final guest instruction pointer.
    pub final_rip: u64,

    /// Final guest stack pointer.
    pub final_rsp: u64,
}

/// Reason why entry-point tracing stopped.
#[derive(Debug, Clone)]
pub enum EntryTraceTermination {
    /// The guest called `KERNEL32.dll!ExitProcess`.
    ExitProcess {
        /// Exit code supplied by the guest.
        code: u32,
    },

    /// Execution reached an unsupported API.
    UnsupportedApi(String),

    /// Execution stopped for another runtime diagnostic reason.
    RuntimeStop(String),

    /// The maximum number of processed API calls was reached.
    ApiLimit,

    /// Execution yielded because `GetMessageA` is waiting for input.
    WaitingForMessage,

    /// Execution stopped before invoking a guest callback.
    GuestCallbackRequested {
        /// Description of the requested callback.
        request: wie_winapi::GuestCallbackRequest,
    },
}

fn run_session_to_summary(
    path: &std::path::Path,
    idle_policy: wie_winapi::MessageQueueIdlePolicy,
    max_api: usize,
) -> Result<EntryTraceSummary> {
    let mut session = RuntimeSession::new(path, idle_policy)?;

    let entry_point_va = session.entry_point_va();
    let initial_rsp = session.initial_rsp();
    let run_summary = session.run_until_stop(max_api)?;
    let profile = if session.profile_enabled() {
        Some(session.profile().clone())
    } else {
        None
    };
    Ok(EntryTraceSummary {
        entry_point_va,
        initial_rsp,
        events: run_summary.events,
        termination: run_summary.termination,
        final_rip: run_summary.final_rip,
        final_rsp: run_summary.final_rsp,
        profile,
    })
}

/// Runs the deterministic entry-to-exit regression trace.
pub fn entry_trace(path: &std::path::Path, max_api: usize) -> Result<EntryTraceSummary> {
    run_session_to_summary(
        path,
        wie_winapi::MessageQueueIdlePolicy::ExitOnIdle,
        max_api,
    )
}

/// Summary of a freestanding / micro-PE run until `ExitProcess` (or failure).
#[derive(Debug, Clone)]
pub struct MicroRunSummary {
    /// Path that was executed.
    pub path: String,
    /// PE entry point VA.
    pub entry_point_va: u64,
    /// Initial RSP.
    pub initial_rsp: u64,
    /// Guest exit code when termination is [`EntryTraceTermination::ExitProcess`].
    pub exit_code: Option<u32>,
    /// Full run segment.
    pub run: RuntimeRunSummary,
    /// Active CPU backend name (`jit` / `iced`).
    pub cpu_backend: String,
    pub profile: Option<RuntimeProfile>,
}

/// Runs a PE until `ExitProcess` (or another terminal condition).
///
/// Intended for freestanding micro-exes that never enter a message loop.
/// Uses [`MessageQueueIdlePolicy::ExitOnIdle`] so an accidental idle path fails
/// closed instead of hanging.
pub fn run_micro_exe(path: &std::path::Path, max_api: usize) -> Result<MicroRunSummary> {
    run_micro_exe_with_root(path, max_api, wie_winapi::bottle_root_from_env())
}

/// Like [`run_micro_exe`], with an explicit bottle root (`None` = no bottle / env ignored).
pub fn run_micro_exe_with_root(
    path: &std::path::Path,
    max_api: usize,
    bottle_root: Option<std::path::PathBuf>,
) -> Result<MicroRunSummary> {
    let wall_t0 = std::time::Instant::now();
    let (cpu0_user, cpu0_sys) = wie_cpu::process_cpu_times_us();
    let mut session = RuntimeSession::new(path, wie_winapi::MessageQueueIdlePolicy::ExitOnIdle)?;
    session.set_bottle_root(bottle_root);
    let entry_point_va = session.entry_point_va();
    let initial_rsp = session.initial_rsp();
    let run = session.run_until_stop(max_api)?;
    let wall_ns = wall_t0.elapsed().as_nanos();
    let (cpu1_user, cpu1_sys) = wie_cpu::process_cpu_times_us();
    let cpu_user_us = cpu1_user.saturating_sub(cpu0_user);
    let cpu_sys_us = cpu1_sys.saturating_sub(cpu0_sys);
    if session.profile_enabled() {
        session.finalize_profile(wall_ns, cpu_user_us, cpu_sys_us);
    }
    let profile = if session.profile_enabled() {
        Some(session.profile().clone())
    } else {
        None
    };
    let exit_code = match run.termination {
        EntryTraceTermination::ExitProcess { code } => Some(code),
        _ => None,
    };
    Ok(MicroRunSummary {
        path: path.display().to_string(),
        entry_point_va,
        initial_rsp,
        exit_code,
        run,
        cpu_backend: crate::active_backend_name().to_owned(),
        profile,
    })
}

/// Runs Lunar Magic until the runtime yields waiting for a message
/// or reaches another terminal condition.
pub fn run_persistent_until_yield(
    path: &std::path::Path,
    max_api: usize,
) -> Result<EntryTraceSummary> {
    run_session_to_summary(
        path,
        wie_winapi::MessageQueueIdlePolicy::YieldOnIdle,
        max_api,
    )
}
