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
    run_micro_exe_with_options(
        path,
        max_api,
        MicroRunOptions {
            bottle_root,
            ..MicroRunOptions::default()
        },
    )
}

/// Options for [`run_micro_exe_with_options`].
#[derive(Debug, Clone, Default)]
pub struct MicroRunOptions {
    /// Bottle root for guest `C:\…` mapping (`None` = no bottle / ignore `WIE_ROOT`).
    pub bottle_root: Option<std::path::PathBuf>,
    /// Extra guest argv after the module basename (visible via `GetCommandLine*`).
    pub guest_args: Vec<String>,
    /// Console stdin bytes for `ReadFile(STD_INPUT_HANDLE)`.
    /// Non-empty injects and disables live host read; empty enables live host.
    pub stdin_bytes: Vec<u8>,
}

/// Like [`run_micro_exe_with_root`], with guest argv and stdin injection.
pub fn run_micro_exe_with_options(
    path: &std::path::Path,
    max_api: usize,
    options: MicroRunOptions,
) -> Result<MicroRunSummary> {
    let wall_t0 = std::time::Instant::now();
    let (cpu0_user, cpu0_sys) = wie_cpu::process_cpu_times_us();
    let mut session = RuntimeSession::new_with_options(
        path,
        wie_winapi::MessageQueueIdlePolicy::ExitOnIdle,
        crate::DEFAULT_LAYOUT,
        crate::SessionOptions {
            guest_args: options.guest_args,
            stdin_bytes: options.stdin_bytes,
        },
    )?;
    session.set_bottle_root(options.bottle_root);
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

/// Runs until the runtime yields waiting for a message or another terminal condition.
///
/// Phase 6: under [`wie_winapi::IdlePolicy::Park`] (default for persistent when
/// `WIE_IDLE` is unset), empty `GetMessage` parks the host for short quanta and
/// re-enters until a message arrives or `WIE_IDLE_MAX_PARKS` is hit (then yields).
pub fn run_persistent_until_yield(
    path: &std::path::Path,
    max_api: usize,
) -> Result<EntryTraceSummary> {
    use std::time::Instant;
    use wie_winapi::{IdleContext, IdlePolicy};

    let idle = IdlePolicy::from_env_for(IdleContext::Persistent);
    let mut session =
        RuntimeSession::new(path, wie_winapi::MessageQueueIdlePolicy::YieldOnIdle)?;

    if session.profile_enabled() {
        session.profile_mut().idle_policy = idle.as_str().to_owned();
    }

    let entry_point_va = session.entry_point_va();
    let initial_rsp = session.initial_rsp();
    let mut events = Vec::new();
    let mut final_rip = 0;
    let mut final_rsp = 0;
    let mut remaining_api = max_api;
    let mut message_parks: u32 = 0;
    let max_parks = wie_winapi::idle::idle_max_message_parks();

    let termination = loop {
        if remaining_api == 0 {
            break EntryTraceTermination::ApiLimit;
        }

        let run_summary = session.run_until_stop(remaining_api)?;
        let used = run_summary.events.len();
        remaining_api = remaining_api.saturating_sub(used);
        events.extend(run_summary.events);
        final_rip = run_summary.final_rip;
        final_rsp = run_summary.final_rsp;

        match run_summary.termination {
            EntryTraceTermination::WaitingForMessage if idle.should_park_message() => {
                let unlimited = max_parks == 0;
                if !unlimited && message_parks >= max_parks {
                    break EntryTraceTermination::WaitingForMessage;
                }
                let t0 = Instant::now();
                wie_winapi::idle::apply_message_park();
                let park_ns = t0.elapsed().as_nanos();
                message_parks = message_parks.saturating_add(1);
                if session.profile_enabled() {
                    let p = session.profile_mut();
                    p.idle_parks = p.idle_parks.saturating_add(1);
                    p.idle_park_ns = p.idle_park_ns.saturating_add(park_ns);
                }
                // Re-enter GetMessage (guest still at fake-API entry).
            }
            other => break other,
        }
    };

    let profile = if session.profile_enabled() {
        Some(session.profile().clone())
    } else {
        None
    };

    Ok(EntryTraceSummary {
        entry_point_va,
        initial_rsp,
        events,
        termination,
        final_rip,
        final_rsp,
        profile,
    })
}
