//! Entry-point tracing summaries and persistent smoke-test entry points.

use crate::session::RuntimeSession;
use anyhow::{Context, Result};

/// One API event observed during entry-point tracing.
#[derive(Debug, Clone)]
pub struct EntryTraceEvent {
    /// Event index.
    pub index: usize,

    /// Imported library name.
    pub library: String,

    /// Imported function name.
    pub name: String,

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

/// Result of the persistent yield/resume smoke test.
#[derive(Debug, Clone)]
pub struct PersistentResumeSmokeSummary {
    /// PE entry point.
    pub entry_point_va: u64,

    /// Initial guest stack pointer.
    pub initial_rsp: u64,

    /// First segment, expected to yield on an empty message queue.
    pub first_run: RuntimeRunSummary,

    /// Second segment after queuing `WM_NULL`.
    pub resumed_run: RuntimeRunSummary,
}

/// Result of detecting a guest callback request.
#[derive(Debug, Clone)]
pub struct PersistentCallbackSmokeSummary {
    /// PE entry point.
    pub entry_point_va: u64,

    /// Initial guest stack pointer.
    pub initial_rsp: u64,

    /// Initial run ending at an empty `GetMessageA`.
    pub first_run: RuntimeRunSummary,

    /// Run after posting a message to a guest-owned window.
    pub callback_run: RuntimeRunSummary,
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

    Ok(EntryTraceSummary {
        entry_point_va,
        initial_rsp,
        events: run_summary.events,
        termination: run_summary.termination,
        final_rip: run_summary.final_rip,
        final_rsp: run_summary.final_rsp,
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
    let mut session = RuntimeSession::new(path, wie_winapi::MessageQueueIdlePolicy::ExitOnIdle)?;
    session.set_bottle_root(bottle_root);
    let entry_point_va = session.entry_point_va();
    let initial_rsp = session.initial_rsp();
    let run = session.run_until_stop(max_api)?;
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

/// Verifies that a persistent session can yield, receive a message and resume.
pub fn run_persistent_resume_smoke(
    path: &std::path::Path,
    max_api: usize,
) -> Result<PersistentResumeSmokeSummary> {
    const WM_NULL: u32 = 0x0000;

    let mut session = RuntimeSession::new(path, wie_winapi::MessageQueueIdlePolicy::YieldOnIdle)?;

    let entry_point_va = session.entry_point_va();
    let initial_rsp = session.initial_rsp();

    let first_run = session.run_until_stop(max_api)?;

    if !matches!(
        first_run.termination,
        EntryTraceTermination::WaitingForMessage
    ) {
        anyhow::bail!(
            "persistent smoke expected WaitingForMessage, got {:?}",
            first_run.termination,
        );
    }

    /*
     * A thread message with HWND == 0 is sufficient for this smoke test.
     * WM_NULL has no application semantics, but proves that GetMessageA can
     * return a real queued message after the runtime resumes.
     */
    session.post_window_message(0, WM_NULL, 0, 0)?;

    let resumed_run = session.run_until_stop(max_api)?;

    Ok(PersistentResumeSmokeSummary {
        entry_point_va,
        initial_rsp,
        first_run,
        resumed_run,
    })
}

/// Verifies that `DispatchMessageA` invokes a guest window procedure and returns.
///
/// After posting `WM_NULL` to a guest-owned window the runtime must:
/// 1. enter the guest WndProc through the callback bridge,
/// 2. complete `DispatchMessageA` with the WndProc `LRESULT`,
/// 3. eventually yield again on an empty message queue.
pub fn run_persistent_callback_smoke(
    path: &std::path::Path,
    max_api: usize,
) -> Result<PersistentCallbackSmokeSummary> {
    const WM_NULL: u32 = 0x0000;

    let mut session = RuntimeSession::new(path, wie_winapi::MessageQueueIdlePolicy::YieldOnIdle)?;

    let entry_point_va = session.entry_point_va();
    let initial_rsp = session.initial_rsp();

    let first_run = session.run_until_stop(max_api)?;

    if !matches!(
        first_run.termination,
        EntryTraceTermination::WaitingForMessage
    ) {
        anyhow::bail!(
            "callback smoke expected initial WaitingForMessage, got {:?}",
            first_run.termination,
        );
    }

    let window_handle = session
        .first_guest_window_handle()
        .context("callback smoke found no window backed by a guest WndProc")?;

    session.post_window_message(window_handle, WM_NULL, 0, 0)?;

    let callback_run = session.run_until_stop(max_api)?;

    if !matches!(
        callback_run.termination,
        EntryTraceTermination::WaitingForMessage
    ) {
        anyhow::bail!(
            "callback smoke expected WaitingForMessage after WndProc completed, got {:?}",
            callback_run.termination,
        );
    }

    if session.pending_callback_depth() != 0 {
        anyhow::bail!(
            "callback smoke left {} pending guest callback(s)",
            session.pending_callback_depth(),
        );
    }

    // Completion is logged under the outer API name with LRESULT + resume.
    let dispatch_completed = callback_run.events.iter().any(|event| {
        event.library.eq_ignore_ascii_case("USER32.dll")
            && event.name.eq_ignore_ascii_case("DispatchMessageA")
            && event.return_value.is_some()
            && event.return_address.is_some()
    });

    if !dispatch_completed {
        anyhow::bail!(
            "callback smoke did not observe a completed DispatchMessageA \
             (with LRESULT and resume address) after the guest WndProc"
        );
    }

    Ok(PersistentCallbackSmokeSummary {
        entry_point_va,
        initial_rsp,
        first_run,
        callback_run,
    })
}

/// Summary of the host-backed ROM mount / open smoke test.
#[derive(Debug, Clone)]
pub struct RomFilesystemSmokeSummary {
    /// Guest path used for the mount and dialog policy.
    pub guest_path: String,

    /// Host path of the ROM.
    pub host_path: String,

    /// Open handle returned by the guest FS layer.
    pub handle: u64,

    /// ROM size in bytes.
    pub size: u64,

    /// First 16 bytes of the ROM (for identity checks).
    pub header_prefix: Vec<u8>,

    /// Whether bootstrap still reaches the message loop after mounting.
    pub message_loop_yielded: bool,
}

/// Mounts a host ROM, verifies `CreateFile`-compatible open/read, and
/// confirms the message loop still yields after bootstrap.
pub fn run_rom_filesystem_smoke(
    pe_path: &std::path::Path,
    rom_host_path: &std::path::Path,
    guest_path: &str,
    max_api: usize,
) -> Result<RomFilesystemSmokeSummary> {
    let mut session =
        RuntimeSession::new(pe_path, wie_winapi::MessageQueueIdlePolicy::YieldOnIdle)?;

    session.mount_host_file(guest_path, rom_host_path)?;
    session.set_file_dialog_policy(wie_winapi::FileDialogPolicy::Accept {
        path: guest_path.to_owned(),
    });

    let handle = session.open_guest_path(guest_path)?;
    let size = session.guest_file_size(handle)?;
    let header_prefix = session.peek_guest_file(handle, 0, 16.min(usize::try_from(size)?))?;

    if size == 0 {
        anyhow::bail!(
            "mounted ROM opened with zero size: {}",
            rom_host_path.display()
        );
    }

    let host_size = std::fs::metadata(rom_host_path)
        .with_context(|| format!("failed to stat host ROM {}", rom_host_path.display()))?
        .len();

    if size != host_size {
        anyhow::bail!(
            "mounted ROM size mismatch guest={size} host={host_size} path={}",
            rom_host_path.display()
        );
    }

    let run = session.run_until_stop(max_api)?;
    let message_loop_yielded = matches!(run.termination, EntryTraceTermination::WaitingForMessage);

    if !message_loop_yielded {
        anyhow::bail!(
            "rom fs smoke expected WaitingForMessage after bootstrap, got {:?}",
            run.termination
        );
    }

    Ok(RomFilesystemSmokeSummary {
        guest_path: guest_path.to_owned(),
        host_path: rom_host_path.display().to_string(),
        handle,
        size,
        header_prefix,
        message_loop_yielded,
    })
}

/// Lunar Magic File menu command: `&Open ROM...`
pub const WIE_MENU_ID_OPEN_ROM: u32 = 0x238c;

/// Windows `WM_COMMAND`.
const WM_COMMAND: u32 = 0x0111;

/// File-menu command IDs tried for open-rom / post-open smokes.
const OPEN_ROM_COMMAND_IDS: &[u32] = &[
    WIE_MENU_ID_OPEN_ROM,
    0x238d, // Open Level from File
    0x238e,
    0x2391,
];

/// Window handles to try for synthetic `WM_COMMAND` (preferred first, then WndProc windows).
fn command_window_candidates(session: &RuntimeSession) -> Vec<u64> {
    let preferred = session.preferred_command_window_handle();
    let mut handles: Vec<u64> = preferred.into_iter().collect();
    for (handle, _class, _title, has_proc) in session.guest_windows_snapshot() {
        if has_proc && !handles.contains(&handle) {
            handles.push(handle);
        }
    }
    handles
}

/// Summary of driving File → Open ROM through the guest message path.
#[derive(Debug, Clone)]
pub struct OpenRomSmokeSummary {
    /// PE entry point.
    pub entry_point_va: u64,

    /// Guest path configured for dialog + mount.
    pub guest_path: String,

    /// Host ROM path.
    pub host_path: String,

    /// Menu command id posted as `WM_COMMAND`.
    pub menu_command_id: u32,

    /// Target HWND that received the command.
    pub window_handle: u64,

    /// Bootstrap run ending at empty `GetMessageA`.
    pub first_run: RuntimeRunSummary,

    /// Run after posting `WM_COMMAND` for Open ROM.
    pub open_run: RuntimeRunSummary,

    /// Whether any `GetOpenFileNameA/W` completed during `open_run`.
    pub saw_get_open_file_name: bool,

    /// Whether any `CreateFileA/W` completed during `open_run`.
    pub saw_create_file: bool,

    /// Whether the mounted ROM is among currently open guest files.
    pub rom_handle_open: bool,

    /// Open handle for the ROM if present.
    pub rom_handle: Option<u64>,

    /// ROM size if open.
    pub rom_size: Option<u64>,

    /// Whether open_run returned to the idle message loop.
    pub returned_to_message_loop: bool,

    /// Guest windows that look like a level editor after open.
    pub saw_level_editor_window: bool,
}

/// Mounts a ROM, posts File→Open ROM, and checks dialog + CreateFile progress.
pub fn run_open_rom_smoke(
    pe_path: &std::path::Path,
    rom_host_path: &std::path::Path,
    guest_path: &str,
    max_api: usize,
) -> Result<OpenRomSmokeSummary> {
    let mut session =
        RuntimeSession::new(pe_path, wie_winapi::MessageQueueIdlePolicy::YieldOnIdle)?;

    session.mount_host_file(guest_path, rom_host_path)?;
    session.set_file_dialog_policy(wie_winapi::FileDialogPolicy::Accept {
        path: guest_path.to_owned(),
    });

    let entry_point_va = session.entry_point_va();

    let first_run = session.run_until_stop(max_api)?;
    if !matches!(
        first_run.termination,
        EntryTraceTermination::WaitingForMessage
    ) {
        anyhow::bail!(
            "open-rom smoke expected initial WaitingForMessage, got {:?}",
            first_run.termination,
        );
    }

    let windows = session.guest_windows_snapshot();
    tracing::info!(?windows, "open-rom smoke guest windows");

    let candidate_handles = command_window_candidates(&session);
    if candidate_handles.is_empty() {
        anyhow::bail!("open-rom smoke found no guest window for WM_COMMAND");
    }

    let mut open_run = RuntimeRunSummary {
        events: Vec::new(),
        termination: EntryTraceTermination::ApiLimit,
        final_rip: 0,
        final_rsp: 0,
    };
    let mut window_handle = candidate_handles[0];
    let mut menu_command_id = WIE_MENU_ID_OPEN_ROM;
    let mut saw_get_open_file_name = false;
    let mut saw_create_file = false;

    'commands: for handle in candidate_handles {
        for &command_id in OPEN_ROM_COMMAND_IDS {
            session.post_window_message(handle, WM_COMMAND, u64::from(command_id), 0)?;

            let run = session.run_until_stop(max_api)?;

            let got_dialog = run.events.iter().any(|event| {
                event.library.eq_ignore_ascii_case("comdlg32.dll")
                    && (event.name.eq_ignore_ascii_case("GetOpenFileNameA")
                        || event.name.eq_ignore_ascii_case("GetOpenFileNameW"))
                    && event.handled
            });
            let got_create = run.events.iter().any(|event| {
                event.library.eq_ignore_ascii_case("KERNEL32.dll")
                    && (event.name.eq_ignore_ascii_case("CreateFileA")
                        || event.name.eq_ignore_ascii_case("CreateFileW"))
                    && event.handled
            });

            open_run = run;
            window_handle = handle;
            menu_command_id = command_id;
            saw_get_open_file_name = got_dialog;
            saw_create_file = got_create;

            if got_dialog || got_create {
                break 'commands;
            }

            // If we stopped for an unsupported API, keep that result for diagnosis.
            if matches!(
                open_run.termination,
                EntryTraceTermination::UnsupportedApi(_)
            ) {
                break 'commands;
            }

            // After a clean yield with no progress, try the next command/window.
            if !matches!(
                open_run.termination,
                EntryTraceTermination::WaitingForMessage
            ) {
                break 'commands;
            }
        }
    }

    let guest_base = guest_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(guest_path)
        .to_ascii_lowercase();

    let rom_open =
        session
            .open_guest_files_snapshot()
            .into_iter()
            .find(|(_handle, path, _size)| {
                let path_l = path.to_ascii_lowercase();
                path_l.contains(&guest_path.to_ascii_lowercase())
                    || path_l
                        .rsplit(['\\', '/'])
                        .next()
                        .is_some_and(|name| name == guest_base)
            });

    let rom_handle = rom_open.as_ref().map(|(handle, _, _)| *handle);
    let rom_size = rom_open.as_ref().map(|(_, _, size)| *size);

    let returned_to_message_loop = matches!(
        open_run.termination,
        EntryTraceTermination::WaitingForMessage
    );

    let saw_level_editor_window =
        session
            .guest_windows_snapshot()
            .iter()
            .any(|(_handle, class, title, _has_proc)| {
                let class_l = class.to_ascii_lowercase();
                let title_l = title.to_ascii_lowercase();
                class_l.contains("smw")
                    || class_l.contains("leveleditor")
                    || title_l.contains("level")
                    || title_l.contains("smw")
            });

    if session.profile_enabled() {
        eprintln!("{}", session.profile().report());
    }

    Ok(OpenRomSmokeSummary {
        entry_point_va,
        guest_path: guest_path.to_owned(),
        host_path: rom_host_path.display().to_string(),
        menu_command_id,
        window_handle,
        first_run,
        open_run,
        saw_get_open_file_name,
        saw_create_file,
        rom_handle_open: rom_handle.is_some(),
        rom_handle,
        rom_size,
        returned_to_message_loop,
        saw_level_editor_window,
    })
}

/// Windows `WM_PAINT`.
const WM_PAINT: u32 = 0x000f;
/// Windows mouse / keyboard messages used by research input probes.
const WM_MOUSEMOVE: u32 = 0x0200;
const WM_LBUTTONDOWN: u32 = 0x0201;
const WM_LBUTTONUP: u32 = 0x0202;
const WM_KEYDOWN: u32 = 0x0100;
const WM_KEYUP: u32 = 0x0101;
const WM_CHAR: u32 = 0x0102;
const MK_LBUTTON: u64 = 0x0001;
const VK_RIGHT: u64 = 0x27;
const VK_DOWN: u64 = 0x28;

/// Shared research helper: boot WIE, open mounted ROM, stop at idle message loop.
struct OpenedRomSession {
    session: RuntimeSession,
    open: OpenRomSmokeSummary,
    windows_after_open: Vec<(u64, String, String, bool)>,
}

fn open_rom_session_to_idle(
    pe_path: &std::path::Path,
    rom_host_path: &std::path::Path,
    guest_path: &str,
    max_api: usize,
    scenario: &str,
) -> Result<OpenedRomSession> {
    let mut session =
        RuntimeSession::new(pe_path, wie_winapi::MessageQueueIdlePolicy::YieldOnIdle)?;

    session.mount_host_file(guest_path, rom_host_path)?;
    session.set_file_dialog_policy(wie_winapi::FileDialogPolicy::Accept {
        path: guest_path.to_owned(),
    });

    let entry_point_va = session.entry_point_va();

    let first_run = session.run_until_stop(max_api)?;
    if !matches!(
        first_run.termination,
        EntryTraceTermination::WaitingForMessage
    ) {
        anyhow::bail!(
            "{scenario} expected initial WaitingForMessage, got {:?}",
            first_run.termination,
        );
    }

    let candidate_handles = command_window_candidates(&session);
    if candidate_handles.is_empty() {
        anyhow::bail!("{scenario} found no guest window for WM_COMMAND");
    }

    let mut open_run = RuntimeRunSummary {
        events: Vec::new(),
        termination: EntryTraceTermination::ApiLimit,
        final_rip: 0,
        final_rsp: 0,
    };
    let mut window_handle = candidate_handles[0];
    let mut menu_command_id = WIE_MENU_ID_OPEN_ROM;
    let mut saw_get_open_file_name = false;
    let mut saw_create_file = false;

    'commands: for handle in candidate_handles {
        for &command_id in OPEN_ROM_COMMAND_IDS {
            session.post_window_message(handle, WM_COMMAND, u64::from(command_id), 0)?;
            let run = session.run_until_stop(max_api)?;
            let got_dialog = run.events.iter().any(|event| {
                event.library.eq_ignore_ascii_case("comdlg32.dll")
                    && (event.name.eq_ignore_ascii_case("GetOpenFileNameA")
                        || event.name.eq_ignore_ascii_case("GetOpenFileNameW"))
                    && event.handled
            });
            let got_create = run.events.iter().any(|event| {
                event.library.eq_ignore_ascii_case("KERNEL32.dll")
                    && (event.name.eq_ignore_ascii_case("CreateFileA")
                        || event.name.eq_ignore_ascii_case("CreateFileW"))
                    && event.handled
            });
            open_run = run;
            window_handle = handle;
            menu_command_id = command_id;
            saw_get_open_file_name = got_dialog;
            saw_create_file = got_create;
            if got_dialog || got_create {
                break 'commands;
            }
            if !matches!(
                open_run.termination,
                EntryTraceTermination::WaitingForMessage
            ) {
                break 'commands;
            }
        }
    }

    if !matches!(
        open_run.termination,
        EntryTraceTermination::WaitingForMessage
    ) {
        anyhow::bail!(
            "{scenario} requires open to return to message loop first; got {:?}",
            open_run.termination
        );
    }
    if !(saw_get_open_file_name || saw_create_file) {
        anyhow::bail!("{scenario} saw no open progress before next phase");
    }

    let windows_after_open = session.guest_windows_snapshot();
    let saw_level_editor_window = windows_after_open.iter().any(|(_h, class, title, _)| {
        let class_l = class.to_ascii_lowercase();
        let title_l = title.to_ascii_lowercase();
        class_l.contains("smw")
            || class_l.contains("leveleditor")
            || title_l.contains("level")
            || title_l.contains("smw")
    });

    let guest_base = guest_path
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(guest_path)
        .to_ascii_lowercase();
    let rom_open =
        session
            .open_guest_files_snapshot()
            .into_iter()
            .find(|(_handle, path, _size)| {
                let path_l = path.to_ascii_lowercase();
                path_l.contains(&guest_path.to_ascii_lowercase())
                    || path_l
                        .rsplit(['\\', '/'])
                        .next()
                        .is_some_and(|name| name == guest_base)
            });

    let open = OpenRomSmokeSummary {
        entry_point_va,
        guest_path: guest_path.to_owned(),
        host_path: rom_host_path.display().to_string(),
        menu_command_id,
        window_handle,
        first_run,
        open_run,
        saw_get_open_file_name,
        saw_create_file,
        rom_handle_open: rom_open.is_some(),
        rom_handle: rom_open.as_ref().map(|(h, _, _)| *h),
        rom_size: rom_open.as_ref().map(|(_, _, s)| *s),
        returned_to_message_loop: true,
        saw_level_editor_window,
    };

    Ok(OpenedRomSession {
        session,
        open,
        windows_after_open,
    })
}

fn level_editor_targets(windows: &[(u64, String, String, bool)]) -> Vec<u64> {
    let mut targets: Vec<u64> = windows
        .iter()
        .filter(|(_h, class, title, has_proc)| {
            if !has_proc {
                return false;
            }
            let class_l = class.to_ascii_lowercase();
            let title_l = title.to_ascii_lowercase();
            class_l.contains("smw")
                || class_l.contains("leveleditor")
                || class_l.contains("level")
                || title_l.contains("level")
                || title_l.contains("smw")
        })
        .map(|(h, _, _, _)| *h)
        .collect();
    if targets.is_empty() {
        targets = windows
            .iter()
            .filter(|(_, _, _, has_proc)| *has_proc)
            .map(|(h, _, _, _)| *h)
            .collect();
    }
    targets
}

fn pack_mouse_lparam(x: u16, y: u16) -> u64 {
    u64::from(x) | (u64::from(y) << 16)
}

/// Research probe: open ROM, then drive paint on editor windows.
///
/// This is intentionally a **scenario harness**, not a product default path.
#[derive(Debug, Clone)]
pub struct PostOpenPaintProbeSummary {
    /// Underlying open-ROM progress summary.
    pub open: OpenRomSmokeSummary,

    /// Guest windows after open (handle, class, title, has_proc).
    pub windows_after_open: Vec<(u64, String, String, bool)>,

    /// HWNDs that received `WM_PAINT`.
    pub paint_targets: Vec<u64>,

    /// Run after posting paint messages.
    pub paint_run: RuntimeRunSummary,

    /// Whether paint path hit `BeginPaint`.
    pub saw_begin_paint: bool,

    /// Whether paint path hit `EndPaint`.
    pub saw_end_paint: bool,

    /// Whether paint segment returned to the idle message loop.
    pub returned_to_message_loop: bool,
}

/// Opens a ROM (same path as open-rom smoke), then posts `WM_PAINT` to editor windows.
pub fn run_post_open_paint_probe(
    pe_path: &std::path::Path,
    rom_host_path: &std::path::Path,
    guest_path: &str,
    max_api: usize,
) -> Result<PostOpenPaintProbeSummary> {
    let OpenedRomSession {
        mut session,
        open,
        windows_after_open,
    } = open_rom_session_to_idle(
        pe_path,
        rom_host_path,
        guest_path,
        max_api,
        "post-open paint",
    )?;

    let paint_targets = level_editor_targets(&windows_after_open);
    for &hwnd in &paint_targets {
        session.post_window_message(hwnd, WM_PAINT, 0, 0)?;
    }

    let paint_run = session.run_until_stop(max_api)?;
    let saw_begin_paint = paint_run.events.iter().any(|event| {
        event.library.eq_ignore_ascii_case("USER32.dll")
            && event.name.eq_ignore_ascii_case("BeginPaint")
            && event.handled
    });
    let saw_end_paint = paint_run.events.iter().any(|event| {
        event.library.eq_ignore_ascii_case("USER32.dll")
            && event.name.eq_ignore_ascii_case("EndPaint")
            && event.handled
    });
    let returned_to_message_loop = matches!(
        paint_run.termination,
        EntryTraceTermination::WaitingForMessage
    );

    Ok(PostOpenPaintProbeSummary {
        open,
        windows_after_open,
        paint_targets,
        paint_run,
        saw_begin_paint,
        saw_end_paint,
        returned_to_message_loop,
    })
}

/// Research probe: open ROM, then inject mouse/keyboard into the level editor.
///
/// Scenario harness only — not a product interactive UI.
#[derive(Debug, Clone)]
pub struct PostOpenInputProbeSummary {
    /// Underlying open-ROM progress summary.
    pub open: OpenRomSmokeSummary,

    /// Guest windows after open.
    pub windows_after_open: Vec<(u64, String, String, bool)>,

    /// HWND that received the input sequence.
    pub input_target: u64,

    /// Short description of posted messages.
    pub posted_sequence: Vec<String>,

    /// Run after posting input messages.
    pub input_run: RuntimeRunSummary,

    /// Whether any guest WndProc dispatch happened.
    pub saw_dispatch: bool,

    /// Whether paint APIs ran as a side effect of input.
    pub saw_begin_paint: bool,

    /// Whether input segment returned to the idle message loop.
    pub returned_to_message_loop: bool,
}

/// Opens a ROM, then posts a deterministic mouse + key sequence to the level editor.
pub fn run_post_open_input_probe(
    pe_path: &std::path::Path,
    rom_host_path: &std::path::Path,
    guest_path: &str,
    max_api: usize,
) -> Result<PostOpenInputProbeSummary> {
    let OpenedRomSession {
        mut session,
        open,
        windows_after_open,
    } = open_rom_session_to_idle(
        pe_path,
        rom_host_path,
        guest_path,
        max_api,
        "post-open input",
    )?;

    let targets = level_editor_targets(&windows_after_open);
    let input_target = targets.first().copied().ok_or_else(|| {
        anyhow::anyhow!("post-open input probe found no level-editor target window")
    })?;

    // Client coords roughly inside a typical editor client area.
    let click_x = 128_u16;
    let click_y = 96_u16;
    let mouse_lparam = pack_mouse_lparam(click_x, click_y);

    let mut posted_sequence = Vec::new();
    let sequence: &[(u32, u64, u64, &str)] = &[
        (WM_MOUSEMOVE, 0, mouse_lparam, "WM_MOUSEMOVE"),
        (WM_LBUTTONDOWN, MK_LBUTTON, mouse_lparam, "WM_LBUTTONDOWN"),
        (WM_LBUTTONUP, 0, mouse_lparam, "WM_LBUTTONUP"),
        (WM_KEYDOWN, VK_RIGHT, 1, "WM_KEYDOWN VK_RIGHT"),
        (WM_KEYUP, VK_RIGHT, 0xc000_0001, "WM_KEYUP VK_RIGHT"),
        (WM_KEYDOWN, VK_DOWN, 1, "WM_KEYDOWN VK_DOWN"),
        (WM_KEYUP, VK_DOWN, 0xc000_0001, "WM_KEYUP VK_DOWN"),
        // Common editor shortcut probes (may be ignored by guest).
        (WM_KEYDOWN, u64::from(b'G'), 1, "WM_KEYDOWN 'G'"),
        (WM_CHAR, u64::from(b'g'), 1, "WM_CHAR 'g'"),
        (WM_KEYUP, u64::from(b'G'), 0xc000_0001, "WM_KEYUP 'G'"),
        (WM_PAINT, 0, 0, "WM_PAINT"),
    ];

    for &(message, wparam, lparam, label) in sequence {
        session.post_window_message(input_target, message, wparam, lparam)?;
        posted_sequence.push(format!(
            "hwnd={input_target:#x} {label} wparam={wparam:#x} lparam={lparam:#x}"
        ));
    }

    let input_run = session.run_until_stop(max_api)?;
    let saw_dispatch = input_run.events.iter().any(|event| {
        event.library.eq_ignore_ascii_case("USER32.dll")
            && (event.name.eq_ignore_ascii_case("DispatchMessageA")
                || event.name.eq_ignore_ascii_case("DispatchMessageW")
                || event.name.eq_ignore_ascii_case("SendMessageA")
                || event.name.eq_ignore_ascii_case("SendMessageW"))
            && event.handled
    });
    let saw_begin_paint = input_run.events.iter().any(|event| {
        event.library.eq_ignore_ascii_case("USER32.dll")
            && event.name.eq_ignore_ascii_case("BeginPaint")
            && event.handled
    });
    let returned_to_message_loop = matches!(
        input_run.termination,
        EntryTraceTermination::WaitingForMessage
    );

    Ok(PostOpenInputProbeSummary {
        open,
        windows_after_open,
        input_target,
        posted_sequence,
        input_run,
        saw_dispatch,
        saw_begin_paint,
        returned_to_message_loop,
    })
}
