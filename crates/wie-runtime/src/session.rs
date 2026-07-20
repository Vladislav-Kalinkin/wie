//! Persistent `RuntimeSession`: guest setup, yield/resume, and API hook loop.

use crate::hooks::{
    SoftApiTable, build_iat_fake_api_entries, collect_stub_entries, resolve_fake_api_at,
    resolve_import_fake_va,
};
use crate::memory::{
    DEFAULT_LAYOUT, RuntimeMemoryLayout, build_default_environment_strings_w,
    default_winapi_environment, default_winapi_state, write_process_identity_strings,
};
use crate::mt_runtime::ProcessResources;
use crate::trace::{EntryTraceEvent, EntryTraceTermination, RuntimeRunSummary};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// Bootstrap options for a new guest session (argv / stdin injection).
#[derive(Debug, Clone, Default)]
pub struct SessionOptions {
    /// Extra command-line arguments after argv[0] (module basename).
    pub guest_args: Vec<String>,
    /// Bytes for console `ReadFile(STD_INPUT_HANDLE)`.
    ///
    /// Non-empty: inject-only (no host block). Empty: live host stdin when the
    /// guest reads STD_INPUT (line-oriented).
    pub stdin_bytes: Vec<u8>,
}

/// Guest CRT page layout (must match `wie_winapi::ucrt` and guest stubs).
const CRT_GUEST_BASE: u64 = 0x0000_0000_6800_0000;
const CRT_ARGV_PTR_SLOT: u64 = CRT_GUEST_BASE + 0x308;
const CRT_ARGC_SLOT: u64 = CRT_GUEST_BASE + 0x310;
const CRT_ACMDLN_PTR_SLOT: u64 = CRT_GUEST_BASE + 0x328;
/// Pointer table for `char *argv[]` (null-terminated).
const CRT_ARGV_TABLE: u64 = CRT_GUEST_BASE + 0x400;
/// Storage for argv string bodies.
const CRT_ARGV_STRINGS: u64 = CRT_GUEST_BASE + 0x500;
const CRT_PAGE_END: u64 = CRT_GUEST_BASE + 0x1000;

/// Materialize UCRT `__p___argc` / `__p___argv` / `__p__acmdln` guest slots.
fn materialize_crt_argv(
    engine: &mut dyn wie_cpu::CpuEngine,
    argv0: &str,
    extra_args: &[String],
    command_line_a_ptr: u64,
) -> Result<()> {
    let mut argv: Vec<String> = Vec::with_capacity(1 + extra_args.len());
    argv.push(argv0.to_owned());
    argv.extend(extra_args.iter().cloned());

    let argc = u32::try_from(argv.len()).context("argc does not fit u32")?;
    engine
        .mem_write(CRT_ARGC_SLOT, &argc.to_le_bytes())
        .context("failed to write CRT argc")?;

    // acmdln → GetCommandLineA buffer (char*).
    engine
        .mem_write(CRT_ACMDLN_PTR_SLOT, &command_line_a_ptr.to_le_bytes())
        .context("failed to write CRT acmdln")?;

    // argv pointer table at CRT_ARGV_TABLE; strings packed from CRT_ARGV_STRINGS.
    let mut string_cursor = CRT_ARGV_STRINGS;
    for (i, arg) in argv.iter().enumerate() {
        let slot = CRT_ARGV_TABLE
            .checked_add(u64::try_from(i).context("argv index")? * 8)
            .context("argv slot overflow")?;
        if slot.saturating_add(8) > CRT_ARGV_STRINGS {
            anyhow::bail!("too many argv entries for CRT page");
        }
        let mut bytes = arg.as_bytes().to_vec();
        bytes.push(0);
        let end = string_cursor
            .checked_add(u64::try_from(bytes.len()).context("arg len")?)
            .context("argv string end overflow")?;
        if end > CRT_PAGE_END {
            anyhow::bail!("argv strings exceed CRT guest page");
        }
        engine
            .mem_write(string_cursor, &bytes)
            .context("failed to write argv string")?;
        engine
            .mem_write(slot, &string_cursor.to_le_bytes())
            .context("failed to write argv pointer")?;
        string_cursor = end;
    }

    // Trailing NULL pointer (char** is null-terminated).
    let null_slot = CRT_ARGV_TABLE
        .checked_add(u64::from(argc) * 8)
        .context("argv null slot overflow")?;
    engine
        .mem_write(null_slot, &0_u64.to_le_bytes())
        .context("failed to write argv NULL terminator")?;

    // ARGV_PTR_SLOT holds char** (address of the pointer table).
    engine
        .mem_write(CRT_ARGV_PTR_SLOT, &CRT_ARGV_TABLE.to_le_bytes())
        .context("failed to write CRT argv ptr slot")?;

    Ok(())
}

/// Saved frame for one in-flight guest window-procedure call.
#[derive(Debug, Clone)]
struct PendingGuestCallback {
    /// `RSP` at the outer host API entry (return address of the caller).
    dispatch_rsp: u64,
    /// Original callback request metadata.
    request: wie_winapi::GuestCallbackRequest,
    /// Outer host API that requested the callback (`DispatchMessageA`, `SendMessageA`, …).
    outer_library: Arc<str>,
    /// Outer host API export name.
    outer_name: Arc<str>,
    /// Fake VA of the outer host API entry.
    outer_fake_va: u64,
    /// When set, outer API is `CreateWindowEx*` and must return this HWND
    /// (unless the WndProc returns `-1` from `WM_CREATE`).
    create_window_hwnd: Option<u64>,
}

/// Host-side timing breakdown for one session (enabled via `WIE_RUNTIME_PROFILE=1`).
#[derive(Debug, Clone, Default)]
pub struct RuntimeProfile {
    /// Wall time spent in session init (PE loading, patch, pre-compilation).
    pub init_ns: u128,
    /// Wall time spent inside `run_until_stop` (guest instruction execution).
    pub emu_ns: u128,
    /// Wall time spent in WinAPI handlers / dispatch / return_from_win64_api.
    pub handler_ns: u128,
    /// Wall time spent resolving hook VA → fake API entry.
    pub resolve_ns: u128,
    /// Number of times the CPU stopped on a fake-API hook (host entry points).
    pub host_stops: u64,
    /// Noisy API calls (not charged to max_api).
    pub noisy_calls: u64,
    /// Charged interesting API calls.
    pub charged_calls: u64,
    /// Per-export counts and handler time (library!name → (count, handler_ns)).
    pub by_export: HashMap<String, (u64, u128)>,
    /// End-to-end wall time for the run (set by CLI / micro runner when available).
    pub wall_ns: u128,
    /// Process user CPU microseconds (delta over the run, when available).
    pub cpu_user_us: u64,
    /// Process system CPU microseconds (delta over the run, when available).
    pub cpu_sys_us: u64,
    /// JIT / interpreter diagnostics snapshot at end of run.
    pub jit: Option<wie_cpu::JitStats>,
    /// Active memory backend name (`hash`, …).
    pub mem_backend: String,
    /// Host idle policy name (`busy` / `yield` / `park`, Phase 6).
    pub idle_policy: String,
    /// Empty-message / host park quanta applied by the outer run loop.
    pub idle_parks: u64,
    /// Wall nanoseconds spent in host idle parks (message quanta).
    pub idle_park_ns: u128,
}

impl RuntimeProfile {
    /// Human-readable multi-line report for stderr / logs.
    #[must_use]
    pub fn report(&self) -> String {
        let total = self
            .emu_ns
            .saturating_add(self.handler_ns)
            .saturating_add(self.resolve_ns);
        let pct = |part: u128| -> f64 {
            if total == 0 {
                0.0
            } else {
                (part as f64) * 100.0 / (total as f64)
            }
        };
        let mut lines = Vec::new();
        lines.push("=== WIE_RUNTIME_PROFILE ===".to_owned());
        if !self.mem_backend.is_empty() {
            lines.push(format!("mem_backend={}", self.mem_backend));
        }
        if !self.idle_policy.is_empty() {
            lines.push(format!("idle_policy={}", self.idle_policy));
        }
        if self.idle_parks > 0 || self.idle_park_ns > 0 {
            lines.push(format!(
                "idle_parks={} idle_park_ms={:.2}",
                self.idle_parks,
                self.idle_park_ns as f64 / 1e6
            ));
        }
        lines.push(format!(
            "host_stops={} noisy={} charged={}",
            self.host_stops, self.noisy_calls, self.charged_calls
        ));
        if self.wall_ns > 0 || self.cpu_user_us > 0 || self.cpu_sys_us > 0 {
            let wall_ms = self.wall_ns as f64 / 1e6;
            let cpu_ms = (self.cpu_user_us.saturating_add(self.cpu_sys_us)) as f64 / 1e3;
            let cpu_pct = if wall_ms > 0.0 {
                (cpu_ms / wall_ms) * 100.0
            } else {
                0.0
            };
            lines.push(format!(
                "wall_ms={:.2}  cpu_user_ms={:.2}  cpu_sys_ms={:.2}  cpu%≈{:.1}",
                wall_ms,
                self.cpu_user_us as f64 / 1e3,
                self.cpu_sys_us as f64 / 1e3,
                cpu_pct
            ));
        }
        lines.push(format!(
            "emu_ms={:.2} ({:.1}%)  handler_ms={:.2} ({:.1}%)  resolve_ms={:.2} ({:.1}%)  total_accounted_ms={:.2}  init_ms={:.2}",
            self.emu_ns as f64 / 1e6,
            pct(self.emu_ns),
            self.handler_ns as f64 / 1e6,
            pct(self.handler_ns),
            self.resolve_ns as f64 / 1e6,
            pct(self.resolve_ns),
            total as f64 / 1e6,
            self.init_ns as f64 / 1e6,
        ));
        if let Some(j) = self.jit {
            lines.push(format!(
                "jit: insns={} iced={} compiles={} skip={} cache_hits={} load={} store={}",
                j.jit_insns,
                j.iced_insns,
                j.compiles,
                j.compile_skip,
                j.cache_hits,
                j.load_calls,
                j.store_calls
            ));
        }
        let mut ranked: Vec<_> = self.by_export.iter().collect();
        ranked.sort_by(|a, b| b.1.1.cmp(&a.1.1).then(b.1.0.cmp(&a.1.0)));
        lines.push("top exports by handler time:".to_owned());
        for (name, (count, ns)) in ranked.into_iter().take(20) {
            lines.push(format!(
                "  {count:>7}  {:>8.2} ms  {name}",
                *ns as f64 / 1e6
            ));
        }
        lines.push("top exports by count:".to_owned());
        let mut by_count = self.by_export.iter().collect::<Vec<_>>();
        by_count.sort_by_key(|(_, (count, _))| std::cmp::Reverse(*count));
        for (name, (count, ns)) in by_count.into_iter().take(15) {
            lines.push(format!(
                "  {count:>7}  {:>8.2} ms  {name}",
                *ns as f64 / 1e6
            ));
        }
        lines.join("\n")
    }
}

/// Apply final PE section / header protects after image copy (Phase 3.3).
///
/// Sequence: whole image → `PAGE_NOACCESS` (gap pages), headers → RO, each
/// section → characteristics-derived protect. IAT must already be patched in
/// the host-side image buffer before this runs.
fn apply_pe_section_protects(
    engine: &mut dyn wie_cpu::CpuEngine,
    plan: &wie_pe::PeMapPlan,
) -> Result<()> {
    use wie_cpu::protect::{PAGE_NOACCESS, PAGE_READONLY};

    let image_size = usize::try_from(plan.size_of_image).context("size_of_image")?;
    if image_size == 0 {
        return Ok(());
    }
    // Gaps / padding: committed NOACCESS so VirtualQuery sees image space.
    engine
        .virtual_protect(plan.image_base, image_size, PAGE_NOACCESS)
        .context("PE gap NOACCESS protect")?;

    let header_len = u64::from(plan.header_size);
    if let Some((start, end)) = wie_pe::page_align_image_range(0, header_len, plan.size_of_image) {
        let len = usize::try_from(end.saturating_sub(start)).context("header range")?;
        if len > 0 {
            engine
                .virtual_protect(plan.image_base.saturating_add(start), len, PAGE_READONLY)
                .context("PE headers protect")?;
        }
    }

    for sec in &plan.sections {
        let rva = u64::from(sec.va);
        let vsize = u64::from(sec.virtual_size);
        if vsize == 0 {
            continue;
        }
        let Some((start, end)) = wie_pe::page_align_image_range(rva, vsize, plan.size_of_image)
        else {
            continue;
        };
        let len = usize::try_from(end.saturating_sub(start)).context("section range")?;
        if len == 0 {
            continue;
        }
        engine
            .virtual_protect(
                plan.image_base.saturating_add(start),
                len,
                sec.final_protect,
            )
            .with_context(|| format!("PE section {} protect", sec.name))?;
    }
    Ok(())
}

/// Register default layout ranges into the CPU region table (Phase 1.2 / 3.3).
fn register_layout_regions(
    engine: &mut dyn wie_cpu::CpuEngine,
    layout: &RuntimeMemoryLayout,
    image_base: u64,
    image_size: usize,
    pe_plan: Option<&wie_pe::PeMapPlan>,
) {
    use wie_cpu::{GuestRegion, RegionKind};

    // Whole image + optional per-section named regions for diagnostics / Phase 4.
    engine.register_region(GuestRegion::new(
        "image",
        RegionKind::Image,
        image_base,
        image_size,
        wie_cpu::perm::ALL,
    ));
    if let Some(plan) = pe_plan {
        let header_len = usize::try_from(plan.header_size).unwrap_or(0);
        if header_len > 0 {
            engine.register_region(GuestRegion::new(
                "image.headers",
                RegionKind::Image,
                image_base,
                header_len,
                wie_cpu::protect::rwx_from_page_protect(wie_pe::PeMapPlan::header_protect()),
            ));
        }
        for sec in &plan.sections {
            let va = image_base.saturating_add(u64::from(sec.va));
            let size = usize::try_from(sec.virtual_size).unwrap_or(0);
            if size == 0 {
                continue;
            }
            let name = format!("image.{}", sec.name.trim_matches('\0'));
            engine.register_region(GuestRegion::new(
                name,
                RegionKind::Image,
                va,
                size,
                wie_cpu::protect::rwx_from_page_protect(sec.final_protect),
            ));
        }
    }

    // Phase 4.x: pure data regions are RW (not RWX). Soft-translate W is
    // denied on executable pages; stack/heap must stay non-X for pin super path.
    let data_rw = wie_cpu::perm::READ | wie_cpu::perm::WRITE;
    let code_rwx = wie_cpu::perm::ALL;
    let regs: [GuestRegion; 15] = [
        GuestRegion::new(
            "stack",
            RegionKind::Stack,
            layout.stack_base,
            layout.stack_size,
            data_rw,
        ),
        GuestRegion::new(
            "process_heap",
            RegionKind::Heap,
            layout.process_heap_base,
            layout.process_heap_size,
            data_rw,
        ),
        GuestRegion::new(
            "process_heap_shadow",
            RegionKind::Heap,
            layout.process_heap_shadow_base(),
            layout.process_heap_size,
            data_rw,
        ),
        GuestRegion::new(
            "fake_api",
            RegionKind::FakeApi,
            layout.fake_api_base,
            layout.fake_api_size,
            code_rwx,
        ),
        GuestRegion::new(
            "teb",
            RegionKind::Teb,
            layout.teb_low_base,
            layout.teb_low_size,
            data_rw,
        ),
        GuestRegion::new(
            "env",
            RegionKind::Env,
            layout.env_data_base,
            layout.env_data_size,
            data_rw,
        ),
        GuestRegion::new(
            "resource",
            RegionKind::Resource,
            layout.resource_data_base,
            layout.resource_data_size,
            data_rw,
        ),
        GuestRegion::new(
            "guest_io_code",
            RegionKind::GuestCode,
            layout.guest_io_code_base,
            layout.guest_io_code_size,
            code_rwx,
        ),
        GuestRegion::new(
            "guest_io_table",
            RegionKind::GuestIo,
            layout.guest_io_table_base,
            layout.guest_io_table_size,
            data_rw,
        ),
        GuestRegion::new(
            "guest_file_data",
            RegionKind::GuestIo,
            layout.guest_file_data_base,
            layout.guest_file_data_size,
            data_rw,
        ),
        GuestRegion::new(
            "guest_fls",
            RegionKind::Other,
            layout.guest_fls_table_base,
            layout.guest_fls_table_size,
            data_rw,
        ),
        GuestRegion::new(
            "guest_heap_ctrl",
            RegionKind::Heap,
            layout.guest_heap_ctrl_base,
            layout.guest_heap_ctrl_size,
            data_rw,
        ),
        GuestRegion::new(
            "guest_heap_code",
            RegionKind::GuestCode,
            layout.guest_heap_code_base,
            layout.guest_heap_code_size,
            code_rwx,
        ),
        GuestRegion::new(
            "guest_mbwc_code",
            RegionKind::GuestCode,
            layout.guest_mbwc_code_base,
            layout.guest_mbwc_code_size,
            code_rwx,
        ),
        GuestRegion::new(
            "fast_api_stub",
            RegionKind::GuestCode,
            layout.fast_api_stub_base,
            layout.fast_api_stub_size,
            code_rwx,
        ),
    ];
    for region in regs {
        engine.register_region(region);
    }
}

/// Long-lived executable runtime session.
///
/// The session owns the CPU engine, guest memory, WinAPI state and
/// dispatcher metadata so execution can yield and later resume.
pub struct RuntimeSession {
    /// CPU + WinAPI (local until first `CreateThread`, then shared).
    process: ProcessResources,
    entry_point_va: u64,
    initial_rsp: u64,
    next_api_index: usize,
    no_hook_slices: usize,
    pending_callbacks: Vec<PendingGuestCallback>,
    /// When true, accumulate [`RuntimeProfile`] across `run_until_stop` calls.
    profile_enabled: bool,
    profile: RuntimeProfile,
    /// Last value written to guest TEB.LastErrorValue (skip redundant mem_write).
    last_published_last_error: Option<u32>,
}

/// Bundle of fields produced by session initialization (avoids 8-arg constructors).
struct SessionInit {
    engine: Box<dyn wie_cpu::CpuEngine>,
    environment: wie_winapi::WinApiEnvironment,
    winapi_state: wie_winapi::WinApiState,
    soft_apis: SoftApiTable,
    layout: RuntimeMemoryLayout,
    entry_point_va: u64,
    initial_rsp: u64,
}

impl RuntimeSession {
    fn from_init(init: SessionInit) -> Self {
        let profile_enabled = std::env::var_os("WIE_RUNTIME_PROFILE").is_some();
        Self {
            process: ProcessResources::new(
                init.engine,
                init.winapi_state,
                init.soft_apis,
                init.environment,
                init.layout,
            ),
            entry_point_va: init.entry_point_va,
            initial_rsp: init.initial_rsp,
            next_api_index: 0,
            no_hook_slices: 0,
            pending_callbacks: Vec::new(),
            profile_enabled,
            profile: RuntimeProfile::default(),
            last_published_last_error: None,
        }
    }

    /// Publish host `last_error` into guest TEB.LastErrorValue so in-guest
    /// `GetLastError` stubs stay coherent with host-side API failures.
    fn publish_last_error_to_guest(&mut self) {
        let err = self
            .process
            .with_mut(|_, st| st.last_error);
        if self.last_published_last_error == Some(err) {
            return;
        }
        let bytes = err.to_le_bytes();
        // Best-effort: TEB page is always mapped for this layout.
        let ok = self.process.with_mut(|eng, _| {
            eng.mem_write(crate::guest_stubs::TEB_LAST_ERROR_VA, &bytes)
                .is_ok()
        });
        if ok {
            self.last_published_last_error = Some(err);
        }
    }

    /// Accumulated host-side profile (empty unless `WIE_RUNTIME_PROFILE` is set).
    #[must_use]
    pub fn profile(&self) -> &RuntimeProfile {
        &self.profile
    }

    /// Mutable profile for outer run-loop counters (e.g. idle parks).
    pub fn profile_mut(&mut self) -> &mut RuntimeProfile {
        &mut self.profile
    }

    /// Whether profiling is enabled for this session.
    #[must_use]
    pub fn profile_enabled(&self) -> bool {
        self.profile_enabled
    }

    /// Creates and initializes a long-lived Lunar Magic runtime session.
    pub fn new(
        path: &std::path::Path,
        idle_policy: wie_winapi::MessageQueueIdlePolicy,
    ) -> Result<Self> {
        Self::new_with_options(path, idle_policy, DEFAULT_LAYOUT, SessionOptions::default())
    }

    /// Creates a session with an explicit guest memory layout.
    pub fn new_with_layout(
        path: &std::path::Path,
        idle_policy: wie_winapi::MessageQueueIdlePolicy,
        layout: RuntimeMemoryLayout,
    ) -> Result<Self> {
        Self::new_with_options(path, idle_policy, layout, SessionOptions::default())
    }

    /// Creates a session with guest argv / stdin bootstrap options.
    pub fn new_with_options(
        path: &std::path::Path,
        idle_policy: wie_winapi::MessageQueueIdlePolicy,
        layout: RuntimeMemoryLayout,
        options: SessionOptions,
    ) -> Result<Self> {
        let t_init = Instant::now();
        let mut soft_apis = SoftApiTable::default();
        // MT.4: plant Interlocked* (and other soft-only GPA targets) at fixed
        // soft indices 0..N so GetProcAddress encode_unresolved matches.
        for entry in wie_winapi::PREPLANTED_SOFT_APIS {
            soft_apis
                .intern(entry.library, entry.name, 0)
                .with_context(|| {
                    format!(
                        "failed to plant soft API {}!{}",
                        entry.library, entry.name
                    )
                })?;
        }
        // Read the PE file once; we need the bytes for both identity and loading.
        let pe_bytes = std::fs::read(path)
            .with_context(|| format!("failed to read PE file: {}", path.display()))?;
        let identity = wie_pe::pe_identity_from_bytes(path, &pe_bytes)
            .context("failed to parse PE identity")?;
        let image_size =
            usize::try_from(identity.size_of_image).context("size_of_image does not fit usize")?;

        // WIE CPU backend (Unicorn default; `WIE_CPU=iced` for interpreter).
        let mut engine = crate::open_default_cpu().context("failed to open WIE CPU backend")?;

        // Phase 3.3: one MEM_IMAGE arena, temporary RWX — headers/sections/IAT
        // are written directly into guest memory (no intermediate Vec<u8> buffer).
        engine
            .mem_map_image(
                identity.image_base,
                image_size,
                wie_cpu::perm::ALL,
            )
            .context("failed to map PE image memory")?;

        // Load PE directly into guest memory: single PE parse, writes headers +
        // sections + patches IAT in-place through the engine. Returns the section
        // map plan too — no need to re-read the file.
        let (image_summary, pe_map_plan, patched_imports) = {
            let engine_ref = &mut *engine;
            wie_pe::load_pe_direct_from_bytes(
                &pe_bytes,
                identity.image_base,
                image_size,
                |va, bytes| {
                    engine_ref
                        .mem_write(va, bytes)
                        .map_err(|e| anyhow::anyhow!("PE write to guest memory failed: {e}"))
                },
                |import| {
                    let name = if import.name.is_empty() {
                        format!("ORDINAL {}", import.ordinal)
                    } else {
                        import.name.clone()
                    };
                    // Legacy msvcrt data imports: IAT must hold the variable address,
                    // not a callable fake VA (guest loads through the slot).
                    if wie_winapi::ucrt::is_ucrt_library(&import.library)
                        && let Some(data_va) = wie_winapi::ucrt::crt_data_import_va(&name)
                    {
                        return Ok(data_va);
                    }
                    let (va, _) = resolve_import_fake_va(
                        &import.library,
                        &name,
                        import.iat_slot_va,
                        &mut soft_apis,
                    )?;
                    Ok(va)
                },
            )
            .context("failed to load PE64 image directly into guest memory")?
        };

        let iat_entries = build_iat_fake_api_entries(&patched_imports);
        let fake_api_entries = collect_stub_entries(&iat_entries, &soft_apis);

        apply_pe_section_protects(engine.as_mut(), &pe_map_plan)
            .context("failed to apply PE section protects")?;

        engine
            .mem_map(
                layout.fake_api_base,
                layout.fake_api_size,
                wie_cpu::perm::ALL,
            )
            .context("failed to map fake API memory")?;

        let fake_api_size_u64 =
            u64::try_from(layout.fake_api_size).context("fake API size does not fit u64")?;
        let fake_api_end = layout
            .fake_api_base
            .checked_add(fake_api_size_u64)
            .context("fake API end overflow")?
            .checked_sub(1)
            .context("fake API end underflow")?;

        // Guest acceleration regions (outside host-stop hook range for helpers).
        engine
            .mem_map(
                layout.guest_io_code_base,
                layout.guest_io_code_size,
                wie_cpu::perm::ALL,
            )
            .context("failed to map guest I/O code region")?;
        let data_rw = wie_cpu::perm::READ | wie_cpu::perm::WRITE;
        engine
            .mem_map(
                layout.guest_io_table_base,
                layout.guest_io_table_size,
                data_rw,
            )
            .context("failed to map guest I/O handle table")?;
        engine
            .mem_map(
                layout.guest_file_data_base,
                layout.guest_file_data_size,
                data_rw,
            )
            .context("failed to map guest file-data arena")?;
        engine
            .mem_map(
                layout.guest_fls_table_base,
                layout.guest_fls_table_size,
                data_rw,
            )
            .context("failed to map guest FLS table")?;
        engine
            .mem_write(
                layout.guest_fls_table_base,
                &vec![0_u8; layout.guest_fls_table_size],
            )
            .context("failed to zero guest FLS table")?;

        // Phase 5 stub data: metrics / syscolors / cwd blob (cwd filled after identity).
        engine
            .mem_map(
                layout.guest_stub_data_base,
                layout.guest_stub_data_size,
                data_rw,
            )
            .context("failed to map guest stub data page")?;
        let stub_page = crate::guest_stubs::build_stub_data_page();
        engine
            .mem_write(layout.guest_stub_data_base, &stub_page)
            .context("failed to write guest stub data page")?;

        let stub_cfg = crate::guest_stubs::GuestStubConfig::from_layout(&layout);

        // Plant trivial WinAPI as real x86-64 stubs and build stop-bit mask.
        // OOL helpers live after guest_io ReadFile/SetFP/GetFS (0x000/0x200/0x400).
        // Use the remainder of the guest_io code mapping (~0x1A00 bytes).
        let mut stop_bitmap = crate::guest_stubs::plant_guest_stubs(
            &mut engine,
            &fake_api_entries,
            layout.fake_api_base,
            layout.fake_api_size,
            &stub_cfg,
            layout.guest_io_code_base + 0x600,
            layout.guest_io_code_size.saturating_sub(0x600),
        )?;

        let guest_io_config = crate::guest_io::install_guest_io(
            &mut engine,
            &fake_api_entries,
            &mut stop_bitmap,
            &layout,
        )?;

        engine
            .mem_map(
                layout.guest_heap_ctrl_base,
                layout.guest_heap_ctrl_size,
                data_rw,
            )
            .context("failed to map guest heap control")?;
        engine
            .mem_map(
                layout.guest_heap_code_base,
                layout.guest_heap_code_size,
                wie_cpu::perm::ALL,
            )
            .context("failed to map guest heap code")?;

        let guest_heap_cfg = crate::guest_heap_accel::install_guest_heap_accel(
            &mut engine,
            &fake_api_entries,
            &mut stop_bitmap,
            &layout,
        )?;

        engine
            .mem_map(
                layout.guest_mbwc_code_base,
                layout.guest_mbwc_code_size,
                wie_cpu::perm::ALL,
            )
            .context("failed to map guest MultiByteToWideChar code")?;
        let _guest_mbwc = crate::guest_mbwc::install_guest_mbwc(
            &mut engine,
            &fake_api_entries,
            &mut stop_bitmap,
            &layout,
        )?;

        // JIT: direct UCRT imports (malloc/memcpy/strlen/…) + guest heap layout.
        // Dense: small VA→kind table from soft/IAT names (no runtime HashMap probe on stop).
        {
            let mut pairs = Vec::new();
            for entry in &fake_api_entries {
                if let Some(kind) = wie_cpu::FastApiKind::from_export_name(&entry.name) {
                    pairs.push((entry.fake_target_va, kind));
                }
            }
            let heap_end = layout
                .process_heap_base
                .saturating_add(layout.process_heap_size as u64);
            engine.configure_jit_fast_path(wie_cpu::JitFastPathConfig {
                heap: wie_cpu::JitHeapLayout {
                    ctrl_va: guest_heap_cfg.ctrl_va,
                    base: layout.process_heap_base,
                    end: heap_end,
                },
                pairs,
            });
        }

        engine
            .install_runtime_hooks(layout.fake_api_base, fake_api_end, stop_bitmap)
            .context("failed to install persistent runtime hooks")?;

        // Selective precompile: only in-guest stubs (GetLastError / CS / …).
        // Precompiling every fake-API VA (including host-stop passthroughs and
        // rewire jmps) spikes init peak RAM via Cranelift; hot stubs are cheap
        // (hand-written trampolines or tiny blocks) and hit early.
        for entry in &fake_api_entries {
            if entry.traits.guest_stub() {
                engine.precompile_at(entry.fake_target_va);
            }
        }

        engine
            .mem_map(
                layout.stack_base,
                layout.stack_size,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .context("failed to map entry stack memory")?;

        let stack_size_u64 =
            u64::try_from(layout.stack_size).context("stack size does not fit u64")?;

        let stack_top = layout
            .stack_base
            .checked_add(stack_size_u64)
            .context("entry stack top overflow")?;

        let initial_rsp = stack_top
            .checked_sub(0x1008)
            .context("entry initial RSP underflow")?;

        engine
            .write_rsp(initial_rsp)
            .context("failed to initialize entry RSP")?;

        engine
            .mem_map(
                layout.teb_low_base,
                layout.teb_low_size,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .context("failed to map fake low TEB page")?;

        let stack_limit = layout.stack_base;

        engine
            .mem_write(0x08, &stack_top.to_le_bytes())
            .context("failed to write fake TEB StackBase")?;

        engine
            .mem_write(0x10, &stack_limit.to_le_bytes())
            .context("failed to write fake TEB StackLimit")?;

        // TEB.LastErrorValue (x64 offset 0x68) — guest GetLastError/SetLastError stubs.
        engine
            .mem_write(crate::guest_stubs::TEB_LAST_ERROR_VA, &0_u32.to_le_bytes())
            .context("failed to zero TEB LastErrorValue")?;

        engine
            .mem_map(
                layout.env_data_base,
                layout.env_data_size,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .context("failed to map entry environment data memory")?;

        // Guest page for UCRT FILE* cookies / CRT pointer slots (ucrt module).
        engine
            .mem_map(
                0x0000_0000_6800_0000,
                0x1000,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .context("failed to map guest UCRT data page")?;
        // Pre-init CRT pointer slots (filled fully after process identity is known).
        {
            const CRT: u64 = 0x0000_0000_6800_0000;
            engine.mem_write(CRT + 0x300, &0_u64.to_le_bytes())?; // environ ptr
            engine.mem_write(CRT + 0x308, &0_u64.to_le_bytes())?; // argv ptr (set below)
            engine.mem_write(CRT + 0x310, &1_u32.to_le_bytes())?; // argc (set below)
            engine.mem_write(CRT + 0x318, &0_u32.to_le_bytes())?; // commode
            engine.mem_write(CRT + 0x320, &0_u32.to_le_bytes())?; // fmode
            engine.mem_write(CRT + 0x328, &0_u64.to_le_bytes())?; // acmdln (set below)
        }

        let command_line_a_ptr = layout
            .env_data_base
            .checked_add(0x100)
            .context("entry command line A pointer overflow")?;

        let command_line_w_ptr = layout
            .env_data_base
            .checked_add(0x200)
            .context("entry command line W pointer overflow")?;

        let environment_strings_w_ptr = layout
            .env_data_base
            .checked_add(0x400)
            .context("entry environment strings W pointer overflow")?;

        let module_file_name_a_ptr = layout
            .env_data_base
            .checked_add(0x700)
            .context("entry module file name A pointer overflow")?;

        let module_file_name_w_ptr = layout
            .env_data_base
            .checked_add(0x800)
            .context("entry module file name W pointer overflow")?;

        let process = wie_pe::process_identity_from_host_path_with_args(path, &options.guest_args);
        write_process_identity_strings(
            &mut engine,
            command_line_a_ptr,
            command_line_w_ptr,
            module_file_name_a_ptr,
            module_file_name_w_ptr,
            &process,
        )?;

        // Publish cwd for in-guest GetCurrentDirectoryW (Microsoft Learn path string).
        crate::guest_stubs::publish_cwd_wide(
            engine.as_mut(),
            stub_cfg.cwd_blob_va,
            &process.current_directory,
        )?;

        // UCRT argc/argv/acmdln for CRT-linked and __p__* guest stubs.
        materialize_crt_argv(
            engine.as_mut(),
            &process.module_file_name,
            &options.guest_args,
            command_line_a_ptr,
        )?;

        let environment_strings_w = build_default_environment_strings_w()?;

        engine
            .mem_write(environment_strings_w_ptr, &environment_strings_w)
            .context("failed to write entry UTF-16 environment strings")?;

        engine
            .mem_map(
                layout.process_heap_base,
                layout.process_heap_size,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .context("failed to map fake process heap memory")?;

        engine
            .mem_map(
                layout.process_heap_shadow_base(),
                layout.process_heap_size,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .context("failed to map fake process heap shadow memory")?;

        engine
            .mem_map(
                layout.resource_data_base,
                layout.resource_data_size,
                wie_cpu::perm::READ | wie_cpu::perm::WRITE,
            )
            .context("failed to map fake resource memory")?;

        // Phase 1.2 / 3.3: register named layout + PE section ranges.
        register_layout_regions(
            engine.as_mut(),
            &layout,
            image_summary.image_base,
            image_summary.image_size,
            Some(&pe_map_plan),
        );

        let environment = default_winapi_environment(
            &layout,
            image_summary.image_base,
            command_line_a_ptr,
            command_line_w_ptr,
            environment_strings_w_ptr,
            module_file_name_a_ptr,
            module_file_name_w_ptr,
        );

        let executable_file_bytes = std::fs::read(path)
            .with_context(|| format!("failed to read executable bytes: {}", path.display(),))?;

        let mut winapi_state = default_winapi_state(&layout, executable_file_bytes, &process)?;

        winapi_state.message_queue_idle_policy = idle_policy;
        winapi_state.guest_io = Some(wie_winapi::GuestIoRuntimeConfig {
            table_va: guest_io_config.table_va,
            file_data_base: guest_io_config.file_data_base,
            file_data_size: guest_io_config.file_data_size,
        });
        winapi_state.guest_file_data_next = layout.guest_file_data_base;
        winapi_state.guest_fls_table_va = layout.guest_fls_table_base;
        // Empty inject ⇒ live host stdin on ReadFile(STD_INPUT); non-empty
        // inject is deterministic and never blocks on the TTY.
        winapi_state.stdin_mode = if options.stdin_bytes.is_empty() {
            wie_winapi::GuestStdinMode::LiveHost
        } else {
            wie_winapi::GuestStdinMode::InjectOnly
        };
        winapi_state.stdin_bytes = options.stdin_bytes;
        winapi_state.stdin_cursor = 0;
        winapi_state
            .heap
            .attach_guest_control(guest_heap_cfg.ctrl_va);

        let mut session = Self::from_init(SessionInit {
            engine,
            environment,
            winapi_state,
            soft_apis,
            layout,
            entry_point_va: image_summary.entry_point_va,
            initial_rsp,
        });
        if session.profile_enabled {
            session.profile.init_ns = t_init.elapsed().as_nanos();
            session.profile.mem_backend = session
                .process
                .with_mut(|e, _| e.mem_backend_name().to_owned());
            // Micro / default sessions: idle from env with Micro default (Yield).
            session.profile.idle_policy =
                wie_winapi::IdlePolicy::from_env_for(wie_winapi::IdleContext::Micro)
                    .as_str()
                    .to_owned();
            session.profile.jit = session.process.with_mut(|e, _| e.cpu_stats());
        }
        Ok(session)
    }

    /// Snapshot JIT/CPU stats + optional wall/CPU deltas into the profile.
    ///
    /// Called by micro runners after `run_until_stop` when profiling is enabled.
    pub fn finalize_profile(&mut self, wall_ns: u128, cpu_user_us: u64, cpu_sys_us: u64) {
        if !self.profile_enabled {
            return;
        }
        self.profile.wall_ns = wall_ns;
        self.profile.cpu_user_us = cpu_user_us;
        self.profile.cpu_sys_us = cpu_sys_us;
        self.profile.jit = self.process.with_mut(|e, _| e.cpu_stats());
        self.profile.mem_backend = self.process.with_mut(|e, _| e.mem_backend_name().to_owned());
    }

    /// Returns the PE entry-point address associated with this session.
    #[must_use]
    pub fn entry_point_va(&self) -> u64 {
        self.entry_point_va
    }

    /// Sets the bottle root for guest `C:\…` → host `{root}/drive_c/…` mapping.
    ///
    /// Overrides any `WIE_ROOT` applied at session construction.
    pub fn set_bottle_root(&mut self, root: Option<std::path::PathBuf>) {
        self.process.with_mut(|_, s| {
            if let Some(ref r) = root {
                let _ = wie_winapi::ensure_bottle_skeleton(r);
            }
            s.bottle_root = root.clone();
            s.volumes.bottle_root = root;
        });
    }

    /// Sets optional host-bridge root for guest `D:\…` (`None` unmounts D:).
    pub fn set_drive_d(&mut self, root: Option<std::path::PathBuf>) {
        self.process.with_mut(|_, s| s.volumes.drive_d_root = root);
    }

    /// Replaces guest stdin buffer for console `ReadFile` on STD_INPUT_HANDLE.
    ///
    /// Non-empty bytes are inject-only. Empty enables live host stdin on the
    /// next guest read.
    pub fn set_stdin_bytes(&mut self, bytes: Vec<u8>) {
        self.process.with_mut(|_, s| {
            s.stdin_mode = if bytes.is_empty() {
                wie_winapi::GuestStdinMode::LiveHost
            } else {
                wie_winapi::GuestStdinMode::InjectOnly
            };
            s.stdin_bytes = bytes;
            s.stdin_cursor = 0;
        });
    }

    /// Returns the original stack pointer used to start the guest.
    #[must_use]
    pub fn initial_rsp(&self) -> u64 {
        self.initial_rsp
    }

    /// Returns the guest memory layout used by this session.
    #[must_use]
    pub fn layout(&self) -> RuntimeMemoryLayout {
        self.process.layout
    }

    /// Changes the behavior of `GetMessageA` when the queue is empty.
    pub fn set_message_queue_idle_policy(&mut self, policy: wie_winapi::MessageQueueIdlePolicy) {
        self.process.with_mut(|_, s| s.message_queue_idle_policy = policy);
    }

    /// Adds one message to the persistent guest message queue.
    pub fn post_message(&mut self, message: wie_winapi::QueuedWindowMessage) {
        self.process.with_mut(|_, s| s.message_queue.push(message));
    }

    /// Runs the guest until it yields, terminates, reaches an unsupported API,
    /// or processes `max_api` additional API calls.
    pub fn run_until_stop(&mut self, max_api: usize) -> Result<RuntimeRunSummary> {
        let layout = self.process.layout;
        let environment = self.process.environment;
        let soft_apis = self.process.soft_apis.clone();
        let primary_tid = self.process.primary_tid;

        let fake_api_size_u64 =
            u64::try_from(layout.fake_api_size).context("fake API size does not fit u64")?;

        let fake_api_end = layout
            .fake_api_base
            .checked_add(fake_api_size_u64)
            .context("fake API end overflow")?
            .checked_sub(1)
            .context("fake API end underflow")?;

        let instruction_budget = layout.instruction_budget;
        let no_hook_limit = layout.no_hook_slice_limit;

        let mut events: Vec<crate::trace::EntryTraceEvent> = Vec::new();
        let mut termination = EntryTraceTermination::ApiLimit;

        let max_noisy_api = max_api
            .saturating_mul(50)
            .max(max_api.saturating_add(50_000));
        let mut charged_api = 0_usize;
        let mut noisy_api = 0_usize;

        'outer: while charged_api < max_api {
            if noisy_api >= max_noisy_api {
                termination = EntryTraceTermination::ApiLimit;
                break;
            }

            // MT.2: start any CreateThread workers before the next quantum.
            self.process.drain_spawns()?;

            let index = self.next_api_index;
            self.next_api_index = self
                .next_api_index
                .checked_add(1)
                .context("runtime API index overflow")?;

            // Outcome of one locked quantum (locks dropped before host park).
            enum Quantum {
                Continue,
                Break,
                /// Park then retry same guest API (CS) or complete wait return.
                Park(wie_winapi::HostParkReason),
                /// Worker/primary ExitThread.
                ExitThread(u32),
            }

            let mut quantum = Quantum::Continue;
            let mut break_term: Option<EntryTraceTermination> = None;

            {
                let mut pair = self.process.lock_pair();
                let (engine, winapi_state) = pair.both();

                // Ensure primary TLS/TID active when shared with workers.
                if winapi_state.threads.active.tid != primary_tid {
                    crate::mt_runtime::load_thread(engine, winapi_state, primary_tid);
                }

                let current_rip = engine
                    .read_rip()
                    .context("failed to read RIP before runtime step")?;

                let begin = if current_rip == 0 {
                    self.entry_point_va
                } else {
                    current_rip
                };

                let emu_t0 = self.profile_enabled.then(Instant::now);
                let hook_result = engine.run_until_stop(
                    begin,
                    0,
                    0,
                    instruction_budget,
                    layout.fake_api_base,
                    fake_api_end,
                );
                if let Some(t0) = emu_t0 {
                    self.profile.emu_ns =
                        self.profile.emu_ns.saturating_add(t0.elapsed().as_nanos());
                }

                let (hook, invalid_memory) = match hook_result {
                    Ok(result) => (result.code, result.invalid_memory),
                    Err(error) => {
                        let rip = engine
                            .read_rip()
                            .context("failed to read RIP after runtime emulation error")?;
                        let rsp = engine
                            .read_rsp()
                            .context("failed to read RSP after runtime emulation error")?;
                        let mut slot = [0_u8; 8];
                        let slot_va = rsp.wrapping_add(0x160);
                        let slot_val = engine
                            .mem_read(slot_va, &mut slot)
                            .ok()
                            .map(|()| u64::from_le_bytes(slot));
                        let last_api = match events.last() {
                            Some(e) => format!("{}!{}", e.library.as_ref(), e.name.as_ref()),
                            None => "-".into(),
                        };
                        break_term = Some(EntryTraceTermination::RuntimeStop(format!(
                            "emulation error (api_index={index}, last_api={last_api}): {error}; \
                             rip={rip:#018x}; rsp={rsp:#018x}; [rsp+0x160]={slot_val:?}"
                        )));
                        quantum = Quantum::Break;
                        (
                            wie_cpu::CodeHookOutcome::default(),
                            wie_cpu::InvalidMemoryAccess::default(),
                        )
                    }
                };

                if matches!(quantum, Quantum::Break) {
                    // already set break_term
                } else if invalid_memory.hit {
                    let rip = engine.read_rip().context("rip after invalid mem")?;
                    let rsp = engine.read_rsp().context("rsp after invalid mem")?;
                    let rax = engine.read_rax().context("rax after invalid mem")?;
                    let rcx = engine.read_rcx().context("rcx after invalid mem")?;
                    let rdx = engine.read_rdx().context("rdx after invalid mem")?;
                    let r8 = engine.read_r8().context("r8 after invalid mem")?;
                    let r9 = engine.read_r9().context("r9 after invalid mem")?;
                    // Stack slots (return addr + shadow) and *this / vtable for null-call diagnosis.
                    let mut stack_slots = String::new();
                    for i in 0_u64..32 {
                        let mut b = [0_u8; 8];
                        let off = i.wrapping_mul(8);
                        let va = rsp.wrapping_add(off);
                        match engine.mem_read(va, &mut b) {
                            Ok(()) => {
                                let v = u64::from_le_bytes(b);
                                stack_slots.push_str(&format!(" [rsp+{off:#x}]={v:#x}"));
                            }
                            Err(_) => stack_slots.push_str(&format!(" [rsp+{off:#x}]=?")),
                        }
                    }
                    let mut this_info = String::new();
                    if rcx != 0 {
                        let mut b = [0_u8; 8];
                        if engine.mem_read(rcx, &mut b).is_ok() {
                            let vtbl = u64::from_le_bytes(b);
                            this_info.push_str(&format!(" [rcx]={vtbl:#x}"));
                            // Dump object body (stack COM objects often ~0x40–0x80 bytes).
                            for i in 0_u64..12 {
                                let mut e = [0_u8; 8];
                                let ova = rcx.wrapping_add(i.wrapping_mul(8));
                                if engine.mem_read(ova, &mut e).is_ok() {
                                    this_info.push_str(&format!(
                                        " obj[{i}]={:#x}",
                                        u64::from_le_bytes(e)
                                    ));
                                }
                            }
                            if vtbl > 0x10000 {
                                for i in 0_u64..8 {
                                    let mut e = [0_u8; 8];
                                    let eva = vtbl.wrapping_add(i.wrapping_mul(8));
                                    if engine.mem_read(eva, &mut e).is_ok() {
                                        this_info.push_str(&format!(
                                            " vtbl[{i}]={:#x}",
                                            u64::from_le_bytes(e)
                                        ));
                                    }
                                }
                            }
                        } else {
                            this_info.push_str(" [rcx]=unmapped");
                        }
                    }
                    break_term = Some(EntryTraceTermination::RuntimeStop(format!(
                        "invalid memory access before fake API hook: \
                         type={} address={:#018x} size={} value={} \
                         rip={rip:#018x}; rsp={rsp:#018x}; rax={rax:#018x}; \
                         rcx={rcx:#018x}; rdx={rdx:#018x}; \
                         r8={r8:#018x}; r9={r9:#018x};{stack_slots};{this_info}",
                        invalid_memory.access_type,
                        invalid_memory.address,
                        invalid_memory.size,
                        invalid_memory.value,
                    )));
                    quantum = Quantum::Break;
                } else if !hook.hit {
                    let rip = engine.read_rip().context("rip after no-hook")?;
                    let rsp = engine.read_rsp().context("rsp after no-hook")?;
                    let rax = engine.read_rax().context("rax after no-hook")?;
                    let rcx = engine.read_rcx().context("rcx after no-hook")?;
                    let rdx = engine.read_rdx().context("rdx after no-hook")?;
                    self.no_hook_slices = self
                        .no_hook_slices
                        .checked_add(1)
                        .context("no-hook slice count overflow")?;
                    if self.no_hook_slices == 1
                        || self.no_hook_slices.is_multiple_of(5)
                        || self.no_hook_slices == no_hook_limit
                    {
                        tracing::debug!(
                            slice = self.no_hook_slices,
                            limit = no_hook_limit,
                            begin,
                            rip,
                            rsp,
                            rax,
                            rcx,
                            rdx,
                            "runtime no-hook slice"
                        );
                    }
                    if self.no_hook_slices >= no_hook_limit {
                        break_term = Some(EntryTraceTermination::RuntimeStop(format!(
                            "emulation stopped without hitting fake API hook after {} slices: \
                             begin={begin:#018x}; rip={rip:#018x}; rsp={rsp:#018x}; \
                             rax={rax:#018x}; rcx={rcx:#018x}; rdx={rdx:#018x}; \
                             budget={instruction_budget}",
                            self.no_hook_slices,
                        )));
                        quantum = Quantum::Break;
                    } else {
                        quantum = Quantum::Continue;
                    }
                } else {
                    self.no_hook_slices = 0;

                    if hook.address == layout.callback_return_trampoline_va {
                        // complete_guest_callback needs &mut self — handle outside.
                        // Save marker via special path: use pending flag.
                        drop(pair);
                        match self.complete_guest_callback() {
                            Ok(completion) => {
                                charged_api = charged_api.saturating_add(1);
                                events.push(EntryTraceEvent {
                                    index,
                                    library: completion.outer_library,
                                    name: completion.outer_name,
                                    fake_target_va: completion.outer_fake_va,
                                    handled: true,
                                    return_value: Some(completion.return_value),
                                    return_address: Some(completion.return_address),
                                });
                                self.publish_last_error_to_guest();
                                continue 'outer;
                            }
                            Err(error) => {
                                termination = EntryTraceTermination::RuntimeStop(format!(
                                    "failed to complete guest callback: {error}"
                                ));
                                break 'outer;
                            }
                        }
                    }

                    let resolve_t0 = self.profile_enabled.then(Instant::now);
                    let resolved_opt = resolve_fake_api_at(hook.address, &soft_apis);
                    if resolved_opt.is_none() {
                        break_term = Some(EntryTraceTermination::RuntimeStop(format!(
                            "unresolved fake API at {:#018x}",
                            hook.address,
                        )));
                        quantum = Quantum::Break;
                    }

                    if let Some(resolved) = resolved_opt {
                    if let Some(t0) = resolve_t0 {
                        self.profile.resolve_ns = self
                            .profile
                            .resolve_ns
                            .saturating_add(t0.elapsed().as_nanos());
                    }

                    if self.profile_enabled {
                        self.profile.host_stops = self.profile.host_stops.saturating_add(1);
                    }

                    let export_key = if self.profile_enabled {
                        Some(format!(
                            "{}!{}",
                            resolved.library.as_ref(),
                            resolved.name.as_ref()
                        ))
                    } else {
                        None
                    };

                    {
                        let mut teb_err = [0_u8; 4];
                        if engine
                            .mem_read(crate::guest_stubs::TEB_LAST_ERROR_VA, &mut teb_err)
                            .is_ok()
                        {
                            winapi_state.last_error = u32::from_le_bytes(teb_err);
                        }
                    }

                    let mut record_handler = |ns: u128, noisy: bool| {
                        if !self.profile_enabled {
                            return;
                        }
                        self.profile.handler_ns = self.profile.handler_ns.saturating_add(ns);
                        if noisy {
                            self.profile.noisy_calls = self.profile.noisy_calls.saturating_add(1);
                        } else {
                            self.profile.charged_calls =
                                self.profile.charged_calls.saturating_add(1);
                        }
                        if let Some(key) = export_key.as_ref() {
                            let entry = self.profile.by_export.entry(key.clone()).or_insert((0, 0));
                            entry.0 = entry.0.saturating_add(1);
                            entry.1 = entry.1.saturating_add(ns);
                        }
                    };

                    if resolved.traits.exit_process() {
                        let handler_t0 = self.profile_enabled.then(Instant::now);
                        let exit_code_raw = engine
                            .read_rcx()
                            .context("failed to read RCX for ExitProcess")?;
                        let exit_code = u32::try_from(exit_code_raw & u64::from(u32::MAX))
                            .context("ExitProcess code does not fit u32")?;
                        events.push(EntryTraceEvent {
                            index,
                            library: resolved.library.clone(),
                            name: resolved.name.clone(),
                            fake_target_va: hook.address,
                            handled: true,
                            return_value: None,
                            return_address: None,
                        });
                        if let Some(t0) = handler_t0 {
                            record_handler(t0.elapsed().as_nanos(), false);
                        }
                        winapi_state.sync.process_dying = true;
                        break_term =
                            Some(EntryTraceTermination::ExitProcess { code: exit_code });
                        quantum = Quantum::Break;
                    } else if resolved.traits.fast_void_sync() {
                        let handler_t0 = self.profile_enabled.then(Instant::now);
                        engine
                            .return_from_win64_api(0)
                            .context("failed to return from fast synchronization API")?;
                        if let Some(t0) = handler_t0 {
                            record_handler(t0.elapsed().as_nanos(), true);
                        }
                        noisy_api = noisy_api.saturating_add(1);
                        // publish last error
                        let err = winapi_state.last_error;
                        if self.last_published_last_error != Some(err) {
                            let bytes = err.to_le_bytes();
                            if engine
                                .mem_write(crate::guest_stubs::TEB_LAST_ERROR_VA, &bytes)
                                .is_ok()
                            {
                                self.last_published_last_error = Some(err);
                            }
                        }
                        quantum = Quantum::Continue;
                    } else if matches!(
                        resolved.winapi_id,
                        Some(wie_winapi::WinApiId::Kernel32Heapalloc)
                    ) {
                        let handler_t0 = self.profile_enabled.then(Instant::now);
                        wie_winapi::kernel32::handle_heap_alloc(engine, winapi_state)?;
                        if let Some(t0) = handler_t0 {
                            record_handler(t0.elapsed().as_nanos(), true);
                        }
                        noisy_api = noisy_api.saturating_add(1);
                        let err = winapi_state.last_error;
                        if self.last_published_last_error != Some(err) {
                            let bytes = err.to_le_bytes();
                            if engine
                                .mem_write(crate::guest_stubs::TEB_LAST_ERROR_VA, &bytes)
                                .is_ok()
                            {
                                self.last_published_last_error = Some(err);
                            }
                        }
                        quantum = Quantum::Continue;
                    } else if matches!(
                        resolved.winapi_id,
                        Some(wie_winapi::WinApiId::Kernel32Heapfree)
                    ) {
                        let handler_t0 = self.profile_enabled.then(Instant::now);
                        wie_winapi::kernel32::handle_heap_free(engine, winapi_state)?;
                        if let Some(t0) = handler_t0 {
                            record_handler(t0.elapsed().as_nanos(), true);
                        }
                        noisy_api = noisy_api.saturating_add(1);
                        let err = winapi_state.last_error;
                        if self.last_published_last_error != Some(err) {
                            let bytes = err.to_le_bytes();
                            if engine
                                .mem_write(crate::guest_stubs::TEB_LAST_ERROR_VA, &bytes)
                                .is_ok()
                            {
                                self.last_published_last_error = Some(err);
                            }
                        }
                        quantum = Quantum::Continue;
                    } else if matches!(
                        resolved.winapi_id,
                        Some(wie_winapi::WinApiId::Kernel32Multibytetowidechar)
                    ) {
                        let handler_t0 = self.profile_enabled.then(Instant::now);
                        wie_winapi::kernel32::handle_multi_byte_to_wide_char(engine)?;
                        if let Some(t0) = handler_t0 {
                            record_handler(t0.elapsed().as_nanos(), true);
                        }
                        noisy_api = noisy_api.saturating_add(1);
                        quantum = Quantum::Continue;
                    } else {
                        let handler_t0 = self.profile_enabled.then(Instant::now);
                        let dispatch_result = if let Some(id) = resolved.winapi_id {
                            wie_winapi::dispatch_winapi_id(
                                engine,
                                environment,
                                winapi_state,
                                id,
                            )
                        } else {
                            wie_winapi::dispatch_winapi(
                                engine,
                                environment,
                                winapi_state,
                                &resolved.library,
                                &resolved.name,
                            )
                        };
                        let handler_ns =
                            handler_t0.map(|t0| t0.elapsed().as_nanos()).unwrap_or(0);

                        match dispatch_result {
                            Ok(handler_result) => {
                                if resolved.traits.noisy() {
                                    record_handler(handler_ns, true);
                                    noisy_api = noisy_api.saturating_add(1);
                                } else {
                                    record_handler(handler_ns, false);
                                    charged_api = charged_api.saturating_add(1);
                                    events.push(EntryTraceEvent {
                                        index,
                                        library: resolved.library.clone(),
                                        name: resolved.name.clone(),
                                        fake_target_va: hook.address,
                                        handled: true,
                                        return_value: Some(handler_result.return_value),
                                        return_address: Some(handler_result.return_address),
                                    });
                                }
                                let err = winapi_state.last_error;
                                if self.last_published_last_error != Some(err) {
                                    let bytes = err.to_le_bytes();
                                    if engine
                                        .mem_write(
                                            crate::guest_stubs::TEB_LAST_ERROR_VA,
                                            &bytes,
                                        )
                                        .is_ok()
                                    {
                                        self.last_published_last_error = Some(err);
                                    }
                                }
                                journal_api_return(
                                    index,
                                    resolved.library.as_ref(),
                                    resolved.name.as_ref(),
                                    engine,
                                    handler_result.return_value,
                                    handler_result.return_address,
                                );
                                quantum = Quantum::Continue;
                            }
                            Err(error) => {
                                record_handler(handler_ns, false);
                                let control_signal =
                                    error.downcast_ref::<wie_winapi::WinApiControlSignal>();
                                match control_signal {
                                    Some(wie_winapi::WinApiControlSignal::WaitingForMessage) => {
                                        self.next_api_index = self
                                            .next_api_index
                                            .checked_sub(1)
                                            .context(
                                                "runtime API index underflow after message yield",
                                            )?;
                                        break_term =
                                            Some(EntryTraceTermination::WaitingForMessage);
                                        quantum = Quantum::Break;
                                    }
                                    Some(
                                        wie_winapi::WinApiControlSignal::GuestCallbackRequested {
                                            request,
                                        },
                                    ) => {
                                        let outer_library = resolved.library.clone();
                                        let outer_name = resolved.name.clone();
                                        let request = *request;
                                        charged_api = charged_api.saturating_add(1);
                                        events.push(EntryTraceEvent {
                                            index,
                                            library: outer_library.clone(),
                                            name: outer_name.clone(),
                                            fake_target_va: hook.address,
                                            handled: true,
                                            return_value: None,
                                            return_address: None,
                                        });
                                        // begin_guest_callback needs full self — mark and handle after drop
                                        drop(pair);
                                        if let Err(error) = self.begin_guest_callback(
                                            request,
                                            &outer_library,
                                            &outer_name,
                                            hook.address,
                                        ) {
                                            termination = EntryTraceTermination::RuntimeStop(
                                                format!("failed to begin guest callback: {error}"),
                                            );
                                            break 'outer;
                                        }
                                        continue 'outer;
                                    }
                                    Some(wie_winapi::WinApiControlSignal::HostPark { reason }) => {
                                        crate::mt_runtime::save_thread(
                                            engine,
                                            winapi_state,
                                            primary_tid,
                                        );
                                        quantum = Quantum::Park(*reason);
                                    }
                                    Some(wie_winapi::WinApiControlSignal::ExitThread { code }) => {
                                        quantum = Quantum::ExitThread(*code);
                                    }
                                    None => {
                                        let api = format!(
                                            "{}!{}: {error}",
                                            resolved.library.as_ref(),
                                            resolved.name.as_ref(),
                                        );
                                        events.push(EntryTraceEvent {
                                            index,
                                            library: resolved.library.clone(),
                                            name: resolved.name.clone(),
                                            fake_target_va: hook.address,
                                            handled: false,
                                            return_value: None,
                                            return_address: None,
                                        });
                                        break_term =
                                            Some(EntryTraceTermination::UnsupportedApi(api));
                                        quantum = Quantum::Break;
                                    }
                                }
                            }
                        }
                    }
                    } // break_term.is_none resolved block
                }
            } // drop pair (process locks)

            match quantum {
                Quantum::Continue => {}
                Quantum::Break => {
                    if let Some(t) = break_term {
                        termination = t;
                    }
                    break 'outer;
                }
                Quantum::ExitThread(code) => {
                    // Primary ExitThread ≈ ExitProcess for session.
                    termination = EntryTraceTermination::ExitProcess { code };
                    break 'outer;
                }
                Quantum::Park(reason) => {
                    match reason {
                        wie_winapi::HostParkReason::CriticalSection { cs } => {
                            // Clone queue under lock, park **without** process locks
                            // so the CS owner can Leave and wake us.
                            let q = self.process.with_mut(|_, st| {
                                wie_winapi::kernel32::resolve_cs_queue(st, cs)
                            });
                            q.park_brief();
                            // Retry Enter: restore primary regs; RIP still at API.
                            self.process.with_mut(|eng, st| {
                                crate::mt_runtime::load_thread(eng, st, primary_tid);
                            });
                            // Do not charge API index again — undo increment.
                            self.next_api_index = self.next_api_index.saturating_sub(1);
                        }
                        wie_winapi::HostParkReason::WaitObject { handle, timeout_ms } => {
                            // Detach waitable object, wait **outside** process locks
                            // so workers can ExitThread / SetEvent.
                            let target = self.process.with_mut(|_, st| {
                                wie_winapi::kernel32::resolve_wait_target(st, handle)
                            });
                            let result = match target {
                                Some(t) => t.wait(timeout_ms),
                                None => wie_winapi::WAIT_FAILED,
                            };
                            self.process.with_mut(|eng, st| {
                                crate::mt_runtime::load_thread(eng, st, primary_tid);
                                drop(eng.return_from_win64_api(u64::from(result)));
                                crate::mt_runtime::save_thread(eng, st, primary_tid);
                            });
                            charged_api = charged_api.saturating_add(1);
                        }
                        wie_winapi::HostParkReason::WaitMultiple => {
                            let req = self.process.with_mut(|_, st| {
                                st.sync.multi_wait.remove(&primary_tid)
                            });
                            let result = match req {
                                Some(req) => {
                                    let targets = self.process.with_mut(|_, st| {
                                        st.sync.wait_targets(&req.handles)
                                    });
                                    match targets {
                                        Some(ts) => wie_winapi::wait_multiple(
                                            &ts,
                                            req.wait_all,
                                            req.timeout_ms,
                                        ),
                                        None => wie_winapi::WAIT_FAILED,
                                    }
                                }
                                None => wie_winapi::WAIT_FAILED,
                            };
                            self.process.with_mut(|eng, st| {
                                crate::mt_runtime::load_thread(eng, st, primary_tid);
                                drop(eng.return_from_win64_api(u64::from(result)));
                                crate::mt_runtime::save_thread(eng, st, primary_tid);
                            });
                            charged_api = charged_api.saturating_add(1);
                        }
                    }
                }
            }
        }

        // Join workers if process exited.
        if matches!(
            termination,
            EntryTraceTermination::ExitProcess { .. }
        ) {
            self.process.join_workers();
        }

        let (final_rip, final_rsp) = self.process.with_mut(|eng, _| {
            Ok::<_, anyhow::Error>((
                eng.read_rip().context("failed to read final runtime RIP")?,
                eng.read_rsp().context("failed to read final runtime RSP")?,
            ))
        })?;

        Ok(RuntimeRunSummary {
            events,
            termination,
            final_rip,
            final_rsp,
        })
    }


    /// Queues one deterministic USER32 message for the guest.
    pub fn post_window_message(
        &mut self,
        window_handle: u64,
        message: u32,
        word_parameter: u64,
        long_parameter: u64,
    ) -> Result<()> {
        self.process.with_mut(|_, st| {
            let time = st.next_message_time;
            st.next_message_time = st
                .next_message_time
                .checked_add(1)
                .context("runtime message timestamp overflow")?;
            st.message_queue
                .push(wie_winapi::QueuedWindowMessage {
                    window_handle,
                    message,
                    word_parameter,
                    long_parameter,
                    time,
                    point_x: 0,
                    point_y: 0,
                });
            Ok(())
        })
    }

    /// Returns the first window backed by a guest WndProc.
    #[must_use]
    pub fn first_guest_window_handle(&self) -> Option<u64> {
        self.process.with_winapi_ref(|st| {
            st.windows
                .iter()
                .find(|window| window.window_proc != 0)
                .map(|window| window.handle)
        })
    }

    /// Snapshot of runtime-owned windows (handle, class, title, has WndProc).
    #[must_use]
    pub fn guest_windows_snapshot(&self) -> Vec<(u64, String, String, bool)> {
        self.process.with_winapi_ref(|st| {
            st.windows
                .iter()
                .map(|window| {
                    (
                        window.handle,
                        window.class_name.clone(),
                        window.title.clone(),
                        window.window_proc != 0,
                    )
                })
                .collect()
        })
    }

    /// Number of guest callbacks currently nested on the bridge stack.
    #[must_use]
    pub fn pending_callback_depth(&self) -> usize {
        self.pending_callbacks.len()
    }

    /// Configures the next common file dialog outcome (`GetOpenFileName` / `GetSaveFileName`).
    pub fn set_file_dialog_policy(&mut self, policy: wie_winapi::FileDialogPolicy) {
        self.process.with_mut(|_, s| s.file_dialog_policy = policy);
    }

    /// Returns the last path accepted by a simulated file dialog.
    #[must_use]
    pub fn last_file_dialog_path(&self) -> Option<String> {
        self.process
            .with_winapi_ref(|st| st.last_file_dialog_path.clone())
    }

    /// Mounts a host file so the guest can open it via `CreateFile*` under `guest_path`.
    pub fn mount_host_file(
        &mut self,
        guest_path: &str,
        host_path: impl AsRef<std::path::Path>,
    ) -> Result<()> {
        self.process.with_mut(|_, st| {
            wie_winapi::kernel32::mount_host_file(st, guest_path, host_path)
        })
    }

    /// Opens a guest path with the same rules as `CreateFile*` (for smoke tests).
    pub fn open_guest_path(&mut self, guest_path: &str) -> Result<u64> {
        self.process
            .with_mut(|_, st| wie_winapi::kernel32::open_guest_path(st, guest_path))
    }

    /// Returns the size of an open guest file handle.
    pub fn guest_file_size(&self, handle: u64) -> Result<u64> {
        self.process.with_winapi_ref(|st| {
            let file = st
                .open_files
                .get(&handle)
                .with_context(|| format!("unknown guest file handle {handle:#018x}"))?;
            u64::try_from(file.bytes.len()).context("guest file size does not fit u64")
        })
    }

    /// Reads a slice from an open guest file without advancing the cursor.
    pub fn peek_guest_file(&self, handle: u64, offset: usize, len: usize) -> Result<Vec<u8>> {
        self.process.with_winapi_ref(|st| {
            let file = st
                .open_files
                .get(&handle)
                .with_context(|| format!("unknown guest file handle {handle:#018x}"))?;
            let end = offset
                .checked_add(len)
                .context("guest file peek range overflow")?;
            file.bytes
                .get(offset..end)
                .map(<[u8]>::to_vec)
                .with_context(|| {
                    format!(
                        "guest file peek out of range handle={handle:#018x} offset={offset} len={len}"
                    )
                })
        })
    }

    /// Snapshot of currently open guest files (path + handle + size).
    #[must_use]
    pub fn open_guest_files_snapshot(&self) -> Vec<(u64, String, u64)> {
        self.process.with_winapi_ref(|st| {
            st.open_files
                .iter()
                .filter_map(|(&handle, file)| {
                    let size = u64::try_from(file.bytes.len()).ok()?;
                    Some((handle, file.path.clone(), size))
                })
                .collect()
        })
    }

    /// Sets up Win64 calling convention and transfers control to a guest WndProc.
    ///
    /// Stack layout below the original `DispatchMessageA` frame:
    /// ```text
    /// [dispatch_rsp]      return address of DispatchMessageA caller
    /// [dispatch_rsp-8]    alignment padding
    /// [dispatch_rsp-0x28] 32-byte shadow space
    /// [dispatch_rsp-0x30] trampoline return address  ← new RSP / WndProc entry
    /// ```
    fn begin_guest_callback(
        &mut self,
        request: wie_winapi::GuestCallbackRequest,
        outer_library: &str,
        outer_name: &str,
        outer_fake_va: u64,
    ) -> Result<()> {
        let trampoline = self.process.layout.callback_return_trampoline_va;
        let dispatch_rsp = self.process.with_mut(|engine, _| {
            crate::guest_callback::install_guest_callback_frame(engine, &request, trampoline)
        })?;
        let create_window_hwnd =
            crate::guest_callback::create_window_hwnd_for_outer(outer_name, request.window_handle);

        self.pending_callbacks.push(PendingGuestCallback {
            dispatch_rsp,
            request,
            outer_library: outer_library.into(),
            outer_name: outer_name.into(),
            outer_fake_va,
            create_window_hwnd,
        });

        Ok(())
    }

    /// Completes the most recent guest WndProc and returns from the outer host API.
    fn complete_guest_callback(&mut self) -> Result<GuestCallbackCompletion> {
        let pending = self
            .pending_callbacks
            .pop()
            .context("callback trampoline hit without a pending guest callback")?;

        let (return_value, return_address) = self.process.with_mut(|engine, _| {
            crate::guest_callback::finish_guest_callback(
                engine,
                pending.dispatch_rsp,
                pending.create_window_hwnd,
            )
        })?;

        tracing::debug!(
            outer = %format!("{}!{}", pending.outer_library.as_ref(), pending.outer_name.as_ref()),
            callback = pending.request.callback_address,
            hwnd = pending.request.window_handle,
            message = pending.request.message,
            return_value,
            resume = return_address,
            "completed guest window callback"
        );

        Ok(GuestCallbackCompletion {
            outer_library: pending.outer_library,
            outer_name: pending.outer_name,
            outer_fake_va: pending.outer_fake_va,
            return_value,
            return_address,
        })
    }
}

/// Result of finishing one bridged guest WndProc call.
struct GuestCallbackCompletion {
    outer_library: Arc<str>,
    outer_name: Arc<str>,
    outer_fake_va: u64,
    return_value: u64,
    return_address: u64,
}

/// Append one journal line when `WIE_API_JOURNAL` is set (backend A/B diffs).
fn journal_api_return(
    index: usize,
    library: &str,
    name: &str,
    engine: &mut dyn wie_cpu::CpuEngine,
    return_value: u64,
    return_address: u64,
) {
    let Ok(path) = std::env::var("WIE_API_JOURNAL") else {
        return;
    };
    let rip = engine.read_rip().unwrap_or(0);
    let rsp = engine.read_rsp().unwrap_or(0);
    let rax = engine.read_rax().unwrap_or(return_value);
    let rcx = engine.read_rcx().unwrap_or(0);
    let rdx = engine.read_rdx().unwrap_or(0);
    let r8 = engine.read_r8().unwrap_or(0);
    let r9 = engine.read_r9().unwrap_or(0);
    // Sample stack slots that the crash site uses as call tables.
    let mut slot160 = [0_u8; 8];
    let s160 = engine
        .mem_read(rsp.wrapping_add(0x160), &mut slot160)
        .ok()
        .map_or(0_u64, |()| u64::from_le_bytes(slot160));
    let line = format!(
        "{index}|{library}|{name}|ret={return_value:#x}|retaddr={return_address:#x}|\
         rip={rip:#x}|rsp={rsp:#x}|rax={rax:#x}|rcx={rcx:#x}|rdx={rdx:#x}|r8={r8:#x}|r9={r9:#x}|\
         [rsp+160]={s160:#x}\n"
    );
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        use std::io::Write;
        let _ = f.write_all(line.as_bytes());
    }
}
