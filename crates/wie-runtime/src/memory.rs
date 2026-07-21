//! Guest memory layout and WinAPI environment bootstrap helpers.

use anyhow::{Context, Result};

/// Guest virtual-memory layout used by the WIE runtime.
///
/// Centralizes hardcoded address ranges so they can be inspected, documented,
/// and eventually configured without hunting through session setup code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeMemoryLayout {
    /// Fake API address region base.
    pub fake_api_base: u64,
    /// Fake API address region size.
    pub fake_api_size: usize,
    /// Fake process heap handle returned by `GetProcessHeap`.
    pub process_heap_handle: u64,
    /// Fake process heap base.
    pub process_heap_base: u64,
    /// Fake process heap size.
    pub process_heap_size: usize,
    /// Offset used by observed Lunar Magic/CRT heap metadata accesses.
    pub process_heap_shadow_delta: u64,
    /// Fake low TEB/TIB page base for initial GS-relative CRT reads.
    pub teb_low_base: u64,
    /// Fake low TEB/TIB page size.
    pub teb_low_size: usize,
    /// Fake resource data base.
    pub resource_data_base: u64,
    /// Fake resource data size.
    pub resource_data_size: usize,
    /// Guest stack base.
    pub stack_base: u64,
    /// Guest stack size.
    pub stack_size: usize,
    /// Environment string / module path data page base.
    pub env_data_base: u64,
    /// Environment data page size.
    pub env_data_size: usize,
    /// Maximum guest instructions to execute between fake API hooks.
    pub instruction_budget: usize,
    /// Maximum number of consecutive no-hook instruction slices before stopping.
    pub no_hook_slice_limit: usize,
    /// Guest-code region for trivial WinAPI fast-path stubs.
    pub fast_api_stub_base: u64,
    /// Size of the guest-code fast-path stub region.
    pub fast_api_stub_size: usize,
    /// Fake VA used as the return address from guest window procedures.
    ///
    /// Must lie inside the mapped fake-API hook range so the runtime can
    /// intercept WndProc returns and complete the outer `DispatchMessageA`.
    pub callback_return_trampoline_va: u64,
    /// Guest helper code for accelerated file I/O (outside host-stop hook range).
    pub guest_io_code_base: u64,
    /// Size of the guest I/O helper code region.
    pub guest_io_code_size: usize,
    /// Guest-visible open-file handle table.
    pub guest_io_table_base: u64,
    /// Size of the handle table mapping.
    pub guest_io_table_size: usize,
    /// Arena for mirrored file bytes (CreateFile → guest VA).
    pub guest_file_data_base: u64,
    /// Size of the file-mirror arena.
    pub guest_file_data_size: usize,
    /// Guest-visible FLS value table (u64[GUEST_FLS_SLOT_COUNT]).
    pub guest_fls_table_base: u64,
    /// Size of the FLS table mapping.
    pub guest_fls_table_size: usize,
    /// Guest heap control block (bump + freelist heads).
    pub guest_heap_ctrl_base: u64,
    pub guest_heap_ctrl_size: usize,
    /// Guest HeapAlloc/HeapFree helper code.
    pub guest_heap_code_base: u64,
    pub guest_heap_code_size: usize,
    /// Guest MultiByteToWideChar helper code.
    pub guest_mbwc_code_base: u64,
    pub guest_mbwc_code_size: usize,
    /// Guest-visible tables for Phase 5 stubs (metrics, colors, cwd wide path).
    pub guest_stub_data_base: u64,
    pub guest_stub_data_size: usize,
}

impl RuntimeMemoryLayout {
    /// Default layout for PE64 sessions (addresses avoid common ImageBase values).
    #[must_use]
    pub const fn default() -> Self {
        Self {
            // 4 MiB window: dense kind|payload encoding (see wie_winapi::fake_va).
            fake_api_base: wie_winapi::FAKE_API_BASE,
            fake_api_size: wie_winapi::FAKE_API_SIZE,
            process_heap_handle: 0x0000_0000_5000_0000,
            // Must not collide with common PE ImageBase values (0x400000 and
            // modern 0x140000000). Formerly 0x140000000 — broke micro-PEs on Unicorn.
            process_heap_base: 0x0000_0001_6000_0000,
            // 512 MiB: 16 MiB exhausted while 7za scanned ~60k-file trees (malloc→0
            // → CRT `_CxxThrowException` → Int3). mmap is demand-zero; RSS grows on use.
            // Override with `WIE_PROCESS_HEAP_MB`. Room before shadow at base+1GiB.
            process_heap_size: 0x2000_0000,
            process_heap_shadow_delta: 0x0000_0001_0000_0000,
            teb_low_base: 0x0000_0000_0000_0000,
            teb_low_size: 0x1000,
            resource_data_base: 0x0000_0000_6400_0000,
            resource_data_size: 0x0001_0000,
            stack_base: 0x0000_0000_2000_0000,
            stack_size: 0x0001_0000,
            env_data_base: 0x0000_0000_3000_0000,
            env_data_size: 0x1000,
            // Larger slices cut emu_start restart overhead; still bounded so a
            // pure guest spin cannot hang forever (no_hook_slice_limit).
            instruction_budget: 20_000_000,
            no_hook_slice_limit: 40,
            // All guest helper regions sit after the 4 MiB fake-API window.
            fast_api_stub_base: 0x0000_7000_0040_0000,
            fast_api_stub_size: 0x1000,
            // Dense special VA (kind=Special, payload=callback).
            callback_return_trampoline_va: wie_winapi::callback_return_trampoline_va(),
            guest_io_code_base: 0x0000_7000_0040_1000,
            guest_io_code_size: 0x2000,
            guest_io_table_base: 0x0000_7000_0040_3000,
            guest_io_table_size: 0x2000,
            // Large arena after process heap for file content mirrors.
            guest_file_data_base: 0x0000_0001_5000_0000,
            guest_file_data_size: 0x0400_0000,
            guest_fls_table_base: 0x0000_7000_0040_5000,
            guest_fls_table_size: 0x1000,
            guest_heap_ctrl_base: 0x0000_7000_0040_6000,
            guest_heap_ctrl_size: 0x1000,
            guest_heap_code_base: 0x0000_7000_0040_7000,
            guest_heap_code_size: 0x1000,
            guest_mbwc_code_base: 0x0000_7000_0040_8000,
            guest_mbwc_code_size: 0x1000,
            // Metrics[256×u32] + colors[32×u32] + cwd wide blob.
            guest_stub_data_base: 0x0000_7000_0040_9000,
            guest_stub_data_size: 0x2000,
        }
    }

    /// Shadow heap base used to tolerate high 32-bit tagged heap metadata accesses.
    #[must_use]
    pub const fn process_heap_shadow_base(self) -> u64 {
        self.process_heap_base + self.process_heap_shadow_delta
    }

    /// Shared `ret` stub for void synchronization APIs.
    #[must_use]
    pub const fn fast_void_return_stub_va(self) -> u64 {
        self.fast_api_stub_base
    }

    /// Apply environment overrides (`WIE_PROCESS_HEAP_MB`).
    ///
    /// Heap size is fixed at session start (contiguous mmap arena). Raise it for
    /// large guest workloads (directory scans that pin many CRT allocations).
    #[must_use]
    pub fn with_env_overrides(mut self) -> Self {
        if let Ok(raw) = std::env::var("WIE_PROCESS_HEAP_MB") {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                match trimmed.parse::<u64>() {
                    Ok(mb) if mb > 0 => {
                        // Cap at 16 GiB — enough for heavy tools, avoids absurd maps.
                        let mb = mb.min(16 * 1024);
                        let bytes = usize::try_from(mb.saturating_mul(1024 * 1024)).unwrap_or(self.process_heap_size);
                        // Keep at least 1 MiB so freelist math stays sane.
                        self.process_heap_size = bytes.max(1024 * 1024);
                    }
                    Ok(_) => {
                        tracing::warn!(
                            value = %raw,
                            "WIE_PROCESS_HEAP_MB must be > 0; keeping default process heap size"
                        );
                    }
                    Err(_) => {
                        tracing::warn!(
                            value = %raw,
                            "invalid WIE_PROCESS_HEAP_MB; keeping default process heap size"
                        );
                    }
                }
            }
        }
        self
    }
}

/// Default layout constants re-exported for existing call sites.
pub const DEFAULT_LAYOUT: RuntimeMemoryLayout = RuntimeMemoryLayout::default();

/// Fake API address region base.
pub const FAKE_API_BASE: u64 = DEFAULT_LAYOUT.fake_api_base;
/// Fake API address region size.
pub const FAKE_API_SIZE: usize = DEFAULT_LAYOUT.fake_api_size;
/// Fake process heap handle.
pub const PROCESS_HEAP_HANDLE: u64 = DEFAULT_LAYOUT.process_heap_handle;
/// Fake process heap base.
pub const PROCESS_HEAP_BASE: u64 = DEFAULT_LAYOUT.process_heap_base;
/// Fake process heap size.
pub const PROCESS_HEAP_SIZE: usize = DEFAULT_LAYOUT.process_heap_size;
/// Offset used by observed Lunar Magic/CRT heap metadata accesses.
pub const PROCESS_HEAP_SHADOW_DELTA: u64 = DEFAULT_LAYOUT.process_heap_shadow_delta;
/// Shadow heap base.
pub const PROCESS_HEAP_SHADOW_BASE: u64 =
    DEFAULT_LAYOUT.process_heap_base + DEFAULT_LAYOUT.process_heap_shadow_delta;
/// Fake low TEB/TIB page base.
pub const FAKE_TEB_LOW_BASE: u64 = DEFAULT_LAYOUT.teb_low_base;
/// Fake low TEB/TIB page size.
pub const FAKE_TEB_LOW_SIZE: usize = DEFAULT_LAYOUT.teb_low_size;
/// Fake resource data base.
pub const FAKE_RESOURCE_DATA_BASE: u64 = DEFAULT_LAYOUT.resource_data_base;
/// Fake resource data size.
pub const FAKE_RESOURCE_DATA_SIZE: usize = DEFAULT_LAYOUT.resource_data_size;
/// Maximum guest instructions between fake API hooks.
pub const ENTRY_TRACE_INSTRUCTION_BUDGET: usize = DEFAULT_LAYOUT.instruction_budget;
/// Maximum consecutive no-hook slices.
pub const ENTRY_TRACE_NO_HOOK_SLICE_LIMIT: usize = DEFAULT_LAYOUT.no_hook_slice_limit;
/// Guest-code region for trivial WinAPI fast-path stubs.
pub const FAST_API_STUB_BASE: u64 = DEFAULT_LAYOUT.fast_api_stub_base;
/// Size of the guest-code fast-path stub region.
pub const FAST_API_STUB_SIZE: usize = DEFAULT_LAYOUT.fast_api_stub_size;
/// Shared `ret` stub for void synchronization APIs.
pub const FAST_VOID_RETURN_STUB_VA: u64 = DEFAULT_LAYOUT.fast_api_stub_base;
/// Return trampoline for guest WndProc invocations.
pub const CALLBACK_RETURN_TRAMPOLINE_VA: u64 = DEFAULT_LAYOUT.callback_return_trampoline_va;

pub(crate) fn default_winapi_state(
    layout: &RuntimeMemoryLayout,
    executable_file_bytes: Vec<u8>,
    process: &wie_pe::ProcessIdentity,
) -> Result<wie_winapi::WinApiState> {
    let heap_size_u64 =
        u64::try_from(layout.process_heap_size).context("heap size does not fit u64")?;
    let heap_end = layout
        .process_heap_base
        .checked_add(heap_size_u64)
        .context("heap end overflow")?;

    let executable_file_size = u64::try_from(executable_file_bytes.len())
        .context("executable file size does not fit u64")?;

    Ok(wie_winapi::WinApiState {
        heap: wie_winapi::GuestHeap::new(layout.process_heap_base, heap_end),
        next_fls_index: 1,
        fls_slots: Vec::new(),
        last_error: 0,
        next_registry_key_handle: 0x0000_0000_7000_0000,
        registry_keys: Vec::new(),
        next_find_handle: 0x0000_0000_6200_0000,
        find_handles: Vec::new(),
        executable_file_size,
        executable_file_bytes,
        main_module_file_name: process.module_file_name.clone(),
        main_module_path: process.module_path.clone(),
        threads: wie_winapi::ThreadState::primary(),
        sync: wie_winapi::SyncState::new(),
        bottle_root: wie_winapi::bottle_root_from_env(),
        volumes: {
            let bottle = wie_winapi::bottle_root_from_env();
            let drive_d = wie_winapi::drive_d_from_env();
            if let Some(ref root) = bottle {
                let _ = wie_winapi::ensure_bottle_skeleton(root);
            }
            wie_winapi::VolumeConfig::from_parts(bottle, drive_d)
        },
        executable_file_cursor: 0,
        next_resource_handle: 0x0000_0000_6300_0000,
        resources: Vec::new(),
        current_directory_wide: process.current_directory.encode_utf16().collect(),
        window_long_ptr_values: Vec::new(),
        image_list_counts: Vec::new(),
        image_list_background_colors: Vec::new(),
        window_visible: false,
        window_enabled: true,
        active_window_handle: 0,
        foreground_window_handle: 0,
        focus_window_handle: 0,
        capture_window_handle: 0,
        cursor_handle: 0,
        window_title: process.module_file_name.clone(),
        window_x: 0,
        window_y: 0,
        window_width: 1024,
        window_height: 768,
        window_invalidated: false,
        tick_count: 1_000,
        keyboard_state: [0_u8; 256],
        next_timer_id: 1,
        timers: Vec::new(),
        next_global_atom: 0xc000,
        global_atoms: Vec::new(),
        next_windows_hook_handle: 0x0000_0000_6602_0000,
        windows_hooks: Vec::new(),
        d3d9_current_vertex_shader: 0,
        d3d9_current_fvf: 0,
        d3d9_render_states: Vec::new(),
        d3d9_texture_stage_states: Vec::new(),
        d3d9_sampler_states: Vec::new(),
        menu_item_states: Vec::new(),
        menu_item_check_states: Vec::new(),
        message_queue: Vec::new(),
        next_message_time: 1,
        d3d9_device_object_address: 0,
        d3d9_device_ref_count: 0,
        d3d9_object_address: 0,
        d3d9_ref_count: 0,
        message_queue_idle_policy: wie_winapi::MessageQueueIdlePolicy::ExitOnIdle,
        next_window_class_atom: 1,
        window_classes: Vec::new(),
        next_window_handle: 0x0000_0000_0001_0000,
        windows: Vec::new(),
        get_proc_address_cache: std::collections::HashMap::with_capacity(64),
        file_dialog_policy: wie_winapi::FileDialogPolicy::Cancel,
        last_file_dialog_path: None,
        comm_dlg_extended_error: 0,
        host_file_mounts: Vec::new(),
        virtual_files: Vec::new(),
        open_files: std::collections::HashMap::new(),
        next_file_handle: 0x0000_0000_6700_0001,
        next_menu_handle: 0x0000_0000_6800_1000,
        guest_io: None,
        guest_file_data_next: layout.guest_file_data_base,
        guest_fls_table_va: layout.guest_fls_table_base,
        stdin_bytes: Vec::new(),
        stdin_cursor: 0,
        // Session bootstrap overwrites: empty inject ⇒ LiveHost.
        stdin_mode: wie_winapi::GuestStdinMode::InjectOnly,
    })
}

pub(crate) fn default_winapi_environment(
    layout: &RuntimeMemoryLayout,
    image_base: u64,
    command_line_a_ptr: u64,
    command_line_w_ptr: u64,
    environment_strings_w_ptr: u64,
    module_file_name_a_ptr: u64,
    module_file_name_w_ptr: u64,
) -> wie_winapi::WinApiEnvironment {
    wie_winapi::WinApiEnvironment {
        image_base,
        command_line_a_ptr,
        command_line_w_ptr,
        environment_strings_w_ptr,
        module_file_name_a_ptr,
        module_file_name_w_ptr,
        process_heap_handle: layout.process_heap_handle,
    }
}

/// Writes command line + module path strings for a process into the env data page.
pub(crate) fn write_process_identity_strings(
    engine: &mut dyn wie_cpu::CpuEngine,
    command_line_a_ptr: u64,
    command_line_w_ptr: u64,
    module_file_name_a_ptr: u64,
    module_file_name_w_ptr: u64,
    process: &wie_pe::ProcessIdentity,
) -> Result<()> {
    let mut cmd_a = process.command_line.as_bytes().to_vec();
    cmd_a.push(0);
    engine
        .mem_write(command_line_a_ptr, &cmd_a)
        .context("failed to write entry ANSI command line")?;

    write_utf16_string(engine, command_line_w_ptr, &process.command_line)
        .context("failed to write entry UTF-16 command line")?;

    // Module file name APIs return the full guest path when available.
    let mut mod_a = process.module_path.as_bytes().to_vec();
    mod_a.push(0);
    engine
        .mem_write(module_file_name_a_ptr, &mod_a)
        .context("failed to write entry ANSI module file name")?;

    write_utf16_string(engine, module_file_name_w_ptr, &process.module_path)
        .context("failed to write entry UTF-16 module file name")?;

    Ok(())
}

pub(crate) fn write_utf16_string(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    value: &str,
) -> Result<()> {
    let mut bytes = Vec::new();

    for unit in value.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    bytes.extend_from_slice(&0_u16.to_le_bytes());

    engine
        .mem_write(address, &bytes)
        .context("failed to write UTF-16 string")
}

pub(crate) fn build_default_environment_strings_w() -> Result<Vec<u8>> {
    let values = [
        "PATH=C:\\Windows\\System32",
        "TEMP=C:\\Users\\WIE\\AppData\\Local\\Temp",
        "TMP=C:\\Users\\WIE\\AppData\\Local\\Temp",
    ];

    let mut bytes = Vec::new();

    for value in values {
        for unit in value.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        bytes.extend_from_slice(&0_u16.to_le_bytes());
    }

    // Additional NUL terminates the entire environment block.
    bytes.extend_from_slice(&0_u16.to_le_bytes());

    Ok(bytes)
}
