//! WinAPI dispatcher model for WIE (generic PE64 userspace).

use std::collections::HashMap;
use std::sync::Arc;

pub mod dll_loader;
pub mod advapi32;
pub mod bottle;
pub mod comctl32;
pub mod comdlg32;
pub mod d3d9;
pub mod dynamic_apis;
pub use dynamic_apis::{DYNAMIC_FAKE_APIS, PREPLANTED_SOFT_APIS, resolve_get_proc_address};
pub mod fake_va;
pub mod gdi32;
pub mod guest_heap;
pub mod guest_io_host;
mod guest_memory;
mod guest_string;
pub mod idle;
pub mod kernel32;
pub mod mingw_dispatch;
pub mod seh;
pub mod ole32;
pub mod oleaut32;
pub mod shell32;
pub mod sync_obj;
pub mod thread;
pub mod ucrt;
pub mod user32;
pub mod uxtheme;
pub mod vfs;
pub mod winmm;
pub mod exception;
pub mod msvc_eh;
pub use bottle::{bottle_root_from_env, drive_d_from_env, guest_path_to_host};
pub use sync_obj::{
    CsWaitQueue, INFINITE, KernelObject, MAXIMUM_WAIT_OBJECTS, MultiWaitRequest, PendingSpawn,
    STILL_ACTIVE, SemaphoreObject, SyncState, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT, WaitTarget,
    wait_multiple,
};
pub use vfs::{VolumeConfig, ensure_bottle_skeleton};
pub use exception::{RuntimeFunction, lookup_function_entry};
#[cfg(test)]
mod exception_tests;
#[cfg(test)]
mod exception_helpers;
// HostParkReason is defined with WinApiControlSignal below.
pub use fake_va::{
    COM_IFACE_IDIRECT3D9, COM_IFACE_IDIRECT3DDEVICE9, FAKE_API_BASE, FAKE_API_SIZE, FakeVa,
    SPECIAL_CALLBACK_RETURN, SPECIAL_SEH_CONTINUE, callback_return_trampoline_va,
    decode as decode_fake_va, encode_alias, encode_com, encode_export, encode_unresolved,
    seh_continue_trampoline_va,
};
pub use guest_heap::GuestHeap;
pub use idle::{IdleContext, IdlePolicy};
pub use kernel32::WinApiHandlerResult;
pub use thread::{FIRST_WORKER_TID, GuestThread, PRIMARY_THREAD_ID, ThreadState};

/// Runtime environment values visible to WinAPI handlers.
#[derive(Debug, Clone, Copy)]
pub struct WinApiEnvironment {
    /// Main module image base.
    pub image_base: u64,

    /// Pointer to ANSI command line string in emulated memory.
    pub command_line_a_ptr: u64,

    /// Pointer to UTF-16 command line string in emulated memory.
    pub command_line_w_ptr: u64,

    /// Pointer to UTF-16 environment strings block in emulated memory.
    pub environment_strings_w_ptr: u64,

    /// Pointer to ANSI module file name string in emulated memory.
    pub module_file_name_a_ptr: u64,

    /// Pointer to UTF-16 module file name string in emulated memory.
    pub module_file_name_w_ptr: u64,

    /// Fake process heap handle.
    pub process_heap_handle: u64,
}

pub struct WinApiState {
    /// Process heap: segregated freelist + bump (see [`GuestHeap`]).
    pub heap: GuestHeap,

    /// Next fake `FLS` index.
    pub next_fls_index: u32,

    /// Fake `FLS` slots.
    pub fls_slots: Vec<FlsSlot>,

    /// Last WinAPI error value.
    pub last_error: u32,

    /// Next fake registry key handle.
    pub next_registry_key_handle: u64,

    /// Fake registry key handles.
    pub registry_keys: Vec<RegistryKey>,

    /// Next fake find-file handle.
    pub next_find_handle: u64,

    /// Active fake find-file handles.
    pub find_handles: Vec<FindHandle>,

    /// Size of the executable file visible through fake file handles.
    pub executable_file_size: u64,

    /// Bytes of the executable file visible through fake file handles.
    pub executable_file_bytes: Vec<u8>,

    /// Basename of the main PE (`heap_alloc.exe`, `Lunar Magic.exe`, …).
    pub main_module_file_name: String,

    /// Guest full path of the main PE (`C:\App\…`).
    pub main_module_path: String,

    /// Guest thread table + active TLS/TID (MT.0 / MT.1).
    ///
    /// TLS **indices** are process-wide; **values** live on
    /// [`ThreadState::active`]. Prefer helpers on this field over ad-hoc TID
    /// constants.
    pub threads: ThreadState,

    /// Kernel objects, CS wait queues, pending `CreateThread` spawns (MT.2/3).
    pub sync: SyncState,

    /// Optional bottle root: guest `C:\…` maps to `{root}/drive_c/…` on the host.
    ///
    /// Set via `WIE_ROOT` / session. When set, CreateFile create/open uses real host files.
    /// Prefer [`Self::volumes`]; this field is kept in sync for compatibility.
    pub bottle_root: Option<std::path::PathBuf>,

    /// Volume table: bottle C: + optional host-bridge D:.
    pub volumes: VolumeConfig,

    /// Current cursor for the fake executable file handle.
    ///
    /// Deprecated for multi-file I/O: prefer `open_files`. Kept so the main
    /// executable still has a stable content source at session start.
    pub executable_file_cursor: u64,

    /// Host files mounted into the guest path namespace.
    pub host_file_mounts: Vec<HostFileMount>,

    /// Guest-visible virtual files created at runtime (ini/sidecars/temps).
    pub virtual_files: Vec<VirtualGuestFile>,

    /// Currently open guest file handles, keyed by handle.
    pub open_files: HashMap<u64, OpenGuestFile>,

    /// Next handle value for `CreateFile*`.
    pub next_file_handle: u64,

    /// Next fake resource handle.
    pub next_resource_handle: u64,

    /// Fake resource records.
    pub resources: Vec<ResourceRecord>,

    pub current_directory_wide: Vec<u16>,

    pub window_long_ptr_values: Vec<(u64, i64, u64)>,

    pub image_list_counts: Vec<(u64, u64)>,

    /// Background colors associated with fake image lists.
    pub image_list_background_colors: Vec<(u64, u32)>,

    /// Whether the fake main window is visible.
    pub window_visible: bool,

    /// Whether the fake main window is enabled.
    pub window_enabled: bool,

    /// Current fake active window.
    pub active_window_handle: u64,

    /// Current fake foreground window.
    pub foreground_window_handle: u64,

    /// Current fake keyboard-focus window.
    pub focus_window_handle: u64,

    /// Current fake mouse-capture window.
    pub capture_window_handle: u64,

    /// Current fake cursor handle.
    pub cursor_handle: u64,

    /// Title of the current fake main window.
    pub window_title: String,

    /// X coordinate of the current fake main window.
    pub window_x: i32,

    /// Y coordinate of the current fake main window.
    pub window_y: i32,

    /// Width of the current fake main window.
    pub window_width: i32,

    /// Height of the current fake main window.
    pub window_height: i32,

    /// Whether the current fake main window has a pending repaint.
    pub window_invalidated: bool,

    /// Monotonic fake millisecond counter.
    pub tick_count: u64,

    /// State of the 256 virtual keyboard keys.
    pub keyboard_state: [u8; 256],

    /// Next automatically generated USER32 timer identifier.
    pub next_timer_id: u64,

    /// Active fake USER32 timers.
    pub timers: Vec<TimerRecord>,

    /// Next fake global atom identifier.
    pub next_global_atom: u16,

    /// Fake global atom table.
    pub global_atoms: Vec<GlobalAtomRecord>,

    /// Next fake USER32 hook handle.
    pub next_windows_hook_handle: u64,

    /// Registered fake USER32 hooks.
    pub windows_hooks: Vec<WindowsHookRecord>,

    /// Currently bound fake Direct3D 9 vertex shader.
    pub d3d9_current_vertex_shader: u64,

    /// Currently selected Direct3D 9 flexible vertex format.
    pub d3d9_current_fvf: u32,

    /// Direct3D 9 render-state values indexed by `D3DRENDERSTATETYPE`.
    pub d3d9_render_states: Vec<(u32, u32)>,

    /// Direct3D 9 texture-stage states stored as `(stage, state_type, value)`.
    pub d3d9_texture_stage_states: Vec<(u32, u32, u32)>,

    /// Direct3D 9 sampler states stored as `(sampler, state_type, value)`.
    pub d3d9_sampler_states: Vec<(u32, u32, u32)>,

    /// USER32 menu item enable-state records stored as
    /// `(menu_handle, item, flags)`.
    pub menu_item_states: Vec<(u64, u32, u32)>,

    /// USER32 menu item check-state records stored as
    /// `(menu_handle, item, flags)`.
    pub menu_item_check_states: Vec<(u64, u32, u32)>,

    /// Pending USER32 messages in FIFO order.
    pub message_queue: Vec<QueuedWindowMessage>,

    /// Monotonic fake USER32 message timestamp.
    pub next_message_time: u32,

    /// Guest address of the current fake `IDirect3DDevice9` object.
    pub d3d9_device_object_address: u64,

    /// COM reference count of the current fake `IDirect3DDevice9` object.
    pub d3d9_device_ref_count: u32,

    /// Guest address of the current fake `IDirect3D9` object.
    pub d3d9_object_address: u64,

    /// COM reference count of the current fake `IDirect3D9` object.
    pub d3d9_ref_count: u32,

    /// Policy used when `GetMessageA` finds no matching queued message.
    pub message_queue_idle_policy: MessageQueueIdlePolicy,

    /// Next atom returned for a registered window class.
    pub next_window_class_atom: u16,

    /// Registered USER32 window classes.
    pub window_classes: Vec<WindowClassRecord>,

    /// Next runtime-owned fake HWND.
    pub next_window_handle: u64,

    /// Windows created through `CreateWindowExA/W`.
    pub windows: Vec<WindowRecord>,

    /// Cached `GetProcAddress` resolutions keyed by export name (ASCII lower).
    pub get_proc_address_cache: std::collections::HashMap<String, GetProcAddressCacheEntry>,

    /// Policy applied when the guest opens a common file dialog.
    pub file_dialog_policy: FileDialogPolicy,

    /// Last path accepted by a simulated file dialog (if any).
    pub last_file_dialog_path: Option<String>,

    /// Value returned by `CommDlgExtendedError`.
    pub comm_dlg_extended_error: u32,

    /// Next fake HMENU value for `CreateMenu` / `CreatePopupMenu`.
    pub next_menu_handle: u64,

    /// Guest I/O acceleration config (None until runtime installs helpers).
    pub guest_io: Option<GuestIoRuntimeConfig>,

    /// Next free VA in the guest file-data mirror arena.
    pub guest_file_data_next: u64,

    /// Guest VA of the FLS value table (u64 slots), 0 if not installed.
    pub guest_fls_table_va: u64,

    /// Buffered guest stdin bytes for console `ReadFile(STD_INPUT_HANDLE)`.
    ///
    /// Filled either by host injection (`--stdin` / tests) or by a live host
    /// line-fill when [`Self::stdin_mode`] is [`GuestStdinMode::LiveHost`].
    pub stdin_bytes: Vec<u8>,

    /// Read cursor into [`Self::stdin_bytes`].
    pub stdin_cursor: usize,

    /// How console stdin is sourced when the buffer is empty.
    pub stdin_mode: GuestStdinMode,

    /// In-progress SEH / C++ EH continuation (UnwindMap + catch funclets).
    pub seh_pending: Option<seh::SehPending>,

    /// Import resolver for dynamic DLL loading.
    ///
    /// Set once at session init by the runtime (`wie-runtime::session`).
    /// Resolves `(library, name, iat_slot_va)` → fake API VA for import patching.
    /// `None` means dynamic loading is unavailable (falls back to fake handles).
    pub import_resolver: Option<Box<dyn FnMut(&str, &str, u64) -> anyhow::Result<u64> + Send>>,

    /// Dynamically loaded DLL modules (real, not fake stubs).
    /// Keyed by normalized (lowercase) module name without extension.
    pub loaded_modules: HashMap<String, dll_loader::LoadedModule>,

    /// Next real loaded module handle (monotonically increasing, each step by 0x1000).
    pub next_module_handle: u64,
}

// Manual Debug impl: Box<dyn FnMut + Send> does not implement Debug.
impl std::fmt::Debug for WinApiState {
    #[expect(clippy::todo, reason = "exhaustive field listing")]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WinApiState")
            .field("heap", &self.heap)
            .field("next_fls_index", &self.next_fls_index)
            .field("fls_slots", &self.fls_slots)
            .field("last_error", &self.last_error)
            .field("next_registry_key_handle", &self.next_registry_key_handle)
            .field("registry_keys", &self.registry_keys)
            .field("next_find_handle", &self.next_find_handle)
            .field("find_handles", &self.find_handles)
            .field("executable_file_size", &self.executable_file_size)
            .field("executable_file_bytes", &self.executable_file_bytes)
            .field("main_module_file_name", &self.main_module_file_name)
            .field("main_module_path", &self.main_module_path)
            .field("threads", &self.threads)
            .field("sync", &self.sync)
            .field("bottle_root", &self.bottle_root)
            .field("volumes", &self.volumes)
            .field("executable_file_cursor", &self.executable_file_cursor)
            .field("host_file_mounts", &self.host_file_mounts)
            .field("virtual_files", &self.virtual_files)
            .field("open_files", &self.open_files)
            .field("next_file_handle", &self.next_file_handle)
            .field("next_resource_handle", &self.next_resource_handle)
            .field("resources", &self.resources)
            .field("current_directory_wide", &self.current_directory_wide)
            .field("window_long_ptr_values", &self.window_long_ptr_values)
            .field("image_list_counts", &self.image_list_counts)
            .field("image_list_background_colors", &self.image_list_background_colors)
            .field("window_visible", &self.window_visible)
            .field("window_enabled", &self.window_enabled)
            .field("active_window_handle", &self.active_window_handle)
            .field("foreground_window_handle", &self.foreground_window_handle)
            .field("focus_window_handle", &self.focus_window_handle)
            .field("capture_window_handle", &self.capture_window_handle)
            .field("cursor_handle", &self.cursor_handle)
            .field("window_title", &self.window_title)
            .field("window_x", &self.window_x)
            .field("window_y", &self.window_y)
            .field("window_width", &self.window_width)
            .field("window_height", &self.window_height)
            .field("window_invalidated", &self.window_invalidated)
            .field("tick_count", &self.tick_count)
            .field("keyboard_state", &self.keyboard_state)
            .field("next_timer_id", &self.next_timer_id)
            .field("timers", &self.timers)
            .field("next_global_atom", &self.next_global_atom)
            .field("global_atoms", &self.global_atoms)
            .field("next_windows_hook_handle", &self.next_windows_hook_handle)
            .field("windows_hooks", &self.windows_hooks)
            .field("d3d9_current_vertex_shader", &self.d3d9_current_vertex_shader)
            .field("d3d9_current_fvf", &self.d3d9_current_fvf)
            .field("d3d9_render_states", &self.d3d9_render_states)
            .field("d3d9_texture_stage_states", &self.d3d9_texture_stage_states)
            .field("d3d9_sampler_states", &self.d3d9_sampler_states)
            .field("menu_item_states", &self.menu_item_states)
            .field("menu_item_check_states", &self.menu_item_check_states)
            .field("message_queue", &self.message_queue)
            .field("next_message_time", &self.next_message_time)
            .field("d3d9_device_object_address", &self.d3d9_device_object_address)
            .field("d3d9_device_ref_count", &self.d3d9_device_ref_count)
            .field("d3d9_object_address", &self.d3d9_object_address)
            .field("d3d9_ref_count", &self.d3d9_ref_count)
            .field("message_queue_idle_policy", &self.message_queue_idle_policy)
            .field("next_window_class_atom", &self.next_window_class_atom)
            .field("window_classes", &self.window_classes)
            .field("next_window_handle", &self.next_window_handle)
            .field("windows", &self.windows)
            .field("get_proc_address_cache", &self.get_proc_address_cache)
            .field("file_dialog_policy", &self.file_dialog_policy)
            .field("last_file_dialog_path", &self.last_file_dialog_path)
            .field("comm_dlg_extended_error", &self.comm_dlg_extended_error)
            .field("next_menu_handle", &self.next_menu_handle)
            .field("guest_io", &self.guest_io)
            .field("guest_file_data_next", &self.guest_file_data_next)
            .field("guest_fls_table_va", &self.guest_fls_table_va)
            .field("stdin_bytes", &self.stdin_bytes)
            .field("stdin_cursor", &self.stdin_cursor)
            .field("stdin_mode", &self.stdin_mode)
            .field("seh_pending", &self.seh_pending)
            .field("import_resolver", &"<closure>")
            .field("loaded_modules", &self.loaded_modules)
            .field("next_module_handle", &self.next_module_handle)
            .finish()
    }
}

// Manual Clone impl: Box<dyn FnMut + Send> does not implement Clone.
impl Clone for WinApiState {
    fn clone(&self) -> Self {
        Self {
            heap: self.heap.clone(),
            next_fls_index: self.next_fls_index,
            fls_slots: self.fls_slots.clone(),
            last_error: self.last_error,
            next_registry_key_handle: self.next_registry_key_handle,
            registry_keys: self.registry_keys.clone(),
            next_find_handle: self.next_find_handle,
            find_handles: self.find_handles.clone(),
            executable_file_size: self.executable_file_size,
            executable_file_bytes: self.executable_file_bytes.clone(),
            main_module_file_name: self.main_module_file_name.clone(),
            main_module_path: self.main_module_path.clone(),
            threads: self.threads.clone(),
            sync: self.sync.clone(),
            bottle_root: self.bottle_root.clone(),
            volumes: self.volumes.clone(),
            executable_file_cursor: self.executable_file_cursor,
            host_file_mounts: self.host_file_mounts.clone(),
            virtual_files: self.virtual_files.clone(),
            open_files: self.open_files.clone(),
            next_file_handle: self.next_file_handle,
            next_resource_handle: self.next_resource_handle,
            resources: self.resources.clone(),
            current_directory_wide: self.current_directory_wide.clone(),
            window_long_ptr_values: self.window_long_ptr_values.clone(),
            image_list_counts: self.image_list_counts.clone(),
            image_list_background_colors: self.image_list_background_colors.clone(),
            window_visible: self.window_visible,
            window_enabled: self.window_enabled,
            active_window_handle: self.active_window_handle,
            foreground_window_handle: self.foreground_window_handle,
            focus_window_handle: self.focus_window_handle,
            capture_window_handle: self.capture_window_handle,
            cursor_handle: self.cursor_handle,
            window_title: self.window_title.clone(),
            window_x: self.window_x,
            window_y: self.window_y,
            window_width: self.window_width,
            window_height: self.window_height,
            window_invalidated: self.window_invalidated,
            tick_count: self.tick_count,
            keyboard_state: self.keyboard_state,
            next_timer_id: self.next_timer_id,
            timers: self.timers.clone(),
            next_global_atom: self.next_global_atom,
            global_atoms: self.global_atoms.clone(),
            next_windows_hook_handle: self.next_windows_hook_handle,
            windows_hooks: self.windows_hooks.clone(),
            d3d9_current_vertex_shader: self.d3d9_current_vertex_shader,
            d3d9_current_fvf: self.d3d9_current_fvf,
            d3d9_render_states: self.d3d9_render_states.clone(),
            d3d9_texture_stage_states: self.d3d9_texture_stage_states.clone(),
            d3d9_sampler_states: self.d3d9_sampler_states.clone(),
            menu_item_states: self.menu_item_states.clone(),
            menu_item_check_states: self.menu_item_check_states.clone(),
            message_queue: self.message_queue.clone(),
            next_message_time: self.next_message_time,
            d3d9_device_object_address: self.d3d9_device_object_address,
            d3d9_device_ref_count: self.d3d9_device_ref_count,
            d3d9_object_address: self.d3d9_object_address,
            d3d9_ref_count: self.d3d9_ref_count,
            message_queue_idle_policy: self.message_queue_idle_policy,
            next_window_class_atom: self.next_window_class_atom,
            window_classes: self.window_classes.clone(),
            next_window_handle: self.next_window_handle,
            windows: self.windows.clone(),
            get_proc_address_cache: self.get_proc_address_cache.clone(),
            file_dialog_policy: self.file_dialog_policy.clone(),
            last_file_dialog_path: self.last_file_dialog_path.clone(),
            comm_dlg_extended_error: self.comm_dlg_extended_error,
            next_menu_handle: self.next_menu_handle,
            guest_io: self.guest_io.clone(),
            guest_file_data_next: self.guest_file_data_next,
            guest_fls_table_va: self.guest_fls_table_va,
            stdin_bytes: self.stdin_bytes.clone(),
            stdin_cursor: self.stdin_cursor,
            stdin_mode: self.stdin_mode,
            seh_pending: self.seh_pending.clone(),
            import_resolver: None, // Box<dyn FnMut + Send> is not Clone
            loaded_modules: self.loaded_modules.clone(),
            next_module_handle: self.next_module_handle,
        }
    }
}

/// Source policy for console `ReadFile(STD_INPUT_HANDLE)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GuestStdinMode {
    /// Serve only [`WinApiState::stdin_bytes`]; exhausted buffer → EOF (0 bytes).
    ///
    /// Used for `--stdin FILE` and deterministic micro-tests (no TTY hang).
    #[default]
    InjectOnly,
    /// When the buffer is empty, block-fill one host line (Microsoft Learn
    /// default console line input / `ENABLE_LINE_INPUT` approximation).
    LiveHost,
}

/// Runtime-published guest I/O layout (filled by `wie-runtime` at session start).
#[derive(Debug, Clone)]
pub struct GuestIoRuntimeConfig {
    /// Guest VA of the open-file handle table.
    pub table_va: u64,
    /// Guest VA of the file-content mirror arena base.
    pub file_data_base: u64,
    /// Size in bytes of the file-content mirror arena.
    pub file_data_size: usize,
}

/// Host-side decision for `GetOpenFileName` / `GetSaveFileName`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileDialogPolicy {
    /// Simulate the user cancelling the dialog (`return FALSE`).
    Cancel,

    /// Simulate the user accepting `path` (`return TRUE` and fill `lpstrFile`).
    Accept {
        /// Absolute or relative Windows-style path written into the dialog buffer.
        path: String,
    },
}

/// One host file exposed to the guest under one or more Windows paths.
#[derive(Debug, Clone)]
pub struct HostFileMount {
    /// Preferred guest path (Windows-style), e.g. `C:\LunarMagic\game.sfc`.
    pub guest_path: String,

    /// Absolute path on the host filesystem.
    pub host_path: std::path::PathBuf,
}

/// One open guest file handle returned by `CreateFile*`.
#[derive(Debug, Clone)]
pub struct OpenGuestFile {
    /// Fake handle value.
    pub handle: u64,

    /// Guest path used to open the file.
    pub path: String,

    /// File contents (working buffer). Empty when [`Self::streaming`] is true.
    pub bytes: Vec<u8>,

    /// Current read/write cursor.
    pub cursor: u64,

    /// When set, file is bottle/mount/D-backed and may be flushed/streamed here.
    pub host_path: Option<std::path::PathBuf>,

    /// Large host file: I/O via `host_path` seek/read/write without full buffer.
    pub streaming: bool,

    /// Guest VA of mirrored file bytes for in-guest ReadFile (if registered).
    pub guest_data_va: Option<u64>,

    /// Index into the guest I/O handle table (if registered).
    pub guest_slot_index: Option<u32>,
}

impl OpenGuestFile {
    /// Logical file size in bytes.
    #[must_use]
    pub fn size(&self) -> u64 {
        if self.streaming {
            self.host_path
                .as_ref()
                .and_then(|p| std::fs::metadata(p).ok())
                .map_or(0, |m| m.len())
        } else {
            u64::try_from(self.bytes.len()).unwrap_or(0)
        }
    }
}

/// A pure-guest virtual file (not backed by a host path).
#[derive(Debug, Clone)]
pub struct VirtualGuestFile {
    /// Guest Windows path.
    pub guest_path: String,

    /// Mutable contents.
    pub bytes: Vec<u8>,
}

/// One cached `GetProcAddress` resolution.
#[derive(Debug, Clone)]
pub struct GetProcAddressCacheEntry {
    /// Normalized (lowercase) export name.
    pub name: Arc<str>,

    /// Module handle that first requested this export.
    pub module_handle: u64,

    /// Resolved fake target VA (may be zero for probed-but-absent exports).
    pub address: u64,

    /// How many times this export was resolved.
    pub hit_count: u64,
}

/// Registered fake USER32 window class.
#[derive(Debug, Clone)]
pub struct WindowClassRecord {
    /// Atom returned by `RegisterClassExA/W`.
    pub atom: u16,

    /// Registered class name.
    pub class_name: String,

    /// Guest address of the class window procedure.
    pub window_proc: u64,

    /// Class style flags.
    pub style: u32,

    /// Module instance associated with the class.
    pub instance_handle: u64,

    /// Default icon handle.
    pub icon_handle: u64,

    /// Default cursor handle.
    pub cursor_handle: u64,

    /// Background brush handle.
    pub background_brush: u64,

    /// Small icon handle.
    pub small_icon_handle: u64,

    /// Whether the class was registered through the Unicode API.
    pub unicode: bool,
}

/// USER32 window created inside the compatibility runtime.
#[derive(Debug, Clone)]
pub struct WindowRecord {
    /// Runtime-owned fake HWND.
    pub handle: u64,

    /// Registered class atom.
    pub class_atom: u16,

    /// Registered class name.
    pub class_name: String,

    /// Guest address of the window procedure.
    pub window_proc: u64,

    /// Whether the class uses the Unicode window procedure contract.
    pub unicode: bool,

    /// Window title.
    pub title: String,

    /// Standard window style flags.
    pub style: u32,

    /// Extended window style flags.
    pub extended_style: u32,

    /// Parent or owner window.
    pub parent_handle: u64,

    /// Menu handle or child-window identifier.
    pub menu_handle: u64,

    /// Module instance passed to `CreateWindowExA/W`.
    pub instance_handle: u64,

    /// Initial horizontal position.
    pub x: i32,

    /// Initial vertical position.
    pub y: i32,

    /// Initial width.
    pub width: i32,

    /// Initial height.
    pub height: i32,

    /// Current visibility state.
    pub visible: bool,

    /// Current enabled state.
    pub enabled: bool,
}

/// Request to invoke a function located inside guest executable code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestCallbackRequest {
    /// Guest address of the callback function.
    pub callback_address: u64,

    /// Target runtime-owned window handle.
    pub window_handle: u64,

    /// Numeric Windows message identifier.
    pub message: u32,

    /// Message word parameter.
    pub word_parameter: u64,

    /// Message long parameter.
    pub long_parameter: u64,

    /// Whether the target window class uses the Unicode contract.
    pub unicode: bool,
}

/// A queued fake USER32 message.
#[derive(Debug, Clone)]
pub struct QueuedWindowMessage {
    /// Target window handle.
    pub window_handle: u64,

    /// Numeric Windows message identifier.
    pub message: u32,

    /// Message word parameter.
    pub word_parameter: u64,

    /// Message long parameter.
    pub long_parameter: u64,

    /// Deterministic fake message timestamp.
    pub time: u32,

    /// Fake cursor X coordinate.
    pub point_x: i32,

    /// Fake cursor Y coordinate.
    pub point_y: i32,
}

/// Registered fake USER32 hook.
#[derive(Debug, Clone)]
pub struct WindowsHookRecord {
    /// Fake hook handle returned to the guest.
    pub handle: u64,

    /// Hook type such as `WH_CBT` or `WH_CALLWNDPROC`.
    pub hook_type: i32,

    /// Guest hook procedure address.
    pub callback_address: u64,

    /// Optional module handle supplied by the guest.
    pub module_handle: u64,

    /// Target thread identifier, or zero for a global hook.
    pub thread_id: u32,
}

/// Fake global atom table entry.
#[derive(Debug, Clone)]
pub struct GlobalAtomRecord {
    /// Atom identifier.
    pub atom: u16,

    /// Stored ANSI atom name.
    pub name: String,
}

/// Fake USER32 timer record.
#[derive(Debug, Clone)]
pub struct TimerRecord {
    /// Window associated with the timer, or zero for a thread timer.
    pub window_handle: u64,

    /// Timer identifier.
    pub timer_id: u64,

    /// Requested timer interval in milliseconds.
    pub interval_ms: u32,

    /// Optional guest timer callback address.
    pub callback_address: u64,
}

/// Fake resource record.
#[derive(Debug, Clone)]
pub struct ResourceRecord {
    /// Fake resource handle.
    pub handle: u64,

    /// Fake loaded resource handle.
    pub loaded_handle: u64,

    /// Pointer to fake resource bytes.
    pub data_ptr: u64,

    /// Resource size.
    pub size: u32,
}

/// Fake find-file handle (materialized directory enumeration).
#[derive(Debug, Clone)]
pub struct FindHandle {
    /// Fake find handle.
    pub handle: u64,

    /// Search pattern/path as provided by the guest.
    pub pattern: String,

    /// Remaining entries after the one returned by FindFirst (FindNext consumes).
    pub remaining: Vec<vfs::DirEntry>,
}

/// Fake registry key.
#[derive(Debug, Clone)]
pub struct RegistryKey {
    /// Fake registry key handle.
    pub handle: u64,

    /// Parent key handle.
    pub parent: u64,

    /// Subkey path.
    pub subkey: String,
}

/// Fake heap allocation record.
#[derive(Debug, Clone)]
pub struct HeapAllocation {
    /// Allocation base address.
    pub address: u64,

    /// Allocation size in bytes.
    pub size: u64,
}

/// Fake `FLS` slot.
#[derive(Debug, Clone)]
pub struct FlsSlot {
    /// Slot index.
    pub index: u32,

    /// Slot value.
    pub value: u64,
}

/// Behavior of `GetMessageA` when no matching message is available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageQueueIdlePolicy {
    /// Produce a synthetic `WM_QUIT`.
    ///
    /// This preserves the deterministic bootstrap regression path.
    ExitOnIdle,

    /// Yield execution back to the runtime without modifying the guest `MSG`.
    ///
    /// This will be used by the persistent interactive runtime.
    YieldOnIdle,
}

/// Non-error control signal emitted by a WinAPI handler.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum WinApiControlSignal {
    /// `GetMessageA` cannot continue until a message becomes available.
    #[error("waiting for a window message")]
    WaitingForMessage,

    /// `DispatchMessageA/W` requires execution of a guest window procedure.
    #[error("guest window callback requested: {request:?}")]
    GuestCallbackRequested {
        /// Description of the pending guest callback.
        request: GuestCallbackRequest,
    },

    /// Host thread must park (drop CPU lock) then retry / continue (MT.2/3).
    #[error("host park: {reason:?}")]
    HostPark {
        /// Why the host thread is parking.
        reason: HostParkReason,
    },

    /// Guest `ExitThread` — worker run loop should terminate this host thread.
    #[error("exit thread code={code}")]
    ExitThread {
        /// Thread exit code.
        code: u32,
    },
}

/// Reason for [`WinApiControlSignal::HostPark`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostParkReason {
    /// Waiting to enter critical section at guest VA.
    CriticalSection {
        /// Guest `RTL_CRITICAL_SECTION*`.
        cs: u64,
    },
    /// `WaitForSingleObject` (or similar) on a kernel handle.
    WaitObject {
        /// Kernel handle.
        handle: u64,
        /// Timeout in ms (`INFINITE` = forever).
        timeout_ms: u32,
    },
    /// `WaitForMultipleObjects` — handles live in [`SyncState::multi_wait`].
    ///
    /// Kept small/`Copy` so [`WinApiControlSignal`] stays compact; the handle
    /// list is stored on process sync state for the duration of the park.
    WaitMultiple,
}

mod dispatch_table;
pub use dispatch_table::{
    WINAPI_ID_COUNT, WinApiId, WinApiTraits, dispatch_winapi, dispatch_winapi_id,
    is_winapi_implemented, resolve_winapi_id, winapi_id_export,
};

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;
    use wie_cpu::{CpuEngine, IcedCpu};

    const STACK_VA: u64 = 0x100_0000;
    const STACK_SIZE: usize = 0x1_0000;
    // STACK_VA + STACK_SIZE - 0x100 (leave room for a dummy return address).
    const STACK_TOP: u64 = 0x100_FF00;

    /// Minimal engine for handler unit tests: maps guest pages with a valid return address on the stack.
    fn test_engine() -> IcedCpu {
        let mut cpu = IcedCpu::open_x86_64();
        cpu.mem_map(0x1000, 0x10_0000, 7).expect("map test memory");
        cpu.mem_map(STACK_VA, STACK_SIZE, 7)
            .expect("map test stack");
        // Write a dummy return address — every handler calls return_from_win64_api which reads it.
        cpu.mem_write(STACK_TOP, &0_u64.to_le_bytes())
            .expect("write return address");
        cpu.write_rsp(STACK_TOP).ok();
        cpu
    }

    fn write_regs(cpu: &mut IcedCpu, rcx: u64, rdx: u64, r8: u64, r9: u64, rsp: u64) {
        cpu.write_rcx(rcx).ok();
        cpu.write_rdx(rdx).ok();
        cpu.write_r8(r8).ok();
        cpu.write_r9(r9).ok();
        cpu.write_rsp(if rsp == 0 { STACK_TOP } else { rsp }).ok();
    }

    fn default_env() -> WinApiEnvironment {
        WinApiEnvironment {
            image_base: 0x0000_0000_1400_0000,
            command_line_a_ptr: 0,
            command_line_w_ptr: 0,
            environment_strings_w_ptr: 0,
            module_file_name_a_ptr: 0,
            module_file_name_w_ptr: 0,
            process_heap_handle: 1,
        }
    }

    /// Low 32 bits of RAX as signed LONG (Win64 return convention for Interlocked*).
    fn rax_low_i32(rax: u64) -> i32 {
        i32::from_le_bytes(u32::try_from(rax & 0xffff_ffff).unwrap_or(0).to_le_bytes())
    }

    fn default_winapi_state() -> WinApiState {
        // Simplified default with a bump heap covering [0x2000, 0x10000).
        let mut heap = GuestHeap::new(0x2000, 0x10000);
        heap.attach_guest_control(0x2000);
        WinApiState {
            heap,
            ..winapi_state_default()
        }
    }

    fn winapi_state_default() -> WinApiState {
        // This must stay in sync with the fields of WinApiState.
        // Only the heap is customised; everything else is default.
        WinApiState {
            heap: GuestHeap::new(0x2000, 0x10000),
            next_fls_index: 0,
            fls_slots: Vec::new(),
            last_error: 0,
            next_registry_key_handle: 0,
            registry_keys: Vec::new(),
            next_find_handle: 0,
            find_handles: Vec::new(),
            executable_file_size: 0,
            executable_file_bytes: Vec::new(),
            main_module_file_name: String::new(),
            main_module_path: String::new(),
            threads: ThreadState::primary(),
            sync: SyncState::new(),
            bottle_root: None,
            volumes: VolumeConfig::default(),
            // volumes.bottle_root kept in sync via set helpers / session
            executable_file_cursor: 0,
            host_file_mounts: Vec::new(),
            virtual_files: Vec::new(),
            open_files: HashMap::new(),
            next_file_handle: 0,
            next_resource_handle: 0,
            resources: Vec::new(),
            current_directory_wide: Vec::new(),
            window_long_ptr_values: Vec::new(),
            image_list_counts: Vec::new(),
            image_list_background_colors: Vec::new(),
            window_visible: false,
            window_enabled: false,
            active_window_handle: 0,
            foreground_window_handle: 0,
            focus_window_handle: 0,
            capture_window_handle: 0,
            cursor_handle: 0,
            window_title: String::new(),
            window_x: 0,
            window_y: 0,
            window_width: 0,
            window_height: 0,
            window_invalidated: false,
            tick_count: 0,
            keyboard_state: [0; 256],
            next_timer_id: 0,
            timers: Vec::new(),
            next_global_atom: 0,
            global_atoms: Vec::new(),
            next_windows_hook_handle: 0,
            windows_hooks: Vec::new(),
            d3d9_current_vertex_shader: 0,
            d3d9_current_fvf: 0,
            d3d9_render_states: Vec::new(),
            d3d9_texture_stage_states: Vec::new(),
            d3d9_sampler_states: Vec::new(),
            menu_item_states: Vec::new(),
            menu_item_check_states: Vec::new(),
            message_queue: Vec::new(),
            next_message_time: 0,
            d3d9_device_object_address: 0,
            d3d9_device_ref_count: 0,
            d3d9_object_address: 0,
            d3d9_ref_count: 0,
            message_queue_idle_policy: MessageQueueIdlePolicy::ExitOnIdle,
            next_window_class_atom: 0,
            window_classes: Vec::new(),
            next_window_handle: 0,
            windows: Vec::new(),
            get_proc_address_cache: HashMap::new(),
            file_dialog_policy: FileDialogPolicy::Cancel,
            last_file_dialog_path: None,
            comm_dlg_extended_error: 0,
            next_menu_handle: 0,
            guest_io: None,
            guest_file_data_next: 0,
            guest_fls_table_va: 0,
            stdin_bytes: Vec::new(),
            stdin_cursor: 0,
            stdin_mode: GuestStdinMode::InjectOnly,
            seh_pending: None,
            import_resolver: None,
            loaded_modules: HashMap::new(),
            next_module_handle: dll_loader::REAL_MODULE_HANDLE_BASE,
        }
    }

    macro_rules! assert_return_value {
        ($result:expr, $expected:expr) => {
            let r = $result.expect("handler should succeed");
            assert_eq!(r.return_value, $expected, "return value mismatch");
        };
    }

    // --- Kernel32 ---

    #[test]
    fn test_critical_section_reenter_single_thread() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        // `test_engine` maps [0x1000, 0x101000); place CS there.
        let cs = 0x3000_u64;
        write_regs(&mut engine, cs, 0, 0, 0, 0);
        kernel32::handle_initialize_critical_section(&mut engine).expect("init");
        write_regs(&mut engine, cs, 0, 0, 0, 0);
        kernel32::handle_enter_critical_section(&mut engine, &state).expect("enter1");
        write_regs(&mut engine, cs, 0, 0, 0, 0);
        kernel32::handle_enter_critical_section(&mut engine, &state).expect("enter2");
        let mut rec = [0_u8; 4];
        engine.mem_read(cs + 12, &mut rec).expect("read recursion");
        assert_eq!(u32::from_le_bytes(rec), 2);
        let mut owner = [0_u8; 8];
        engine.mem_read(cs + 16, &mut owner).expect("read owner");
        assert_eq!(u64::from_le_bytes(owner), u64::from(PRIMARY_THREAD_ID));
        write_regs(&mut engine, cs, 0, 0, 0, 0);
        kernel32::handle_leave_critical_section(&mut engine, &mut state).expect("leave1");
        write_regs(&mut engine, cs, 0, 0, 0, 0);
        kernel32::handle_leave_critical_section(&mut engine, &mut state).expect("leave2");
        engine
            .mem_read(cs + 16, &mut owner)
            .expect("read owner unlocked");
        assert_eq!(u64::from_le_bytes(owner), 0);
        assert_eq!(state.threads.current_tid(), PRIMARY_THREAD_ID);
    }

    #[test]
    fn test_interlocked_ops_host_atomics() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        let cell = 0x4000_u64;
        // Zero cell.
        engine.mem_write(cell, &0_i32.to_le_bytes()).expect("zero");

        // Increment → 1
        write_regs(&mut engine, cell, 0, 0, 0, 0);
        let r = kernel32::dispatch_kernel32_extra(
            &mut engine,
            default_env(),
            &mut state,
            "InterlockedIncrement",
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(rax_low_i32(r.return_value), 1);

        // ExchangeAdd(+5) returns previous 1, cell becomes 6
        write_regs(&mut engine, cell, 5, 0, 0, 0);
        let r = kernel32::dispatch_kernel32_extra(
            &mut engine,
            default_env(),
            &mut state,
            "InterlockedExchangeAdd",
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(rax_low_i32(r.return_value), 1);

        // CompareExchange success 6→99
        write_regs(&mut engine, cell, 99, 6, 0, 0);
        let r = kernel32::dispatch_kernel32_extra(
            &mut engine,
            default_env(),
            &mut state,
            "InterlockedCompareExchange",
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(rax_low_i32(r.return_value), 6);

        // CompareExchange fail (expect 6, still 99)
        write_regs(&mut engine, cell, 1, 6, 0, 0);
        let r = kernel32::dispatch_kernel32_extra(
            &mut engine,
            default_env(),
            &mut state,
            "InterlockedCompareExchange",
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(rax_low_i32(r.return_value), 99);

        let mut bytes = [0_u8; 4];
        engine.mem_read(cell, &mut bytes).expect("read");
        assert_eq!(i32::from_le_bytes(bytes), 99);

        // 64-bit Increment64
        let cell64 = 0x4010_u64;
        engine
            .mem_write(cell64, &10_i64.to_le_bytes())
            .expect("zero64");
        write_regs(&mut engine, cell64, 0, 0, 0, 0);
        let r = kernel32::dispatch_kernel32_extra(
            &mut engine,
            default_env(),
            &mut state,
            "InterlockedIncrement64",
        )
        .expect("dispatch")
        .expect("handled");
        assert_eq!(i64::from_le_bytes(r.return_value.to_le_bytes()), 11);
    }

    #[test]
    fn test_free_library_valid_handle() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        write_regs(&mut engine, 0x6100_0001, 0, 0, 0, 0);
        assert_return_value!(kernel32::handle_free_library(&mut engine, &mut state), 1);
        assert_eq!(state.last_error, 0);
    }

    #[test]
    fn test_free_library_null_handle() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        write_regs(&mut engine, 0, 0, 0, 0, 0);
        assert_return_value!(kernel32::handle_free_library(&mut engine, &mut state), 0);
        assert_eq!(state.last_error, 6); // ERROR_INVALID_HANDLE
    }

    #[test]
    fn test_get_last_error() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        state.last_error = 123;
        let r = kernel32::handle_get_last_error(&mut engine, &state).expect("GetLastError");
        assert_eq!(r.return_value, 123);
    }

    #[test]
    fn test_set_last_error() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        state.last_error = 0;
        write_regs(&mut engine, 456, 0, 0, 0, 0);
        let _ = kernel32::handle_set_last_error(&mut engine, &mut state).expect("SetLastError");
        assert_eq!(state.last_error, 456);
    }

    #[test]
    fn test_heap_free_double_free_returns_false() {
        let mut engine = test_engine();
        let mut state = winapi_state_default();
        let p = state.heap.alloc(64);
        assert_ne!(p, 0);

        write_regs(&mut engine, 0x1, 0, p, 0, 0);
        let r = kernel32::handle_heap_free(&mut engine, &mut state).expect("HeapFree");
        assert_eq!(r.return_value, 1, "first free must succeed");

        state.last_error = 0;
        write_regs(&mut engine, 0x1, 0, p, 0, 0);
        let r = kernel32::handle_heap_free(&mut engine, &mut state).expect("HeapFree double");
        assert_eq!(r.return_value, 0, "double free must return FALSE");
        assert_eq!(state.last_error, 6, "ERROR_INVALID_HANDLE");
    }

    // --- User32 ---

    #[test]
    fn test_get_async_key_state_default() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        // VK_RETURN = 0x0D, keyboard_state starts all zero.
        write_regs(&mut engine, 0x0D, 0, 0, 0, 0);
        assert_return_value!(
            user32::handle_get_async_key_state(&mut engine, &mut state),
            0
        );
    }

    #[test]
    fn test_get_async_key_state_down() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        state.keyboard_state[0x0D] = 0x80; // VK_RETURN high bit set
        write_regs(&mut engine, 0x0D, 0, 0, 0, 0);
        assert_return_value!(
            user32::handle_get_async_key_state(&mut engine, &mut state),
            0x81
        );
    }

    #[test]
    fn test_peek_message_a_empty_queue() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        // Write a valid MSG struct address (doesn't matter since queue is empty).
        write_regs(&mut engine, 0x1000, 0, 0, 0, 0x2000);
        assert_return_value!(user32::handle_peek_message_a(&mut engine, &mut state), 0);
    }

    #[test]
    fn test_peek_message_a_with_message() {
        use crate::QueuedWindowMessage;
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        let msg_va = 0x4000;
        // Map memory for the MSG struct.
        engine.mem_map(msg_va, 0x1000, 7).expect("map msg struct");
        // Push a WM_PAINT message for any window.
        state.message_queue.push(QueuedWindowMessage {
            window_handle: 0x100,
            message: 15, // WM_PAINT
            word_parameter: 0,
            long_parameter: 0,
            time: 1,
            point_x: 0,
            point_y: 0,
        });
        // PeekMessageA(msg_ptr=msg_va, hwnd=0, min=0, max=0, wRemoveMsg=1)
        // wRemoveMsg is on the stack at RSP+0x28.
        write_regs(&mut engine, msg_va, 0, 0, 0, 0x3000);
        // Write wRemoveMsg=1 (PM_REMOVE) at RSP+0x28.
        engine.mem_write(0x3028, &1_u32.to_le_bytes()).ok();
        assert_return_value!(user32::handle_peek_message_a(&mut engine, &mut state), 1);
        // WM_PAINT should have been removed from the queue.
        assert_eq!(state.message_queue.len(), 0);
    }

    #[test]
    fn test_peek_message_a_noremove() {
        use crate::QueuedWindowMessage;
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        let msg_va = 0x4000;
        engine.mem_map(msg_va, 0x1000, 7).expect("map msg struct");
        state.message_queue.push(QueuedWindowMessage {
            window_handle: 0x100,
            message: 15,
            word_parameter: 0,
            long_parameter: 0,
            time: 1,
            point_x: 0,
            point_y: 0,
        });
        write_regs(&mut engine, msg_va, 0, 0, 0, 0x3000);
        // wRemoveMsg=0 (PM_NOREMOVE) at RSP+0x28.
        engine.mem_write(0x3028, &0_u32.to_le_bytes()).ok();
        assert_return_value!(user32::handle_peek_message_a(&mut engine, &mut state), 1);
        // Message should still be in the queue.
        assert_eq!(state.message_queue.len(), 1);
    }

    // --- Comctl32 ---

    #[test]
    fn test_init_common_controls() {
        let mut engine = test_engine();
        assert_return_value!(comctl32::handle_init_common_controls(&mut engine), 1);
    }

    // --- Comdlg32 ---

    #[test]
    fn test_choose_color_a_writes_color() {
        let mut engine = test_engine();
        let mut state = default_winapi_state();
        let cc_ptr = 0x5000;
        engine.mem_map(cc_ptr, 0x1000, 7).expect("map CHOOSECOLOR");
        write_regs(&mut engine, cc_ptr, 0, 0, 0, 0);
        assert_return_value!(comdlg32::handle_choose_color_a(&mut engine, &mut state), 1);
        // rgbResult is at offset 0x10 in CHOOSECOLOR — should be RGB black (0).
        let mut rgb = [0_u8; 4];
        engine.mem_read(cc_ptr + 0x10, &mut rgb).ok();
        assert_eq!(u32::from_le_bytes(rgb), 0x00_00_00);
    }

    // --- Gdi32 ---

    #[test]
    fn test_text_out_a_returns_cch() {
        let mut engine = test_engine();
        write_regs(&mut engine, 0x100, 10, 20, 0x2000, 0x3000);
        // cchString at RSP+0x28 = 5.
        engine.mem_write(0x3028, &5_u32.to_le_bytes()).ok();
        assert_return_value!(gdi32::handle_text_out_a(&mut engine), 5);
    }

    #[test]
    fn test_bit_blt_success() {
        let mut engine = test_engine();
        write_regs(&mut engine, 0x100, 0, 0, 100, 0);
        assert_return_value!(gdi32::handle_bit_blt(&mut engine), 1);
    }

    #[test]
    fn test_stretch_blt_success() {
        let mut engine = test_engine();
        write_regs(&mut engine, 0x100, 0, 0, 100, 0);
        assert_return_value!(gdi32::handle_stretch_blt(&mut engine), 1);
    }

    #[test]
    fn test_pat_blt_success() {
        let mut engine = test_engine();
        write_regs(&mut engine, 0x100, 0, 0, 100, 0);
        assert_return_value!(gdi32::handle_pat_blt(&mut engine), 1);
    }

    // --- Advapi32 ---

    #[test]
    fn test_set_security_descriptor_dacl_null_fails() {
        let mut engine = test_engine();
        write_regs(&mut engine, 0, 0, 0, 0, 0);
        assert_return_value!(
            advapi32::handle_set_security_descriptor_dacl(&mut engine),
            0
        );
    }

    #[test]
    fn test_set_security_descriptor_dacl_valid_succeeds() {
        let mut engine = test_engine();
        write_regs(&mut engine, 0x1000, 1, 0x2000, 1, 0);
        assert_return_value!(
            advapi32::handle_set_security_descriptor_dacl(&mut engine),
            1
        );
    }
}
