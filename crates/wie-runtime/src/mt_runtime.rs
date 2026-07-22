//! Process execution states, encoded in the type system.
//!
//! The state is determined once at construction: JIT gets per-thread engines,
//! Iced gets a shared engine behind a mutex. WinAPI is always behind an
//! `Arc<Mutex<>>` so there is no `Local` intermediate state.

use crate::hooks::{SoftApiTable, resolve_fake_api_at};
use crate::memory::RuntimeMemoryLayout;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use wie_cpu::JitCpu;
use wie_winapi::{HostParkReason, PendingSpawn, WinApiControlSignal, WinApiState};
use wie_winapi::kernel32::{resolve_cs_queue, resolve_wait_target};

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ── Shared: join_workers is identical for both JIT and Iced ───────────

fn join_workers_impl(winapi: &Arc<Mutex<WinApiState>>, joins: &mut Vec<JoinHandle<()>>) {
    {
        let mut st = lock(winapi);
        st.sync.process_dying = true;
        for q in st.sync.cs_waiters.values() { q.notify_all(); }
        for obj in st.sync.objects.values() {
            match obj {
                wie_winapi::KernelObject::Event(e) => e.set(),
                wie_winapi::KernelObject::Semaphore(s) => s.notify_all(),
                wie_winapi::KernelObject::Thread(t) => { if !t.is_finished() { t.finish(1); } }
            }
        }
    }
    for j in joins.drain(..) { let _ = j.join(); }
}

// ── Shared config (present in every state) ────────────────────────────

#[derive(Clone)]
pub(crate) struct ProcessConfig {
    pub soft_apis: SoftApiTable,
    pub environment: wie_winapi::WinApiEnvironment,
    pub layout: RuntimeMemoryLayout,
    pub stop_bitmap: Vec<u8>,
    pub primary_tid: u32,
}

// ── Guard: temporary exclusive access to engine + winapi ──────────────

pub(crate) enum ProcessGuard<'a> {
    Jit {
        eng: &'a mut dyn wie_cpu::CpuEngine,
        win: std::sync::MutexGuard<'a, WinApiState>,
    },
    Iced {
        eng: &'a mut dyn wie_cpu::CpuEngine,
        win: std::sync::MutexGuard<'a, WinApiState>,
    },
}

impl ProcessGuard<'_> {
    pub(crate) fn both(&mut self) -> (&mut dyn wie_cpu::CpuEngine, &mut WinApiState) {
        match self {
            Self::Jit { eng, win } => (*eng, &mut *win),
            Self::Iced { eng, win } => (*eng, &mut *win),
        }
    }
}

// ── JitState: per-thread engines, shared WinAPI ───────────────────────

pub(crate) struct JitState {
    pub config: ProcessConfig,
    pub engine: Box<dyn wie_cpu::CpuEngine>,
    pub shared_jit: Arc<wie_cpu::JitShared>,
    pub shared_winapi: Arc<Mutex<WinApiState>>,
    pub worker_joins: Vec<JoinHandle<()>>,
}

impl JitState {
    fn lock_pair(&mut self) -> ProcessGuard<'_> {
        ProcessGuard::Jit {
            eng: &mut *self.engine,
            win: self.shared_winapi.lock().unwrap_or_else(|p| p.into_inner()),
        }
    }

    pub(crate) fn with_mut<R>(
        &mut self,
        f: impl FnOnce(&mut dyn wie_cpu::CpuEngine, &mut WinApiState) -> R,
    ) -> R {
        let mut guard = self.lock_pair();
        let (e, w) = guard.both();
        f(e, w)
    }

    pub(crate) fn with_winapi_ref<R>(&self, f: impl FnOnce(&WinApiState) -> R) -> R {
        f(&lock(&self.shared_winapi))
    }

    pub(crate) fn drain_spawns(&mut self) -> Result<()> {
        let spawns: Vec<PendingSpawn> = self.with_mut(|_, st| {
            st.sync.pending_spawns.drain(..).collect()
        });
        if spawns.is_empty() {
            return Ok(());
        }
        let shared_winapi = Arc::clone(&self.shared_winapi);
        let soft = self.config.soft_apis.clone();
        let env = self.config.environment;
        let layout = self.config.layout;
        let stop_bitmap = self.config.stop_bitmap.clone();
        let shared_jit = Arc::clone(&self.shared_jit);

        for spawn in spawns {
            let jit = Arc::clone(&shared_jit);
            let winapi = Arc::clone(&shared_winapi);
            let soft = soft.clone();
            let stop_bitmap = stop_bitmap.clone();
            const STACK: usize = 8 * 1024 * 1024;
            let handle = std::thread::Builder::new()
                .name(format!("wie-guest-{}", spawn.tid))
                .stack_size(STACK)
                .spawn(move || jit_worker_main(jit, winapi, soft, env, layout, spawn.tid, stop_bitmap))
                .context("failed to spawn guest worker")?;
            self.worker_joins.push(handle);
        }
        Ok(())
    }

    pub(crate) fn join_workers(&mut self) {
        join_workers_impl(&self.shared_winapi, &mut self.worker_joins);
    }
}

// ── IcedState: per-thread engines, shared WinAPI ──────────────────────

pub(crate) struct IcedState {
    pub config: ProcessConfig,
    pub engine: Box<dyn wie_cpu::CpuEngine>,  // primary's per-thread engine
    pub shared_winapi: Arc<Mutex<WinApiState>>,
    pub worker_joins: Vec<JoinHandle<()>>,
}

impl IcedState {
    fn lock_pair(&mut self) -> ProcessGuard<'_> {
        ProcessGuard::Iced {
            eng: &mut *self.engine,
            win: lock(&self.shared_winapi),
        }
    }

    pub(crate) fn with_mut<R>(
        &mut self,
        f: impl FnOnce(&mut dyn wie_cpu::CpuEngine, &mut WinApiState) -> R,
    ) -> R {
        let mut guard = self.lock_pair();
        let (e, w) = guard.both();
        f(e, w)
    }

    pub(crate) fn with_winapi_ref<R>(&self, f: impl FnOnce(&WinApiState) -> R) -> R {
        f(&lock(&self.shared_winapi))
    }

    pub(crate) fn drain_spawns(&mut self) -> Result<()> {
        let spawns: Vec<PendingSpawn> = self.with_mut(|_, st| {
            st.sync.pending_spawns.drain(..).collect()
        });
        if spawns.is_empty() {
            return Ok(());
        }
        let shared_winapi = Arc::clone(&self.shared_winapi);
        let soft = self.config.soft_apis.clone();
        let env = self.config.environment;
        let layout = self.config.layout;
        let stop_bitmap = self.config.stop_bitmap.clone();

        // Create per-thread IcedCpu engines sharing the primary's GuestMemory.
        // SAFETY: engine is always IcedCpu in this state.
        let primary_iced = unsafe {
            &*(&*self.engine as *const dyn wie_cpu::CpuEngine as *const wie_cpu::IcedCpu)
        };

        for spawn in spawns {
            let engine: Box<dyn wie_cpu::CpuEngine> = Box::new(wie_cpu::IcedCpu::new_shared(primary_iced));
            let winapi = Arc::clone(&shared_winapi);
            let s = soft.clone();
            let b = stop_bitmap.clone();
            const STACK: usize = 8 * 1024 * 1024;
            let handle = std::thread::Builder::new()
                .name(format!("wie-guest-{}", spawn.tid))
                .stack_size(STACK)
                .spawn(move || iced_worker_main(engine, winapi, s, env, layout, spawn.tid, b))
                .context("failed to spawn guest worker")?;
            self.worker_joins.push(handle);
        }
        Ok(())
    }

    pub(crate) fn join_workers(&mut self) {
        join_workers_impl(&self.shared_winapi, &mut self.worker_joins);
    }
}

// ── ProcessState: JIT vs Iced, determined at construction ─────────────

pub(crate) enum ProcessState {
    Jit(JitState),
    Iced(IcedState),
}

impl ProcessState {
    pub(crate) fn lock_pair(&mut self) -> ProcessGuard<'_> {
        match self {
            Self::Jit(s) => s.lock_pair(),
            Self::Iced(s) => s.lock_pair(),
        }
    }

    pub(crate) fn with_mut<R>(
        &mut self,
        f: impl FnOnce(&mut dyn wie_cpu::CpuEngine, &mut WinApiState) -> R,
    ) -> R {
        match self {
            Self::Jit(s) => s.with_mut(f),
            Self::Iced(s) => s.with_mut(f),
        }
    }

    pub(crate) fn with_winapi_ref<R>(&self, f: impl FnOnce(&WinApiState) -> R) -> R {
        match self {
            Self::Jit(s) => s.with_winapi_ref(f),
            Self::Iced(s) => s.with_winapi_ref(f),
        }
    }

    pub(crate) fn config(&self) -> &ProcessConfig {
        match self {
            Self::Jit(s) => &s.config,
            Self::Iced(s) => &s.config,
        }
    }
    pub(crate) fn layout(&self) -> &RuntimeMemoryLayout { &self.config().layout }
    pub(crate) fn environment(&self) -> &wie_winapi::WinApiEnvironment { &self.config().environment }
    pub(crate) fn soft_apis(&self) -> &SoftApiTable { &self.config().soft_apis }
    pub(crate) fn primary_tid(&self) -> u32 { self.config().primary_tid }

    pub(crate) fn drain_spawns(&mut self) -> Result<()> {
        match self {
            Self::Jit(s) => s.drain_spawns(),
            Self::Iced(s) => s.drain_spawns(),
        }
    }

    pub(crate) fn join_workers(&mut self) {
        match self {
            Self::Jit(s) => s.join_workers(),
            Self::Iced(s) => s.join_workers(),
        }
    }
}

// ── Worker threads ────────────────────────────────────────────────────

fn jit_worker_main(
    shared_jit: Arc<wie_cpu::JitShared>,
    shared_winapi: Arc<Mutex<WinApiState>>,
    soft_apis: SoftApiTable,
    environment: wie_winapi::WinApiEnvironment,
    layout: RuntimeMemoryLayout,
    tid: u32,
    stop_bitmap: Vec<u8>,
) {
    let budget = layout.instruction_budget;
    let fake_api_end = layout
        .fake_api_base
        .saturating_add(u64::try_from(layout.fake_api_size).unwrap_or(0))
        .saturating_sub(1);

    let mut engine: Box<dyn wie_cpu::CpuEngine> =
        Box::new(JitCpu::new_shared(shared_jit));

    let _ = engine.install_runtime_hooks(layout.fake_api_base, fake_api_end, stop_bitmap);

    // Load initial thread context set by CreateThread.
    {
        let st = lock(&shared_winapi);
        if let Some(ctx) = st.sync.thread_cpu.get(&tid).cloned() {
            drop(st);
            engine.restore_thread_context(&ctx);
            engine.on_thread_switch();
        }
    }

    loop {
        let park_reason: Option<HostParkReason>;
        {
            let mut st = lock(&shared_winapi);
            if st.sync.process_dying { finish_tid(&st, tid, 1); return; }

            let begin = engine.read_rip().unwrap_or(0);
            if begin == 0 {
                let code = u32::try_from(engine.read_rax().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code); return;
            }

            let hook = match engine.run_until_stop(begin, 0, 0, budget, layout.fake_api_base, fake_api_end) {
                Ok(r) if r.code.hit => r.code,
                Ok(_) => { std::thread::yield_now(); continue; }
                Err(_) => { finish_tid(&st, tid, 1); return; }
            };

            if hook.address == layout.callback_return_trampoline_va { continue; }

            let Some(resolved) = resolve_fake_api_at(hook.address, &soft_apis) else {
                finish_tid(&st, tid, 1); return;
            };
            if resolved.traits.exit_process() {
                st.sync.process_dying = true;
                let code = u32::try_from(engine.read_rcx().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code); return;
            }

            let dispatch = if let Some(id) = resolved.winapi_id {
                wie_winapi::dispatch_winapi_id(&mut *engine, environment, &mut st, id)
            } else {
                wie_winapi::dispatch_winapi(&mut *engine, environment, &mut st, &resolved.library, &resolved.name)
            };

            match dispatch {
                Ok(_) => park_reason = None,
                Err(e) => {
                    if let Some(WinApiControlSignal::ExitThread { code }) = e.downcast_ref() {
                        finish_tid(&st, tid, *code); return;
                    }
                    if let Some(WinApiControlSignal::HostPark { reason }) = e.downcast_ref() {
                        park_reason = Some(*reason);
                    } else {
                        finish_tid(&st, tid, 1); return;
                    }
                }
            }
        } // drop WinAPI lock

        if let Some(reason) = park_reason { handle_park_jit(&mut engine, &shared_winapi, tid, reason); }
    }
}

fn iced_worker_main(
    mut engine: Box<dyn wie_cpu::CpuEngine>,
    shared_winapi: Arc<Mutex<WinApiState>>,
    soft_apis: SoftApiTable,
    environment: wie_winapi::WinApiEnvironment,
    layout: RuntimeMemoryLayout,
    tid: u32,
    stop_bitmap: Vec<u8>,
) {
    let budget = layout.instruction_budget;
    let fake_api_end = layout
        .fake_api_base
        .saturating_add(u64::try_from(layout.fake_api_size).unwrap_or(0))
        .saturating_sub(1);

    // Install runtime hooks so the engine can stop on fake API calls.
    let _ = engine.install_runtime_hooks(layout.fake_api_base, fake_api_end, stop_bitmap);

    // Load initial thread context set by CreateThread.
    {
        let st = lock(&shared_winapi);
        if let Some(ctx) = st.sync.thread_cpu.get(&tid).cloned() {
            drop(st);
            engine.restore_thread_context(&ctx);
            engine.on_thread_switch();
        }
    }

    loop {
        let park_reason: Option<HostParkReason>;
        {
            let mut st = lock(&shared_winapi);
            if st.sync.process_dying { finish_tid(&st, tid, 1); return; }

            let begin = engine.read_rip().unwrap_or(0);
            if begin == 0 {
                let code = u32::try_from(engine.read_rax().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code); return;
            }

            let hook = match engine.run_until_stop(begin, 0, 0, budget, layout.fake_api_base, fake_api_end) {
                Ok(r) if r.code.hit => r.code,
                Ok(_) => { std::thread::yield_now(); continue; }
                Err(_) => { finish_tid(&st, tid, 1); return; }
            };

            if hook.address == layout.callback_return_trampoline_va { continue; }

            let Some(resolved) = resolve_fake_api_at(hook.address, &soft_apis) else {
                finish_tid(&st, tid, 1); return;
            };
            if resolved.traits.exit_process() {
                st.sync.process_dying = true;
                let code = u32::try_from(engine.read_rcx().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code); return;
            }

            let dispatch = if let Some(id) = resolved.winapi_id {
                wie_winapi::dispatch_winapi_id(&mut *engine, environment, &mut st, id)
            } else {
                wie_winapi::dispatch_winapi(&mut *engine, environment, &mut st, &resolved.library, &resolved.name)
            };

            match dispatch {
                Ok(_) => park_reason = None,
                Err(e) => {
                    if let Some(WinApiControlSignal::ExitThread { code }) = e.downcast_ref() {
                        finish_tid(&st, tid, *code); return;
                    }
                    if let Some(WinApiControlSignal::HostPark { reason }) = e.downcast_ref() {
                        park_reason = Some(*reason);
                    } else {
                        finish_tid(&st, tid, 1); return;
                    }
                }
            }
        } // drop WinAPI lock

        if let Some(reason) = park_reason { handle_park_jit(&mut engine, &shared_winapi, tid, reason); }
    }
}

fn handle_park_jit(
    engine: &mut Box<dyn wie_cpu::CpuEngine>,
    shared_winapi: &Arc<Mutex<WinApiState>>,
    tid: u32,
    reason: HostParkReason,
) {
    match reason {
        HostParkReason::CriticalSection { cs } => {
            let q = {
                let mut st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                resolve_cs_queue(&mut st, cs)
            };
            q.park_brief();
        }
        HostParkReason::WaitObject { handle, timeout_ms } => {
            let target = {
                let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                resolve_wait_target(&st, handle)
            };
            let result = wait_on_target(target, timeout_ms, shared_winapi, tid);
            let st = lock(shared_winapi);
            if st.sync.process_dying { finish_tid(&st, tid, 1); return; }
            engine.return_from_win64_api(u64::from(result))
                .expect("return_from_win64_api: guest stack corrupted");
        }
        HostParkReason::WaitMultiple => {
            let req = {
                let mut st = lock(shared_winapi);
                st.sync.multi_wait.remove(&tid)
            };
            let result = wait_multiple_result(req, shared_winapi, tid);
            let st = lock(shared_winapi);
            if st.sync.process_dying { finish_tid(&st, tid, 1); return; }
            engine.return_from_win64_api(u64::from(result))
                .expect("return_from_win64_api: guest stack corrupted");
        }
    }
}

// ── Common helpers ────────────────────────────────────────────────────

fn finish_tid(st: &WinApiState, tid: u32, code: u32) {
    for obj in st.sync.objects.values() {
        if let wie_winapi::KernelObject::Thread(t) = obj && t.tid == tid {
            t.finish(code); return;
        }
    }
}

fn wait_on_target(
    target: Option<wie_winapi::WaitTarget>,
    timeout_ms: u32,
    shared_winapi: &Arc<Mutex<WinApiState>>,
    tid: u32,
) -> u32 {
    match target {
        Some(t) => {
            if timeout_ms == wie_winapi::INFINITE {
                loop {
                    let r = t.wait(50);
                    if r == wie_winapi::WAIT_OBJECT_0 { return r; }
                    let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                    if st.sync.process_dying { finish_tid(&st, tid, 1); return wie_winapi::WAIT_FAILED; }
                }
            } else {
                t.wait(timeout_ms)
            }
        }
        None => wie_winapi::WAIT_FAILED,
    }
}

fn wait_multiple_result(
    req: Option<wie_winapi::MultiWaitRequest>,
    shared_winapi: &Arc<Mutex<WinApiState>>,
    tid: u32,
) -> u32 {
    let Some(req) = req else { return wie_winapi::WAIT_FAILED };
    let targets = {
        let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
        st.sync.wait_targets(&req.handles)
    };
    let Some(ts) = targets else { return wie_winapi::WAIT_FAILED };

    if req.timeout_ms == wie_winapi::INFINITE {
        loop {
            let r = wie_winapi::wait_multiple(&ts, req.wait_all, 50);
            if r != wie_winapi::WAIT_TIMEOUT { return r; }
            let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
            if st.sync.process_dying { finish_tid(&st, tid, 1); return wie_winapi::WAIT_FAILED; }
        }
    } else {
        wie_winapi::wait_multiple(&ts, req.wait_all, req.timeout_ms)
    }
}

/// Save active thread CPU into sync table.
pub(crate) fn save_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    tid: u32,
) {
    let ctx = engine.snapshot_thread_context();
    state.sync.thread_cpu.insert(tid, ctx);
    state.threads.save_active();
}

/// Restore active thread CPU from sync table.
pub(crate) fn load_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut WinApiState,
    tid: u32,
) {
    state.threads.activate(tid);
    if let Some(ctx) = state.sync.thread_cpu.get(&tid).cloned() {
        engine.restore_thread_context(&ctx);
        engine.on_thread_switch();
    }
}
