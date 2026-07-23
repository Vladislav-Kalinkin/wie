//! Process execution state: single `ProcessResources` for both JIT and Iced.
//!
//! Per-thread engines: each guest thread runs on its own `CpuEngine` instance.
//! JIT workers share `Arc<JitShared>` (compilation cache). Iced workers share
//! `Arc<RwLock<GuestMemory>>` extracted from the primary `IcedCpu` and passed to
//! workers at spawn time. WinAPI is always behind `Arc<Mutex<>>`.

use crate::hooks::{SoftApiTable, resolve_fake_api_at};
use crate::memory::RuntimeMemoryLayout;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::thread::JoinHandle;
use wie_cpu::{CpuEngine, GuestMemory, IcedCpu, JitCpu};
use wie_winapi::kernel32::{resolve_cs_queue, resolve_wait_target};
use wie_winapi::{HostParkReason, PendingSpawn, WinApiControlSignal, WinApiState};

// ── Lock helpers ───────────────────────────────────────────────────────

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

// ── Shared config ──────────────────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct ProcessConfig {
    pub soft_apis: SoftApiTable,
    pub environment: wie_winapi::WinApiEnvironment,
    pub layout: RuntimeMemoryLayout,
    pub stop_bitmap: Vec<u8>,
    pub primary_tid: u32,
}

// ── ProcessResources: single struct for both JIT and Iced ──────────────

pub(crate) struct ProcessResources {
    pub config: ProcessConfig,
    pub engine: Box<dyn CpuEngine>,
    /// `Some` when the JIT backend is active; workers clone this to share
    /// the compilation cache. `None` for the Iced interpreter backend.
    pub shared_jit: Option<Arc<wie_cpu::JitShared>>,
    /// `Some` when the Iced backend is active; workers clone this to share
    /// guest memory (mmap arenas + page tables). `None` for JIT.
    pub guest_mem: Option<Arc<RwLock<GuestMemory>>>,
    pub shared_winapi: Arc<Mutex<WinApiState>>,
    pub worker_joins: Vec<JoinHandle<()>>,
}

/// Temporary exclusive access to engine + WinAPI.
pub(crate) struct ProcessGuard<'a> {
    pub eng: &'a mut dyn CpuEngine,
    pub win: MutexGuard<'a, WinApiState>,
}

impl ProcessGuard<'_> {
    pub(crate) fn both(&mut self) -> (&mut dyn CpuEngine, &mut WinApiState) {
        (&mut *self.eng, &mut *self.win)
    }
}

impl ProcessResources {
    pub(crate) fn lock_pair(&mut self) -> ProcessGuard<'_> {
        ProcessGuard {
            eng: &mut *self.engine,
            win: lock(&self.shared_winapi),
        }
    }

    pub(crate) fn with_mut<R>(
        &mut self,
        f: impl FnOnce(&mut dyn CpuEngine, &mut WinApiState) -> R,
    ) -> R {
        let mut guard = self.lock_pair();
        let (e, w) = guard.both();
        f(e, w)
    }

    pub(crate) fn with_winapi_ref<R>(&self, f: impl FnOnce(&WinApiState) -> R) -> R {
        f(&lock(&self.shared_winapi))
    }

    pub(crate) fn layout(&self) -> &RuntimeMemoryLayout {
        &self.config.layout
    }
    pub(crate) fn environment(&self) -> &wie_winapi::WinApiEnvironment {
        &self.config.environment
    }
    pub(crate) fn soft_apis(&self) -> &SoftApiTable {
        &self.config.soft_apis
    }
    pub(crate) fn primary_tid(&self) -> u32 {
        self.config.primary_tid
    }

    pub(crate) fn join_workers(&mut self) {
        join_workers_impl(&self.shared_winapi, &mut self.worker_joins);
    }

    /// Spawn a host thread for each pending `CreateThread` spawn.
    pub(crate) fn drain_spawns(&mut self) -> Result<()> {
        let spawns: Vec<PendingSpawn> =
            self.with_mut(|_, st| st.sync.pending_spawns.drain(..).collect());
        if spawns.is_empty() {
            return Ok(());
        }
        if std::env::var_os("WIE_MT_DEBUG").is_some() {
            eprintln!(
                "[mt] drain_spawns count={} tids={:?}",
                spawns.len(),
                spawns.iter().map(|s| format!("{:#x}", s.tid)).collect::<Vec<_>>()
            );
        }
        let shared_winapi = Arc::clone(&self.shared_winapi);
        let config = Arc::new(self.config.clone());
        let shared_jit = self.shared_jit.clone();
        let guest_mem = self.guest_mem.clone();

        for spawn in spawns {
            let engine: Box<dyn CpuEngine> = if let Some(ref jit) = shared_jit {
                Box::new(JitCpu::new_shared(Arc::clone(jit)))
            } else if let Some(ref mem) = guest_mem {
                let temp = IcedCpu::new_standalone_with_mem(Arc::clone(mem));
                Box::new(IcedCpu::new_shared(&temp))
            } else {
                anyhow::bail!("no shared memory for worker spawn")
            };
            let winapi = Arc::clone(&shared_winapi);
            let cfg = Arc::clone(&config);
            const STACK: usize = 8 * 1024 * 1024;
            let handle = std::thread::Builder::new()
                .name(format!("wie-guest-{}", spawn.tid))
                .stack_size(STACK)
                .spawn(move || worker_main(engine, winapi, cfg, spawn.tid))
                .context("failed to spawn guest worker")?;
            self.worker_joins.push(handle);
        }
        Ok(())
    }
}

// ── Join workers ───────────────────────────────────────────────────────

fn join_workers_impl(winapi: &Arc<Mutex<WinApiState>>, joins: &mut Vec<JoinHandle<()>>) {
    {
        let mut st = lock(winapi);
        st.sync.process_dying = true;
        for q in st.sync.cs_waiters.values() {
            q.notify_all();
        }
        for obj in st.sync.objects.values() {
            match obj {
                wie_winapi::KernelObject::Event(e) => e.set(),
                wie_winapi::KernelObject::Semaphore(s) => s.notify_all(),
                wie_winapi::KernelObject::Thread(t) => {
                    if !t.is_finished() {
                        t.finish(1);
                    }
                }
            }
        }
    }
    for j in joins.drain(..) {
        let _ = j.join();
    }
}

// ── Single worker main (JIT and Iced) ──────────────────────────────────

fn worker_main(
    mut engine: Box<dyn CpuEngine>,
    shared_winapi: Arc<Mutex<WinApiState>>,
    config: Arc<ProcessConfig>,
    tid: u32,
) {
    if std::env::var_os("WIE_MT_DEBUG").is_some() {
        eprintln!("[mt] worker_main start tid={tid:#x}");
    }
    let layout = &config.layout;
    let budget = layout.instruction_budget;
    let fake_api_end = layout
        .fake_api_base
        .saturating_add(u64::try_from(layout.fake_api_size).unwrap_or(0))
        .saturating_sub(1);

    if let Err(e) = engine.install_runtime_hooks(
        layout.fake_api_base,
        fake_api_end,
        config.stop_bitmap.clone(),
    ) {
        tracing::error!(tid, error = %e, "failed to install runtime hooks for worker");
        if std::env::var_os("WIE_MT_DEBUG").is_some() {
            eprintln!("[mt] worker_main hooks failed tid={tid:#x}: {e}");
        }
        // Always mark finished so joiners do not hang forever.
        let st = lock(&shared_winapi);
        finish_tid(&st, tid, 1);
        return;
    }

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
        // Activate + liveness under WinAPI lock only — do **not** hold the lock
        // across pure guest execution (per-thread engines need concurrent quanta).
        {
            let mut st = lock(&shared_winapi);
            st.threads.activate(tid);
            if st.sync.process_dying {
                finish_tid(&st, tid, 1);
                return;
            }
        }

        let begin = engine.read_rip().unwrap_or(0);
        if begin == 0 {
            let code = u32::try_from(engine.read_rax().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
            let st = lock(&shared_winapi);
            finish_tid(&st, tid, code);
            return;
        }

        // Guest compute / iced / JIT: no shared WinAPI mutex.
        let hook = match engine.run_until_stop(
            begin,
            0,
            0,
            budget,
            layout.fake_api_base,
            fake_api_end,
        ) {
            Ok(r) if r.code.hit => r.code,
            Ok(_) => {
                std::thread::yield_now();
                continue;
            }
            Err(_) => {
                let st = lock(&shared_winapi);
                finish_tid(&st, tid, 1);
                return;
            }
        };

        if hook.address == layout.callback_return_trampoline_va {
            continue;
        }

        // SEH / C++ EH continuation trampoline (primary path is session.rs; workers
        // can hit it if a throw originated on that thread).
        if hook.address == wie_winapi::seh_continue_trampoline_va() {
            let mut st = lock(&shared_winapi);
            // Always re-activate: peer threads may have stolen `active` while we
            // ran pure guest code without the WinAPI lock.
            st.threads.activate(tid);
            if let Err(e) = wie_winapi::seh::continue_pending(&mut *engine, &mut st) {
                tracing::warn!(tid, error = %e, "worker SEH continue failed");
                finish_tid(&st, tid, 1);
                return;
            }
            continue;
        }

        let Some(resolved) = resolve_fake_api_at(hook.address, &config.soft_apis) else {
            let st = lock(&shared_winapi);
            finish_tid(&st, tid, 1);
            return;
        };

        let park_reason: Option<HostParkReason>;
        {
            let mut st = lock(&shared_winapi);
            // Re-activate after pure guest run (primary/peers may have activated).
            st.threads.activate(tid);
            if st.sync.process_dying {
                finish_tid(&st, tid, 1);
                return;
            }

            if resolved.traits.exit_process() {
                st.sync.process_dying = true;
                let code = u32::try_from(engine.read_rcx().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code);
                return;
            }

            let dispatch = if let Some(id) = resolved.winapi_id {
                wie_winapi::dispatch_winapi_id(&mut *engine, config.environment, &mut st, id)
            } else {
                wie_winapi::dispatch_winapi(
                    &mut *engine,
                    config.environment,
                    &mut st,
                    &resolved.library,
                    &resolved.name,
                )
            };

            match dispatch {
                Ok(_) => park_reason = None,
                Err(e) => {
                    if let Some(WinApiControlSignal::ExitThread { code }) = e.downcast_ref() {
                        finish_tid(&st, tid, *code);
                        return;
                    }
                    if let Some(WinApiControlSignal::HostPark { reason }) = e.downcast_ref() {
                        park_reason = Some(*reason);
                    } else {
                        finish_tid(&st, tid, 1);
                        return;
                    }
                }
            }
        } // drop WinAPI lock before host park

        if let Some(reason) = park_reason {
            handle_park(&mut engine, &shared_winapi, tid, reason);
        }
    }
}

fn handle_park(
    engine: &mut Box<dyn CpuEngine>,
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
            if st.sync.process_dying {
                finish_tid(&st, tid, 1);
                return;
            }
            let _ = engine
                .return_from_win64_api(u64::from(result))
                .map_err(|e| tracing::error!("guest stack corrupted on wait park: {e}"));
        }
        HostParkReason::WaitMultiple => {
            let req = {
                let mut st = lock(shared_winapi);
                st.sync.multi_wait.remove(&tid)
            };
            let result = wait_multiple_result(req, shared_winapi, tid);
            let st = lock(shared_winapi);
            if st.sync.process_dying {
                finish_tid(&st, tid, 1);
                return;
            }
            let _ = engine
                .return_from_win64_api(u64::from(result))
                .map_err(|e| tracing::error!("guest stack corrupted on wait multiple park: {e}"));
        }
    }
}

// ── Common helpers ────────────────────────────────────────────────────

fn finish_tid(st: &WinApiState, tid: u32, code: u32) {
    let thread = st
        .sync
        .objects
        .values()
        .find(|obj| matches!(obj, wie_winapi::KernelObject::Thread(t) if t.tid == tid));
    if let Some(wie_winapi::KernelObject::Thread(t)) = thread {
        t.finish(code);
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
                    if r == wie_winapi::WAIT_OBJECT_0 {
                        return r;
                    }
                    let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                    if st.sync.process_dying {
                        finish_tid(&st, tid, 1);
                        return wie_winapi::WAIT_FAILED;
                    }
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
    let Some(req) = req else {
        return wie_winapi::WAIT_FAILED;
    };
    let targets = {
        let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
        st.sync.wait_targets(&req.handles)
    };
    let Some(ts) = targets else {
        return wie_winapi::WAIT_FAILED;
    };

    if req.timeout_ms == wie_winapi::INFINITE {
        loop {
            let r = wie_winapi::wait_multiple(&ts, req.wait_all, 50);
            if r != wie_winapi::WAIT_TIMEOUT {
                return r;
            }
            let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
            if st.sync.process_dying {
                finish_tid(&st, tid, 1);
                return wie_winapi::WAIT_FAILED;
            }
        }
    } else {
        wie_winapi::wait_multiple(&ts, req.wait_all, req.timeout_ms)
    }
}
