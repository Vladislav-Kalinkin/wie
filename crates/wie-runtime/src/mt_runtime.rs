//! MT.2 / MT.3 process sharing: per-thread engines under shared WinAPI lock.
//!
//! Each guest thread gets its own `CpuEngine` (sharing a common `JitShared`
//! compilation cache). No engine mutex — only the WinAPI state is shared.

use crate::hooks::{SoftApiTable, resolve_fake_api_at};
use crate::memory::RuntimeMemoryLayout;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use wie_cpu::JitCpu;
use wie_winapi::{HostParkReason, PRIMARY_THREAD_ID, PendingSpawn, WinApiControlSignal};

/// Exclusive borrow of engine + WinAPI (local refs or mutex guards).
pub(crate) enum ProcessPairGuard<'a> {
    /// Single-thread exclusive ownership (engine + winapi both direct).
    Local {
        eng: &'a mut dyn wie_cpu::CpuEngine,
        win: &'a mut wie_winapi::WinApiState,
    },
    /// Multi-thread: engine is direct, winapi behind Mutex.
    Shared {
        eng: &'a mut dyn wie_cpu::CpuEngine,
        win: std::sync::MutexGuard<'a, wie_winapi::WinApiState>,
    },
}

impl ProcessPairGuard<'_> {
    /// Simultaneous exclusive access to both sides (primary run loop).
    #[inline]
    pub(crate) fn both(&mut self) -> (&mut dyn wie_cpu::CpuEngine, &mut wie_winapi::WinApiState) {
        match self {
            Self::Local { eng, win } => (*eng, *win),
            Self::Shared { eng, win } => (*eng, &mut *win),
        }
    }
}

/// Owns process resources: primary engine + optional shared WinAPI state.
pub(crate) struct ProcessResources {
    /// Primary thread's dedicated engine.
    pub engine: Box<dyn wie_cpu::CpuEngine>,
    /// Shared JIT compilation cache + guest memory (None before any CreateThread).
    pub shared_jit: Option<Arc<wie_cpu::JitShared>>,
    /// Exclusive WinAPI state (ST). `None` when moved into [`Self::shared_winapi`].
    local_winapi: Option<wie_winapi::WinApiState>,
    /// Shared WinAPI state after first `CreateThread`.
    shared_winapi: Option<Arc<Mutex<wie_winapi::WinApiState>>>,
    /// Soft API table (cloneable; shared by value with workers).
    pub soft_apis: SoftApiTable,
    pub environment: wie_winapi::WinApiEnvironment,
    pub layout: RuntimeMemoryLayout,
    /// Stop bitmap for fake-API hooks (reused by worker engines).
    pub stop_bitmap: Vec<u8>,
    /// Host join handles for workers.
    pub worker_joins: Vec<JoinHandle<()>>,
    /// Active guest TID on the primary host thread.
    pub primary_tid: u32,
}

impl ProcessResources {
    pub(crate) fn new(
        engine: Box<dyn wie_cpu::CpuEngine>,
        winapi: wie_winapi::WinApiState,
        soft_apis: SoftApiTable,
        environment: wie_winapi::WinApiEnvironment,
        layout: RuntimeMemoryLayout,
        stop_bitmap: Vec<u8>,
        shared_jit: Option<Arc<wie_cpu::JitShared>>,
    ) -> Self {
        Self {
            engine,
            shared_jit,
            local_winapi: Some(winapi),
            shared_winapi: None,
            soft_apis,
            environment,
            layout,
            stop_bitmap,
            worker_joins: Vec::new(),
            primary_tid: PRIMARY_THREAD_ID,
        }
    }

    /// Borrow engine + winapi exclusively (ST: direct; MT: mutex).
    pub(crate) fn with_mut<R>(
        &mut self,
        f: impl FnOnce(&mut dyn wie_cpu::CpuEngine, &mut wie_winapi::WinApiState) -> R,
    ) -> R {
        let mut guard = self.lock_pair();
        let (e, w) = guard.both();
        f(e, w)
    }

    /// Read-only borrow of WinAPI state.
    pub(crate) fn with_winapi_ref<R>(&self, f: impl FnOnce(&wie_winapi::WinApiState) -> R) -> R {
        if let Some(ref shared) = self.shared_winapi {
            let g = shared.lock().unwrap_or_else(|p| p.into_inner());
            f(&g)
        } else {
            f(self
                .local_winapi
                .as_ref()
                .expect("local winapi present before share"))
        }
    }

    /// Long exclusive access for the primary run loop (drop before host park).
    pub(crate) fn lock_pair(&mut self) -> ProcessPairGuard<'_> {
        if let Some(ref shared) = self.shared_winapi {
            ProcessPairGuard::Shared {
                eng: &mut *self.engine,
                win: shared.lock().unwrap_or_else(|p| p.into_inner()),
            }
        } else {
            ProcessPairGuard::Local {
                eng: &mut *self.engine,
                win: self
                    .local_winapi
                    .as_mut()
                    .expect("local winapi present before share"),
            }
        }
    }

    /// Promote WinAPI state to shared storage (idempotent).
    pub(crate) fn ensure_shared(&mut self) -> Arc<Mutex<wie_winapi::WinApiState>> {
        if let Some(ref s) = self.shared_winapi {
            return Arc::clone(s);
        }
        let win = self
            .local_winapi
            .take()
            .expect("local winapi when promoting to shared");
        let arc = Arc::new(Mutex::new(win));
        self.shared_winapi = Some(Arc::clone(&arc));
        arc
    }

    /// Drain `pending_spawns` and start host worker threads.
    pub(crate) fn drain_spawns(&mut self) -> Result<()> {
        let spawns: Vec<PendingSpawn> = self.with_mut(|eng, st| {
            let pending: Vec<_> = st.sync.pending_spawns.drain(..).collect();
            if !pending.is_empty() {
                let tid = st.threads.current_tid();
                let ctx = eng.snapshot_thread_context();
                st.sync.thread_cpu.insert(tid, ctx);
                st.threads.save_active();
            }
            pending
        });
        if spawns.is_empty() {
            return Ok(());
        }
        // Extract shared_jit from the primary engine (must be JitCpu).
            let shared_jit = self.ensure_shared_jit();
            let shared_winapi = self.ensure_shared();
            let soft = self.soft_apis.clone();
            let env = self.environment;
            let layout = self.layout;
            let stop_bitmap = self.stop_bitmap.clone();
            for spawn in spawns {
                let shared_jit = Arc::clone(&shared_jit);
                let winapi = Arc::clone(&shared_winapi);
                let soft = soft.clone();
                let bitmap = stop_bitmap.clone();
                const HOST_WORKER_STACK: usize = 8 * 1024 * 1024;
                let handle = std::thread::Builder::new()
                    .name(format!("wie-guest-{}", spawn.tid))
                    .stack_size(HOST_WORKER_STACK)
                    .spawn(move || {
                        worker_main(shared_jit, winapi, soft, env, layout, spawn.tid, bitmap);
                    })
                    .context("failed to spawn guest worker host thread")?;
            self.worker_joins.push(handle);
        }
        Ok(())
    }

    /// Get or create `Arc<JitShared>` from the stored value.
    fn ensure_shared_jit(&mut self) -> Arc<wie_cpu::JitShared> {
        self.shared_jit.as_ref().expect("shared_jit must be set for multi-threaded sessions; ensure the engine is JitCpu").clone()
    }

    /// Join workers on `ExitProcess` (MT.4): set dying, wake all waiters, join hosts.
    pub(crate) fn join_workers(&mut self) {
        self.with_mut(|_, st| {
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
        });
        for j in self.worker_joins.drain(..) {
            let _ = j.join();
        }
    }
}

/// Host worker: owns its own engine, shares WinAPI state.
fn worker_main(
    shared_jit: Arc<wie_cpu::JitShared>,
    shared_winapi: Arc<Mutex<wie_winapi::WinApiState>>,
    soft_apis: SoftApiTable,
    environment: wie_winapi::WinApiEnvironment,
    layout: RuntimeMemoryLayout,
    tid: u32,
    stop_bitmap: Vec<u8>,
) {
    let fake_api_end = layout
        .fake_api_base
        .saturating_add(u64::try_from(layout.fake_api_size).unwrap_or(0))
        .saturating_sub(1);
    let budget = layout.instruction_budget;

    // Each worker gets its own per-thread JitCpu sharing the compilation cache.
    let mut engine: Box<dyn wie_cpu::CpuEngine> =
        Box::new(JitCpu::new_shared(shared_jit));

    // Install runtime hooks (stop bitmap) so the engine stops on fake API calls.
    let _ = engine.install_runtime_hooks(
        layout.fake_api_base,
        fake_api_end,
        stop_bitmap,
    );

    // Load initial thread context set by CreateThread (RIP=start, RCX=param, RSP=stack).
    {
        let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(ctx) = st.sync.thread_cpu.get(&tid).cloned() {
            drop(st);
            engine.restore_thread_context(&ctx);
            engine.on_thread_switch();
        }
    }

    loop {
        let park_reason: Option<HostParkReason>;

        {
            let mut st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());

            if st.sync.process_dying {
                finish_tid(&st, tid, 1);
                return;
            }

            activate_thread(engine.as_mut(), &mut st, tid);

            let begin = engine.read_rip().unwrap_or(0);
            if begin == 0 {
                let code = u32::try_from(engine.read_rax().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code);
                return;
            }

            let hook_result =
                engine.run_until_stop(begin, 0, 0, budget, layout.fake_api_base, fake_api_end);

            let hook = match hook_result {
                Ok(r) if r.code.hit => r.code,
                Ok(_) => {
                    deactivate_thread(&mut st, tid);
                    std::thread::yield_now();
                    continue;
                }
                Err(_) => {
                    finish_tid(&st, tid, 1);
                    return;
                }
            };

            if hook.address == layout.callback_return_trampoline_va {
                deactivate_thread(&mut st, tid);
                continue;
            }

            let Some(resolved) = resolve_fake_api_at(hook.address, &soft_apis) else {
                finish_tid(&st, tid, 1);
                return;
            };

            if resolved.traits.exit_process() {
                st.sync.process_dying = true;
                let code = u32::try_from(engine.read_rcx().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code);
                return;
            }

            let dispatch = if let Some(id) = resolved.winapi_id {
                wie_winapi::dispatch_winapi_id(engine.as_mut(), environment, &mut st, id)
            } else {
                wie_winapi::dispatch_winapi(
                    engine.as_mut(),
                    environment,
                    &mut st,
                    &resolved.library,
                    &resolved.name,
                )
            };

            match dispatch {
                Ok(_) => {
                    deactivate_thread(&mut st, tid);
                    park_reason = None;
                }
                Err(e) => {
                    if let Some(WinApiControlSignal::ExitThread { code }) =
                        e.downcast_ref::<WinApiControlSignal>()
                    {
                        finish_tid(&st, tid, *code);
                        return;
                    }
                    if let Some(WinApiControlSignal::HostPark { reason }) =
                        e.downcast_ref::<WinApiControlSignal>()
                    {
                        let reason = *reason;
                        deactivate_thread(&mut st, tid);
                        park_reason = Some(reason);
                    } else {
                        finish_tid(&st, tid, 1);
                        return;
                    }
                }
            }
        } // drop WinAPI lock

        if let Some(reason) = park_reason {
            {
                let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                if st.sync.process_dying {
                    finish_tid(&st, tid, 1);
                    return;
                }
            }
            match reason {
                HostParkReason::CriticalSection { cs } => {
                    let q = {
                        let mut st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                        wie_winapi::kernel32::resolve_cs_queue(&mut st, cs)
                    };
                    q.park_brief();
                }
                HostParkReason::WaitObject { handle, timeout_ms } => {
                    let target = {
                        let st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                        wie_winapi::kernel32::resolve_wait_target(&st, handle)
                    };
                    let result = match target {
                        Some(t) => {
                            if timeout_ms == wie_winapi::INFINITE {
                                loop {
                                    let r = t.wait(50);
                                    if r == wie_winapi::WAIT_OBJECT_0 {
                                        break wie_winapi::WAIT_OBJECT_0;
                                    }
                                    let st =
                                        shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                                    if st.sync.process_dying {
                                        finish_tid(&st, tid, 1);
                                        return;
                                    }
                                }
                            } else {
                                t.wait(timeout_ms)
                            }
                        }
                        None => wie_winapi::WAIT_FAILED,
                    };
                    // Engine is per-thread — no engine mutex needed.
                    let mut st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                    if st.sync.process_dying {
                        finish_tid(&st, tid, 1);
                        return;
                    }
                    activate_thread(engine.as_mut(), &mut st, tid);
                    drop(engine.return_from_win64_api(u64::from(result)));
                    deactivate_thread(&mut st, tid);
                }
                HostParkReason::WaitMultiple => {
                    let req = {
                        let mut st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                        st.sync.multi_wait.remove(&tid)
                    };
                    let result = match req {
                        Some(req) => {
                            let targets = {
                                let st =
                                    shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                                st.sync.wait_targets(&req.handles)
                            };
                            match targets {
                                Some(ts) => {
                                    if req.timeout_ms == wie_winapi::INFINITE {
                                        loop {
                                            let r = wie_winapi::wait_multiple(&ts, req.wait_all, 50);
                                            if r != wie_winapi::WAIT_TIMEOUT {
                                                break r;
                                            }
                                            let st = shared_winapi
                                                .lock()
                                                .unwrap_or_else(|p| p.into_inner());
                                            if st.sync.process_dying {
                                                finish_tid(&st, tid, 1);
                                                return;
                                            }
                                        }
                                    } else {
                                        wie_winapi::wait_multiple(&ts, req.wait_all, req.timeout_ms)
                                    }
                                }
                                None => wie_winapi::WAIT_FAILED,
                            }
                        }
                        None => wie_winapi::WAIT_FAILED,
                    };
                    let mut st = shared_winapi.lock().unwrap_or_else(|p| p.into_inner());
                    if st.sync.process_dying {
                        finish_tid(&st, tid, 1);
                        return;
                    }
                    activate_thread(engine.as_mut(), &mut st, tid);
                    drop(engine.return_from_win64_api(u64::from(result)));
                    deactivate_thread(&mut st, tid);
                }
            }
        }
    }
}

fn finish_tid(st: &wie_winapi::WinApiState, tid: u32, code: u32) {
    for obj in st.sync.objects.values() {
        if let wie_winapi::KernelObject::Thread(t) = obj
            && t.tid == tid
        {
            t.finish(code);
            return;
        }
    }
}

fn activate_thread(
    _engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut wie_winapi::WinApiState,
    tid: u32,
) {
    // Per-thread engine: each engine is permanently assigned to one guest thread.
    // The engine's registers ARE this thread's registers — no save/restore needed.
    // Only `register_thread` in CreateThread sets the initial context (RIP/RSP/RCX),
    // which was already loaded onto this engine by the caller (drain_spawns loads it).
    state.threads.activate(tid);
}

fn deactivate_thread(
    state: &mut wie_winapi::WinApiState,
    _tid: u32,
) {
    state.threads.save_active();
}

/// Save active thread CPU into sync table.
pub(crate) fn save_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut wie_winapi::WinApiState,
    tid: u32,
) {
    let ctx = engine.snapshot_thread_context();
    state.sync.thread_cpu.insert(tid, ctx);
    state.threads.save_active();
}

/// Restore active thread CPU from sync table.
pub(crate) fn load_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut wie_winapi::WinApiState,
    tid: u32,
) {
    state.threads.activate(tid);
    if let Some(ctx) = state.sync.thread_cpu.get(&tid).cloned() {
        engine.restore_thread_context(&ctx);
        engine.on_thread_switch();
    }
}
