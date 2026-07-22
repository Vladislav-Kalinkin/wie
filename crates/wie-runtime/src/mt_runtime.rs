//! MT.2 / MT.3 process sharing: engine + WinAPI under optional host locks.
//!
//! Single-thread (no `CreateThread` yet): storage stays **local** — no mutex on
//! the hot path. After the first worker is queued, ownership moves into
//! `Arc<Mutex<_>>` so host threads can serialize on the shared CPU.

use crate::hooks::{SoftApiTable, resolve_fake_api_at};
use crate::memory::RuntimeMemoryLayout;
use anyhow::{Context, Result};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use wie_winapi::{HostParkReason, PRIMARY_THREAD_ID, PendingSpawn, WinApiControlSignal};

/// Owns either exclusive (ST) or shared (MT) process resources.
pub(crate) struct ProcessResources {
    /// Exclusive engine (ST). `None` when moved into [`Self::shared`].
    local_engine: Option<Box<dyn wie_cpu::CpuEngine>>,
    /// Exclusive WinAPI state (ST).
    local_winapi: Option<wie_winapi::WinApiState>,
    /// Shared pair after first `CreateThread`.
    shared: Option<Arc<SharedProcess>>,
    /// Soft API table (cloneable; shared by value with workers).
    pub soft_apis: SoftApiTable,
    pub environment: wie_winapi::WinApiEnvironment,
    pub layout: RuntimeMemoryLayout,
    /// Host join handles for workers.
    pub worker_joins: Vec<JoinHandle<()>>,
    /// Active guest TID on the primary host thread.
    pub primary_tid: u32,
}

/// Shared process resources for concurrent host threads.
pub(crate) struct SharedProcess {
    pub engine: Mutex<Box<dyn wie_cpu::CpuEngine>>,
    pub winapi: Mutex<wie_winapi::WinApiState>,
}

/// Exclusive borrow of engine + WinAPI (local refs or mutex guards).
pub(crate) enum ProcessPairGuard<'a> {
    /// Single-thread exclusive ownership.
    Local {
        eng: &'a mut Box<dyn wie_cpu::CpuEngine>,
        win: &'a mut wie_winapi::WinApiState,
    },
    /// Multi-thread: holding both process mutexes.
    Shared {
        eng: std::sync::MutexGuard<'a, Box<dyn wie_cpu::CpuEngine>>,
        win: std::sync::MutexGuard<'a, wie_winapi::WinApiState>,
    },
}

impl ProcessPairGuard<'_> {
    /// Simultaneous exclusive access to both sides (primary run loop).
    #[inline]
    pub(crate) fn both(&mut self) -> (&mut dyn wie_cpu::CpuEngine, &mut wie_winapi::WinApiState) {
        match self {
            Self::Local { eng, win } => (eng.as_mut(), win),
            Self::Shared { eng, win } => (eng.as_mut(), win),
        }
    }
}

impl ProcessResources {
    pub(crate) fn new(
        engine: Box<dyn wie_cpu::CpuEngine>,
        winapi: wie_winapi::WinApiState,
        soft_apis: SoftApiTable,
        environment: wie_winapi::WinApiEnvironment,
        layout: RuntimeMemoryLayout,
    ) -> Self {
        Self {
            local_engine: Some(engine),
            local_winapi: Some(winapi),
            shared: None,
            soft_apis,
            environment,
            layout,
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
        if let Some(shared) = self.shared.as_ref() {
            let g = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
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
        if let Some(shared) = self.shared.as_ref() {
            ProcessPairGuard::Shared {
                eng: shared.engine.lock().unwrap_or_else(|p| p.into_inner()),
                win: shared.winapi.lock().unwrap_or_else(|p| p.into_inner()),
            }
        } else {
            ProcessPairGuard::Local {
                eng: self
                    .local_engine
                    .as_mut()
                    .expect("local engine present before share"),
                win: self
                    .local_winapi
                    .as_mut()
                    .expect("local winapi present before share"),
            }
        }
    }

    /// Promote to shared storage (idempotent). Returns the shared arc.
    pub(crate) fn ensure_shared(&mut self) -> Arc<SharedProcess> {
        if let Some(s) = self.shared.as_ref() {
            return Arc::clone(s);
        }
        let eng = self
            .local_engine
            .take()
            .expect("local engine when promoting to shared");
        let win = self
            .local_winapi
            .take()
            .expect("local winapi when promoting to shared");
        let arc = Arc::new(SharedProcess {
            engine: Mutex::new(eng),
            winapi: Mutex::new(win),
        });
        self.shared = Some(Arc::clone(&arc));
        arc
    }

    /// Drain `pending_spawns` and start host worker threads.
    pub(crate) fn drain_spawns(&mut self) -> Result<()> {
        let spawns: Vec<PendingSpawn> = self.with_mut(|eng, st| {
            let pending: Vec<_> = st.sync.pending_spawns.drain(..).collect();
            if !pending.is_empty() {
                // Snapshot the creating thread (usually primary) before workers
                // can overwrite the shared engine registers.
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
        let shared = self.ensure_shared();
        let soft = self.soft_apis.clone();
        let env = self.environment;
        let layout = self.layout;
        for spawn in spawns {
            let shared = Arc::clone(&shared);
            let soft = soft.clone();
            // Host stack must be large enough for JIT / iced dispatch; macOS
            // secondary-thread defaults are often too small for guest workers.
            const HOST_WORKER_STACK: usize = 8 * 1024 * 1024;
            let handle = std::thread::Builder::new()
                .name(format!("wie-guest-{}", spawn.tid))
                .stack_size(HOST_WORKER_STACK)
                .spawn(move || {
                    worker_main(shared, soft, env, layout, spawn.tid);
                })
                .context("failed to spawn guest worker host thread")?;
            self.worker_joins.push(handle);
        }
        Ok(())
    }

    /// Join workers on `ExitProcess` (MT.4): set dying, wake all waiters, join hosts.
    ///
    /// Protocol:
    /// 1. `process_dying = true` so workers exit at the next quantum.
    /// 2. Notify all CS queues and signal all events so parks do not hang forever.
    /// 3. Mark unfinished thread objects finished (wakes `WaitForSingleObject` joiners).
    /// 4. Join host worker threads (best-effort; workers recheck dying flag).
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
                        // Wake `WaitForSingleObject` joiners. Workers that still
                        // hold the engine will exit after seeing `process_dying`.
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

/// Host worker: serialize on shared engine, run guest until ExitThread.
fn worker_main(
    shared: Arc<SharedProcess>,
    soft_apis: SoftApiTable,
    environment: wie_winapi::WinApiEnvironment,
    layout: RuntimeMemoryLayout,
    tid: u32,
) {
    let fake_api_end = layout
        .fake_api_base
        .saturating_add(u64::try_from(layout.fake_api_size).unwrap_or(0))
        .saturating_sub(1);
    let budget = layout.instruction_budget;

    loop {
        let park_reason: Option<HostParkReason>;

        {
            let mut eng = shared.engine.lock().unwrap_or_else(|p| p.into_inner());
            let mut st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());

            if st.sync.process_dying {
                finish_tid(&st, tid, 1);
                return;
            }

            activate_thread(eng.as_mut(), &mut st, tid);

            let begin = eng.read_rip().unwrap_or(0);
            if begin == 0 {
                // ThreadProc / `_beginthreadex` start returned (retaddr was 0).
                // Win64: exit code is the low 32 bits of RAX.
                let code = u32::try_from(eng.read_rax().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code);
                return;
            }

            let hook_result =
                eng.run_until_stop(begin, 0, 0, budget, layout.fake_api_base, fake_api_end);

            let hook = match hook_result {
                Ok(r) if r.code.hit => r.code,
                Ok(_) => {
                    deactivate_thread(eng.as_mut(), &mut st, tid);
                    std::thread::yield_now();
                    continue;
                }
                Err(_) => {
                    finish_tid(&st, tid, 1);
                    return;
                }
            };

            if hook.address == layout.callback_return_trampoline_va {
                deactivate_thread(eng.as_mut(), &mut st, tid);
                continue;
            }

            let Some(resolved) = resolve_fake_api_at(hook.address, &soft_apis) else {
                finish_tid(&st, tid, 1);
                return;
            };

            if resolved.traits.exit_process() {
                st.sync.process_dying = true;
                let code = u32::try_from(eng.read_rcx().unwrap_or(0) & 0xffff_ffff).unwrap_or(0);
                finish_tid(&st, tid, code);
                return;
            }

            // Fast void sync / heap paths use full dispatch for workers.
            let dispatch = if let Some(id) = resolved.winapi_id {
                wie_winapi::dispatch_winapi_id(eng.as_mut(), environment, &mut st, id)
            } else {
                wie_winapi::dispatch_winapi(
                    eng.as_mut(),
                    environment,
                    &mut st,
                    &resolved.library,
                    &resolved.name,
                )
            };

            match dispatch {
                Ok(_) => {
                    deactivate_thread(eng.as_mut(), &mut st, tid);
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
                        deactivate_thread(eng.as_mut(), &mut st, tid);
                        park_reason = Some(reason);
                    } else {
                        finish_tid(&st, tid, 1);
                        return;
                    }
                }
            }
        } // drop locks

        if let Some(reason) = park_reason {
            // Bail if process is dying while we were about to park.
            {
                let st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
                if st.sync.process_dying {
                    finish_tid(&st, tid, 1);
                    return;
                }
            }
            match reason {
                HostParkReason::CriticalSection { cs } => {
                    // Take queue under winapi lock, then wait **without** holding it.
                    let q = {
                        let mut st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
                        wie_winapi::kernel32::resolve_cs_queue(&mut st, cs)
                    };
                    q.park_brief();
                }
                HostParkReason::WaitObject { handle, timeout_ms } => {
                    let target = {
                        let st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
                        wie_winapi::kernel32::resolve_wait_target(&st, handle)
                    };
                    // Slice infinite waits so process_dying is observed promptly.
                    let result = match target {
                        Some(t) => {
                            if timeout_ms == wie_winapi::INFINITE {
                                loop {
                                    let r = t.wait(50);
                                    if r == wie_winapi::WAIT_OBJECT_0 {
                                        break wie_winapi::WAIT_OBJECT_0;
                                    }
                                    let st =
                                        shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
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
                    let mut eng = shared.engine.lock().unwrap_or_else(|p| p.into_inner());
                    let mut st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
                    if st.sync.process_dying {
                        finish_tid(&st, tid, 1);
                        return;
                    }
                    activate_thread(eng.as_mut(), &mut st, tid);
                    drop(eng.return_from_win64_api(u64::from(result)));
                    deactivate_thread(eng.as_mut(), &mut st, tid);
                }
                HostParkReason::WaitMultiple => {
                    let req = {
                        let mut st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
                        st.sync.multi_wait.remove(&tid)
                    };
                    let result = match req {
                        Some(req) => {
                            let targets = {
                                let st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
                                st.sync.wait_targets(&req.handles)
                            };
                            match targets {
                                Some(ts) => {
                                    if req.timeout_ms == wie_winapi::INFINITE {
                                        loop {
                                            let r =
                                                wie_winapi::wait_multiple(&ts, req.wait_all, 50);
                                            if r != wie_winapi::WAIT_TIMEOUT {
                                                break r;
                                            }
                                            let st = shared
                                                .winapi
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
                    let mut eng = shared.engine.lock().unwrap_or_else(|p| p.into_inner());
                    let mut st = shared.winapi.lock().unwrap_or_else(|p| p.into_inner());
                    if st.sync.process_dying {
                        finish_tid(&st, tid, 1);
                        return;
                    }
                    activate_thread(eng.as_mut(), &mut st, tid);
                    drop(eng.return_from_win64_api(u64::from(result)));
                    deactivate_thread(eng.as_mut(), &mut st, tid);
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
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut wie_winapi::WinApiState,
    tid: u32,
) {
    // Always park the previously running guest thread's CPU before overwriting
    // the shared engine. Without this, a worker that wins the process lock
    // between primary quanta clobbers unsaved primary registers (universal MT bug).
    let prev = state.threads.current_tid();
    if prev != tid {
        let prev_ctx = engine.snapshot_thread_context();
        state.sync.thread_cpu.insert(prev, prev_ctx);
        state.threads.save_active();
    }
    state.threads.activate(tid);
    if let Some(ctx) = state.sync.thread_cpu.get(&tid).cloned() {
        engine.restore_thread_context(&ctx);
        engine.on_thread_switch();
    }
}

fn deactivate_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut wie_winapi::WinApiState,
    tid: u32,
) {
    let ctx = engine.snapshot_thread_context();
    state.sync.thread_cpu.insert(tid, ctx);
    state.threads.save_active();
}

/// Save active thread CPU into sync table.
pub(crate) fn save_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut wie_winapi::WinApiState,
    tid: u32,
) {
    deactivate_thread(engine, state, tid);
}

/// Restore active thread CPU from sync table.
pub(crate) fn load_thread(
    engine: &mut dyn wie_cpu::CpuEngine,
    state: &mut wie_winapi::WinApiState,
    tid: u32,
) {
    activate_thread(engine, state, tid);
}
