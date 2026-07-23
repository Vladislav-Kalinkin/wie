//! Kernel waitable objects for MT.2 / MT.3 (threads, events, CS wait queues).
//!
//! Host threads park on [`std::sync::Condvar`] while another guest thread holds
//! the shared CPU engine. Guest data races are still the application's problem;
//! engine metadata is serialized by the runtime process lock.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use wie_cpu::ThreadContext;

/// `STILL_ACTIVE` — thread has not terminated (`GetExitCodeThread`).
pub const STILL_ACTIVE: u32 = 259;

/// `WAIT_OBJECT_0` success from `WaitForSingleObject`.
pub const WAIT_OBJECT_0: u32 = 0;
/// `WAIT_TIMEOUT`.
pub const WAIT_TIMEOUT: u32 = 0x0000_0102;
/// `WAIT_FAILED`.
pub const WAIT_FAILED: u32 = 0xffff_ffff;
/// `INFINITE` timeout.
pub const INFINITE: u32 = 0xffff_ffff;

/// Handle table + wait infrastructure owned by [`crate::WinApiState`].
#[derive(Debug, Clone, Default)]
pub struct SyncState {
    /// Next kernel handle value (never zero / `INVALID_HANDLE_VALUE`).
    pub next_handle: u64,
    /// Live kernel objects keyed by handle.
    pub objects: HashMap<u64, KernelObject>,
    /// Guest TID → saved CPU context while not running on the shared engine.
    pub thread_cpu: HashMap<u32, ThreadContext>,
    /// Critical-section wait queues keyed by guest CS VA.
    pub cs_waiters: HashMap<u64, Arc<CsWaitQueue>>,
    /// Monotonic stack slot for worker stacks.
    pub next_stack_slot: u32,
    /// Threads waiting to be spawned by the session after `CreateThread`.
    pub pending_spawns: Vec<PendingSpawn>,
    /// `CREATE_SUSPENDED` threads awaiting `ResumeThread` (keyed by handle).
    pub suspended_spawns: HashMap<u64, PendingSpawn>,
    /// Pending `WaitForMultipleObjects` args, keyed by guest TID of the waiter.
    pub multi_wait: HashMap<u32, MultiWaitRequest>,
    /// Process is dying (`ExitProcess`); workers should stop.
    pub process_dying: bool,
    /// Per-module function tables (image_base → sorted Vec of RuntimeFunction).
    /// Used by `RtlLookupFunctionEntry` to find unwind info for a given RIP.
    pub function_tables: HashMap<u64, Vec<crate::exception::RuntimeFunction>>,
}

/// Detached args for one `WaitForMultipleObjects` host park.
#[derive(Debug, Clone)]
pub struct MultiWaitRequest {
    /// Kernel handles to wait on.
    pub handles: Vec<u64>,
    /// Wait for all (`true`) or any (`false`).
    pub wait_all: bool,
    /// Timeout in ms (`INFINITE` = forever).
    pub timeout_ms: u32,
}

impl SyncState {
    /// Bootstrap empty sync state (primary thread is not a kernel object until needed).
    #[must_use]
    pub fn new() -> Self {
        Self {
            next_handle: 0x0000_0000_8000_0001,
            objects: HashMap::new(),
            thread_cpu: HashMap::new(),
            cs_waiters: HashMap::new(),
            next_stack_slot: 1,
            pending_spawns: Vec::new(),
            suspended_spawns: HashMap::new(),
            multi_wait: HashMap::new(),
            process_dying: false,
            function_tables: HashMap::new(),
        }
    }

    fn alloc_handle(&mut self) -> u64 {
        let h = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        if self.next_handle == 0 || self.next_handle == u64::MAX {
            self.next_handle = 0x0000_0000_8000_0001;
        }
        h
    }

    /// Register a new thread object; returns (handle, Arc body).
    pub fn register_thread(&mut self, tid: u32, ctx: ThreadContext) -> (u64, Arc<ThreadObject>) {
        let handle = self.alloc_handle();
        let obj = Arc::new(ThreadObject {
            tid,
            handle,
            exit_code: std::sync::atomic::AtomicU32::new(STILL_ACTIVE),
            finished: Mutex::new(false),
            finished_cv: Condvar::new(),
        });
        self.thread_cpu.insert(tid, ctx);
        self.objects
            .insert(handle, KernelObject::Thread(Arc::clone(&obj)));
        (handle, obj)
    }

    /// Register a Win32 event object.
    pub fn register_event(&mut self, manual_reset: bool, initial: bool) -> (u64, Arc<EventObject>) {
        let handle = self.alloc_handle();
        let obj = Arc::new(EventObject {
            handle,
            manual_reset,
            state: Mutex::new(EventInner { signaled: initial }),
            cv: Condvar::new(),
        });
        self.objects
            .insert(handle, KernelObject::Event(Arc::clone(&obj)));
        (handle, obj)
    }

    /// Register a Win32 semaphore (`CreateSemaphore*`).
    pub fn register_semaphore(
        &mut self,
        initial_count: i32,
        maximum_count: i32,
    ) -> (u64, Arc<SemaphoreObject>) {
        let handle = self.alloc_handle();
        let initial = initial_count.clamp(0, maximum_count.max(0));
        let maximum = maximum_count.max(1);
        let obj = Arc::new(SemaphoreObject {
            handle,
            maximum,
            state: Mutex::new(SemaphoreInner { count: initial }),
            cv: Condvar::new(),
        });
        self.objects
            .insert(handle, KernelObject::Semaphore(Arc::clone(&obj)));
        (handle, obj)
    }

    /// Look up a thread object by handle.
    pub fn thread_by_handle(&self, handle: u64) -> Option<Arc<ThreadObject>> {
        match self.objects.get(&handle)? {
            KernelObject::Thread(t) => Some(Arc::clone(t)),
            KernelObject::Event(_) | KernelObject::Semaphore(_) => None,
        }
    }

    /// Look up any waitable object.
    pub fn object(&self, handle: u64) -> Option<&KernelObject> {
        self.objects.get(&handle)
    }

    /// CS wait queue for guest VA (created on demand).
    pub fn cs_queue(&mut self, cs_va: u64) -> Arc<CsWaitQueue> {
        self.cs_waiters
            .entry(cs_va)
            .or_insert_with(|| {
                Arc::new(CsWaitQueue {
                    lock: Mutex::new(()),
                    cv: Condvar::new(),
                })
            })
            .clone()
    }
}

/// One pending `CreateThread` for the session to spawn as a host OS thread.
#[derive(Debug, Clone)]
pub struct PendingSpawn {
    /// Guest TID.
    pub tid: u32,
    /// Thread handle returned to the creator.
    pub handle: u64,
    /// Start routine guest VA.
    pub start_address: u64,
    /// Parameter in RCX.
    pub parameter: u64,
    /// Guest stack base (mapped).
    pub stack_base: u64,
    /// Guest stack size in bytes.
    pub stack_size: usize,
}

/// Kernel object stored in the handle table.
#[derive(Debug, Clone)]
pub enum KernelObject {
    /// Guest thread (1:1 host thread after spawn).
    Thread(Arc<ThreadObject>),
    /// Auto/manual-reset event.
    Event(Arc<EventObject>),
    /// Counting semaphore.
    Semaphore(Arc<SemaphoreObject>),
}

/// Guest thread waitable + exit state.
#[derive(Debug)]
pub struct ThreadObject {
    /// Guest TID (`GetCurrentThreadId` for that thread).
    pub tid: u32,
    /// Kernel handle value.
    pub handle: u64,
    /// Exit code or [`STILL_ACTIVE`].
    pub exit_code: std::sync::atomic::AtomicU32,
    /// True after `ExitThread` / natural end.
    pub finished: Mutex<bool>,
    /// Notified when the thread finishes.
    pub finished_cv: Condvar,
}

impl ThreadObject {
    /// Mark finished with `code` and wake joiners.
    pub fn finish(&self, code: u32) {
        self.exit_code
            .store(code, std::sync::atomic::Ordering::Release);
        if let Ok(mut g) = self.finished.lock() {
            *g = true;
            self.finished_cv.notify_all();
        }
    }

    /// Whether the thread has terminated.
    pub fn is_finished(&self) -> bool {
        self.finished.lock().map_or(true, |g| *g)
    }

    /// Block until finished or timeout. Returns true if finished.
    pub fn wait_until_finished(&self, timeout_ms: u32) -> bool {
        let Ok(guard) = self.finished.lock() else {
            return true;
        };
        if *guard {
            return true;
        }
        if timeout_ms == 0 {
            return false;
        }
        if timeout_ms == INFINITE {
            let mut g = guard;
            while !*g {
                g = match self.finished_cv.wait(g) {
                    Ok(x) => x,
                    Err(p) => p.into_inner(),
                };
            }
            return true;
        }
        let remain = Duration::from_millis(u64::from(timeout_ms));
        let (next, timeout_result) = match self.finished_cv.wait_timeout(guard, remain) {
            Ok(x) => x,
            Err(p) => {
                let (inner, _) = p.into_inner();
                return *inner;
            }
        };
        if *next {
            return true;
        }
        // One-shot wait; for short timeouts this is enough for micros.
        // Extended waits loop with fixed slices.
        if timeout_result.timed_out() {
            return false;
        }
        true
    }
}

/// Win32 event object.
#[derive(Debug)]
pub struct EventObject {
    /// Kernel handle.
    pub handle: u64,
    /// Manual-reset vs auto-reset.
    pub manual_reset: bool,
    /// Signaled flag.
    pub state: Mutex<EventInner>,
    /// Waiters.
    pub cv: Condvar,
}

/// Interior of an event (under mutex).
#[derive(Debug)]
pub struct EventInner {
    /// Whether the event is signaled.
    pub signaled: bool,
}

impl EventObject {
    /// `SetEvent` — signal; wake all (manual) or one (auto).
    pub fn set(&self) {
        if let Ok(mut g) = self.state.lock() {
            g.signaled = true;
            if self.manual_reset {
                self.cv.notify_all();
            } else {
                self.cv.notify_one();
            }
        }
    }

    /// `ResetEvent`.
    pub fn reset(&self) {
        if let Ok(mut g) = self.state.lock() {
            g.signaled = false;
        }
    }

    /// Wait until signaled (auto-reset consumes). Returns false on timeout.
    pub fn wait(&self, timeout_ms: u32) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return true;
        };
        if guard.signaled {
            if !self.manual_reset {
                guard.signaled = false;
            }
            return true;
        }
        if timeout_ms == 0 {
            return false;
        }
        if timeout_ms == INFINITE {
            while !guard.signaled {
                guard = match self.cv.wait(guard) {
                    Ok(x) => x,
                    Err(p) => p.into_inner(),
                };
            }
            if !self.manual_reset {
                guard.signaled = false;
            }
            return true;
        }
        let remain = Duration::from_millis(u64::from(timeout_ms));
        let (next, timeout_result) = match self.cv.wait_timeout(guard, remain) {
            Ok(x) => x,
            Err(p) => {
                let (inner, _) = p.into_inner();
                return inner.signaled;
            }
        };
        guard = next;
        if guard.signaled {
            if !self.manual_reset {
                guard.signaled = false;
            }
            return true;
        }
        if timeout_result.timed_out() {
            return false;
        }
        true
    }
}

/// Win32 counting semaphore.
#[derive(Debug)]
pub struct SemaphoreObject {
    /// Kernel handle.
    pub handle: u64,
    /// Maximum count (`lMaximumCount`).
    pub maximum: i32,
    /// Current count under mutex.
    pub state: Mutex<SemaphoreInner>,
    /// Waiters for count &gt; 0.
    pub cv: Condvar,
}

/// Interior of a semaphore (under mutex).
#[derive(Debug)]
pub struct SemaphoreInner {
    /// Current count (`0..=maximum`).
    pub count: i32,
}

impl SemaphoreObject {
    /// Non-blocking acquire: true if a unit was taken.
    pub fn try_acquire(&self) -> bool {
        let Ok(mut g) = self.state.lock() else {
            return false;
        };
        if g.count > 0 {
            g.count = g.count.saturating_sub(1);
            true
        } else {
            false
        }
    }

    /// Wait until a unit is available (decrements). Returns false on timeout.
    pub fn wait(&self, timeout_ms: u32) -> bool {
        let Ok(mut guard) = self.state.lock() else {
            return true;
        };
        if guard.count > 0 {
            guard.count = guard.count.saturating_sub(1);
            return true;
        }
        if timeout_ms == 0 {
            return false;
        }
        if timeout_ms == INFINITE {
            while guard.count <= 0 {
                guard = match self.cv.wait(guard) {
                    Ok(x) => x,
                    Err(p) => p.into_inner(),
                };
            }
            guard.count = guard.count.saturating_sub(1);
            return true;
        }
        let remain = Duration::from_millis(u64::from(timeout_ms));
        let (next, timeout_result) = match self.cv.wait_timeout(guard, remain) {
            Ok(x) => x,
            Err(p) => {
                let (inner, _) = p.into_inner();
                return inner.count > 0;
            }
        };
        guard = next;
        if guard.count > 0 {
            guard.count = guard.count.saturating_sub(1);
            return true;
        }
        if timeout_result.timed_out() {
            return false;
        }
        // Spurious wake: treat as timeout for short waits (caller may retry).
        false
    }

    /// `ReleaseSemaphore` — add `release_count` units. Returns previous count, or `None` if invalid.
    pub fn release(&self, release_count: i32) -> Option<i32> {
        if release_count <= 0 {
            return None;
        }
        let Ok(mut g) = self.state.lock() else {
            return None;
        };
        let prev = g.count;
        let new = prev.checked_add(release_count)?;
        if new > self.maximum {
            return None;
        }
        g.count = new;
        // Wake waiters proportional to units released (notify_all is safe).
        if prev == 0 {
            self.cv.notify_all();
        } else {
            for _ in 0..release_count.min(16) {
                self.cv.notify_one();
            }
        }
        Some(prev)
    }

    /// Wake all waiters during process teardown (does not change count semantics for dying).
    pub fn notify_all(&self) {
        self.cv.notify_all();
    }
}

/// Wait queue for one guest critical section VA.
#[derive(Debug)]
pub struct CsWaitQueue {
    /// Mutex for condvar (no extra state).
    pub lock: Mutex<()>,
    /// Signaled on Leave when unlocked.
    pub cv: Condvar,
}

impl CsWaitQueue {
    /// Park until Leave notifies, or a short timeout (lost-wakeup safe).
    ///
    /// Callers **must** retry `EnterCriticalSection` after this returns. Never
    /// wait forever without a timeout: Leave may notify before we reach
    /// `wait_timeout` (classic lost wakeup under process-lock serialization).
    pub fn wait_ms(&self, timeout_ms: u64) {
        let Ok(guard) = self.lock.lock() else {
            return;
        };
        drop(
            self.cv
                .wait_timeout(guard, Duration::from_millis(timeout_ms.max(1))),
        );
    }

    /// Preferred park for contended CS: yield, then brief condvar wait.
    pub fn park_brief(&self) {
        for _ in 0..16 {
            std::thread::yield_now();
        }
        self.wait_ms(1);
    }

    /// Wake one waiter after Leave unlocks the CS.
    pub fn notify_one(&self) {
        self.cv.notify_one();
    }

    /// Wake all waiters (process dying / teardown).
    pub fn notify_all(&self) {
        self.cv.notify_all();
    }
}

/// Detached wait target so the host can park **without** holding process locks.
///
/// Holding `engine`/`winapi` mutexes while waiting deadlocks workers that need
/// those locks to `ExitThread` / `LeaveCriticalSection` / `SetEvent`.
#[derive(Debug, Clone)]
pub enum WaitTarget {
    /// Thread object (join).
    Thread(Arc<ThreadObject>),
    /// Event object.
    Event(Arc<EventObject>),
    /// Semaphore object.
    Semaphore(Arc<SemaphoreObject>),
}

impl WaitTarget {
    /// Non-blocking check / consume. True if the wait would succeed immediately.
    pub fn try_wait(&self) -> bool {
        match self {
            Self::Thread(t) => t.is_finished(),
            Self::Event(e) => e.wait(0),
            Self::Semaphore(s) => s.try_acquire(),
        }
    }

    /// Block until signaled / finished. Returns `WAIT_*` codes.
    pub fn wait(&self, timeout_ms: u32) -> u32 {
        match self {
            Self::Thread(t) => {
                if t.wait_until_finished(timeout_ms) {
                    WAIT_OBJECT_0
                } else {
                    WAIT_TIMEOUT
                }
            }
            Self::Event(e) => {
                if e.wait(timeout_ms) {
                    WAIT_OBJECT_0
                } else {
                    WAIT_TIMEOUT
                }
            }
            Self::Semaphore(s) => {
                if s.wait(timeout_ms) {
                    WAIT_OBJECT_0
                } else {
                    WAIT_TIMEOUT
                }
            }
        }
    }
}

/// Maximum handles for `WaitForMultipleObjects` (Windows `MAXIMUM_WAIT_OBJECTS`).
pub const MAXIMUM_WAIT_OBJECTS: usize = 64;

/// Wait on multiple detached targets (any or all). Parks with short polls so
/// the process lock is never held while sleeping.
///
/// Returns `WAIT_OBJECT_0 + index` for wait-any, `WAIT_OBJECT_0` for wait-all,
/// or `WAIT_TIMEOUT` / `WAIT_FAILED`.
pub fn wait_multiple(targets: &[WaitTarget], wait_all: bool, timeout_ms: u32) -> u32 {
    if targets.is_empty() || targets.len() > MAXIMUM_WAIT_OBJECTS {
        return WAIT_FAILED;
    }

    if let Some(code) = multi_try_once(targets, wait_all) {
        return code;
    }
    if timeout_ms == 0 {
        return WAIT_TIMEOUT;
    }

    let infinite = timeout_ms == INFINITE;
    let deadline = if infinite {
        None
    } else {
        Some(
            std::time::Instant::now()
                .checked_add(Duration::from_millis(u64::from(timeout_ms)))
                .unwrap_or_else(std::time::Instant::now),
        )
    };

    loop {
        if let Some(code) = multi_try_once(targets, wait_all) {
            return code;
        }
        if let Some(dl) = deadline
            && std::time::Instant::now() >= dl
        {
            return WAIT_TIMEOUT;
        }

        let slice_ms: u32 = if let Some(dl) = deadline {
            let rem = dl.saturating_duration_since(std::time::Instant::now());
            u32::try_from(rem.as_millis().min(25)).unwrap_or(25).max(1)
        } else {
            25
        };

        if wait_all {
            // Avoid consuming auto-reset units while not all are ready.
            std::thread::sleep(Duration::from_millis(u64::from(slice_ms.min(5))));
        } else if let Some(first) = targets.first() {
            // Park on the first object; if it signals, that is index 0.
            if first.wait(slice_ms) == WAIT_OBJECT_0 {
                return WAIT_OBJECT_0;
            }
            // Else re-poll the whole set (another handle may have signaled).
        } else {
            return WAIT_FAILED;
        }
    }
}

/// One non-blocking multi-wait attempt. `Some` if satisfied.
fn multi_try_once(targets: &[WaitTarget], wait_all: bool) -> Option<u32> {
    if wait_all {
        // Threads: readiness is non-destructive. Events/semaphores consume on
        // acquire — only acquire after every thread is finished; if a later
        // acquire fails, earlier units stay taken (emulator limitation).
        for t in targets {
            if let WaitTarget::Thread(th) = t
                && !th.is_finished()
            {
                return None;
            }
        }
        for t in targets {
            if !t.try_wait() {
                return None;
            }
        }
        Some(WAIT_OBJECT_0)
    } else {
        for (i, t) in targets.iter().enumerate() {
            if t.try_wait() {
                return Some(WAIT_OBJECT_0.saturating_add(u32::try_from(i).unwrap_or(0)));
            }
        }
        None
    }
}

impl SyncState {
    /// Clone a waitable handle into a [`WaitTarget`] (or `None` if invalid).
    pub fn wait_target(&self, handle: u64) -> Option<WaitTarget> {
        match self.objects.get(&handle)? {
            KernelObject::Thread(t) => Some(WaitTarget::Thread(Arc::clone(t))),
            KernelObject::Event(e) => Some(WaitTarget::Event(Arc::clone(e))),
            KernelObject::Semaphore(s) => Some(WaitTarget::Semaphore(Arc::clone(s))),
        }
    }

    /// Build wait targets for a handle list; `None` if any handle is invalid.
    pub fn wait_targets(&self, handles: &[u64]) -> Option<Vec<WaitTarget>> {
        let mut out = Vec::with_capacity(handles.len());
        for &h in handles {
            out.push(self.wait_target(h)?);
        }
        Some(out)
    }
}
