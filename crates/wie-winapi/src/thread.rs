//! Guest thread identity and thread-local storage (MT.0–MT.3).
//!
//! WIE models a Windows process with one or more guest threads. Primary runs on
//! the session host thread; workers (MT.2+) each get a host `std::thread` and
//! serialize guest execution on the shared CPU engine.
//!
//! Design notes (Apple Silicon / soft-translate):
//! - Guest TID is independent of host pthread id.
//! - TLS **indices** are process-wide (`TlsAlloc`); **values** live on the
//!   active [`GuestThread`].
//! - TEB last-error is still mirrored at a fixed low VA for the primary
//!   thread until multi-TEB / GS-base (later phase).

use std::collections::HashMap;

/// Documented primary (bootstrap) guest thread id.
///
/// Matches the historical constant used by `GetCurrentThreadId` stubs and
/// micro-tests that only require a non-zero TID.
pub const PRIMARY_THREAD_ID: u32 = 0x5678;

/// First guest TID allocated for workers (`CreateThread`).
pub const FIRST_WORKER_TID: u32 = 0x5679;

/// Process-wide TLS index bookkeeping + the currently scheduled guest thread.
///
/// Embedded in [`crate::WinApiState`]. Session / worker loops switch
/// [`Self::active`] when dispatching host API stops for that guest thread.
#[derive(Debug, Clone)]
pub struct ThreadState {
    /// Number of TLS indices allocated process-wide (`TlsAlloc` count).
    pub tls_index_count: u32,
    /// Thread that is currently running guest code / handling a WinAPI stop.
    pub active: GuestThread,
    /// All known guest threads (primary + workers), keyed by TID.
    pub by_tid: HashMap<u32, GuestThread>,
    /// Next TID for `CreateThread` (monotonic).
    pub next_tid: u32,
}

impl Default for ThreadState {
    fn default() -> Self {
        Self::primary()
    }
}

impl ThreadState {
    /// Primary thread only (session bootstrap).
    #[must_use]
    pub fn primary() -> Self {
        let primary = GuestThread::primary();
        let mut by_tid = HashMap::new();
        by_tid.insert(primary.tid, primary.clone());
        Self {
            tls_index_count: 0,
            active: primary,
            by_tid,
            next_tid: FIRST_WORKER_TID,
        }
    }

    /// Guest TID of the active thread.
    #[must_use]
    pub fn current_tid(&self) -> u32 {
        self.active.tid
    }

    /// Allocate a new worker TID and register an empty [`GuestThread`].
    pub fn alloc_worker(&mut self) -> u32 {
        let tid = self.next_tid;
        self.next_tid = self.next_tid.saturating_add(1);
        if self.next_tid == 0 {
            self.next_tid = FIRST_WORKER_TID;
        }
        let mut gt = GuestThread::with_tid(tid);
        let need = usize::try_from(self.tls_index_count).unwrap_or(0);
        if gt.tls_values.len() < need {
            gt.tls_values.resize(need, 0);
        }
        self.by_tid.insert(tid, gt);
        tid
    }

    /// Ensure `active.tls_values` can index `[0, tls_index_count)`.
    pub fn grow_active_tls_to_process_count(&mut self) {
        let need = usize::try_from(self.tls_index_count).unwrap_or(0);
        if self.active.tls_values.len() < need {
            self.active.tls_values.resize(need, 0);
        }
    }

    /// Persist `active` into `by_tid` (after host API that mutated TLS).
    pub fn save_active(&mut self) {
        let tid = self.active.tid;
        self.by_tid.insert(tid, self.active.clone());
    }

    /// Load `tid` into `active` (before running that guest thread).
    pub fn activate(&mut self, tid: u32) {
        self.save_active();
        if let Some(gt) = self.by_tid.get(&tid).cloned() {
            self.active = gt;
        } else {
            let mut gt = GuestThread::with_tid(tid);
            let need = usize::try_from(self.tls_index_count).unwrap_or(0);
            gt.tls_values.resize(need, 0);
            self.active = gt;
        }
        self.grow_active_tls_to_process_count();
    }
}

/// Per-guest-thread private state (registers live on the CPU engine / sync table).
#[derive(Debug, Clone)]
pub struct GuestThread {
    /// Guest `GetCurrentThreadId` value.
    pub tid: u32,
    /// Values for process TLS indices (`TlsGetValue` / `TlsSetValue`).
    pub tls_values: Vec<u64>,
}

impl GuestThread {
    /// Bootstrap primary thread.
    #[must_use]
    pub fn primary() -> Self {
        Self {
            tid: PRIMARY_THREAD_ID,
            tls_values: Vec::new(),
        }
    }

    /// New worker thread with the given guest TID (MT.2+).
    #[must_use]
    pub fn with_tid(tid: u32) -> Self {
        Self {
            tid,
            tls_values: Vec::new(),
        }
    }
}
