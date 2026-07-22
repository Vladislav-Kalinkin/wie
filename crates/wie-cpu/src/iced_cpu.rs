//! iced-x86 interpreter backend (WIE Phase 1). x86-64 only.

use crate::exec::{self, HookWindow, StepResult};
use crate::mem::{GuestMemory, GuestRegion};
use crate::regs::RegFile;
use crate::{CodeHookOutcome, InvalidMemoryAccess};
use crate::{CpuEngine, CpuError, RunUntilHook};
use std::sync::{Arc, RwLock};

fn lock_rd<T>(m: &RwLock<T>) -> std::sync::RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(|p| p.into_inner())
}

fn lock_wr<T>(m: &RwLock<T>) -> std::sync::RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(|p| p.into_inner())
}

const RIP_TRACE_CAP: usize = 32;
const RIP_TRACE_MASK: usize = RIP_TRACE_CAP - 1;

/// Software x86-64 CPU using iced-x86 decode + interpret.
///
/// Guest memory is shared behind `Arc<RwLock<>>` so per-thread `IcedCpu`
/// engines can read page tables and guest memory concurrently, while
/// structural mutations (map, protect, VirtualAlloc) take exclusive access.
pub struct IcedCpu {
    mem: Arc<RwLock<GuestMemory>>,
    regs: RegFile,
    hooks: Option<HookWindow>,
    rip_trace: [u64; RIP_TRACE_CAP],
    rip_trace_i: usize,
    rip_trace_n: usize,
    iced_steps: u64,
}

impl IcedCpu {
    #[must_use]
    pub fn open_x86_64() -> Self {
        Self {
            mem: Arc::new(RwLock::new(GuestMemory::new())),
            regs: RegFile::new(),
            hooks: None,
            rip_trace: [0; RIP_TRACE_CAP],
            rip_trace_i: 0,
            rip_trace_n: 0,
            iced_steps: 0,
        }
    }

    #[must_use]
    pub fn new_shared(source: &Self) -> Self {
        Self {
            mem: Arc::clone(&source.mem),
            regs: RegFile::new(),
            hooks: None,
            rip_trace: [0; RIP_TRACE_CAP],
            rip_trace_i: 0,
            rip_trace_n: 0,
            iced_steps: 0,
        }
    }

    #[must_use]
    #[expect(dead_code)]
    pub(crate) fn guest_mem_arc(&self) -> &Arc<RwLock<GuestMemory>> {
        &self.mem
    }

    #[must_use]
    pub fn iced_steps(&self) -> u64 {
        self.iced_steps
    }

    fn push_rip_trace(&mut self, rip: u64) {
        let i = self.rip_trace_i & RIP_TRACE_MASK;
        if let Some(slot) = self.rip_trace.get_mut(i) {
            *slot = rip;
        }
        self.rip_trace_i = self.rip_trace_i.wrapping_add(1);
        if self.rip_trace_n < RIP_TRACE_CAP {
            self.rip_trace_n = self.rip_trace_n.saturating_add(1);
        }
    }

    #[must_use]
    pub fn rip_trace_vec(&self) -> Vec<u64> {
        let n = self.rip_trace_n;
        let mut out = Vec::with_capacity(n);
        let start = self.rip_trace_i.wrapping_sub(n);
        for k in 0..n {
            let idx = start.wrapping_add(k) & RIP_TRACE_MASK;
            if let Some(&r) = self.rip_trace.get(idx) {
                out.push(r);
            }
        }
        out
    }

    #[must_use]
    pub fn regs(&self) -> &RegFile {
        &self.regs
    }

    pub fn regs_mut(&mut self) -> &mut RegFile {
        &mut self.regs
    }

    #[must_use]
    #[expect(dead_code)]
    pub(crate) fn hooks_ref(&self) -> Option<&HookWindow> {
        self.hooks.as_ref()
    }

    #[expect(dead_code)]
    pub(crate) fn mem_read_into(&self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        lock_rd(&self.mem).read(address, bytes)
    }

    #[expect(dead_code)]
    pub(crate) fn guest_mem_mut(&mut self) -> impl std::ops::DerefMut<Target = GuestMemory> + '_ {
        lock_wr(&self.mem)
    }

    #[expect(dead_code)]
    pub(crate) fn guest_mem(&self) -> impl std::ops::Deref<Target = GuestMemory> + '_ {
        lock_rd(&self.mem)
    }

    pub(crate) fn step_once_result(&mut self) -> Result<StepResult, CpuError> {
        self.push_rip_trace(self.regs.rip);
        let hook = self.hooks.as_ref();
        let mem_guard = lock_rd(&self.mem);
        let result = exec::step(&*mem_guard, &mut self.regs, hook)?;
        drop(mem_guard);
        if matches!(result, StepResult::Continue) {
            self.iced_steps = self.iced_steps.saturating_add(1);
        }
        Ok(result)
    }

    pub fn step_once(&mut self) -> Result<(), CpuError> {
        match self.step_once_result()? {
            StepResult::Continue => Ok(()),
            StepResult::HostStop { address, .. } => {
                Err(CpuError::Message(format!("host_stop at {address:#x}")))
            }
            StepResult::InvalidMemory(inv) => Err(CpuError::Message(format!(
                "invalid memory {} at {:#x} size={}",
                inv.access_type, inv.address, inv.size
            ))),
        }
    }
}

impl CpuEngine for IcedCpu {
    fn mem_map(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        lock_wr(&self.mem).map(address, size, perms)
    }

    fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        lock_rd(&self.mem).write(address, bytes)
    }

    fn mem_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        lock_rd(&self.mem).read(address, bytes)
    }

    fn host_span(&mut self, address: u64, len: usize, write: bool) -> Option<*mut u8> {
        lock_rd(&self.mem).host_span(address, len, write)
    }

    fn mem_generation(&self) -> u64 {
        lock_rd(&self.mem).generation()
    }

    fn virtual_alloc(
        &mut self,
        addr: u64,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64, CpuError> {
        lock_wr(&self.mem).virtual_alloc(addr, size, alloc_type, protect)
    }

    fn virtual_free(&mut self, addr: u64, size: usize, free_type: u32) -> Result<(), CpuError> {
        lock_wr(&self.mem).virtual_free(addr, size, free_type)
    }

    fn virtual_protect(
        &mut self,
        addr: u64,
        size: usize,
        new_protect: u32,
    ) -> Result<u32, CpuError> {
        lock_wr(&self.mem).virtual_protect(addr, size, new_protect)
    }

    fn virtual_query(&self, addr: u64) -> crate::MemoryBasicInformation {
        lock_rd(&self.mem).virtual_query(addr)
    }

    fn mem_map_image(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        lock_wr(&self.mem).map_image(address, size, perms)
    }

    fn register_region(&mut self, region: GuestRegion) {
        lock_wr(&self.mem).register_region(region);
    }

    fn find_region(&self, va: u64) -> Option<GuestRegion> {
        lock_rd(&self.mem).find_region(va).cloned()
    }

    fn cpu_stats(&self) -> Option<crate::JitStats> {
        Some(crate::JitStats {
            iced_insns: self.iced_steps,
            ..crate::JitStats::default()
        })
    }

    fn mem_backend_name(&self) -> &'static str {
        lock_rd(&self.mem).backend_name()
    }

    fn install_runtime_hooks(
        &mut self,
        hook_begin: u64,
        hook_end: u64,
        stop_bitmap: Vec<u8>,
    ) -> Result<(), CpuError> {
        let range_len = hook_end.saturating_sub(hook_begin).saturating_add(1);
        let expected_bytes = usize::try_from(range_len).unwrap_or(usize::MAX).div_ceil(8);
        if expected_bytes != usize::MAX && stop_bitmap.len() < expected_bytes {
            return Err(CpuError::Message(format!(
                "stop_bitmap too small: {} < {expected_bytes}",
                stop_bitmap.len()
            )));
        }
        self.hooks = Some(HookWindow {
            begin: hook_begin,
            end: hook_end,
            stop_bitmap,
        });
        Ok(())
    }

    fn run_until_stop(
        &mut self,
        begin: u64,
        until: u64,
        _timeout: u64,
        count: usize,
        _hook_begin: u64,
        _hook_end: u64,
    ) -> Result<RunUntilHook, CpuError> {
        self.regs.rip = begin;
        let budget = if count == 0 {
            100_000_000_usize
        } else {
            count
        };

        let mut executed = 0_usize;
        while executed < budget {
            if until != 0 && self.regs.rip == until {
                break;
            }

            let rip_before = self.regs.rip;
            if executed.is_multiple_of(16) {
                self.push_rip_trace(rip_before);
            }
            let hook_ref = self.hooks.as_ref();
            let mem_guard = lock_rd(&self.mem);
            match exec::step(&*mem_guard, &mut self.regs, hook_ref) {
                Ok(StepResult::Continue) => {
                    drop(mem_guard);
                    executed = executed.saturating_add(1);
                    self.iced_steps = self.iced_steps.saturating_add(1);
                }
                Ok(StepResult::HostStop { address, size }) => {
                    return Ok(RunUntilHook {
                        code: CodeHookOutcome { hit: true, address, size },
                        invalid_memory: InvalidMemoryAccess {
                            hit: false, access_type: 0, address: 0, size: 0, value: 0,
                        },
                    });
                }
                Ok(StepResult::InvalidMemory(inv)) => {
                    return Ok(RunUntilHook {
                        code: CodeHookOutcome {
                            hit: false, address: 0, size: 0,
                        },
                        invalid_memory: InvalidMemoryAccess {
                            hit: true,
                            access_type: inv.access_type,
                            address: inv.address,
                            size: inv.size,
                            value: inv.value,
                        },
                    });
                }
                Err(e) => {
                    let trace = self.rip_trace_vec();
                    let trace_s = trace
                        .iter()
                        .map(|r| format!("{r:#x}"))
                        .collect::<Vec<_>>()
                        .join(" -> ");
                    let r = &self.regs;
                    return Err(CpuError::Message(format!(
                        "{e}; iced_regs rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} \
                         rsp={:#x} rbp={:#x} rsi={:#x} rdi={:#x} \
                         r8={:#x} r9={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}; \
                         iced_rip_trace=[{trace_s}]",
                        r.rax(), r.rbx(), r.rcx(), r.rdx(),
                        r.rsp(), r.rbp(), r.rsi(), r.rdi(),
                        r.r8(), r.r9(),
                        r.gpr(12), r.gpr(13), r.gpr(14), r.gpr(15),
                    )));
                }
            }
        }

        Ok(RunUntilHook {
            code: CodeHookOutcome { hit: false, address: 0, size: 0 },
            invalid_memory: InvalidMemoryAccess {
                hit: false, access_type: 0, address: 0, size: 0, value: 0,
            },
        })
    }

    fn return_from_win64_api(&mut self, rax: u64) -> Result<u64, CpuError> {
        let rsp = self.regs.rsp();
        let mut ret_bytes = [0_u8; 8];
        let mem_guard = lock_rd(&self.mem);
        mem_guard
            .read(rsp, &mut ret_bytes)
            .map_err(|e| CpuError::Message(format!("return_from_win64_api stack read: {e}")))?;
        drop(mem_guard);
        let return_address = u64::from_le_bytes(ret_bytes);
        self.regs.set_rsp(rsp.wrapping_add(8));
        self.regs.set_rax(rax);
        self.regs.rip = return_address;
        Ok(return_address)
    }

    fn read_rip(&mut self) -> Result<u64, CpuError> { Ok(self.regs.rip) }
    fn write_rip(&mut self, value: u64) -> Result<(), CpuError> { self.regs.rip = value; Ok(()) }
    fn read_rsp(&mut self) -> Result<u64, CpuError> { Ok(self.regs.rsp()) }
    fn write_rsp(&mut self, value: u64) -> Result<(), CpuError> { self.regs.set_rsp(value); Ok(()) }
    fn read_rax(&mut self) -> Result<u64, CpuError> { Ok(self.regs.rax()) }
    fn write_rax(&mut self, value: u64) -> Result<(), CpuError> { self.regs.set_rax(value); Ok(()) }
    fn read_rcx(&mut self) -> Result<u64, CpuError> { Ok(self.regs.rcx()) }
    fn write_rcx(&mut self, value: u64) -> Result<(), CpuError> { self.regs.set_rcx(value); Ok(()) }
    fn read_rdx(&mut self) -> Result<u64, CpuError> { Ok(self.regs.rdx()) }
    fn write_rdx(&mut self, value: u64) -> Result<(), CpuError> { self.regs.set_rdx(value); Ok(()) }
    fn read_r8(&mut self) -> Result<u64, CpuError> { Ok(self.regs.r8()) }
    fn write_r8(&mut self, value: u64) -> Result<(), CpuError> { self.regs.set_r8(value); Ok(()) }
    fn read_r9(&mut self) -> Result<u64, CpuError> { Ok(self.regs.r9()) }
    fn write_r9(&mut self, value: u64) -> Result<(), CpuError> { self.regs.set_r9(value); Ok(()) }
    fn read_rbx(&mut self) -> Result<u64, CpuError> { Ok(self.regs.gpr(3)) }
    fn read_r12(&mut self) -> Result<u64, CpuError> { Ok(self.regs.gpr(12)) }

    fn snapshot_thread_context(&mut self) -> crate::ThreadContext {
        self.regs.snapshot()
    }

    fn restore_thread_context(&mut self, ctx: &crate::ThreadContext) {
        self.regs.restore(ctx);
    }

    fn on_thread_switch(&mut self) {}
}
