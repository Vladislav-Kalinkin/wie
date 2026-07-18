//! iced-x86 interpreter backend (WIE Phase 1). x86-64 only.

use crate::exec::{self, HookWindow, StepResult};
// Re-export for JIT host-stop checks.
use crate::mem::{GuestMemory, GuestRegion};
use crate::regs::RegFile;
use crate::{CodeHookOutcome, InvalidMemoryAccess};
use crate::{CpuEngine, CpuError, RunUntilHook};

/// Power-of-two RIP ring capacity (mask indexing avoids `%` side-effect lints).
const RIP_TRACE_CAP: usize = 32;
const RIP_TRACE_MASK: usize = RIP_TRACE_CAP - 1;

/// Software x86-64 CPU using iced-x86 decode + interpret.
///
/// Universal PE64 backend — no app-specific shortcuts. Completeness grows with
/// the implemented mnemonic set in [`crate::exec`].
pub struct IcedCpu {
    mem: GuestMemory,
    regs: RegFile,
    hooks: Option<HookWindow>,
    /// Recent RIP history for diagnostics (ring buffer).
    rip_trace: [u64; RIP_TRACE_CAP],
    rip_trace_i: usize,
    rip_trace_n: usize,
    /// Instructions retired via interpreter (Phase 0 baselines).
    iced_steps: u64,
}

impl IcedCpu {
    /// Create a fresh x86-64 interpreter instance.
    #[must_use]
    pub fn open_x86_64() -> Self {
        Self {
            mem: GuestMemory::new(),
            regs: RegFile::new(),
            hooks: None,
            rip_trace: [0; RIP_TRACE_CAP],
            rip_trace_i: 0,
            rip_trace_n: 0,
            iced_steps: 0,
        }
    }

    /// Interpreter step counter (also used when JIT falls back to iced).
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

    /// Recent RIP values (oldest → newest), for crash diagnostics.
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

    /// Expose registers for tests / debugging.
    #[must_use]
    pub fn regs(&self) -> &RegFile {
        &self.regs
    }

    /// Mutable registers for tests.
    pub fn regs_mut(&mut self) -> &mut RegFile {
        &mut self.regs
    }

    /// Runtime hook window (JIT consults stop-bitmap before entering a block).
    #[must_use]
    pub(crate) fn hooks_ref(&self) -> Option<&HookWindow> {
        self.hooks.as_ref()
    }

    /// Read guest bytes without going through the `CpuEngine` trait (JIT decode).
    pub(crate) fn mem_read_into(&self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        self.mem.read(address, bytes)
    }

    /// Mutable guest memory pointer for JIT host load/store callbacks.
    pub(crate) fn guest_mem_mut(&mut self) -> &mut GuestMemory {
        &mut self.mem
    }

    /// One step returning the raw [`StepResult`] (shared by `step_once` and JIT fallback).
    pub(crate) fn step_once_result(&mut self) -> Result<StepResult, CpuError> {
        self.push_rip_trace(self.regs.rip);
        let hook = self.hooks.as_ref();
        let result = exec::step(&mut self.mem, &mut self.regs, hook)?;
        if matches!(result, StepResult::Continue) {
            self.iced_steps = self.iced_steps.saturating_add(1);
        }
        Ok(result)
    }

    /// Execute a single instruction at the current `RIP`.
    ///
    /// # Errors
    /// Decode/execute failure, invalid memory, or host-stop hit.
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
        self.mem.map(address, size, perms)
    }

    fn mem_write(&mut self, address: u64, bytes: &[u8]) -> Result<(), CpuError> {
        self.mem.write(address, bytes)
    }

    fn mem_read(&mut self, address: u64, bytes: &mut [u8]) -> Result<(), CpuError> {
        self.mem.read(address, bytes)
    }

    fn virtual_alloc(
        &mut self,
        addr: u64,
        size: usize,
        alloc_type: u32,
        protect: u32,
    ) -> Result<u64, CpuError> {
        self.mem.virtual_alloc(addr, size, alloc_type, protect)
    }

    fn virtual_free(
        &mut self,
        addr: u64,
        size: usize,
        free_type: u32,
    ) -> Result<(), CpuError> {
        self.mem.virtual_free(addr, size, free_type)
    }

    fn virtual_protect(
        &mut self,
        addr: u64,
        size: usize,
        new_protect: u32,
    ) -> Result<u32, CpuError> {
        self.mem.virtual_protect(addr, size, new_protect)
    }

    fn virtual_query(&self, addr: u64) -> crate::MemoryBasicInformation {
        self.mem.virtual_query(addr)
    }

    fn mem_map_image(&mut self, address: u64, size: usize, perms: u32) -> Result<(), CpuError> {
        self.mem.map_image(address, size, perms)
    }

    fn register_region(&mut self, region: GuestRegion) {
        self.mem.register_region(region);
    }

    fn find_region(&self, va: u64) -> Option<GuestRegion> {
        self.mem.find_region(va).cloned()
    }

    fn cpu_stats(&self) -> Option<crate::JitStats> {
        // Pure iced backend: report step count in the shared stats shape.
        Some(crate::JitStats {
            iced_insns: self.iced_steps,
            ..crate::JitStats::default()
        })
    }

    fn mem_backend_name(&self) -> &'static str {
        self.mem.backend_name()
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
            // Unicorn: 0 means unlimited; keep a hard cap so a bug cannot hang forever.
            100_000_000_usize
        } else {
            count
        };

        let mut executed = 0_usize;
        while executed < budget {
            // Unicorn: stop when RIP reaches `until` (before executing that address).
            if until != 0 && self.regs.rip == until {
                break;
            }

            let rip_before = self.regs.rip;
            // Sampled RIP history (every 16th) — full every-insn ring was pure overhead
            // on the open-rom hot path (~97% emu wall). Fault path still has recent samples.
            if executed.is_multiple_of(16) {
                self.push_rip_trace(rip_before);
            }
            let hook_ref = self.hooks.as_ref();
            match exec::step(&mut self.mem, &mut self.regs, hook_ref) {
                Ok(StepResult::Continue) => {
                    executed = executed.saturating_add(1);
                    self.iced_steps = self.iced_steps.saturating_add(1);
                }
                Ok(StepResult::HostStop { address, size }) => {
                    return Ok(RunUntilHook {
                        code: CodeHookOutcome {
                            hit: true,
                            address,
                            size,
                        },
                        invalid_memory: InvalidMemoryAccess {
                            hit: false,
                            access_type: 0,
                            address: 0,
                            size: 0,
                            value: 0,
                        },
                    });
                }
                Ok(StepResult::InvalidMemory(inv)) => {
                    return Ok(RunUntilHook {
                        code: CodeHookOutcome {
                            hit: false,
                            address: 0,
                            size: 0,
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
                        .join(" → ");
                    let r = &self.regs;
                    return Err(CpuError::Message(format!(
                        "{e}; iced_regs rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} \
                         rsp={:#x} rbp={:#x} rsi={:#x} rdi={:#x} \
                         r8={:#x} r9={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}; \
                         iced_rip_trace=[{trace_s}]",
                        r.rax(),
                        r.rbx(),
                        r.rcx(),
                        r.rdx(),
                        r.rsp(),
                        r.rbp(),
                        r.rsi(),
                        r.rdi(),
                        r.r8(),
                        r.r9(),
                        r.gpr(12),
                        r.gpr(13),
                        r.gpr(14),
                        r.gpr(15),
                    )));
                }
            }
        }

        Ok(RunUntilHook {
            code: CodeHookOutcome {
                hit: false,
                address: 0,
                size: 0,
            },
            invalid_memory: InvalidMemoryAccess {
                hit: false,
                access_type: 0,
                address: 0,
                size: 0,
                value: 0,
            },
        })
    }

    fn return_from_win64_api(&mut self, rax: u64) -> Result<u64, CpuError> {
        let rsp = self.regs.rsp();
        let mut ret_bytes = [0_u8; 8];
        self.mem
            .read(rsp, &mut ret_bytes)
            .map_err(|e| CpuError::Message(format!("return_from_win64_api stack read: {e}")))?;
        let return_address = u64::from_le_bytes(ret_bytes);
        self.regs.set_rsp(rsp.wrapping_add(8));
        self.regs.set_rax(rax);
        self.regs.rip = return_address;
        Ok(return_address)
    }

    fn read_rip(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.rip)
    }
    fn write_rip(&mut self, value: u64) -> Result<(), CpuError> {
        self.regs.rip = value;
        Ok(())
    }
    fn read_rsp(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.rsp())
    }
    fn write_rsp(&mut self, value: u64) -> Result<(), CpuError> {
        self.regs.set_rsp(value);
        Ok(())
    }
    fn read_rax(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.rax())
    }
    fn write_rax(&mut self, value: u64) -> Result<(), CpuError> {
        self.regs.set_rax(value);
        Ok(())
    }
    fn read_rcx(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.rcx())
    }
    fn write_rcx(&mut self, value: u64) -> Result<(), CpuError> {
        self.regs.set_rcx(value);
        Ok(())
    }
    fn read_rdx(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.rdx())
    }
    fn write_rdx(&mut self, value: u64) -> Result<(), CpuError> {
        self.regs.set_rdx(value);
        Ok(())
    }
    fn read_r8(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.r8())
    }
    fn write_r8(&mut self, value: u64) -> Result<(), CpuError> {
        self.regs.set_r8(value);
        Ok(())
    }
    fn read_r9(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.r9())
    }
    fn write_r9(&mut self, value: u64) -> Result<(), CpuError> {
        self.regs.set_r9(value);
        Ok(())
    }
    fn read_rbx(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.gpr(3))
    }
    fn read_r12(&mut self) -> Result<u64, CpuError> {
        Ok(self.regs.gpr(12))
    }
}
