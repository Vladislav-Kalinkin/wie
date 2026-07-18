# Phase 5.5 – Neon Soft-Accel & Cranelift ISA Tuning

**Date:** 2026-07-18  
**Depends on:** Phase 4–5 (sticky TLB, string bulk, guest stubs).  
**Before:** Phase 6 (Idle CPU Management).  
**Scope:** ARM64 Neon acceleration for SSE2, set-associative software TLB, inline small REP strings, Cranelift target flags for Apple Silicon.

## Invariants (unchanged)

1. Guest VA ≠ Host VA — soft-translate only.
2. SPC + `mem_gen` on sticky / pin / `host_span` / TLB install.
3. No W soft-translate onto executable pages.
4. Clean-room: public docs only (Microsoft Learn, ARM ARM, Cranelift).

## Track A – SSE2 → Cranelift SIMD (Neon Q-regs)

| Item | Detail |
| ---- | ------ |
| Bank | `XmmSlot` (`#[repr(C, align(16))]`, lo/hi `u64`) × 16 |
| IR | `load/store.i8x16` + `bitcast` to `I64X2` / `F32X4` / `F64X2` when `WIE_JIT_SIMD≠0` |
| Bitwise | `band` / `bor` / `bxor` / `bnot` on `I8X16` |
| Scalar/packed FP | native `fadd`/`fsub`/`fmul`/`fdiv` (no host helper when SIMD on) |
| Live/dirty | `CompiledBlock.xmm_live_mask` / `xmm_may_def_mask`; `JitCtx.xmm_dirty_bits` |
| Entry | load only live XMMs; pure GPR still skips bank |
| Exit | write back dirty (or may_def on fault) |

**Kill-switch:** `WIE_JIT_SIMD=0` → legacy dual-`I64` path + FP helpers.

## Track B – Set-associative Neon TLB

| Item | Detail |
| ---- | ------ |
| Geometry | `TLB_SETS=16` × `TLB_WAYS_PER_SET=4` |
| Layout | `TlbBucket` (`tags[4]`, `host[4]`, align 16); `TlbBucketAux` (`generation[4]`, `prot[4]`, `rr`) |
| Lookup order | sticky → set-assoc probe → pin → page walk |
| Neon | `vdupq_n_u64` + 2× `vceqq_u64` → way bitmask (`cfg(aarch64)`) |
| Tags | full `u64` page keys (no 32-bit compress) |

**Kill-switch:** `WIE_TLB_NEON=0` → scalar 4-way scan.

## Track C – Inline REP MOVS/STOS (16–64 B)

| Item | Detail |
| ---- | ------ |
| Helper | `wie_jit_host_span(ctx, va, len, write) → host_or_0` |
| Eligibility | REP MOVS/STOS, DF=0 at runtime, `byte_len ∈ [16,64]`, soft span ok |
| Fast path | unrolled up to 4× `I8X16` load/store (MOVS) or splat fill (STOS) |
| Slow path | existing `wie_jit_string` / Phase 4.3 bulk |
| Overlap / DF=1 | stay on helper / element loop |

**Kill-switch:** `WIE_STRING_INLINE=0`.

## Track D – Cranelift flags (Apple Silicon)

| Flag | Value |
| ---- | ----- |
| `opt_level` | `speed` (override: `WIE_JIT_OPT=speed\|speed_and_size\|none`) |
| `enable_verifier` | `true` under `cfg(test)` or `WIE_JIT_VERIFY=1` |
| `is_pic` / `enable_probestack` | `false` |
| `unwind_info` | `false` |
| `enable_heap_access_spectre_mitigation` | `false` |
| macOS aarch64 ISA | re-assert `sign_return_address`, `…_with_bkey`, `has_pauth` |

Neon is **not** a settings bit — enabled by emitting SIMD IR types.

## Environment knobs

```bash
WIE_JIT_OPT=speed|speed_and_size|none
WIE_JIT_VERIFY=1
WIE_JIT_SIMD=0          # scalar XMM path
WIE_TLB_NEON=0          # scalar set-assoc TLB
WIE_STRING_INLINE=0     # no dual-path inline strings
WIE_STRING_BULK=0       # Phase 4.3 host-span bulk off
```

## Verification

```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p wie-cpu
WIE_MEM=hybrid ./scripts/run-micro-suite.sh
WIE_JIT_SIMD=0 WIE_TLB_NEON=0 WIE_STRING_INLINE=0 ./scripts/run-micro-suite.sh
```

## Related

- Roadmap: [`Optimization ROADMAP.md`](../Optimization%20ROADMAP.md)
- String bulk (4.3): [`phase4-string-bulk.md`](phase4-string-bulk.md)
- TLB foundation (4.0): [`phase4-foundation.md`](phase4-foundation.md)
