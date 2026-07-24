//! Host-side MSVC C++ EH tables (FuncInfo / try-block map / ThrowInfo).
//!
//! Layouts follow the publicly documented MSVC x64 exception model used by
//! `_CxxThrowException` / `__CxxFrameHandler*` (magic `0x1993052x`). Clean-room:
//! PE/COFF language data + widely documented structure field orders — no
//! third-party OS source.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::as_conversions
)]

use crate::exception::MemRead;

/// `FuncInfo.magicNumber` values used by MSVC C++ EH.
pub const FUNCINFO_MAGIC_V1: u32 = 0x1993_0520;
pub const FUNCINFO_MAGIC_V2: u32 = 0x1993_0521;
pub const FUNCINFO_MAGIC_V3: u32 = 0x1993_0522;

/// Catch-all adjective / null type descriptor: any thrown type matches.
const HT_CATCH_ALL_TYPE: u32 = 0;

/// `HandlerType.adjectives` bits (public MSVC EH docs).
pub const HT_IS_CONST: u32 = 0x01;
pub const HT_IS_VOLATILE: u32 = 0x02;
pub const HT_IS_UNALIGNED: u32 = 0x04;
pub const HT_IS_REFERENCE: u32 = 0x08;
pub const HT_IS_RESUMABLE: u32 = 0x10;
pub const HT_IS_STD_DOT_DOT: u32 = 0x40;

/// x64 `HandlerType` size: adjectives, type RVA, dispCatchObj, handler RVA, dispFrame.
const HANDLER_TYPE_SIZE: u64 = 20;

/// Minimal view of MSVC `FuncInfo` (first fields common to v1–v3).
#[derive(Debug, Clone, Copy)]
pub struct FuncInfoHeader {
    pub magic: u32,
    pub max_state: i32,
    pub unwind_map_rva: u32,
    pub n_try_blocks: u32,
    pub try_block_map_rva: u32,
    pub n_ip_map: u32,
    pub ip_to_state_map_rva: u32,
}

/// One try / catch region.
#[derive(Debug, Clone, Copy)]
pub struct TryBlockMapEntry {
    pub try_low: i32,
    pub try_high: i32,
    pub catch_high: i32,
    pub n_catches: i32,
    pub handler_array_rva: u32,
}

/// One catch handler descriptor (`HandlerType`, x64 relative form).
#[derive(Debug, Clone, Copy)]
pub struct HandlerType {
    pub adjectives: u32,
    /// RVA of `TypeDescriptor`, or 0 for catch-all (`...`).
    pub type_rva: u32,
    /// Byte displacement of the catch object from the establisher frame.
    pub disp_catch_obj: i32,
    /// RVA of the catch handler code.
    pub handler_rva: u32,
    /// Nested-frame displacement (x64); 0 when unused.
    pub disp_frame: i32,
}

/// Unwind-map entry: transition + optional destructor action.
#[derive(Debug, Clone, Copy)]
pub struct UnwindMapEntry {
    pub to_state: i32,
    /// RVA of destructor / cleanup function, or 0.
    pub action_rva: u32,
}

/// Result of a successful MSVC catch match.
#[derive(Debug, Clone, Copy)]
pub struct MsvcCatch {
    pub landing_pad: u64,
    pub disp_catch_obj: i32,
    pub adjectives: u32,
    pub type_rva: u32,
    /// Nested frame displacement from establisher (x64 `HandlerType.dispFrame`).
    pub disp_frame: i32,
    /// State at the throw site inside this function (for later dtor walk).
    pub state: i32,
    /// `tryLow` of the matched try block — UnwindMap target before entering catch.
    pub try_low: i32,
    pub func_info: FuncInfoHeader,
}

fn read_u32(read_mem: &mut MemRead<'_>, va: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    read_mem(va, &mut b).ok()?;
    Some(u32::from_le_bytes(b))
}

fn read_i32(read_mem: &mut MemRead<'_>, va: u64) -> Option<i32> {
    read_u32(read_mem, va).map(|u| i32::from_le_bytes(u.to_le_bytes()))
}

/// Parse `FuncInfo` header at guest VA. Returns `None` if magic unknown.
pub fn parse_func_info(read_mem: &mut MemRead<'_>, va: u64) -> Option<FuncInfoHeader> {
    let magic = read_u32(read_mem, va)?;
    if magic != FUNCINFO_MAGIC_V1 && magic != FUNCINFO_MAGIC_V2 && magic != FUNCINFO_MAGIC_V3 {
        return None;
    }
    Some(FuncInfoHeader {
        magic,
        max_state: read_i32(read_mem, va + 4)?,
        unwind_map_rva: read_u32(read_mem, va + 8)?,
        n_try_blocks: read_u32(read_mem, va + 12)?,
        try_block_map_rva: read_u32(read_mem, va + 16)?,
        n_ip_map: read_u32(read_mem, va + 20)?,
        ip_to_state_map_rva: read_u32(read_mem, va + 24)?,
    })
}

/// Exact IP-to-state lookup: last map entry with `Ip <= control_pc` RVA.
///
/// Returns `None` only when the table cannot be read. When the PC is before
/// the first entry, returns `-1` (no EH state). Empty map → `None` (caller
/// must not invent a state).
pub fn state_for_ip(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    info: &FuncInfoHeader,
    control_pc: u64,
) -> Option<i32> {
    if info.n_ip_map == 0 || info.ip_to_state_map_rva == 0 {
        return None;
    }
    let map_va = image_base.saturating_add(u64::from(info.ip_to_state_map_rva));
    let pc_rva = control_pc.saturating_sub(image_base) as u32;
    // Entries sorted by Ip; each is 8 bytes: Ip (u32 RVA) + State (i32).
    let mut best_state: Option<i32> = None;
    for i in 0..info.n_ip_map {
        let e = map_va.saturating_add(u64::from(i) * 8);
        let ip = read_u32(read_mem, e)?;
        let state = read_i32(read_mem, e + 4)?;
        if pc_rva >= ip {
            best_state = Some(state);
        } else {
            break;
        }
    }
    // PC before first entry → state -1 (outside any try).
    Some(best_state.unwrap_or(-1))
}

fn read_try_block(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    info: &FuncInfoHeader,
    index: u32,
) -> Option<TryBlockMapEntry> {
    let base = image_base.saturating_add(u64::from(info.try_block_map_rva));
    let e = base.saturating_add(u64::from(index) * 20);
    Some(TryBlockMapEntry {
        try_low: read_i32(read_mem, e)?,
        try_high: read_i32(read_mem, e + 4)?,
        catch_high: read_i32(read_mem, e + 8)?,
        n_catches: read_i32(read_mem, e + 12)?,
        handler_array_rva: read_u32(read_mem, e + 16)?,
    })
}

fn read_handler_type(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    array_rva: u32,
    index: i32,
) -> Option<HandlerType> {
    if index < 0 {
        return None;
    }
    let base = image_base.saturating_add(u64::from(array_rva));
    // x64 MSVC EH: 20-byte HandlerType (includes dispFrame).
    let e = base.saturating_add(u64::from(index as u32).saturating_mul(HANDLER_TYPE_SIZE));
    let handler_rva = read_u32(read_mem, e + 12)?;
    // Reject obvious non-RVA garbage (HRESULT-like high bits, null).
    if handler_rva == 0 || handler_rva >= 0x8000_0000 {
        return None;
    }
    Some(HandlerType {
        adjectives: read_u32(read_mem, e)?,
        type_rva: read_u32(read_mem, e + 4)?,
        disp_catch_obj: read_i32(read_mem, e + 8)?,
        handler_rva,
        disp_frame: read_i32(read_mem, e + 16).unwrap_or(0),
    })
}

/// Collect TypeDescriptor RVAs from `ThrowInfo.pCatchableTypeArray`.
///
/// `ThrowInfo` (x64, image-relative): attributes, pmfnUnwind, pForwardCompat,
/// pCatchableTypeArray — four dwords. Each CatchableType starts with
/// properties + type RVA.
pub fn throw_catchable_type_rvas(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    throw_info_va: u64,
) -> Option<Vec<u32>> {
    if throw_info_va == 0 {
        return None;
    }
    // pCatchableTypeArray at +12
    let cta_rva = read_u32(read_mem, throw_info_va.saturating_add(12))?;
    if cta_rva == 0 {
        return None;
    }
    let cta_va = image_base.saturating_add(u64::from(cta_rva));
    let n = read_i32(read_mem, cta_va)?;
    if n <= 0 || n > 64 {
        return None;
    }
    let mut out = Vec::with_capacity(n as usize);
    for i in 0..n {
        let ct_rva = read_u32(
            read_mem,
            cta_va
                .saturating_add(4)
                .saturating_add(u64::from(i as u32) * 4),
        )?;
        if ct_rva == 0 {
            continue;
        }
        let ct_va = image_base.saturating_add(u64::from(ct_rva));
        // CatchableType.pType at +4
        let type_rva = read_u32(read_mem, ct_va.saturating_add(4))?;
        if type_rva != 0 {
            out.push(type_rva);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// Optional size of the primary catchable type (for by-value copy).
pub fn throw_object_size(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    throw_info_va: u64,
) -> Option<u32> {
    if throw_info_va == 0 {
        return None;
    }
    let cta_rva = read_u32(read_mem, throw_info_va.saturating_add(12))?;
    if cta_rva == 0 {
        return None;
    }
    let cta_va = image_base.saturating_add(u64::from(cta_rva));
    let n = read_i32(read_mem, cta_va)?;
    if n <= 0 {
        return None;
    }
    let ct_rva = read_u32(read_mem, cta_va.saturating_add(4))?;
    if ct_rva == 0 {
        return None;
    }
    let ct_va = image_base.saturating_add(u64::from(ct_rva));
    // size at +20 (after props, pType, thisDisplacement[3])
    read_u32(read_mem, ct_va.saturating_add(20))
}

fn handler_matches(ht: &HandlerType, thrown_types: Option<&[u32]>) -> bool {
    if ht.type_rva == HT_CATCH_ALL_TYPE || (ht.adjectives & HT_IS_STD_DOT_DOT) != 0 {
        return true;
    }
    match thrown_types {
        Some(types) => types.contains(&ht.type_rva),
        // No ThrowInfo: only catch-all is safe (never guess a typed handler).
        None => false,
    }
}

/// Search `FuncInfo` for a catch covering `control_pc`.
///
/// Matching policy:
/// 1. Resolve **exact** EH state from IP map when present; if map missing, only
///    consider catch-all handlers (no invented state).
/// 2. For each try block whose `[tryLow, tryHigh]` covers the state, scan handlers
///    in order: first exact type match (via ThrowInfo CatchableType RVAs), else
///    catch-all (`type_rva == 0` / `HT_IsStdDotDot`).
/// 3. Never accept an arbitrary typed handler without a type match.
pub fn find_msvc_catch(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    func_info_va: u64,
    control_pc: u64,
    throw_info_va: u64,
) -> Option<MsvcCatch> {
    let info = parse_func_info(read_mem, func_info_va)?;
    if info.n_try_blocks == 0 || info.try_block_map_rva == 0 {
        return None;
    }

    let Some(state) = state_for_ip(read_mem, image_base, &info, control_pc) else {
        // No IP map: only catch-all in any try (rare for MSVC x64).
        return find_catch_all_any_try(read_mem, image_base, &info, -1);
    };

    let thrown_types = throw_catchable_type_rvas(read_mem, image_base, throw_info_va);

    // Two-pass over handlers in state-covered tries: typed match, then catch-all.
    let mut catch_all: Option<MsvcCatch> = None;

    for ti in 0..info.n_try_blocks {
        let tb = read_try_block(read_mem, image_base, &info, ti)?;
        if state < tb.try_low || state > tb.try_high {
            continue;
        }
        if tb.n_catches <= 0 || tb.handler_array_rva == 0 {
            continue;
        }
        for hi in 0..tb.n_catches {
            let ht = read_handler_type(read_mem, image_base, tb.handler_array_rva, hi)?;
            if ht.handler_rva == 0 {
                continue;
            }
            let is_catch_all =
                ht.type_rva == HT_CATCH_ALL_TYPE || (ht.adjectives & HT_IS_STD_DOT_DOT) != 0;
            if !is_catch_all {
                if handler_matches(&ht, thrown_types.as_deref()) {
                    return Some(MsvcCatch {
                        landing_pad: image_base.saturating_add(u64::from(ht.handler_rva)),
                        disp_catch_obj: ht.disp_catch_obj,
                        adjectives: ht.adjectives,
                        type_rva: ht.type_rva,
                        disp_frame: ht.disp_frame,
                        state,
                        try_low: tb.try_low,
                        func_info: info,
                    });
                }
            } else if catch_all.is_none() {
                catch_all = Some(MsvcCatch {
                    landing_pad: image_base.saturating_add(u64::from(ht.handler_rva)),
                    disp_catch_obj: ht.disp_catch_obj,
                    adjectives: ht.adjectives,
                    type_rva: ht.type_rva,
                    disp_frame: ht.disp_frame,
                    state,
                    try_low: tb.try_low,
                    func_info: info,
                });
            }
        }
    }
    catch_all
}

fn find_catch_all_any_try(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    info: &FuncInfoHeader,
    state: i32,
) -> Option<MsvcCatch> {
    for ti in 0..info.n_try_blocks {
        let tb = read_try_block(read_mem, image_base, info, ti)?;
        if tb.n_catches <= 0 || tb.handler_array_rva == 0 {
            continue;
        }
        for hi in 0..tb.n_catches {
            let ht = read_handler_type(read_mem, image_base, tb.handler_array_rva, hi)?;
            let is_catch_all =
                ht.type_rva == HT_CATCH_ALL_TYPE || (ht.adjectives & HT_IS_STD_DOT_DOT) != 0;
            if is_catch_all && ht.handler_rva != 0 {
                return Some(MsvcCatch {
                    landing_pad: image_base.saturating_add(u64::from(ht.handler_rva)),
                    disp_catch_obj: ht.disp_catch_obj,
                    adjectives: ht.adjectives,
                    type_rva: ht.type_rva,
                    disp_frame: ht.disp_frame,
                    state,
                    try_low: tb.try_low,
                    func_info: *info,
                });
            }
        }
    }
    None
}

/// Read one unwind-map entry for `state` (index into the map).
pub fn read_unwind_map_entry(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    unwind_map_rva: u32,
    state: i32,
) -> Option<UnwindMapEntry> {
    if state < 0 || unwind_map_rva == 0 {
        return None;
    }
    let base = image_base.saturating_add(u64::from(unwind_map_rva));
    let e = base.saturating_add(u64::from(state as u32) * 8);
    Some(UnwindMapEntry {
        to_state: read_i32(read_mem, e)?,
        action_rva: read_u32(read_mem, e + 4)?,
    })
}

/// Walk UnwindMap from `from_state` down toward `to_state` (exclusive of `to_state`
/// when `to_state >= -1`). Collects cleanup action RVAs in destruction order.
///
/// Does not execute actions — the dispatcher decides how to call guest code.
pub fn collect_unwind_actions(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    unwind_map_rva: u32,
    max_state: i32,
    from_state: i32,
    to_state: i32,
) -> Vec<u32> {
    let mut actions = Vec::new();
    if unwind_map_rva == 0 || from_state < 0 {
        return actions;
    }
    let mut state = from_state;
    // Bound iterations to avoid cycles from corrupt tables.
    for _ in 0..64 {
        if state < 0 || state <= to_state {
            break;
        }
        if max_state > 0 && state >= max_state {
            break;
        }
        let Some(entry) = read_unwind_map_entry(read_mem, image_base, unwind_map_rva, state) else {
            break;
        };
        if entry.action_rva != 0 {
            actions.push(entry.action_rva);
        }
        if entry.to_state >= state {
            // Corrupt / non-progressing map.
            break;
        }
        state = entry.to_state;
    }
    actions
}

/// Compute the catch-object address for writing the exception pointer / value.
///
/// `establisher_frame` is the fixed stack frame base of the catching function
/// (RSP after prologue for typical frames). When `disp_frame` is a small positive
/// nested-frame offset that looks like a pointer slot, nested handling may read
/// an outer frame; for the common non-nested case `disp_frame` is a stack size
/// constant and is ignored (object is at `establisher + disp_catch_obj`).
pub fn catch_object_address(establisher_frame: u64, catch: &MsvcCatch) -> Option<u64> {
    if catch.disp_catch_obj == 0 {
        return None;
    }
    let disp = i64::from(catch.disp_catch_obj);
    let base = establisher_frame.cast_signed();
    let addr = base.saturating_add(disp);
    if addr <= 0 {
        return None;
    }
    Some(addr.cast_unsigned())
}

/// Whether the catch expects a pointer (reference / catch-all object slot)
/// rather than a by-value copy.
#[must_use]
pub fn catch_is_reference(adjectives: u32) -> bool {
    (adjectives & HT_IS_REFERENCE) != 0
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::unreadable_literal,
        clippy::unusual_byte_groupings
    )]

    use super::*;
    use crate::exception_helpers::MemSim;

    #[test]
    fn parse_func_info_magic() {
        let mut mem = MemSim::new();
        mem.map(0x1000, 64);
        mem.write_bytes(0x1000, &FUNCINFO_MAGIC_V3.to_le_bytes());
        mem.write_bytes(0x1004, &0i32.to_le_bytes());
        let mut r = mem.reader();
        let h = parse_func_info(&mut r, 0x1000).expect("header");
        assert_eq!(h.magic, FUNCINFO_MAGIC_V3);
    }

    #[test]
    fn find_catch_all_with_ip_map() {
        let mut mem = MemSim::new();
        let image = 0x14000_0000u64;
        let fi = image + 0x2000;
        mem.map(fi, 64);
        mem.write_bytes(fi, &FUNCINFO_MAGIC_V3.to_le_bytes());
        mem.write_bytes(fi + 4, &1i32.to_le_bytes()); // maxState
        mem.write_bytes(fi + 8, &0u32.to_le_bytes()); // unwind map
        mem.write_bytes(fi + 12, &1u32.to_le_bytes()); // nTryBlocks
        mem.write_bytes(fi + 16, &0x2100u32.to_le_bytes()); // try map rva
        mem.write_bytes(fi + 20, &2u32.to_le_bytes()); // nIPMap
        mem.write_bytes(fi + 24, &0x2300u32.to_le_bytes()); // ip map rva

        // IP map: [0x1000 → -1], [0x1010 → 0]
        let ipm = image + 0x2300;
        mem.map(ipm, 32);
        mem.write_bytes(ipm, &0x1000u32.to_le_bytes());
        mem.write_bytes(ipm + 4, &(-1i32).to_le_bytes());
        mem.write_bytes(ipm + 8, &0x1010u32.to_le_bytes());
        mem.write_bytes(ipm + 12, &0i32.to_le_bytes());

        // TryBlockMap at image+0x2100: tryLow=0 tryHigh=0
        let tb = image + 0x2100;
        mem.map(tb, 32);
        mem.write_bytes(tb, &0i32.to_le_bytes());
        mem.write_bytes(tb + 4, &0i32.to_le_bytes());
        mem.write_bytes(tb + 8, &1i32.to_le_bytes());
        mem.write_bytes(tb + 12, &1i32.to_le_bytes());
        mem.write_bytes(tb + 16, &0x2200u32.to_le_bytes());

        // HandlerType catch-all, 20-byte x64 layout
        let ht = image + 0x2200;
        mem.map(ht, 32);
        mem.write_bytes(ht, &HT_IS_STD_DOT_DOT.to_le_bytes());
        mem.write_bytes(ht + 4, &0u32.to_le_bytes());
        mem.write_bytes(ht + 8, &0i32.to_le_bytes());
        mem.write_bytes(ht + 12, &0x5000u32.to_le_bytes());
        mem.write_bytes(ht + 16, &0i32.to_le_bytes());

        let mut r = mem.reader();
        // PC in try → state 0
        let c = find_msvc_catch(&mut r, image, fi, image + 0x1010, 0).expect("catch");
        assert_eq!(c.landing_pad, image + 0x5000);
        assert_eq!(c.state, 0);

        // PC before try → state -1 → no catch
        let mut r = mem.reader();
        assert!(find_msvc_catch(&mut r, image, fi, image + 0x1000, 0).is_none());
    }

    #[test]
    fn typed_match_prefers_correct_handler_not_first() {
        let mut mem = MemSim::new();
        let image = 0x14000_0000u64;
        let fi = image + 0x2000;
        mem.map(fi, 64);
        mem.write_bytes(fi, &FUNCINFO_MAGIC_V1.to_le_bytes());
        mem.write_bytes(fi + 4, &2i32.to_le_bytes());
        mem.write_bytes(fi + 8, &0u32.to_le_bytes());
        mem.write_bytes(fi + 12, &1u32.to_le_bytes());
        mem.write_bytes(fi + 16, &0x2100u32.to_le_bytes());
        mem.write_bytes(fi + 20, &1u32.to_le_bytes());
        mem.write_bytes(fi + 24, &0x2300u32.to_le_bytes());

        let ipm = image + 0x2300;
        mem.map(ipm, 16);
        mem.write_bytes(ipm, &0x1000u32.to_le_bytes());
        mem.write_bytes(ipm + 4, &1i32.to_le_bytes());

        let tb = image + 0x2100;
        mem.map(tb, 32);
        mem.write_bytes(tb, &1i32.to_le_bytes()); // tryLow
        mem.write_bytes(tb + 4, &1i32.to_le_bytes()); // tryHigh
        mem.write_bytes(tb + 8, &2i32.to_le_bytes());
        mem.write_bytes(tb + 12, &2i32.to_le_bytes()); // nCatches
        mem.write_bytes(tb + 16, &0x2200u32.to_le_bytes());

        // Two handlers: wrong type first, correct type second (dispCatch=48)
        let ht = image + 0x2200;
        mem.map(ht, 64);
        // h0 wrong
        mem.write_bytes(ht, &(HT_IS_CONST | HT_IS_REFERENCE).to_le_bytes());
        mem.write_bytes(ht + 4, &0xAAAAu32.to_le_bytes());
        mem.write_bytes(ht + 8, &0i32.to_le_bytes());
        mem.write_bytes(ht + 12, &0x5000u32.to_le_bytes());
        mem.write_bytes(ht + 16, &56i32.to_le_bytes());
        // h1 correct CSystemException-like
        mem.write_bytes(ht + 20, &(HT_IS_CONST | HT_IS_REFERENCE).to_le_bytes());
        mem.write_bytes(ht + 24, &0x1340_a8u32.to_le_bytes());
        mem.write_bytes(ht + 28, &48i32.to_le_bytes());
        mem.write_bytes(ht + 32, &0x5dba4u32.to_le_bytes());
        mem.write_bytes(ht + 36, &72i32.to_le_bytes());

        // ThrowInfo + CatchableTypeArray for type 0x1340a8
        let ti = image + 0x3000;
        mem.map(ti, 64);
        mem.write_bytes(ti, &0u32.to_le_bytes()); // attributes
        mem.write_bytes(ti + 4, &0u32.to_le_bytes());
        mem.write_bytes(ti + 8, &0u32.to_le_bytes());
        mem.write_bytes(ti + 12, &0x3100u32.to_le_bytes()); // CTA rva
        let cta = image + 0x3100;
        mem.map(cta, 32);
        mem.write_bytes(cta, &1i32.to_le_bytes());
        mem.write_bytes(cta + 4, &0x3200u32.to_le_bytes()); // CT rva
        let ct = image + 0x3200;
        mem.map(ct, 32);
        mem.write_bytes(ct, &0u32.to_le_bytes()); // props
        mem.write_bytes(ct + 4, &0x1340_a8u32.to_le_bytes()); // type
        mem.write_bytes(ct + 20, &4u32.to_le_bytes()); // size

        let mut r = mem.reader();
        let c = find_msvc_catch(&mut r, image, fi, image + 0x1000, ti).expect("typed catch");
        assert_eq!(c.landing_pad, image + 0x5dba4);
        assert_eq!(c.disp_catch_obj, 48);
        assert_eq!(c.type_rva, 0x1340_a8);
    }

    #[test]
    fn state_for_ip_exact() {
        let mut mem = MemSim::new();
        let image = 0x400000u64;
        let fi_hdr = FuncInfoHeader {
            magic: FUNCINFO_MAGIC_V1,
            max_state: 2,
            unwind_map_rva: 0,
            n_try_blocks: 0,
            try_block_map_rva: 0,
            n_ip_map: 4,
            ip_to_state_map_rva: 0x1000,
        };
        let map = image + 0x1000;
        mem.map(map, 64);
        // Real 7za-like map pattern
        let entries = [
            (0x14d08u32, -1i32),
            (0x14d21, 0),
            (0x14e2f, -1),
            (0x14e34, 0),
        ];
        for (i, (ip, st)) in entries.iter().enumerate() {
            let e = map + (i as u64) * 8;
            mem.write_bytes(e, &ip.to_le_bytes());
            mem.write_bytes(e + 4, &st.to_le_bytes());
        }
        let mut r = mem.reader();
        assert_eq!(
            state_for_ip(&mut r, image, &fi_hdr, image + 0x14d08),
            Some(-1)
        );
        assert_eq!(
            state_for_ip(&mut r, image, &fi_hdr, image + 0x14d21),
            Some(0)
        );
        assert_eq!(
            state_for_ip(&mut r, image, &fi_hdr, image + 0x14d30),
            Some(0)
        );
        assert_eq!(
            state_for_ip(&mut r, image, &fi_hdr, image + 0x14e2f),
            Some(-1)
        );
        assert_eq!(
            state_for_ip(&mut r, image, &fi_hdr, image + 0x14e40),
            Some(0)
        );
    }

    #[test]
    fn collect_unwind_actions_order() {
        let mut mem = MemSim::new();
        let image = 0x400000u64;
        let map = image + 0x2000;
        mem.map(map, 64);
        // state0 → -1 action 0
        mem.write_bytes(map, &(-1i32).to_le_bytes());
        mem.write_bytes(map + 4, &0u32.to_le_bytes());
        // state1 → 0 action 0x1000
        mem.write_bytes(map + 8, &0i32.to_le_bytes());
        mem.write_bytes(map + 12, &0x1000u32.to_le_bytes());
        // state2 → 1 action 0x2000
        mem.write_bytes(map + 16, &1i32.to_le_bytes());
        mem.write_bytes(map + 20, &0x2000u32.to_le_bytes());

        let mut r = mem.reader();
        let acts = collect_unwind_actions(&mut r, image, 0x2000, 3, 2, -1);
        assert_eq!(acts, vec![0x2000, 0x1000]);
    }

    #[test]
    fn catch_object_address_disp() {
        let c = MsvcCatch {
            landing_pad: 0,
            disp_catch_obj: 48,
            adjectives: HT_IS_REFERENCE,
            type_rva: 1,
            disp_frame: 72,
            state: 1,
            try_low: 1,
            func_info: FuncInfoHeader {
                magic: FUNCINFO_MAGIC_V1,
                max_state: 0,
                unwind_map_rva: 0,
                n_try_blocks: 0,
                try_block_map_rva: 0,
                n_ip_map: 0,
                ip_to_state_map_rva: 0,
            },
        };
        assert_eq!(
            catch_object_address(0x207f_e000, &c),
            Some(0x207f_e000 + 48)
        );
        assert!(catch_is_reference(HT_IS_CONST | HT_IS_REFERENCE));
    }
}
