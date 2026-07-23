//! Host-side MSVC C++ EH tables (FuncInfo / try-block map).
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

/// One catch handler descriptor (`HandlerType`).
#[derive(Debug, Clone, Copy)]
pub struct HandlerType {
    pub adjectives: u32,
    /// RVA of `TypeDescriptor`, or 0 for catch-all (`...`).
    pub type_rva: u32,
    pub disp_catch_obj: i32,
    /// RVA of the catch handler code.
    pub handler_rva: u32,
}

/// Unwind-map entry: transition + optional destructor action.
#[derive(Debug, Clone, Copy)]
pub struct UnwindMapEntry {
    pub to_state: i32,
    /// RVA of destructor / cleanup function, or 0.
    pub action_rva: u32,
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

/// IP-to-state map entry (x64): `(Ip, State)` as two dwords (Ip is RVA).
fn state_for_ip(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    info: &FuncInfoHeader,
    control_pc: u64,
) -> Option<i32> {
    if info.n_ip_map == 0 || info.ip_to_state_map_rva == 0 {
        // No IP map: treat as state 0 (still allow try-block search).
        return Some(0);
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
    best_state.or(Some(-1))
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
    // x64 MSVC EH stores RVAs: HandlerType is 16 bytes
    // (adjectives, type RVA, dispCatchObj, handler RVA).
    let e = base.saturating_add(u64::from(index as u32).saturating_mul(16));
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
    })
}

/// Result of a successful MSVC catch match.
#[derive(Debug, Clone, Copy)]
pub struct MsvcCatch {
    pub landing_pad: u64,
    pub disp_catch_obj: i32,
    pub type_rva: u32,
    /// State at the throw site inside this function (for later dtor walk).
    pub state: i32,
    pub func_info: FuncInfoHeader,
}

/// Search `FuncInfo` for a catch covering `control_pc`.
///
/// Matching policy (MVP):
/// 1. Resolve EH state from IP map when present.
/// 2. For each try block whose `[tryLow, tryHigh]` covers the state, scan handlers.
/// 3. Accept catch-all (`type_rva == 0`) or any handler if `accept_any` is true.
/// 4. If IP map missing/unknown, still accept catch-all handlers in any try block
///    (best-effort for incomplete tables).
pub fn find_msvc_catch(
    read_mem: &mut MemRead<'_>,
    image_base: u64,
    func_info_va: u64,
    control_pc: u64,
    accept_any_typed: bool,
) -> Option<MsvcCatch> {
    let info = parse_func_info(read_mem, func_info_va)?;
    if info.n_try_blocks == 0 || info.try_block_map_rva == 0 {
        return None;
    }
    let state = state_for_ip(read_mem, image_base, &info, control_pc).unwrap_or(0);

    for ti in 0..info.n_try_blocks {
        let tb = read_try_block(read_mem, image_base, &info, ti)?;
        let state_in_try = state >= tb.try_low && state <= tb.try_high;
        // When state is unknown (-1) or IP map empty (0 with no coverage), still
        // consider catch-all so simple try/catch functions can recover.
        let consider = state_in_try || state < 0 || (state == 0 && info.n_ip_map == 0);
        if !consider {
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
            let is_catch_all = ht.type_rva == HT_CATCH_ALL_TYPE;
            if is_catch_all || accept_any_typed {
                return Some(MsvcCatch {
                    landing_pad: image_base.saturating_add(u64::from(ht.handler_rva)),
                    disp_catch_obj: ht.disp_catch_obj,
                    type_rva: ht.type_rva,
                    state,
                    func_info: info,
                });
            }
        }
    }
    None
}

/// Read one unwind-map entry.
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
        // magic v3 + zeros
        mem.write_bytes(0x1000, &FUNCINFO_MAGIC_V3.to_le_bytes());
        mem.write_bytes(0x1004, &0i32.to_le_bytes());
        let mut r = mem.reader();
        let h = parse_func_info(&mut r, 0x1000).expect("header");
        assert_eq!(h.magic, FUNCINFO_MAGIC_V3);
    }

    #[test]
    fn find_catch_all() {
        let mut mem = MemSim::new();
        let image = 0x14000_0000u64;
        // FuncInfo at image+0x2000
        let fi = image + 0x2000;
        mem.map(fi, 64);
        mem.write_bytes(fi, &FUNCINFO_MAGIC_V3.to_le_bytes());
        mem.write_bytes(fi + 4, &1i32.to_le_bytes()); // maxState
        mem.write_bytes(fi + 8, &0u32.to_le_bytes()); // unwind map
        mem.write_bytes(fi + 12, &1u32.to_le_bytes()); // nTryBlocks
        mem.write_bytes(fi + 16, &0x2100u32.to_le_bytes()); // try map rva
        mem.write_bytes(fi + 20, &0u32.to_le_bytes()); // nIPMap
        mem.write_bytes(fi + 24, &0u32.to_le_bytes());

        // TryBlockMap at image+0x2100
        let tb = image + 0x2100;
        mem.map(tb, 32);
        mem.write_bytes(tb, &0i32.to_le_bytes()); // tryLow
        mem.write_bytes(tb + 4, &0i32.to_le_bytes()); // tryHigh
        mem.write_bytes(tb + 8, &1i32.to_le_bytes()); // catchHigh
        mem.write_bytes(tb + 12, &1i32.to_le_bytes()); // nCatches
        mem.write_bytes(tb + 16, &0x2200u32.to_le_bytes()); // handlers

        // HandlerType catch-all at image+0x2200 (16-byte x64 layout)
        let ht = image + 0x2200;
        mem.map(ht, 32);
        mem.write_bytes(ht, &0u32.to_le_bytes()); // adjectives
        mem.write_bytes(ht + 4, &0u32.to_le_bytes()); // type = catch-all
        mem.write_bytes(ht + 8, &0i32.to_le_bytes()); // dispCatchObj
        mem.write_bytes(ht + 12, &0x5000u32.to_le_bytes()); // handler rva

        let mut r = mem.reader();
        let c = find_msvc_catch(&mut r, image, fi, image + 0x1000, false).expect("catch");
        assert_eq!(c.landing_pad, image + 0x5000);
    }
}
