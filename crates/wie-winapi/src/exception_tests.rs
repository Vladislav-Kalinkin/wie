//! SEH pipeline diagnostics: verify each layer independently.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::unreadable_literal,
    clippy::unusual_byte_groupings
)]

#[cfg(test)]
mod tests {
    use crate::exception::*;
    use crate::exception_helpers::*;

    // ── Layer 1: .pdata parsing ────────────────────────────────────────

    #[test]
    fn parse_empty() {
        assert!(parse_pdata(&[]).is_empty());
    }

    #[test]
    fn parse_one() {
        let raw: [u8; 12] = [
            0x00, 0x10, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00,
        ];
        let e = parse_pdata(&raw);
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].begin_address, 0x1000);
        assert_eq!(e[0].end_address, 0x1100);
    }

    #[test]
    fn parse_unsorted_input_keeps_order() {
        // .pdata from linker is pre-sorted.  We don't re-sort.
        let mut raw = Vec::new();
        for &(b, e, u) in &[
            (0x2000u32, 0x2100u32, 0x3000u32),
            (0x1000u32, 0x1100u32, 0x4000u32),
        ] {
            raw.extend_from_slice(&b.to_le_bytes());
            raw.extend_from_slice(&e.to_le_bytes());
            raw.extend_from_slice(&u.to_le_bytes());
        }
        let entries = parse_pdata(&raw);
        assert_eq!(entries.len(), 2);
        // In insertion order: (2000, 1000)
        assert_eq!(entries[0].begin_address, 0x2000);
        assert_eq!(entries[1].begin_address, 0x1000);
    }

    // ── Layer 1: function table lookup ──────────────────────────────────

    #[test]
    fn lookup_hit() {
        let mut s = crate::sync_obj::SyncState::new();
        let b = register_table(
            &mut s,
            0x14000_0000,
            vec![runtime_function(0x1000, 0x1100, 0x2000)],
        );
        let f = lookup_function_entry(&s, b + 0x1080).expect("hit");
        assert_eq!(f.entry.begin_address, 0x1000);
    }

    #[test]
    fn lookup_bsearch() {
        let mut s = crate::sync_obj::SyncState::new();
        let b = register_table(
            &mut s,
            0x14000_0000,
            vec![
                runtime_function(0x1000, 0x1100, 0x2000),
                runtime_function(0x2000, 0x2500, 0x3000),
            ],
        );
        let f = lookup_function_entry(&s, b + 0x2100).expect("hit");
        assert_eq!(f.entry.begin_address, 0x2000);
    }

    #[test]
    fn lookup_miss() {
        let mut s = crate::sync_obj::SyncState::new();
        let b = register_table(
            &mut s,
            0x14000_0000,
            vec![runtime_function(0x1000, 0x1100, 0x2000)],
        );
        assert!(lookup_function_entry(&s, b + 0x0500).is_none());
    }

    // ── Layer 2: UNWIND_INFO parsing ────────────────────────────────────

    #[test]
    fn info_no_handler() {
        let raw: [u8; 4] = [0x01, 0x08, 0x02, 0x00];
        let i = UnwindInfo::from_bytes(&raw, 0).expect("parse");
        assert_eq!(i.version, 1);
        assert_eq!(i.flags, 0);
        assert_eq!(i.count_of_codes, 2);
        assert_eq!(i.header_size(), 4 + 4);
    }

    #[test]
    fn info_with_handler() {
        let raw: [u8; 4] = [0x09, 0x04, 0x01, 0x00];
        let i = UnwindInfo::from_bytes(&raw, 0).expect("parse");
        assert_eq!(i.flags, 1);
        assert_eq!(i.header_size(), 8);
        assert_eq!(i.total_size(), 16);
    }

    // ── Layer 2: virtual unwinding ──────────────────────────────────────

    #[test]
    fn unwind_leaf() {
        let mut mem = MemSim::new();
        mem.map(0x1000, 16);
        mem.write_u64(0x1000, 0x401000);

        let entry = runtime_function(0x1000, 0x1001, 0);
        let ctx = unwind_ctx(0x401000, 0x1000);
        let r = virtual_unwind(&mut mem.reader(), 0, &entry, ctx).expect("unwind");
        assert_eq!(r.ctx.rip, 0x401000);
        assert_eq!(r.ctx.rsp, 0x1008);
        assert!(r.handler_rva.is_none());
    }

    #[test]
    fn unwind_push_nonvol_and_alloc() {
        let codes: [(u8, UnwindCode); 2] = [
            at(alloc_small(0x20), 2), // sub rsp,0x20 (offset 2)
            at(push_nonvol(3), 4),    // push rbx (offset 4)
        ];
        let info = unwind_info(&codes, 0, 8, 0, 0);
        let xdata = encode_unwind(&info, &codes);

        // Stack layout (RSP=0x2000 after prologue):
        //   [0x2028] = return addr, [0x2020] = saved RBX
        let mut mem = MemSim::new();
        mem.map(0x2000, 0x100);
        mem.map(0x6000, xdata.len());
        mem.write_u64(0x2028, 0x401000);
        mem.write_u64(0x2020, 0xDEAD_BEEF);
        // Write xdata bytes into the simulated region.
        mem.write_bytes(0x6000, &xdata);

        let entry = runtime_function(0x1000, 0x1100, 0x6000);
        let ctx = unwind_ctx(0x401050, 0x2000);
        let r = virtual_unwind(&mut mem.reader(), 0, &entry, ctx).expect("unwind");

        assert_eq!(r.ctx.gpr[3], 0xDEAD_BEEF, "RBX restored");
        assert_eq!(r.ctx.rsp, 0x2030, "caller RSP");
        assert_eq!(r.ctx.rip, 0x401000, "caller RIP");
        assert!(r.handler_rva.is_none());
    }

    #[test]
    fn handler_flag_returns_handler_rva() {
        let mut mem = MemSim::new();
        mem.map(0x1000, 16);
        mem.write_u64(0x1000, 0x401000);
        let info = UnwindInfo {
            version: 1,
            flags: UnwindInfo::FLAG_EHANDLER,
            size_of_prolog: 0,
            count_of_codes: 0,
            frame_register: 0,
            frame_offset: 0,
        };
        let codes: [(u8, UnwindCode); 0] = [];
        let xdata = encode_unwind(&info, &codes);
        mem.map(0x6000, xdata.len() + 8);
        mem.write_bytes(0x6000, &xdata);
        // handler_rva at +0, language_data at +4
        mem.write_bytes(0x6000 + info.header_size() as u64, &0x3000u32.to_le_bytes());
        mem.write_bytes(
            0x6000 + info.header_size() as u64 + 4,
            &0x4000u32.to_le_bytes(),
        );

        let entry = runtime_function(0x1000, 0x1100, 0x6000);
        let ctx = unwind_ctx(0x401050, 0x1000);
        let r = virtual_unwind(&mut mem.reader(), 0, &entry, ctx).expect("unwind");
        assert_eq!(r.handler_rva, Some(0x3000));
        assert_eq!(r.handler_data, Some(0x4000));
    }

    #[test]
    fn multi_frame_restore_nonvolatiles() {
        // Outer: push rbx; sub rsp,0x20  — saved RBX = 0xAAAA
        // Inner: push rbp; sub rsp,0x10  — saved RBP = 0xBBBB
        // Unwind inner then outer: RBX and RBP restored.
        let outer_codes = [
            at(alloc_small(0x20), 2),
            at(push_nonvol(3), 4), // RBX
        ];
        let outer_info = unwind_info(&outer_codes, 0, 8, 0, 0);
        let outer_xdata = encode_unwind(&outer_info, &outer_codes);

        let inner_codes = [
            at(alloc_small(0x10), 2),
            at(push_nonvol(5), 4), // RBP
        ];
        let inner_info = unwind_info(&inner_codes, 0, 8, 0, 0);
        let inner_xdata = encode_unwind(&inner_info, &inner_codes);

        let mut mem = MemSim::new();
        // Stack (high → low): [ret_to_main][saved RBX][outer frame 0x20][ret_to_outer][saved RBP][inner 0x10]
        // Inner RSP after prologue = 0x2000
        //   0x2000..0x2010 alloc, 0x2010 saved RBP, 0x2018 ret to outer
        // Outer after prologue would have been 0x2020:
        //   0x2020..0x2040 alloc, 0x2040 saved RBX, 0x2048 ret to main
        mem.map(0x2000, 0x100);
        mem.write_u64(0x2010, 0xBBBB); // saved RBP
        mem.write_u64(0x2018, 0x401_100); // return to outer body
        mem.write_u64(0x2040, 0xAAAA); // saved RBX
        mem.write_u64(0x2048, 0x401_000); // return to main

        mem.map(0x6000, outer_xdata.len());
        mem.write_bytes(0x6000, &outer_xdata);
        mem.map(0x6100, inner_xdata.len());
        mem.write_bytes(0x6100, &inner_xdata);

        let outer_entry = runtime_function(0x1000, 0x1100, 0x6000);
        let inner_entry = runtime_function(0x1200, 0x1300, 0x6100);

        let ctx = unwind_ctx(0x401_250, 0x2000);
        let r1 = virtual_unwind(&mut mem.reader(), 0, &inner_entry, ctx).expect("inner");
        assert_eq!(r1.ctx.gpr[5], 0xBBBB, "RBP restored from inner");
        assert_eq!(r1.ctx.rip, 0x401_100);
        assert_eq!(r1.ctx.rsp, 0x2020);

        let r2 = virtual_unwind(&mut mem.reader(), 0, &outer_entry, r1.ctx).expect("outer");
        assert_eq!(r2.ctx.gpr[3], 0xAAAA, "RBX restored from outer");
        assert_eq!(r2.ctx.gpr[5], 0xBBBB, "RBP preserved");
        assert_eq!(r2.ctx.rip, 0x401_000);
        assert_eq!(r2.ctx.rsp, 0x2050);
    }

    #[test]
    fn language_data_candidates_dedup_paths() {
        let c = language_data_candidates(0x14000_0000, 0x14000_5000, 0x20, None);
        assert_eq!(c[0], 0x14000_0020); // image + rva
        assert_eq!(c[1], 0x14000_5020); // unwind + full
        // low16 collapses with full when high half is 0
        assert_eq!(c.len(), 2);
    }

    #[test]
    fn language_data_candidates_prefers_embedded_lsda() {
        let emb = 0x14000_5010u64;
        let c = language_data_candidates(0x14000_0000, 0x14000_5000, 0x20, Some(emb));
        assert_eq!(c[0], emb);
        assert!(c.contains(&0x14000_0020));
    }

    /// Real Mingw-style LSDA: uleb call sites + catch-all action (filter 0).
    #[test]
    fn lsda_mingw_uleb_call_site_ip_minus_one() {
        // lp=omit, ttype=udata4 abs (no pcrel), cs=uleb
        // call site: start=0x3a len=5 lp=0x3f action=1
        // action@1: filter=0 (catch-all), next=0
        // type table empty (catch-all does not read it)
        let lsda = vec![
            0xff, // lp omit
            0x03, // ttype udata4
            0x04, // ttype base offset → past call-site+action
            0x01, // cs uleb128
            0x08, // cs len
            0x3a, 0x05, 0x3f, 0x01, // site 0
            0x47, 0x22, 0x00, 0x00, // site 1 (no lp)
            0x00, 0x00, // action: filter=0, next=0
            // type table padding so base offset lands after actions
            0x00, 0x00, 0x00, 0x00,
        ];
        let base = 0x2000u64;
        let mut mem = MemSim::new();
        mem.map(base, lsda.len() + 16);
        mem.write_bytes(base, &lsda);
        let func = 0x1400_73e0u64;
        // Return address after call = func+0x3f → needs IP-1 to hit [0x3a,0x3f)
        let mut r = mem.reader();
        let m = find_landing_pad_ex(&mut r, base, 0x14000_0000, func, func + 0x3f, None)
            .expect("landing pad");
        assert_eq!(m.landing_pad, func + 0x3f);
        assert_eq!(m.switch_value, 0);
    }

    #[test]
    fn lsda_cleanup_only_not_a_catch() {
        // action_index 0 + landing pad = cleanup; search must ignore it.
        let lsda = vec![
            0xff, 0xff, 0x01, 0x04, // omit omit uleb len=4
            0x3a, 0x05, 0x3b, 0x00, // site with cleanup lp, act=0
        ];
        let base = 0x3000u64;
        let mut mem = MemSim::new();
        mem.map(base, 32);
        mem.write_bytes(base, &lsda);
        let func = 0x1000u64;
        let mut r = mem.reader();
        assert!(find_landing_pad_ex(&mut r, base, 0, func, func + 0x3f, None).is_none());
        let mut r = mem.reader();
        let c = find_cleanup_landing_pad(&mut r, base, 0, func, func + 0x3f).expect("cleanup");
        assert_eq!(c.landing_pad, func + 0x3b);
    }
}
