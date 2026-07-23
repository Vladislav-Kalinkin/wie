//! SEH pipeline diagnostics: verify each layer independently.

#[cfg(test)]
mod tests {
    use crate::exception::*;
    use crate::exception_helpers::*;

    // ── Layer 1: .pdata parsing ────────────────────────────────────────

    #[test]
    fn parse_empty() { assert!(parse_pdata(&[]).is_empty()); }

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
        for &(b, e, u) in &[(0x2000u32, 0x2100u32, 0x3000u32), (0x1000u32, 0x1100u32, 0x4000u32)] {
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
        let b = register_table(&mut s, 0x14000_0000, vec![runtime_function(0x1000, 0x1100, 0x2000)]);
        let f = lookup_function_entry(&s, b + 0x1080).expect("hit");
        assert_eq!(f.entry.begin_address, 0x1000);
    }

    #[test]
    fn lookup_bsearch() {
        let mut s = crate::sync_obj::SyncState::new();
        let b = register_table(&mut s, 0x14000_0000, vec![
            runtime_function(0x1000, 0x1100, 0x2000),
            runtime_function(0x2000, 0x2500, 0x3000),
        ]);
        let f = lookup_function_entry(&s, b + 0x2100).expect("hit");
        assert_eq!(f.entry.begin_address, 0x2000);
    }

    #[test]
    fn lookup_miss() {
        let mut s = crate::sync_obj::SyncState::new();
        let b = register_table(&mut s, 0x14000_0000, vec![runtime_function(0x1000, 0x1100, 0x2000)]);
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
            version: 1, flags: UnwindInfo::FLAG_EHANDLER,
            size_of_prolog: 0, count_of_codes: 0,
            frame_register: 0, frame_offset: 0,
        };
        let codes: [(u8, UnwindCode); 0] = [];
        let xdata = encode_unwind(&info, &codes);
        mem.map(0x6000, xdata.len() + 8);
        mem.write_bytes(0x6000, &xdata);
        mem.write_u64(0x6000 + info.header_size() as u64, 0x3000); // handler_rva=0x3000

        let entry = runtime_function(0x1000, 0x1100, 0x6000);
        let ctx = unwind_ctx(0x401050, 0x1000);
        let r = virtual_unwind(&mut mem.reader(), 0, &entry, ctx).expect("unwind");
        assert_eq!(r.handler_rva, Some(0x3000));
    }
}