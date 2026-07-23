//! SEH pipeline diagnostics: verify each layer independently.

#[cfg(test)]
mod tests {
    use crate::exception::*;

    // ── Layer 1: .pdata parsing ────────────────────────────────────────

    #[test]
    fn parse_empty_pdata() {
        let entries = parse_pdata(&[]);
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_pdata_one_entry() {
        // One RUNTIME_FUNCTION: begin=0x1000, end=0x1100, unwind=0x2000
        let raw: [u8; 12] = [
            0x00, 0x10, 0x00, 0x00, // begin_address
            0x00, 0x11, 0x00, 0x00, // end_address
            0x00, 0x20, 0x00, 0x00, // unwind_data
        ];
        let entries = parse_pdata(&raw);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].begin_address, 0x1000);
        assert_eq!(entries[0].end_address, 0x1100);
        assert_eq!(entries[0].unwind_data, 0x2000);
    }

    #[test]
    fn parse_pdata_multiple_entries_sorted() {
        // Two entries: (0x2000..0x2100) then (0x1000..0x1100)
        let mut raw = Vec::new();
        raw.extend_from_slice(&0x0000_2000_u32.to_le_bytes()); // begin
        raw.extend_from_slice(&0x0000_2100_u32.to_le_bytes()); // end
        raw.extend_from_slice(&0x0000_3000_u32.to_le_bytes()); // unwind
        raw.extend_from_slice(&0x0000_1000_u32.to_le_bytes()); // begin
        raw.extend_from_slice(&0x0000_1100_u32.to_le_bytes()); // end
        raw.extend_from_slice(&0x0000_4000_u32.to_le_bytes()); // unwind
        let entries = parse_pdata(&raw);
        assert_eq!(entries.len(), 2);
        // Must be sorted by begin_address.
        assert_eq!(entries[0].begin_address, 0x1000);
        assert_eq!(entries[1].begin_address, 0x2000);
    }

    // ── Layer 1: function table lookup ──────────────────────────────────

    #[test]
    fn lookup_hit_exact() {
        let mut state = crate::sync_obj::SyncState::new();
        let image_base = 0x14000_0000;
        let entries = vec![RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1100,
            unwind_data: 0x2000,
        }];
        state.function_tables.insert(image_base, entries);

        // RIP in the middle of the function.
        let found = lookup_function_entry(&state, image_base + 0x1080);
        assert!(found.is_some());
        let f = found.unwrap();
        assert_eq!(f.entry.begin_address, 0x1000);
        assert_eq!(f.image_base, image_base);
    }

    #[test]
    fn lookup_hit_binary_search_fallback() {
        let mut state = crate::sync_obj::SyncState::new();
        let image_base = 0x14000_0000;
        let entries = vec![
            RuntimeFunction { begin_address: 0x1000, end_address: 0x1100, unwind_data: 0x2000 },
            RuntimeFunction { begin_address: 0x2000, end_address: 0x2500, unwind_data: 0x3000 },
        ];
        state.function_tables.insert(image_base, entries);

        // RIP in second function — not an exact match on begin_address.
        let found = lookup_function_entry(&state, image_base + 0x2100);
        assert!(found.is_some());
        assert_eq!(found.unwrap().entry.begin_address, 0x2000);
    }

    #[test]
    fn lookup_miss_outside_range() {
        let mut state = crate::sync_obj::SyncState::new();
        let image_base = 0x14000_0000;
        let entries = vec![RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1100,
            unwind_data: 0x2000,
        }];
        state.function_tables.insert(image_base, entries);

        assert!(lookup_function_entry(&state, image_base + 0x0500).is_none());
        assert!(lookup_function_entry(&state, image_base + 0x2000).is_none());
    }

    // ── Layer 2: unwind info parsing ────────────────────────────────────

    #[test]
    fn unwind_info_no_handler() {
        // Version=1, Flags=0, PrologSize=8, CountOfCodes=2,
        // FrameRegister=0, FrameOffset=0
        let raw: [u8; 4] = [
            0x01, // version=1 flags=0
            0x08, // prolog=8
            0x02, // codes=2
            0x00, // frame_reg=0 frame_off=0
        ];
        let info = UnwindInfo::from_bytes(&raw, 0).expect("parse");
        assert_eq!(info.version, 1);
        assert_eq!(info.flags, 0);
        assert_eq!(info.size_of_prolog, 8);
        assert_eq!(info.count_of_codes, 2);
        assert_eq!(info.frame_register, 0);
        assert_eq!(info.frame_offset, 0);
        assert_eq!(info.header_size(), 4 + 2 * 2); // 4 header + 4 codes, already aligned
    }

    #[test]
    fn unwind_info_with_handler() {
        // Flags = 1 (EHANDLER)
        let raw: [u8; 4] = [
            0x09, // version=1 flags=1 (EHANDLER)
            0x04, // prolog=4
            0x01, // codes=1
            0x00,
        ];
        let info = UnwindInfo::from_bytes(&raw, 0).expect("parse");
        assert_eq!(info.flags, 1);
        // header_size: 4 + 2 = 6, padded to 8
        assert_eq!(info.header_size(), 8);
        // total_size: header(8) + handler_rva(4) + handler_data(4) = 16
        assert_eq!(info.total_size(), 16);
    }

    // ── Layer 2: leaf function unwinding ────────────────────────────────

    #[test]
    fn unwind_leaf_function() {
        // Simulate guest memory: RSP points to a return address of 0x401000.
        let guest_stack: Vec<u8> = {
            let mut v = vec![0u8; 16];
            v[0..8].copy_from_slice(&0x401000_u64.to_le_bytes());
            v
        };
        let read = |va: u64, buf: &mut [u8]| {
            let offset = (va - 0x1000) as usize;
            buf.copy_from_slice(&guest_stack[offset..offset + buf.len()]);
            Ok(())
        };
        let mut read_mut = read;

        // Leaf function: no RUNTIME_FUNCTION entry.  Simulate by using
        // unwind_leaf directly (it's private in the module, so test via
        // virtual_unwind with unwind_data=0).
        let entry = RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1000,
            unwind_data: 0, // signals leaf function
        };
        let ctx = UnwindContext {
            rip: 0x401000,
            rsp: 0x1000,
            gpr: [0; 16],
        };
        let result = virtual_unwind(&mut read_mut, 0, &entry, ctx).expect("unwind");
        assert_eq!(result.ctx.rip, 0x401000); // popped return address
        assert_eq!(result.ctx.rsp, 0x1008); // RSP + 8
        assert!(result.handler_rva.is_none());
    }

    // ── Layer 2: full frame unwinding ────────────────────────────────────

    #[test]
    fn unwind_push_nonvol() {
        // Simulate a function whose prologue pushes RBX (reg=3) then
        // allocates 0x20 bytes (UWOP_ALLOC_SMALL with op_info=3).
        // UWOP codes (reverse order): [ALLOC_SMALL(3), PUSH_NONVOL(3)]
        // ALLOC_SMALL: op_info=3 → size = 3*8+8 = 32 (0x20)
        // PUSH_NONVOL: reg=3 (RBX)

        // Build guest memory.  RSP in function: 0x2000 (after prologue).
        // Original RSP was 0x2028 (before push rbx).  After push rbx: RSP=0x2020,
        // RBX saved at [0x2020].  After sub rsp 0x20: RSP=0x2000.
        // Return address is at [0x2028] (the caller's stack slot).
        let mut guest_mem = vec![0u8; 0x3000];
        guest_mem[0x2028..0x2030].copy_from_slice(&0x401000_u64.to_le_bytes());
        guest_mem[0x2020..0x2028].copy_from_slice(&0xDEADBEEF_u64.to_le_bytes());

        // .xdata: UNWIND_INFO header + 2 UNWIND_CODEs
        // Prologue:  push rbx (offset 4)  then  sub rsp,0x20 (offset 2)
        // Stored in REVERSE order:  sub rsp first, push rbx second.
        let mut xdata = vec![0u8; 16];
        // Header
        xdata[0] = 0x01; // version=1 flags=0
        xdata[1] = 0x08; // prolog=8
        xdata[2] = 0x02; // codes=2
        xdata[3] = 0x00; // frame=0
        // Code 0 (stored first = last prologue op): ALLOC_SMALL size 0x20
        xdata[4] = 0x02; // code_offset=2  (sub rsp,0x20)
        xdata[5] = 0x32; // op=ALLOC_SMALL(2) | op_info=3<<4
        // Code 1 (stored second = first prologue op): PUSH_NONVOL RBX
        xdata[6] = 0x04; // code_offset=4  (push rbx)
        xdata[7] = 0x30; // op=PUSH_NONVOL(0) | op_info=3<<4

        let read = |va: u64, buf: &mut [u8]| -> Result<(), ()> {
            if (0x6000..0x6000 + xdata.len() as u64).contains(&va) {
                let off = (va - 0x6000) as usize;
                buf.copy_from_slice(&xdata[off..off + buf.len()]);
                return Ok(());
            }
            let offset = va as usize;
            if offset + buf.len() <= guest_mem.len() {
                buf.copy_from_slice(&guest_mem[offset..offset + buf.len()]);
                Ok(())
            } else {
                Err(())
            }
        };
        let mut read_mut = read;

        let entry = RuntimeFunction {
            begin_address: 0x1000,
            end_address: 0x1100,
            unwind_data: 0x6000, // RVA of xdata in guest memory
        };
        let ctx = UnwindContext {
            rip: 0x401050, // inside the function
            rsp: 0x2000, // RSP after prologue
            gpr: {
                let mut g = [0u64; 16];
                g[3] = 0; // RBX will be restored
                g
            },
        };
        let result = virtual_unwind(&mut read_mut, 0, &entry, ctx).expect("unwind");
        // RBX should be restored from stack
        assert_eq!(result.ctx.gpr[3], 0xDEADBEEF);
        // RSP should be at caller's frame (past return address)
        assert_eq!(result.ctx.rsp, 0x2030); // 0x2000 + 0x20 (alloc) + 8 (RBX push) + 8 (ret addr)
        // RIP should be popped return address
        assert_eq!(result.ctx.rip, 0x401000);
        assert!(result.handler_rva.is_none());
    }
}
