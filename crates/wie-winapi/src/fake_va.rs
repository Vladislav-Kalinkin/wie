//! Dense fake-API virtual addresses: IDs encoded in the guest VA.
//!
//! Layout (relative to [`FAKE_API_BASE`], stride 16 bytes):
//!
//! ```text
//! offset bits:
//!   [21:20] kind   (2 bits)
//!   [19:4]  payload (16 bits)
//!   [3:0]   0 (alignment)
//! ```
//!
//! | kind | payload |
//! |------|---------|
//! | 0 Export | `WinApiId` as u16 |
//! | 1 Com | `(iface << 8) \| method` |
//! | 2 Special | runtime special id |
//! | 3 Soft | `0x0000..0x7FFF` = alias of `WinApiId`; `0x8000..` = unresolved index |

use crate::WinApiId;

/// Guest base of the fake-API hook window (matches runtime layout).
pub const FAKE_API_BASE: u64 = 0x0000_7000_0000_0000;

/// Size of the mapped fake-API window (4 MiB — room for kind/payload encoding).
pub const FAKE_API_SIZE: usize = 0x0040_0000;

const ALIGN_SHIFT: u32 = 4;
const PAYLOAD_BITS: u32 = 16;
const KIND_SHIFT: u32 = ALIGN_SHIFT + PAYLOAD_BITS; // 20
const PAYLOAD_MASK: u64 = (1 << PAYLOAD_BITS) - 1;
const KIND_MASK: u64 = 0b11;

/// Primary WinAPI export (`WinApiId` in payload).
pub const KIND_EXPORT: u8 = 0;
/// COM / vtable method (`iface` high byte, `method` low byte).
pub const KIND_COM: u8 = 1;
/// Runtime special (callback trampoline, …).
pub const KIND_SPECIAL: u8 = 2;
/// Alias of a `WinApiId` (host fallback) or soft/unresolved slot.
pub const KIND_SOFT: u8 = 3;

/// Soft payloads below this are `WinApiId` aliases; at/above are unresolved indices.
pub const SOFT_UNRESOLVED_BASE: u16 = 0x8000;

/// `kind=Special` payload: USER32 guest WndProc return trampoline.
pub const SPECIAL_CALLBACK_RETURN: u16 = 0;

/// COM iface id: `IDirect3D9`.
pub const COM_IFACE_IDIRECT3D9: u8 = 0;
/// COM iface id: `IDirect3DDevice9`.
pub const COM_IFACE_IDIRECT3DDEVICE9: u8 = 1;

/// Decoded fake-API address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FakeVa {
    /// Dense handler id.
    Export(WinApiId),
    /// Host-fallback / alias VA that dispatches the same `WinApiId`.
    Alias(WinApiId),
    /// Import without a dense id (UCRT, ordinals, …); index into soft table.
    Unresolved(u16),
    /// COM vtable slot.
    Com { iface: u8, method: u8 },
    /// Runtime special.
    Special(u16),
}

/// Pack `kind` + `payload` into a guest fake VA.
#[must_use]
#[allow(clippy::as_conversions)] // const: widen kind/payload into the packed VA bitfield
pub const fn encode(kind: u8, payload: u16) -> u64 {
    FAKE_API_BASE | ((kind as u64) << KIND_SHIFT) | ((payload as u64) << ALIGN_SHIFT)
}

/// Encode a primary export address for `id`.
#[must_use]
pub const fn encode_export(id: WinApiId) -> u64 {
    encode(KIND_EXPORT, id.to_u16())
}

/// Encode a host-fallback alias that dispatches the same `id`.
#[must_use]
pub const fn encode_alias(id: WinApiId) -> u64 {
    encode(KIND_SOFT, id.to_u16())
}

/// Encode a soft/unresolved slot (`index` must be `< 0x8000`).
#[must_use]
pub const fn encode_unresolved(index: u16) -> u64 {
    encode(KIND_SOFT, SOFT_UNRESOLVED_BASE | (index & 0x7fff))
}

/// Encode a COM method address.
#[must_use]
#[allow(clippy::as_conversions)]
pub const fn encode_com(iface: u8, method: u8) -> u64 {
    encode(KIND_COM, ((iface as u16) << 8) | (method as u16))
}

/// Encode a runtime special address.
#[must_use]
pub const fn encode_special(id: u16) -> u64 {
    encode(KIND_SPECIAL, id)
}

/// Callback-return trampoline VA (inside the fake-API window).
#[must_use]
pub const fn callback_return_trampoline_va() -> u64 {
    encode_special(SPECIAL_CALLBACK_RETURN)
}

/// Decode a guest VA into a [`FakeVa`], if it lies in the fake-API window.
#[must_use]
#[allow(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    clippy::arithmetic_side_effects
)] // bitfield decode: checked window, then truncating payload/kind extracts
pub fn decode(va: u64) -> Option<FakeVa> {
    if va < FAKE_API_BASE {
        return None;
    }
    let off = va - FAKE_API_BASE;
    let window = FAKE_API_SIZE as u64;
    if off >= window {
        return None;
    }
    // Require 16-byte alignment (IAT / stub stride).
    if off & ((1 << ALIGN_SHIFT) - 1) != 0 {
        return None;
    }

    let payload = ((off >> ALIGN_SHIFT) & PAYLOAD_MASK) as u16;
    let kind = ((off >> KIND_SHIFT) & KIND_MASK) as u8;

    match kind {
        KIND_EXPORT => {
            let id = WinApiId::from_u16(payload)?;
            Some(FakeVa::Export(id))
        }
        KIND_COM => {
            let iface = (payload >> 8) as u8;
            let method = payload as u8;
            Some(FakeVa::Com { iface, method })
        }
        KIND_SPECIAL => Some(FakeVa::Special(payload)),
        KIND_SOFT => {
            if payload < SOFT_UNRESOLVED_BASE {
                let id = WinApiId::from_u16(payload)?;
                Some(FakeVa::Alias(id))
            } else {
                Some(FakeVa::Unresolved(
                    payload.wrapping_sub(SOFT_UNRESOLVED_BASE),
                ))
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::as_conversions)] // test: FAKE_API_SIZE usize → u64 window bound
    fn export_round_trip() {
        let id = WinApiId::Kernel32Getlasterror;
        let va = encode_export(id);
        assert_eq!(decode(va), Some(FakeVa::Export(id)));
        assert!(va >= FAKE_API_BASE);
        assert!((va - FAKE_API_BASE) < FAKE_API_SIZE as u64);
        assert_eq!(va & 0xf, 0);
    }

    #[test]
    fn alias_and_unresolved_distinct() {
        let id = WinApiId::Kernel32Readfile;
        let a = encode_alias(id);
        let u = encode_unresolved(3);
        assert_ne!(a, u);
        assert_eq!(decode(a), Some(FakeVa::Alias(id)));
        assert_eq!(decode(u), Some(FakeVa::Unresolved(3)));
    }

    #[test]
    fn com_and_special() {
        let va = encode_com(COM_IFACE_IDIRECT3DDEVICE9, 57);
        assert_eq!(
            decode(va),
            Some(FakeVa::Com {
                iface: COM_IFACE_IDIRECT3DDEVICE9,
                method: 57
            })
        );
        let cb = callback_return_trampoline_va();
        assert_eq!(decode(cb), Some(FakeVa::Special(SPECIAL_CALLBACK_RETURN)));
    }

    #[test]
    #[allow(clippy::as_conversions)] // test: FAKE_API_SIZE usize → u64 window bound
    fn rejects_outside_window() {
        assert!(decode(0x140_000_000).is_none());
        assert!(decode(FAKE_API_BASE + FAKE_API_SIZE as u64).is_none());
    }
}
