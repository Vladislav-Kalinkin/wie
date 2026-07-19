//! Path / string encoding boundary: UTF-16 ↔ UTF-8 ↔ Windows-1252 ACP.
//!
//! Clean room: ACP matches `GetACP` = 1252. CP_UTF8 = 65001 is real UTF-8.
//! Internal VFS paths are Rust UTF-8 `String` with Windows separators.

/// ANSI code page returned by `GetACP`.
pub const CP_ACP: u32 = 1252;
/// OEM code page returned by `GetOEMCP`.
pub const CP_OEMCP: u32 = 437;
/// UTF-8 code page.
pub const CP_UTF8: u32 = 65001;

/// Windows-1252 mapping for bytes 0x80..=0x9F (rest is Latin-1 / identity).
const CP1252_80_9F: [u16; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, // 80-87
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F, // 88-8F
    0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, // 90-97
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178, // 98-9F
];

/// Decode a single Windows-1252 byte to Unicode scalar (as `u16` BMP).
#[must_use]
pub fn cp1252_byte_to_u16(byte: u8) -> u16 {
    if (0x80..=0x9F).contains(&byte) {
        let index = usize::from(byte.saturating_sub(0x80));
        CP1252_80_9F.get(index).copied().unwrap_or(u16::from(byte))
    } else {
        u16::from(byte)
    }
}

/// Encode a Unicode scalar to one Windows-1252 byte when possible.
#[must_use]
pub fn unicode_to_cp1252_byte(ch: char) -> Option<u8> {
    let cp = u32::from(ch);
    if cp <= 0x7F || (0xA0..=0xFF).contains(&cp) {
        return u8::try_from(cp).ok();
    }
    for (i, &mapped) in CP1252_80_9F.iter().enumerate() {
        if u32::from(mapped) == cp {
            let offset = u8::try_from(i).ok()?;
            return Some(0x80_u8.saturating_add(offset));
        }
    }
    None
}

/// Decode ACP/Windows-1252 bytes to a Rust UTF-8 string.
#[must_use]
pub fn decode_acp(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if let Some(ch) = char::from_u32(u32::from(cp1252_byte_to_u16(b))) {
            out.push(ch);
        } else {
            out.push('\u{FFFD}');
        }
    }
    out
}

/// Encode a Rust string to ACP/Windows-1252 bytes (unmappable → `?`).
#[must_use]
pub fn encode_acp(text: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(text.len());
    for ch in text.chars() {
        out.push(unicode_to_cp1252_byte(ch).unwrap_or(b'?'));
    }
    out
}

/// Decode multi-byte input for `MultiByteToWideChar`.
///
/// - CP_ACP / 1252 / 0 / 1 / 2 / 3 / 437: single-byte zero-extend via CP1252 for 1252/ACP,
///   identity for 437/0-3 (legacy SBCS path).
/// - CP_UTF8: strict UTF-8 when possible; lossy fallback if invalid.
pub fn multibyte_to_wide(code_page: u32, bytes: &[u8]) -> Vec<u16> {
    match code_page {
        CP_ACP => bytes.iter().map(|&b| cp1252_byte_to_u16(b)).collect(), // 1252
        0 | 1 | 2 | 3 | CP_OEMCP => bytes.iter().map(|&b| u16::from(b)).collect(),
        CP_UTF8 => match std::str::from_utf8(bytes) {
            Ok(s) => s.encode_utf16().collect(),
            Err(_) => String::from_utf8_lossy(bytes).encode_utf16().collect(),
        },
        _ => String::from_utf8_lossy(bytes).encode_utf16().collect(),
    }
}

/// Encode wide string for `WideCharToMultiByte`.
///
/// Returns `None` when the UTF-16 input is invalid.
#[must_use]
pub fn wide_to_multibyte(code_page: u32, units: &[u16]) -> Option<Vec<u8>> {
    let has_nul = units.last().is_some_and(|u| *u == 0);
    let text_units = if has_nul {
        units.get(..units.len().saturating_sub(1)).unwrap_or(&[])
    } else {
        units
    };
    let text = String::from_utf16(text_units).ok()?;
    let mut bytes = match code_page {
        0 | CP_ACP => encode_acp(&text), // CP_ACP == 1252
        CP_OEMCP | 1 | 2 | 3 => text
            .chars()
            .map(|c| {
                let cp = u32::from(c);
                if cp <= 0xFF {
                    u8::try_from(cp).unwrap_or(b'?')
                } else {
                    b'?'
                }
            })
            .collect(),
        // UTF-8 and unknown pages: emit UTF-8 bytes (matches prior host path).
        _ => text.into_bytes(),
    };
    if has_nul {
        bytes.push(0);
    }
    Some(bytes)
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn euro_sign_roundtrip_cp1252() {
        let s = decode_acp(&[0x80]);
        assert_eq!(s, "€");
        assert_eq!(encode_acp("€"), vec![0x80]);
    }

    #[test]
    fn utf8_multibyte() {
        let units = multibyte_to_wide(CP_UTF8, "привет".as_bytes());
        let back = wide_to_multibyte(CP_UTF8, &units).expect("utf8");
        assert_eq!(back, "привет".as_bytes());
    }

    #[test]
    fn ascii_identity_acp() {
        assert_eq!(decode_acp(b"C:\\App\\x.txt"), r"C:\App\x.txt");
        assert_eq!(encode_acp(r"C:\App\x.txt"), b"C:\\App\\x.txt".to_vec());
    }
}
