use anyhow::{Context, Result};

pub(crate) fn read_ansi_lossy(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    max_bytes: usize,
) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }

    let mut bytes = Vec::new();

    for index in 0..max_bytes {
        let offset = u64::try_from(index).context("ANSI string index does not fit u64")?;

        let byte_address = address
            .checked_add(offset)
            .context("ANSI string address overflow")?;

        let mut byte = [0_u8; 1];

        engine
            .mem_read(byte_address, &mut byte)
            .context("failed to read ANSI string byte")?;

        let value = u8::from_le_bytes(byte);

        if value == 0 {
            break;
        }

        bytes.push(value);
    }

    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

pub(crate) fn read_utf16_lossy(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    max_units: usize,
) -> Result<String> {
    if address == 0 {
        return Ok(String::new());
    }

    let mut units = Vec::new();

    for index in 0..max_units {
        let index_u64 = u64::try_from(index).context("UTF-16 string index does not fit u64")?;

        let byte_offset = index_u64
            .checked_mul(2)
            .context("UTF-16 string byte offset overflow")?;

        let unit_address = address
            .checked_add(byte_offset)
            .context("UTF-16 string address overflow")?;

        let mut bytes = [0_u8; 2];

        engine
            .mem_read(unit_address, &mut bytes)
            .context("failed to read UTF-16 string unit")?;

        let unit = u16::from_le_bytes(bytes);

        if unit == 0 {
            break;
        }

        units.push(unit);
    }

    Ok(String::from_utf16_lossy(&units))
}

pub(crate) fn write_utf16_units(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    units: &[u16],
) -> Result<()> {
    let byte_length = units
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .context("UTF-16 byte length overflow")?;

    let mut bytes = Vec::with_capacity(byte_length);

    for unit in units {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }

    crate::guest_memory::write_bytes(engine, address, &bytes)
        .context("failed to write UTF-16 units to guest memory")
}

/// Writes a NUL-terminated ANSI string into a fixed-size guest buffer.
pub(crate) fn write_fixed_ansi(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    byte_len: usize,
    value: &[u8],
) -> Result<()> {
    let mut bytes = vec![0_u8; byte_len];
    let copy_len = value.len().min(byte_len.saturating_sub(1));

    let destination = bytes
        .get_mut(0..copy_len)
        .context("ANSI fixed string destination out of range")?;

    let source = value
        .get(0..copy_len)
        .context("ANSI fixed string source out of range")?;

    destination.copy_from_slice(source);

    crate::guest_memory::write_bytes(engine, address, &bytes)
        .context("failed to write fixed ANSI string")
}

/// Writes a NUL-terminated UTF-16 string into a fixed-size guest buffer.
pub(crate) fn write_fixed_utf16(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    unit_len: usize,
    value: &str,
) -> Result<()> {
    let byte_len = unit_len
        .checked_mul(2)
        .context("UTF-16 fixed string byte length overflow")?;

    let mut bytes = vec![0_u8; byte_len];

    for (index, unit) in value
        .encode_utf16()
        .take(unit_len.saturating_sub(1))
        .enumerate()
    {
        let offset = index
            .checked_mul(2)
            .context("UTF-16 fixed string offset overflow")?;

        let range_end = offset
            .checked_add(2)
            .context("UTF-16 fixed string range overflow")?;

        let destination = bytes
            .get_mut(offset..range_end)
            .context("UTF-16 fixed string destination out of range")?;

        destination.copy_from_slice(&unit.to_le_bytes());
    }

    crate::guest_memory::write_bytes(engine, address, &bytes)
        .context("failed to write fixed UTF-16 string")
}

/// Writes a NUL-terminated ANSI string and returns the number of content bytes.
pub(crate) fn write_ansi_c_string(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    max_characters: usize,
    text: &str,
) -> Result<usize> {
    if address == 0 || max_characters == 0 {
        return Ok(0);
    }

    let content_capacity = max_characters.saturating_sub(1);

    let mut output = text
        .as_bytes()
        .iter()
        .copied()
        .take(content_capacity)
        .collect::<Vec<_>>();

    let copied = output.len();
    output.push(0);

    crate::guest_memory::write_bytes(engine, address, &output)
        .context("failed to write ANSI C string")?;

    Ok(copied)
}

/// Writes a NUL-terminated UTF-16 string and returns the number of content units.
pub(crate) fn write_utf16_c_string(
    engine: &mut dyn wie_cpu::CpuEngine,
    address: u64,
    max_characters: usize,
    text: &str,
) -> Result<usize> {
    if address == 0 || max_characters == 0 {
        return Ok(0);
    }

    let content_capacity = max_characters.saturating_sub(1);

    let mut units = text
        .encode_utf16()
        .take(content_capacity)
        .collect::<Vec<_>>();

    let copied = units.len();
    units.push(0);

    write_utf16_units(engine, address, &units).context("failed to write UTF-16 C string")?;

    Ok(copied)
}
