//! GUID string ↔ mixed-endian bytes conversion.
//!
//! First 3 groups (time_low, time_mid, time_hi) are byte-reversed,
//! last 2 groups (clock_seq, node) are kept as-is.

use anyhow::{Context, Result};

/// Parse a GUID string into 16 bytes in mixed-endian (bytes_le) format.
pub fn guid_to_le_bytes(guid: &str) -> Result<[u8; 16]> {
    let parts: Vec<&str> = guid.split('-').collect();
    if parts.len() != 5 {
        anyhow::bail!("invalid GUID format: {guid}");
    }

    let mut result = [0u8; 16];
    let mut offset = 0;

    // Group 1: 4 bytes, reversed
    let g1 = hex_decode(parts[0]).context("GUID group 1")?;
    for i in (0..g1.len()).rev() {
        result[offset] = g1[i];
        offset += 1;
    }

    // Group 2: 2 bytes, reversed
    let g2 = hex_decode(parts[1]).context("GUID group 2")?;
    for i in (0..g2.len()).rev() {
        result[offset] = g2[i];
        offset += 1;
    }

    // Group 3: 2 bytes, reversed
    let g3 = hex_decode(parts[2]).context("GUID group 3")?;
    for i in (0..g3.len()).rev() {
        result[offset] = g3[i];
        offset += 1;
    }

    // Group 4: 2 bytes, as-is
    let g4 = hex_decode(parts[3]).context("GUID group 4")?;
    result[offset..offset + g4.len()].copy_from_slice(&g4);
    offset += g4.len();

    // Group 5: 6 bytes, as-is
    let g5 = hex_decode(parts[4]).context("GUID group 5")?;
    result[offset..offset + g5.len()].copy_from_slice(&g5);

    Ok(result)
}

/// Convert 16 bytes in mixed-endian format to a GUID string.
pub fn le_bytes_to_guid(data: &[u8; 16]) -> String {
    let g1: Vec<u8> = data[0..4].iter().rev().copied().collect();
    let g2: Vec<u8> = data[4..6].iter().rev().copied().collect();
    let g3: Vec<u8> = data[6..8].iter().rev().copied().collect();
    let g4 = &data[8..10];
    let g5 = &data[10..16];

    format!(
        "{}-{}-{}-{}-{}",
        hex_encode(&g1),
        hex_encode(&g2),
        hex_encode(&g3),
        hex_encode(g4),
        hex_encode(g5),
    )
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        anyhow::bail!("odd-length hex string: {s}");
    }
    let mut bytes = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        let byte = u8::from_str_radix(&s[i..i + 2], 16)
            .with_context(|| format!("invalid hex byte in '{s}' at position {i}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guid_roundtrip() {
        let guid = "96b582de-1fb2-45f7-baea-a366c55a082d";
        let bytes = guid_to_le_bytes(guid).unwrap();
        let back = le_bytes_to_guid(&bytes);
        assert_eq!(guid, back);
    }

    #[test]
    fn guid_known_value() {
        let bytes = guid_to_le_bytes("96b582de-1fb2-45f7-baea-a366c55a082d").unwrap();
        assert_eq!(
            bytes,
            [
                0xDE, 0x82, 0xB5, 0x96, 0xB2, 0x1F, 0xF7, 0x45, 0xBA, 0xEA, 0xA3, 0x66, 0xC5, 0x5A,
                0x08, 0x2D
            ]
        );
    }
}
