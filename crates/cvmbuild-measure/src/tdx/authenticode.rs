//! PE Authenticode hash calculation.
//!
//! Computes the Authenticode digest of a PE/COFF binary by hashing all file
//! content except three excluded regions:
//!   1. The PE checksum field (4 bytes)
//!   2. The Certificate Table data directory entry (8 bytes)
//!   3. The certificate table data at the end of the file

use anyhow::{ensure, Result};
use sha2::{Digest, Sha384};

fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

/// Compute the SHA-384 Authenticode hash of a PE binary.
pub fn pe_authenticode_hash(pe: &[u8]) -> Result<Vec<u8>> {
    // 1. Read PE offset from DOS header at 0x3C
    let pe_offset = read_u32_le(pe, 0x3C) as usize;

    // Verify PE signature "PE\0\0"
    ensure!(
        pe.len() >= pe_offset + 4 && &pe[pe_offset..pe_offset + 4] == b"PE\x00\x00",
        "Invalid PE signature"
    );

    // 2. COFF File Header (20 bytes, starts after 4-byte PE signature)
    let coff_offset = pe_offset + 4;
    let number_of_sections = read_u16_le(pe, coff_offset + 2) as usize;
    let size_of_optional_header = read_u16_le(pe, coff_offset + 16) as usize;

    // 3. Optional Header
    let opt_offset = coff_offset + 20;
    let magic = read_u16_le(pe, opt_offset);
    let is_pe32_plus = magic == 0x20B;
    ensure!(
        magic == 0x10B || magic == 0x20B,
        "unknown PE optional header magic: 0x{magic:x}"
    );

    // Checksum is at optional header + 64
    let checksum_offset = opt_offset + 64;

    // DataDirectory[4] (Certificate Table) location
    let dd4_offset = if is_pe32_plus {
        opt_offset + 144
    } else {
        opt_offset + 128
    };

    // SizeOfHeaders at optional header + 60
    let size_of_headers = read_u32_le(pe, opt_offset + 60) as usize;

    // Certificate table size
    let cert_table_size = read_u32_le(pe, dd4_offset + 4) as usize;

    // 4. Parse section headers (40 bytes each, after optional header)
    let section_table_offset = opt_offset + size_of_optional_header;
    let mut sections: Vec<(usize, usize)> = Vec::new();

    for i in 0..number_of_sections {
        let sec_off = section_table_offset + i * 40;
        let raw_size = read_u32_le(pe, sec_off + 16) as usize;
        let file_offset = read_u32_le(pe, sec_off + 20) as usize;
        if raw_size > 0 {
            sections.push((file_offset, raw_size));
        }
    }

    sections.sort_by_key(|s| s.0);

    // 5. Build incremental SHA-384 hash, skipping excluded regions
    let mut h = Sha384::new();

    // Hash from start to checksum field
    h.update(&pe[..checksum_offset]);

    // Skip checksum (4 bytes), hash to Certificate Table directory entry
    h.update(&pe[checksum_offset + 4..dd4_offset]);

    // Skip DD[4] (8 bytes), hash to end of headers
    h.update(&pe[dd4_offset + 8..size_of_headers]);

    // Hash each section in file-offset order
    let mut sum_of_bytes_hashed = size_of_headers;
    for &(file_offset, raw_size) in &sections {
        h.update(&pe[file_offset..file_offset + raw_size]);
        sum_of_bytes_hashed += raw_size;
    }

    // Hash any extra data between sections and the certificate table
    let extra_len = pe.len() - sum_of_bytes_hashed - cert_table_size;
    if extra_len > 0 {
        h.update(&pe[sum_of_bytes_hashed..sum_of_bytes_hashed + extra_len]);
    }

    // Pad total file size to 8-byte alignment
    let pad_len = (8 - (pe.len() % 8)) % 8;
    if pad_len > 0 {
        h.update(vec![0u8; pad_len]);
    }

    Ok(h.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_minimal_pe() -> Vec<u8> {
        let mut pe = vec![0u8; 1024];

        // DOS header
        pe[0] = 0x4D;
        pe[1] = 0x5A; // "MZ"
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes()); // PE offset

        // PE signature
        pe[0x80] = 0x50;
        pe[0x81] = 0x45; // "PE\0\0"

        // COFF file header at 0x84
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes()); // Machine: AMD64
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // NumberOfSections: 1
        pe[0x94..0x96].copy_from_slice(&240u16.to_le_bytes()); // SizeOfOptionalHeader

        // Optional header at 0x98
        pe[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes()); // Magic: PE32+

        // SizeOfHeaders at opt+60 = 0xD4
        pe[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes());

        // Checksum at opt+64 = 0xD8
        pe[0xD8..0xDC].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        // NumberOfRvaAndSizes at opt+108 = 0x104
        pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());

        // DataDirectory[4] at opt+144 = 0x128
        pe[0x128..0x12C].copy_from_slice(&0u32.to_le_bytes());
        pe[0x12C..0x130].copy_from_slice(&0u32.to_le_bytes());

        // Section table at 0x188
        let sec_off = 0x188;
        pe[sec_off] = 0x2E; // "."
        pe[sec_off + 1] = 0x74; // "t"
        pe[sec_off + 2] = 0x65; // "e"
        pe[sec_off + 3] = 0x78; // "x"
        pe[sec_off + 4] = 0x74; // "t"
        pe[sec_off + 8..sec_off + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
        pe[sec_off + 12..sec_off + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
        pe[sec_off + 16..sec_off + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
        pe[sec_off + 20..sec_off + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData

        // Fill section with recognizable data
        for i in 0x200..0x400 {
            pe[i] = ((i * 3 + 7) & 0xFF) as u8;
        }

        pe
    }

    #[test]
    fn pe_authenticode_hash_skips_checksum_and_cert_table_entry() {
        let pe = build_minimal_pe();
        let hash1 = pe_authenticode_hash(&pe).unwrap();

        let mut pe2 = pe.clone();
        pe2[0xD8..0xDC].copy_from_slice(&0x12345678u32.to_le_bytes());
        let hash2 = pe_authenticode_hash(&pe2).unwrap();

        assert_eq!(hex::encode(&hash1), hex::encode(&hash2));
    }

    #[test]
    fn pe_authenticode_hash_changes_when_section_content_changes() {
        let pe = build_minimal_pe();
        let hash1 = pe_authenticode_hash(&pe).unwrap();

        let mut pe2 = pe.clone();
        pe2[0x200] ^= 0xFF;
        let hash2 = pe_authenticode_hash(&pe2).unwrap();

        assert_ne!(hex::encode(&hash1), hex::encode(&hash2));
    }

    #[test]
    fn pe_authenticode_hash_skips_certificate_table_directory_entry() {
        let pe = build_minimal_pe();
        let hash1 = pe_authenticode_hash(&pe).unwrap();

        let mut pe2 = pe.clone();
        pe2[0x128..0x12C].copy_from_slice(&0xAAAAu32.to_le_bytes());
        pe2[0x12C..0x130].copy_from_slice(&0u32.to_le_bytes());
        let hash2 = pe_authenticode_hash(&pe2).unwrap();

        assert_eq!(hex::encode(&hash1), hex::encode(&hash2));
    }

    #[test]
    fn pe_authenticode_hash_produces_48_byte_sha384_digest() {
        let pe = build_minimal_pe();
        let h = pe_authenticode_hash(&pe).unwrap();
        assert_eq!(h.len(), 48);
    }

    #[test]
    fn pe_authenticode_hash_matches_manual_hash_computation() {
        let pe = build_minimal_pe();

        let ref_hash = {
            let mut h = Sha384::new();
            h.update(&pe[..0xD8]); // start to checksum
            h.update(&pe[0xDC..0x128]); // after checksum to DD[4]
            h.update(&pe[0x130..0x200]); // after DD[4] to end of headers
            h.update(&pe[0x200..0x400]); // .text section
            h.finalize().to_vec()
        };

        let actual = pe_authenticode_hash(&pe).unwrap();
        assert_eq!(hex::encode(&actual), hex::encode(&ref_hash));
    }

    #[test]
    fn pe_authenticode_hash_rejects_non_pe_binary() {
        let garbage = vec![0u8; 1024];
        assert!(pe_authenticode_hash(&garbage).is_err());
    }
}
