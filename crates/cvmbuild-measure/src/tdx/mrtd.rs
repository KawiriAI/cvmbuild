//! MRTD (Measurement Register for Trust Domain) — build-time measurement.
//!
//! Implements the TDX launch measurement algorithm per:
//! - Intel TDX Module Base Architecture Specification, Section 12.2.1
//! - Intel TDX Module ABI Reference Specification, Sections 5.3.20, 5.3.37, 5.3.44, 5.3.45

use anyhow::{ensure, Result};
use sha2::{Digest, Sha384};

const PAGE_SIZE: usize = 0x1000; // 4096
const CHUNK_SIZE: usize = 256;

/// Tracks the SHA-384 measurement state during TD build.
///
/// Corresponds to the state initialized by TDH.MNG.INIT.
pub struct LaunchContext {
    hash: Sha384,
}

impl Default for LaunchContext {
    fn default() -> Self {
        Self::new()
    }
}

impl LaunchContext {
    pub fn new() -> Self {
        Self {
            hash: Sha384::new(),
        }
    }

    /// Record a page addition (TDH.MEM.PAGE.ADD).
    ///
    /// 128-byte buffer: "MEM.PAGE.ADD\0..." (16 bytes) + LE64(GPA) + zeros.
    pub fn mem_page_add(&mut self, gpa: u64) {
        let mut buf = [0u8; 128];
        buf[0..12].copy_from_slice(b"MEM.PAGE.ADD");
        buf[16..24].copy_from_slice(&gpa.to_le_bytes());
        self.hash.update(buf);
    }

    /// Record a content extension (TDH.MR.EXTEND).
    ///
    /// 128-byte header + 256-byte chunk.
    pub fn mr_extend(&mut self, gpa: u64, chunk: &[u8]) {
        assert_eq!(chunk.len(), 256, "MR.EXTEND chunk must be 256 bytes");

        let mut header = [0u8; 128];
        header[0..9].copy_from_slice(b"MR.EXTEND");
        header[16..24].copy_from_slice(&gpa.to_le_bytes());

        self.hash.update(header);
        self.hash.update(chunk);
    }

    /// Write a firmware region into the measurement.
    pub fn write_region(
        &mut self,
        gpa: u64,
        data: &[u8],
        data_len: usize,
        extend: bool,
    ) -> Result<()> {
        ensure!(
            data_len.is_multiple_of(PAGE_SIZE),
            "data length 0x{data_len:x} is not a multiple of page size 0x{PAGE_SIZE:x}"
        );

        let num_pages = data_len / PAGE_SIZE;
        for i in 0..num_pages {
            let page_offset = i * PAGE_SIZE;
            let page_address = gpa + page_offset as u64;

            self.mem_page_add(page_address);

            if !extend {
                continue;
            }

            let chunks_per_page = PAGE_SIZE / CHUNK_SIZE;
            for j in 0..chunks_per_page {
                let chunk_offset = page_offset + j * CHUNK_SIZE;
                let chunk_address = page_address + (j * CHUNK_SIZE) as u64;

                let mut chunk = [0u8; 256];
                let end = (chunk_offset + 256).min(data.len());
                if chunk_offset < data.len() {
                    let src = &data[chunk_offset..end];
                    chunk[..src.len()].copy_from_slice(src);
                }

                self.mr_extend(chunk_address, &chunk);
            }
        }

        Ok(())
    }

    /// Finalize the MRTD calculation. Returns the 48-byte SHA-384 digest.
    pub fn finalize(self) -> Vec<u8> {
        self.hash.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_page_add_produces_correct_128_byte_buffer() {
        let mut expected = [0u8; 128];
        expected[0..12].copy_from_slice(b"MEM.PAGE.ADD");
        expected[16..24].copy_from_slice(&0x1000u64.to_le_bytes());

        let ref_hash = {
            let mut h = Sha384::new();
            h.update(expected);
            h.finalize().to_vec()
        };

        let mut ctx = LaunchContext::new();
        ctx.mem_page_add(0x1000);
        let digest = ctx.finalize();

        assert_eq!(hex::encode(&digest), hex::encode(&ref_hash));
    }

    #[test]
    fn mr_extend_produces_correct_header_and_content() {
        let chunk: Vec<u8> = (0..256).map(|i| (i & 0xFF) as u8).collect();

        let mut header = [0u8; 128];
        header[0..9].copy_from_slice(b"MR.EXTEND");
        header[16..24].copy_from_slice(&0x2000u64.to_le_bytes());

        let ref_hash = {
            let mut h = Sha384::new();
            h.update(header);
            h.update(&chunk);
            h.finalize().to_vec()
        };

        let mut ctx = LaunchContext::new();
        ctx.mr_extend(0x2000, &chunk);
        let digest = ctx.finalize();

        assert_eq!(hex::encode(&digest), hex::encode(&ref_hash));
    }

    #[test]
    fn write_region_without_extend_only_adds_pages() {
        let data = vec![0u8; 0x2000];
        let mut ctx = LaunchContext::new();
        ctx.write_region(0x100000, &data, 0x2000, false).unwrap();
        let digest = ctx.finalize();

        let ref_hash = {
            let mut h = Sha384::new();
            for gpa in [0x100000u64, 0x101000u64] {
                let mut buf = [0u8; 128];
                buf[0..12].copy_from_slice(b"MEM.PAGE.ADD");
                buf[16..24].copy_from_slice(&gpa.to_le_bytes());
                h.update(buf);
            }
            h.finalize().to_vec()
        };

        assert_eq!(hex::encode(&digest), hex::encode(&ref_hash));
    }

    #[test]
    fn write_region_with_extend_adds_pages_and_chunks() {
        let mut data = vec![0u8; 0x1000];
        for i in 0..data.len() {
            data[i] = ((i * 7) & 0xFF) as u8;
        }

        let mut ctx = LaunchContext::new();
        ctx.write_region(0x200000, &data, 0x1000, true).unwrap();
        let digest = ctx.finalize();

        let ref_hash = {
            let mut h = Sha384::new();

            // PAGE.ADD
            let mut page_add = [0u8; 128];
            page_add[0..12].copy_from_slice(b"MEM.PAGE.ADD");
            page_add[16..24].copy_from_slice(&0x200000u64.to_le_bytes());
            h.update(page_add);

            // 16 MR.EXTEND chunks
            for j in 0..16usize {
                let chunk_addr = 0x200000u64 + (j * 256) as u64;
                let mut header = [0u8; 128];
                header[0..9].copy_from_slice(b"MR.EXTEND");
                header[16..24].copy_from_slice(&chunk_addr.to_le_bytes());
                h.update(header);

                let chunk = &data[j * 256..(j + 1) * 256];
                h.update(chunk);
            }

            h.finalize().to_vec()
        };

        assert_eq!(hex::encode(&digest), hex::encode(&ref_hash));
    }

    #[test]
    fn write_region_rejects_non_page_aligned_data_length() {
        let mut ctx = LaunchContext::new();
        let result = ctx.write_region(0, &[0u8; 100], 100, false);
        assert!(result.is_err());
    }
}
