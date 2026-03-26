//! SNP Guest Context (GCTX) — maintains a running SHA-384 launch digest.
//!
//! Implements the PAGE_INFO structure from SNP spec 8.17.2, Table 67.

use sha2::{Digest, Sha384};

const SHA384_SIZE: usize = 48;
const PAGE_SIZE: usize = 4096;
const ZEROS: [u8; SHA384_SIZE] = [0u8; SHA384_SIZE];

const PAGE_TYPE_NORMAL: u8 = 0x01;
const PAGE_TYPE_VMSA: u8 = 0x02;
const PAGE_TYPE_ZERO: u8 = 0x03;
const PAGE_TYPE_UNMEASURED: u8 = 0x04;
const PAGE_TYPE_SECRETS: u8 = 0x05;
const PAGE_TYPE_CPUID: u8 = 0x06;

pub const VMSA_GPA: u64 = 0xFFFFFFFFF000;

fn sha384(data: &[u8]) -> [u8; SHA384_SIZE] {
    let mut hasher = Sha384::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; SHA384_SIZE];
    out.copy_from_slice(&result);
    out
}

/// SNP Guest Context — accumulates SHA-384 launch digest.
pub struct Gctx {
    ld: [u8; SHA384_SIZE],
}

impl Gctx {
    pub fn new(seed: Option<&[u8]>) -> Self {
        let mut ld = ZEROS;
        if let Some(s) = seed {
            let len = s.len().min(SHA384_SIZE);
            ld[..len].copy_from_slice(&s[..len]);
        }
        Self { ld }
    }

    pub fn ld(&self) -> &[u8; SHA384_SIZE] {
        &self.ld
    }

    fn update(&mut self, page_type: u8, gpa: u64, contents: &[u8; SHA384_SIZE]) {
        // SNP spec 8.17.2 Table 67: PAGE_INFO structure (0x70 = 112 bytes)
        let mut page_info = [0u8; 0x70];
        page_info[0..48].copy_from_slice(&self.ld); // digest_cur
        page_info[48..96].copy_from_slice(contents); // contents
        page_info[96..98].copy_from_slice(&0x70u16.to_le_bytes()); // length
        page_info[98] = page_type; // page_type
        page_info[99] = 0; // imi_page
        page_info[100] = 0; // vmpl3_perms
        page_info[101] = 0; // vmpl2_perms
        page_info[102] = 0; // vmpl1_perms
        page_info[103] = 0; // padding
        page_info[104..112].copy_from_slice(&gpa.to_le_bytes()); // gpa

        self.ld = sha384(&page_info);
    }

    pub fn update_normal_pages(&mut self, start_gpa: u64, data: &[u8]) {
        assert!(
            data.len().is_multiple_of(PAGE_SIZE),
            "data must be page-aligned"
        );
        let mut offset = 0;
        while offset < data.len() {
            let page_data = &data[offset..offset + PAGE_SIZE];
            self.update(
                PAGE_TYPE_NORMAL,
                start_gpa + offset as u64,
                &sha384(page_data),
            );
            offset += PAGE_SIZE;
        }
    }

    pub fn update_vmsa_page(&mut self, data: &[u8]) {
        assert_eq!(data.len(), PAGE_SIZE, "VMSA page must be 4096 bytes");
        self.update(PAGE_TYPE_VMSA, VMSA_GPA, &sha384(data));
    }

    pub fn update_zero_pages(&mut self, gpa: u64, length: usize) {
        assert!(
            length.is_multiple_of(PAGE_SIZE),
            "length must be page-aligned"
        );
        let mut offset = 0;
        while offset < length {
            self.update(PAGE_TYPE_ZERO, gpa + offset as u64, &ZEROS);
            offset += PAGE_SIZE;
        }
    }

    pub fn update_unmeasured_pages(&mut self, gpa: u64, length: usize) {
        assert!(
            length.is_multiple_of(PAGE_SIZE),
            "length must be page-aligned"
        );
        let mut offset = 0;
        while offset < length {
            self.update(PAGE_TYPE_UNMEASURED, gpa + offset as u64, &ZEROS);
            offset += PAGE_SIZE;
        }
    }

    pub fn update_secrets_page(&mut self, gpa: u64) {
        self.update(PAGE_TYPE_SECRETS, gpa, &ZEROS);
    }

    pub fn update_cpuid_page(&mut self, gpa: u64) {
        self.update(PAGE_TYPE_CPUID, gpa, &ZEROS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gctx_starts_at_zeros() {
        let gctx = Gctx::new(None);
        assert_eq!(gctx.ld(), &ZEROS);
    }

    #[test]
    fn gctx_with_seed() {
        let mut seed = [0u8; 48];
        seed[0] = 0xAB;
        let gctx = Gctx::new(Some(&seed));
        assert_eq!(gctx.ld()[0], 0xAB);
    }

    #[test]
    fn update_normal_changes_digest() {
        let mut gctx = Gctx::new(None);
        let page = [0u8; PAGE_SIZE];
        gctx.update_normal_pages(0x1000, &page);
        assert_ne!(gctx.ld(), &ZEROS);
    }
}
