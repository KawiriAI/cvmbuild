//! RTMR (Run-Time Measurement Registers) for Intel TDX.
//!
//! Per Intel TDX Module Base Architecture Specification, Section 12.2.2,
//! RTMRs are 48-byte SHA-384 registers extended via:
//!   new_value = SHA-384(old_value || input_hash)

use anyhow::{ensure, Result};
use sha2::{Digest, Sha384};

use super::authenticode::pe_authenticode_hash;
use super::tdvf::find_cfv;
use super::types::GpuModel;

const SHA384_SIZE: usize = 48;

fn sha384(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha384::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

/// EFI_GLOBAL_VARIABLE GUID in mixed-endian (bytes_le) format.
const EFI_GLOBAL_VARIABLE: [u8; 16] = [
    0x61, 0xDF, 0xE4, 0x8B, 0xCA, 0x93, 0xD2, 0x11, 0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C,
];

/// EFI_IMAGE_SECURITY_DATABASE GUID in mixed-endian (bytes_le) format.
const EFI_IMAGE_SECURITY_DATABASE: [u8; 16] = [
    0xCB, 0xB2, 0x19, 0xD7, 0x3A, 0x3D, 0x96, 0x45, 0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F,
];

/// Run-Time Measurement Register.
pub struct Rtmr {
    value: Vec<u8>,
}

impl Default for Rtmr {
    fn default() -> Self {
        Self::new()
    }
}

impl Rtmr {
    pub fn new() -> Self {
        Self {
            value: vec![0u8; SHA384_SIZE],
        }
    }

    /// Extend the register with a 48-byte hash.
    pub fn extend(&mut self, hash_value: &[u8]) -> Result<()> {
        ensure!(
            hash_value.len() == SHA384_SIZE,
            "RTMR extend expects 48 bytes, got {}",
            hash_value.len()
        );
        let mut combined = self.value.clone();
        combined.extend_from_slice(hash_value);
        self.value = sha384(&combined);
        Ok(())
    }

    /// Hash data with SHA-384, then extend the register.
    pub fn hash_and_extend(&mut self, data: &[u8]) -> Result<()> {
        let h = sha384(data);
        self.extend(&h)
    }

    /// Extend with an EFI variable measurement (UEFI_VARIABLE_DATA structure).
    pub fn extend_variable(&mut self, guid: &[u8; 16], name: &str, data: &[u8]) -> Result<()> {
        let codepoints = encode_utf16le(name);
        let num_codepoints = codepoints.len() / 2;

        let mut varlog = vec![0u8; 32 + codepoints.len() + data.len()];
        varlog[0..16].copy_from_slice(guid);
        varlog[16..24].copy_from_slice(&(num_codepoints as u64).to_le_bytes());
        varlog[24..32].copy_from_slice(&(data.len() as u64).to_le_bytes());
        varlog[32..32 + codepoints.len()].copy_from_slice(&codepoints);
        varlog[32 + codepoints.len()..].copy_from_slice(data);

        self.hash_and_extend(&varlog)
    }

    /// Extend with a raw variable value.
    pub fn extend_variable_value(&mut self, data: &[u8]) -> Result<()> {
        self.hash_and_extend(data)
    }

    /// Extend with the standard EFI separator event (4 zero bytes).
    pub fn extend_separator(&mut self) -> Result<()> {
        self.hash_and_extend(&[0u8; 4])
    }

    /// Return the current 48-byte register value.
    pub fn get(&self) -> &[u8] {
        &self.value
    }
}

/// Validate that a CvmDsdt.aml blob has the expected ACPI header.
///
/// Checks for DSDT signature, Table ID "CVMDSDT", and consistent length.
fn validate_cvm_dsdt(data: &[u8]) -> Result<()> {
    ensure!(
        data.len() >= 36,
        "CvmDsdt.aml too small ({} bytes)",
        data.len()
    );
    ensure!(&data[0..4] == b"DSDT", "CvmDsdt.aml: bad signature");
    ensure!(&data[16..23] == b"CVMDSDT", "CvmDsdt.aml: bad Table ID");
    let len = u32::from_le_bytes(data[4..8].try_into()?) as usize;
    ensure!(
        len == data.len(),
        "CvmDsdt.aml: header length {} != file size {}",
        len,
        data.len()
    );
    Ok(())
}

/// Calculate RTMR[0] — firmware configuration measurement.
///
/// OVMF patch 0004 skips measurement of ALL QEMU fw_cfg ACPI blobs (FADT,
/// MADT, MCFG, DSDT, SSDT, etc.) and only measures the hardcoded CvmDsdt
/// template BEFORE sentinel patching.  This makes RTMR[0] independent of
/// vCPU count, GPU model/count, memory size, and other hardware config.
///
/// `dsdt` is the raw CvmDsdt.aml bytes (compiled ACPI DSDT template with
/// sentinel placeholders intact), produced alongside the firmware by the
/// OVMF build.  The firmware binary itself compresses the DSDT into an
/// LZMA firmware volume, so it cannot be extracted by scanning raw bytes.
pub fn calc_rtmr0(firmware: &[u8], dsdt: &[u8], _gpu: GpuModel) -> Result<Vec<u8>> {
    validate_cvm_dsdt(dsdt)?;

    let mut rtmr = Rtmr::new();

    // CFV hash
    let cfv = find_cfv(firmware)?;
    rtmr.hash_and_extend(&cfv)?;

    // QEMU FW CFG.BootMenu
    rtmr.extend_variable_value(b"\x00\x00")?;
    // QEMU FW CFG.BootOrder
    rtmr.extend_variable_value(b"/rom@genroms/linuxboot_dma.bin\0")?;

    // Secure boot variables (empty data = not enrolled)
    rtmr.extend_variable(&EFI_GLOBAL_VARIABLE, "SecureBoot", b"")?;
    rtmr.extend_variable(&EFI_GLOBAL_VARIABLE, "PK", b"")?;
    rtmr.extend_variable(&EFI_GLOBAL_VARIABLE, "KEK", b"")?;
    rtmr.extend_variable(&EFI_IMAGE_SECURITY_DATABASE, "db", b"")?;
    rtmr.extend_variable(&EFI_IMAGE_SECURITY_DATABASE, "dbx", b"")?;

    // Separator
    rtmr.extend_separator()?;

    // CvmDsdt — the ONLY ACPI measurement.  The raw .aml file with
    // sentinel placeholders intact (pre-patch), matching what OVMF
    // measures in CvmInstallReconstructedDsdt().
    rtmr.hash_and_extend(dsdt)?;

    Ok(rtmr.get().to_vec())
}

/// Calculate RTMR[1] — kernel image measurement.
pub fn calc_rtmr1(kernel: &[u8]) -> Result<Vec<u8>> {
    let mut rtmr = Rtmr::new();

    // Kernel Authenticode hash
    let kernel_hash = pe_authenticode_hash(kernel)?;
    rtmr.extend(&kernel_hash)?;

    // EFI boot events
    rtmr.hash_and_extend(b"Calling EFI Application from Boot Option")?;
    rtmr.extend_separator()?;
    rtmr.hash_and_extend(b"Exit Boot Services Invocation")?;
    rtmr.hash_and_extend(b"Exit Boot Services Returned with Success")?;

    Ok(rtmr.get().to_vec())
}

/// Calculate RTMR[2] — kernel command line and initrd measurement.
pub fn calc_rtmr2(cmdline: &str, initrd: &[u8]) -> Result<Vec<u8>> {
    let mut rtmr = Rtmr::new();

    // OVMF prepends "initrd=initrd " to the cmdline
    let full_cmdline = format!("initrd=initrd {cmdline}");

    // Encode as UTF-16LE with null terminator
    let mut encoded = encode_utf16le(&full_cmdline);
    encoded.extend_from_slice(&[0x00, 0x00]);
    rtmr.hash_and_extend(&encoded)?;

    // Initrd content hash
    rtmr.hash_and_extend(initrd)?;

    Ok(rtmr.get().to_vec())
}

/// Calculate RTMR[3] — reserved, always zeros.
pub fn calc_rtmr3() -> Vec<u8> {
    vec![0u8; SHA384_SIZE]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtmr_starts_at_all_zeros() {
        let rtmr = Rtmr::new();
        assert_eq!(hex::encode(rtmr.get()), "0".repeat(96));
    }

    #[test]
    fn rtmr_extend_produces_sha384_old_concat_new() {
        let mut rtmr = Rtmr::new();
        let mut input_hash = vec![0u8; 48];
        input_hash[0] = 0xAB;

        rtmr.extend(&input_hash).unwrap();

        let mut combined = vec![0u8; 48];
        combined.extend_from_slice(&input_hash);
        let expected = sha384(&combined);

        assert_eq!(hex::encode(rtmr.get()), hex::encode(&expected));
    }

    #[test]
    fn rtmr_double_extend_chains_correctly() {
        let mut rtmr = Rtmr::new();

        let mut h1 = vec![0u8; 48];
        h1[0] = 0x01;
        let mut h2 = vec![0u8; 48];
        h2[0] = 0x02;

        rtmr.extend(&h1).unwrap();
        rtmr.extend(&h2).unwrap();

        let zeros = vec![0u8; 48];
        let mut c1 = zeros;
        c1.extend_from_slice(&h1);
        let v1 = sha384(&c1);

        let mut c2 = v1;
        c2.extend_from_slice(&h2);
        let v2 = sha384(&c2);

        assert_eq!(hex::encode(rtmr.get()), hex::encode(&v2));
    }

    #[test]
    fn rtmr_hash_and_extend_hashes_then_extends() {
        let mut rtmr = Rtmr::new();
        let data = b"hello world";

        rtmr.hash_and_extend(data).unwrap();

        let data_hash = sha384(data);
        let mut combined = vec![0u8; 48];
        combined.extend_from_slice(&data_hash);
        let expected = sha384(&combined);

        assert_eq!(hex::encode(rtmr.get()), hex::encode(&expected));
    }

    #[test]
    fn rtmr_extend_rejects_wrong_length_input() {
        let mut rtmr = Rtmr::new();
        assert!(rtmr.extend(&[0u8; 32]).is_err());
    }

    #[test]
    fn calc_rtmr3_returns_all_zeros() {
        let digest = calc_rtmr3();
        assert_eq!(digest.len(), 48);
        assert_eq!(hex::encode(&digest), "0".repeat(96));
    }

    #[test]
    fn rtmr_extend_separator_uses_4_zero_bytes() {
        let mut rtmr = Rtmr::new();
        rtmr.extend_separator().unwrap();

        let sep_hash = sha384(&[0u8; 4]);
        let mut combined = vec![0u8; 48];
        combined.extend_from_slice(&sep_hash);
        let expected = sha384(&combined);

        assert_eq!(hex::encode(rtmr.get()), hex::encode(&expected));
    }
}
