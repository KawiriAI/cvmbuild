//! CVM image measurement calculator for AMD SEV-SNP and Intel TDX.
//!
//! Rust port of imgmsr — computes TEE launch digests from firmware,
//! kernel, initrd, and command line inputs.

pub mod common;
pub mod snp;
pub mod tdx;
