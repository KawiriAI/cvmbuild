//! Main measurement calculation logic for all SEV modes.

use std::path::Path;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use super::gctx::Gctx;
use super::ovmf::{Ovmf, SectionType, Svsm};
use super::sev_hashes::SevHashes;
use super::types::{SevMode, VmmType};
use super::vmsa::{svsm_vmsa_pages, vmsa_pages};

const PAGE_MASK: u32 = 0xFFF;

/// Options for launch digest calculation.
pub struct LaunchDigestOptions<'a> {
    pub mode: SevMode,
    pub vcpus: u32,
    pub vcpu_sig: u32,
    pub ovmf_file: &'a Path,
    pub kernel: Option<&'a [u8]>,
    pub initrd: Option<&'a [u8]>,
    pub append: Option<&'a str>,
    pub guest_features: u64,
    pub snp_ovmf_hash: Option<&'a [u8]>,
    pub vmm_type: VmmType,
    pub svsm_file: Option<&'a Path>,
    pub ovmf_vars_size: usize,
}

impl<'a> Default for LaunchDigestOptions<'a> {
    fn default() -> Self {
        Self {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: 0,
            ovmf_file: Path::new(""),
            kernel: None,
            initrd: None,
            append: None,
            guest_features: 0x1,
            snp_ovmf_hash: None,
            vmm_type: VmmType::Qemu,
            svsm_file: None,
            ovmf_vars_size: 0,
        }
    }
}

/// Calculate the expected launch digest for a guest VM.
pub fn calc_launch_digest(opts: &LaunchDigestOptions) -> Result<Vec<u8>> {
    match opts.mode {
        SevMode::SevSnp => snp_calc_launch_digest(opts),
        SevMode::SevEs => seves_calc_launch_digest(opts),
        SevMode::Sev => sev_calc_launch_digest(opts),
        SevMode::SevSnpSvsm => {
            anyhow::ensure!(
                opts.vmm_type == VmmType::Qemu,
                "SVSM mode is only implemented for QEMU"
            );
            svsm_calc_launch_digest(opts)
        }
    }
}

/// Calculate just the SNP OVMF hash (for precalculation).
pub fn calc_snp_ovmf_hash(ovmf_file: &Path) -> Result<Vec<u8>> {
    let ovmf = Ovmf::load(ovmf_file)?;
    let mut gctx = Gctx::new(None);
    gctx.update_normal_pages(ovmf.gpa(), ovmf.data());
    Ok(gctx.ld().to_vec())
}

fn snp_update_kernel_hashes(
    gctx: &mut Gctx,
    ovmf: &Ovmf,
    sev_hashes: Option<&SevHashes>,
    gpa: u32,
    size: u32,
) -> Result<()> {
    if let Some(hashes) = sev_hashes {
        let sev_hashes_table_gpa = ovmf.sev_hashes_table_gpa()?;
        let offset_in_page = (sev_hashes_table_gpa & PAGE_MASK) as usize;
        let sev_hashes_page = hashes.construct_page(offset_in_page);
        anyhow::ensure!(
            size as usize == sev_hashes_page.len(),
            "expected size {} but got {}",
            size,
            sev_hashes_page.len()
        );
        gctx.update_normal_pages(gpa as u64, &sev_hashes_page);
    } else {
        gctx.update_zero_pages(gpa as u64, size as usize);
    }
    Ok(())
}

fn snp_update_section(
    gctx: &mut Gctx,
    ovmf: &Ovmf,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VmmType,
    gpa: u32,
    size: u32,
    section_type: SectionType,
) -> Result<()> {
    match section_type {
        SectionType::SnpSecMem => {
            if vmm_type == VmmType::Gce {
                gctx.update_unmeasured_pages(gpa as u64, size as usize);
            } else {
                gctx.update_zero_pages(gpa as u64, size as usize);
            }
        }
        SectionType::SnpSecrets => {
            gctx.update_secrets_page(gpa as u64);
        }
        SectionType::Cpuid => {
            if vmm_type != VmmType::Ec2 {
                gctx.update_cpuid_page(gpa as u64);
            }
        }
        SectionType::SnpKernelHashes => {
            snp_update_kernel_hashes(gctx, ovmf, sev_hashes, gpa, size)?;
        }
        SectionType::SvsmCaa => {
            gctx.update_zero_pages(gpa as u64, size as usize);
        }
    }
    Ok(())
}

fn snp_update_metadata_pages(
    gctx: &mut Gctx,
    ovmf: &Ovmf,
    sev_hashes: Option<&SevHashes>,
    vmm_type: VmmType,
) -> Result<()> {
    for desc in ovmf.metadata_items() {
        snp_update_section(
            gctx,
            ovmf,
            sev_hashes,
            vmm_type,
            desc.gpa,
            desc.size,
            desc.section_type,
        )?;
    }

    // EC2 measures CPUID page after all other sections
    if vmm_type == VmmType::Ec2 {
        for desc in ovmf.metadata_items() {
            if desc.section_type == SectionType::Cpuid {
                gctx.update_cpuid_page(desc.gpa as u64);
            }
        }
    }

    if sev_hashes.is_some() && !ovmf.has_metadata_section(SectionType::SnpKernelHashes) {
        anyhow::bail!(
            "Kernel specified but OVMF metadata doesn't include SNP_KERNEL_HASHES section"
        );
    }

    Ok(())
}

fn snp_calc_launch_digest(opts: &LaunchDigestOptions) -> Result<Vec<u8>> {
    let ovmf = Ovmf::load(opts.ovmf_file)?;

    let mut gctx = if let Some(ovmf_hash) = opts.snp_ovmf_hash {
        Gctx::new(Some(ovmf_hash))
    } else {
        let mut g = Gctx::new(None);
        g.update_normal_pages(ovmf.gpa(), ovmf.data());
        g
    };

    let sev_hashes = if let Some(kernel_data) = opts.kernel {
        let initrd_data = opts.initrd.unwrap_or(b"");
        Some(SevHashes::new(kernel_data, initrd_data, opts.append))
    } else {
        None
    };

    snp_update_metadata_pages(&mut gctx, &ovmf, sev_hashes.as_ref(), opts.vmm_type)?;

    let reset_eip = ovmf.sev_es_reset_eip()?;
    let pages = vmsa_pages(
        reset_eip,
        opts.vcpu_sig,
        opts.guest_features,
        opts.vmm_type,
        opts.vcpus,
    );
    for vmsa_page in &pages {
        gctx.update_vmsa_page(vmsa_page);
    }

    Ok(gctx.ld().to_vec())
}

fn svsm_calc_launch_digest(opts: &LaunchDigestOptions) -> Result<Vec<u8>> {
    let mut gctx = Gctx::new(None);
    let ovmf = Ovmf::load(opts.ovmf_file)?;
    let svsm_path = opts
        .svsm_file
        .context("svsm_file is required for SVSM mode")?;
    let svsm = Svsm::load(svsm_path, ovmf.gpa() - opts.ovmf_vars_size as u64)?;

    let eip = svsm.sev_es_reset_eip()?;

    gctx.update_normal_pages(ovmf.gpa(), ovmf.data());
    gctx.update_normal_pages(svsm.gpa(), svsm.data());

    // Use the SVSM's metadata for section updates
    snp_update_svsm_metadata_pages(&mut gctx, &svsm)?;

    let pages = svsm_vmsa_pages(eip, opts.vcpu_sig, opts.vcpus, VmmType::Qemu);
    for vmsa_page in &pages {
        gctx.update_vmsa_page(vmsa_page);
    }

    Ok(gctx.ld().to_vec())
}

fn snp_update_svsm_metadata_pages(gctx: &mut Gctx, svsm: &Svsm) -> Result<()> {
    for desc in svsm.metadata_items() {
        match desc.section_type {
            SectionType::SnpSecMem => {
                gctx.update_zero_pages(desc.gpa as u64, desc.size as usize);
            }
            SectionType::SnpSecrets => {
                gctx.update_secrets_page(desc.gpa as u64);
            }
            SectionType::Cpuid => {
                gctx.update_cpuid_page(desc.gpa as u64);
            }
            SectionType::SnpKernelHashes => {
                gctx.update_zero_pages(desc.gpa as u64, desc.size as usize);
            }
            SectionType::SvsmCaa => {
                gctx.update_zero_pages(desc.gpa as u64, desc.size as usize);
            }
        }
    }
    Ok(())
}

fn seves_calc_launch_digest(opts: &LaunchDigestOptions) -> Result<Vec<u8>> {
    let ovmf = Ovmf::load(opts.ovmf_file)?;
    let mut hasher = Sha256::new();
    hasher.update(ovmf.data());

    if opts.kernel.is_some() {
        anyhow::ensure!(
            ovmf.is_sev_hashes_table_supported(),
            "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
        );
        let kernel_data = opts.kernel.unwrap_or(b"");
        let initrd_data = opts.initrd.unwrap_or(b"");
        let sev_hashes = SevHashes::new(kernel_data, initrd_data, opts.append);
        hasher.update(sev_hashes.construct_table());
    }

    let reset_eip = ovmf.sev_es_reset_eip()?;
    let pages = vmsa_pages(reset_eip, opts.vcpu_sig, 0x0, opts.vmm_type, opts.vcpus);
    for vmsa_page in &pages {
        hasher.update(vmsa_page);
    }

    Ok(hasher.finalize().to_vec())
}

fn sev_calc_launch_digest(opts: &LaunchDigestOptions) -> Result<Vec<u8>> {
    let ovmf = Ovmf::load(opts.ovmf_file)?;
    let mut hasher = Sha256::new();
    hasher.update(ovmf.data());

    if opts.kernel.is_some() {
        anyhow::ensure!(
            ovmf.is_sev_hashes_table_supported(),
            "Kernel specified but OVMF doesn't support kernel/initrd/cmdline measurement"
        );
        let kernel_data = opts.kernel.unwrap_or(b"");
        let initrd_data = opts.initrd.unwrap_or(b"");
        let sev_hashes = SevHashes::new(kernel_data, initrd_data, opts.append);
        hasher.update(sev_hashes.construct_table());
    }

    Ok(hasher.finalize().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
    }

    const EPYC_V4_SIG: u32 = 0x00800F12;

    // --- SNP with OVMF hash ---

    #[test]
    fn snp_ovmf_hash_gen_default() {
        let ovmf_hash = hex::decode(
            "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2\
             c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74",
        )
        .unwrap();
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x21,
            snp_ovmf_hash: Some(&ovmf_hash),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "329c8ce0972ae52343b64d34a434a86f245dfd74f5ed7aae\
             15d22efc78fb9683632b9b50e4e1d7fa41179ef98a7ef198"
        );
    }

    #[test]
    fn snp_ovmf_hash_gen_feature_snp_only() {
        let ovmf_hash = hex::decode(
            "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2\
             c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74",
        )
        .unwrap();
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x1,
            snp_ovmf_hash: Some(&ovmf_hash),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "ddc5224521617a536ee7ce9dd6224d1b58a8d4fda1c741f3\
             ac99fc4bfa04ba6e9fc98646d4a07a9079397fa3852819b5"
        );
    }

    #[test]
    fn snp_ovmf_hash_full_default() {
        let ovmf_hash_vec = calc_snp_ovmf_hash(&fixtures().join("ovmf_AmdSev_suffix.bin")).unwrap();
        assert_eq!(
            hex::encode(&ovmf_hash_vec),
            "086e2e9149ebf45abdc3445fba5b2da8270bdbb04094d7a2\
             c37faaa4b24af3aa16aff8c374c2a55c467a50da6d466b74"
        );
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some("console=ttyS0 loglevel=7"),
            guest_features: 0x21,
            snp_ovmf_hash: Some(&ovmf_hash_vec),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb2\
             8c653360fe4b3aba7e534442e7e1e17895dfe778d0228977"
        );
    }

    #[test]
    fn snp_ovmf_hash_full_feature_snp_only() {
        let ovmf_hash_vec = calc_snp_ovmf_hash(&fixtures().join("ovmf_AmdSev_suffix.bin")).unwrap();
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some("console=ttyS0 loglevel=7"),
            guest_features: 0x1,
            snp_ovmf_hash: Some(&ovmf_hash_vec),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "6d287813eb5222d770f75005c664e34c204f385ce832cc2c\
             e7d0d6f354454362f390ef83a92046c042e706363b4b08fa"
        );
    }

    // --- SNP EC2 ---

    #[test]
    fn snp_ec2_default() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x21,
            vmm_type: VmmType::Ec2,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "6ae80856486b1396af8c82a40351d6ed76a20c785e9c7fa4\
             ffa27c22d5d6313b4b3b458cd3c9968e6f89fb5d8450d7a6"
        );
    }

    #[test]
    fn snp_ec2_feature_snp_only() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x1,
            vmm_type: VmmType::Ec2,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "7d3756157c805bf6adf617064c8552e8c1688fa1c8756f11\
             cbf56ba5d25c9270fb69c0505c1cbe1c5c66c0e34c6ed3be"
        );
    }

    // --- SNP GCE ---

    #[test]
    fn snp_gce_default() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: 0,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x1,
            vmm_type: VmmType::Gce,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "5da7106cf14cf46b1725ebab123eb9e53bd46a1e9f400cd0\
             c08e7827b04b688ea8b4e403c8404efed4397ea5d5d0722e"
        );
    }

    #[test]
    fn snp_gce_with_multiple_vcpus_default() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 4,
            vcpu_sig: 0,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x1,
            vmm_type: VmmType::Gce,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "5c5debf100fc339f90276e761ee1f1658d08922c3b20e2a2\
             e6c7a6c3370b2452a15a00eae11886a93d6fd1e7ab81e29d"
        );
    }

    // --- SNP direct (no precomputed OVMF hash) ---

    #[test]
    fn snp_default() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some("console=ttyS0 loglevel=7"),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "803f691094946e42068aaa3a8f9e26a5c89f36f7b73ecfb2\
             8c653360fe4b3aba7e534442e7e1e17895dfe778d0228977"
        );
    }

    #[test]
    fn snp_guest_feature_snp_only() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some("console=ttyS0 loglevel=7"),
            guest_features: 0x1,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "6d287813eb5222d770f75005c664e34c204f385ce832cc2c\
             e7d0d6f354454362f390ef83a92046c042e706363b4b08fa"
        );
    }

    #[test]
    fn snp_without_kernel_default() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "e1e1ca029dd7973ab9513295be68198472dcd4fc834bd9af\
             9b63f6e8a1674dbf281a9278a4a2ebe0eed9f22adbcd0e2b"
        );
    }

    #[test]
    fn snp_without_kernel_feature_snp_only() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            guest_features: 0x1,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "19358ba9a7615534a9a1e2f0dfc29384dcd4dcb7062ff9c6\
             013b26869a5fc6ecabe033c48dd6f6db5d6d76e7c5df632d"
        );
    }

    #[test]
    fn snp_with_multiple_vcpus_default() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 4,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "4953b1fb416fa874980e8442b3706d345926d5f38879134e\
             00813c5d7abcbe78eafe7b422907be0b4698e2414a631942"
        );
    }

    #[test]
    fn snp_with_multiple_vcpus_feature_snp_only() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 4,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x1,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "5061fffb019493a903613d56d54b94912a1a2f9e4502385f\
             5c194616753720a92441310ba6c4933de877c36e23046ad5"
        );
    }

    // --- OvmfX64 ---

    #[test]
    fn snp_with_ovmfx64_without_kernel_default() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_OvmfX64_suffix.bin"),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "28797ae0afaba4005a81e629acebfb59e6687949d6be4400\
             7cd5506823b0dd66f146aaae26ff291eed7b493d8a64c385"
        );
    }

    #[test]
    fn snp_with_ovmfx64_without_kernel_feature_snp_only() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_OvmfX64_suffix.bin"),
            guest_features: 0x1,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "da0296de8193586a5512078dcd719eccecbd87e2b825ad41\
             48c44f665dc87df21e5b49e21523a9ad993afdb6a30b4005"
        );
    }

    #[test]
    fn snp_with_ovmfx64_and_kernel_should_fail() {
        let result = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_OvmfX64_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x21,
            ..Default::default()
        });
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("SNP_KERNEL_HASHES"));
    }

    // --- SEV-ES ---

    #[test]
    fn seves() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevEs,
            vcpus: 1,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x1,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "13810ae661ea11e2bb205621f582fee268f0367c8f97bc297b7fadef3e12002c"
        );
    }

    #[test]
    fn seves_with_multiple_vcpus() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevEs,
            vcpus: 4,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "0dccbcaba8e90b261bd0d2e1863a2f9da714768b7b2a19363cd6ae35aa90de91"
        );
    }

    #[test]
    fn seves_with_ovmfx64_and_kernel_should_fail() {
        let result = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevEs,
            vcpus: 1,
            vcpu_sig: 0,
            ovmf_file: &fixtures().join("ovmf_OvmfX64_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x21,
            ..Default::default()
        });
        assert!(result.is_err());
    }

    // --- SEV ---

    #[test]
    fn sev() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::Sev,
            vcpus: 1,
            vcpu_sig: 0,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some("console=ttyS0 loglevel=7"),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "82a3ee5d537c3620628270c292ae30cb40c3c878666a7890ee7ef2a08fb535ff"
        );
    }

    #[test]
    fn sev_with_kernel_without_initrd_and_append() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::Sev,
            vcpus: 1,
            vcpu_sig: 0,
            ovmf_file: &fixtures().join("ovmf_AmdSev_suffix.bin"),
            kernel: Some(b""),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "77f613d7bbcdf12a73782ea9e88b0172aeda50d1a54201cb903594ff52846898"
        );
    }

    #[test]
    fn sev_with_ovmfx64_and_kernel_should_fail() {
        let result = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::Sev,
            vcpus: 1,
            vcpu_sig: 0,
            ovmf_file: &fixtures().join("ovmf_OvmfX64_suffix.bin"),
            kernel: Some(b""),
            initrd: Some(b""),
            append: Some(""),
            guest_features: 0x21,
            ..Default::default()
        });
        assert!(result.is_err());
    }

    #[test]
    fn sev_with_ovmfx64_without_kernel() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::Sev,
            vcpus: 1,
            vcpu_sig: 0,
            ovmf_file: &fixtures().join("ovmf_OvmfX64_suffix.bin"),
            guest_features: 0x21,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "b4c021e085fb83ceffe6571a3d357b4a98773c83c474e47f76c876708fe316da"
        );
    }

    // --- SVSM ---

    #[test]
    fn snp_svsm_4_vcpus() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnpSvsm,
            vcpus: 4,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("svsm_ovmf.fd"),
            guest_features: 0x21,
            vmm_type: VmmType::Qemu,
            svsm_file: Some(&fixtures().join("svsm.bin")),
            ovmf_vars_size: 540672,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "27d154c27b7b359c935e250ec6fee72aa0ae8c1225e3b0e1\
             cf46a9567e938066d7d6f94bbdc4a857818bdb79277a44b2"
        );
    }

    #[test]
    fn snp_svsm_2_vcpus() {
        let ld = calc_launch_digest(&LaunchDigestOptions {
            mode: SevMode::SevSnpSvsm,
            vcpus: 2,
            vcpu_sig: EPYC_V4_SIG,
            ovmf_file: &fixtures().join("svsm_ovmf.fd"),
            guest_features: 0x21,
            vmm_type: VmmType::Qemu,
            svsm_file: Some(&fixtures().join("svsm.bin")),
            ovmf_vars_size: 540672,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(
            hex::encode(&ld),
            "9b94745036aafddf4f7f8b00c7513abb5b7703178cb95aaa\
             57928bd963d68d3bfcb715d6019b9167ee2517b11b0d9be7"
        );
    }
}
