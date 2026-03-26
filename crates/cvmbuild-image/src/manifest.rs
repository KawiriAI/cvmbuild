//! Attestation manifest generation.
//!
//! Produces a JSON manifest compatible with katt (KAttValidator) for
//! verifying CVM image integrity and TEE measurements.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use cvmbuild_measure::snp::guest::{calc_launch_digest, LaunchDigestOptions};
use cvmbuild_measure::snp::types::{SevMode, VmmType};

use crate::ext4::VerityDiskResult;

/// Complete attestation manifest.
#[derive(Debug, Serialize)]
pub struct Manifest {
    #[serde(rename = "buildInputs")]
    pub build_inputs: BuildInputs,
    pub measurements: Measurements,
    pub policy: Policy,
}

/// Build-time inputs — hashes and parameters of all image artifacts.
#[derive(Debug, Serialize)]
pub struct BuildInputs {
    pub rootfs_roothash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_roothash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_hashoffset: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_roothash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hashoffset: Option<u64>,
    pub kernel_sha256: String,
    pub initrd_sha256: String,
    pub ovmf_sha256: String,
    pub cmdline: String,
}

/// TEE measurement values.
#[derive(Debug, Serialize)]
pub struct Measurements {
    pub snp: BTreeMap<String, String>,
    pub tdx: BTreeMap<String, String>,
}

/// Security policy assertions.
#[derive(Debug, Serialize)]
pub struct Policy {
    #[serde(rename = "debugDisabled")]
    pub debug_disabled: bool,
    #[serde(rename = "migrationDisabled")]
    pub migration_disabled: bool,
    #[serde(rename = "verityEnabled")]
    pub verity_enabled: bool,
    #[serde(rename = "panicOnCorruption")]
    pub panic_on_corruption: bool,
    #[serde(rename = "shellsRemoved")]
    pub shells_removed: bool,
    #[serde(rename = "outboundDeny")]
    pub outbound_deny: bool,
    #[serde(rename = "modulesLocked")]
    pub modules_locked: bool,
    #[serde(rename = "kernelLockdown")]
    pub kernel_lockdown: String,
}

/// Build the full kernel cmdline used for both boot and measurement.
///
/// Both `boot-cmd` and manifest generation MUST use this function so that
/// the cmdline measured by the hardware matches what cvmbuild precomputes.
///
/// Each verity disk entry is `(name, roothash, hashoffset)`.
pub fn build_boot_cmdline(
    base_cmdline: &str,
    rootfs_roothash: &str,
    verity_disks: &[(&str, &str, u64)],
) -> String {
    let mut cmdline = base_cmdline.to_string();
    cmdline.push_str(&format!(" roothash={rootfs_roothash}"));
    cmdline.push_str(" console=ttyS0,115200n8");
    for (name, roothash, hashoffset) in verity_disks {
        cmdline.push_str(&format!(
            " {name}_roothash={roothash} {name}_hashoffset={hashoffset}"
        ));
    }
    cmdline
}

/// Build a manifest from seal results and verity disk results.
///
/// If `kernel_path` and `initrd_path` are provided and `config.manifest.ovmf_file` is set,
/// computes real SNP LAUNCH_DIGEST measurements for all known CPU types.
pub fn build_manifest(
    config: &cvmbuild_config::Config,
    rootfs_roothash: &str,
    kernel_hash: &str,
    initrd_hash: &str,
    verity_disks: &[(&str, &VerityDiskResult)],
    kernel_path: Option<&Path>,
    initrd_path: Option<&Path>,
) -> Manifest {
    // Extract model and config disk results
    let model = verity_disks.iter().find(|(name, _)| *name == "models");
    let config_disk = verity_disks.iter().find(|(name, _)| *name == "config");

    // Build cmdline using the shared builder
    let disk_tuples: Vec<(&str, &str, u64)> = verity_disks
        .iter()
        .map(|(name, r)| (*name, r.roothash.as_str(), r.hashoffset))
        .collect();
    let cmdline = build_boot_cmdline(&config.kernel.cmdline, rootfs_roothash, &disk_tuples);

    let ovmf_sha256 = config
        .manifest
        .snp
        .ovmf_file
        .as_ref()
        .or(config.manifest.tdx.ovmf_file.as_ref())
        .and_then(|p| crate::squashfs::sha256_file(Path::new(p)).ok())
        .unwrap_or_else(|| "REQUIRES_OVMF_PATH".to_string());

    let snp = compute_snp_measurements(config, kernel_path, initrd_path, &cmdline);
    let tdx = compute_tdx_measurements(config, kernel_path, initrd_path, &cmdline);

    Manifest {
        build_inputs: BuildInputs {
            rootfs_roothash: rootfs_roothash.to_string(),
            model_roothash: model.map(|(_, r)| r.roothash.clone()),
            model_hashoffset: model.map(|(_, r)| r.hashoffset),
            config_roothash: config_disk.map(|(_, r)| r.roothash.clone()),
            config_hashoffset: config_disk.map(|(_, r)| r.hashoffset),
            kernel_sha256: kernel_hash.to_string(),
            initrd_sha256: initrd_hash.to_string(),
            ovmf_sha256,
            cmdline,
        },
        measurements: Measurements { snp, tdx },
        policy: Policy {
            debug_disabled: true,
            migration_disabled: true,
            verity_enabled: config.verity.enabled,
            panic_on_corruption: config.verity.panic_on_corruption,
            shells_removed: config.security.remove.iter().any(|r| r == "bash"),
            outbound_deny: config.firewall.outbound == "deny",
            modules_locked: config.security.lock_modules,
            kernel_lockdown: if config.kernel.cmdline.contains("lockdown=confidentiality") {
                "confidentiality".to_string()
            } else {
                "none".to_string()
            },
        },
    }
}

/// Compute SNP LAUNCH_DIGEST for all known CPU types.
///
/// Uses vcpus=1 (BSP-only VMSA — KVM patch makes measurement SMP-independent),
/// VMM=QEMU, and guest_features from config.
pub fn compute_snp_measurements(
    config: &cvmbuild_config::Config,
    kernel_path: Option<&Path>,
    initrd_path: Option<&Path>,
    cmdline: &str,
) -> BTreeMap<String, String> {
    let mut snp = BTreeMap::new();

    let ovmf_path = match config.manifest.snp.ovmf_file.as_ref() {
        Some(p) => Path::new(p),
        None => {
            snp.insert(
                "LAUNCH_DIGEST".to_string(),
                "REQUIRES_OVMF_PATH".to_string(),
            );
            return snp;
        }
    };

    // Read kernel/initrd bytes for SEV hash table
    let kernel_data = kernel_path.and_then(|p| std::fs::read(p).ok());
    let initrd_data = initrd_path.and_then(|p| std::fs::read(p).ok());

    let guest_features = config.manifest.snp.guest_features;

    // CPU types to compute measurements for
    let cpu_types: &[(&str, u32)] = &[
        ("EPYC-v4", 0x00800F12),
        ("EPYC-Rome", 0x00830F10),
        ("EPYC-Milan", 0x00A00F11),
        ("EPYC-Genoa", 0x00A10F10),
    ];

    for (cpu_name, vcpu_sig) in cpu_types {
        let opts = LaunchDigestOptions {
            mode: SevMode::SevSnp,
            vcpus: 1,
            vcpu_sig: *vcpu_sig,
            ovmf_file: ovmf_path,
            kernel: kernel_data.as_deref(),
            initrd: initrd_data.as_deref(),
            append: if kernel_data.is_some() {
                Some(cmdline)
            } else {
                None
            },
            guest_features,
            vmm_type: VmmType::Qemu,
            ..Default::default()
        };

        match calc_launch_digest(&opts) {
            Ok(digest) => {
                snp.insert(format!("SNP_{cpu_name}"), hex::encode(&digest));
            }
            Err(e) => {
                tracing::warn!("SNP measurement for {cpu_name} failed: {e:#}");
                snp.insert(format!("SNP_{cpu_name}"), format!("ERROR: {e}"));
            }
        }
    }

    snp
}

/// Compute TDX measurements (MRTD + RTMR[0-3]).
///
/// Requires a TDVF-conformant firmware at ovmf_path.
/// RTMR[1] and RTMR[2] additionally require kernel and initrd.
pub fn compute_tdx_measurements(
    config: &cvmbuild_config::Config,
    kernel_path: Option<&Path>,
    initrd_path: Option<&Path>,
    cmdline: &str,
) -> BTreeMap<String, String> {
    let mut tdx = BTreeMap::new();

    let ovmf_path = match config.manifest.tdx.ovmf_file.as_ref() {
        Some(p) => Path::new(p),
        None => {
            tdx.insert("MRTD".to_string(), "REQUIRES_OVMF_PATH".to_string());
            return tdx;
        }
    };

    let firmware = match std::fs::read(ovmf_path) {
        Ok(fw) => fw,
        Err(e) => {
            tracing::warn!("Failed to read OVMF for TDX measurement: {e:#}");
            tdx.insert("MRTD".to_string(), format!("ERROR: {e}"));
            return tdx;
        }
    };

    // MRTD — build-time firmware measurement
    match cvmbuild_measure::tdx::tdvf::calculate_mrtd(&firmware) {
        Ok(digest) => {
            tdx.insert("MRTD".to_string(), hex::encode(&digest));
        }
        Err(e) => {
            // OVMF may not have TDVF metadata (SNP-only firmware)
            tracing::debug!("TDX MRTD calculation skipped: {e:#}");
            tdx.insert("MRTD".to_string(), "NOT_TDVF_FIRMWARE".to_string());
            return tdx;
        }
    }

    // RTMR[0] — firmware configuration (CFV + boot config + SecureBoot vars + ACPI)
    // Load CvmDsdt.aml from alongside the firmware (built by Dockerfile.ovmf).
    // The DSDT is LZMA-compressed inside the firmware binary, so we need
    // the separate .aml artifact for measurement prediction.
    let dsdt_path = ovmf_path.with_file_name("CvmDsdt.aml");
    let dsdt_data = match std::fs::read(&dsdt_path) {
        Ok(d) => Some(d),
        Err(e) => {
            tracing::warn!(
                "CvmDsdt.aml not found at {}: {e:#} — RTMR0 will be skipped",
                dsdt_path.display()
            );
            None
        }
    };
    if let Some(ref dsdt) = dsdt_data {
        match cvmbuild_measure::tdx::rtmr::calc_rtmr0(
            &firmware,
            dsdt,
            cvmbuild_measure::tdx::types::GpuModel::None,
        ) {
            Ok(digest) => {
                tdx.insert("RTMR0".to_string(), hex::encode(&digest));
            }
            Err(e) => {
                tracing::warn!("TDX RTMR0 calculation failed: {e:#}");
                tdx.insert("RTMR0".to_string(), format!("ERROR: {e}"));
            }
        }
    } else {
        tdx.insert("RTMR0".to_string(), "REQUIRES_CvmDsdt.aml".to_string());
    }

    // RTMR[1] — kernel image (PE Authenticode + EFI boot events)
    let kernel_data = kernel_path.and_then(|p| std::fs::read(p).ok());
    if let Some(ref kernel) = kernel_data {
        match cvmbuild_measure::tdx::rtmr::calc_rtmr1(kernel) {
            Ok(digest) => {
                tdx.insert("RTMR1".to_string(), hex::encode(&digest));
            }
            Err(e) => {
                tracing::warn!("TDX RTMR1 calculation failed: {e:#}");
                tdx.insert("RTMR1".to_string(), format!("ERROR: {e}"));
            }
        }
    } else {
        tdx.insert("RTMR1".to_string(), "REQUIRES_KERNEL".to_string());
    }

    // RTMR[2] — kernel cmdline + initrd
    let initrd_data = initrd_path.and_then(|p| std::fs::read(p).ok());
    if let Some(ref initrd) = initrd_data {
        match cvmbuild_measure::tdx::rtmr::calc_rtmr2(cmdline, initrd) {
            Ok(digest) => {
                tdx.insert("RTMR2".to_string(), hex::encode(&digest));
            }
            Err(e) => {
                tracing::warn!("TDX RTMR2 calculation failed: {e:#}");
                tdx.insert("RTMR2".to_string(), format!("ERROR: {e}"));
            }
        }
    } else {
        tdx.insert("RTMR2".to_string(), "REQUIRES_INITRD".to_string());
    }

    // RTMR[3] — reserved, always zeros
    tdx.insert(
        "RTMR3".to_string(),
        hex::encode(cvmbuild_measure::tdx::rtmr::calc_rtmr3()),
    );

    tdx
}

/// Write manifest to a JSON file, reporting changes if an existing manifest is present.
pub fn write_manifest(manifest: &Manifest, output: &Path) -> Result<()> {
    let json = serde_json::to_string_pretty(manifest).context("serializing manifest")?;

    // Diff against existing manifest before overwriting
    if let Ok(old_content) = std::fs::read_to_string(output) {
        if let Ok(old) = serde_json::from_str::<serde_json::Value>(&old_content) {
            let new: serde_json::Value = serde_json::from_str(&json)?;
            let changes = diff_manifest_values("", &old, &new);
            if changes.is_empty() {
                tracing::info!("manifest unchanged");
            } else {
                tracing::info!(
                    "manifest updated ({} change{}):",
                    changes.len(),
                    if changes.len() == 1 { "" } else { "s" }
                );
                for change in &changes {
                    tracing::info!("  {change}");
                }
            }
        }
    }

    std::fs::write(output, &json).with_context(|| format!("writing {}", output.display()))?;
    Ok(())
}

/// Recursively diff two JSON values, returning human-readable change descriptions.
fn diff_manifest_values(
    path: &str,
    old: &serde_json::Value,
    new: &serde_json::Value,
) -> Vec<String> {
    let mut changes = Vec::new();

    match (old, new) {
        (serde_json::Value::Object(o), serde_json::Value::Object(n)) => {
            for key in o
                .keys()
                .chain(n.keys())
                .collect::<std::collections::BTreeSet<_>>()
            {
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match (o.get(key), n.get(key)) {
                    (Some(ov), Some(nv)) => {
                        changes.extend(diff_manifest_values(&child_path, ov, nv));
                    }
                    (Some(ov), None) => {
                        changes.push(format!("{child_path}: removed (was {ov})"));
                    }
                    (None, Some(nv)) => {
                        changes.push(format!("{child_path}: added {nv}"));
                    }
                    (None, None) => unreachable!(),
                }
            }
        }
        _ => {
            if old != new {
                // Truncate long values for readability
                let old_s = old.to_string();
                let new_s = new.to_string();
                let old_display = if old_s.len() > 20 {
                    format!("{}…", &old_s[..16])
                } else {
                    old_s
                };
                let new_display = if new_s.len() > 20 {
                    format!("{}…", &new_s[..16])
                } else {
                    new_s
                };
                changes.push(format!("{path}: {old_display} → {new_display}"));
            }
        }
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> cvmbuild_config::Config {
        cvmbuild_config::Config::parse(
            r#"
[image]
id = "test"
version = "0.1.0"
base = "test:latest"
[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod"]
[verity]
enabled = true
panic_on_corruption = true
[security]
remove = ["bash", "sh", "dash", "apt", "dpkg", "pip", "dmsetup"]
lock_modules = true
[firewall]
inbound = [{ port = 8443, proto = "tcp" }]
outbound = "deny"
"#,
        )
        .unwrap()
    }

    #[test]
    fn manifest_serializes_to_json() {
        let config = test_config();
        let manifest = build_manifest(&config, "aabb", "ccdd", "eeff", &[], None, None);

        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert!(json.contains("buildInputs"));
        assert!(json.contains("rootfs_roothash"));
        assert!(json.contains("aabb"));
        assert!(json.contains("measurements"));
        assert!(json.contains("policy"));
        assert!(json.contains("\"debugDisabled\": true"));
        assert!(manifest
            .build_inputs
            .cmdline
            .contains("console=ttyS0,115200n8"));
    }

    #[test]
    fn manifest_includes_verity_disk_params() {
        let config = test_config();
        let model_result = VerityDiskResult {
            image_path: std::path::PathBuf::from("models.img"),
            roothash: "deadbeef".repeat(8),
            hashoffset: 67108864,
            image_hash: "1234".repeat(16),
        };

        let manifest = build_manifest(
            &config,
            "rootaabb",
            "kerncc",
            "initee",
            &[("models", &model_result)],
            None,
            None,
        );

        assert_eq!(
            manifest.build_inputs.model_roothash.as_deref(),
            Some(&"deadbeef".repeat(8)[..])
        );
        assert_eq!(manifest.build_inputs.model_hashoffset, Some(67108864));
        assert!(manifest.build_inputs.cmdline.contains("models_roothash="));
        assert!(manifest
            .build_inputs
            .cmdline
            .contains("models_hashoffset=67108864"));
    }

    #[test]
    fn manifest_policy_from_config() {
        let config = test_config();
        let manifest = build_manifest(&config, "aa", "bb", "cc", &[], None, None);

        assert!(manifest.policy.verity_enabled);
        assert!(manifest.policy.panic_on_corruption);
        assert!(manifest.policy.shells_removed);
        assert!(manifest.policy.outbound_deny);
        assert!(manifest.policy.modules_locked);
        assert_eq!(manifest.policy.kernel_lockdown, "confidentiality");
    }

    #[test]
    fn build_boot_cmdline_includes_all_params() {
        let base = "root=/dev/mapper/root lockdown=confidentiality";
        let disks = vec![
            ("models", "deadbeef", 67108864u64),
            ("config", "cafebabe", 4096u64),
        ];
        let cmdline = build_boot_cmdline(base, "aabbccdd", &disks);
        assert_eq!(
            cmdline,
            "root=/dev/mapper/root lockdown=confidentiality \
             roothash=aabbccdd \
             console=ttyS0,115200n8 \
             models_roothash=deadbeef models_hashoffset=67108864 \
             config_roothash=cafebabe config_hashoffset=4096"
        );
    }

    #[test]
    fn write_manifest_creates_file() {
        let config = test_config();
        let manifest = build_manifest(&config, "aa", "bb", "cc", &[], None, None);

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("manifest.json");
        write_manifest(&manifest, &path).unwrap();

        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(parsed["buildInputs"]["rootfs_roothash"].is_string());
    }
}
