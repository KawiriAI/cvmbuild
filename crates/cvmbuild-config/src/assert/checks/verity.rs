use crate::assert::types::AssertionResult;
use crate::Config;

// --- Catalog checks ---

pub fn verity_enabled(config: &Config) -> Vec<AssertionResult> {
    if config.verity.enabled {
        vec![]
    } else {
        vec![AssertionResult::error(
            "verity_enabled",
            "verity.enabled",
            "dm-verity must be enabled for CVM images",
        )]
    }
}

pub fn verity_panic_on_corruption(config: &Config) -> Vec<AssertionResult> {
    if config.verity.panic_on_corruption {
        vec![]
    } else {
        vec![AssertionResult::error(
            "verity_panic_on_corruption",
            "verity.panic_on_corruption",
            "verity must panic on corruption to prevent tampered rootfs boot",
        )]
    }
}

pub fn verity_initrd_dm_verity(config: &Config) -> Vec<AssertionResult> {
    if config
        .kernel
        .initrd_modules
        .iter()
        .any(|m| m == "dm-verity")
    {
        vec![]
    } else {
        vec![AssertionResult::error(
            "verity_initrd_dm_verity",
            "kernel.initrd_modules",
            "'dm-verity' must be in initrd_modules for dm-verity boot",
        )]
    }
}

pub fn verity_initrd_dm_mod(config: &Config) -> Vec<AssertionResult> {
    if config.kernel.initrd_modules.iter().any(|m| m == "dm-mod") {
        vec![]
    } else {
        vec![AssertionResult::error(
            "verity_initrd_dm_mod",
            "kernel.initrd_modules",
            "'dm-mod' must be in initrd_modules for dm-verity boot",
        )]
    }
}

// --- Structural checks (always-on) ---

pub fn verity_disk_device_valid(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for disk in &config.verity_disks {
        if !disk.device.starts_with("vd") || disk.device.len() != 3 {
            results.push(AssertionResult::error(
                "verity_disk_device_valid",
                "verity_disks",
                format!("device '{}' must match pattern vd[a-z]", disk.device),
            ));
        }
    }
    results
}

pub fn verity_disk_names_unique(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for disk in &config.verity_disks {
        if !seen.insert(&disk.name) {
            results.push(AssertionResult::error(
                "verity_disk_names_unique",
                "verity_disks",
                format!("duplicate disk name: '{}'", disk.name),
            ));
        }
    }
    results
}

pub fn verity_disk_devices_unique(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for disk in &config.verity_disks {
        if !seen.insert(&disk.device) {
            results.push(AssertionResult::error(
                "verity_disk_devices_unique",
                "verity_disks",
                format!("duplicate device: '{}'", disk.device),
            ));
        }
    }
    results
}
