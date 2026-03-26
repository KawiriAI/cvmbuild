use crate::assert::types::AssertionResult;
use crate::Config;

pub fn kernel_lockdown_confidentiality(config: &Config) -> Vec<AssertionResult> {
    if config.kernel.cmdline.contains("lockdown=confidentiality") {
        vec![]
    } else {
        vec![AssertionResult::error(
            "kernel_lockdown_confidentiality",
            "kernel.cmdline",
            "kernel cmdline must include 'lockdown=confidentiality'",
        )]
    }
}

pub fn kernel_iommu_enabled(config: &Config) -> Vec<AssertionResult> {
    if config.kernel.cmdline.contains("iommu=pt") || config.kernel.cmdline.contains("iommu=on") {
        vec![]
    } else {
        vec![AssertionResult::error(
            "kernel_iommu_enabled",
            "kernel.cmdline",
            "IOMMU must be enabled (iommu=pt or iommu=on)",
        )]
    }
}

pub fn kernel_no_console(config: &Config) -> Vec<AssertionResult> {
    if config.kernel.cmdline.contains("console=") {
        vec![AssertionResult::error(
            "kernel_no_console",
            "kernel.cmdline",
            "serial console in kernel cmdline leaks data in production",
        )]
    } else {
        vec![]
    }
}

fn check_cmdline_absent(
    config: &Config,
    check_name: &str,
    token: &str,
    reason: &str,
) -> Vec<AssertionResult> {
    // Check for exact token match (space-delimited)
    let has_token = config.kernel.cmdline.split_whitespace().any(|t| t == token);
    if has_token {
        vec![AssertionResult::error(check_name, "kernel.cmdline", reason)]
    } else {
        vec![]
    }
}

pub fn kernel_no_nokaslr(config: &Config) -> Vec<AssertionResult> {
    check_cmdline_absent(
        config,
        "kernel_no_nokaslr",
        "nokaslr",
        "nokaslr disables kernel ASLR — must not be present",
    )
}

pub fn kernel_no_nosmap(config: &Config) -> Vec<AssertionResult> {
    check_cmdline_absent(
        config,
        "kernel_no_nosmap",
        "nosmap",
        "nosmap disables Supervisor Mode Access Prevention — must not be present",
    )
}

pub fn kernel_no_nosmep(config: &Config) -> Vec<AssertionResult> {
    check_cmdline_absent(
        config,
        "kernel_no_nosmep",
        "nosmep",
        "nosmep disables Supervisor Mode Execution Prevention — must not be present",
    )
}

pub fn kernel_no_nopti(config: &Config) -> Vec<AssertionResult> {
    check_cmdline_absent(
        config,
        "kernel_no_nopti",
        "nopti",
        "nopti disables Page Table Isolation — must not be present",
    )
}

pub fn kernel_no_lockdown_none(config: &Config) -> Vec<AssertionResult> {
    if config.kernel.cmdline.contains("lockdown=none") {
        vec![AssertionResult::error(
            "kernel_no_lockdown_none",
            "kernel.cmdline",
            "lockdown=none explicitly disables kernel lockdown",
        )]
    } else {
        vec![]
    }
}

pub fn kernel_no_lockdown_integrity(config: &Config) -> Vec<AssertionResult> {
    // integrity is weaker than confidentiality — only block if confidentiality is not also present
    if config.kernel.cmdline.contains("lockdown=integrity")
        && !config.kernel.cmdline.contains("lockdown=confidentiality")
    {
        vec![AssertionResult::error(
            "kernel_no_lockdown_integrity",
            "kernel.cmdline",
            "lockdown=integrity is insufficient — must use lockdown=confidentiality",
        )]
    } else {
        vec![]
    }
}

pub fn kernel_has_init(config: &Config) -> Vec<AssertionResult> {
    if config.kernel.cmdline.contains("init=") {
        vec![]
    } else {
        vec![AssertionResult::warning(
            "kernel_has_init",
            "kernel.cmdline",
            "kernel cmdline should include 'init=/usr/lib/systemd/systemd' for explicit init",
        )]
    }
}

pub fn kernel_verity_panic(config: &Config) -> Vec<AssertionResult> {
    if config
        .kernel
        .cmdline
        .contains("systemd.verity_root_options=panic-on-corruption")
    {
        vec![]
    } else {
        vec![AssertionResult::error(
            "kernel_verity_panic",
            "kernel.cmdline",
            "kernel cmdline must include 'systemd.verity_root_options=panic-on-corruption'",
        )]
    }
}
