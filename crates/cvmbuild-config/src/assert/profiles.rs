/// All catalog checks — maximum security.
pub static PRODUCTION: &[&str] = &[
    // Kernel cmdline (11)
    "kernel_lockdown_confidentiality",
    "kernel_iommu_enabled",
    "kernel_no_console",
    "kernel_no_nokaslr",
    "kernel_no_nosmap",
    "kernel_no_nosmep",
    "kernel_no_nopti",
    "kernel_no_lockdown_none",
    "kernel_no_lockdown_integrity",
    "kernel_verity_panic",
    "kernel_has_init",
    // Verity (4)
    "verity_enabled",
    "verity_panic_on_corruption",
    "verity_initrd_dm_verity",
    "verity_initrd_dm_mod",
    // Binary removal (6)
    "no_shells",
    "no_shells_extended",
    "no_package_managers",
    "no_dmsetup",
    // Module security (2)
    "modules_locked",
    "modules_lock_before_services",
    // Firewall (5)
    "firewall_outbound_deny",
    "firewall_no_ssh",
    "firewall_no_http",
    "firewall_no_telnet",
    "firewall_no_ftp",
    // Network (5)
    "network_no_ipv6",
    "network_no_dns",
    "network_ntp_specified",
    "network_ntp_no_pool",
    "network_ntp_private_or_known",
    // Service hardening (13)
    "service_hardening_no_none",
    "service_hardening_full_or_minimal",
    "service_no_new_privileges",
    "service_private_tmp",
    "service_unset_dangerous_env",
    "service_no_privilege_escalation_override",
    "service_no_protect_system_off",
    "service_no_protect_home_off",
    "service_no_private_tmp_off",
    "service_no_restrict_suidsgid_off",
    "service_no_memory_deny_off",
    "service_no_protect_kernel_tunables_off",
    "service_dynamic_user_preferred",
    // Mount security (5)
    "mount_verity_disks_readonly",
    "mount_verity_disks_noexec",
    "mount_verity_disks_nosuid",
    "mount_verity_disks_nodev",
    "mount_tmpfs_noexec",
    // Logging (4)
    "logging_volatile",
    "logging_bounded_size",
    "logging_no_persistent",
    "logging_no_forward_console",
];

/// Production minus extended removals and niche checks.
pub static STANDARD: &[&str] = &[
    // Kernel cmdline (10 — drop kernel_no_lockdown_integrity)
    "kernel_lockdown_confidentiality",
    "kernel_iommu_enabled",
    "kernel_no_console",
    "kernel_no_nokaslr",
    "kernel_no_nosmap",
    "kernel_no_nosmep",
    "kernel_no_nopti",
    "kernel_no_lockdown_none",
    "kernel_verity_panic",
    "kernel_has_init",
    // Verity (4)
    "verity_enabled",
    "verity_panic_on_corruption",
    "verity_initrd_dm_verity",
    "verity_initrd_dm_mod",
    // Binary removal (4 — drop extended variants and remove_package_dirs)
    "no_shells",
    "no_package_managers",
    "no_dmsetup",
    // Module security (1 — drop modules_lock_before_services)
    "modules_locked",
    // Firewall (3 — drop telnet/ftp)
    "firewall_outbound_deny",
    "firewall_no_ssh",
    "firewall_no_http",
    // Network (3 — drop ntp_private_or_known and ntp_no_pool)
    "network_no_ipv6",
    "network_no_dns",
    "network_ntp_specified",
    // Service hardening (11 — drop unset_dangerous_env and dynamic_user_preferred)
    "service_hardening_no_none",
    "service_hardening_full_or_minimal",
    "service_no_new_privileges",
    "service_private_tmp",
    "service_no_privilege_escalation_override",
    "service_no_protect_system_off",
    "service_no_protect_home_off",
    "service_no_private_tmp_off",
    "service_no_restrict_suidsgid_off",
    "service_no_memory_deny_off",
    "service_no_protect_kernel_tunables_off",
    // Mount security (5)
    "mount_verity_disks_readonly",
    "mount_verity_disks_noexec",
    "mount_verity_disks_nosuid",
    "mount_verity_disks_nodev",
    "mount_tmpfs_noexec",
    // Logging (2 — drop bounded_size and no_forward_console)
    "logging_volatile",
    "logging_no_persistent",
];

/// Core security only. Allows shells, console, relaxed firewall.
pub static DEVELOPMENT: &[&str] = &[
    // Kernel (6)
    "kernel_lockdown_confidentiality",
    "kernel_iommu_enabled",
    "kernel_no_nokaslr",
    "kernel_no_nosmap",
    "kernel_no_nosmep",
    "kernel_no_nopti",
    // Verity (4)
    "verity_enabled",
    "verity_panic_on_corruption",
    "verity_initrd_dm_verity",
    "verity_initrd_dm_mod",
    // Binary (1)
    "no_dmsetup",
    // Module (1)
    "modules_locked",
    // Firewall (2)
    "firewall_outbound_deny",
    "firewall_no_ssh",
    // Service (3)
    "service_hardening_no_none",
    "service_no_privilege_escalation_override",
    "service_no_protect_system_off",
    // Mount (2)
    "mount_verity_disks_readonly",
    "mount_verity_disks_noexec",
    // Logging (2)
    "logging_volatile",
    "logging_no_persistent",
];

/// Fundamental CVM invariants only. Prototyping.
pub static MINIMAL: &[&str] = &[
    "verity_enabled",
    "verity_panic_on_corruption",
    "kernel_lockdown_confidentiality",
    "kernel_iommu_enabled",
    "firewall_outbound_deny",
    "modules_locked",
    "no_dmsetup",
    "logging_volatile",
];

/// Look up a profile by name.
pub fn profile_checks(name: &str) -> Option<&'static [&'static str]> {
    match name {
        "production" => Some(PRODUCTION),
        "standard" => Some(STANDARD),
        "development" => Some(DEVELOPMENT),
        "minimal" => Some(MINIMAL),
        _ => None,
    }
}

/// List all profile names.
pub fn profile_names() -> &'static [&'static str] {
    &["production", "standard", "development", "minimal"]
}
