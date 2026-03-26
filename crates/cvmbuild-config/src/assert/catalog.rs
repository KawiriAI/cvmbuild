use super::checks;
use super::types::{Category, CheckInfo};

/// Structural checks — always on, cannot be disabled.
pub static STRUCTURAL_CHECKS: &[CheckInfo] = &[
    // Verity structural
    CheckInfo {
        name: "verity_disk_device_valid",
        description: "verity disk device matches vd[a-z]",
        category: Category::Structural,
        check: checks::verity::verity_disk_device_valid,
    },
    CheckInfo {
        name: "verity_disk_names_unique",
        description: "verity disk names are unique",
        category: Category::Structural,
        check: checks::verity::verity_disk_names_unique,
    },
    CheckInfo {
        name: "verity_disk_devices_unique",
        description: "verity disk devices are unique",
        category: Category::Structural,
        check: checks::verity::verity_disk_devices_unique,
    },
    // Firewall structural
    CheckInfo {
        name: "firewall_proto_valid",
        description: "firewall protocol is tcp or udp",
        category: Category::Structural,
        check: checks::firewall::firewall_proto_valid,
    },
    CheckInfo {
        name: "firewall_port_nonzero",
        description: "firewall port is > 0",
        category: Category::Structural,
        check: checks::firewall::firewall_port_nonzero,
    },
    // Service structural
    CheckInfo {
        name: "service_exec_absolute_path",
        description: "service exec is absolute path",
        category: Category::Structural,
        check: checks::service::service_exec_absolute_path,
    },
    CheckInfo {
        name: "service_type_valid",
        description: "service type is valid",
        category: Category::Structural,
        check: checks::service::service_type_valid,
    },
    // Cross-cutting structural
    CheckInfo {
        name: "struct_service_names_unique",
        description: "no duplicate service names",
        category: Category::Structural,
        check: checks::structural::struct_service_names_unique,
    },
    CheckInfo {
        name: "struct_service_deps_exist",
        description: "service deps reference known units",
        category: Category::Structural,
        check: checks::structural::struct_service_deps_exist,
    },
    CheckInfo {
        name: "struct_mount_paths_no_overlap",
        description: "mount paths don't overlap",
        category: Category::Structural,
        check: checks::structural::struct_mount_paths_no_overlap,
    },
    CheckInfo {
        name: "struct_mount_paths_absolute",
        description: "mount paths are absolute",
        category: Category::Structural,
        check: checks::structural::struct_mount_paths_absolute,
    },
    CheckInfo {
        name: "struct_env_file_on_mounted_path",
        description: "env files are on mounted paths",
        category: Category::Structural,
        check: checks::structural::struct_env_file_on_mounted_path,
    },
    CheckInfo {
        name: "struct_group_refs_exist",
        description: "service groups are defined",
        category: Category::Structural,
        check: checks::structural::struct_group_refs_exist,
    },
    CheckInfo {
        name: "struct_overlay_dst_absolute",
        description: "overlay dst paths are absolute",
        category: Category::Structural,
        check: checks::structural::struct_overlay_dst_absolute,
    },
    CheckInfo {
        name: "struct_verity_disk_mountpoint_absolute",
        description: "verity disk mountpoints are absolute",
        category: Category::Structural,
        check: checks::structural::struct_verity_disk_mountpoint_absolute,
    },
    CheckInfo {
        name: "struct_verity_disk_mountpoints_unique",
        description: "verity disk mountpoints are unique",
        category: Category::Structural,
        check: checks::structural::struct_verity_disk_mountpoints_unique,
    },
    CheckInfo {
        name: "struct_device_allow_format",
        description: "device_allow is '<path> <perms>'",
        category: Category::Structural,
        check: checks::structural::struct_device_allow_format,
    },
    CheckInfo {
        name: "struct_read_write_paths_absolute",
        description: "read_write_paths are absolute",
        category: Category::Structural,
        check: checks::structural::struct_read_write_paths_absolute,
    },
    CheckInfo {
        name: "struct_image_id_valid",
        description: "image id matches [a-z][a-z0-9.-]*",
        category: Category::Structural,
        check: checks::structural::struct_image_id_valid,
    },
    CheckInfo {
        name: "struct_image_version_semver",
        description: "image version is valid semver",
        category: Category::Structural,
        check: checks::structural::struct_image_version_semver,
    },
    CheckInfo {
        name: "struct_cmdline_not_empty",
        description: "kernel cmdline is not empty",
        category: Category::Structural,
        check: checks::structural::struct_cmdline_not_empty,
    },
    CheckInfo {
        name: "struct_ovmf_path_exists",
        description: "OVMF firmware path exists on disk",
        category: Category::Structural,
        check: checks::structural::struct_ovmf_path_exists,
    },
    CheckInfo {
        name: "struct_env_var_format",
        description: "environment entries are KEY=VALUE",
        category: Category::Structural,
        check: checks::structural::struct_env_var_format,
    },
    CheckInfo {
        name: "struct_verity_disk_source_not_empty",
        description: "verity disk source is not empty string",
        category: Category::Structural,
        check: checks::structural::struct_verity_disk_source_not_empty,
    },
    CheckInfo {
        name: "struct_base_image_has_dockerfile",
        description: "base_image requires base_image_dockerfile",
        category: Category::Structural,
        check: checks::structural::struct_base_image_has_dockerfile,
    },
];

/// Catalog checks — opt-in via [assert] section.
pub static CATALOG_CHECKS: &[CheckInfo] = &[
    // Kernel cmdline (10)
    CheckInfo {
        name: "kernel_lockdown_confidentiality",
        description: "lockdown=confidentiality in cmdline",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_lockdown_confidentiality,
    },
    CheckInfo {
        name: "kernel_iommu_enabled",
        description: "IOMMU enabled in cmdline",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_iommu_enabled,
    },
    CheckInfo {
        name: "kernel_no_console",
        description: "no serial console in cmdline",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_no_console,
    },
    CheckInfo {
        name: "kernel_no_nokaslr",
        description: "nokaslr not present",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_no_nokaslr,
    },
    CheckInfo {
        name: "kernel_no_nosmap",
        description: "nosmap not present",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_no_nosmap,
    },
    CheckInfo {
        name: "kernel_no_nosmep",
        description: "nosmep not present",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_no_nosmep,
    },
    CheckInfo {
        name: "kernel_no_nopti",
        description: "nopti not present",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_no_nopti,
    },
    CheckInfo {
        name: "kernel_no_lockdown_none",
        description: "lockdown=none not present",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_no_lockdown_none,
    },
    CheckInfo {
        name: "kernel_no_lockdown_integrity",
        description: "lockdown=integrity not present",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_no_lockdown_integrity,
    },
    CheckInfo {
        name: "kernel_verity_panic",
        description: "verity panic-on-corruption in cmdline",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_verity_panic,
    },
    CheckInfo {
        name: "kernel_has_init",
        description: "explicit init= in cmdline",
        category: Category::KernelCmdline,
        check: checks::kernel::kernel_has_init,
    },
    // Verity (4)
    CheckInfo {
        name: "verity_enabled",
        description: "dm-verity enabled",
        category: Category::Verity,
        check: checks::verity::verity_enabled,
    },
    CheckInfo {
        name: "verity_panic_on_corruption",
        description: "verity panics on corruption",
        category: Category::Verity,
        check: checks::verity::verity_panic_on_corruption,
    },
    CheckInfo {
        name: "verity_initrd_dm_verity",
        description: "dm-verity in initrd modules",
        category: Category::Verity,
        check: checks::verity::verity_initrd_dm_verity,
    },
    CheckInfo {
        name: "verity_initrd_dm_mod",
        description: "dm-mod in initrd modules",
        category: Category::Verity,
        check: checks::verity::verity_initrd_dm_mod,
    },
    // Binary removal (6)
    CheckInfo {
        name: "no_shells",
        description: "bash/sh/dash removed",
        category: Category::BinaryRemoval,
        check: checks::binary::no_shells,
    },
    CheckInfo {
        name: "no_shells_extended",
        description: "all shell variants removed",
        category: Category::BinaryRemoval,
        check: checks::binary::no_shells_extended,
    },
    CheckInfo {
        name: "no_package_managers",
        description: "apt/dpkg/pip removed",
        category: Category::BinaryRemoval,
        check: checks::binary::no_package_managers,
    },
    CheckInfo {
        name: "no_package_managers_extended",
        description: "all package manager variants removed",
        category: Category::BinaryRemoval,
        check: checks::binary::no_package_managers_extended,
    },
    CheckInfo {
        name: "no_dmsetup",
        description: "dmsetup removed (RT-18)",
        category: Category::BinaryRemoval,
        check: checks::binary::no_dmsetup,
    },
    CheckInfo {
        name: "remove_package_dirs",
        description: "package manager dirs removed",
        category: Category::BinaryRemoval,
        check: checks::binary::remove_package_dirs,
    },
    // Module security (2)
    CheckInfo {
        name: "modules_locked",
        description: "kernel modules locked after init",
        category: Category::ModuleSecurity,
        check: checks::modules::modules_locked,
    },
    CheckInfo {
        name: "modules_lock_before_services",
        description: "lock-modules.service in service after lists",
        category: Category::ModuleSecurity,
        check: checks::modules::modules_lock_before_services,
    },
    // Firewall (5)
    CheckInfo {
        name: "firewall_outbound_deny",
        description: "outbound firewall is deny",
        category: Category::Firewall,
        check: checks::firewall::firewall_outbound_deny,
    },
    CheckInfo {
        name: "firewall_no_ssh",
        description: "SSH port 22 not allowed",
        category: Category::Firewall,
        check: checks::firewall::firewall_no_ssh,
    },
    CheckInfo {
        name: "firewall_no_http",
        description: "HTTP port 80 not allowed",
        category: Category::Firewall,
        check: checks::firewall::firewall_no_http,
    },
    CheckInfo {
        name: "firewall_no_telnet",
        description: "telnet port 23 not allowed",
        category: Category::Firewall,
        check: checks::firewall::firewall_no_telnet,
    },
    CheckInfo {
        name: "firewall_no_ftp",
        description: "FTP ports 20/21 not allowed",
        category: Category::Firewall,
        check: checks::firewall::firewall_no_ftp,
    },
    // Network (5)
    CheckInfo {
        name: "network_no_ipv6",
        description: "IPv6 disabled",
        category: Category::Network,
        check: checks::network::network_no_ipv6,
    },
    CheckInfo {
        name: "network_no_dns",
        description: "DNS disabled",
        category: Category::Network,
        check: checks::network::network_no_dns,
    },
    CheckInfo {
        name: "network_ntp_specified",
        description: "NTP servers configured",
        category: Category::Network,
        check: checks::network::network_ntp_specified,
    },
    CheckInfo {
        name: "network_ntp_no_pool",
        description: "NTP servers are IPs not hostnames",
        category: Category::Network,
        check: checks::network::network_ntp_no_pool,
    },
    CheckInfo {
        name: "network_ntp_private_or_known",
        description: "NTP IPs are trusted",
        category: Category::Network,
        check: checks::network::network_ntp_private_or_known,
    },
    // Service hardening (12)
    CheckInfo {
        name: "service_hardening_no_none",
        description: "no service has hardening=none",
        category: Category::ServiceHardening,
        check: checks::service::service_hardening_no_none,
    },
    CheckInfo {
        name: "service_hardening_full_or_minimal",
        description: "all services full or minimal",
        category: Category::ServiceHardening,
        check: checks::service::service_hardening_full_or_minimal,
    },
    CheckInfo {
        name: "service_no_new_privileges",
        description: "services have NoNewPrivileges",
        category: Category::ServiceHardening,
        check: checks::service::service_no_new_privileges,
    },
    CheckInfo {
        name: "service_private_tmp",
        description: "services have PrivateTmp",
        category: Category::ServiceHardening,
        check: checks::service::service_private_tmp,
    },
    CheckInfo {
        name: "service_unset_dangerous_env",
        description: "services unset LD_PRELOAD/LD_LIBRARY_PATH",
        category: Category::ServiceHardening,
        check: checks::service::service_unset_dangerous_env,
    },
    CheckInfo {
        name: "service_no_privilege_escalation_override",
        description: "no NoNewPrivileges=no override",
        category: Category::ServiceHardening,
        check: checks::service::service_no_privilege_escalation_override,
    },
    CheckInfo {
        name: "service_no_protect_system_off",
        description: "no ProtectSystem=no override",
        category: Category::ServiceHardening,
        check: checks::service::service_no_protect_system_off,
    },
    CheckInfo {
        name: "service_no_protect_home_off",
        description: "no ProtectHome=no override",
        category: Category::ServiceHardening,
        check: checks::service::service_no_protect_home_off,
    },
    CheckInfo {
        name: "service_no_private_tmp_off",
        description: "no PrivateTmp=no override",
        category: Category::ServiceHardening,
        check: checks::service::service_no_private_tmp_off,
    },
    CheckInfo {
        name: "service_no_restrict_suidsgid_off",
        description: "no RestrictSUIDSGID=no override",
        category: Category::ServiceHardening,
        check: checks::service::service_no_restrict_suidsgid_off,
    },
    CheckInfo {
        name: "service_no_memory_deny_off",
        description: "no MemoryDenyWriteExecute=no override",
        category: Category::ServiceHardening,
        check: checks::service::service_no_memory_deny_off,
    },
    CheckInfo {
        name: "service_no_protect_kernel_tunables_off",
        description: "no ProtectKernelTunables=no override",
        category: Category::ServiceHardening,
        check: checks::service::service_no_protect_kernel_tunables_off,
    },
    CheckInfo {
        name: "service_dynamic_user_preferred",
        description: "at least one service uses DynamicUser",
        category: Category::ServiceHardening,
        check: checks::service::service_dynamic_user_preferred,
    },
    // Mount security (5)
    CheckInfo {
        name: "mount_verity_disks_readonly",
        description: "verity disks mounted ro",
        category: Category::MountSecurity,
        check: checks::mount::mount_verity_disks_readonly,
    },
    CheckInfo {
        name: "mount_verity_disks_noexec",
        description: "verity disks mounted noexec",
        category: Category::MountSecurity,
        check: checks::mount::mount_verity_disks_noexec,
    },
    CheckInfo {
        name: "mount_verity_disks_nosuid",
        description: "verity disks mounted nosuid",
        category: Category::MountSecurity,
        check: checks::mount::mount_verity_disks_nosuid,
    },
    CheckInfo {
        name: "mount_verity_disks_nodev",
        description: "verity disks mounted nodev",
        category: Category::MountSecurity,
        check: checks::mount::mount_verity_disks_nodev,
    },
    CheckInfo {
        name: "mount_tmpfs_noexec",
        description: "tmpfs mounted noexec",
        category: Category::MountSecurity,
        check: checks::mount::mount_tmpfs_noexec,
    },
    // Logging (4)
    CheckInfo {
        name: "logging_volatile",
        description: "journald uses volatile storage",
        category: Category::Logging,
        check: checks::logging::logging_volatile,
    },
    CheckInfo {
        name: "logging_bounded_size",
        description: "journald size bounded",
        category: Category::Logging,
        check: checks::logging::logging_bounded_size,
    },
    CheckInfo {
        name: "logging_no_persistent",
        description: "no persistent log storage",
        category: Category::Logging,
        check: checks::logging::logging_no_persistent,
    },
    CheckInfo {
        name: "logging_no_forward_console",
        description: "no console log forwarding",
        category: Category::Logging,
        check: checks::logging::logging_no_forward_console,
    },
];
