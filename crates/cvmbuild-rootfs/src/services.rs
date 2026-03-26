//! Generate systemd services and config files from the TOML config.
//!
//! All service units, mount units, sysusers, fstab entries, nftables, and
//! system configs are driven by the `[services]` section of the TOML config.
//! No application-specific logic (vllm, kawa, etc.) is hardcoded here.

use std::path::Path;

use anyhow::{Context, Result};
use cvmbuild_config::{Config, MountConfig, ServiceConfig};

/// Generate and write all service/config files to the rootfs.
pub fn apply_services(rootfs: &Path, config: &Config) -> Result<()> {
    // Lock-modules service (if security.lock_modules is set)
    if config.security.lock_modules {
        write_rootfs_file(
            rootfs,
            "etc/systemd/system/lock-modules.service",
            &lock_modules_service(),
        )?;
        enable_unit(rootfs, "lock-modules.service", "multi-user.target")?;
    }

    // Create mount point directories for verity disks
    for disk in &config.verity_disks {
        let mountpoint = rootfs.join(
            disk.mountpoint
                .strip_prefix('/')
                .unwrap_or(&disk.mountpoint),
        );
        std::fs::create_dir_all(&mountpoint)
            .with_context(|| format!("creating mountpoint {}", mountpoint.display()))?;
    }

    // Verity activation services (one per verity_disks entry)
    if !config.verity_disks.is_empty() {
        // Write verity-activate.py with baked-in allowed disk names
        write_rootfs_file(
            rootfs,
            "usr/local/lib/cvmbuild/verity-activate.py",
            &verity_activate_py(&config.verity_disks),
        )?;
        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = rootfs.join("usr/local/lib/cvmbuild/verity-activate.py");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    for disk in &config.verity_disks {
        let unit_file = format!("verity-{}.service", disk.name);
        write_rootfs_file(
            rootfs,
            &format!("etc/systemd/system/{unit_file}"),
            &verity_service(disk),
        )?;
        enable_unit(rootfs, &unit_file, "local-fs.target")?;
    }

    // Mask systemd-veritysetup-generator — our initrd handles root verity,
    // and the generator conflicts by trying to auto-discover GPT verity partitions
    if config.verity.enabled {
        let mask_dir = rootfs.join("etc/systemd/system-generators");
        std::fs::create_dir_all(&mask_dir)?;
        let gen_link = mask_dir.join("systemd-veritysetup-generator");
        let _ = std::fs::remove_file(&gen_link);
        std::os::unix::fs::symlink("/dev/null", &gen_link)?;
    }

    // User-defined service units from [[services.units]]
    for unit in &config.services.units {
        let unit_file = format!("{}.service", unit.name);
        write_rootfs_file(
            rootfs,
            &format!("etc/systemd/system/{unit_file}"),
            &generate_service_unit(unit),
        )?;
        enable_unit(rootfs, &unit_file, "multi-user.target")?;
    }

    // Mount units from [[services.mounts]]
    for mount in &config.services.mounts {
        let unit_name = mount_unit_name(&mount.where_);
        write_rootfs_file(
            rootfs,
            &format!("etc/systemd/system/{unit_name}"),
            &generate_mount_unit(mount),
        )?;
        enable_unit(rootfs, &unit_name, "multi-user.target")?;
    }

    // fstab
    write_rootfs_file(rootfs, "etc/fstab", &fstab_entries(config))?;

    // nftables
    write_rootfs_file(rootfs, "etc/nftables.conf", &nftables_conf(config))?;

    // networkd
    write_rootfs_file(
        rootfs,
        "etc/systemd/network/80-dhcp.network",
        &networkd_conf(),
    )?;

    // journald
    write_rootfs_file(
        rootfs,
        "etc/systemd/journald.conf.d/cvm.conf",
        &journald_conf(),
    )?;

    // sysctl hardening
    write_rootfs_file(rootfs, "etc/sysctl.d/99-cvm.conf", &sysctl_conf())?;

    // Add groups directly to /etc/group (sysusers can't run on read-only squashfs)
    if !config.services.groups.is_empty() {
        let group_path = rootfs.join("etc/group");
        let mut group_content = std::fs::read_to_string(&group_path).unwrap_or_default();
        // Collect existing GIDs to find a free one in the 900-999 system range
        let used_gids: std::collections::HashSet<u32> = group_content
            .lines()
            .filter_map(|l| l.split(':').nth(2))
            .filter_map(|g| g.parse::<u32>().ok())
            .collect();
        // Allocate from 900 downward (system group range, avoids 65534/65535 sentinels)
        let mut next_gid = (900..=990)
            .rev()
            .find(|gid| !used_gids.contains(gid))
            .unwrap_or(800);
        for g in &config.services.groups {
            // Only add if not already present
            if !group_content
                .lines()
                .any(|l| l.starts_with(&format!("{}:", g.name)))
            {
                group_content.push_str(&format!("{}:x:{}:\n", g.name, next_gid));
                // Find next free GID
                next_gid = (100..next_gid)
                    .rev()
                    .find(|gid| !used_gids.contains(gid))
                    .unwrap_or(next_gid.saturating_sub(1));
            }
        }
        std::fs::write(&group_path, &group_content)
            .with_context(|| format!("writing {}", group_path.display()))?;

        // Also update /etc/gshadow if it exists
        let gshadow_path = rootfs.join("etc/gshadow");
        if gshadow_path.exists() {
            let mut gshadow = std::fs::read_to_string(&gshadow_path).unwrap_or_default();
            for g in &config.services.groups {
                if !gshadow
                    .lines()
                    .any(|l| l.starts_with(&format!("{}:", g.name)))
                {
                    gshadow.push_str(&format!("{}:!*::\n", g.name));
                }
            }
            std::fs::write(&gshadow_path, &gshadow)?;
        }
    }

    // Add static users for services that use user= (DynamicUser doesn't work on RO squashfs)
    {
        let passwd_path = rootfs.join("etc/passwd");
        let shadow_path = rootfs.join("etc/shadow");
        let group_path = rootfs.join("etc/group");
        let mut passwd = std::fs::read_to_string(&passwd_path).unwrap_or_default();
        let mut shadow = std::fs::read_to_string(&shadow_path).unwrap_or_default();
        let group_content = std::fs::read_to_string(&group_path).unwrap_or_default();

        // Collect existing UIDs
        let used_uids: std::collections::HashSet<u32> = passwd
            .lines()
            .filter_map(|l| l.split(':').nth(2))
            .filter_map(|u| u.parse::<u32>().ok())
            .collect();

        let mut next_uid = 900u32;

        for svc in &config.services.units {
            if let Some(ref user) = svc.user {
                if passwd.lines().any(|l| l.starts_with(&format!("{user}:"))) {
                    continue;
                }
                // Allocate UID from 900 downward
                let uid = (100..=next_uid)
                    .rev()
                    .find(|u| !used_uids.contains(u))
                    .unwrap_or(next_uid);
                next_uid = uid.saturating_sub(1);

                // Resolve primary group GID
                let gid = svc
                    .group
                    .as_deref()
                    .and_then(|g| {
                        group_content
                            .lines()
                            .find(|l| l.starts_with(&format!("{g}:")))
                            .and_then(|l| l.split(':').nth(2))
                            .and_then(|g| g.parse::<u32>().ok())
                    })
                    .unwrap_or(uid); // fallback: GID = UID

                passwd.push_str(&format!(
                    "{user}:x:{uid}:{gid}::/nonexistent:/usr/sbin/nologin\n",
                ));
                shadow.push_str(&format!("{user}:!*:19785::::::\n"));
                tracing::info!("Created static user {user} uid={uid} gid={gid}");
            }
        }

        std::fs::write(&passwd_path, &passwd)
            .with_context(|| format!("writing {}", passwd_path.display()))?;
        if shadow_path.exists() {
            std::fs::write(&shadow_path, &shadow)
                .with_context(|| format!("writing {}", shadow_path.display()))?;
        }
    }

    // Mask distro services that fail or are useless in a read-only CVM
    for unit in &[
        "proc-sys-fs-binfmt_misc.automount", // lockdown=confidentiality blocks binfmt_misc
        "proc-sys-fs-binfmt_misc.mount",     // lockdown=confidentiality blocks it
        "systemd-binfmt.service",            // depends on binfmt_misc mount
        "e2scrub_reap.service",              // ext4 scrub, useless on squashfs
        "serial-getty@ttyS0.service",        // VT100 escape sequences pollute serial console
    ] {
        mask_unit(rootfs, unit)?;
    }

    // Enable system services: systemd-networkd (DHCP), nftables (firewall)
    enable_system_unit(rootfs, "systemd-networkd.service", "multi-user.target")?;
    enable_system_unit(
        rootfs,
        "systemd-networkd-wait-online.service",
        "network-online.target",
    )?;
    if !config.firewall.inbound.is_empty() || config.firewall.outbound == "deny" {
        enable_system_unit(rootfs, "nftables.service", "multi-user.target")?;
        // nftables needs nf_tables + nft_ct (for ct state) + nf_conntrack
        // kernel modules.  The distro unit has DefaultDependencies=no so it
        // can start before modules are loaded — add ordering + preload list.
        write_rootfs_file(
            rootfs,
            "etc/systemd/system/nftables.service.d/after-modules.conf",
            "[Unit]\nAfter=systemd-modules-load.service\n",
        )?;
        write_rootfs_file(
            rootfs,
            "etc/modules-load.d/nftables.conf",
            "# nftables firewall modules — loaded before nftables.service\n\
             nf_tables\n\
             nfnetlink\n\
             nf_conntrack\n\
             nft_ct\n",
        )?;
    }

    // udev rules for verity disks
    if !config.verity_disks.is_empty() {
        write_rootfs_file(
            rootfs,
            "etc/udev/rules.d/99-z-cvmbuild-verity.rules",
            &udev_rules(config),
        )?;
    }

    Ok(())
}

/// Create a systemd enable symlink: {target}.wants/{unit} → /etc/systemd/system/{unit}
fn enable_unit(rootfs: &Path, unit: &str, target: &str) -> Result<()> {
    let wants_dir = rootfs.join(format!("etc/systemd/system/{target}.wants"));
    std::fs::create_dir_all(&wants_dir)?;
    let link = wants_dir.join(unit);
    // Remove any pre-existing symlink/file (idempotent for --skip-container reuse)
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(format!("/etc/systemd/system/{unit}"), &link)?;
    Ok(())
}

/// Mask a systemd unit by symlinking it to /dev/null.
fn mask_unit(rootfs: &Path, unit: &str) -> Result<()> {
    let system_dir = rootfs.join("etc/systemd/system");
    std::fs::create_dir_all(&system_dir)?;
    let link = system_dir.join(unit);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink("/dev/null", &link)?;
    Ok(())
}

/// Enable a distribution-provided systemd unit (lives in /usr/lib/systemd/system/).
fn enable_system_unit(rootfs: &Path, unit: &str, target: &str) -> Result<()> {
    let wants_dir = rootfs.join(format!("etc/systemd/system/{target}.wants"));
    std::fs::create_dir_all(&wants_dir)?;
    let link = wants_dir.join(unit);
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(format!("/usr/lib/systemd/system/{unit}"), &link)?;
    Ok(())
}

fn write_rootfs_file(rootfs: &Path, rel_path: &str, content: &str) -> Result<()> {
    let path = rootfs.join(rel_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Service generators
// ---------------------------------------------------------------------------

fn lock_modules_service() -> String {
    "\
[Unit]
Description=Lock kernel modules — disable further module loading
After=systemd-modules-load.service systemd-udev-settle.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/sysctl -w kernel.modules_disabled=1
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes

[Install]
WantedBy=multi-user.target
"
    .to_string()
}

fn verity_service(disk: &cvmbuild_config::VerityDiskConfig) -> String {
    format!(
        "\
[Unit]
Description=dm-verity activation for {description}
DefaultDependencies=no
After=dev-{device}.device local-fs-pre.target
Requires=dev-{device}.device
Before=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
Environment=DM_DISABLE_UDEV=1
ExecStart=/usr/bin/python3 -I /usr/local/lib/cvmbuild/verity-activate.py {name} /dev/{device}

[Install]
WantedBy=local-fs.target
",
        name = disk.name,
        device = disk.device,
        description = disk.description,
    )
}

/// Generate a systemd service unit from a generic ServiceConfig.
fn generate_service_unit(svc: &ServiceConfig) -> String {
    let mut unit = String::new();

    // [Unit] section
    unit.push_str("[Unit]\n");
    unit.push_str(&format!("Description={}\n", svc.description));

    if !svc.after.is_empty() {
        unit.push_str(&format!("After={}\n", svc.after.join(" ")));
    }
    if !svc.requires.is_empty() {
        unit.push_str(&format!("Requires={}\n", svc.requires.join(" ")));
    }
    if !svc.wants.is_empty() {
        unit.push_str(&format!("Wants={}\n", svc.wants.join(" ")));
    }
    // StartLimit* directives belong in [Unit], not [Service]
    for opt in &svc.extra_options {
        if opt.starts_with("StartLimit") {
            unit.push_str(opt);
            unit.push('\n');
        }
    }

    // [Service] section
    unit.push_str("\n[Service]\n");
    unit.push_str(&format!("Type={}\n", svc.service_type));
    unit.push_str(&format!("ExecStart={}\n", svc.exec));

    if let Some(ref env_file) = svc.environment_file {
        unit.push_str(&format!("EnvironmentFile={env_file}\n"));
    }
    for env in &svc.environment {
        unit.push_str(&format!("Environment={env}\n"));
    }
    if !svc.unset_environment.is_empty() {
        unit.push_str(&format!(
            "UnsetEnvironment={}\n",
            svc.unset_environment.join(" ")
        ));
    }

    unit.push_str("Restart=on-failure\n");
    unit.push_str("RestartSec=5\n");
    // Log to both journal and serial console for debugging
    unit.push_str("StandardOutput=journal+console\n");
    unit.push_str("StandardError=journal+console\n");

    // User/group
    if let Some(true) = svc.dynamic_user {
        unit.push_str("DynamicUser=yes\n");
    }
    if let Some(ref user) = svc.user {
        unit.push_str(&format!("User={user}\n"));
        unit.push_str("WorkingDirectory=/\n");
    }
    if let Some(ref group) = svc.group {
        unit.push_str(&format!("Group={group}\n"));
    }
    if !svc.supplementary_groups.is_empty() {
        unit.push_str(&format!(
            "SupplementaryGroups={}\n",
            svc.supplementary_groups.join(" ")
        ));
    }

    // Hardening
    apply_hardening(&mut unit, &svc.hardening);

    // Read-write paths
    for path in &svc.read_write_paths {
        unit.push_str(&format!("ReadWritePaths={path}\n"));
    }

    // Device allow
    for dev in &svc.device_allow {
        unit.push_str(&format!("DeviceAllow={dev}\n"));
    }

    // Extra options (raw lines, skip StartLimit* already emitted in [Unit])
    for opt in &svc.extra_options {
        if !opt.starts_with("StartLimit") {
            unit.push_str(opt);
            unit.push('\n');
        }
    }

    // [Install] section
    unit.push_str("\n[Install]\n");
    unit.push_str("WantedBy=multi-user.target\n");

    unit
}

/// Apply hardening directives based on the hardening level string.
fn apply_hardening(unit: &mut String, level: &str) {
    match level {
        "full" => {
            unit.push_str("PrivateTmp=yes\n");
            unit.push_str("NoNewPrivileges=yes\n");
            unit.push_str("ProtectSystem=strict\n");
            unit.push_str("ProtectHome=yes\n");
            unit.push_str("ProtectKernelTunables=yes\n");
            unit.push_str("ProtectKernelModules=yes\n");
            unit.push_str("ProtectKernelLogs=yes\n");
            unit.push_str("ProtectControlGroups=yes\n");
            unit.push_str("RestrictNamespaces=yes\n");
            unit.push_str("RestrictRealtime=yes\n");
            unit.push_str("RestrictSUIDSGID=yes\n");
            unit.push_str("LockPersonality=yes\n");
            unit.push_str("ProtectHostname=yes\n");
            unit.push_str("ProtectClock=yes\n");
            unit.push_str("ProtectProc=invisible\n");
        }
        "minimal" => {
            unit.push_str("NoNewPrivileges=yes\n");
            unit.push_str("ProtectSystem=strict\n");
        }
        _ => {
            // "none" or unknown — no hardening
        }
    }
}

// ---------------------------------------------------------------------------
// Mount unit generator
// ---------------------------------------------------------------------------

/// Generate a systemd mount unit from MountConfig.
fn generate_mount_unit(mount: &MountConfig) -> String {
    let mut unit = String::new();

    unit.push_str("[Unit]\n");
    if let Some(ref desc) = mount.description {
        unit.push_str(&format!("Description={desc}\n"));
    }
    if let Some(ref cond) = mount.condition_path_exists {
        unit.push_str(&format!("ConditionPathExists={cond}\n"));
    }

    unit.push_str("\n[Mount]\n");
    unit.push_str(&format!("What={}\n", mount.what));
    unit.push_str(&format!("Where={}\n", mount.where_));
    unit.push_str(&format!("Type={}\n", mount.fs_type));

    unit.push_str("\n[Install]\n");
    unit.push_str("WantedBy=multi-user.target\n");

    unit
}

/// Convert a mount path to a systemd mount unit filename.
/// e.g., "/sys/kernel/config" → "sys-kernel-config.mount"
fn mount_unit_name(path: &str) -> String {
    let stripped = path.strip_prefix('/').unwrap_or(path);
    let escaped = stripped.replace('/', "-");
    format!("{escaped}.mount")
}

// ---------------------------------------------------------------------------
// System config generators (fstab, nftables, networkd, journald, sysctl, udev)
// ---------------------------------------------------------------------------

fn fstab_entries(_config: &Config) -> String {
    let mut fstab = String::from("# Generated by cvmbuild\n");

    // tmpfs mounts
    fstab.push_str("tmpfs /tmp tmpfs mode=1777,strictatime,noexec,nosuid,nodev,size=50% 0 0\n");
    fstab.push_str("tmpfs /var/log tmpfs mode=0755,strictatime,noexec,nosuid,nodev,size=1G 0 0\n");
    fstab.push_str(
        "tmpfs /var/lib/systemd tmpfs mode=0755,strictatime,noexec,nosuid,nodev,size=32M 0 0\n",
    );

    // Verity disk mounts are handled by verity-activate.py (not fstab)
    // because DM_DISABLE_UDEV=1 prevents systemd device readiness detection

    fstab
}

fn nftables_conf(config: &Config) -> String {
    // Build inbound port rules from config.firewall.inbound
    let mut inbound_rules = String::new();
    for rule in &config.firewall.inbound {
        inbound_rules.push_str(&format!(
            "        {} dport {} ct state new accept\n",
            rule.proto, rule.port
        ));
    }

    let ntp_addrs = if config.services.network.ntp_servers.is_empty() {
        "162.159.200.1, 162.159.200.123".to_string()
    } else {
        config.services.network.ntp_servers.join(", ")
    };

    format!(
        "\
#!/usr/sbin/nft -f
flush ruleset

table inet filter {{
    chain input {{
        type filter hook input priority 0; policy drop;
        iif \"lo\" accept
        ct state established,related accept
{inbound_rules}\
    }}

    chain forward {{
        type filter hook forward priority 0; policy drop;
    }}

    chain output {{
        type filter hook output priority 0; policy drop;
        oif \"lo\" accept
        ct state established,related accept
        ip daddr {{ {ntp_addrs} }} udp dport 123 accept
    }}
}}
"
    )
}

fn networkd_conf() -> String {
    "\
[Match]
Name=en*

[Network]
DHCP=yes
IPv6AcceptRA=no
LinkLocalAddressing=no

[DHCPv4]
UseDNS=no
UseNTP=no
UseHostname=no
"
    .to_string()
}

fn journald_conf() -> String {
    "\
[Journal]
Storage=volatile
RuntimeMaxUse=16M
RuntimeMaxFileSize=4M
"
    .to_string()
}

fn sysctl_conf() -> String {
    "\
fs.suid_dumpable = 0
kernel.core_pattern = |/bin/false
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
"
    .to_string()
}

fn udev_rules(config: &Config) -> String {
    let mut rules =
        String::from("# cvmbuild dm-verity — mark verity devices as ready for systemd\n");
    for disk in &config.verity_disks {
        rules.push_str(&format!(
            "SUBSYSTEM==\"block\", ENV{{DM_NAME}}==\"verity-{name}\", ENV{{SYSTEMD_READY}}=\"1\"\n",
            name = disk.name,
        ));
    }
    rules
}

/// Generate verity-activate.py script with allowed disk names baked in.
/// This is written to the rootfs so the verity-{name}.service units can call it.
fn verity_activate_py(verity_disks: &[cvmbuild_config::VerityDiskConfig]) -> String {
    let allowed_names = verity_disks
        .iter()
        .map(|d| format!("\"{}\"", d.name))
        .collect::<Vec<_>>()
        .join(", ");
    let disk_name_help = verity_disks
        .iter()
        .map(|d| d.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    // Bake in name → mountpoint mapping
    let mountpoint_entries = verity_disks
        .iter()
        .map(|d| format!("    \"{}\": \"{}\"", d.name, d.mountpoint))
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r#"#!/usr/bin/python3 -I
"""cvmbuild dm-verity activation — reads roothash/hashoffset from /proc/cmdline."""

import os
import subprocess
import sys


def parse_cmdline(name):
    with open("/proc/cmdline", "r") as f:
        cmdline = f.read().strip()
    params = {{}}
    for token in cmdline.split():
        if "=" in token:
            key, _, value = token.partition("=")
            params[key] = value
    roothash = params.get(f"{{name}}_roothash")
    if not roothash:
        print(f"FATAL: {{name}}_roothash not found in kernel cmdline", file=sys.stderr)
        sys.exit(1)
    hashoffset = params.get(f"{{name}}_hashoffset")
    if not hashoffset:
        print(f"FATAL: {{name}}_hashoffset not found in kernel cmdline", file=sys.stderr)
        sys.exit(1)
    try:
        bytes.fromhex(roothash)
    except ValueError:
        print(f"FATAL: {{name}}_roothash is not valid hex", file=sys.stderr)
        sys.exit(1)
    return roothash, int(hashoffset)


def activate_verity(name, device):
    roothash, hashoffset = parse_cmdline(name)
    mapper_name = f"verity-{{name}}"
    print(f"verity-activate: opening {{device}} as /dev/mapper/{{mapper_name}}")
    print(f"  roothash:   {{roothash}}")
    print(f"  hashoffset: {{hashoffset}}")
    data_blocks = hashoffset // 4096
    result = subprocess.run(
        ["/usr/sbin/veritysetup", "open",
         "--no-superblock", "--format=1",
         "--hash=sha256", "--data-block-size=4096", "--hash-block-size=4096",
         "--salt=-", f"--data-blocks={{data_blocks}}",
         f"--hash-offset={{hashoffset}}", "--panic-on-corruption",
         device, mapper_name, device, roothash],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"FATAL: veritysetup failed (exit {{result.returncode}})", file=sys.stderr)
        if result.stderr:
            print(f"  stderr: {{result.stderr.strip()}}", file=sys.stderr)
        sys.exit(1)
    print(f"verity-activate: /dev/mapper/{{mapper_name}} is now active")

    # Mount the filesystem
    mountpoint = MOUNTPOINTS.get(name)
    if mountpoint:
        dm_path = f"/dev/mapper/{{mapper_name}}"
        os.makedirs(mountpoint, exist_ok=True)
        mount_result = subprocess.run(
            ["/usr/bin/mount", "-t", "ext4", "-o", "ro,noatime,noexec,nosuid,nodev",
             dm_path, mountpoint],
            capture_output=True, text=True,
        )
        if mount_result.returncode != 0:
            print(f"FATAL: mount {{dm_path}} → {{mountpoint}} failed", file=sys.stderr)
            if mount_result.stderr:
                print(f"  stderr: {{mount_result.stderr.strip()}}", file=sys.stderr)
            sys.exit(1)
        print(f"verity-activate: mounted {{dm_path}} → {{mountpoint}}")


MOUNTPOINTS = {{
{mountpoint_entries}
}}


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {{sys.argv[0]}} <name> <device>", file=sys.stderr)
        print("  name:   disk name ({disk_name_help})", file=sys.stderr)
        print("  device: block device (/dev/vdb, /dev/vdc)", file=sys.stderr)
        sys.exit(1)
    name = sys.argv[1]
    device = sys.argv[2]
    ALLOWED_NAMES = ({allowed_names})
    if name not in ALLOWED_NAMES:
        print(f"FATAL: disk name must be one of {{ALLOWED_NAMES}}", file=sys.stderr)
        sys.exit(1)
    if not device.startswith("/dev/") or ".." in device:
        print(f"FATAL: invalid device path", file=sys.stderr)
        sys.exit(1)
    activate_verity(name, device)


if __name__ == "__main__":
    main()
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        cvmbuild_config::Config::parse(
            r#"
[image]
id = "test"
version = "0.1.0"
base = "test:latest"
[kernel]
cmdline = "lockdown=confidentiality iommu=pt"
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
[[verity_disks]]
name = "models"
device = "vdb"
mountpoint = "/mnt/models"
description = "model weights"
[[verity_disks]]
name = "config"
device = "vdc"
mountpoint = "/mnt/config"
description = "config disk"
[services]
network = { ntp_servers = ["1.2.3.4"] }

[[services.groups]]
name = "vllm-ipc"

[[services.mounts]]
what = "configfs"
where = "/sys/kernel/config"
type = "configfs"
description = "Kernel Configuration File System"
condition_path_exists = "/sys/kernel/config"

[[services.units]]
name = "myapp"
description = "My application service"
exec = "/usr/local/bin/myapp"
after = ["mnt-config.mount"]
requires = ["mnt-config.mount"]
environment_file = "/mnt/config/config.env"
environment = ["DO_NOT_TRACK=1"]
unset_environment = ["LD_PRELOAD"]
hardening = "full"
dynamic_user = true

[[services.units]]
name = "proxy"
description = "Reverse proxy"
exec = "/usr/local/bin/proxy"
after = ["myapp.service", "network-online.target"]
wants = ["network-online.target"]
hardening = "full"
supplementary_groups = ["vllm-ipc"]
read_write_paths = ["/sys/kernel/config"]
device_allow = ["/dev/sev-guest rw"]
"#,
        )
        .unwrap()
    }

    #[test]
    fn lock_modules_service_content() {
        let svc = lock_modules_service();
        assert!(svc.contains("kernel.modules_disabled=1"));
        assert!(svc.contains("WantedBy=multi-user.target"));
        // Should NOT reference any specific application
        assert!(!svc.contains("vllm"));
    }

    #[test]
    fn verity_service_content() {
        let config = test_config();
        let svc = verity_service(&config.verity_disks[0]);
        assert!(svc.contains("verity-activate.py models /dev/vdb"));
        assert!(svc.contains("DM_DISABLE_UDEV=1"));
        assert!(svc.contains("dev-vdb.device"));
    }

    #[test]
    fn generic_service_unit_generation() {
        let config = test_config();
        let svc = generate_service_unit(&config.services.units[0]);
        assert!(svc.contains("Description=My application service"));
        assert!(svc.contains("ExecStart=/usr/local/bin/myapp"));
        assert!(svc.contains("After=mnt-config.mount"));
        assert!(svc.contains("EnvironmentFile=/mnt/config/config.env"));
        assert!(svc.contains("Environment=DO_NOT_TRACK=1"));
        assert!(svc.contains("UnsetEnvironment=LD_PRELOAD"));
        assert!(svc.contains("DynamicUser=yes"));
        assert!(svc.contains("NoNewPrivileges=yes"));
        assert!(svc.contains("ProtectSystem=strict"));
    }

    #[test]
    fn generic_service_with_extras() {
        let config = test_config();
        let svc = generate_service_unit(&config.services.units[1]);
        assert!(svc.contains("Description=Reverse proxy"));
        assert!(svc.contains("Wants=network-online.target"));
        assert!(svc.contains("SupplementaryGroups=vllm-ipc"));
        assert!(svc.contains("ReadWritePaths=/sys/kernel/config"));
        assert!(svc.contains("DeviceAllow=/dev/sev-guest rw"));
    }

    #[test]
    fn mount_unit_generation() {
        let config = test_config();
        let mount = generate_mount_unit(&config.services.mounts[0]);
        assert!(mount.contains("What=configfs"));
        assert!(mount.contains("Where=/sys/kernel/config"));
        assert!(mount.contains("Type=configfs"));
        assert!(mount.contains("ConditionPathExists=/sys/kernel/config"));
    }

    #[test]
    fn mount_unit_name_escaping() {
        assert_eq!(
            mount_unit_name("/sys/kernel/config"),
            "sys-kernel-config.mount"
        );
        assert_eq!(mount_unit_name("/mnt/data"), "mnt-data.mount");
    }

    #[test]
    fn fstab_has_tmpfs_mounts() {
        let config = test_config();
        let fstab = fstab_entries(&config);
        // Verity disk mounts are handled by verity-activate.py, not fstab
        assert!(!fstab.contains("/dev/mapper/verity-models"));
        assert!(fstab.contains("tmpfs /tmp"));
    }

    #[test]
    fn nftables_uses_firewall_config() {
        let config = test_config();
        let nft = nftables_conf(&config);
        assert!(nft.contains("tcp dport 8443"));
        assert!(nft.contains("1.2.3.4"));
        assert!(nft.contains("policy drop"));
    }

    #[test]
    fn sysusers_from_groups() {
        let config = test_config();
        let sysusers = config
            .services
            .groups
            .iter()
            .map(|g| format!("g {} -", g.name))
            .collect::<Vec<_>>()
            .join("\n")
            + "\n";
        assert_eq!(sysusers, "g vllm-ipc -\n");
    }

    #[test]
    fn apply_writes_files() {
        let config = test_config();
        let tmp = tempfile::tempdir().unwrap();
        let rootfs = tmp.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();

        apply_services(&rootfs, &config).unwrap();

        assert!(rootfs
            .join("etc/systemd/system/lock-modules.service")
            .exists());
        assert!(rootfs
            .join("etc/systemd/system/verity-models.service")
            .exists());
        assert!(rootfs
            .join("etc/systemd/system/verity-config.service")
            .exists());
        assert!(rootfs.join("etc/systemd/system/myapp.service").exists());
        assert!(rootfs.join("etc/systemd/system/proxy.service").exists());
        assert!(rootfs
            .join("etc/systemd/system/sys-kernel-config.mount")
            .exists());
        assert!(rootfs.join("etc/fstab").exists());
        assert!(rootfs.join("etc/nftables.conf").exists());
        assert!(rootfs.join("etc/systemd/network/80-dhcp.network").exists());
        assert!(rootfs.join("etc/sysctl.d/99-cvm.conf").exists());
        assert!(rootfs
            .join("etc/udev/rules.d/99-z-cvmbuild-verity.rules")
            .exists());
    }
}
