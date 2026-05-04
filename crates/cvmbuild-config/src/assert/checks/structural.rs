use crate::assert::types::AssertionResult;
use crate::Config;

pub fn struct_service_names_unique(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for unit in &config.services.units {
        if !seen.insert(&unit.name) {
            results.push(AssertionResult::error(
                "struct_service_names_unique",
                "services.units",
                format!("duplicate service name: '{}'", unit.name),
            ));
        }
    }
    results
}

pub fn struct_service_deps_exist(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    let mut known = std::collections::HashSet::new();

    // Well-known system units
    for unit in &[
        "network-online.target",
        "multi-user.target",
        "local-fs.target",
        "local-fs-pre.target",
        "systemd-modules-load.service",
        "systemd-udev-settle.service",
        "default.target",
        "sysinit.target",
        "basic.target",
        "sockets.target",
    ] {
        known.insert(unit.to_string());
    }

    if config.security.lock_modules {
        known.insert("lock-modules.service".to_string());
    }

    for disk in &config.verity_disks {
        known.insert(format!("verity-{}.service", disk.name));
        // Verity disks get fstab mounts
        let stripped = disk
            .mountpoint
            .strip_prefix('/')
            .unwrap_or(&disk.mountpoint);
        let escaped = stripped.replace('/', "-");
        known.insert(format!("{escaped}.mount"));
    }

    for mount in &config.services.mounts {
        let stripped = mount.where_.strip_prefix('/').unwrap_or(&mount.where_);
        let escaped = stripped.replace('/', "-");
        known.insert(format!("{escaped}.mount"));
    }

    for unit in &config.services.units {
        known.insert(format!("{}.service", unit.name));
    }

    for unit in &config.services.units {
        for dep in unit
            .after
            .iter()
            .chain(unit.requires.iter())
            .chain(unit.wants.iter())
        {
            if !known.contains(dep.as_str()) {
                results.push(AssertionResult::error(
                    "struct_service_deps_exist",
                    &format!("services.units[{}]", unit.name),
                    format!(
                        "service '{}' depends on '{}' which is not a known unit",
                        unit.name, dep
                    ),
                ));
            }
        }
    }

    results
}

pub fn struct_mount_paths_no_overlap(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    let paths: Vec<&str> = config
        .services
        .mounts
        .iter()
        .map(|m| m.where_.as_str())
        .collect();
    for (i, a) in paths.iter().enumerate() {
        for b in &paths[i + 1..] {
            let a_slash = if a.ends_with('/') {
                a.to_string()
            } else {
                format!("{a}/")
            };
            let b_slash = if b.ends_with('/') {
                b.to_string()
            } else {
                format!("{b}/")
            };
            if b_slash.starts_with(&a_slash) || a_slash.starts_with(&b_slash) {
                results.push(AssertionResult::error(
                    "struct_mount_paths_no_overlap",
                    "services.mounts",
                    format!("mount paths '{}' and '{}' overlap", a, b),
                ));
            }
        }
    }
    results
}

pub fn struct_mount_paths_absolute(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for mount in &config.services.mounts {
        if !mount.where_.starts_with('/') {
            results.push(AssertionResult::error(
                "struct_mount_paths_absolute",
                "services.mounts",
                format!("mount path '{}' must be absolute", mount.where_),
            ));
        }
    }
    results
}

pub fn struct_env_file_on_mounted_path(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();

    let mut mount_paths: Vec<String> = config
        .verity_disks
        .iter()
        .map(|d| d.mountpoint.clone())
        .collect();
    mount_paths.extend(config.services.mounts.iter().map(|m| m.where_.clone()));
    // tmpfs paths always available
    mount_paths.extend(
        ["/tmp", "/var/log", "/var/lib/systemd"]
            .iter()
            .map(|s| s.to_string()),
    );

    for unit in &config.services.units {
        if let Some(ref env_file) = unit.environment_file {
            let on_mount = mount_paths
                .iter()
                .any(|mp| env_file.starts_with(mp.as_str()));
            if !on_mount {
                results.push(AssertionResult::error(
                    "struct_env_file_on_mounted_path",
                    &format!("services.units[{}].environment_file", unit.name),
                    format!(
                        "environment_file '{}' is not under any known mountpoint — it may not be accessible at runtime",
                        env_file
                    ),
                ));
            }
        }
    }

    results
}

pub fn struct_group_refs_exist(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    let mut known_groups: std::collections::HashSet<&str> = std::collections::HashSet::new();

    // System groups that always exist
    for g in &[
        "root",
        "daemon",
        "sys",
        "adm",
        "tty",
        "disk",
        "lp",
        "mail",
        "news",
        "uucp",
        "man",
        "proxy",
        "kmem",
        "dialout",
        "fax",
        "voice",
        "cdrom",
        "floppy",
        "tape",
        "sudo",
        "audio",
        "dip",
        "www-data",
        "backup",
        "operator",
        "list",
        "irc",
        "src",
        "gnats",
        "shadow",
        "utmp",
        "video",
        "sasl",
        "plugdev",
        "staff",
        "games",
        "users",
        "nogroup",
        "render",
        "input",
        "sgx",
        "messagebus",
        "systemd-journal",
        "systemd-network",
        "systemd-resolve",
        "systemd-timesync",
        "kvm",
    ] {
        known_groups.insert(g);
    }

    for g in &config.services.groups {
        known_groups.insert(&g.name);
    }

    for unit in &config.services.units {
        if let Some(ref group) = unit.group {
            if !known_groups.contains(group.as_str()) {
                results.push(AssertionResult::error(
                    "struct_group_refs_exist",
                    &format!("services.units[{}].group", unit.name),
                    format!(
                        "group '{}' is not a known system group or defined in services.groups",
                        group
                    ),
                ));
            }
        }
        for sg in &unit.supplementary_groups {
            if !known_groups.contains(sg.as_str()) {
                results.push(AssertionResult::error(
                    "struct_group_refs_exist",
                    &format!("services.units[{}].supplementary_groups", unit.name),
                    format!("supplementary group '{}' is not a known system group or defined in services.groups", sg),
                ));
            }
        }
    }

    results
}

pub fn struct_overlay_dst_absolute(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for file in &config.overlay.files {
        if !file.dst.starts_with('/') {
            results.push(AssertionResult::error(
                "struct_overlay_dst_absolute",
                "overlay.files",
                format!("overlay dst '{}' must be an absolute path", file.dst),
            ));
        }
    }
    results
}

pub fn struct_verity_disk_mountpoint_absolute(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for disk in &config.verity_disks {
        if !disk.mountpoint.starts_with('/') {
            results.push(AssertionResult::error(
                "struct_verity_disk_mountpoint_absolute",
                "verity_disks",
                format!("mountpoint '{}' must be an absolute path", disk.mountpoint),
            ));
        }
    }
    results
}

pub fn struct_verity_disk_mountpoints_unique(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for disk in &config.verity_disks {
        if !seen.insert(&disk.mountpoint) {
            results.push(AssertionResult::error(
                "struct_verity_disk_mountpoints_unique",
                "verity_disks",
                format!("duplicate mountpoint: '{}'", disk.mountpoint),
            ));
        }
    }
    results
}

pub fn struct_device_allow_format(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        for da in &unit.device_allow {
            let parts: Vec<&str> = da.splitn(2, ' ').collect();
            if parts.len() != 2 || !parts[0].starts_with('/') {
                results.push(AssertionResult::error(
                    "struct_device_allow_format",
                    &format!("services.units[{}].device_allow", unit.name),
                    format!(
                        "device_allow '{}' must be '<path> <perms>' (e.g., '/dev/sev-guest rw')",
                        da
                    ),
                ));
            }
        }
    }
    results
}

pub fn struct_read_write_paths_absolute(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        for path in &unit.read_write_paths {
            if !path.starts_with('/') {
                results.push(AssertionResult::error(
                    "struct_read_write_paths_absolute",
                    &format!("services.units[{}].read_write_paths", unit.name),
                    format!("read_write_paths entry '{}' must be an absolute path", path),
                ));
            }
        }
    }
    results
}

pub fn struct_image_id_valid(config: &Config) -> Vec<AssertionResult> {
    let id = &config.image.id;
    let valid = !id.is_empty()
        && id.starts_with(|c: char| c.is_ascii_lowercase())
        && id
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.');
    if valid {
        vec![]
    } else {
        vec![AssertionResult::error(
            "struct_image_id_valid",
            "image.id",
            format!("image id '{}' must match [a-z][a-z0-9.-]*", id),
        )]
    }
}

pub fn struct_image_version_semver(config: &Config) -> Vec<AssertionResult> {
    let v = &config.image.version;
    let parts: Vec<&str> = v.split('.').collect();
    let valid = parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok());
    if valid {
        vec![]
    } else {
        vec![AssertionResult::error(
            "struct_image_version_semver",
            "image.version",
            format!("image version '{}' must be valid semver (X.Y.Z)", v),
        )]
    }
}

pub fn struct_env_var_format(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        for env in &unit.environment {
            if !env.contains('=') {
                results.push(AssertionResult::error(
                    "struct_env_var_format",
                    &format!("services.units[{}].environment", unit.name),
                    format!("environment entry '{}' must be KEY=VALUE format", env),
                ));
            } else {
                let key = env.split('=').next().unwrap();
                if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                    results.push(AssertionResult::error(
                        "struct_env_var_format",
                        &format!("services.units[{}].environment", unit.name),
                        format!("environment key '{}' must be alphanumeric/underscore", key),
                    ));
                }
            }
        }
        for env in &unit.unset_environment {
            if env.is_empty() || !env.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                results.push(AssertionResult::error(
                    "struct_env_var_format",
                    &format!("services.units[{}].unset_environment", unit.name),
                    format!(
                        "unset_environment entry '{}' must be a valid variable name",
                        env
                    ),
                ));
            }
        }
    }
    results
}

pub fn struct_verity_disk_source_not_empty(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for disk in &config.verity_disks {
        if let Some(ref source) = disk.source {
            if source.trim().is_empty() {
                results.push(AssertionResult::error(
                    "struct_verity_disk_source_not_empty",
                    &format!("verity_disks[{}].source", disk.name),
                    format!("verity disk '{}' has empty source path", disk.name),
                ));
            }
        }
    }
    results
}

pub fn struct_ovmf_path_exists(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    if let Some(ref p) = config.manifest.snp.ovmf_file {
        if !std::path::Path::new(p).exists() {
            results.push(AssertionResult::error(
                "struct_ovmf_path_exists",
                "manifest.snp.ovmf_file",
                format!("OVMF file '{}' does not exist — set --ovmf-dir or check paths.ovmf in teehost config", p),
            ));
        }
    }
    if let Some(ref p) = config.manifest.tdx.ovmf_file {
        if !std::path::Path::new(p).exists() {
            results.push(AssertionResult::error(
                "struct_ovmf_path_exists",
                "manifest.tdx.ovmf_file",
                format!("OVMF file '{}' does not exist — set --ovmf-dir or check paths.ovmf in teehost config", p),
            ));
        }
    }
    results
}

pub fn struct_cmdline_not_empty(config: &Config) -> Vec<AssertionResult> {
    if config.kernel.cmdline.trim().is_empty() {
        vec![AssertionResult::error(
            "struct_cmdline_not_empty",
            "kernel.cmdline",
            "kernel cmdline must not be empty",
        )]
    } else {
        vec![]
    }
}
