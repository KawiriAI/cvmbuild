use crate::assert::types::AssertionResult;
use crate::Config;

// --- Catalog checks ---

pub fn service_hardening_no_none(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        if unit.hardening == "none" {
            results.push(AssertionResult::error(
                "service_hardening_no_none",
                &format!("services.units[{}]", unit.name),
                format!(
                    "service '{}' has hardening=none — must be 'full' or 'minimal'",
                    unit.name
                ),
            ));
        }
    }
    results
}

pub fn service_hardening_full_or_minimal(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        if unit.hardening != "full" && unit.hardening != "minimal" {
            results.push(AssertionResult::error(
                "service_hardening_full_or_minimal",
                &format!("services.units[{}]", unit.name),
                format!(
                    "service '{}' has hardening='{}' — must be 'full' or 'minimal'",
                    unit.name, unit.hardening
                ),
            ));
        }
    }
    results
}

pub fn service_no_new_privileges(config: &Config) -> Vec<AssertionResult> {
    // Services with hardening=full get NoNewPrivileges automatically.
    // This check is informational — verifies policy intent.
    let mut results = Vec::new();
    for unit in &config.services.units {
        if unit.hardening != "full" && unit.hardening != "minimal" {
            results.push(AssertionResult::warning(
                "service_no_new_privileges",
                &format!("services.units[{}]", unit.name),
                format!(
                    "service '{}' does not use 'full' hardening — NoNewPrivileges may not be set",
                    unit.name
                ),
            ));
        }
    }
    results
}

pub fn service_private_tmp(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        if unit.hardening != "full" && unit.hardening != "minimal" {
            results.push(AssertionResult::warning(
                "service_private_tmp",
                &format!("services.units[{}]", unit.name),
                format!(
                    "service '{}' does not use 'full' hardening — PrivateTmp may not be set",
                    unit.name
                ),
            ));
        }
    }
    results
}

pub fn service_unset_dangerous_env(config: &Config) -> Vec<AssertionResult> {
    let dangerous = ["LD_PRELOAD", "LD_LIBRARY_PATH"];
    let mut results = Vec::new();
    for unit in &config.services.units {
        for var in dangerous {
            if !unit.unset_environment.iter().any(|v| v == var) {
                results.push(AssertionResult::warning(
                    "service_unset_dangerous_env",
                    &format!("services.units[{}]", unit.name),
                    format!(
                        "service '{}' should unset {} to prevent library injection",
                        unit.name, var
                    ),
                ));
            }
        }
    }
    results
}

fn check_no_extra_option(
    config: &Config,
    check_name: &str,
    forbidden: &str,
) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        if unit.extra_options.iter().any(|o| o.contains(forbidden)) {
            results.push(AssertionResult::error(
                check_name,
                &format!("services.units[{}].extra_options", unit.name),
                format!(
                    "service '{}' must not set '{}' — weakens hardening",
                    unit.name, forbidden
                ),
            ));
        }
    }
    results
}

pub fn service_no_privilege_escalation_override(config: &Config) -> Vec<AssertionResult> {
    check_no_extra_option(
        config,
        "service_no_privilege_escalation_override",
        "NoNewPrivileges=no",
    )
}

pub fn service_no_protect_system_off(config: &Config) -> Vec<AssertionResult> {
    check_no_extra_option(config, "service_no_protect_system_off", "ProtectSystem=no")
}

pub fn service_no_protect_home_off(config: &Config) -> Vec<AssertionResult> {
    check_no_extra_option(config, "service_no_protect_home_off", "ProtectHome=no")
}

pub fn service_no_private_tmp_off(config: &Config) -> Vec<AssertionResult> {
    check_no_extra_option(config, "service_no_private_tmp_off", "PrivateTmp=no")
}

pub fn service_no_restrict_suidsgid_off(config: &Config) -> Vec<AssertionResult> {
    check_no_extra_option(
        config,
        "service_no_restrict_suidsgid_off",
        "RestrictSUIDSGID=no",
    )
}

pub fn service_no_memory_deny_off(config: &Config) -> Vec<AssertionResult> {
    check_no_extra_option(
        config,
        "service_no_memory_deny_off",
        "MemoryDenyWriteExecute=no",
    )
}

pub fn service_no_protect_kernel_tunables_off(config: &Config) -> Vec<AssertionResult> {
    check_no_extra_option(
        config,
        "service_no_protect_kernel_tunables_off",
        "ProtectKernelTunables=no",
    )
}

pub fn service_dynamic_user_preferred(config: &Config) -> Vec<AssertionResult> {
    if config.services.units.is_empty() {
        return vec![];
    }
    let any_non_root = config
        .services
        .units
        .iter()
        .any(|u| u.dynamic_user == Some(true) || u.user.is_some());
    if any_non_root {
        vec![]
    } else {
        vec![AssertionResult::warning(
            "service_dynamic_user_preferred",
            "services.units",
            "no service uses DynamicUser=yes or User= — consider it for least-privilege",
        )]
    }
}

// --- Structural checks (always-on) ---

pub fn service_exec_absolute_path(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for unit in &config.services.units {
        if !unit.exec.starts_with('/') {
            results.push(AssertionResult::error(
                "service_exec_absolute_path",
                &format!("services.units[{}].exec", unit.name),
                format!(
                    "service '{}' exec must be an absolute path: '{}'",
                    unit.name, unit.exec
                ),
            ));
        }
    }
    results
}

pub fn service_type_valid(config: &Config) -> Vec<AssertionResult> {
    let valid = ["simple", "oneshot", "forking", "notify", "exec"];
    let mut results = Vec::new();
    for unit in &config.services.units {
        if !valid.contains(&unit.service_type.as_str()) {
            results.push(AssertionResult::error(
                "service_type_valid",
                &format!("services.units[{}].service_type", unit.name),
                format!(
                    "service '{}' has invalid type '{}' — must be one of: {}",
                    unit.name,
                    unit.service_type,
                    valid.join(", ")
                ),
            ));
        }
    }
    results
}
