use crate::assert::types::AssertionResult;
use crate::Config;

pub fn modules_locked(config: &Config) -> Vec<AssertionResult> {
    if config.security.lock_modules {
        vec![]
    } else {
        vec![AssertionResult::error(
            "modules_locked",
            "security.lock_modules",
            "kernel modules must be locked after init",
        )]
    }
}

pub fn modules_lock_before_services(config: &Config) -> Vec<AssertionResult> {
    if !config.security.lock_modules {
        return vec![];
    }
    let mut results = Vec::new();
    for unit in &config.services.units {
        if !unit.after.iter().any(|a| a == "lock-modules.service") {
            results.push(AssertionResult::warning(
                "modules_lock_before_services",
                &format!("services.units[{}]", unit.name),
                format!(
                    "service '{}' should have 'lock-modules.service' in after to ensure modules are locked before it starts",
                    unit.name
                ),
            ));
        }
    }
    results
}
