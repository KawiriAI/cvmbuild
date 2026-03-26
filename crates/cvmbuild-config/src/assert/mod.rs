pub mod catalog;
pub mod checks;
pub mod profiles;
pub mod types;

pub use types::{AssertionResult, Category, CheckInfo, Severity};

use crate::Config;

use serde::Deserialize;

/// Assertion configuration from [assert] section of cvm.toml.
#[derive(Debug, Default, Deserialize)]
pub struct AssertConfig {
    /// Named profile: "production", "standard", "development", "minimal"
    #[serde(default)]
    pub profile: Option<String>,

    /// Explicit list of check names (mutually exclusive with profile).
    #[serde(default)]
    pub checks: Vec<String>,

    /// Additional checks to enable on top of a profile.
    #[serde(default)]
    pub include: Vec<String>,

    /// Checks to disable from a profile.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Resolve the final set of active catalog check names.
pub fn resolve_checks(assert_cfg: &AssertConfig) -> Result<Vec<&'static str>, Vec<String>> {
    let mut errors = Vec::new();

    // Validate mutual exclusivity
    if assert_cfg.profile.is_some() && !assert_cfg.checks.is_empty() {
        errors.push("cannot set both 'profile' and 'checks' in [assert]".into());
    }
    if assert_cfg.profile.is_none()
        && (!assert_cfg.include.is_empty() || !assert_cfg.exclude.is_empty())
        && assert_cfg.checks.is_empty()
    {
        errors.push("'include'/'exclude' require 'profile' to be set".into());
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let catalog_names: std::collections::HashSet<&str> =
        catalog::CATALOG_CHECKS.iter().map(|c| c.name).collect();

    if !assert_cfg.checks.is_empty() {
        // Explicit check list mode
        let mut active = Vec::new();
        for name in &assert_cfg.checks {
            if let Some(found) = catalog::CATALOG_CHECKS.iter().find(|c| c.name == name) {
                active.push(found.name);
            } else {
                errors.push(format!("unknown check: '{name}'"));
            }
        }
        if !errors.is_empty() {
            return Err(errors);
        }
        return Ok(active);
    }

    // Profile mode (default to "production")
    let profile_name = assert_cfg.profile.as_deref().unwrap_or("production");
    let base = match profiles::profile_checks(profile_name) {
        Some(p) => p,
        None => {
            errors.push(format!("unknown profile: '{profile_name}'"));
            return Err(errors);
        }
    };

    let mut active: std::collections::HashSet<&str> = base.iter().copied().collect();

    for name in &assert_cfg.include {
        if catalog_names.contains(name.as_str()) {
            active.insert(
                catalog::CATALOG_CHECKS
                    .iter()
                    .find(|c| c.name == name)
                    .unwrap()
                    .name,
            );
        } else {
            errors.push(format!("unknown check in include: '{name}'"));
        }
    }
    for name in &assert_cfg.exclude {
        if !catalog_names.contains(name.as_str()) {
            errors.push(format!("unknown check in exclude: '{name}'"));
        }
        active.remove(name.as_str());
    }

    if !errors.is_empty() {
        return Err(errors);
    }
    let mut result: Vec<&str> = active.into_iter().collect();
    result.sort_unstable();
    Ok(result)
}

/// Run all applicable checks against a config.
/// Always runs structural checks. Runs catalog checks per the [assert] config.
pub fn validate(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();

    // 1. Always-on structural checks
    for check in catalog::STRUCTURAL_CHECKS {
        results.extend((check.check)(config));
    }

    // 2. Catalog checks based on [assert] config
    let active = match resolve_checks(&config.assert) {
        Ok(checks) => checks,
        Err(errors) => {
            for err in errors {
                results.push(AssertionResult::error("assert_config", "assert", err));
            }
            return results;
        }
    };

    let active_set: std::collections::HashSet<&str> = active.into_iter().collect();

    for check in catalog::CATALOG_CHECKS {
        if active_set.contains(check.name) {
            results.extend((check.check)(config));
        }
    }

    results
}

/// Count of structural checks (always on).
pub fn structural_count() -> usize {
    catalog::STRUCTURAL_CHECKS.len()
}

/// Count of active catalog checks for a given config.
pub fn catalog_count(config: &Config) -> usize {
    resolve_checks(&config.assert).map(|c| c.len()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> AssertConfig {
        AssertConfig::default()
    }

    // --- resolve_checks tests ---

    #[test]
    fn default_config_uses_production_profile() {
        let checks = resolve_checks(&default_cfg()).unwrap();
        assert_eq!(checks.len(), profiles::PRODUCTION.len());
    }

    #[test]
    fn explicit_profile_standard() {
        let cfg = AssertConfig {
            profile: Some("standard".into()),
            ..Default::default()
        };
        let checks = resolve_checks(&cfg).unwrap();
        assert_eq!(checks.len(), profiles::STANDARD.len());
    }

    #[test]
    fn explicit_profile_development() {
        let cfg = AssertConfig {
            profile: Some("development".into()),
            ..Default::default()
        };
        let checks = resolve_checks(&cfg).unwrap();
        assert_eq!(checks.len(), profiles::DEVELOPMENT.len());
    }

    #[test]
    fn explicit_profile_minimal() {
        let cfg = AssertConfig {
            profile: Some("minimal".into()),
            ..Default::default()
        };
        let checks = resolve_checks(&cfg).unwrap();
        assert_eq!(checks.len(), profiles::MINIMAL.len());
    }

    #[test]
    fn unknown_profile_errors() {
        let cfg = AssertConfig {
            profile: Some("nonexistent".into()),
            ..Default::default()
        };
        let err = resolve_checks(&cfg).unwrap_err();
        assert!(err[0].contains("unknown profile"));
    }

    #[test]
    fn explicit_checks_list() {
        let cfg = AssertConfig {
            checks: vec!["verity_enabled".into(), "modules_locked".into()],
            ..Default::default()
        };
        let checks = resolve_checks(&cfg).unwrap();
        assert_eq!(checks.len(), 2);
        assert!(checks.contains(&"verity_enabled"));
        assert!(checks.contains(&"modules_locked"));
    }

    #[test]
    fn unknown_check_name_errors() {
        let cfg = AssertConfig {
            checks: vec!["verity_enabled".into(), "totally_fake".into()],
            ..Default::default()
        };
        let err = resolve_checks(&cfg).unwrap_err();
        assert!(err[0].contains("totally_fake"));
    }

    #[test]
    fn profile_and_checks_mutual_exclusion() {
        let cfg = AssertConfig {
            profile: Some("production".into()),
            checks: vec!["verity_enabled".into()],
            ..Default::default()
        };
        let err = resolve_checks(&cfg).unwrap_err();
        assert!(err[0].contains("cannot set both"));
    }

    #[test]
    fn include_without_profile_errors() {
        let cfg = AssertConfig {
            include: vec!["verity_enabled".into()],
            ..Default::default()
        };
        let err = resolve_checks(&cfg).unwrap_err();
        assert!(err[0].contains("require 'profile'"));
    }

    #[test]
    fn profile_with_include() {
        let cfg = AssertConfig {
            profile: Some("minimal".into()),
            include: vec!["firewall_no_ssh".into()],
            ..Default::default()
        };
        let checks = resolve_checks(&cfg).unwrap();
        assert_eq!(checks.len(), profiles::MINIMAL.len() + 1);
        assert!(checks.contains(&"firewall_no_ssh"));
    }

    #[test]
    fn profile_with_exclude() {
        let cfg = AssertConfig {
            profile: Some("minimal".into()),
            exclude: vec!["verity_enabled".into()],
            ..Default::default()
        };
        let checks = resolve_checks(&cfg).unwrap();
        assert_eq!(checks.len(), profiles::MINIMAL.len() - 1);
        assert!(!checks.contains(&"verity_enabled"));
    }

    #[test]
    fn include_unknown_check_errors() {
        let cfg = AssertConfig {
            profile: Some("minimal".into()),
            include: vec!["fake_check".into()],
            ..Default::default()
        };
        let err = resolve_checks(&cfg).unwrap_err();
        assert!(err[0].contains("fake_check"));
    }

    #[test]
    fn exclude_unknown_check_errors() {
        let cfg = AssertConfig {
            profile: Some("minimal".into()),
            exclude: vec!["fake_check".into()],
            ..Default::default()
        };
        let err = resolve_checks(&cfg).unwrap_err();
        assert!(err[0].contains("fake_check"));
    }

    // --- Profile sanity checks ---

    #[test]
    fn all_profile_checks_exist_in_catalog() {
        let catalog_names: std::collections::HashSet<&str> =
            catalog::CATALOG_CHECKS.iter().map(|c| c.name).collect();

        for profile_name in profiles::profile_names() {
            let checks = profiles::profile_checks(profile_name).unwrap();
            for check in checks {
                assert!(
                    catalog_names.contains(check),
                    "profile '{profile_name}' references unknown check '{check}'"
                );
            }
        }
    }

    #[test]
    fn production_is_superset_of_standard() {
        let prod: std::collections::HashSet<&&str> = profiles::PRODUCTION.iter().collect();
        for check in profiles::STANDARD {
            assert!(
                prod.contains(check),
                "standard check '{check}' missing from production"
            );
        }
    }

    #[test]
    fn standard_is_superset_of_development() {
        let std: std::collections::HashSet<&&str> = profiles::STANDARD.iter().collect();
        for check in profiles::DEVELOPMENT {
            assert!(
                std.contains(check),
                "development check '{check}' missing from standard"
            );
        }
    }

    #[test]
    fn development_is_superset_of_minimal() {
        let dev: std::collections::HashSet<&&str> = profiles::DEVELOPMENT.iter().collect();
        for check in profiles::MINIMAL {
            assert!(
                dev.contains(check),
                "minimal check '{check}' missing from development"
            );
        }
    }

    #[test]
    fn profile_sizes_decrease() {
        assert!(profiles::PRODUCTION.len() > profiles::STANDARD.len());
        assert!(profiles::STANDARD.len() > profiles::DEVELOPMENT.len());
        assert!(profiles::DEVELOPMENT.len() > profiles::MINIMAL.len());
    }

    // --- Catalog integrity ---

    #[test]
    fn no_duplicate_check_names() {
        let mut seen = std::collections::HashSet::new();
        for check in catalog::STRUCTURAL_CHECKS {
            assert!(
                seen.insert(check.name),
                "duplicate structural check: {}",
                check.name
            );
        }
        for check in catalog::CATALOG_CHECKS {
            assert!(
                seen.insert(check.name),
                "duplicate catalog check: {}",
                check.name
            );
        }
    }

    #[test]
    fn structural_count_matches() {
        assert_eq!(structural_count(), catalog::STRUCTURAL_CHECKS.len());
    }

    #[test]
    fn catalog_count_matches_profile() {
        let config = Config::parse(MINIMAL_TOML).unwrap();
        assert_eq!(catalog_count(&config), profiles::MINIMAL.len());
    }

    // --- Integration: validate() with different profiles ---

    const MINIMAL_TOML: &str = r#"
[image]
id = "test-cvm"
version = "0.1.0"

[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality iommu=pt systemd.verity_root_options=panic-on-corruption"
initrd_modules = ["dm-verity", "dm-mod"]

[verity]
enabled = true
panic_on_corruption = true

[security]
remove = ["bash", "sh", "dash", "dmsetup"]
lock_modules = true

[firewall]
outbound = "deny"

[assert]
profile = "minimal"
"#;

    #[test]
    fn minimal_profile_config_passes() {
        let config = Config::parse(MINIMAL_TOML).unwrap();
        let errors: Vec<_> = config
            .validate_full()
            .into_iter()
            .filter(|r| r.severity == Severity::Error)
            .collect();
        assert!(errors.is_empty(), "Expected no errors, got: {:?}", errors);
    }

    #[test]
    fn validate_always_runs_structural_checks() {
        // Use explicit empty checks list (no catalog checks)
        let toml = r#"
[image]
id = "test-cvm"
version = "0.1.0"

[kernel]
cmdline = "root=/dev/mapper/root"

[verity]
enabled = true

[security]
remove = []

[firewall]
inbound = [{ port = 443, proto = "invalid_proto" }]
outbound = "deny"

[assert]
checks = []
"#;
        let config = Config::parse(toml).unwrap();
        let results = config.validate_full();
        // Should have structural error for invalid proto
        assert!(
            results
                .iter()
                .any(|r| r.check_name == "firewall_proto_valid"),
            "structural check should run even with empty catalog checks"
        );
    }

    #[test]
    fn validate_skips_disabled_catalog_checks() {
        // Use development profile (no no_shells check)
        let toml = r#"
[image]
id = "test-cvm"
version = "0.1.0"

[kernel]
cmdline = "root=/dev/mapper/root lockdown=confidentiality iommu=pt"
initrd_modules = ["dm-verity", "dm-mod"]

[verity]
enabled = true
panic_on_corruption = true

[security]
remove = ["dmsetup"]
lock_modules = true

[firewall]
outbound = "deny"

[assert]
profile = "development"
"#;
        let config = Config::parse(toml).unwrap();
        let results = config.validate_full();
        // no_shells is not in development profile, so shouldn't appear
        assert!(
            !results.iter().any(|r| r.check_name == "no_shells"),
            "no_shells should not run under development profile"
        );
    }
}
