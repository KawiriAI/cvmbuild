use crate::assert::types::AssertionResult;
use crate::Config;

fn check_all_in_remove(
    config: &Config,
    check_name: &str,
    binaries: &[&str],
    reason: &str,
) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for bin in binaries {
        if !config.security.remove.iter().any(|r| r == bin) {
            results.push(AssertionResult::error(
                check_name,
                "security.remove",
                format!("'{}' must be in the removal list — {}", bin, reason),
            ));
        }
    }
    results
}

pub fn no_shells(config: &Config) -> Vec<AssertionResult> {
    check_all_in_remove(
        config,
        "no_shells",
        &["bash", "sh", "dash"],
        "shells leak attack surface",
    )
}

pub fn no_shells_extended(config: &Config) -> Vec<AssertionResult> {
    check_all_in_remove(
        config,
        "no_shells_extended",
        &["csh", "tcsh", "zsh", "fish", "ksh", "rbash", "busybox"],
        "all shell variants must be removed",
    )
}

pub fn no_package_managers(config: &Config) -> Vec<AssertionResult> {
    check_all_in_remove(
        config,
        "no_package_managers",
        &["apt", "dpkg", "pip"],
        "package managers enable runtime modification",
    )
}

pub fn no_package_managers_extended(config: &Config) -> Vec<AssertionResult> {
    check_all_in_remove(
        config,
        "no_package_managers_extended",
        &[
            "apt-get",
            "apt-cache",
            "apt-config",
            "apt-key",
            "apt-mark",
            "dpkg-deb",
            "dpkg-query",
            "pip3",
        ],
        "all package manager variants must be removed",
    )
}

pub fn no_dmsetup(config: &Config) -> Vec<AssertionResult> {
    check_all_in_remove(
        config,
        "no_dmsetup",
        &["dmsetup"],
        "dmsetup can replace dm-verity targets with dm-linear (RT-18)",
    )
}

pub fn remove_package_dirs(config: &Config) -> Vec<AssertionResult> {
    let required = ["/usr/lib/apt", "/var/lib/apt", "/var/lib/dpkg"];
    let mut results = Vec::new();
    for dir in required {
        if !config.security.remove_dirs.iter().any(|d| d == dir) {
            results.push(AssertionResult::error(
                "remove_package_dirs",
                "security.remove_dirs",
                format!(
                    "'{}' should be in remove_dirs to prevent package manager resurrection",
                    dir
                ),
            ));
        }
    }
    results
}
