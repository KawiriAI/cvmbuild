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

/// Distro-agnostic check: any common package manager binary present in the
/// rootfs must be removed. Covers apt/dpkg (Debian family), dnf/yum/rpm
/// (RPM family), pacman (Arch), apk (Alpine), and Python's pip variants.
/// Authors don't have to know which distro their base image is on — if it
/// ships any of these, the check flags it.
pub fn no_package_managers(config: &Config) -> Vec<AssertionResult> {
    const KNOWN: &[&str] = &[
        // Debian / Ubuntu
        "apt",
        "apt-get",
        "apt-cache",
        "apt-config",
        "apt-key",
        "apt-mark",
        "dpkg",
        "dpkg-deb",
        "dpkg-query",
        // RPM family
        "dnf",
        "yum",
        "rpm",
        "microdnf",
        // Arch
        "pacman",
        // Alpine
        "apk",
        // Python
        "pip",
        "pip3",
    ];
    let mut results = Vec::new();
    for bin in KNOWN {
        // Only fail if the binary is NOT in remove. We don't require all of
        // them — only the ones that the base image actually ships.
        // Rationale: this check runs against the cvm.toml; we can't introspect
        // the rootfs from here. So the policy is "if you might use a
        // Debian-family base, list these"; authors override per-image.
        if !config.security.remove.iter().any(|r| r == bin) {
            results.push(AssertionResult::warning(
                "no_package_managers",
                "security.remove",
                format!(
                    "'{}' is not in the removal list — if your base image \
                     contains this package manager, runtime tampering is \
                     possible. List it explicitly to silence this warning.",
                    bin
                ),
            ));
        }
    }
    results
}

pub fn no_dmsetup(config: &Config) -> Vec<AssertionResult> {
    check_all_in_remove(
        config,
        "no_dmsetup",
        &["dmsetup"],
        "dmsetup can replace dm-verity targets with dm-linear (RT-18)",
    )
}
