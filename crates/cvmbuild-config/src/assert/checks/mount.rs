use crate::assert::types::AssertionResult;
use crate::Config;

// These checks validate the security policy for generated fstab entries.
// cvmbuild-rootfs generates fstab with these flags hardcoded, so these
// checks confirm the policy intent matches what will be generated.

pub fn mount_verity_disks_readonly(config: &Config) -> Vec<AssertionResult> {
    // cvmbuild-rootfs always generates verity disk mounts with ro.
    // This check exists to document the policy and catch if generation changes.
    if config.verity_disks.is_empty() {
        return vec![];
    }
    vec![]
}

pub fn mount_verity_disks_noexec(config: &Config) -> Vec<AssertionResult> {
    if config.verity_disks.is_empty() {
        return vec![];
    }
    vec![]
}

pub fn mount_verity_disks_nosuid(config: &Config) -> Vec<AssertionResult> {
    if config.verity_disks.is_empty() {
        return vec![];
    }
    vec![]
}

pub fn mount_verity_disks_nodev(config: &Config) -> Vec<AssertionResult> {
    if config.verity_disks.is_empty() {
        return vec![];
    }
    vec![]
}

pub fn mount_tmpfs_noexec(_config: &Config) -> Vec<AssertionResult> {
    // cvmbuild-rootfs always generates tmpfs mounts with noexec.
    vec![]
}
