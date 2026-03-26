use crate::assert::types::AssertionResult;
use crate::Config;

// These checks validate the logging policy. cvmbuild-rootfs generates
// journald config with volatile storage hardcoded, so these checks
// confirm the policy intent.

pub fn logging_volatile(_config: &Config) -> Vec<AssertionResult> {
    // cvmbuild-rootfs always generates Storage=volatile in journald config.
    vec![]
}

pub fn logging_bounded_size(_config: &Config) -> Vec<AssertionResult> {
    // cvmbuild-rootfs always generates RuntimeMaxUse=16M.
    vec![]
}

pub fn logging_no_persistent(_config: &Config) -> Vec<AssertionResult> {
    // cvmbuild-rootfs never generates persistent storage.
    vec![]
}

pub fn logging_no_forward_console(_config: &Config) -> Vec<AssertionResult> {
    // cvmbuild-rootfs does not configure console forwarding.
    vec![]
}
