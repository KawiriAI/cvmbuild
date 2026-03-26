use crate::assert::types::AssertionResult;
use crate::Config;

// --- Catalog checks ---

pub fn firewall_outbound_deny(config: &Config) -> Vec<AssertionResult> {
    if config.firewall.outbound == "deny" {
        vec![]
    } else {
        vec![AssertionResult::error(
            "firewall_outbound_deny",
            "firewall.outbound",
            "zero-trust: outbound must be 'deny' by default",
        )]
    }
}

fn check_no_port(
    config: &Config,
    check_name: &str,
    ports: &[u16],
    reason: &str,
) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for rule in &config.firewall.inbound {
        if ports.contains(&rule.port) {
            results.push(AssertionResult::error(
                check_name,
                "firewall.inbound",
                format!("port {} must not be allowed — {}", rule.port, reason),
            ));
        }
    }
    results
}

pub fn firewall_no_ssh(config: &Config) -> Vec<AssertionResult> {
    check_no_port(
        config,
        "firewall_no_ssh",
        &[22],
        "SSH is prohibited in CVM images",
    )
}

pub fn firewall_no_http(config: &Config) -> Vec<AssertionResult> {
    check_no_port(
        config,
        "firewall_no_http",
        &[80],
        "plain HTTP is prohibited — use HTTPS only",
    )
}

pub fn firewall_no_telnet(config: &Config) -> Vec<AssertionResult> {
    check_no_port(
        config,
        "firewall_no_telnet",
        &[23],
        "telnet is unencrypted and prohibited",
    )
}

pub fn firewall_no_ftp(config: &Config) -> Vec<AssertionResult> {
    check_no_port(
        config,
        "firewall_no_ftp",
        &[20, 21],
        "FTP is unencrypted and prohibited",
    )
}

// --- Structural checks (always-on) ---

pub fn firewall_proto_valid(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for rule in &config.firewall.inbound {
        if rule.proto != "tcp" && rule.proto != "udp" {
            results.push(AssertionResult::error(
                "firewall_proto_valid",
                "firewall.inbound",
                format!("protocol '{}' must be 'tcp' or 'udp'", rule.proto),
            ));
        }
    }
    results
}

pub fn firewall_port_nonzero(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for rule in &config.firewall.inbound {
        if rule.port == 0 {
            results.push(AssertionResult::error(
                "firewall_port_nonzero",
                "firewall.inbound",
                "port must be > 0",
            ));
        }
    }
    results
}
