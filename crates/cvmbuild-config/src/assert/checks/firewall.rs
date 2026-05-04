use crate::assert::types::AssertionResult;
use crate::Config;

// --- Catalog checks ---

/// Zero-trust default: outbound must be "deny". Image authors who
/// genuinely need open egress (e.g. dev-friendly SSH-CVMs that
/// `apt update` and pull from registries) opt out by adding
/// `firewall_outbound_deny` to `[assert].exclude` and setting
/// `outbound = "allow"`. Inference images stay locked.
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
        if let Some(port) = rule.port {
            if ports.contains(&port) {
                results.push(AssertionResult::error(
                    check_name,
                    "firewall.inbound",
                    format!("port {port} must not be allowed — {reason}"),
                ));
            }
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

/// Allowed inbound protocols. tcp/udp are port-based; icmp/icmpv6 are
/// ports-irrelevant (the protocols carry types/codes, not ports).
const PORT_PROTOS: &[&str] = &["tcp", "udp"];
const PORTLESS_PROTOS: &[&str] = &["icmp", "icmpv6"];

pub fn firewall_proto_valid(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for rule in &config.firewall.inbound {
        let valid = PORT_PROTOS.contains(&rule.proto.as_str())
            || PORTLESS_PROTOS.contains(&rule.proto.as_str());
        if !valid {
            results.push(AssertionResult::error(
                "firewall_proto_valid",
                "firewall.inbound",
                format!(
                    "protocol '{}' must be one of: tcp, udp, icmp, icmpv6",
                    rule.proto
                ),
            ));
        }
    }
    results
}

/// Tcp/udp rules must carry a non-zero port; icmp/icmpv6 rules must
/// not carry a port. Mismatched combinations almost always mean the
/// author confused themselves, so we error rather than silently
/// dropping or accepting.
pub fn firewall_port_consistency(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for rule in &config.firewall.inbound {
        if PORT_PROTOS.contains(&rule.proto.as_str()) {
            match rule.port {
                None => results.push(AssertionResult::error(
                    "firewall_port_consistency",
                    "firewall.inbound",
                    format!("{} rule needs a port", rule.proto),
                )),
                Some(0) => results.push(AssertionResult::error(
                    "firewall_port_consistency",
                    "firewall.inbound",
                    format!("{} port must be > 0", rule.proto),
                )),
                Some(_) => {}
            }
        } else if PORTLESS_PROTOS.contains(&rule.proto.as_str()) && rule.port.is_some() {
            results.push(AssertionResult::error(
                "firewall_port_consistency",
                "firewall.inbound",
                format!(
                    "{} rule must not have a port (icmp has no port number)",
                    rule.proto
                ),
            ));
        }
    }
    results
}

/// Outbound value must be "deny" or "allow". Anything else (typo,
/// unsupported syntax) is rejected at validate time so we don't fall
/// back to silent deny in the rule generator.
pub fn firewall_outbound_value_valid(config: &Config) -> Vec<AssertionResult> {
    let v = config.firewall.outbound.as_str();
    if v == "deny" || v == "allow" {
        vec![]
    } else {
        vec![AssertionResult::error(
            "firewall_outbound_value_valid",
            "firewall.outbound",
            format!("must be 'deny' or 'allow', got '{v}'"),
        )]
    }
}
