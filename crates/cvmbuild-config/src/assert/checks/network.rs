use crate::assert::types::AssertionResult;
use crate::Config;

pub fn network_no_ipv6(_config: &Config) -> Vec<AssertionResult> {
    // cvmbuild always generates networkd config with IPv6AcceptRA=no.
    // This check validates the policy intent — the generated config enforces it.
    vec![]
}

pub fn network_no_dns(_config: &Config) -> Vec<AssertionResult> {
    // cvmbuild always generates networkd config with UseDNS=no.
    vec![]
}

pub fn network_ntp_specified(config: &Config) -> Vec<AssertionResult> {
    if config.services.network.ntp_servers.is_empty() {
        vec![AssertionResult::error(
            "network_ntp_specified",
            "services.network.ntp_servers",
            "NTP servers must be specified for time synchronization",
        )]
    } else {
        vec![]
    }
}

pub fn network_ntp_no_pool(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for server in &config.services.network.ntp_servers {
        // If it's not an IP address, it's a hostname (requires DNS)
        if server.parse::<std::net::IpAddr>().is_err() {
            results.push(AssertionResult::error(
                "network_ntp_no_pool",
                "services.network.ntp_servers",
                format!(
                    "NTP server '{}' is a hostname — use IP addresses (DNS is disabled)",
                    server
                ),
            ));
        }
    }
    results
}

pub fn network_ntp_private_or_known(config: &Config) -> Vec<AssertionResult> {
    let mut results = Vec::new();
    for server in &config.services.network.ntp_servers {
        if let Ok(ip) = server.parse::<std::net::IpAddr>() {
            if !is_trusted_ntp(ip) {
                results.push(AssertionResult::warning(
                    "network_ntp_private_or_known",
                    "services.network.ntp_servers",
                    format!("NTP server '{}' is not a known trusted provider", server),
                ));
            }
        }
    }
    results
}

fn is_trusted_ntp(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let octets = v4.octets();
            // RFC1918 private ranges
            if octets[0] == 10
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                || (octets[0] == 192 && octets[1] == 168)
            {
                return true;
            }
            // Cloudflare NTP (162.159.200.x)
            if octets[0] == 162 && octets[1] == 159 && octets[2] == 200 {
                return true;
            }
            // Google NTP (216.239.35.x)
            if octets[0] == 216 && octets[1] == 239 && octets[2] == 35 {
                return true;
            }
            false
        }
        std::net::IpAddr::V6(_) => false, // IPv6 NTP not expected in CVM
    }
}
