//! SSDP device discovery (UDP 1900).
//!
//! Ports the unicast `M-SEARCH` built in `ProbeSsdpAsync` and the
//! `ParseSsdpFriendlyName` SERVER-header parser. The skipped noise tokens
//! (`UPnP`, `Linux`, `Windows`, `DLNADOC`, `HTTP`) were confirmed via REA.

use std::net::Ipv4Addr;

/// UDP port for SSDP.
pub const SSDP_PORT: u16 = 1900;

/// Server-header tokens that are generic OS/protocol noise, not a device name.
const NOISE_PREFIXES: [&str; 5] = ["UPnP", "Linux", "Windows", "DLNADOC", "HTTP"];

/// Builds a unicast SSDP `M-SEARCH` request addressed to `ip`.
///
/// Exact port of the request string in `ProbeSsdpAsync`.
pub fn build_msearch(ip: Ipv4Addr) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {ip}:1900\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 1\r\n\
         ST: ssdp:all\r\n\
         \r\n"
    )
}

/// Extracts a friendly device name from an SSDP response's `SERVER:` header.
///
/// Port of `ParseSsdpFriendlyName`: finds the `SERVER:` line, splits it on
/// spaces, skips generic OS/protocol tokens, and returns the first meaningful
/// token with any trailing `/version` stripped.
pub fn parse_server_name(response: &str) -> Option<String> {
    if response.is_empty() {
        return None;
    }

    for line in response.split('\n') {
        let trimmed = line.trim();
        if trimmed.len() >= 7 && trimmed[..7].eq_ignore_ascii_case("SERVER:") {
            let server = trimmed[7..].trim();
            for part in server.split(' ') {
                let p = part.trim();
                if p.is_empty() {
                    continue;
                }
                if NOISE_PREFIXES
                    .iter()
                    .any(|pre| p.len() >= pre.len() && p[..pre.len()].eq_ignore_ascii_case(pre))
                {
                    continue;
                }
                // First meaningful token; strip "/version".
                return Some(match p.find('/') {
                    Some(idx) if idx > 0 => p[..idx].to_string(),
                    _ => p.to_string(),
                });
            }
        }
    }

    None
}
