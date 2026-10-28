//! Hostname cleaning and best-candidate selection.
//!
//! Ports `DeviceIdentifierService.CleanHostname`, the mDNS tail of
//! `TryParseMdnsName`, and `SelectBestHostname`. The literal suffixes and the
//! googlecast mapping were confirmed verbatim via REA (`.in-addr.arpa`,
//! `.ip6.arpa`, `.arpa`, `._`, `.local`, `.lan`, `.home`, `_googlecast`,
//! `Chromecast / Google Cast`).

use std::net::IpAddr;

/// Friendly label substituted for any googlecast name.
pub const GOOGLE_CAST_LABEL: &str = "Chromecast / Google Cast";

fn ends_with_ci(haystack: &str, suffix: &str) -> bool {
    let h = haystack.to_ascii_lowercase();
    h.ends_with(&suffix.to_ascii_lowercase())
}

/// True for reverse-DNS zone names that should never be treated as hostnames.
fn is_arpa(name: &str) -> bool {
    ends_with_ci(name, ".in-addr.arpa")
        || ends_with_ci(name, ".ip6.arpa")
        || ends_with_ci(name, ".arpa")
}

/// True for the special googlecast service names.
fn is_googlecast(name: &str) -> bool {
    name.eq_ignore_ascii_case("_googlecast") || ends_with_ci(name, "googlecast")
}

/// Cleans a DNS/mDNS PTR name. Port of `CleanHostname`.
///
/// Rejects `.arpa` names, trims the service-type suffix at `._`, strips
/// `.local` / `.lan` / `.home`, and maps googlecast to [`GOOGLE_CAST_LABEL`].
/// Returns `None` if nothing usable remains.
pub fn clean_hostname(full_name: &str) -> Option<String> {
    if full_name.is_empty() || is_arpa(full_name) {
        return None;
    }

    let mut name = full_name;
    if let Some(idx) = name.find("._") {
        if idx > 0 {
            name = &name[..idx];
        }
    }

    let name = strip_one_suffix_ci(name, &[".local", ".lan", ".home"]);
    let trimmed = name.trim();

    if is_googlecast(trimmed) {
        return Some(GOOGLE_CAST_LABEL.to_string());
    }
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Cleans a name extracted from a raw mDNS frame. Port of the tail of
/// `TryParseMdnsName`: like [`clean_hostname`] but strips only `.local`.
pub fn clean_mdns_name(full_name: &str) -> Option<String> {
    if is_arpa(full_name) {
        return None;
    }

    let mut name = full_name;
    if let Some(idx) = name.find("._") {
        if idx > 0 {
            name = &name[..idx];
        }
    }

    let name = strip_one_suffix_ci(name, &[".local"]);
    let trimmed = name.trim();

    if is_googlecast(trimmed) {
        return Some(GOOGLE_CAST_LABEL.to_string());
    }
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Strips the first matching suffix (case-insensitive) from `name`.
fn strip_one_suffix_ci<'a>(name: &'a str, suffixes: &[&str]) -> &'a str {
    for suf in suffixes {
        if ends_with_ci(name, suf) {
            return &name[..name.len() - suf.len()];
        }
    }
    name
}

/// Selects the best hostname from candidates given in priority order.
///
/// Port of `SelectBestHostname` (called as mDNS, NetBIOS, SSDP, LLMNR, DNS):
/// returns the first candidate that is non-empty, not an IP literal, not
/// `localhost`, and not an `.arpa` name; a googlecast candidate yields
/// [`GOOGLE_CAST_LABEL`].
pub fn select_best_hostname(candidates: &[Option<&str>]) -> Option<String> {
    for candidate in candidates {
        let name = match candidate {
            Some(n) if !n.trim().is_empty() => n.trim(),
            _ => continue,
        };
        if name.parse::<IpAddr>().is_ok() {
            continue;
        }
        if name.eq_ignore_ascii_case("localhost") {
            continue;
        }
        if is_arpa(name) {
            continue;
        }
        if is_googlecast(name) {
            return Some(GOOGLE_CAST_LABEL.to_string());
        }
        return Some(name.to_string());
    }
    None
}
