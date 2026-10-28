//! Shared test helpers.

/// Parses a 12-hex-char MAC string (no separators), e.g. "74D83E6E1BC6".
pub fn parse_mac(s: &str) -> [u8; 6] {
    let clean: String = s.chars().filter(|c| *c != ':').collect();
    assert_eq!(clean.len(), 12, "MAC must be 12 hex chars: {s}");
    let mut out = [0u8; 6];
    for i in 0..6 {
        out[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).expect("valid hex");
    }
    out
}
