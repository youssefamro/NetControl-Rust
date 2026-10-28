//! Deterministic tests for the identification protocol builders/parsers,
//! using synthetic packets. No live network access.

use std::net::Ipv4Addr;

use netcontrol_net::dns::{
    build_ptr_query, parse_mdns_frame_name, parse_ptr_response, LLMNR_TXID, MDNS_TXID,
};
use netcontrol_net::hostname::{
    clean_hostname, clean_mdns_name, select_best_hostname, GOOGLE_CAST_LABEL,
};
use netcontrol_net::netbios::{
    build_node_status_query, parse_node_status_response, NODE_STATUS_QUERY_LEN,
};
use netcontrol_net::ssdp::{build_msearch, parse_server_name};

// ── DNS PTR query build ────────────────────────────────────────────

#[test]
fn dns_ptr_query_matches_expected_layout() {
    let q = build_ptr_query(Ipv4Addr::new(192, 168, 1, 42), MDNS_TXID);

    #[rustfmt::skip]
    let expected: Vec<u8> = vec![
        0x00, 0x00,                   // txid 0x0000 (mDNS)
        0x00, 0x00,                   // flags
        0x00, 0x01,                   // QDCOUNT = 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR
        0x02, b'4', b'2',             // "42"  (o[3])
        0x01, b'1',                   // "1"   (o[2])
        0x03, b'1', b'6', b'8',       // "168" (o[1])
        0x03, b'1', b'9', b'2',       // "192" (o[0])
        0x07, b'i', b'n', b'-', b'a', b'd', b'd', b'r', // "in-addr"
        0x04, b'a', b'r', b'p', b'a', // "arpa"
        0x00,                         // root
        0x00, 0x0C,                   // QTYPE PTR
        0x00, 0x01,                   // QCLASS IN
    ];
    assert_eq!(q, expected);
}

#[test]
fn dns_ptr_query_txid_differs_for_llmnr() {
    let q = build_ptr_query(Ipv4Addr::new(10, 0, 0, 1), LLMNR_TXID);
    assert_eq!(&q[0..2], &[0x13, 0x37]);
}

// ── DNS PTR response parse (+ compression) ─────────────────────────

/// Builds a minimal DNS PTR response: 1 question (a.b.c.d.in-addr.arpa) and 1
/// PTR answer pointing to `ptr_labels` (uncompressed name, root-terminated).
fn dns_ptr_response(ptr_labels: &[&str]) -> Vec<u8> {
    let mut m = vec![
        0x00, 0x00, // txid
        0x81, 0x80, // flags: response
        0x00, 0x01, // QD = 1
        0x00, 0x01, // AN = 1
        0x00, 0x00, 0x00, 0x00, // NS/AR
    ];
    // Question: 1.1.168.192.in-addr.arpa PTR IN
    for label in ["1", "1", "168", "192", "in-addr", "arpa"] {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0x00);
    m.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // PTR IN
                                                    // Answer: name pointer to question at offset 12, PTR, IN, ttl, rdata.
    m.extend_from_slice(&[0xC0, 0x0C]); // name -> offset 12
    m.extend_from_slice(&[0x00, 0x0C, 0x00, 0x01]); // type PTR, class IN
    m.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // ttl 60
    let mut rdata = Vec::new();
    for label in ptr_labels {
        rdata.push(label.len() as u8);
        rdata.extend_from_slice(label.as_bytes());
    }
    rdata.push(0x00);
    m.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    m.extend_from_slice(&rdata);
    m
}

#[test]
fn parse_ptr_response_extracts_cleaned_hostname() {
    let resp = dns_ptr_response(&["living-room-pc", "local"]);
    assert_eq!(parse_ptr_response(&resp).as_deref(), Some("living-room-pc"));
}

#[test]
fn parse_ptr_response_maps_googlecast() {
    let resp = dns_ptr_response(&["_googlecast", "_tcp", "local"]);
    // "_googlecast._tcp.local" -> trimmed at "._" -> "_googlecast" -> cast label.
    assert_eq!(
        parse_ptr_response(&resp).as_deref(),
        Some(GOOGLE_CAST_LABEL)
    );
}

#[test]
fn parse_ptr_response_rejects_no_answer() {
    let mut resp = dns_ptr_response(&["x", "local"]);
    resp[6] = 0x00;
    resp[7] = 0x00; // AN = 0
    assert_eq!(parse_ptr_response(&resp), None);
}

#[test]
fn parse_ptr_response_handles_truncated_packet() {
    let resp = dns_ptr_response(&["host", "local"]);
    // Truncate mid-answer; parser must not panic and returns None.
    assert_eq!(parse_ptr_response(&resp[..20]), None);
}

// ── mDNS raw-frame name parse ──────────────────────────────────────

#[test]
fn parse_mdns_frame_name_extracts_device_name() {
    // Synthetic frame: 42 bytes padding then a DNS payload at offset 42.
    let mut frame = vec![0u8; 42];
    frame.extend_from_slice(&[0u8; 12]); // DNS header
    for label in ["iPhone-de-Carlos", "_companion-link", "_tcp", "local"] {
        frame.push(label.len() as u8);
        frame.extend_from_slice(label.as_bytes());
    }
    frame.push(0x00);

    assert_eq!(
        parse_mdns_frame_name(&frame, 42).as_deref(),
        Some("iPhone-de-Carlos")
    );
}

#[test]
fn parse_mdns_frame_name_rejects_too_short() {
    assert_eq!(parse_mdns_frame_name(&[0u8; 10], 42), None);
}

// ── NetBIOS ────────────────────────────────────────────────────────

#[test]
fn netbios_query_is_fixed_wildcard_request() {
    let q = build_node_status_query();
    assert_eq!(q.len(), NODE_STATUS_QUERY_LEN);
    assert_eq!(&q[0..6], &[0x00, 0x01, 0x00, 0x00, 0x00, 0x01]);
    assert_eq!(q[12], 0x20); // name length 32
    assert_eq!(&q[13..15], b"CK");
    assert!(q[15..45].iter().all(|&b| b == b'A')); // 30 'A'
    assert_eq!(q[45], 0x00);
    assert_eq!(&q[46..50], &[0x00, 0x21, 0x00, 0x01]); // NBSTAT, IN
}

#[test]
fn parse_netbios_response_returns_workstation_name() {
    // header(12) + name ptr(2) + type/class/ttl/rdlength(10) + numNames(1) + entry(18)
    let mut r = vec![0u8; 12];
    r.extend_from_slice(&[0xC0, 0x0C]); // compressed name pointer
    r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]); // type/class/ttl
    r.extend_from_slice(&[0x00, 0x3B]); // rdlength
    r.push(0x01); // numNames = 1
                  // entry: 15-byte name "WORKSTATION-01 " + suffix 0x00 + flags 0x0000 (unique)
    let mut name = b"WORKSTATION-01 ".to_vec();
    name.resize(15, b' ');
    r.extend_from_slice(&name);
    r.push(0x00); // suffix
    r.extend_from_slice(&[0x00, 0x00]); // flags: unique
                                        // pad to >= 75 bytes
    r.resize(80, 0);

    assert_eq!(
        parse_node_status_response(&r).as_deref(),
        Some("WORKSTATION-01")
    );
}

#[test]
fn parse_netbios_skips_group_names() {
    let mut r = vec![0u8; 12];
    r.extend_from_slice(&[0xC0, 0x0C]);
    r.extend_from_slice(&[0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]);
    r.extend_from_slice(&[0x00, 0x3B]);
    r.push(0x01); // one name
    let mut name = b"WORKGROUP".to_vec();
    name.resize(15, b' ');
    r.extend_from_slice(&name);
    r.push(0x00);
    r.extend_from_slice(&[0x80, 0x00]); // flags: group bit set
    r.resize(80, 0);

    assert_eq!(parse_node_status_response(&r), None);
}

#[test]
fn parse_netbios_rejects_short_packet() {
    assert_eq!(parse_node_status_response(&[0u8; 40]), None);
}

// ── SSDP ───────────────────────────────────────────────────────────

#[test]
fn ssdp_msearch_has_required_headers() {
    let m = build_msearch(Ipv4Addr::new(192, 168, 1, 10));
    assert!(m.starts_with("M-SEARCH * HTTP/1.1\r\n"));
    assert!(m.contains("HOST: 192.168.1.10:1900\r\n"));
    assert!(m.contains("MAN: \"ssdp:discover\"\r\n"));
    assert!(m.contains("ST: ssdp:all\r\n"));
    assert!(m.ends_with("\r\n\r\n"));
}

#[test]
fn parse_ssdp_server_extracts_meaningful_token() {
    let resp = "HTTP/1.1 200 OK\r\nSERVER: Linux/3.14 UPnP/1.0 Roku/12.0\r\nST: ssdp:all\r\n\r\n";
    // Skips Linux and UPnP, takes "Roku", strips "/12.0".
    assert_eq!(parse_server_name(resp).as_deref(), Some("Roku"));
}

#[test]
fn parse_ssdp_returns_none_without_server_header() {
    let resp = "HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n";
    assert_eq!(parse_server_name(resp), None);
}

// ── Hostname cleaning + selection ──────────────────────────────────

#[test]
fn clean_hostname_strips_suffixes_and_rejects_arpa() {
    assert_eq!(
        clean_hostname("MacBook-Pro.local").as_deref(),
        Some("MacBook-Pro")
    );
    assert_eq!(clean_hostname("printer.lan").as_deref(), Some("printer"));
    assert_eq!(clean_hostname("nas.home").as_deref(), Some("nas"));
    assert_eq!(clean_hostname("1.1.168.192.in-addr.arpa"), None);
    assert_eq!(
        clean_hostname("Device._http._tcp.local").as_deref(),
        Some("Device")
    );
}

#[test]
fn clean_mdns_name_strips_only_local() {
    assert_eq!(clean_mdns_name("host.local").as_deref(), Some("host"));
    // .lan is NOT stripped by the mDNS cleaner (matches TryParseMdnsName).
    assert_eq!(clean_mdns_name("host.lan").as_deref(), Some("host.lan"));
}

#[test]
fn select_best_hostname_priority_and_validation() {
    // mDNS wins over the rest.
    let picked = select_best_hostname(&[
        Some("mdns-name"),
        Some("netbios-name"),
        None,
        Some("llmnr-name"),
        Some("dns-name"),
    ]);
    assert_eq!(picked.as_deref(), Some("mdns-name"));

    // Falls back past empty / invalid candidates to NetBIOS.
    let fallback = select_best_hostname(&[
        None,
        Some("WIN-PC"),
        Some("192.168.1.5"),
        None,
        Some("router.in-addr.arpa"),
    ]);
    assert_eq!(fallback.as_deref(), Some("WIN-PC"));

    // IP literals, localhost, and arpa are all rejected -> None.
    let none = select_best_hostname(&[
        Some("10.0.0.1"),
        Some("localhost"),
        Some("x.arpa"),
        None,
        Some("   "),
    ]);
    assert_eq!(none, None);
}
