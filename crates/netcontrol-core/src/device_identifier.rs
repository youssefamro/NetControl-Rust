//! Device-type inference heuristics.
//!
//! Ported from `DeviceIdentifierService.InferDeviceType` in the C# project.
//! This is the pure, offline classification layer (Layer 5): it maps a device's
//! vendor + hostname (and gateway flag) to a [`DeviceType`]. The active network
//! probes (DNS/NetBIOS/mDNS/SSDP/LLMNR) from the original service are **not**
//! implemented in this phase.

use crate::device_type::DeviceType;
use crate::pc::Pc;

/// Case-insensitive "contains any of these substrings" test, matching the C#
/// `ContainsAny` helper (which used `StringComparison.OrdinalIgnoreCase`).
fn contains_any(text: &str, keywords: &[&str]) -> bool {
    let lower = text.to_ascii_lowercase();
    keywords
        .iter()
        .any(|kw| lower.contains(&kw.to_ascii_lowercase()))
}

/// Infers a device category from vendor and hostname heuristics.
///
/// Faithful port of `DeviceIdentifierService.InferDeviceType`; the ordering of
/// checks is significant and preserved exactly.
pub fn infer_device_type(device: &Pc) -> DeviceType {
    if device.is_gateway {
        return DeviceType::Router;
    }

    let vendor = device.vendor.as_deref().unwrap_or("");
    let hostname = device.hostname.as_deref().unwrap_or("");

    // 1. Check hostname keywords first (more specific)
    if contains_any(
        hostname,
        &[
            "-TV",
            "SmartTV",
            "BRAVIA",
            "Roku",
            "Fire-TV",
            "FireTV",
            "Chromecast",
            "AppleTV",
            "Apple-TV",
            "Tizen",
            "WebOS",
            "Shield",
            "AndroidTV",
            "GoogleTV",
            "MiBox",
            "Vizio",
            "Hisense",
            "TCL",
            "Panasonic-TV",
            "Sharp-TV",
            "Smart-TV",
            "googlecast",
            "_googlecast",
            "Cast",
        ],
    ) {
        return DeviceType::SmartTV;
    }

    if contains_any(
        hostname,
        &[
            "PlayStation",
            "PS3",
            "PS4",
            "PS5",
            "Xbox",
            "Switch",
            "Nintendo",
            "SteamDeck",
        ],
    ) {
        return DeviceType::Console;
    }

    if contains_any(
        hostname,
        &[
            "iPhone", "Galaxy", "Redmi", "POCO", "Pixel", "Xperia", "Huawei", "Honor", "OnePlus",
            "Moto", "Realme", "Android",
        ],
    ) {
        return DeviceType::Mobile;
    }

    if contains_any(hostname, &["iPad", "Tab", "MediaPad", "MatePad", "Kindle"]) {
        return DeviceType::Tablet;
    }

    if contains_any(
        hostname,
        &[
            "MacBook",
            "iMac",
            "Macmini",
            "MacPro",
            "DESKTOP-",
            "LAPTOP-",
            "PC-",
            "Surface",
            "ThinkPad",
            "Latitude",
            "Inspiron",
            "Precision",
            "EliteBook",
            "ProBook",
            "OptiPlex",
            "Workstation",
        ],
    ) {
        return DeviceType::Desktop;
    }

    if contains_any(
        hostname,
        &[
            "printer",
            "LaserJet",
            "DeskJet",
            "OfficeJet",
            "EPSON",
            "Canon",
            "Brother",
            "Kyocera",
            "Xerox",
            "Ricoh",
            "Pantum",
        ],
    ) {
        return DeviceType::Printer;
    }

    if contains_any(
        hostname,
        &[
            "router",
            "gateway",
            "accesspoint",
            "ap-",
            "switch",
            "modem",
            "unifi",
            "amplifi",
            "mikrotik",
            "openwrt",
            "pfsense",
        ],
    ) {
        return DeviceType::NetworkInfra;
    }

    if contains_any(
        hostname,
        &[
            "sonos",
            "echo",
            "alexa",
            "nest",
            "homepod",
            "hue",
            "lifx",
            "tuya",
            "shelly",
            "esp32",
            "esp8266",
            "espressif",
            "raspberrypi",
            "arduino",
            "ring",
            "wyze",
            "blink",
            "tapo",
            "ezviz",
            "smart",
            "plug",
            "bulb",
            "light",
            "thermostat",
            "vacuum",
            "camera",
            "cam-",
        ],
    ) {
        return DeviceType::IoT;
    }

    // 2. Check vendor keywords
    if contains_any(vendor, &["Nintendo", "Sony Interactive", "Valve"]) {
        return DeviceType::Console;
    }

    if contains_any(vendor, &["Roku", "Vizio", "TCL", "Hisense"]) {
        return DeviceType::SmartTV;
    }

    if contains_any(vendor, &["LG Electronics"]) && contains_any(hostname, &["TV", "webOS", "LG"]) {
        return DeviceType::SmartTV;
    }

    if contains_any(
        vendor,
        &[
            "Sonos",
            "Espressif",
            "Tuya",
            "Raspberry Pi",
            "Nest Labs",
            "Ring LLC",
            "Zengge",
            "Yeelight",
            "Signify",
        ],
    ) {
        return DeviceType::IoT;
    }

    if contains_any(
        vendor,
        &[
            "Ubiquiti",
            "Cisco",
            "NETGEAR",
            "TP-Link",
            "D-Link",
            "Arris",
            "ZTE",
            "Sagemcom",
            "Aruba",
            "Arcadyan",
            "Technicolor",
            "Zhone/DZS",
            "Dasan",
            "CIG/Shanghai Bell",
            "AVM",
            "MikroTik",
        ],
    ) {
        return DeviceType::NetworkInfra;
    }

    if contains_any(
        vendor,
        &[
            "HP", "Epson", "Canon", "Brother", "Kyocera", "Xerox", "Ricoh",
        ],
    ) && !contains_any(hostname, &["DESKTOP", "LAPTOP", "PC"])
    {
        return DeviceType::Printer;
    }

    if contains_any(vendor, &["Apple"]) {
        if contains_any(hostname, &["MacBook", "iMac", "Mac"]) {
            return DeviceType::Desktop;
        }
        if contains_any(hostname, &["iPad"]) {
            return DeviceType::Tablet;
        }
        if contains_any(hostname, &["TV"]) {
            return DeviceType::SmartTV;
        }
        if contains_any(hostname, &["HomePod"]) {
            return DeviceType::IoT;
        }
        return DeviceType::Mobile;
    }

    if contains_any(
        vendor,
        &[
            "Samsung",
            "Xiaomi",
            "Huawei",
            "OnePlus",
            "OPPO",
            "Vivo",
            "Motorola",
            "Transsion",
        ],
    ) {
        if contains_any(hostname, &["TV", "Tizen"]) {
            return DeviceType::SmartTV;
        }
        return DeviceType::Mobile;
    }

    if contains_any(
        vendor,
        &[
            "Intel",
            "Realtek",
            "Dell",
            "Lenovo",
            "Microsoft",
            "ASUSTek",
            "Acer",
            "MSI",
            "Gigabyte",
        ],
    ) {
        if contains_any(hostname, &["Xbox"]) {
            return DeviceType::Console;
        }
        return DeviceType::Desktop;
    }

    if contains_any(vendor, &["Amazon"]) {
        if contains_any(hostname, &["Fire-TV", "FireTV", "AFT"]) {
            return DeviceType::SmartTV;
        }
        return DeviceType::IoT;
    }

    if contains_any(vendor, &["Google"]) {
        if contains_any(hostname, &["Chromecast", "GoogleTV"]) {
            return DeviceType::SmartTV;
        }
        if contains_any(hostname, &["Pixel"]) {
            return DeviceType::Mobile;
        }
        return DeviceType::IoT;
    }

    DeviceType::Unknown
}
