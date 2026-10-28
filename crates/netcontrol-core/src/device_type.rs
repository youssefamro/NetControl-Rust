//! Device category enumeration.

/// Categories of network devices inferred from OUI vendor and hostname heuristics.
///
/// Ported from the C# `DeviceType` enum (same variants, same order).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DeviceType {
    #[default]
    Unknown,
    Router,
    Desktop,
    Mobile,
    Tablet,
    SmartTV,
    Console,
    IoT,
    Printer,
    NetworkInfra,
}

impl DeviceType {
    /// Display name used in labels, matching C#'s `Enum.ToString()`.
    pub fn as_str(self) -> &'static str {
        match self {
            DeviceType::Unknown => "Unknown",
            DeviceType::Router => "Router",
            DeviceType::Desktop => "Desktop",
            DeviceType::Mobile => "Mobile",
            DeviceType::Tablet => "Tablet",
            DeviceType::SmartTV => "SmartTV",
            DeviceType::Console => "Console",
            DeviceType::IoT => "IoT",
            DeviceType::Printer => "Printer",
            DeviceType::NetworkInfra => "NetworkInfra",
        }
    }
}

impl std::fmt::Display for DeviceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
