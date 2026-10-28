//! Passive ARP observation and device learning.
//!
//! The observation logic ports `CArp.ArpListenerLoop`: for each captured frame
//! it ignores anything shorter than a full ARP frame, skips frames sent by the
//! local host, learns from ARP requests and replies, flags the gateway and
//! local host, and records the device in a [`PcList`].
//!
//! [`observe_arp_frame`] is pure and fully testable with synthetic frames. The
//! live capture loop that feeds it real frames is behind the `live-capture`
//! feature and is **off by default** (it requires Npcap/libpcap). This is
//! read-only observation: no packet is ever transmitted here.

use std::net::Ipv4Addr;

use netcontrol_core::{AddOutcome, Pc, PcList};

use crate::arp::{ArpPacket, ARP_FRAME_LEN};

/// Fixed context for interpreting observed frames.
#[derive(Debug, Clone, Copy)]
pub struct ObserveContext {
    /// The local interface MAC; frames whose Ethernet source equals this are
    /// skipped (the host's own traffic), matching the C# `srcMac == LocalMac`.
    pub local_mac: [u8; 6],
    /// The local host IPv4, used to flag the local device (optional).
    pub local_ip: Option<Ipv4Addr>,
    /// The gateway IPv4, used to flag the router device (optional).
    pub router_ip: Option<Ipv4Addr>,
}

/// Outcome of observing a single frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// Frame was shorter than a full ARP frame (< 42 bytes).
    TooShort,
    /// Not an ARP frame (wrong EtherType) or malformed ARP payload.
    NotArp,
    /// Frame originated from the local host; ignored.
    FromSelf,
    /// A valid ARP frame whose opcode is neither request nor reply.
    NotLearnable,
    /// A device was learned (added or refreshed).
    Learned {
        ip: Ipv4Addr,
        mac: [u8; 6],
        is_gateway: bool,
        is_local: bool,
        outcome: AddOutcome,
        /// Set when the learned device is the gateway, exposing its MAC
        /// (informational only — never used to poison or redirect).
        learned_gateway_mac: Option<[u8; 6]>,
    },
}

/// Processes one captured Ethernet frame, updating `list`.
///
/// Faithful port of the body of `CArp.ArpListenerLoop`, with the frame offsets
/// confirmed by REA (srcMAC\@6, opcode\@21, senderMAC\@22, senderIP\@28, min
/// length 42). Unlike the original — which tested only the low opcode byte —
/// this validates the full 16-bit opcode and the ARP EtherType before learning.
pub fn observe_arp_frame(list: &PcList, frame: &[u8], ctx: &ObserveContext) -> Observation {
    if frame.len() < ARP_FRAME_LEN {
        return Observation::TooShort;
    }

    // Ethernet source == local MAC -> our own frame; skip.
    if frame[6..12] == ctx.local_mac {
        return Observation::FromSelf;
    }

    let (_eth, arp) = match ArpPacket::parse_frame(frame) {
        Some(parsed) => parsed,
        None => return Observation::NotArp,
    };

    if !arp.op.is_learnable() {
        return Observation::NotLearnable;
    }

    let sender_ip = arp.sender_ip;
    let sender_mac = arp.sender_mac;

    let is_gateway = ctx.router_ip == Some(sender_ip);
    let is_local = ctx.local_ip == Some(sender_ip);

    let mut pc = Pc::new();
    pc.ip = Some(sender_ip);
    pc.mac = Some(sender_mac);
    pc.is_gateway = is_gateway;
    pc.is_local_pc = is_local;

    let outcome = list.add_device(pc);

    Observation::Learned {
        ip: sender_ip,
        mac: sender_mac,
        is_gateway,
        is_local,
        outcome,
        learned_gateway_mac: if is_gateway { Some(sender_mac) } else { None },
    }
}

// ── Live capture backend (opt-in, off by default) ──────────────────

#[cfg(feature = "live-capture")]
pub use live::ArpListener;

#[cfg(feature = "live-capture")]
mod live {
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};

    use netcontrol_core::PcList;

    use super::{observe_arp_frame, ObserveContext};
    use crate::capture::{self, CaptureDevice, CaptureHealth};
    use crate::error::{CancelToken, NetError};

    /// Consecutive read errors tolerated before declaring the capture failed.
    const MAX_CONSECUTIVE_ERRORS: u32 = 50;

    /// A passive, read-only ARP listener running on a background thread.
    ///
    /// It only *reads* frames and updates the device list; it never transmits.
    /// Dropping the listener (or calling [`stop`](ArpListener::stop)) cancels
    /// the loop and joins the thread (bounded; see [`capture::join_with_grace`]).
    pub struct ArpListener {
        cancel: CancelToken,
        health: Arc<CaptureHealth>,
        handle: Option<JoinHandle<()>>,
    }

    impl ArpListener {
        /// Starts observing ARP on the resolved capture `device`, feeding `list`.
        pub fn start(
            device: &CaptureDevice,
            list: Arc<PcList>,
            ctx: ObserveContext,
        ) -> Result<ArpListener, NetError> {
            let mut rx = capture::open_receiver(device)?;

            let cancel = CancelToken::new();
            let health = Arc::new(CaptureHealth::default());
            let loop_cancel = cancel.clone();
            let loop_health = health.clone();
            let handle = thread::Builder::new()
                .name("arp-listener".into())
                .spawn(move || {
                    let mut errors = 0u32;
                    while !loop_cancel.is_cancelled() {
                        match rx.next() {
                            Ok(frame) => {
                                errors = 0;
                                let _ = observe_arp_frame(&list, frame, &ctx);
                            }
                            Err(e) if capture::is_idle_timeout(&e) => {}
                            Err(e) => {
                                errors += 1;
                                if errors >= MAX_CONSECUTIVE_ERRORS {
                                    loop_health.fail(format!("ARP listener stopped: {e}"));
                                    return;
                                }
                            }
                        }
                    }
                })
                .map_err(NetError::Io)?;

            Ok(ArpListener {
                cancel,
                health,
                handle: Some(handle),
            })
        }

        /// Whether the listener stopped because reads kept failing.
        pub fn has_failed(&self) -> bool {
            self.health.has_failed()
        }

        /// The terminal read error, if the listener failed.
        pub fn last_error(&self) -> Option<String> {
            self.health.last_error()
        }

        /// Signals the loop to stop and joins the background thread.
        pub fn stop(mut self) {
            self.shutdown();
        }

        fn shutdown(&mut self) {
            self.cancel.cancel();
            if let Some(handle) = self.handle.take() {
                capture::join_with_grace(handle, capture::STOP_GRACE);
            }
        }
    }

    impl Drop for ArpListener {
        fn drop(&mut self) {
            self.shutdown();
        }
    }
}
