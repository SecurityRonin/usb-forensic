//! Source: macOS unified-log USB enumeration events (`log show --style json`) →
//! USB-history [`Claim`]s — the macOS *connection history* (with times).
//!
//! The macOS unified log records a `AppleUSBHostPort::enumerateDeviceComplete` message
//! each time a USB device is enumerated (connected), e.g.
//! `enumerated 0x0781/55ab/0100 ( SanDisk 3.2Gen1 / 1) at 5 Gbps`, carrying the device's
//! VID/PID, its product name, and — as the event timestamp — the moment it was connected.
//! Unlike the live `system_profiler` snapshot, this yields *when* a device was attached and
//! recovers every connection, so a device removed before imaging is still seen. This reader
//! parses those events into first/last-connected times per device.

#![allow(clippy::doc_markdown)] // macOS proper nouns (AppleUSBHostPort, …)

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use std::collections::BTreeMap;

/// A USB device enumeration event decoded from one unified-log message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsbEnumeration {
    /// USB vendor id.
    pub vid: u16,
    /// USB product id.
    pub pid: u16,
    /// The device's product name, trimmed.
    pub name: String,
    /// The enumeration (connect) time, epoch seconds UTC.
    pub when: i64,
}

/// Parse `log show --style json` output into USB enumeration events. Only
/// `enumerateDeviceComplete` messages carrying an `enumerated 0x<vid>/<pid>/<bcd> ( <name>`
/// payload are decoded; every other log line is skipped. Robust: non-JSON, or a log with no
/// USB events, yields an empty result rather than a panic.
#[must_use]
pub fn parse_unified_log(json: &[u8]) -> Vec<UsbEnumeration> {
    let Ok(events) = serde_json::from_slice::<Vec<serde_json::Value>>(json) else {
        return Vec::new();
    };
    events
        .iter()
        .filter_map(|e| {
            let msg = e.get("eventMessage")?.as_str()?;
            let (vid, pid, name) = parse_enumeration_message(msg)?;
            let when = parse_log_timestamp(e.get("timestamp")?.as_str()?)?;
            Some(UsbEnumeration {
                vid,
                pid,
                name,
                when,
            })
        })
        .collect()
}

/// Extract `(vid, pid, name)` from an `enumerateDeviceComplete` message. The payload is
/// `enumerated 0x<vid>/<pid>/<bcd> ( <name> / <n>) at …`; `None` for any other message.
fn parse_enumeration_message(msg: &str) -> Option<(u16, u16, String)> {
    let rest = msg.split("enumerated 0x").nth(1)?;
    let mut ids = rest.splitn(3, '/');
    let vid = u16::from_str_radix(ids.next()?.trim(), 16).ok()?;
    let pid = u16::from_str_radix(ids.next()?.trim(), 16).ok()?;
    // The product name sits between the first "( " and the following " / ".
    let after_paren = rest.split('(').nth(1)?;
    let name = after_paren.split('/').next()?.trim().to_string();
    Some((vid, pid, name))
}

/// Parse a unified-log timestamp (`2026-07-12 18:51:45.843302+0800`) to epoch seconds.
/// Normalizes the space separator and the `+HHMM` offset to RFC 3339 for `jiff`.
fn parse_log_timestamp(ts: &str) -> Option<i64> {
    let (date, rest) = ts.split_once(' ')?;
    // rest is `HH:MM:SS.ffffff±HHMM`; find the offset sign to insert the colon.
    let sign = rest.rfind(['+', '-'])?;
    let (time, off) = rest.split_at(sign);
    // off is `+0800` → `+08:00`.
    if off.len() != 5 {
        return None;
    }
    let rfc = format!("{date}T{time}{}:{}", &off[..3], &off[3..]);
    rfc.parse::<jiff::Timestamp>()
        .ok()
        .map(jiff::Timestamp::as_second)
}

/// A [`HistorySource`] over decoded USB enumeration events.
pub struct MacUnifiedLogSource<'a> {
    events: &'a [UsbEnumeration],
    locator: String,
}

impl<'a> MacUnifiedLogSource<'a> {
    /// Wrap decoded enumeration events with the locator of the log capture.
    #[must_use]
    pub fn new(events: &'a [UsbEnumeration], locator: impl Into<String>) -> Self {
        Self {
            events,
            locator: locator.into(),
        }
    }
}

impl HistorySource for MacUnifiedLogSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        // Aggregate every enumeration of the same device (by VID/PID) into its first and
        // last connect time — the connection history a live snapshot cannot provide.
        let mut by_device: BTreeMap<(u16, u16), (i64, i64, String)> = BTreeMap::new();
        for e in self.events {
            let entry = by_device
                .entry((e.vid, e.pid))
                .or_insert((e.when, e.when, e.name.clone()));
            entry.0 = entry.0.min(e.when);
            entry.1 = entry.1.max(e.when);
        }
        let mut out = Vec::new();
        for ((vid, pid), (first, last, name)) in by_device {
            let device = DeviceKey(format!("usb-{vid:04X}-{pid:04X}"));
            let provenance = Provenance {
                source: SourceKind::MacosUnifiedLog,
                locator: self.locator.clone(),
            };
            let claim = |attribute, value| Claim {
                device: device.clone(),
                attribute,
                value,
                provenance: provenance.clone(),
            };
            out.push(claim(Attribute::FirstConnected, Value::Timestamp(first)));
            out.push(claim(Attribute::LastConnected, Value::Timestamp(last)));
            if !name.is_empty() {
                out.push(claim(Attribute::VolumeName, Value::Text(name)));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The real message + timestamp shape captured from a Mac (SanDisk stick, this project).
    const MSG: &str = "usb-drd0-port-ss@00200000: AppleUSBHostPort::enumerateDeviceComplete_block_invoke: enumerated 0x0781/55ab/0100 ( SanDisk 3.2Gen1 / 1) at 5 Gbps";

    fn log_json(events: &[(&str, &str)]) -> Vec<u8> {
        let items: Vec<String> = events
            .iter()
            .map(|(ts, msg)| {
                format!(
                    r#"{{"timestamp":"{ts}","eventMessage":{}}}"#,
                    serde_json::to_string(msg).unwrap()
                )
            })
            .collect();
        format!("[{}]", items.join(",")).into_bytes()
    }

    #[test]
    fn parse_enumeration_message_extracts_vid_pid_name() {
        let (vid, pid, name) = parse_enumeration_message(MSG).expect("enumeration");
        assert_eq!(vid, 0x0781);
        assert_eq!(pid, 0x55ab);
        assert_eq!(name, "SanDisk 3.2Gen1");
        // a non-enumeration message yields None.
        assert_eq!(parse_enumeration_message("some other log line"), None);
    }

    #[test]
    fn parse_log_timestamp_handles_the_real_offset_format() {
        // 2026-07-12 18:51:45 +0800 = 2026-07-12 10:51:45 UTC = epoch 1_783_853_505
        // (verified with an independent oracle: Python `datetime.fromisoformat`).
        assert_eq!(
            parse_log_timestamp("2026-07-12 18:51:45.843302+0800"),
            Some(1_783_853_505)
        );
        assert_eq!(parse_log_timestamp("garbage"), None);
        assert_eq!(parse_log_timestamp("2026-07-12 18:51:45+08"), None); // short offset
    }

    #[test]
    fn multiple_enumerations_aggregate_to_first_and_last_connected() {
        let json = log_json(&[
            ("2026-07-12 18:51:45.843302+0800", MSG),
            ("2026-07-12 18:54:04.537000+0800", MSG),
        ]);
        let events = parse_unified_log(&json);
        assert_eq!(events.len(), 2);
        let claims = MacUnifiedLogSource::new(&events, "log.json").claims();
        let first = claims
            .iter()
            .find(|c| c.attribute == Attribute::FirstConnected)
            .expect("first-connected");
        let last = claims
            .iter()
            .find(|c| c.attribute == Attribute::LastConnected)
            .expect("last-connected");
        assert_eq!(first.value, Value::Timestamp(1_783_853_505)); // 18:51:45 +0800
        assert_eq!(last.value, Value::Timestamp(1_783_853_644)); // 18:54:04 +0800
        assert_eq!(first.device, DeviceKey("usb-0781-55AB".to_string()));
        assert_eq!(first.provenance.source, SourceKind::MacosUnifiedLog);
    }

    #[test]
    fn non_json_or_no_usb_events_yields_nothing() {
        assert!(parse_unified_log(b"not json").is_empty());
        let other = log_json(&[("2026-07-12 18:51:45.0+0800", "unrelated kernel message")]);
        assert!(parse_unified_log(&other).is_empty());
    }
}
