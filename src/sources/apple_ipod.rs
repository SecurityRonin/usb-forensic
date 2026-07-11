//! Source: macOS `com.apple.iPod.plist` → USB-history [`Claim`]s — the macOS counterpart
//! to the Windows registry USB history.
//!
//! `~/Library/Preferences/com.apple.iPod.plist` durably records every Apple device
//! (iPhone/iPad/iPod) connected over USB to a Mac. Under `Devices`, each entry is keyed by
//! its ID and carries the device serial, model, and — as `Connected` — the last-connected
//! timestamp (recorded by macOS, so authoritative). This source parses that plist (binary
//! or XML) and emits a [`Attribute::LastConnected`] claim per device, keyed by its serial,
//! plus its model as a [`Attribute::VolumeName`]-style human label.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use std::io::Cursor;

/// One Apple device connection decoded from `com.apple.iPod.plist`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleDevice {
    /// The device's serial number, when present.
    pub serial: Option<String>,
    /// The device ID (the `Devices` dictionary key) — the fallback identity.
    pub id: String,
    /// The model / class (`iPad14,6` / `iPad`), when present.
    pub model: Option<String>,
    /// Last-connected time (`Connected`), epoch seconds UTC, when present.
    pub last_connected: Option<i64>,
}

/// Parse `com.apple.iPod.plist` bytes into Apple-device connections. Robust: a non-plist,
/// or a plist lacking the `Devices` shape, yields an empty result rather than a panic.
#[must_use]
pub fn parse_ipod_plist(bytes: &[u8]) -> Vec<AppleDevice> {
    let Ok(root) = plist::Value::from_reader(Cursor::new(bytes)) else {
        return Vec::new();
    };
    let Some(devices) = root
        .as_dictionary()
        .and_then(|d| d.get("Devices"))
        .and_then(plist::Value::as_dictionary)
    else {
        return Vec::new();
    };
    devices
        .iter()
        .filter_map(|(id, entry)| {
            let dict = entry.as_dictionary()?;
            let s = |k: &str| {
                dict.get(k)
                    .and_then(plist::Value::as_string)
                    .map(str::to_owned)
            };
            Some(AppleDevice {
                serial: s("Serial Number"),
                id: dict
                    .get("ID")
                    .and_then(plist::Value::as_string)
                    .unwrap_or(id)
                    .to_string(),
                model: s("Product Type").or_else(|| s("Device Class")),
                last_connected: dict
                    .get("Connected")
                    .and_then(plist::Value::as_date)
                    .map(|d| system_time_to_epoch(d.into())),
            })
        })
        .collect()
}

/// Convert a plist `SystemTime` to Unix epoch seconds (pre-1970 saturates to 0).
fn system_time_to_epoch(t: std::time::SystemTime) -> i64 {
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(_) => 0,
    }
}

/// A [`HistorySource`] over decoded Apple-device connections, with the source locator.
pub struct AppleIPodSource<'a> {
    devices: &'a [AppleDevice],
    locator: String,
}

impl<'a> AppleIPodSource<'a> {
    /// Wrap decoded Apple devices with the on-disk locator of the plist they came from.
    #[must_use]
    pub fn new(devices: &'a [AppleDevice], locator: impl Into<String>) -> Self {
        Self {
            devices,
            locator: locator.into(),
        }
    }
}

impl HistorySource for AppleIPodSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for dev in self.devices {
            // Key by the device serial when present (the cross-source identity), else the ID.
            let device = DeviceKey(dev.serial.clone().unwrap_or_else(|| dev.id.clone()));
            let provenance = Provenance {
                source: SourceKind::AppleIPod,
                locator: format!("{}#Devices/{}", self.locator, dev.id),
            };
            if let Some(when) = dev.last_connected {
                out.push(Claim {
                    device: device.clone(),
                    attribute: Attribute::LastConnected,
                    value: Value::Timestamp(when),
                    provenance: provenance.clone(),
                });
            }
            if let Some(model) = &dev.model {
                out.push(Claim {
                    device,
                    attribute: Attribute::VolumeName,
                    value: Value::Text(model.clone()),
                    provenance,
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Devices</key><dict>
  <key>0004486C1A03401E</key><dict>
    <key>Device Class</key><string>iPad</string>
    <key>Product Type</key><string>iPad14,6</string>
    <key>Serial Number</key><string>TESTSERIAL9</string>
    <key>ID</key><string>0004486C1A03401E</string>
    <key>Connected</key><date>2023-07-04T00:50:36Z</date>
  </dict>
  <key>NOSERIAL</key><dict><key>Device Class</key><string>iPhone</string></dict>
</dict></dict></plist>"#;

    #[test]
    fn parse_extracts_serial_model_and_last_connected() {
        let devs = parse_ipod_plist(XML.as_bytes());
        let ipad = devs
            .iter()
            .find(|d| d.serial.as_deref() == Some("TESTSERIAL9"))
            .expect("device present");
        assert_eq!(ipad.model.as_deref(), Some("iPad14,6"));
        assert_eq!(ipad.last_connected, Some(1_688_431_836));
    }

    #[test]
    fn a_non_plist_or_wrong_shape_yields_nothing() {
        assert!(parse_ipod_plist(b"not a plist").is_empty());
        let other = r#"<?xml version="1.0"?><plist version="1.0"><dict><key>X</key><string>y</string></dict></plist>"#;
        assert!(parse_ipod_plist(other.as_bytes()).is_empty());
    }

    #[test]
    fn a_pre_1970_connected_date_saturates_to_epoch_zero() {
        // Defensive: a clock-wrong device with a pre-epoch `Connected` date yields 0, not a
        // panic or a negative wraparound.
        let xml = r#"<?xml version="1.0"?><plist version="1.0"><dict><key>Devices</key><dict>
          <key>OLD</key><dict><key>Serial Number</key><string>S</string>
          <key>Connected</key><date>1969-01-01T00:00:00Z</date></dict>
        </dict></dict></plist>"#;
        let devs = parse_ipod_plist(xml.as_bytes());
        assert_eq!(devs[0].last_connected, Some(0));
    }

    #[test]
    fn source_emits_last_connected_and_model_keyed_by_serial() {
        let devs = parse_ipod_plist(XML.as_bytes());
        let claims = AppleIPodSource::new(&devs, "com.apple.iPod.plist").claims();
        let lc = claims
            .iter()
            .find(|c| c.attribute == Attribute::LastConnected)
            .expect("last-connected claim");
        assert_eq!(lc.device, DeviceKey("TESTSERIAL9".to_string()));
        assert_eq!(lc.value, Value::Timestamp(1_688_431_836));
        assert_eq!(lc.provenance.source, SourceKind::AppleIPod);
        assert!(lc.provenance.locator.contains("Devices/0004486C1A03401E"));
        let name = claims
            .iter()
            .find(|c| c.attribute == Attribute::VolumeName)
            .expect("model claim");
        assert_eq!(name.value, Value::Text("iPad14,6".to_string()));
    }

    #[test]
    fn a_serialless_device_is_keyed_by_its_id_and_still_emits_its_model() {
        let devs = parse_ipod_plist(XML.as_bytes());
        let claims = AppleIPodSource::new(&devs, "f").claims();
        // NOSERIAL has a model but no serial and no Connected date → one VolumeName claim.
        let name = claims
            .iter()
            .find(|c| c.device == DeviceKey("NOSERIAL".to_string()))
            .expect("serialless device present");
        assert_eq!(name.attribute, Attribute::VolumeName);
        assert_eq!(name.value, Value::Text("iPhone".to_string()));
    }
}
