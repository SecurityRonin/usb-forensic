//! Source: macOS `system_profiler -json SPUSBDataType` → USB-history [`Claim`]s.
//!
//! `system_profiler SPUSBDataType` reports the live USB device tree (the same data the
//! IORegistry `IOUSBHostDevice` nodes expose), as a JSON tree of buses/hubs/devices. Each
//! device carries its `serial_num`, `product_id`/`vendor_id` (as `0x….` strings),
//! `manufacturer`, and — for mass storage — a `Media` array. This reader walks that tree
//! and emits, per device, the model as a label and its VID/PID; it is the macOS live-triage
//! counterpart to the Windows registry USB history.

#![allow(clippy::doc_markdown)] // macOS proper nouns (system_profiler, IORegistry)
use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};

/// One USB device decoded from the `system_profiler` tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacUsbDevice {
    /// The device's serial number, when reported.
    pub serial: Option<String>,
    /// The product / device name (`_name`).
    pub name: String,
    /// USB vendor id (`vendor_id`, parsed from its `0x….` form), when present.
    pub vid: Option<u16>,
    /// USB product id (`product_id`), when present.
    pub pid: Option<u16>,
    /// The manufacturer string, when reported.
    pub manufacturer: Option<String>,
    /// Whether the device presents mass-storage media (a `Media` array).
    pub is_mass_storage: bool,
}

/// Parse `system_profiler -json SPUSBDataType` output into USB devices. A node is a
/// *device* (rather than a bus/hub) when it reports a `product_id` or a `serial_num`; buses
/// and hubs are walked through to reach the devices beneath them. Robust: non-JSON, or a
/// tree with no devices, yields an empty result rather than a panic.
#[must_use]
pub fn parse_system_profiler(json: &[u8]) -> Vec<MacUsbDevice> {
    let Ok(root) = serde_json::from_slice::<serde_json::Value>(json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(items) = root.get("SPUSBDataType").and_then(|v| v.as_array()) {
        for item in items {
            walk(item, &mut out);
        }
    }
    out
}

/// Recursively collect device nodes from a `system_profiler` USB tree node.
fn walk(node: &serde_json::Value, out: &mut Vec<MacUsbDevice>) {
    let str_field = |k: &str| node.get(k).and_then(|v| v.as_str()).map(str::to_owned);
    // A device node reports a product id or a serial; a bare bus/hub reports neither.
    if node.get("product_id").is_some() || node.get("serial_num").is_some() {
        out.push(MacUsbDevice {
            serial: str_field("serial_num"),
            name: str_field("_name").unwrap_or_default(),
            vid: node.get("vendor_id").and_then(|v| parse_hex_id(v.as_str())),
            pid: node
                .get("product_id")
                .and_then(|v| parse_hex_id(v.as_str())),
            manufacturer: str_field("manufacturer"),
            is_mass_storage: node.get("Media").and_then(|v| v.as_array()).is_some(),
        });
    }
    if let Some(children) = node.get("_items").and_then(|v| v.as_array()) {
        for child in children {
            walk(child, out);
        }
    }
}

/// Parse a `system_profiler` id like `"0x05ac"` or `"0x05ac  (Apple Inc.)"` into a `u16`.
/// The value is the leading `0x…` hex token; a trailing vendor-name gloss is ignored.
fn parse_hex_id(s: Option<&str>) -> Option<u16> {
    let tok = s?.split_whitespace().next()?;
    let hex = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X"))?;
    u16::from_str_radix(hex, 16).ok()
}

/// A [`HistorySource`] over decoded macOS USB devices, with the capture's locator.
pub struct MacUsbSource<'a> {
    devices: &'a [MacUsbDevice],
    locator: String,
}

impl<'a> MacUsbSource<'a> {
    /// Wrap decoded devices with the locator of the `system_profiler` capture.
    #[must_use]
    pub fn new(devices: &'a [MacUsbDevice], locator: impl Into<String>) -> Self {
        Self {
            devices,
            locator: locator.into(),
        }
    }
}

impl HistorySource for MacUsbSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for dev in self.devices {
            // Key by serial (the cross-source identity) when present, else the device name.
            let device = DeviceKey(dev.serial.clone().unwrap_or_else(|| dev.name.clone()));
            let provenance = Provenance {
                source: SourceKind::MacosUsb,
                locator: self.locator.clone(),
            };
            if !dev.name.is_empty() {
                out.push(Claim {
                    device: device.clone(),
                    attribute: Attribute::VolumeName,
                    value: Value::Text(dev.name.clone()),
                    provenance: provenance.clone(),
                });
            }
            if dev.is_mass_storage {
                out.push(Claim {
                    device,
                    attribute: Attribute::DeviceClass,
                    value: Value::Text("MassStorage".to_string()),
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

    /// A `system_profiler -json SPUSBDataType` capture with one bus, one hub, and a
    /// mass-storage stick beneath it — the documented shape (a bus → `_items` → device).
    const JSON: &str = r#"{"SPUSBDataType":[
      {"_name":"USB31Bus","host_controller":"AppleT8132USBXHCI","_items":[
        {"_name":"USB3.0 Hub","product_id":"0x2513","_items":[
          {"_name":"Cruzer Blade","serial_num":"4C531001234","product_id":"0x5567",
           "vendor_id":"0x0781  (SanDisk Corporation)","manufacturer":"SanDisk",
           "Media":[{"bsd_name":"disk4","size":"16 GB"}]}
        ]}
      ]}
    ]}"#;

    #[test]
    fn walks_the_tree_and_extracts_the_storage_device() {
        let devs = parse_system_profiler(JSON.as_bytes());
        let stick = devs
            .iter()
            .find(|d| d.serial.as_deref() == Some("4C531001234"))
            .expect("storage device present");
        assert_eq!(stick.name, "Cruzer Blade");
        assert_eq!(stick.vid, Some(0x0781)); // vendor gloss ignored
        assert_eq!(stick.pid, Some(0x5567));
        assert_eq!(stick.manufacturer.as_deref(), Some("SanDisk"));
        assert!(stick.is_mass_storage);
        // The hub (product_id, no serial, no Media) is a device node but not mass storage.
        let hub = devs.iter().find(|d| d.name == "USB3.0 Hub").expect("hub");
        assert!(!hub.is_mass_storage);
        assert_eq!(hub.serial, None);
    }

    #[test]
    fn a_real_empty_bus_capture_yields_no_devices() {
        // The exact shape this project captured from a real Mac with nothing plugged in:
        // three buses, no `_items`, no device fields → zero devices, no panic.
        let empty = r#"{"SPUSBDataType":[
          {"_name":"USB31Bus","host_controller":"AppleT8132USBXHCI"},
          {"_name":"USB31Bus","host_controller":"AppleT8132USBXHCI"}
        ]}"#;
        assert!(parse_system_profiler(empty.as_bytes()).is_empty());
    }

    #[test]
    fn non_json_or_missing_key_yields_nothing() {
        assert!(parse_system_profiler(b"not json").is_empty());
        assert!(parse_system_profiler(br#"{"Other":[]}"#).is_empty());
    }

    #[test]
    fn parse_hex_id_reads_the_leading_hex_token_only() {
        assert_eq!(parse_hex_id(Some("0x05ac")), Some(0x05ac));
        assert_eq!(
            parse_hex_id(Some("0x0781  (SanDisk Corporation)")),
            Some(0x0781)
        );
        assert_eq!(parse_hex_id(Some("garbage")), None);
        assert_eq!(parse_hex_id(None), None);
    }

    #[test]
    fn source_emits_name_and_mass_storage_claims_keyed_by_serial() {
        let devs = parse_system_profiler(JSON.as_bytes());
        let claims = MacUsbSource::new(&devs, "mac-usb.json").claims();
        let stick_claims: Vec<_> = claims
            .iter()
            .filter(|c| c.device == DeviceKey("4C531001234".to_string()))
            .collect();
        assert!(stick_claims
            .iter()
            .any(|c| c.attribute == Attribute::VolumeName
                && c.value == Value::Text("Cruzer Blade".to_string())));
        assert!(stick_claims
            .iter()
            .any(|c| c.attribute == Attribute::DeviceClass
                && c.value == Value::Text("MassStorage".to_string())));
        assert_eq!(stick_claims[0].provenance.source, SourceKind::MacosUsb);
    }
}
