//! Adapter: Microsoft-Windows-Kernel-PnP/Configuration event-log records → USB-history
//! [`Claim`]s.
//!
//! The Kernel-PnP Configuration log records a device-configuration event each time Windows
//! configures a Plug-and-Play device — EID 400 (started), 410 (migrated), 430 (installed).
//! For a USB device the `DeviceInstanceId` carries the same instance serial the registry
//! `Enum\{USB,USBSTOR}` keys record, so a Kernel-PnP event is an **event-log** witness that
//! the device was connected at the record's time — a different tamper surface from the
//! registry / setupapi record of the same device, so when they agree the correlation core
//! grades it corroborated. A pure mapping over already-decoded event JSON; the `evtx` reader
//! (in the binary) does the `.evtx` parsing.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};

/// Kernel-PnP device-configuration Event IDs that witness a device being present/configured:
/// 400 (device started), 410 (device migrated), 430 (device installed).
const CONFIG_EVENT_IDS: [u32; 3] = [400, 410, 430];

/// A decoded USB Kernel-PnP configuration event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelPnpEvent {
    /// `System/TimeCreated` in ISO-8601 UTC — the record's time.
    pub timestamp: String,
    /// The configuration Event ID (400 started / 410 migrated / 430 installed).
    pub event_id: u32,
    /// `EventData/DeviceInstanceId`, e.g. `USB\VID_0781&PID_5597\4C530000261130109435`.
    pub device_instance_id: String,
    /// `EventData/DriverName` when present (e.g. `usbstor.inf`) — context for the locator.
    pub driver_name: Option<String>,
}

/// Extract USB Kernel-PnP configuration events from an iterator of `evtx` record JSON values
/// (each the `{"Event": {…}}` object from `records_json_value()`). Keeps only
/// `Microsoft-Windows-Kernel-PnP` records with a configuration Event ID whose
/// `DeviceInstanceId` is a `USB\` / `USBSTOR\` device (internal ACPI/PCI/root-hub devices
/// are dropped).
pub fn kernel_pnp_events<I>(records: I) -> Vec<KernelPnpEvent>
where
    I: IntoIterator<Item = serde_json::Value>,
{
    records
        .into_iter()
        .filter_map(|r| kernel_pnp_event(&r))
        .collect()
}

/// Decode one `evtx` record; `None` unless it is a USB Kernel-PnP configuration event.
fn kernel_pnp_event(record: &serde_json::Value) -> Option<KernelPnpEvent> {
    let system = record.pointer("/Event/System")?;
    if system
        .pointer("/Provider/#attributes/Name")
        .and_then(serde_json::Value::as_str)
        != Some("Microsoft-Windows-Kernel-PnP")
    {
        return None;
    }
    let event_id = event_id(system)?;
    if !CONFIG_EVENT_IDS.contains(&event_id) {
        return None;
    }
    // `flatten_event_data` normalizes both EVTX EventData serialization shapes into a flat
    // field map — reused from winevt-extract, the crate that owns the evtx field decoding.
    let fields = winevt_extract::flatten_event_data(record);
    let device_instance_id = fields.get("DeviceInstanceId")?.clone();
    if !is_usb_instance(&device_instance_id) {
        return None;
    }
    let timestamp = system
        .pointer("/TimeCreated/#attributes/SystemTime")?
        .as_str()?
        .to_string();
    let driver_name = fields.get("DriverName").filter(|s| !s.is_empty()).cloned();
    Some(KernelPnpEvent {
        timestamp,
        event_id,
        device_instance_id,
        driver_name,
    })
}

/// Read `System/EventID`, tolerating both the bare-number and `{"#text": N, …}` shapes.
fn event_id(system: &serde_json::Value) -> Option<u32> {
    let raw = system.get("EventID")?;
    let n = raw
        .as_u64()
        .or_else(|| raw.get("#text").and_then(serde_json::Value::as_u64))?;
    u32::try_from(n).ok()
}

/// A `USB\` / `USBSTOR\` peripheral / mass-storage device instance id, excluding the host's
/// own root hubs (`USB\ROOT_HUB*`, the USB controllers — infrastructure that is always
/// present and carries no removable-media identity) and internal `ACPI\` / `PCI\` devices.
fn is_usb_instance(id: &str) -> bool {
    (id.starts_with("USB\\") || id.starts_with("USBSTOR\\")) && !id.starts_with("USB\\ROOT_HUB")
}

/// A [`HistorySource`] over decoded USB Kernel-PnP configuration events.
pub struct KernelPnpSource<'a> {
    events: &'a [KernelPnpEvent],
}

impl<'a> KernelPnpSource<'a> {
    /// Wrap decoded Kernel-PnP events (from [`kernel_pnp_events`]).
    #[must_use]
    pub fn new(events: &'a [KernelPnpEvent]) -> Self {
        Self { events }
    }
}

impl HistorySource for KernelPnpSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for event in self.events {
            // Key by the instance serial — the last '\'-separated component of the device
            // instance id — identical to how the registry / setupapi sources key, so a
            // Kernel-PnP event corroborates the registry record of the same device.
            let start = event.device_instance_id.rfind('\\').map_or(0, |i| i + 1);
            let serial = &event.device_instance_id[start..];
            if serial.is_empty() {
                continue; // no instance serial to key on
            }
            // A malformed timestamp is dropped, never turned into a bogus epoch.
            let Ok(when) = event.timestamp.parse::<jiff::Timestamp>() else {
                continue;
            };
            out.push(Claim {
                device: DeviceKey(serial.to_string()),
                attribute: Attribute::LastConnected,
                value: Value::Timestamp(when.as_second()),
                provenance: Provenance {
                    source: SourceKind::KernelPnp,
                    locator: format!(
                        "Microsoft-Windows-Kernel-PnP/Configuration#{} {}",
                        event.event_id, event.device_instance_id
                    ),
                },
            });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A Kernel-PnP configuration record as `evtx` serializes it (flat `EventData`).
    fn record(provider: &str, event_id: u32, instance: &str, when: &str) -> serde_json::Value {
        json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": provider } },
                    "EventID": event_id,
                    "TimeCreated": { "#attributes": { "SystemTime": when } }
                },
                "EventData": {
                    "DeviceInstanceId": instance,
                    "DriverName": "usbstor.inf"
                }
            }
        })
    }

    #[test]
    fn extracts_a_usb_configuration_event() {
        let rec = record(
            "Microsoft-Windows-Kernel-PnP",
            400,
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42.874132Z",
        );
        let events = kernel_pnp_events([rec]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 400);
        assert_eq!(
            events[0].device_instance_id,
            "USB\\VID_0781&PID_5597\\4C530000261130109435"
        );
        assert_eq!(events[0].timestamp, "2020-09-19T04:36:42.874132Z");
        assert_eq!(events[0].driver_name.as_deref(), Some("usbstor.inf"));
    }

    #[test]
    fn a_usbstor_disk_layer_event_is_extracted() {
        let rec = record(
            "Microsoft-Windows-Kernel-PnP",
            400,
            "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide_3.0&Rev_1.00\\4C530000261130109435&0",
            "2020-09-19T04:36:42.906239Z",
        );
        assert_eq!(kernel_pnp_events([rec]).len(), 1);
    }

    #[test]
    fn non_kernel_pnp_provider_is_ignored() {
        let rec = record(
            "Microsoft-Windows-Partition",
            400,
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42Z",
        );
        assert!(kernel_pnp_events([rec]).is_empty());
    }

    #[test]
    fn a_non_configuration_event_id_is_ignored() {
        let rec = record(
            "Microsoft-Windows-Kernel-PnP",
            420, // a problem/error event, not a configuration witness
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42Z",
        );
        assert!(kernel_pnp_events([rec]).is_empty());
    }

    #[test]
    fn an_internal_non_usb_device_is_ignored() {
        let rec = record(
            "Microsoft-Windows-Kernel-PnP",
            400,
            "ACPI\\PNP0A03\\0",
            "2020-09-19T04:36:42Z",
        );
        assert!(kernel_pnp_events([rec]).is_empty());
    }

    #[test]
    fn a_usb_root_hub_controller_is_ignored() {
        // The host's own USB root hubs are infrastructure, not removable devices.
        for id in [
            "USB\\ROOT_HUB\\5&3bb57b&0",
            "USB\\ROOT_HUB30\\5&d01e486&0&0",
        ] {
            let rec = record(
                "Microsoft-Windows-Kernel-PnP",
                400,
                id,
                "2020-09-19T04:36:42Z",
            );
            assert!(kernel_pnp_events([rec]).is_empty(), "{id} must be excluded");
        }
    }

    #[test]
    fn an_event_id_serialized_as_an_object_is_read() {
        // Some providers serialize EventID as {"#text": N, "#attributes": {...}}.
        let mut rec = record(
            "Microsoft-Windows-Kernel-PnP",
            0,
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42Z",
        );
        rec["Event"]["System"]["EventID"] =
            json!({ "#text": 410, "#attributes": { "Qualifiers": "0" } });
        let events = kernel_pnp_events([rec]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 410);
    }

    fn event(instance: &str, when: &str) -> KernelPnpEvent {
        KernelPnpEvent {
            timestamp: when.to_string(),
            event_id: 400,
            device_instance_id: instance.to_string(),
            driver_name: Some("usbstor.inf".to_string()),
        }
    }

    #[test]
    fn source_emits_last_connected_keyed_by_the_instance_serial() {
        let ev = event(
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42.874132Z",
        );
        let claims = KernelPnpSource::new(std::slice::from_ref(&ev)).claims();
        assert_eq!(claims.len(), 1);
        // Keyed by the last '\'-component — the same key the registry USBSTOR source uses.
        assert_eq!(
            claims[0].device,
            DeviceKey("4C530000261130109435".to_string())
        );
        assert_eq!(claims[0].attribute, Attribute::LastConnected);
        assert_eq!(claims[0].value, Value::Timestamp(1_600_490_202));
        assert_eq!(claims[0].provenance.source, SourceKind::KernelPnp);
        assert!(claims[0]
            .provenance
            .locator
            .contains("Microsoft-Windows-Kernel-PnP/Configuration#400"));
    }

    #[test]
    fn a_usbstor_event_keys_by_its_own_last_component() {
        let ev = event(
            "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer_Glide_3.0&Rev_1.00\\4C530000261130109435&0",
            "2020-09-19T04:36:42.906239Z",
        );
        let claims = KernelPnpSource::new(std::slice::from_ref(&ev)).claims();
        // The USBSTOR layer keys by `<serial>&0` — matching the registry USBSTOR Enum key.
        assert_eq!(
            claims[0].device,
            DeviceKey("4C530000261130109435&0".to_string())
        );
    }

    #[test]
    fn a_malformed_timestamp_yields_no_claim() {
        let ev = event("USB\\VID_0781&PID_5597\\SERIAL", "not-a-timestamp");
        assert!(KernelPnpSource::new(std::slice::from_ref(&ev))
            .claims()
            .is_empty());
    }

    #[test]
    fn an_instance_id_with_no_serial_component_yields_no_claim() {
        // A trailing backslash leaves an empty last component — nothing to key on.
        let ev = event("USB\\", "2020-09-19T04:36:42Z");
        assert!(KernelPnpSource::new(std::slice::from_ref(&ev))
            .claims()
            .is_empty());
    }
}
