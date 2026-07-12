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
    let _ = records; // RED stub
    Vec::new()
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
        Vec::new() // RED stub
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
