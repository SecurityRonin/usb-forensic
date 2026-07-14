//! Adapter: Microsoft-Windows-DriverFrameworks-UserMode/Operational event-log records →
//! USB-history [`Claim`]s.
//!
//! The DriverFrameworks-UserMode (UMDF) Operational log tracks the user-mode driver host's
//! view of a device's lifecycle. For a USB device the two forensically load-bearing records
//! are the *arrival* (EID 2003, `UMDFHostDeviceArrivalBegin`) and the *final removal*
//! (EID 2102, `UMDFHostDeviceRequest`), correlated by the device instance serial — the same
//! key the registry `Enum\{USB,USBSTOR}` and Kernel-PnP records use. So a DriverFrameworks
//! record is an **event-log** witness of a connect/disconnect at the record's time, on a
//! different tamper surface than the registry, and the correlation core grades agreement as
//! corroborated. A pure mapping over already-decoded event JSON; the `evtx` reader (in the
//! binary) does the `.evtx` parsing.
//!
//! Field structure per two independent authoritative maps — Eric Zimmerman's EvtxECmd map
//! (`.../DriverFrameworks-UserMode_2100.map`, InstanceId under `UserData/UMDFHostDeviceRequest`)
//! and IncideDigital rvt2 (`instance`/`lifetime` as attributes on the UserData child element).
//! Real logs use the *attribute* form; the element form is handled defensively. EID 2003/2102
//! chosen as the clean connect/disconnect pair (2100/2101 are intermediate power ops — noise).
//! The log is disabled by default on Win8+, so it is present only when an admin enabled it.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};

/// UMDF device *arrival* — the primary connection witness (hardware ids embedded inline).
const CONNECT_EVENT_ID: u32 = 2003;
/// UMDF device *final removal* — the disconnect witness.
const DISCONNECT_EVENT_ID: u32 = 2102;

/// A decoded USB DriverFrameworks arrival/removal event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverFrameworkEvent {
    /// `System/TimeCreated` in ISO-8601 UTC — the record's time.
    pub timestamp: String,
    /// The Event ID: 2003 (arrival/connect) or 2102 (final removal/disconnect).
    pub event_id: u32,
    /// The device instance id, e.g. `USB\VID_0781&PID_5597\4C530000261130109435`, from the
    /// UserData child's `instance` attribute (or `InstanceId` element).
    pub instance_id: String,
}

/// Extract USB DriverFrameworks arrival/removal events from an iterator of `evtx` record JSON
/// values (each the `{"Event": {…}}` object). Keeps only
/// `Microsoft-Windows-DriverFrameworks-UserMode` records with EID 2003 or 2102 whose instance
/// is a `USB\` / `USBSTOR\` device (root hubs and internal devices dropped).
pub fn driver_framework_events<I>(records: I) -> Vec<DriverFrameworkEvent>
where
    I: IntoIterator<Item = serde_json::Value>,
{
    records
        .into_iter()
        .filter_map(|r| driver_framework_event(&r))
        .collect()
}

/// Decode one `evtx` record; `None` unless it is a USB DriverFrameworks arrival/removal event.
fn driver_framework_event(record: &serde_json::Value) -> Option<DriverFrameworkEvent> {
    let system = record.pointer("/Event/System")?;
    if system
        .pointer("/Provider/#attributes/Name")
        .and_then(serde_json::Value::as_str)
        != Some("Microsoft-Windows-DriverFrameworks-UserMode")
    {
        return None;
    }
    let event_id = event_id(system)?;
    if event_id != CONNECT_EVENT_ID && event_id != DISCONNECT_EVENT_ID {
        return None;
    }
    let instance_id = instance_id(record)?;
    if !is_usb_instance(&instance_id) {
        return None;
    }
    let timestamp = system
        .pointer("/TimeCreated/#attributes/SystemTime")?
        .as_str()?
        .to_string();
    Some(DriverFrameworkEvent {
        timestamp,
        event_id,
        instance_id,
    })
}

/// The device instance id from the UserData child element. DriverFrameworks nests it under a
/// single child whose name varies by EID (`UMDFHostDeviceArrivalBegin` for 2003,
/// `UMDFHostDeviceRequest` for 2100–2102); rather than hard-code the name, take the first
/// child and read its `instance` attribute (real form) or `InstanceId` element (map form).
fn instance_id(record: &serde_json::Value) -> Option<String> {
    let _ = record; // RED stub — no extraction yet
    None
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
/// own root hubs and internal `ACPI\` / `PCI\` / `SWD\` devices. The `SWD\WPDBUSENUM\`
/// symbolic-link form (used by some UMDF records) is intentionally skipped — its serial is
/// embedded in a `#`-delimited compound with no reliable, corpus-validated split, so keying it
/// would risk a wrong device key; the same connect is witnessed by the clean `USB\` arrival.
fn is_usb_instance(id: &str) -> bool {
    (id.starts_with("USB\\") || id.starts_with("USBSTOR\\")) && !id.starts_with("USB\\ROOT_HUB")
}

/// A [`HistorySource`] over decoded USB DriverFrameworks events.
pub struct DriverFrameworkSource<'a> {
    events: &'a [DriverFrameworkEvent],
}

impl<'a> DriverFrameworkSource<'a> {
    /// Wrap decoded DriverFrameworks events (from [`driver_framework_events`]).
    #[must_use]
    pub fn new(events: &'a [DriverFrameworkEvent]) -> Self {
        Self { events }
    }
}

impl HistorySource for DriverFrameworkSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let _ = &self.events; // RED stub — no claim mapping yet
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A DriverFrameworks record as `evtx` serializes it: UserData with a single child element
    /// (`root`) carrying `instance`/`lifetime` attributes.
    fn record(
        provider: &str,
        event_id: u32,
        root: &str,
        instance: &str,
        when: &str,
    ) -> serde_json::Value {
        json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": provider } },
                    "EventID": event_id,
                    "TimeCreated": { "#attributes": { "SystemTime": when } }
                },
                "UserData": {
                    root: {
                        "#attributes": {
                            "instance": instance,
                            "lifetime": "{6c1e8fd0-0000-0000-0000-000000000000}"
                        }
                    }
                }
            }
        })
    }

    #[test]
    fn extracts_a_2003_arrival_event() {
        let rec = record(
            "Microsoft-Windows-DriverFrameworks-UserMode",
            2003,
            "UMDFHostDeviceArrivalBegin",
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42.874132Z",
        );
        let events = driver_framework_events([rec]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 2003);
        assert_eq!(
            events[0].instance_id,
            "USB\\VID_0781&PID_5597\\4C530000261130109435"
        );
        assert_eq!(events[0].timestamp, "2020-09-19T04:36:42.874132Z");
    }

    #[test]
    fn extracts_a_2102_removal_event() {
        let rec = record(
            "Microsoft-Windows-DriverFrameworks-UserMode",
            2102,
            "UMDFHostDeviceRequest",
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T05:10:00Z",
        );
        let events = driver_framework_events([rec]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 2102);
    }

    #[test]
    fn reads_the_instanceid_element_form() {
        // EvtxECmd's map documents an `<InstanceId>` child-element variant; handle it too.
        let rec = json!({
            "Event": {
                "System": {
                    "Provider": { "#attributes": { "Name": "Microsoft-Windows-DriverFrameworks-UserMode" } },
                    "EventID": 2003,
                    "TimeCreated": { "#attributes": { "SystemTime": "2020-09-19T04:36:42Z" } }
                },
                "UserData": {
                    "UMDFHostDeviceArrivalBegin": {
                        "InstanceId": "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C530000261130109435&0",
                        "LifetimeId": "{guid}"
                    }
                }
            }
        });
        let events = driver_framework_events([rec]);
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].instance_id,
            "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C530000261130109435&0"
        );
    }

    #[test]
    fn non_driver_framework_provider_is_ignored() {
        let rec = record(
            "Microsoft-Windows-Kernel-PnP",
            2003,
            "UMDFHostDeviceArrivalBegin",
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42Z",
        );
        assert!(driver_framework_events([rec]).is_empty());
    }

    #[test]
    fn an_intermediate_power_event_id_is_ignored() {
        // 2100/2101 are intermediate PnP/power operations — noise, not a connect/disconnect.
        let rec = record(
            "Microsoft-Windows-DriverFrameworks-UserMode",
            2100,
            "UMDFHostDeviceRequest",
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42Z",
        );
        assert!(driver_framework_events([rec]).is_empty());
    }

    #[test]
    fn an_internal_non_usb_device_is_ignored() {
        let rec = record(
            "Microsoft-Windows-DriverFrameworks-UserMode",
            2003,
            "UMDFHostDeviceArrivalBegin",
            "ACPI\\PNP0A03\\0",
            "2020-09-19T04:36:42Z",
        );
        assert!(driver_framework_events([rec]).is_empty());
    }

    #[test]
    fn a_wpdbusenum_symbolic_link_instance_is_skipped() {
        // The SWD\WPDBUSENUM\ symbolic-link form embeds the serial in a #-compound with no
        // corpus-validated split; skip it rather than risk a wrong device key.
        let rec = record(
            "Microsoft-Windows-DriverFrameworks-UserMode",
            2100,
            "UMDFHostDeviceRequest",
            "SWD\\WPDBUSENUM\\_??_USBSTOR#DISK&VEN_SANDISK#4C53...&0#{guid}",
            "2020-09-19T04:36:42Z",
        );
        assert!(driver_framework_events([rec]).is_empty());
    }

    #[test]
    fn a_usb_root_hub_controller_is_ignored() {
        let rec = record(
            "Microsoft-Windows-DriverFrameworks-UserMode",
            2003,
            "UMDFHostDeviceArrivalBegin",
            "USB\\ROOT_HUB30\\5&d01e486&0&0",
            "2020-09-19T04:36:42Z",
        );
        assert!(driver_framework_events([rec]).is_empty());
    }

    #[test]
    fn an_event_id_serialized_as_an_object_is_read() {
        let mut rec = record(
            "Microsoft-Windows-DriverFrameworks-UserMode",
            0,
            "UMDFHostDeviceArrivalBegin",
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42Z",
        );
        rec["Event"]["System"]["EventID"] =
            json!({ "#text": 2003, "#attributes": { "Qualifiers": "0" } });
        let events = driver_framework_events([rec]);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, 2003);
    }

    fn event(event_id: u32, instance: &str, when: &str) -> DriverFrameworkEvent {
        DriverFrameworkEvent {
            timestamp: when.to_string(),
            event_id,
            instance_id: instance.to_string(),
        }
    }

    #[test]
    fn arrival_emits_last_connected_keyed_by_serial() {
        let ev = event(
            2003,
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T04:36:42.874132Z",
        );
        let claims = DriverFrameworkSource::new(std::slice::from_ref(&ev)).claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(
            claims[0].device,
            DeviceKey("4C530000261130109435".to_string())
        );
        assert_eq!(claims[0].attribute, Attribute::LastConnected);
        assert_eq!(claims[0].value, Value::Timestamp(1_600_490_202));
        assert_eq!(claims[0].provenance.source, SourceKind::DriverFramework);
        assert!(claims[0]
            .provenance
            .locator
            .contains("DriverFrameworks-UserMode/Operational#2003"));
    }

    #[test]
    fn removal_emits_last_removed() {
        let ev = event(
            2102,
            "USB\\VID_0781&PID_5597\\4C530000261130109435",
            "2020-09-19T05:10:00Z",
        );
        let claims = DriverFrameworkSource::new(std::slice::from_ref(&ev)).claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].attribute, Attribute::LastRemoved);
    }

    #[test]
    fn a_usbstor_instance_keys_by_its_own_last_component() {
        let ev = event(
            2003,
            "USBSTOR\\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.00\\4C530000261130109435&0",
            "2020-09-19T04:36:42Z",
        );
        let claims = DriverFrameworkSource::new(std::slice::from_ref(&ev)).claims();
        assert_eq!(
            claims[0].device,
            DeviceKey("4C530000261130109435&0".to_string())
        );
    }

    #[test]
    fn a_malformed_timestamp_yields_no_claim() {
        let ev = event(2003, "USB\\VID_0781&PID_5597\\SERIAL", "not-a-timestamp");
        assert!(DriverFrameworkSource::new(std::slice::from_ref(&ev))
            .claims()
            .is_empty());
    }

    #[test]
    fn an_instance_id_with_no_serial_component_yields_no_claim() {
        let ev = event(2003, "USB\\", "2020-09-19T04:36:42Z");
        assert!(DriverFrameworkSource::new(std::slice::from_ref(&ev))
            .claims()
            .is_empty());
    }

    #[test]
    fn source_kind_lives_in_the_event_log_container() {
        assert_eq!(
            SourceKind::DriverFramework.container(),
            crate::ArtifactContainer::EventLog
        );
        assert!(!SourceKind::DriverFramework.clock_is_local());
    }
}
