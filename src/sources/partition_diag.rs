//! Adapter: `winevt-extract` [`PartitionDiagEvent`]s (Microsoft-Windows-Partition
//! EID 1006) → USB-history [`Claim`]s.
//!
//! The Partition/Diagnostic event log records a disk-arrival event each time the
//! partition manager scans a disk. Each record independently attests that a device —
//! identified by its serial number, or failing that its disk GUID — was connected at
//! the record's time. That is an **event-log** witness of a connection, a different
//! tamper surface from the registry/setupapi record of the same device, so when the two
//! agree the correlation core can grade it corroborated. A pure mapping over
//! already-decoded events; the reader crate did the `.evtx` parsing.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use winevt_extract::PartitionDiagEvent;

/// A [`HistorySource`] over decoded Partition/Diagnostic disk-arrival events.
pub struct PartitionDiagSource<'a> {
    events: &'a [PartitionDiagEvent],
}

impl<'a> PartitionDiagSource<'a> {
    /// Wrap decoded EID-1006 events (from `winevt_extract::partition_diag`).
    #[must_use]
    pub fn new(events: &'a [PartitionDiagEvent]) -> Self {
        Self { events }
    }
}

impl HistorySource for PartitionDiagSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for event in self.events {
            push_event(event, &mut out);
        }
        out
    }
}

/// The device identity a record keys on: the device serial when the provider recorded a
/// non-empty one, else the disk GUID. `None` when neither is present — there is no stable
/// identity to correlate on, so the record contributes nothing.
fn device_key(event: &PartitionDiagEvent) -> Option<DeviceKey> {
    event
        .serial_number
        .clone()
        .filter(|s| !s.is_empty())
        .or_else(|| event.disk_id.clone())
        .map(DeviceKey)
}

fn push_event(event: &PartitionDiagEvent, out: &mut Vec<Claim>) {
    let Some(device) = device_key(event) else {
        return;
    };
    let locator = format!(
        "Microsoft-Windows-Partition/Diagnostic#1006 DiskId={}",
        event.disk_id.as_deref().unwrap_or("?")
    );
    let claim = |device, attribute, value| Claim {
        device,
        attribute,
        value,
        provenance: Provenance {
            source: SourceKind::PartitionDiag,
            locator: locator.clone(),
        },
    };
    // The provider timestamp is ISO-8601 UTC; a malformed one is dropped, never turned
    // into a bogus epoch (a wrong time is worse than a missing one).
    if let Ok(when) = event.timestamp.parse::<jiff::Timestamp>() {
        out.push(claim(
            device.clone(),
            Attribute::LastConnected,
            Value::Timestamp(when.as_second()),
        ));
    }
    if let Some(serial) = volume_serial_string(event) {
        out.push(claim(device, Attribute::VolumeSerial, Value::Text(serial)));
    }
}

/// The device's volume serial as a matchable string. A FAT serial is rendered the way a
/// Shell Link records its `DriveSerialNumber` (`XXXX-XXXX`, the 4-byte join key) so it can
/// reconcile with LNK file-access on the same volume; an NTFS serial is rendered in its
/// distinct 8-byte form (`XXXXXXXX-XXXXXXXX`), which by construction cannot collide with a
/// 4-byte LNK serial. `None` when the VBR carried neither.
fn volume_serial_string(event: &PartitionDiagEvent) -> Option<String> {
    if let Some(fat) = event.fat_volume_serial {
        return Some(format!("{:04X}-{:04X}", fat >> 16, fat & 0xFFFF));
    }
    event.ntfs_volume_serial.map(|ntfs| {
        format!(
            "{:08X}-{:08X}",
            (ntfs >> 32) as u32,
            (ntfs & 0xFFFF_FFFF) as u32
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(serial: Option<&str>, disk_id: Option<&str>, ts: &str) -> PartitionDiagEvent {
        PartitionDiagEvent {
            timestamp: ts.to_string(),
            event_id: 1006,
            disk_number: Some(0),
            bus_type: Some(7),
            model: Some("Kingston DataTraveler".to_string()),
            serial_number: serial.map(str::to_owned),
            disk_id: disk_id.map(str::to_owned),
            capacity: Some(1_000_000_000),
            parent_id: Some("USB\\VID_0951&PID_1666\\SN123".to_string()),
            vbr0_hex: None,
            fat_volume_serial: None,
            ntfs_volume_serial: None,
        }
    }

    fn claims_for(e: PartitionDiagEvent) -> Vec<Claim> {
        let evs = [e];
        PartitionDiagSource::new(&evs).claims()
    }

    fn volume_serial_claim(claims: &[Claim]) -> Option<&Value> {
        claims
            .iter()
            .find(|c| c.attribute == Attribute::VolumeSerial)
            .map(|c| &c.value)
    }

    #[test]
    fn fat_volume_serial_is_rendered_as_the_lnk_join_key() {
        // A FAT 4-byte serial is formatted exactly as a Shell Link records it, so it can
        // reconcile with LNK file-access on the same volume.
        let mut e = event(Some("SN1"), None, "2020-01-01T00:00:00Z");
        e.fat_volume_serial = Some(0xDEAD_BEEF);
        let claims = claims_for(e);
        assert_eq!(
            volume_serial_claim(&claims),
            Some(&Value::Text("DEAD-BEEF".to_string()))
        );
    }

    #[test]
    fn ntfs_volume_serial_is_rendered_as_a_distinct_8_byte_form() {
        // The NTFS 8-byte serial must not collide with a 4-byte LNK serial → distinct form.
        let mut e = event(Some("SN2"), None, "2020-01-01T00:00:00Z");
        e.ntfs_volume_serial = Some(0x36B0_8F15_B08E_DAAF);
        let claims = claims_for(e);
        assert_eq!(
            volume_serial_claim(&claims),
            Some(&Value::Text("36B08F15-B08EDAAF".to_string()))
        );
    }

    #[test]
    fn no_volume_serial_emits_no_volume_serial_claim() {
        let claims = claims_for(event(Some("SN3"), None, "2020-01-01T00:00:00Z"));
        assert_eq!(volume_serial_claim(&claims), None);
    }

    #[test]
    fn serial_keyed_event_yields_last_connected() {
        let claims = claims_for(event(Some("SN123"), Some("{guid}"), "2020-01-01T00:00:00Z"));
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].device, DeviceKey("SN123".to_string()));
        assert_eq!(claims[0].attribute, Attribute::LastConnected);
        assert_eq!(claims[0].value, Value::Timestamp(1_577_836_800));
        assert_eq!(claims[0].provenance.source, SourceKind::PartitionDiag);
    }

    #[test]
    fn empty_serial_falls_back_to_disk_id() {
        // The real ATA sample logs an empty SerialNumber → key on the disk GUID.
        let claims = claims_for(event(Some(""), Some("DISK-GUID-1"), "2020-01-01T00:00:00Z"));
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].device, DeviceKey("DISK-GUID-1".to_string()));
    }

    #[test]
    fn missing_serial_falls_back_to_disk_id() {
        let claims = claims_for(event(None, Some("DISK-GUID-2"), "2020-01-01T00:00:00Z"));
        assert_eq!(claims[0].device, DeviceKey("DISK-GUID-2".to_string()));
    }

    #[test]
    fn no_identity_is_skipped() {
        // Neither a serial nor a disk GUID → nothing to correlate on.
        assert!(claims_for(event(Some(""), None, "2020-01-01T00:00:00Z")).is_empty());
    }

    #[test]
    fn unparseable_timestamp_is_skipped() {
        // A malformed TimeCreated must not panic and must not emit a bogus epoch.
        assert!(claims_for(event(Some("SN9"), None, "not-a-timestamp")).is_empty());
    }

    #[test]
    fn subsecond_iso8601_truncates_to_whole_seconds() {
        // The provider emits sub-second precision; the model is seconds-UTC.
        let claims = claims_for(event(Some("SN7"), None, "2020-08-01T21:47:55.7235131Z"));
        assert_eq!(claims[0].value, Value::Timestamp(1_596_318_475));
    }
}
