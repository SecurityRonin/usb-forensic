//! Adapter: `peripheral-core` [`DeviceConnection`]s → USB-history [`Claim`]s.
//!
//! `peripheral-core` is the device-connection domain reader: today it decodes
//! `setupapi.dev.log` (first-install times); with its 0.2 registry module it also
//! decodes USBSTOR/SCSI/USB device instances (first/last connect + last removal). This
//! adapter maps either into `Claim`s keyed by the device serial, so both flow into the
//! same correlation engine. A pure mapping over already-decoded records.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use peripheral_core::DeviceConnection;

/// A [`HistorySource`] over decoded [`DeviceConnection`]s from one origin.
///
/// A single `peripheral-core` parse call handles one origin at a time —
/// `parse_setupapi`, `parse_registry`, or `parse_linux_syslog` — so the caller
/// knows which [`SourceKind`] every connection in the batch came from and passes
/// it in. The adapter carries that verbatim onto each [`Claim`]'s provenance,
/// which is what drives the container / clock-locality reasoning downstream.
pub struct PeripheralSource<'a> {
    conns: &'a [DeviceConnection],
    source: SourceKind,
}

impl<'a> PeripheralSource<'a> {
    /// Wrap decoded device connections, all from `source` (e.g.
    /// [`SourceKind::SetupApi`], [`SourceKind::Usbstor`] for the registry reader,
    /// or [`SourceKind::LinuxKernelLog`]).
    #[must_use]
    pub fn new(conns: &'a [DeviceConnection], source: SourceKind) -> Self {
        Self { conns, source }
    }
}

impl HistorySource for PeripheralSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for conn in self.conns {
            push_conn(conn, self.source, &mut out);
        }
        out
    }
}

fn push_conn(conn: &DeviceConnection, source: SourceKind, out: &mut Vec<Claim>) {
    // Key by the instance serial so setupapi and the registry reader (which keys by the
    // bare instance name) agree on the same device: the explicit `device_serial` when
    // present, else the last `\`-separated component of the instance id.
    let device = DeviceKey(if let Some(serial) = &conn.device_serial {
        serial.clone()
    } else {
        let id = &conn.device_instance_id;
        let start = id.rfind('\\').map_or(0, |i| i + 1);
        id[start..].to_string()
    });
    // Line-oriented sources (setupapi/syslog) locate by file:line; a registry
    // connection carries the full key path instead (line is 0), so prefer it.
    let locator = conn
        .source
        .key_path
        .clone()
        .unwrap_or_else(|| format!("{}:{}", conn.source.file, conn.source.line));
    let claim = |attribute, value: i64| Claim {
        device: device.clone(),
        attribute,
        value: Value::Timestamp(value),
        provenance: Provenance {
            source,
            locator: locator.clone(),
        },
    };
    if let Some(s) = &conn.first_install {
        out.push(claim(Attribute::FirstConnected, s.value));
    }
    if let Some(s) = &conn.last_arrival {
        out.push(claim(Attribute::LastConnected, s.value));
    }
    if let Some(s) = &conn.last_removal {
        out.push(claim(Attribute::LastRemoved, s.value));
    }
    if let Some(letter) = conn.drive_letter {
        out.push(Claim {
            device: device.clone(),
            attribute: Attribute::DriveLetter,
            value: Value::Text(format!("{letter}:")),
            provenance: Provenance {
                source,
                locator: locator.clone(),
            },
        });
    }
    // Surface an MTP/PTP portable device (phone/tablet/camera) — a data-exfil endpoint that
    // never appears under USBSTOR; peripheral-core classified it from its WUDFWpdMtp service.
    if conn.bus == peripheral_core::Bus::Mtp {
        out.push(Claim {
            device,
            attribute: Attribute::DeviceClass,
            value: Value::Text("MTP".to_string()),
            provenance: Provenance { source, locator },
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peripheral_core::setupapi::parse_setupapi;
    use peripheral_core::Stamp;

    const USBSTOR_HEADER: &str = "[Device Install (Hardware initiated) - \
        USBSTOR\\Disk&Ven_Generic&Prod_Flash\\7&1c2c4f0a&0 2024/01/02 03:04:05.000]";

    #[test]
    fn setupapi_connection_yields_first_connected_claim() {
        let conns = parse_setupapi(USBSTOR_HEADER, "setupapi.dev.log");
        assert_eq!(conns.len(), 1);
        let claims = PeripheralSource::new(&conns, SourceKind::SetupApi).claims();
        let fc = claims
            .iter()
            .find(|c| c.attribute == Attribute::FirstConnected)
            .expect("first-connected claim");
        // keyed by the last instance-id component (the instance serial).
        assert_eq!(fc.device, DeviceKey("7&1c2c4f0a&0".to_string()));
        assert_eq!(fc.provenance.source, SourceKind::SetupApi);
        // A line-oriented source (no key_path) locates by file:line.
        assert_eq!(fc.provenance.locator, "setupapi.dev.log:1");
        assert!(matches!(fc.value, Value::Timestamp(_)));
    }

    #[test]
    fn source_kind_is_taken_from_the_caller() {
        // The bin knows each connection's origin (setupapi vs registry vs Linux) and
        // stamps it; the adapter faithfully carries whatever SourceKind it is given.
        let conns = parse_setupapi(USBSTOR_HEADER, "syslog");
        let claims = PeripheralSource::new(&conns, SourceKind::LinuxKernelLog).claims();
        assert!(!claims.is_empty());
        assert!(claims
            .iter()
            .all(|c| c.provenance.source == SourceKind::LinuxKernelLog));
    }

    #[test]
    fn registry_key_path_is_used_as_the_locator() {
        // A registry-sourced connection is not line-oriented (line 0) — its locator is
        // the full key path, so provenance points at the exact hive key.
        let mut conn = parse_setupapi(USBSTOR_HEADER, "SYSTEM")
            .pop()
            .expect("one conn");
        let key = "ControlSet001\\Enum\\USBSTOR\\Disk&Ven_Generic&Prod_Flash\\7&1c2c4f0a&0";
        conn.source.key_path = Some(key.to_string());
        conn.source.line = 0;
        let conns = [conn];
        let claims = PeripheralSource::new(&conns, SourceKind::Usbstor).claims();
        assert_eq!(claims[0].provenance.source, SourceKind::Usbstor);
        assert_eq!(claims[0].provenance.locator, key);
    }

    #[test]
    fn drive_letter_yields_a_drive_letter_claim() {
        // peripheral-core 0.3's MountedDevices join sets `drive_letter`; the adapter
        // surfaces it as a `DriveLetter` claim keyed by the same device, so the
        // correlated record shows the mount (e.g. `E:`).
        let mut conn = parse_setupapi(USBSTOR_HEADER, "SYSTEM")
            .pop()
            .expect("one conn");
        conn.drive_letter = Some('E');
        let conns = [conn];
        let claims = PeripheralSource::new(&conns, SourceKind::Usbstor).claims();
        let dl = claims
            .iter()
            .find(|c| c.attribute == Attribute::DriveLetter)
            .expect("drive-letter claim");
        assert_eq!(dl.value, Value::Text("E:".to_string()));
        assert_eq!(dl.device, DeviceKey("7&1c2c4f0a&0".to_string()));
        assert_eq!(dl.provenance.source, SourceKind::Usbstor);
    }

    #[test]
    fn explicit_device_serial_is_used_as_the_key() {
        let mut conn = parse_setupapi(USBSTOR_HEADER, "f").pop().expect("one conn");
        conn.device_serial = Some("AA11BB22".to_string());
        let conns = [conn];
        let claims = PeripheralSource::new(&conns, SourceKind::SetupApi).claims();
        assert_eq!(claims[0].device, DeviceKey("AA11BB22".to_string()));
    }

    #[test]
    fn arrival_and_removal_stamps_yield_last_connected_and_removed() {
        let mut conn = parse_setupapi(USBSTOR_HEADER, "f").pop().expect("one conn");
        conn.last_arrival = Some(Stamp::inferred(1_700_000_500));
        conn.last_removal = Some(Stamp::inferred(1_700_000_900));
        let conns = [conn];
        let claims = PeripheralSource::new(&conns, SourceKind::SetupApi).claims();
        assert_eq!(
            claims
                .iter()
                .find(|c| c.attribute == Attribute::LastConnected)
                .map(|c| &c.value),
            Some(&Value::Timestamp(1_700_000_500))
        );
        assert_eq!(
            claims
                .iter()
                .find(|c| c.attribute == Attribute::LastRemoved)
                .map(|c| &c.value),
            Some(&Value::Timestamp(1_700_000_900))
        );
    }

    #[test]
    fn an_mtp_bus_device_emits_a_device_class_claim() {
        let mut conn = parse_setupapi(USBSTOR_HEADER, "f").pop().expect("one conn");
        conn.bus = peripheral_core::Bus::Mtp;
        let conns = [conn];
        let claims = PeripheralSource::new(&conns, SourceKind::Usbstor).claims();
        let dc = claims
            .iter()
            .find(|c| c.attribute == Attribute::DeviceClass)
            .expect("device-class claim");
        assert_eq!(dc.value, Value::Text("MTP".to_string()));
    }

    #[test]
    fn a_non_mtp_bus_device_emits_no_device_class_claim() {
        let conns = parse_setupapi(USBSTOR_HEADER, "f"); // bus classified as Usb
        let claims = PeripheralSource::new(&conns, SourceKind::Usbstor).claims();
        assert!(!claims.iter().any(|c| c.attribute == Attribute::DeviceClass));
    }

    #[test]
    fn separatorless_instance_id_is_used_whole() {
        // No `\` in the instance id → the whole string is the key (rfind → None branch).
        let mut conn = parse_setupapi(USBSTOR_HEADER, "f").pop().expect("one conn");
        conn.device_serial = None;
        conn.device_instance_id = "BAREINSTANCE".to_string();
        let conns = [conn];
        let claims = PeripheralSource::new(&conns, SourceKind::SetupApi).claims();
        assert_eq!(claims[0].device, DeviceKey("BAREINSTANCE".to_string()));
    }
}
