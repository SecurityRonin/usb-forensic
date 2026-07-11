//! Adapter: `peripheral-core` [`EmdVolume`]s (Windows `EMDMgmt` `ReadyBoost` cache) →
//! USB-history [`Claim`]s.
//!
//! `EMDMgmt` caches, per volume, its label and 4-byte volume serial. The serial is the
//! value a Shell Link's `DriveSerialNumber` stores, so keying the label and the serial by
//! that serial lets a `.lnk` file-access (keyed by the same serial) reconcile onto the
//! named volume — attributing "files opened" to a volume by *name*, even after the device
//! is gone. A pure mapping over already-decoded records.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use peripheral_core::emdmgmt::EmdVolume;

/// A [`HistorySource`] over decoded [`EmdVolume`]s.
pub struct EmdMgmtSource<'a> {
    volumes: &'a [EmdVolume],
}

impl<'a> EmdMgmtSource<'a> {
    /// Wrap decoded `EMDMgmt` volumes (from `peripheral_core::emdmgmt::parse_emdmgmt`).
    #[must_use]
    pub fn new(volumes: &'a [EmdVolume]) -> Self {
        Self { volumes }
    }
}

/// Render a 4-byte volume serial as `dir`/`vol` show it (`XXXX-XXXX`, upper hex), the same
/// canonical form the LNK adapter uses, so the same serial from either source matches.
fn format_volume_serial(serial: u32) -> String {
    format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF)
}

impl HistorySource for EmdMgmtSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for vol in self.volumes {
            let serial = format_volume_serial(vol.volume_serial);
            let device = DeviceKey(serial.clone());
            let locator = vol
                .source
                .key_path
                .clone()
                .unwrap_or_else(|| vol.source.file.clone());
            // The volume serial, surfaced as the matchable join key.
            out.push(Claim {
                device: device.clone(),
                attribute: Attribute::VolumeSerial,
                value: Value::Text(serial),
                provenance: Provenance {
                    source: SourceKind::EmdMgmt,
                    locator: locator.clone(),
                },
            });
            // The label, when the volume had one (an unlabelled volume still has a serial).
            if !vol.volume_label.is_empty() {
                out.push(Claim {
                    device,
                    attribute: Attribute::VolumeName,
                    value: Value::Text(vol.volume_label.clone()),
                    provenance: Provenance {
                        source: SourceKind::EmdMgmt,
                        locator,
                    },
                });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peripheral_core::Provenance as PcProvenance;

    fn vol(label: &str, serial: u32) -> EmdVolume {
        EmdVolume {
            volume_label: label.to_string(),
            volume_serial: serial,
            source: PcProvenance {
                file: "SOFTWARE".to_string(),
                line: 0,
                key_path: Some("…\\EMDMgmt\\x".to_string()),
            },
        }
    }

    #[test]
    fn labelled_volume_yields_serial_and_name_claims_keyed_by_serial() {
        // 0x5C754D3E = 5C75-4D3E (CFReDS "Authorized USB").
        let vols = [vol("Authorized USB", 0x5C75_4D3E)];
        let claims = EmdMgmtSource::new(&vols).claims();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[0].device, DeviceKey("5C75-4D3E".to_string()));
        assert_eq!(claims[0].attribute, Attribute::VolumeSerial);
        assert_eq!(claims[0].value, Value::Text("5C75-4D3E".to_string()));
        assert_eq!(claims[1].attribute, Attribute::VolumeName);
        assert_eq!(claims[1].value, Value::Text("Authorized USB".to_string()));
        assert_eq!(claims[1].provenance.source, SourceKind::EmdMgmt);
    }

    #[test]
    fn unlabelled_volume_yields_only_the_serial_claim() {
        let vols = [vol("", 1)];
        let claims = EmdMgmtSource::new(&vols).claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].attribute, Attribute::VolumeSerial);
        assert_eq!(claims[0].value, Value::Text("0000-0001".to_string()));
    }

    #[test]
    fn locator_falls_back_to_the_file_without_a_key_path() {
        let mut v = vol("X", 2);
        v.source.key_path = None;
        let vols = [v];
        let claims = EmdMgmtSource::new(&vols).claims();
        assert_eq!(claims[0].provenance.locator, "SOFTWARE");
    }
}
