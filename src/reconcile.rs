//! Volume-serial reconciliation: attribute volume-keyed claims (LNK/jump-list file
//! access) to the physical device that carries that volume — the file-to-device link.
//!
//! An LNK or jump list records a file access against a **volume** serial, not a device,
//! so its claims are keyed by a volume-serial pseudo-identity. A device source (registry
//! `MountedDevices`, Partition/Diagnostic VBR) records that a **physical device** carries
//! a given volume serial. This pass joins the two: when exactly one physical device
//! reports a volume serial `V`, every claim keyed by the pseudo-identity `V` is re-keyed
//! to that device, so the file access lands on the real device and correlates with its
//! connection history. Ambiguous serials (reported by two devices) and unmatched serials
//! are left untouched — the pass never guesses an attribution.
//!
//! This is a reconciliation **rule**; its correctness is defined by the rule itself, not
//! by any external value, so it is specified and tested directly.

use crate::model::{Attribute, Claim, DeviceKey, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Re-key volume-pseudo-device claims to the unique physical device that carries the
/// volume. See the module docs for the rule. Order-preserving; leaves ambiguous and
/// unmatched claims unchanged.
#[must_use]
pub fn reconcile_volume_serials(claims: &[Claim]) -> Vec<Claim> {
    // Map each volume serial to the physical device(s) that reported carrying it. A claim
    // is a *physical* assertion when its device key differs from the serial value; an LNK
    // pseudo-device's own serial (key == value) is not an assertion of ownership.
    let mut carriers: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for claim in claims {
        if claim.attribute == Attribute::VolumeSerial {
            if let Value::Text(serial) = &claim.value {
                if claim.device.0 != *serial {
                    carriers
                        .entry(serial.clone())
                        .or_default()
                        .insert(claim.device.0.clone());
                }
            }
        }
    }

    claims
        .iter()
        .map(|claim| {
            let mut out = claim.clone();
            // Re-key only when the device key is a volume serial carried by exactly one
            // physical device — never guess an ambiguous attribution.
            if let Some(devices) = carriers.get(&claim.device.0) {
                if let (1, Some(device)) = (devices.len(), devices.iter().next()) {
                    out.device = DeviceKey(device.clone());
                }
            }
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Provenance, SourceKind};

    fn vol_serial(device: &str, serial: &str, src: SourceKind) -> Claim {
        Claim {
            device: DeviceKey(device.into()),
            attribute: Attribute::VolumeSerial,
            value: Value::Text(serial.into()),
            provenance: Provenance {
                source: src,
                locator: "x".into(),
            },
        }
    }

    fn accessed(device: &str, path: &str) -> Claim {
        Claim {
            device: DeviceKey(device.into()),
            attribute: Attribute::AccessedFile,
            value: Value::Text(path.into()),
            provenance: Provenance {
                source: SourceKind::Lnk,
                locator: "y".into(),
            },
        }
    }

    fn device_of(out: &[Claim], attr: Attribute, src: SourceKind) -> &DeviceKey {
        &out.iter()
            .find(|c| c.attribute == attr && c.provenance.source == src)
            .expect("claim present")
            .device
    }

    #[test]
    fn file_access_is_reattributed_to_the_device_carrying_the_volume() {
        let claims = vec![
            // A physical device reports volume serial DEAD-BEEF (device key != serial).
            vol_serial("USBSTOR-DEV-1", "DEAD-BEEF", SourceKind::PartitionDiag),
            // The LNK volume-pseudo-device DEAD-BEEF: its own serial (key == value) and a
            // file accessed from that volume.
            vol_serial("DEAD-BEEF", "DEAD-BEEF", SourceKind::Lnk),
            accessed("DEAD-BEEF", "E:\\secret.docx"),
        ];
        let out = reconcile_volume_serials(&claims);
        let dev = DeviceKey("USBSTOR-DEV-1".into());
        // The file access and the LNK self-serial now key on the physical device …
        assert_eq!(
            *device_of(&out, Attribute::AccessedFile, SourceKind::Lnk),
            dev
        );
        assert_eq!(
            *device_of(&out, Attribute::VolumeSerial, SourceKind::Lnk),
            dev
        );
        // … and the physical device's own claim is unchanged.
        assert_eq!(
            *device_of(&out, Attribute::VolumeSerial, SourceKind::PartitionDiag),
            dev
        );
    }

    #[test]
    fn ambiguous_volume_serial_is_left_untouched() {
        // Two physical devices claim the same volume serial — cannot disambiguate.
        let claims = vec![
            vol_serial("DEV-A", "AAAA-BBBB", SourceKind::PartitionDiag),
            vol_serial("DEV-B", "AAAA-BBBB", SourceKind::Usbstor),
            accessed("AAAA-BBBB", "E:\\f.txt"),
        ];
        let out = reconcile_volume_serials(&claims);
        assert_eq!(
            *device_of(&out, Attribute::AccessedFile, SourceKind::Lnk),
            DeviceKey("AAAA-BBBB".into())
        );
    }

    #[test]
    fn unmatched_volume_serial_is_left_untouched() {
        let claims = vec![accessed("NO-MATCH", "E:\\f.txt")];
        let out = reconcile_volume_serials(&claims);
        assert_eq!(out[0].device, DeviceKey("NO-MATCH".into()));
    }

    fn drive_letter(device: &str, letter: &str, src: SourceKind) -> Claim {
        Claim {
            device: DeviceKey(device.into()),
            attribute: Attribute::DriveLetter,
            value: Value::Text(letter.into()),
            provenance: Provenance {
                source: src,
                locator: "d".into(),
            },
        }
    }

    fn volume_name(device: &str, name: &str) -> Claim {
        Claim {
            device: DeviceKey(device.into()),
            attribute: Attribute::VolumeName,
            value: Value::Text(name.into()),
            provenance: Provenance {
                source: SourceKind::VolumeInfoCache,
                locator: "v".into(),
            },
        }
    }

    #[test]
    fn volume_label_is_reattributed_to_the_device_mounted_at_that_drive_letter() {
        // A device (keyed by serial) mounted at E: (a DriveLetter claim), and a
        // VolumeInfoCache label keyed by the drive-letter pseudo-device "E:". The label
        // should re-key onto the physical device.
        let claims = vec![
            drive_letter("USBSTOR-DEV-1", "E:", SourceKind::Usbstor),
            volume_name("E:", "Authorized USB"),
        ];
        let out = reconcile_volume_serials(&claims);
        assert_eq!(
            *device_of(&out, Attribute::VolumeName, SourceKind::VolumeInfoCache),
            DeviceKey("USBSTOR-DEV-1".into())
        );
    }

    #[test]
    fn ambiguous_drive_letter_label_is_left_untouched() {
        // Two devices both report drive E: — can't disambiguate, so the label stays.
        let claims = vec![
            drive_letter("DEV-A", "E:", SourceKind::Usbstor),
            drive_letter("DEV-B", "E:", SourceKind::PartitionDiag),
            volume_name("E:", "Authorized USB"),
        ];
        let out = reconcile_volume_serials(&claims);
        assert_eq!(
            *device_of(&out, Attribute::VolumeName, SourceKind::VolumeInfoCache),
            DeviceKey("E:".into())
        );
    }

    #[test]
    fn non_text_volume_serial_cannot_seed_the_map() {
        // A VolumeSerial claim whose value is not text can't map a serial → device, so a
        // device whose key isn't a real volume serial is never re-keyed.
        let claims = vec![
            Claim {
                device: DeviceKey("DEV".into()),
                attribute: Attribute::VolumeSerial,
                value: Value::Timestamp(5),
                provenance: Provenance {
                    source: SourceKind::Usbstor,
                    locator: "x".into(),
                },
            },
            accessed("DEV", "E:\\f.txt"),
        ];
        let out = reconcile_volume_serials(&claims);
        assert_eq!(out[1].device, DeviceKey("DEV".into()));
    }
}
