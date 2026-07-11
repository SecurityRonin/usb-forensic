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
        // A physical device asserts it *carries* an identity when its device key differs
        // from the value: a device's volume serial (vs the LNK pseudo-device whose key ==
        // value), or the drive letter it was mounted at (vs a VolumeInfoCache label whose
        // key IS the drive letter). Both feed the same identity → device map.
        let (Attribute::VolumeSerial | Attribute::DriveLetter, Value::Text(identity)) =
            (claim.attribute, &claim.value)
        else {
            continue;
        };
        if claim.device.0 != *identity {
            carriers
                .entry(identity.clone())
                .or_default()
                .insert(claim.device.0.clone());
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

/// Unify claims keyed by a drive letter or a volume GUID that name the **same volume**,
/// using the `MountedDevices` MBR bridge: volumes sharing a `(disk_signature,
/// partition_offset)` are one volume, so a drive-letter fact (a cached volume label) and a
/// volume-GUID fact (a per-user mount) collapse onto one canonical device key — the volume
/// GUID (the stable identity). Order-preserving; a drive letter with no bridged volume GUID
/// is left untouched.
#[must_use]
pub fn canonicalize_mounted_volumes(
    claims: &[Claim],
    volumes: &[peripheral_core::mounted_volumes::MountedVolume],
) -> Vec<Claim> {
    // Group volume identifiers by their disk (signature, offset); the volume GUID in each
    // group is the canonical key every member re-keys to.
    let mut names: BTreeMap<(u32, u64), Vec<String>> = BTreeMap::new();
    let mut canonical: BTreeMap<(u32, u64), String> = BTreeMap::new();
    for v in volumes {
        let key = (v.disk_signature, v.partition_offset);
        if let Some(letter) = v.drive_letter {
            names.entry(key).or_default().push(format!("{letter}:"));
        }
        if let Some(guid) = &v.volume_guid {
            names.entry(key).or_default().push(guid.clone());
            canonical.insert(key, guid.clone());
        }
        // The physical-device media identity: a device image keyed by its MBR disk
        // signature joins this group too, so imaging the stick attributes it to the
        // volume (and thus its label and per-user mount).
        names
            .entry(key)
            .or_default()
            .push(format!("disk-{:08X}", v.disk_signature));
    }
    // Build the identifier → canonical-key map (only for groups that have a volume GUID).
    let mut remap: BTreeMap<String, String> = BTreeMap::new();
    for (key, members) in &names {
        if let Some(canon) = canonical.get(key) {
            for member in members {
                remap.insert(member.clone(), canon.clone());
            }
        }
    }

    claims
        .iter()
        .map(|claim| {
            let mut out = claim.clone();
            if let Some(canon) = remap.get(&claim.device.0) {
                out.device = DeviceKey(canon.clone());
            }
            out
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Provenance, SourceKind};
    use peripheral_core::mounted_volumes::MountedVolume;
    use peripheral_core::Provenance as PcProvenance;

    fn mounted(letter: Option<char>, guid: Option<&str>, sig: u32, off: u64) -> MountedVolume {
        MountedVolume {
            drive_letter: letter,
            volume_guid: guid.map(str::to_owned),
            disk_signature: sig,
            partition_offset: off,
            source: PcProvenance {
                file: "SYSTEM".into(),
                line: 0,
                key_path: None,
            },
        }
    }

    fn text_claim(device: &str, attr: Attribute, val: &str, src: SourceKind) -> Claim {
        Claim {
            device: DeviceKey(device.into()),
            attribute: attr,
            value: Value::Text(val.into()),
            provenance: Provenance {
                source: src,
                locator: "x".into(),
            },
        }
    }

    #[test]
    fn drive_letter_and_volume_guid_facts_collapse_onto_the_volume_guid() {
        // MountedDevices MBR: E: and {vol} share disk sig 0xAB, offset 0x1000 → same volume.
        let volumes = [
            mounted(Some('E'), None, 0xAB, 0x1000),
            mounted(None, Some("{vol}"), 0xAB, 0x1000),
        ];
        let claims = vec![
            // A VolumeInfoCache label keyed by drive letter E:.
            text_claim(
                "E:",
                Attribute::VolumeName,
                "IAMAN",
                SourceKind::VolumeInfoCache,
            ),
            // A MountPoints2 mount keyed by the volume GUID.
            Claim {
                device: DeviceKey("{vol}".into()),
                attribute: Attribute::LastConnected,
                value: Value::Timestamp(1_427_230_953),
                provenance: Provenance {
                    source: SourceKind::MountPoints2,
                    locator: "m".into(),
                },
            },
        ];
        let out = canonicalize_mounted_volumes(&claims, &volumes);
        // Both now key on the canonical volume GUID → they correlate into one device.
        assert!(out.iter().all(|c| c.device == DeviceKey("{vol}".into())));
    }

    #[test]
    fn a_device_image_disk_signature_joins_the_bridged_volume() {
        // A device image (keyed by its MBR disk signature) and the volume GUID that
        // MountedDevices maps that disk signature to collapse onto one record — attributing
        // the physical stick to its host volume/label.
        let volumes = [mounted(None, Some("{vol}"), 0xE221_034C, 0x1000)];
        let claims = vec![
            // The device image's volume-serial fact, keyed by the disk-signature identity.
            text_claim(
                "disk-E221034C",
                Attribute::VolumeSerial,
                "B4D8-5399",
                SourceKind::DeviceImage,
            ),
            // A per-user mount keyed by the same volume GUID.
            Claim {
                device: DeviceKey("{vol}".into()),
                attribute: Attribute::LastConnected,
                value: Value::Timestamp(1),
                provenance: Provenance {
                    source: SourceKind::MountPoints2,
                    locator: "m".into(),
                },
            },
        ];
        let out = canonicalize_mounted_volumes(&claims, &volumes);
        assert!(out.iter().all(|c| c.device == DeviceKey("{vol}".into())));
    }

    #[test]
    fn a_drive_letter_without_a_bridged_volume_guid_is_left_untouched() {
        // Only a drive-letter MBR record (no volume GUID) → no canonical key.
        let volumes = [mounted(Some('E'), None, 0xAB, 0x1000)];
        let claims = vec![text_claim(
            "E:",
            Attribute::VolumeName,
            "IAMAN",
            SourceKind::VolumeInfoCache,
        )];
        let out = canonicalize_mounted_volumes(&claims, &volumes);
        assert_eq!(out[0].device, DeviceKey("E:".into()));
    }

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
