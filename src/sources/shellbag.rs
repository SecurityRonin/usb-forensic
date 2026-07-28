//! Adapter: `peripheral-core` [`ShellbagEntry`]s (`BagMRU` ShellBags) → USB-history
//! [`Claim`]s (the drive-letter browsed-folder join).
//!
//! A ShellBags `BagMRU` node records that a user browsed a folder in Explorer. When
//! that folder lived on a **drive letter** (`E:\...`), it is per-user evidence that a
//! volume was mounted at `E:` and that a directory on it was opened — but a shellbag,
//! like an LNK, names a **drive letter / volume**, not a device. So this adapter emits
//! join material keyed by the **drive-letter pseudo-device** (`E:`), exactly as the
//! `VolumeInfoCache` label adapter does:
//!
//! - a [`Attribute::DriveLetter`] claim carrying the drive letter (so it is discoverable
//!   and matchable), and
//! - a [`Attribute::BrowsedFolder`] claim carrying the browsed path,
//!
//! both keyed by [`DeviceKey`]`("E:")`. [`reconcile_volume_serials`] then re-keys the
//! pseudo-device onto the physical device that a registry source (`MountedDevices` /
//! USBSTOR) reports was mounted at `E:`, so the browsed folder lands on the real device
//! and corroborates its connection history.
//!
//! [`reconcile_volume_serials`]: crate::reconcile_volume_serials
//!
//! This is a pure mapping over [`ShellbagEntry`] values the reader has already decoded;
//! it never touches raw bytes. Mirrors [`LnkSource`](crate::LnkSource).

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use peripheral_core::shellbag::ShellbagEntry;

/// A [`HistorySource`] over decoded [`ShellbagEntry`]s.
pub struct ShellbagSource<'a> {
    entries: &'a [ShellbagEntry],
}

impl<'a> ShellbagSource<'a> {
    /// Wrap decoded shellbag entries (from `peripheral_core::shellbag::parse_shellbags`).
    #[must_use]
    pub fn new(entries: &'a [ShellbagEntry]) -> Self {
        Self { entries }
    }
}

impl HistorySource for ShellbagSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        // Stubbed for the RED phase.
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peripheral_core::Provenance as PcProvenance;

    fn entry(path: &str, drive: Option<char>, key_path: Option<&str>) -> ShellbagEntry {
        ShellbagEntry {
            path: path.to_string(),
            drive_letter: drive,
            last_write: Some(1_600_000_000),
            source: PcProvenance {
                file: "NTUSER.DAT".to_string(),
                line: 0,
                key_path: key_path.map(ToString::to_string),
            },
        }
    }

    fn claims_for(entries: &[ShellbagEntry]) -> Vec<Claim> {
        ShellbagSource::new(entries).claims()
    }

    #[test]
    fn drive_letter_entry_yields_drive_letter_and_browsed_folder() {
        let entries = [entry(
            "My Computer\\E:\\\\photos",
            Some('E'),
            Some("Software\\Microsoft\\Windows\\Shell\\BagMRU\\0\\0\\0"),
        )];
        let claims = claims_for(&entries);
        assert_eq!(claims.len(), 2);

        let dl = &claims[0];
        assert_eq!(dl.device, DeviceKey("E:".to_string()));
        assert_eq!(dl.attribute, Attribute::DriveLetter);
        assert_eq!(dl.value, Value::Text("E:".to_string()));
        assert_eq!(dl.provenance.source, SourceKind::Shellbag);
        assert_eq!(
            dl.provenance.locator,
            "Software\\Microsoft\\Windows\\Shell\\BagMRU\\0\\0\\0"
        );

        let bf = &claims[1];
        assert_eq!(bf.device, DeviceKey("E:".to_string()));
        assert_eq!(bf.attribute, Attribute::BrowsedFolder);
        assert_eq!(
            bf.value,
            Value::Text("My Computer\\E:\\\\photos".to_string())
        );
        assert_eq!(bf.provenance.source, SourceKind::Shellbag);
    }

    #[test]
    fn entry_without_a_drive_letter_is_skipped() {
        // A volume item with no clean drive-letter name carries no join key.
        let entries = [entry("My Computer\\Some Volume", None, None)];
        assert!(claims_for(&entries).is_empty());
    }

    #[test]
    fn locator_falls_back_to_the_file_without_a_key_path() {
        let entries = [entry("My Computer\\E:\\", Some('E'), None)];
        let claims = claims_for(&entries);
        assert_eq!(claims[0].provenance.locator, "NTUSER.DAT");
    }

    #[test]
    fn multiple_entries_accumulate() {
        let entries = [
            entry("My Computer\\E:\\", Some('E'), None),
            entry("My Computer\\F:\\docs", Some('F'), None),
        ];
        let claims = claims_for(&entries);
        assert_eq!(claims.len(), 4);
        assert_eq!(claims[0].device, DeviceKey("E:".to_string()));
        assert_eq!(claims[3].device, DeviceKey("F:".to_string()));
    }

    #[test]
    fn browsed_folder_is_reattributed_to_the_device_mounted_at_that_drive_letter() {
        // End-to-end with reconcile: a physical device reports it was mounted at E:,
        // so the shellbag's browsed folder re-keys onto that device.
        let entries = [entry("My Computer\\E:\\\\photos", Some('E'), None)];
        let mut all = claims_for(&entries);
        all.push(Claim {
            device: DeviceKey("USBSTOR-DEV-1".into()),
            attribute: Attribute::DriveLetter,
            value: Value::Text("E:".into()),
            provenance: Provenance {
                source: SourceKind::Usbstor,
                locator: "x".into(),
            },
        });
        let out = crate::reconcile_volume_serials(&all);
        let bf = out
            .iter()
            .find(|c| c.attribute == Attribute::BrowsedFolder)
            .expect("browsed folder present");
        assert_eq!(bf.device, DeviceKey("USBSTOR-DEV-1".into()));
    }
}
