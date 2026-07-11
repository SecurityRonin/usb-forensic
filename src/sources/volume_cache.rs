//! Adapter: `peripheral-core` [`VolumeLabel`]s (Windows `VolumeInfoCache`) → USB-history
//! [`Claim`]s.
//!
//! `VolumeInfoCache` records the label a user gave a volume against the drive letter it
//! was mounted at. That label is a [`Attribute::VolumeName`] fact keyed by the **drive
//! letter**; the correlation layer's drive-letter reconciliation then attributes it to the
//! device that `MountedDevices` maps to that letter, so a stick's human-readable name
//! ("Authorized USB") lands on the stick. A pure mapping over already-decoded records.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use peripheral_core::volume_info::VolumeLabel;

/// A [`HistorySource`] over decoded [`VolumeLabel`]s.
pub struct VolumeCacheSource<'a> {
    labels: &'a [VolumeLabel],
}

impl<'a> VolumeCacheSource<'a> {
    /// Wrap decoded volume labels (from `peripheral_core::volume_info::parse_volume_info_cache`).
    #[must_use]
    pub fn new(labels: &'a [VolumeLabel]) -> Self {
        Self { labels }
    }
}

impl HistorySource for VolumeCacheSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        self.labels
            .iter()
            .map(|label| Claim {
                // Keyed by the drive letter (`E:`) — the drive-letter reconciliation joins
                // it to the device that MountedDevices maps to that letter.
                device: DeviceKey(format!("{}:", label.drive_letter)),
                attribute: Attribute::VolumeName,
                value: Value::Text(label.volume_label.clone()),
                provenance: Provenance {
                    source: SourceKind::VolumeInfoCache,
                    locator: label
                        .source
                        .key_path
                        .clone()
                        .unwrap_or_else(|| label.source.file.clone()),
                },
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peripheral_core::Provenance as PcProvenance;

    fn label(drive: char, name: &str) -> VolumeLabel {
        VolumeLabel {
            drive_letter: drive,
            volume_label: name.to_string(),
            source: PcProvenance {
                file: "SOFTWARE".to_string(),
                line: 0,
                key_path: Some(format!(
                    "Microsoft\\Windows Search\\VolumeInfoCache\\{drive}:"
                )),
            },
        }
    }

    #[test]
    fn volume_label_yields_a_volume_name_claim_keyed_by_drive_letter() {
        let labels = [label('E', "Authorized USB")];
        let claims = VolumeCacheSource::new(&labels).claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].device, DeviceKey("E:".to_string()));
        assert_eq!(claims[0].attribute, Attribute::VolumeName);
        assert_eq!(claims[0].value, Value::Text("Authorized USB".to_string()));
        assert_eq!(claims[0].provenance.source, SourceKind::VolumeInfoCache);
        assert!(claims[0].provenance.locator.contains("VolumeInfoCache"));
    }

    #[test]
    fn multiple_labels_accumulate() {
        let labels = [label('E', "Authorized USB"), label('F', "IAMAN")];
        let claims = VolumeCacheSource::new(&labels).claims();
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[1].device, DeviceKey("F:".to_string()));
    }
}
