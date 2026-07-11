//! Adapter: `peripheral-core` [`UserMount`]s (`NTUSER` MountPoints2) → USB-history
//! [`Claim`]s.
//!
//! Each `MountPoints2` record is a per-user attestation that a volume (by GUID) was
//! mounted, with the subkey's last-write as the mount time. This adapter emits that as a
//! [`Attribute::LastConnected`] claim keyed by the **volume GUID**; the volume
//! canonicalization then ties the GUID (via the `MountedDevices` MBR bridge) to a drive
//! letter and its cached label, so a user's mount, the drive letter, and the volume label
//! land on one device record.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use peripheral_core::mountpoints2::UserMount;

/// A [`HistorySource`] over decoded per-user [`UserMount`]s.
pub struct MountPoints2Source<'a> {
    mounts: &'a [UserMount],
}

impl<'a> MountPoints2Source<'a> {
    /// Wrap decoded mounts (from `peripheral_core::mountpoints2::parse_mountpoints2`).
    #[must_use]
    pub fn new(mounts: &'a [UserMount]) -> Self {
        Self { mounts }
    }
}

impl HistorySource for MountPoints2Source<'_> {
    fn claims(&self) -> Vec<Claim> {
        self.mounts
            .iter()
            .filter_map(|mount| {
                // A mount with no recorded time carries no timeline fact.
                let when = mount.last_mounted?;
                Some(Claim {
                    device: DeviceKey(mount.volume_guid.clone()),
                    attribute: Attribute::LastConnected,
                    value: Value::Timestamp(when),
                    provenance: Provenance {
                        source: SourceKind::MountPoints2,
                        locator: mount
                            .source
                            .key_path
                            .clone()
                            .unwrap_or_else(|| mount.source.file.clone()),
                    },
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peripheral_core::Provenance as PcProvenance;

    fn mount(guid: &str, when: Option<i64>) -> UserMount {
        UserMount {
            volume_guid: guid.to_string(),
            last_mounted: when,
            source: PcProvenance {
                file: "NTUSER.DAT".to_string(),
                line: 0,
                key_path: Some(format!("…\\MountPoints2\\{guid}")),
            },
        }
    }

    #[test]
    fn a_timed_mount_yields_a_last_connected_claim_keyed_by_volume_guid() {
        let mounts = [mount(
            "{a2f2048e-d228-11e4-b630-000c29ff2429}",
            Some(1_427_230_953),
        )];
        let claims = MountPoints2Source::new(&mounts).claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(
            claims[0].device,
            DeviceKey("{a2f2048e-d228-11e4-b630-000c29ff2429}".to_string())
        );
        assert_eq!(claims[0].attribute, Attribute::LastConnected);
        assert_eq!(claims[0].value, Value::Timestamp(1_427_230_953));
        assert_eq!(claims[0].provenance.source, SourceKind::MountPoints2);
    }

    #[test]
    fn a_mount_without_a_time_is_skipped() {
        let mounts = [mount("{guid}", None)];
        assert!(MountPoints2Source::new(&mounts).claims().is_empty());
    }

    #[test]
    fn locator_falls_back_to_the_file_without_a_key_path() {
        let mut m = mount("{guid}", Some(1));
        m.source.key_path = None;
        let mounts = [m];
        let claims = MountPoints2Source::new(&mounts).claims();
        assert_eq!(claims[0].provenance.locator, "NTUSER.DAT");
    }
}
