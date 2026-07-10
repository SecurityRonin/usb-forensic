//! Adapter: `lnk-core` Jump Lists → USB-history [`Claim`]s.
//!
//! A Jump List (`*.automaticDestinations-ms` / `*.customDestinations-ms`) records a
//! per-application MRU whose entries each embed a Shell Link. This adapter reuses the
//! LNK mapping for each embedded link (volume serial + accessed file) and, for
//! automatic destinations, adds the `DestList` **last-access** time as a
//! `LastConnected` signal: a file accessed on a volume at time *T* is evidence the
//! volume was mounted at *T*. A pure mapping over already-decoded records.

use crate::sources::lnk::{link_volume_serial, shell_link_claims};
use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use lnk_core::JumpList;

/// A parsed Jump List paired with the on-disk locator it was read from (the decoded
/// [`JumpList`] does not record its own path).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JumpListArtifact {
    /// Precise pointer to the source jump-list file, used in the [`Provenance`] locator.
    pub source_path: String,
    /// The already-decoded Jump List.
    pub list: JumpList,
}

/// A [`HistorySource`] over parsed Jump Lists.
pub struct JumpListSource<'a> {
    artifacts: &'a [JumpListArtifact],
}

impl<'a> JumpListSource<'a> {
    /// Wrap parsed Jump Lists (each paired with its source locator).
    #[must_use]
    pub fn new(artifacts: &'a [JumpListArtifact]) -> Self {
        Self { artifacts }
    }
}

impl HistorySource for JumpListSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for artifact in self.artifacts {
            for (idx, entry) in artifact.list.entries.iter().enumerate() {
                let locator = format!("{}#{idx}", artifact.source_path);
                out.extend(shell_link_claims(
                    &entry.link,
                    SourceKind::JumpList,
                    &locator,
                ));

                // DestList last-access → LastConnected for the file's volume.
                if let Some(destlist) = &entry.destlist {
                    if destlist.last_access != 0 {
                        if let Some(serial) = link_volume_serial(&entry.link) {
                            out.push(Claim {
                                device: DeviceKey(serial),
                                attribute: Attribute::LastConnected,
                                value: Value::Timestamp(destlist.last_access),
                                provenance: Provenance {
                                    source: SourceKind::JumpList,
                                    locator,
                                },
                            });
                        }
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use lnk_core::{
        DestListEntry, JumpListEntry, JumpListKind, LinkInfo, ShellLink, ShellLinkHeader,
        StringData, VolumeId,
    };

    fn link(serial: u32) -> ShellLink {
        ShellLink {
            header: ShellLinkHeader {
                link_flags: 0,
                file_attributes: 0,
                creation_time: 0,
                access_time: 0,
                write_time: 0,
                file_size: 0,
                icon_index: 0,
                show_command: 1,
                hotkey: 0,
            },
            link_target_idlist: None,
            link_info: (serial != 0).then(|| LinkInfo {
                volume_id: Some(VolumeId {
                    drive_type: lnk_core::drive_type::REMOVABLE,
                    drive_serial_number: serial,
                    volume_label: None,
                }),
                local_base_path: Some("E:\\x".to_string()),
                common_network_relative_link: None,
            }),
            string_data: StringData::default(),
            tracker: None,
        }
    }

    fn destlist(last_access: i64) -> DestListEntry {
        DestListEntry {
            droid_volume_guid: String::new(),
            droid_file_guid: String::new(),
            birth_droid_volume_guid: String::new(),
            birth_droid_file_guid: String::new(),
            hostname: "HOST".into(),
            entry_number: 1,
            last_access,
            pinned: false,
            access_count: None,
            path: "E:\\x".into(),
        }
    }

    fn jumplist(entries: Vec<JumpListEntry>) -> JumpListArtifact {
        JumpListArtifact {
            source_path: "1234.automaticDestinations-ms".into(),
            list: JumpList {
                kind: JumpListKind::Automatic,
                app_id: Some("1234".into()),
                entries,
            },
        }
    }

    #[test]
    fn destlist_access_time_becomes_a_last_connected_claim() {
        let arts = [jumplist(vec![JumpListEntry {
            destlist: Some(destlist(1_700_000_000)),
            link: link(0xDEAD_BEEF),
        }])];
        let claims = JumpListSource::new(&arts).claims();
        assert!(claims.iter().any(|c| c.attribute == Attribute::VolumeSerial
            && c.provenance.source == SourceKind::JumpList));
        let last = claims
            .iter()
            .find(|c| c.attribute == Attribute::LastConnected)
            .expect("last-connected from DestList access time");
        assert_eq!(last.value, Value::Timestamp(1_700_000_000));
        assert_eq!(last.device, DeviceKey("DEAD-BEEF".into()));
    }

    #[test]
    fn zero_access_time_and_missing_serial_add_no_last_connected() {
        let arts = [jumplist(vec![
            // destlist present but last_access == 0 → no LastConnected
            JumpListEntry {
                destlist: Some(destlist(0)),
                link: link(0x1111_2222),
            },
            // volume serial absent → link_volume_serial None → no claims at all
            JumpListEntry {
                destlist: Some(destlist(1_700_000_000)),
                link: link(0),
            },
            // no destlist → skip the DestList branch
            JumpListEntry {
                destlist: None,
                link: link(0x3333_4444),
            },
        ])];
        let claims = JumpListSource::new(&arts).claims();
        assert!(claims
            .iter()
            .all(|c| c.attribute != Attribute::LastConnected));
    }
}
