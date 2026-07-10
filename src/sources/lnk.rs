//! Adapter: `lnk-core` Shell Links → USB-history [`Claim`]s (the volume-serial join).
//!
//! A Windows Shell Link (`.lnk`) records the target file's path together with the
//! `VolumeID` `DriveSerialNumber` of the volume the target lived on. That drive
//! serial is a **volume** serial, not a device/instance serial — so a `.lnk`
//! cannot on its own name a USB device. What it *can* do is tie a **file access**
//! to a **volume**; the correlation engine then reconciles that volume serial with
//! the device that carried it (a volume serial reported by `MountedDevices`, the
//! Partition/Diagnostic event log, or `VolumeInfoCache`). This adapter emits that
//! join material and nothing more:
//!
//! - a [`Attribute::VolumeSerial`] claim carrying the canonical volume serial, so
//!   the value is discoverable and matchable against other sources' serials, and
//! - a [`Attribute::AccessedFile`] claim carrying the target path,
//!
//! both keyed by a [`DeviceKey`] holding the **volume** serial. See the module
//! `blockers` note: this `DeviceKey` is a volume-serial identity, which the core must
//! reconcile into a device identity — it is deliberately not a device serial.
//!
//! This is a pure mapping: it consumes [`lnk_core::ShellLink`] values the reader has
//! already decoded and never touches raw bytes. Verified against `lnk-core` 0.4.0
//! (`ShellLink` / `LinkInfo` / `VolumeId` / `CommonNetworkRelativeLink` /
//! `LinkTargetIdList`, all public-field structs).

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};

/// A parsed Shell Link paired with the on-disk locator of the `.lnk` it came from.
///
/// The reader's [`lnk_core::ShellLink`] carries no record of which file it was
/// parsed from, but a [`Provenance`] locator must point back at the artifact — so
/// the caller pairs each decoded link with the path (or jump-list stream pointer)
/// it was read from. This is the one field the decoded structure cannot supply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LnkArtifact {
    /// Precise pointer to the source `.lnk` (e.g. a full path, or
    /// `jumplist:<appid>#<n>` for an embedded link). Used verbatim as the
    /// [`Provenance::locator`].
    pub source_path: String,
    /// The already-decoded Shell Link.
    pub link: lnk_core::ShellLink,
}

/// A [`HistorySource`] over a set of parsed Shell Links.
pub struct LnkSource<'a> {
    artifacts: &'a [LnkArtifact],
}

impl<'a> LnkSource<'a> {
    /// Wrap parsed Shell Links (each paired with its source locator).
    #[must_use]
    pub fn new(artifacts: &'a [LnkArtifact]) -> Self {
        Self { artifacts }
    }
}

impl HistorySource for LnkSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        let mut out = Vec::new();
        for artifact in self.artifacts {
            push_artifact_claims(artifact, &mut out);
        }
        out
    }
}

/// Render a Windows volume serial the way `dir` / `vol` display it: two uppercase
/// hex halves joined by a dash, zero-padded (e.g. `0xDEADBEEF` → `DEAD-BEEF`,
/// `0x00000001` → `0000-0001`). A stable canonical form so the same volume serial
/// from any source produces the same string to join on.
fn format_volume_serial(serial: u32) -> String {
    format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF)
}

/// Resolve the Shell Link's target path: the local base path when present, else the
/// network (UNC) name, else the reconstructed `LinkTargetIDList` path. Returns
/// `None` when no non-empty target can be recovered.
fn target_path(link: &lnk_core::ShellLink) -> Option<String> {
    let from_info = link.link_info.as_ref().and_then(|info| {
        info.local_base_path.clone().or_else(|| {
            info.common_network_relative_link
                .as_ref()
                .and_then(|cnrl| cnrl.net_name.clone())
        })
    });
    from_info
        .or_else(|| {
            link.link_target_idlist
                .as_ref()
                .and_then(|t| t.path.clone())
        })
        .filter(|p| !p.is_empty())
}

fn push_artifact_claims(artifact: &LnkArtifact, out: &mut Vec<Claim>) {
    out.extend(shell_link_claims(
        &artifact.link,
        SourceKind::Lnk,
        &artifact.source_path,
    ));
}

/// The canonical volume serial (`DEAD-BEEF`) of a Shell Link's `VolumeID`, or `None`
/// when the link has no volume id or the serial is the `0` unset sentinel.
pub(crate) fn link_volume_serial(link: &lnk_core::ShellLink) -> Option<String> {
    let serial = link
        .link_info
        .as_ref()?
        .volume_id
        .as_ref()?
        .drive_serial_number;
    (serial != 0).then(|| format_volume_serial(serial))
}

/// Map one decoded Shell Link into its volume-serial-join claims, tagged with the given
/// source and locator. Shared by the LNK and jump-list adapters (a jump-list entry
/// embeds a Shell Link). A link contributes only when it carries a `VolumeID` with a
/// non-zero drive serial (serial `0` is the "unset" sentinel — no volume to key on, so
/// it is skipped rather than emitting a bogus `0000-0000` device).
pub(crate) fn shell_link_claims(
    link: &lnk_core::ShellLink,
    source: SourceKind,
    locator: &str,
) -> Vec<Claim> {
    let mut out = Vec::new();
    let Some(serial_str) = link_volume_serial(link) else {
        return out;
    };
    let device = DeviceKey(serial_str.clone());
    let provenance = Provenance {
        source,
        locator: locator.to_string(),
    };

    out.push(Claim {
        device: device.clone(),
        attribute: Attribute::VolumeSerial,
        value: Value::Text(serial_str),
        provenance: provenance.clone(),
    });
    if let Some(path) = target_path(link) {
        out.push(Claim {
            device,
            attribute: Attribute::AccessedFile,
            value: Value::Text(path),
            provenance,
        });
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use lnk_core::{
        CommonNetworkRelativeLink, LinkInfo, LinkTargetIdList, ShellLink, ShellLinkHeader,
        StringData, VolumeId,
    };

    fn header() -> ShellLinkHeader {
        ShellLinkHeader {
            link_flags: 0,
            file_attributes: 0,
            creation_time: 0,
            access_time: 0,
            write_time: 0,
            file_size: 0,
            icon_index: 0,
            show_command: 1,
            hotkey: 0,
        }
    }

    fn link(
        volume_id: Option<VolumeId>,
        local_base_path: Option<&str>,
        cnrl: Option<CommonNetworkRelativeLink>,
        idlist_path: Option<&str>,
    ) -> ShellLink {
        let link_info = if volume_id.is_some() || local_base_path.is_some() || cnrl.is_some() {
            Some(LinkInfo {
                volume_id,
                local_base_path: local_base_path.map(ToString::to_string),
                common_network_relative_link: cnrl,
            })
        } else {
            None
        };
        ShellLink {
            header: header(),
            link_target_idlist: idlist_path.map(|p| LinkTargetIdList {
                raw: Vec::new(),
                items: Vec::new(),
                path: Some(p.to_string()),
            }),
            link_info,
            string_data: StringData::default(),
            tracker: None,
        }
    }

    fn removable(serial: u32) -> VolumeId {
        VolumeId {
            drive_type: lnk_core::drive_type::REMOVABLE,
            drive_serial_number: serial,
            volume_label: None,
        }
    }

    fn artifact(source_path: &str, link: ShellLink) -> LnkArtifact {
        LnkArtifact {
            source_path: source_path.to_string(),
            link,
        }
    }

    fn claims_for(source_path: &str, link: ShellLink) -> Vec<Claim> {
        let arts = [artifact(source_path, link)];
        LnkSource::new(&arts).claims()
    }

    #[test]
    fn volume_serial_is_canonical_padded_hex() {
        assert_eq!(format_volume_serial(0xDEAD_BEEF), "DEAD-BEEF");
        assert_eq!(format_volume_serial(1), "0000-0001");
        assert_eq!(format_volume_serial(0), "0000-0000");
    }

    #[test]
    fn local_target_yields_volume_serial_and_accessed_file() {
        let claims = claims_for(
            "C:\\Users\\a\\Recent\\secret.lnk",
            link(
                Some(removable(0xDEAD_BEEF)),
                Some("E:\\secret.docx"),
                None,
                None,
            ),
        );
        assert_eq!(claims.len(), 2);

        let vs = &claims[0];
        assert_eq!(vs.device, DeviceKey("DEAD-BEEF".to_string()));
        assert_eq!(vs.attribute, Attribute::VolumeSerial);
        assert_eq!(vs.value, Value::Text("DEAD-BEEF".to_string()));
        assert_eq!(vs.provenance.source, SourceKind::Lnk);
        assert_eq!(vs.provenance.locator, "C:\\Users\\a\\Recent\\secret.lnk");

        let af = &claims[1];
        assert_eq!(af.device, DeviceKey("DEAD-BEEF".to_string()));
        assert_eq!(af.attribute, Attribute::AccessedFile);
        assert_eq!(af.value, Value::Text("E:\\secret.docx".to_string()));
        assert_eq!(af.provenance.source, SourceKind::Lnk);
    }

    #[test]
    fn serial_without_resolvable_path_yields_only_volume_serial() {
        let claims = claims_for(
            "x.lnk",
            link(Some(removable(0x1234_5678)), None, None, None),
        );
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].attribute, Attribute::VolumeSerial);
        assert_eq!(claims[0].value, Value::Text("1234-5678".to_string()));
    }

    #[test]
    fn empty_local_base_path_is_not_a_target() {
        // A present-but-empty base path must not become a pathless AccessedFile.
        let claims = claims_for(
            "x.lnk",
            link(Some(removable(0x0000_0001)), Some(""), None, None),
        );
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].attribute, Attribute::VolumeSerial);
    }

    #[test]
    fn network_name_used_as_target_when_no_local_path() {
        let cnrl = CommonNetworkRelativeLink {
            net_name: Some("\\\\server\\share".to_string()),
            device_name: None,
        };
        let claims = claims_for(
            "x.lnk",
            link(Some(removable(0xABCD_0000)), None, Some(cnrl), None),
        );
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[1].attribute, Attribute::AccessedFile);
        assert_eq!(
            claims[1].value,
            Value::Text("\\\\server\\share".to_string())
        );
    }

    #[test]
    fn cnrl_without_net_name_falls_through_to_idlist_path() {
        let cnrl = CommonNetworkRelativeLink {
            net_name: None,
            device_name: Some("Z:".to_string()),
        };
        let claims = claims_for(
            "x.lnk",
            link(
                Some(removable(0x0001_0002)),
                None,
                Some(cnrl),
                Some("My Computer\\E:\\photo.jpg"),
            ),
        );
        assert_eq!(claims.len(), 2);
        assert_eq!(claims[1].attribute, Attribute::AccessedFile);
        assert_eq!(
            claims[1].value,
            Value::Text("My Computer\\E:\\photo.jpg".to_string())
        );
    }

    #[test]
    fn zero_serial_is_skipped() {
        let claims = claims_for(
            "x.lnk",
            link(Some(removable(0)), Some("E:\\f.txt"), None, None),
        );
        assert!(claims.is_empty());
    }

    #[test]
    fn link_without_volume_id_is_skipped() {
        // A LinkInfo with no VolumeID (e.g. a pure network target) has no volume
        // serial to key on, so it contributes no device-join claim.
        let claims = claims_for("x.lnk", link(None, Some("C:\\local.txt"), None, None));
        assert!(claims.is_empty());
    }

    #[test]
    fn link_without_link_info_is_skipped() {
        let claims = claims_for("x.lnk", link(None, None, None, Some("My Computer\\C:\\x")));
        assert!(claims.is_empty());
    }

    #[test]
    fn multiple_artifacts_accumulate() {
        let arts = [
            artifact(
                "a.lnk",
                link(Some(removable(0x1111_2222)), Some("E:\\a"), None, None),
            ),
            artifact(
                "b.lnk",
                link(Some(removable(0x3333_4444)), Some("F:\\b"), None, None),
            ),
        ];
        let claims = LnkSource::new(&arts).claims();
        assert_eq!(claims.len(), 4);
        assert_eq!(claims[0].device, DeviceKey("1111-2222".to_string()));
        assert_eq!(claims[3].device, DeviceKey("3333-4444".to_string()));
    }
}
