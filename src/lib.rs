//! `usb-forensic` — the USB device-history correlation engine.
//!
//! A thin **orchestration / correlation** crate — it parses no raw format itself. It
//! consumes the fleet's reader crates, normalizes their output into one uniform
//! USB-history [`Claim`], and cross-correlates values across sources, grading each by
//! how well its independent storage containers agree ([`Consistency`]) so an examiner
//! can tell a reliable first-connected time from a partial or contradicted one. Every
//! finding is an **observation** ("consistent with …"), a
//! `forensicnomicon::report::Finding`; the examiner draws the conclusions.
//!
//! ## What runs today
//!
//! - **Correlation core:** [`correlate()`] / [`correlate_sources`] → [`DeviceHistory`]
//!   with per-attribute [`Consistency`] + retained provenance; [`to_jsonl`] output.
//! - **Findings:** [`audit`] → `forensicnomicon` findings (conflicts graded, MITRE
//!   T1070.006 consistent-with; corroborations as reliable history).
//! - **Sources:** [`PeripheralSource`] (`peripheral-core` — `setupapi.dev.log`,
//!   SYSTEM-hive `Enum\{USBSTOR,SCSI,USB}` device keys, and Linux kernel logs) and
//!   [`LnkSource`] (`lnk-core` — the volume-serial file join).
//! - **CLI:** the `usb4n6` binary runs the pipeline over setupapi, a SYSTEM hive,
//!   `.lnk`, jump-list, and Linux syslog evidence (type auto-detected).
//!
//! Correlation across the setupapi device serial and the LNK volume serial awaits the
//! registry `MountedDevices` bridge; event-log and macOS sources follow. See
//! `docs/roadmap.md` and `docs/feature-parity.md`.
//!
//! ## The wedge (why it is not a USB Detective clone)
//!
//! Headless, library-embeddable, pipeline-native, and **reproducible** — every
//! reported value re-derivable from `hive → key → raw bytes → decoding rule`. It
//! targets the pipeline operator (lab automation, Velociraptor/KAPE), not the GUI
//! examiner. See the README for the full, adversarially-pressure-tested positioning.

#![forbid(unsafe_code)]

pub mod correlate;
pub mod docx;
pub mod model;
pub mod pdf;
pub mod reconcile;
pub mod render;
pub mod report;
pub mod source;
pub mod sources;
pub mod timeline;
pub mod tz;

pub use correlate::{correlate, to_jsonl, CorrelatedAttribute, DeviceHistory, ProvenancedValue};
pub use docx::render_docx;
pub use model::{ArtifactContainer, Attribute, Claim, DeviceKey, Provenance, SourceKind, Value};
pub use pdf::render_pdf;
pub use reconcile::{canonicalize_mounted_volumes, reconcile_volume_serials};
pub use render::{format_epoch, render_accessed_files, render_report, render_table};
pub use report::audit;
pub use source::{correlate_sources, HistorySource};
pub use sources::apple_ipod::{parse_ipod_plist, AppleDevice, AppleIPodSource};
pub use sources::device_image::{
    parse_boot_sectors, DeviceImage, DeviceImageSource, EncryptionKind,
};
pub use sources::emdmgmt::EmdMgmtSource;
pub use sources::jumplist::{JumpListArtifact, JumpListSource};
pub use sources::lnk::{LnkArtifact, LnkSource};
pub use sources::macos_unified_log::{parse_unified_log, MacUnifiedLogSource, UsbEnumeration};
pub use sources::macos_usb::{parse_system_profiler, MacUsbDevice, MacUsbSource};
pub use sources::mountpoints2::MountPoints2Source;
pub use sources::partition_diag::PartitionDiagSource;
pub use sources::peripheral::PeripheralSource;
pub use sources::volume_cache::VolumeCacheSource;
pub use timeline::{super_timeline, timeline_to_jsonl, TimelineEvent};
pub use tz::normalize_local_clocks;

use serde::Serialize;

/// The cross-source agreement grade for one reported attribute (first-connected time,
/// volume name, serial, …) — the defining output of the correlation engine.
///
/// It records whether an independent second source corroborated a value and whether the
/// sources agreed, so a partial or contradicted value is visibly distinct from a
/// corroborated one. It is a description of the evidence, never a verdict: `Conflicting`
/// says the sources disagree, not that a value was "spoofed".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[non_exhaustive]
pub enum Consistency {
    /// Exactly one source reported the value; nothing independent to corroborate it.
    SingleSource,
    /// Two or more independent sources reported the value and they agree.
    Corroborated,
    /// Two or more independent sources reported the value and they disagree.
    Conflicting,
}

impl Consistency {
    /// A short, stable label for human-facing output. This is a published contract:
    /// existing labels never change; new variants get new labels.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::SingleSource => "single-source",
            Self::Corroborated => "corroborated",
            Self::Conflicting => "conflicting",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_stable_and_distinct() {
        let all = [
            Consistency::SingleSource,
            Consistency::Corroborated,
            Consistency::Conflicting,
        ];
        let labels: Vec<&str> = all.iter().map(|c| c.label()).collect();
        assert_eq!(labels, ["single-source", "corroborated", "conflicting"]);
        assert_eq!(
            labels
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len(),
            all.len(),
            "labels must be distinct",
        );
    }
}
