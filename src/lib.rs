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
//! - **Sources:** [`PeripheralSource`] (`peripheral-core` — `setupapi.dev.log` now,
//!   registry USBSTOR/SCSI/USB once `peripheral-core` 0.2 ships) and [`LnkSource`]
//!   (`lnk-core` — the volume-serial file join).
//! - **CLI:** the `usb4n6` binary runs the pipeline over setupapi + `.lnk` evidence.
//!
//! Correlation across the setupapi device serial and the LNK volume serial awaits the
//! registry `MountedDevices` bridge (`peripheral-core` 0.2); event-log, macOS, and
//! Linux sources follow. See `docs/roadmap.md` and `docs/feature-parity.md`.
//!
//! ## The wedge (why it is not a USB Detective clone)
//!
//! Headless, library-embeddable, pipeline-native, and **reproducible** — every
//! reported value re-derivable from `hive → key → raw bytes → decoding rule`. It
//! targets the pipeline operator (lab automation, Velociraptor/KAPE), not the GUI
//! examiner. See the README for the full, adversarially-pressure-tested positioning.

#![forbid(unsafe_code)]

pub mod correlate;
pub mod model;
pub mod render;
pub mod report;
pub mod source;
pub mod sources;

pub use correlate::{correlate, to_jsonl, CorrelatedAttribute, DeviceHistory, ProvenancedValue};
pub use model::{ArtifactContainer, Attribute, Claim, DeviceKey, Provenance, SourceKind, Value};
pub use render::{format_epoch, render_report, render_table};
pub use report::audit;
pub use source::{correlate_sources, HistorySource};
pub use sources::lnk::{LnkArtifact, LnkSource};
pub use sources::peripheral::PeripheralSource;

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
