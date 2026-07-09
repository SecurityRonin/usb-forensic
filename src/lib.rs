//! `usb-forensic` — the USB device-history correlation engine.
//!
//! **Status: pre-code design seed.** This crate is scaffolded to the SecurityRonin
//! fleet standard (CI, lints, docs, supply-chain gates) but carries no correlation
//! logic yet. The product thesis lives in the repository `README.md` and
//! `docs/competitive-landscape.md`; the build plan lives in `docs/roadmap.md`. Code
//! is filled in under strict TDD, one source and one finding at a time.
//!
//! ## What it will be
//!
//! A thin **orchestration / correlation** crate — it parses no raw format itself.
//! It consumes the fleet's already-built reader crates, normalizes their output into
//! one uniform USB-device-history event, and cross-correlates the timestamps across
//! sources, reporting each value as *consistent with* or *not consistent with* the
//! others so an examiner can tell a reliable first-connected time from a partial or
//! contradicted one. Every finding is an **observation** ("consistent with …"), a
//! `forensicnomicon::report::Finding`; the examiner draws the conclusions.
//!
//! ## Sources it will consume (Windows)
//!
//! - **Registry** (`winreg-artifacts`) — `USBSTOR`, `Enum\USB`, `MountedDevices`,
//!   `WPDBUSENUM`, `VolumeInfoCache`, `MountPoints2`, `Amcache.hve`
//! - **`Enum\SCSI`** — UASP / USB-3 drives (`uaspstor.sys`), which do **not** land in
//!   `USBSTOR`
//! - **SetupAPI** (`peripheral-core`) — `setupapi.dev.log` device-install events
//! - **Event Log** (`winevt-forensic`) — the Partition/Diagnostic log volume serials
//! - **LNK** (`lnk-core`) — recent-file volume-serial join
//!
//! ## The wedge (why it is not a USB Detective clone)
//!
//! Headless, library-embeddable, pipeline-native, and **reproducible** — every
//! reported value re-derivable from `hive → key → raw bytes → decoding rule`. It
//! targets the pipeline operator (lab automation, Velociraptor/KAPE), not the GUI
//! examiner. See the README for the full, adversarially-pressure-tested positioning.

#![forbid(unsafe_code)]

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
