//! The source-agnostic domain model: atomic claims a source adapter emits, which the
//! correlation core groups and grades.
//!
//! Enum variants are intentionally minimal and `#[non_exhaustive]` — each new source
//! adds the variant it needs (additive, non-breaking). The full planned set is the
//! `docs/feature-parity.md` checklist.

use serde::Serialize;

/// Which artifact a claim was extracted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub enum SourceKind {
    /// `SYSTEM\...\Enum\{USBSTOR,SCSI,USB}` — device instance keys and their
    /// install / first-install / last-arrival / last-removal property `FILETIME`s.
    Usbstor,
    /// `SYSTEM\MountedDevices` — drive-letter ↔ device mapping.
    MountedDevices,
    /// `setupapi.dev.log` — first device-install time.
    SetupApi,
    /// Microsoft-Windows-Partition/Diagnostic event log — volume serials.
    PartitionDiag,
    /// A Windows Shell Link (`.lnk`) — the volume-serial file join.
    Lnk,
    /// A Windows Jump List (`*.automaticDestinations-ms` / `*.customDestinations-ms`).
    JumpList,
    /// A Linux kernel log (`syslog` / `dmesg`) — USB enumeration events.
    LinuxKernelLog,
}

/// The physical storage container an artifact lives in — the tamper surface.
///
/// Corroboration counts *independent* sources, and independence is a property of the
/// container, not the recording mechanism: two sources in the same container share one
/// tamper surface, so their agreement is not tamper-independent. Distinct from
/// [`SourceKind`], which is the recording mechanism (guards against parse error and
/// coincidence, a weaker form of independence).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub enum ArtifactContainer {
    /// The `SYSTEM` registry hive (USBSTOR, MountedDevices, …).
    SystemHive,
    /// The `setupapi.dev.log` text log.
    SetupApiLog,
    /// A Windows event log (`.evtx`).
    EventLog,
    /// A Shell Link file (`.lnk`) or jump list on the filesystem.
    LnkFile,
    /// A Linux kernel log file (`syslog` / `dmesg`).
    KernelLog,
}

impl SourceKind {
    /// The storage container this source lives in — its tamper surface. Total.
    #[must_use]
    pub const fn container(self) -> ArtifactContainer {
        match self {
            Self::Usbstor | Self::MountedDevices => ArtifactContainer::SystemHive,
            Self::SetupApi => ArtifactContainer::SetupApiLog,
            Self::PartitionDiag => ArtifactContainer::EventLog,
            Self::Lnk | Self::JumpList => ArtifactContainer::LnkFile,
            Self::LinuxKernelLog => ArtifactContainer::KernelLog,
        }
    }

    /// Whether this source records timestamps in **host-local** time (rather than UTC).
    ///
    /// `setupapi.dev.log` and Linux kernel logs write local wall-clock with no zone, so
    /// their readers convert them naively (local-as-UTC). Registry `FILETIME`, event-log
    /// `FILETIME`, and LNK/jump-list epochs are true UTC. [`normalize_local_clocks`]
    /// uses this to correct local timestamps to UTC given the host's offset.
    ///
    /// [`normalize_local_clocks`]: crate::normalize_local_clocks
    #[must_use]
    pub fn clock_is_local(self) -> bool {
        matches!(self, Self::SetupApi | Self::LinuxKernelLog)
    }
}

/// Which device attribute a claim describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[non_exhaustive]
pub enum Attribute {
    /// First time the device was connected to this system.
    FirstConnected,
    /// Most recent time the device was connected.
    LastConnected,
    /// Most recent time the device was removed (disconnected).
    LastRemoved,
    /// Volume label (friendly name) of the device's volume.
    VolumeName,
    /// Volume serial number of the device's volume.
    VolumeSerial,
    /// A file accessed from the device (e.g. an LNK target) — the file-to-device link.
    AccessedFile,
}

/// A comparable claim value, normalized by the source adapter.
///
/// Timestamps are epoch **seconds, UTC**: the adapter normalizes each source's native
/// precision (registry `FILETIME` is 100 ns, `setupapi` is 1 s) down to seconds so the
/// core compares like-for-like. Sub-second precision is not a real disagreement, so it
/// is removed at the boundary rather than papered over with a tolerance constant here.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Value {
    /// A point in time, epoch seconds UTC.
    Timestamp(i64),
    /// A textual value (volume name, serial, …), verbatim.
    Text(String),
}

/// Where a value came from: the source plus a locator (registry key path, log line,
/// event record id). The reproducibility chain (raw bytes → decoding rule) extends this.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct Provenance {
    /// The artifact the value was read from.
    pub source: SourceKind,
    /// A precise pointer within that artifact (e.g. the full key path or log line).
    pub locator: String,
}

/// Cross-source identity of a device — typically the device/instance serial number
/// that appears across `USBSTOR`, `MountedDevices`, `setupapi`, and the event log.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct DeviceKey(pub String);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_kernel_log_is_its_own_container_with_a_local_clock() {
        // A Linux syslog/dmesg file is a distinct tamper surface from any Windows
        // artifact, and (like setupapi) records host-local wall-clock.
        assert_eq!(
            SourceKind::LinuxKernelLog.container(),
            ArtifactContainer::KernelLog
        );
        assert!(SourceKind::LinuxKernelLog.clock_is_local());
    }

    #[test]
    fn registry_source_lives_in_the_system_hive_container_in_utc() {
        assert_eq!(
            SourceKind::Usbstor.container(),
            ArtifactContainer::SystemHive
        );
        assert!(!SourceKind::Usbstor.clock_is_local());
    }
}

/// One atomic extracted fact about one device, from one source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Claim {
    /// The device this fact is about.
    pub device: DeviceKey,
    /// The attribute this fact describes.
    pub attribute: Attribute,
    /// The value the source reported.
    pub value: Value,
    /// Where the value came from.
    pub provenance: Provenance,
}
