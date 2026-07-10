# Feature-Parity Matrix

The goal: the most comprehensive USB-device-history analyzer available — matching or
exceeding every dedicated competitor, then adding the pipeline/reproducibility wedge no
incumbent has. This page is the **authoritative checklist**: every row is a capability
one of the reference tools ships, and the status column tracks `usb-forensic` against it.

Status legend: ✅ implemented & tested · 🏗 build in progress · 📋 planned · — not applicable.
No cell is marked ✅ until it is implemented **and** validated against an independent
oracle (see [validation](validation.md)).

Reference tools absorbed: **USB Detective** (the depth/scoring leader), **USB Forensic
Tracker / USBFT** (breadth: multi-OS, image mounting, VSCs, encrypted-volume history),
**USB Historian**, **USBDeview**, **KAPE + RegRipper / Registry Explorer**.

## 1. Input & acquisition

| Capability | Seen in | Status |
|---|---|---|
| Live system processing | USB Detective, USBFT, USBDeview | 📋 |
| Individual files / folders of extracted artifacts | all | 🏗 (core accepts decoded records) |
| Logical drives | USB Detective, USBFT | 📋 |
| Mounted forensic images (E01/raw/…) | USB Detective (Pro), USBFT | 📋 (via fleet `ewf`/`dd` + filesystem readers) |
| Built-in image mounting (no external mounter) | USBFT (Arsenal Image Mounter) | 📋 (fleet `4n6mount` FUSE bridge) |
| Volume Shadow Copies — auto-aggregated | USB Detective, USBFT | 📋 (fleet `[H]` VSS layer) |
| Registry transaction-log replay (uncommitted data) | USB Detective | 📋 |
| Remote-machine enumeration | USBDeview | 📋 |
| Cross-platform runtime (analyze from any OS) | USBFT (parses), — (none scores) | 🏗 (Rust, OS-agnostic) |

## 2. Windows artifact coverage

| Artifact | Signal | Seen in | Status |
|---|---|---|---|
| `USBSTOR` (SYSTEM) | device class/serial/VID-PID, first/last connect | all dedicated | 📋 |
| `Enum\USB` (SYSTEM) | parent USB device, container id | USB Detective, RegRipper | 📋 |
| **`Enum\SCSI`** (UASP / USB-3 drives) | modern drives absent from `USBSTOR` | (gap in most) | 📋 |
| `MountedDevices` (SYSTEM) | drive-letter ↔ device mapping | USB Detective, USBFT, RegRipper | 📋 |
| `WPDBUSENUM` / Windows Portable Devices (SOFTWARE) | MTP/PTP + mass-storage, volume label | USB Detective, USBFT | 📋 |
| `VolumeInfoCache` (SOFTWARE) | volume label ↔ serial history | USB Detective | 📋 |
| `MountPoints2` (NTUSER.DAT) | per-user mounts | USB Detective, USBFT, RegRipper | 📋 |
| `Amcache.hve` | execution / first-seen corroboration | USB Detective | 📋 |
| SetupAPI (`setupapi.dev.log`) | first-install time (local, TZ-normalized) | all dedicated | ✅ (`PeripheralSource`) |
| Partition/Diagnostic event log | volume serial numbers, connect events | USB Detective | 📋 |
| Other USB event-log providers (Kernel-PnP, DriverFrameworks-UserMode, Ntfs) | connect/disconnect, mount | RegRipper/KAPE workflows | 📋 |
| LNK files | files opened on device (volume-serial join) | USB Detective, USBFT | ✅ (`LnkSource`) |
| Jump Lists | recent items per app on device | USB Detective | ✅ (`JumpListSource`, MRU access times) |
| ShellBags | folders browsed on device | USB Detective, USBFT | 📋 |

## 3. Correlation & scoring (the moat)

| Capability | Seen in | Status |
|---|---|---|
| Merge all sources into one per-device record | USB Detective | ✅ (`correlate` / `correlate_sources`) |
| Cross-source timestamp comparison per attribute | USB Detective | ✅ core primitive (`Consistency`) |
| Consistency grading (corroborated / conflicting / single-source) | USB Detective (colour-coded) | ✅ `Consistency` |
| Per-value source provenance retained | USB Detective | ✅ (`ProvenancedValue`: source + locator) |
| Reproducibility chain (raw bytes → decoding rule per value) | (none) | 📋 the wedge |
| Deleted / removed-device recovery (Win10 cleanup) | USB Detective | 📋 |
| Prior volume names/serials for formatted devices | USB Detective | 📋 |
| Device/volume encryption-type detection | USB Detective | 📋 |
| TrueCrypt/VeraCrypt mounted-volume history | USBFT | 📋 |
| File-to-device linking (which files touched which stick) | USB Detective, USBFT | 📋 |
| Timezone normalization (local ↔ UTC), TZ-aware querying | USB Detective | 📋 |
| OS-version-aware artifact semantics | USB Detective | 📋 |

## 4. Cross-platform evidence (USBFT breadth)

Per-OS modules report what each system actually retains, with **explicit retention
windows** — a timestamped event list, not a fabricated consistency score where the
sources cannot support one (see [roadmap](roadmap.md) Phase 3).

| Source | OS | Status |
|---|---|---|
| Unified logs (USBMSC), `/var/log/daily.out`, IORegistry snapshots, `com.apple.iPod.plist` | macOS | 📋 |
| syslog/dmesg kernel USB blocks (journald/GVFS planned) | Linux | 🏗 validated reader in peripheral-core PR #2 |

## 5. Output & reporting

| Capability | Seen in | Status |
|---|---|---|
| Results grid / high-level report | USB Detective, USBFT, Historian, USBDeview | ✅ (`usb4n6 --table`) |
| Verbose per-value report with provenance | USB Detective | ✅ (`usb4n6 --report`) |
| Per-device timeline | USB Detective | ✅ (per-device JSONL / report block) |
| Aggregate super-timeline | USB Detective | 📋 |
| Opened/accessed-files report | USB Detective | 📋 |
| Machine-readable output (JSONL, diffable, pipeable) | (weak in all — Excel/CSV only) | ✅ (`to_jsonl`, default) |
| `forensicnomicon::report` findings (fleet-uniform, MITRE-tagged) | (fleet-only) | ✅ (`audit`) |
| Court-ready report with per-value source chain | (Excel only elsewhere) | ✅ native DOCX (`--docx`, oracle-validated) + Markdown (`--report`); PDF via pandoc |
| Volume / MBR export | USB Detective | 📋 |
| Differential mode vs USB Detective / RegRipper (validation) | (none) | 📋 |

## 6. Engineering posture (the fleet differentiators)

| Property | Status |
|---|---|
| Single static binary, no runtime deps, `cargo install` | 🏗 (`usb4n6` builds & runs; `cargo install` at publish) |
| Library-embeddable (used by Issen / other fleet crates) | ✅ (this crate) |
| `#![forbid(unsafe_code)]`, panic-free (unwrap/expect denied) | ✅ |
| 100% line coverage gate | ✅ |
| Fuzzed at every parse boundary | 📋 (upstream reader crates + own adapters) |
| Validated against independent oracle on real images | 📋 |

---

The correlation **core** (source-agnostic: claims → consistency + provenance → findings)
is the highest-leverage work; every artifact row above becomes "add a `HistorySource`"
once it is solid. That is what is being built first.
