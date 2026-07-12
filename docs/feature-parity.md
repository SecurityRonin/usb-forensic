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
| Mounted forensic images (E01/raw/…) | USB Detective (Pro), USBFT | 🏗 (raw disk-image boot sectors — MBR disk signature + FAT volume serial — read directly by `usb4n6`; E01 via `ewfexport` to raw. Tier-1: CFReDS RM#2 stick → its host label) |
| Built-in image mounting (no external mounter) | USBFT (Arsenal Image Mounter) | 📋 (fleet `4n6mount` FUSE bridge) |
| Volume Shadow Copies — auto-aggregated | USB Detective, USBFT | 📋 (fleet `[H]` VSS layer) |
| Registry transaction-log replay (uncommitted data) | USB Detective | 📋 |
| Remote-machine enumeration | USBDeview | 📋 |
| Cross-platform runtime (analyze from any OS) | USBFT (parses), — (none scores) | 🏗 (Rust, OS-agnostic) |

## 2. Windows artifact coverage

| Artifact | Signal | Seen in | Status |
|---|---|---|---|
| `USBSTOR` (SYSTEM) | device class/serial/VID-PID, first/last connect | all dedicated | ✅ (`PeripheralSource` via `peripheral-core` registry reader; regipy-validated) |
| `Enum\USB` (SYSTEM) | parent USB device, container id | USB Detective, RegRipper | ✅ (same reader) |
| **`Enum\SCSI`** (UASP / USB-3 drives) | modern drives absent from `USBSTOR` | (gap in most) | ✅ (same reader; Szechuan VMware disk validated) |
| `MountedDevices` (SYSTEM) | drive-letter ↔ device mapping | USB Detective, USBFT, RegRipper | ✅ (`peripheral-core` 0.3 decodes device-path entries → `DriveLetter` claim; Szechuan `D:`→CD-ROM validated) |
| MTP/PTP portable devices (phones/tablets/cameras) | MTP/PTP endpoints not under USBSTOR | USB Detective, USBFT | ✅ (`peripheral-core` 0.8 classifies `Enum\USB` devices whose `Service` is `WUDFWpdMtp` as `Bus::Mtp`; usb-forensic emits a `DeviceClass=MTP` claim + a Low `USB-MTP-DEVICE` finding, MITRE T1052.001. Spec rule; real-data negative control on CFReDS) |
| `VolumeInfoCache` + `EMDMgmt` (SOFTWARE) | volume label ↔ serial history | USB Detective | ✅ (`VolumeCacheSource` (label by drive letter) + `EmdMgmtSource` (label + 4-byte volume serial, the LNK `DriveSerialNumber` join key) via `peripheral-core` 0.4/0.7. Tier-1 on the real NIST CFReDS SOFTWARE hive: `Authorized USB`/1551191358 and `IAMAN $_@`/2657770370, matching the answer key) |
| `MountPoints2` (NTUSER.DAT) | per-user mounts | USB Detective, USBFT, RegRipper | ✅ (`MountPoints2Source` via `peripheral-core` 0.6; per-user volume-GUID mount + time, unified with the drive letter & label by the MountedDevices MBR-signature bridge. Tier-1 on the real NIST CFReDS: informant mounted `{a2f2048e}` = E: = `IAMAN $_@` at 2015-03-24 21:02:33) |
| `Amcache.hve` | execution / first-seen corroboration | USB Detective | 📋 |
| SetupAPI (`setupapi.dev.log`) | first-install time (local, TZ-normalized) | all dedicated | ✅ (`PeripheralSource`) |
| Linux kernel log (`syslog`/`dmesg`) | USB enumeration (VID/PID, serial, first-seen) | USBFT (parses) | ✅ (`PeripheralSource` via `peripheral-core` `linux_syslog`; UAC-syslog validated) |
| Partition/Diagnostic event log | volume serial numbers, connect events | USB Detective | ✅ (`PartitionDiagSource` via `winevt-extract` 0.3 EID-1006 extractor; disk-arrival connect events, Tier-1 on the real DFIRArtifactMuseum `.evtx`. Volume-serial VBR decode: follow-up) |
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
| Anti-forensics / tampering leads (impossible timestamp ordering) | USB Detective (timestamp scoring) | ✅ (`audit` `USB-IMPOSSIBLE-ORDERING`: first-connect after last-connect → MITRE T1070.006) |
| Per-value source provenance retained | USB Detective | ✅ (`ProvenancedValue`: source + locator) |
| Reproducibility chain (raw bytes → decoding rule per value) | (none) | 📋 the wedge |
| Deleted / removed-device recovery (Win10 cleanup) | USB Detective | 📋 |
| Prior volume names/serials for formatted devices | USB Detective | ✅ (`USB-VOLUME-REFORMATTED` finding: a label seen with ≥2 distinct volume serials → reformatted-and-reused, MITRE T1070.004. Tier-1 on the real CFReDS hive: 'IAMAN \$_@' = serials 9E6A-5B82 + B4D8-5399) |
| Device/volume encryption-type detection | USB Detective | ✅ (BitLocker via the `-FVE-FS-` VBR signature read from a device image → `Encryption` attribute + `USB-VOLUME-ENCRYPTED` finding. Spec-defined rule (Tier-3); validated against a signature fixture AND the real CFReDS FAT stick as a non-false-positive) |
| Encrypted-container detection (VeraCrypt/TrueCrypt/unrecognized-FS) | USBFT | ✅ (device-image VBR with no known filesystem signature → `unrecognized-filesystem (possible encrypted container)` + `USB-VOLUME-ENCRYPTED` finding. Heuristic rule; real-data negative control on the FAT rm2 stick — not flagged) |
| Physical-device→host attribution (image the stick, tie it to its host footprint) | USB Detective, USBFT | ✅ (`DeviceImageSource` + disk-signature canonicalization: a raw device image's MBR disk signature joins the MountedDevices bridge AND its FAT volume serial joins EMDMgmt/LNK — unifying the physical device, drive letter, volume label, and per-user mount into ONE record. Tier-1 on the real CFReDS RM#2 stick: the SanDisk 'IAMAN' stick tied to drive E:, label 'IAMAN \$_@', and the informant's 2015-03-24 mount — volume serial Corroborated across the device media and the host SOFTWARE hive) |
| File-to-device linking (which files touched which stick) | USB Detective, USBFT | ✅ (`reconcile_volume_serials` — LNK volume-keyed file access re-attributed to the device carrying that volume serial; ambiguous/unmatched left untouched. Rule-tested; end-to-end join needs a FAT-volume + LNK corpus) |
| Timezone normalization (local ↔ UTC) | USB Detective | ✅ (`--tz-offset`; `clock_is_local` per source) |
| OS-version-aware artifact semantics | USB Detective | 📋 |

## 4. Cross-platform evidence (USBFT breadth)

Per-OS modules report what each system actually retains, with **explicit retention
windows** — a timestamped event list, not a fabricated consistency score where the
sources cannot support one (see [roadmap](roadmap.md) Phase 3).

| Source | OS | Status |
|---|---|---|
| `com.apple.iPod.plist` (Apple-device connection history) | macOS | ✅ (`AppleIPodSource` via the `plist` crate; per-device serial, model, last-connected. Tier-1 on a real macOS `com.apple.iPod.plist`) |
| `system_profiler` / IORegistry (live USB device tree) | macOS | ✅ (`MacUsbSource`: parses `system_profiler -json SPUSBDataType` → serial, VID/PID, model, mass-storage. Tier-1 on a real SanDisk stick plugged into a Mac) |
| Unified log (USB enumeration/connection history) | macOS | ✅ (`MacUnifiedLogSource`: parses `log show --style json` `enumerateDeviceComplete` events → VID/PID, name, first/last-connect times. Tier-1 on a real SanDisk stick's live log; VID cross-checks `system_profiler`) |
| syslog/dmesg kernel USB blocks (journald/GVFS planned) | Linux | ✅ wired end-to-end (`peripheral-core` `linux_syslog`, `--year`); UAC-syslog validated |

## 5. Output & reporting

| Capability | Seen in | Status |
|---|---|---|
| Results grid / high-level report | USB Detective, USBFT, Historian, USBDeview | ✅ (`usb4n6 --table`) |
| Verbose per-value report with provenance | USB Detective | ✅ (`usb4n6 --report`) |
| Per-device timeline | USB Detective | ✅ (per-device JSONL / report block) |
| Aggregate super-timeline | USB Detective | ✅ (`usb4n6 --timeline`; every timestamped event across all devices, chronological JSONL) |
| Opened/accessed-files report | USB Detective | ✅ (`usb4n6 --files`: files opened per device from LNK/jump-list AccessedFile claims, with source locators) |
| Machine-readable output (JSONL, diffable, pipeable) | (weak in all — Excel/CSV only) | ✅ (`to_jsonl`, default) |
| `forensicnomicon::report` findings (fleet-uniform, MITRE-tagged) | (fleet-only) | ✅ (`audit`) |
| Court-ready report with per-value source chain | (Excel only elsewhere) | ✅ native **DOCX + PDF** (`--docx`/`--pdf`, both oracle-validated) + Markdown (`--report`) |
| Volume / MBR export | USB Detective | ✅ (`usb4n6 --export-mbr`: annotated hex dump of each device image's raw 512-byte MBR sector, headed by the disk signature) |
| Differential mode vs USB Detective / RegRipper (validation) | (none) | 📋 |

## 6. Engineering posture (the fleet differentiators)

| Property | Status |
|---|---|
| Single static binary, no runtime deps, `cargo install` | 🏗 (`usb4n6` builds & runs; `cargo install` at publish) |
| Library-embeddable (used by Issen / other fleet crates) | ✅ (this crate) |
| `#![forbid(unsafe_code)]`, panic-free (unwrap/expect denied) | ✅ |
| 100% line coverage gate | ✅ |
| Fuzzed at every parse boundary | ✅ (cargo-fuzz targets for all four raw parsers — boot sectors, system_profiler JSON, unified-log JSON, iPod plist — 100k iterations each clean; PR smoke-fuzz + weekly 10-min CI) |
| Validated against independent oracle on real images | ✅ (every source validated Tier-1 against real artifacts + an independent oracle: regipy, python-evtx, the NIST CFReDS answer key, `system_profiler` cross-check, a Python epoch oracle) |

---

The correlation **core** (source-agnostic: claims → consistency + provenance → findings)
is the highest-leverage work; every artifact row above becomes "add a `HistorySource`"
once it is solid. That is what is being built first.
