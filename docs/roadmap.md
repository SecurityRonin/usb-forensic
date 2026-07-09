# Roadmap

`usb-forensic` is the USB device-history correlation engine. Its power grows with
every source it can cross-check. Each source slots in behind an `HistorySource`-style
trait — purely additive, with no breaking change to the audit surface.

The sequencing is deliberate and **inverts the obvious "clone USB Detective first"
plan** (see the [competitive landscape](competitive-landscape.md) for why). The wedge
is the form factor — headless, reproducible, pipeline-native — so that ships first
with conservative correlation, and Windows depth accretes underneath it under
differential test.

## Phase 1 — the library/CLI wedge (form factor first)

Ship the thing USB Detective structurally cannot be, before the thing it already is.

| Source | Reader crate | Produces |
|---|---|---|
| `USBSTOR` / `Enum\USB` / `MountedDevices` | [`winreg-artifacts`](https://crates.io/crates/winreg-artifacts) | device id, serial, VID/PID, first/last-connected candidates |
| `Enum\SCSI` (UASP / USB-3 drives) | `winreg-artifacts` | the modern drives that never appear in `USBSTOR` |
| `WPDBUSENUM` / `VolumeInfoCache` / `MountPoints2` | `winreg-artifacts` | volume names, per-user mount points |
| `Amcache.hve` | `winreg-artifacts` | execution / first-seen corroboration |
| `setupapi.dev.log` | [`peripheral-core`](https://crates.io/crates/peripheral-core) | first-install time (local-time, TZ-normalized) |

Deliverables: normalized event + timeline; **conservative** correlation that reports
`consistent with` / `not consistent with` across sources and **refuses** definitive
labels like "spoofed"; diffable JSONL output; a `--reproduce` mode that re-derives
every value deterministically from the raw bytes.

## Phase 2 — Windows depth (match under differential test)

| Source | Reader crate | Adds |
|---|---|---|
| Partition/Diagnostic event log | [`winevt-forensic`](https://crates.io/crates/winevt-forensic) | volume serials with independent timestamps to cross-check |
| Recent-file LNK | [`lnk-core`](https://crates.io/crates/lnk-core) | the `VolumeID` `DriveSerialNumber` join — files opened on the device |
| Registry transaction-log replay | (fleet hive layer) | records not yet flushed to the primary hive |
| Volume Shadow Copy aggregation | (fleet `[H]` layer) | historical states, de-duplicated across snapshots |

This is where the semantic model earns its keep: per-build timestamp-rewrite quirks,
Win10 30-day device-cleanup semantics, deleted/removed-device recovery. Validated
differentially against **USB Detective Community edition** and **RegRipper** on real
images — every disagreement is either a bug or a documented edge case.

## Phase 3 — cross-platform *runtime* (honest, not overstated)

Analyze Windows evidence from any OS at fleet scale (the runtime USB Detective cannot
match). Per-OS *evidence* modules for macOS/Linux report what those systems actually
retain — a timestamped event list with **explicit retention windows** — and do **not**
claim the Windows consistency score where the sources cannot support it (macOS ≈ one
timestamped source with days-to-weeks retention; Linux ≈ single-source journald). A
consistency-scoring tool whose own marketing overstates would be self-refuting.

## Kill criteria (revisit at every phase boundary)

1. **The 80%-clone trap** — a free-Community clone wins no examiners; if Phase 1
   slips toward "just match USB Detective," stop and re-scope to the form-factor wedge.
2. **No sustained validation corpus** — an unvalidated correlator is a liability
   generator; without a maintained XP→11 image corpus with documented ground truth,
   do not ship the scorer.
3. **Can't generalize past USB** — rational only if this becomes the fleet's first
   general artifact-domain correlation engine, not a one-off.
