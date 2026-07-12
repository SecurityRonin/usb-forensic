# Product Requirements Document: usb-forensic

*Status: pre-release (`publish = false`). This document describes what `usb-forensic`
is, who it serves, and what it must do. It separates what ships today from what is
planned. For the current capability-by-capability status, see
[`feature-parity.md`](feature-parity.md); for the build order, see
[`roadmap.md`](roadmap.md).*

## Executive Summary

USB device history is spread across a dozen Windows artifacts — registry keys,
SetupAPI logs, event logs, LNK files — plus whatever a macOS or Linux host retains.
Reconstructing "which stick was plugged in, when, by whom, and what files it touched"
means reading all of them and reconciling their timestamps. The established tools that
do this well are Windows-only GUIs. An analyst who wants to run the same analysis
headless, at fleet scale, inside a pipeline has no scored, provenance-tracking option.

`usb-forensic` is that option: a USB device-history **correlation engine**, not a
viewer. It ingests already-decoded USB artifacts from many sources, normalizes them
into source-agnostic claims — device, attribute, value, provenance — and scores how
well those claims agree across sources. Each device attribute is graded corroborated,
single-source, or conflicting, and the grade turns on **tamper-independence**: two
claims that live in the same hive share one tamper surface, so their agreement is not
independent evidence. The engine runs headless on macOS, Linux, and Windows, emits
pipeline-native JSONL by default, and keeps every value tied to the raw bytes it came
from so any party can re-derive it.

Two people need this. The DFIR analyst triaging USB exfiltration across a fleet needs
it headless and scriptable. The forensic examiner or expert witness needs every value
traceable to source and every conclusion reproducible by the opposing expert. The
product thesis, stated in the README and kept verbatim here: **the first USB-history
correlation engine built for pipelines and courtrooms rather than a viewer window —
USB Detective-grade Windows artifact depth, running headless on any OS at fleet scale,
with every timestamp traceable to its raw bytes and every conclusion re-derivable by
anyone, including the other side's expert.**

## The problem and who has it

USB history is a multi-source artifact domain. On Windows the same connection leaves
traces in the registry (`USBSTOR`, `Enum\USB`, `Enum\SCSI`, `MountedDevices`,
`VolumeInfoCache`, `MountPoints2`, `EMDMgmt`), in `setupapi.dev.log`, in the
Partition/Diagnostic and Kernel-PnP event logs, and in LNK files and jump lists. No
single artifact tells the whole story, and any one of them can be wrong — a boot-time
`USBSTOR` LastWrite rewrite looks like tampering to a naive reader; a UASP drive
enumerates under `Enum\SCSI` and is invisible to a `USBSTOR`-only tool.

Reconciling those sources by hand is slow and error-prone, and the tools that automate
it share three constraints:

- **GUI-bound.** The reference tools run interactively on Windows. They do not drop
  into a Velociraptor or KAPE pipeline, and they do not fan out across a fleet.
- **Correlation left to the analyst, or opaque when automated.** Free tools present
  each source in its own table and leave the cross-checking manual. The one tool that
  scores consistency does so behind a closed GUI.
- **Reporting for the eye, not the pipe.** Output is Excel or CSV — hard to diff,
  hard to pipe, hard to re-run.

The people this hurts are the DFIR analyst who wants to run USB triage the way they run
everything else (headless, in a pipeline, at scale) and the examiner who has to defend
each timestamp in a report that carries their name.

## Goals and non-goals

**Goals**

- Match or exceed the Windows artifact coverage of the dedicated USB-forensics tools,
  and add the pipeline and reproducibility properties none of them has.
- Score cross-source consistency per device attribute, weighting agreement by
  tamper-independence rather than by count of agreeing sources.
- Run headless and identically on macOS, Linux, and Windows.
- Keep every reported value tied to its source and locator so it can be re-derived.
- Report observations ("consistent with…"), never verdicts. The tool refuses labels
  like "spoofed."

**Non-goals**

- Acquisition and imaging. The tool consumes images and extracted artifacts; it does
  not acquire them.
- Live-agent deployment. It is a library and CLI, not an endpoint agent.
- Being a GUI viewer. The output is JSONL, tables, and reports, not an interactive
  window.

## Target users and their jobs

**DFIR analyst / incident responder.** Triaging possible USB exfiltration, often
across many hosts. The job is to answer "what devices touched these machines, when,
and what files moved" without opening a GUI per host. Needs headless operation, JSONL
that pipes into existing tooling, and findings tagged for triage.

**Forensic examiner / expert witness.** Building a court-defensible account of USB
activity on one machine. The job is to state each value, show where it came from, and
survive an opposing expert re-running the analysis. Needs per-value provenance,
reproducibility, and language that stays at the level of observation.

The two jobs share a spine — the same correlation core, the same claims, the same
provenance — and differ only in output: the analyst lives in JSONL and findings, the
examiner in the DOCX/PDF report.

## The correlation-and-consistency thesis

What separates this from a viewer is the model underneath it.

Every source, whatever its format, is normalized into a **claim**: a device, an
attribute, a value, and a provenance record naming the source and the byte-level
locator. Claims about the same device merge into one record. For each attribute, the
engine compares the claims and grades their agreement.

The grade turns on **tamper-independence**, not vote-counting. Each claim carries the
`ArtifactContainer` it lives in. Two claims sitting in the same registry hive share a
single tamper surface: if someone edited that hive, both move together, so their
agreement proves nothing about reliability. Agreement across *different* containers — a
volume serial that matches between the device media and the host SOFTWARE hive — is
independent corroboration. An attribute is graded:

- **corroborated** when tamper-independent sources agree,
- **single-source** when only one container speaks to it,
- **conflicting** when sources disagree.

This is why the tool can be conservative and defensible at once. It never asserts a
value is genuine; it reports how many independent surfaces vouch for it and lets the
examiner weigh that.

## Scope: shipped versus planned

The authoritative status is in [`feature-parity.md`](feature-parity.md), which tracks
every capability against the reference tools. The parity matrix currently stands at
**45 done, 13 remaining**. Remaining items are mostly blocked on a specific corpus or
an external oracle rather than on unwritten code; each is noted in the matrix and the
[roadmap](roadmap.md). What follows summarizes scope without duplicating that matrix.

### Shipped

**Source adapters (13).** `setupapi.dev.log`; registry `Enum\{USBSTOR,SCSI,USB}`;
`MountedDevices` (drive-letter join); `VolumeInfoCache` (labels); `MountPoints2`
(per-user mounts); `EMDMgmt` (ReadyBoost label/serial history); MTP-device detection;
Partition/Diagnostic event log; Kernel-PnP Configuration event log (device-install
events); device-image boot sectors (MBR/GPT partition parsing delegated to the
`disk-forensic` crate; FAT volume serial plus BitLocker, BitLocker To Go, and LUKS
detection); LNK; jump lists; Linux syslog/dmesg; macOS (`com.apple.iPod.plist`,
`system_profiler`/IORegistry, unified log).

**Correlation core.** Source-agnostic claims, cross-source timestamp comparison,
consistency grading by tamper-independence, per-value provenance retained end to end.

**Finding types (6).** `USB-DEVICE-HISTORY`, `USB-TIMESTAMP-CONFLICT`,
`USB-IMPOSSIBLE-ORDERING` (clock-rollback lead), `USB-MTP-DEVICE`,
`USB-VOLUME-ENCRYPTED`, `USB-VOLUME-REFORMATTED` (prior-serial).

**Output modes (8).** JSONL (default, pipeline-native), `--table`, `--timeline`
(aggregate super-timeline), `--files` (accessed-files report), `--export-mbr`,
`--report` (Markdown), `--docx`, `--pdf` (native court-report export).

### Planned

Tracked in [`feature-parity.md`](feature-parity.md) and [`roadmap.md`](roadmap.md).
The larger open items include the `--reproduce` chain (raw bytes → decoding rule per
value), `Amcache.hve`, ShellBags, additional event-log providers, Volume Shadow Copy
aggregation, registry transaction-log replay, deleted/removed-device recovery for
Windows 10 cleanup, OS-version-aware artifact semantics, and a differential mode that
runs the tool against USB Detective Community edition and RegRipper. Several depend on
sourcing a corpus or an oracle before they can be marked done.

## Requirements

### Functional

**Sources.** Ingest already-decoded USB artifacts through a per-source adapter that
emits normalized claims. Each new source is additive behind the source trait and does
not alter the audit surface. When a source contains an unrecognized value — an unknown
signature, filesystem, or provider — the tool surfaces the raw value and its offset,
not a bare "unknown."

**Correlation.** Merge claims into one record per device. Compare timestamps and
attributes across sources. Grade each attribute by tamper-independence, keying on the
`ArtifactContainer`. Join across sources on the identifiers the artifacts actually
share — MBR disk signature for the MountedDevices bridge, FAT volume serial for the
EMDMgmt/LNK join — not on values baked to a sample.

**Findings.** Emit `forensicnomicon` findings, MITRE-tagged, for the six finding types
above. Findings state observations. `USB-IMPOSSIBLE-ORDERING` reports a first-connect
after last-connect as a clock-rollback *lead*, not a proven event.

**Outputs.** Default to JSONL, one device history per line, every value carrying its
provenance. Provide table, timeline, files, MBR-export, Markdown, DOCX, and PDF modes.
Machine views stay faithful and round-trippable; human views render for reading.

### Non-functional

**Reproducibility.** Every reported value must be traceable to its source and locator
today; the planned `--reproduce` mode extends this to a deterministic, hashable
re-derivation from raw bytes that any party can re-run.

**Cross-OS.** The same binary runs headless on macOS, Linux, and Windows and produces
the same analysis of the same Windows evidence regardless of host OS.

**Panic-free and memory-safe.** Rust with `#![forbid(unsafe_code)]`; the workspace
denies `unwrap` and `expect` in production. Raw parsers are fuzzed with cargo-fuzz.
The library carries a 100% line-coverage gate. The app targets MSRV 1.96; the reader
and knowledge crates hold a low MSRV.

**Court-defensibility.** Output stays at the level of observation. The tool reports
"consistent with" / "not consistent with" and refuses definitive tamper labels. Every
value shows its source chain.

## Validation requirements

Correctness is proven against an **independent oracle on real data**, never against
fixtures the project authored (Evidence-Based Rigor, tier 1). A correlator that
miscorrelates is worse than none: a legitimate timestamp flagged "suspicious," or a
spoofed one blessed, in a report with the examiner's name on it.

Current validation posture, detailed in [`validation.md`](validation.md):

- **Real-world corpora with ground truth.** The NIST CFReDS Data-Leakage case
  (device-image path) and Stolen Szechuan Sauce (registry hive plus Kernel-PnP `.evtx`)
  supply documented device histories to score against. macOS sources are validated on
  real devices.
- **Independent oracles per source.** regipy for registry values, python-evtx for
  event logs, the CFReDS answer key, a `system_profiler` cross-check for macOS, a
  Python epoch oracle for timestamps, python-docx for the DOCX export.
- **Spec-defined detection rules.** BitLocker signature, MTP classification, and
  reformatting detection are defined by their specifications and validated with a
  real-data non-false-positive control (for example, the FAT CFReDS stick is *not*
  flagged encrypted).

No capability is marked done in the parity matrix until it is implemented and validated
this way.

## Out of scope

Stated plainly so the boundary is unambiguous:

- **Acquisition and imaging.** The tool reads images and extracted artifacts. It does
  not create them.
- **Live-agent deployment.** It is a library and CLI, not a resident endpoint agent.
- **GUI viewer.** There is no interactive window; output is JSONL, tables, and reports.

## Open questions and risks

- **Validation corpus is the gating risk.** Several remaining parity items are blocked
  on sourcing a corpus or oracle, and the consistency scorer should not ship broadly
  without a maintained XP-through-11 image corpus with documented ground truth. An
  unvalidated correlator is a liability generator.
- **The 80%-clone trap.** A free-Community clone of a Windows GUI wins no examiners.
  The roadmap's inversion — ship the pipeline/library form factor first, let Windows
  depth accrete under differential test — is a deliberate hedge against this, and each
  phase boundary re-checks it.
- **Cross-platform scoring is not symmetric.** macOS and Linux retain too few
  independent, persistent sources to support a Windows-style consistency score. The
  cross-platform modules report timestamped events with explicit retention windows and
  do not fabricate a score the sources cannot back. Overstating this would be
  self-refuting for a consistency-scoring tool.
- **Generalization beyond USB.** The engine is rational as the fleet's first general
  artifact-domain correlator. If it cannot generalize past USB, the investment is a
  one-off.
