# usb-forensic

[![CI](https://github.com/SecurityRonin/usb-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/usb-forensic/actions)
[![Rust 1.81+](https://img.shields.io/badge/rust-1.81%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**The first USB-history correlation engine built for pipelines and courtrooms rather than a viewer window — USB Detective-grade Windows artifact depth, running headless on any OS at fleet scale, with every timestamp traceable to its raw bytes and every conclusion re-derivable by anyone, including the other side's expert.**

> **Status: pre-code design seed.** This repo is scaffolded to the SecurityRonin fleet
> standard (CI, panic-free lints, supply-chain gates, MkDocs docs) but carries **no
> correlation logic yet**. It holds a validated, adversarially-pressure-tested product
> thesis and a build plan. `Cargo.toml` sets `publish = false` until the first Phase 1
> feature lands under TDD; the crates.io / docs.rs / coverage badges join the row at
> first publish. Code is filled in one source and one finding at a time.

## What this is

A thin **orchestration / correlation** crate — it parses no raw format itself. It
consumes the fleet's already-built reader crates, normalizes their output into one
uniform USB-device-history event, and cross-correlates the timestamps across sources,
reporting each value as *consistent with* or *not consistent with* the others so an
examiner can tell a reliable first-connected time from a partial or contradicted one.

USB history is a **multi-source artifact domain**, not a single-parser job. On Windows
the evidence is spread across:

- **Registry** — `USBSTOR`, `Enum\USB`, `MountedDevices` (SYSTEM); Windows Portable
  Devices / `WPDBUSENUM`, `VolumeInfoCache` (SOFTWARE); `MountPoints2` (NTUSER.DAT);
  `Amcache.hve` (execution / first-seen signal)
- **`Enum\SCSI`** — UASP / USB-3 drives (`uaspstor.sys`, Win8+) enumerate here, **not**
  under `USBSTOR`; a correlator reading only `USBSTOR` silently misses the modern drives
  most likely to matter in an exfiltration case
- **SetupAPI** device-install logs (`setupapi.dev.log`) — local time, no TZ marker
- **Event Logs** (the Partition/Diagnostic log for volume serial numbers)
- **LNK files, jump lists, shellbags** — files opened and directories touched on the device

## Where it sits in the fleet

An **artifact-domain analyzer**, a layer above the data-source parsers — it **consumes**
them rather than reimplement them, and emits `forensicnomicon::report::Finding`s that
Issen renders alongside every other analyzer.

```
usb-forensic  ── correlates USB device history, scores cross-source timestamp consistency
   ├── consumes winreg-artifacts  ── USBSTOR / MountedDevices / WPDBUSENUM / Amcache / …
   ├── consumes peripheral-core   ── setupapi.dev.log device-install events
   ├── consumes winevt-forensic   ── Partition/Diagnostic event log (volume serials)
   └── consumes lnk-core          ── recent-file LNK volume-serial join
```

It is the deep, USB-specific sibling of
[`useract-forensic`](https://github.com/SecurityRonin/useract-forensic): that crate
treats a device connection as one input to a broad user-activity timeline;
`usb-forensic` is the focused consistency-scoring engine for the USB domain itself.

## Why build it — the whitespace (adversarially pressure-tested)

The reference product is [USB Detective](https://usbdetective.com/): Windows-only,
closed-source, GUI, ~6 years mature. Its moat is **cross-source timestamp consistency
scoring + per-value provenance** — the defensibility an expert witness needs.

An earlier draft of this thesis claimed we could go *cross-platform with the same
confidence model* and be "better." A deep analysis (Fable 5) and a hostile critique
(Codex) both rejected that. What survives:

**Rejected — not the wedge:**

1. **"Same confidence model on macOS/Linux" is illusory.** Consistency scoring needs
   several *independent, persistent* sources with different update semantics to
   cross-check — a Windows-specific property. macOS ≈ one strongly timestamped source
   (unified logs / USBMSC, days-to-weeks retention) plus name-only plists; Linux ≈
   single-source journald. With 1–2 sources there is nothing to score against.
2. **"Match USB Detective on Windows" is not a cheap phase 1.** The scoring *algorithm*
   is a weekend; the semantic model under it (per-build timestamp-rewrite quirks,
   `Enum\SCSI`/UASP coverage, Win10 30-day cleanup, local-vs-UTC traps) is ~12–24 months
   of corpus-driven differential validation.
3. **"Open-source = court-defensible" is narrow.** Courts admit closed tools under
   Daubert routinely; source availability aids *testimony*, not admissibility (and it
   hands the opposing expert your bug tracker).

**The actual wedge — structural, not feature gaps the incumbent can patch:**

1. **Form factor USB Detective cannot match without ceasing to be itself:** headless,
   library-embeddable, pipeline-native, diffable JSONL, running on any OS to analyse
   *Windows* evidence at fleet scale. Nothing open does scored multi-source USB
   correlation as a CLI/library (RegRipper = raw plugins; USBFT = unscored GUI).
2. **Reproducibility by construction** — a `--reproduce` mode re-deriving every value
   from `hive → key → raw bytes → decoding rule`, hashable and runnable by the opposing
   expert. The durable half of "court-ready"; the PDF/DOCX *format* is a weekend feature.
3. **The customer is the pipeline operator, not the GUI examiner** (who has a free
   Community edition and zero switching pressure): lab automation, Velociraptor/KAPE,
   fleet integration. Smaller, quieter market — infrastructure, not a hero product.

Full landscape, sources, and competitor matrix:
[`docs/competitive-landscape.md`](docs/competitive-landscape.md). Build sequence:
[`docs/roadmap.md`](docs/roadmap.md).

## Kill criteria — build only if none of these trip

1. **The 80%-clone trap.** Community edition is free; a 90%-of-Windows clone offers the
   examiner nothing. The only viable sequencing is the **inverse**: ship the
   pipeline/library form factor first (zero incumbent there), let Windows depth accrete
   under differential test.
2. **No sustained validation corpus.** An unvalidated correlator is a liability
   generator — a miscorrelation that flags a legitimate timestamp, in a report with the
   examiner's name on it, is worse than no tool. v1 must say "consistent with / not
   consistent with" and **refuse** "spoofed." Requires a maintained XP→11 image corpus
   with documented ground truth.
3. **Can't generalize past USB.** Rational only as the fleet's **first general
   artifact-domain correlation engine**, not a one-off USB tool.

Useful lever: **USB Detective Community edition is a free differential oracle** — run
both over the same evidence; every disagreement is either a bug or a documentable edge
case, converting the incumbent's moat into the test suite.

## Trust, but verify

`#![forbid(unsafe_code)]`, panic-free (the workspace denies `unwrap`/`expect` in
production), and gated on 100% library line coverage. The correlation logic will be
validated **differentially against an independent oracle** (USB Detective Community
edition, RegRipper) on real disk images — see
[`docs/validation.md`](docs/validation.md). Findings are **observations**, never
verdicts: "consistent with …", the examiner draws the conclusions.

---

[Privacy Policy](https://securityronin.github.io/usb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/usb-forensic/terms/) · © 2026 Security Ronin Ltd
