# usb-forensic

[![CI](https://github.com/SecurityRonin/usb-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/usb-forensic/actions)
[![Rust 1.96+](https://img.shields.io/badge/rust-1.96%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**The first USB-history correlation engine built for pipelines and courtrooms rather than a viewer window — USB Detective-grade Windows artifact depth, running headless on any OS at fleet scale, with every timestamp traceable to its raw bytes and every conclusion re-derivable by anyone, including the other side's expert.**

> **Status: pre-release.** The correlation core and **13 source adapters** run and are
> tested — every Windows registry source (`Enum\{USBSTOR,SCSI,USB}`, `MountedDevices`,
> `VolumeInfoCache`, `MountPoints2`, `EMDMgmt`), `setupapi.dev.log`, the Partition/Diagnostic
> and Kernel-PnP event logs, device-image boot sectors (MBR/GPT via `disk-forensic`; FAT
> serial + BitLocker/BitLocker-To-Go/LUKS), LNK, jump lists, Linux `syslog`, and macOS
> (iPod plist, `system_profiler`, unified log). Output is JSONL, `--table`, `--timeline`,
> `--files`, `--report`, `--docx`, and `--pdf`; six `forensicnomicon` finding types.
> Correctness is Tier-1 validated against independent oracles on real corpora (NIST CFReDS,
> Stolen Szechuan Sauce, real macOS devices) — see [`docs/validation.md`](docs/validation.md).
> The parity matrix stands at **45 done / 13 remaining** ([`docs/feature-parity.md`](docs/feature-parity.md)),
> the remaining items mostly blocked on a specific corpus or oracle. `Cargo.toml` keeps
> `publish = false` until the differential (USB Detective / RegRipper) corpus lands;
> crates.io / docs.rs / coverage badges join then.

## Run it

```console
$ usb4n6 path/to/setupapi.dev.log path/to/RecentItem.lnk
{"device":"7&12a3b4c5&0&0000","attributes":[{"attribute":"FirstConnected","consistency":"SingleSource","values":[{"value":{"Timestamp":1681760520},"provenance":{"source":"SetupApi","locator":"setupapi.dev.log:27"}}]}]}
{"device":"DEAD-BEEF","attributes":[{"attribute":"AccessedFile","consistency":"SingleSource","values":[{"value":{"Text":"E:\\payload.exe"},"provenance":{"source":"Lnk","locator":"RecentItem.lnk"}}]}]}
usb4n6: 6 device(s) from 6 source record(s), 0 finding(s)
```

Each device history is one JSONL object carrying every value with its source and
locator; findings (cross-source conflicts and corroborations) print to stderr.

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
them rather than reimplement them (see [ADR 0002](docs/decisions/0002-delegate-parsing-to-fleet-crates.md)),
and emits `forensicnomicon::report::Finding`s that Issen renders alongside every other analyzer.
It correlates USB device history and scores cross-source timestamp consistency on top of:

- **`peripheral-core`** — `setupapi.dev.log`, the SYSTEM-hive `Enum\{USBSTOR,SCSI,USB}` +
  `MountedDevices` device keys, and Linux kernel-log USB events
- **`winevt-extract`** — the Partition/Diagnostic and Kernel-PnP Configuration event logs
- **`disk-forensic`** — device-image partition/filesystem parsing (MBR/GPT), with `ewf` for
  E01 images
- **`lnk-core`** — recent-file LNK and jump-list volume-serial joins
- **`winreg-core`** — opens SOFTWARE / NTUSER hives for the `VolumeInfoCache`, `MountPoints2`,
  and `EMDMgmt` readers; **`plist`** for the macOS `com.apple.iPod.plist`

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
production), raw parsers fuzzed with cargo-fuzz, and gated on 100% library line coverage.
Correctness is proven against **independent oracles on real data** — NIST CFReDS
(device-image), Stolen Szechuan Sauce (registry hive + Kernel-PnP event log, via regipy /
python-evtx), and real macOS devices — each labelled by evidence tier in
[`docs/validation.md`](docs/validation.md). A broader **differential** against USB Detective
Community edition and RegRipper is the remaining validation step before release. Findings are
**observations, never verdicts** — "consistent with …", with the epistemic limit stated as a
property of the evidence.

---

[Privacy Policy](https://securityronin.github.io/usb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/usb-forensic/terms/) · © 2026 Security Ronin Ltd
