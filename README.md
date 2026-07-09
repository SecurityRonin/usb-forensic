# usb-forensic

**Status: design seed (research only, no code yet).** This repo captures the market
research and product thesis for a Windows USB-device forensics tool. It exists to hold
the decision to build before a line of code is written.

## What this would be

A **correlation engine** — headless, library-embeddable, reproducible — that reconstructs
USB-device connection history from every relevant Windows artifact and cross-correlates
the timestamps across sources, reporting each value as *consistent with* or *not
consistent with* the others so an examiner can tell a reliable first-connected time from a
partial or contradicted one. Built for pipelines and courtrooms, not a viewer window.

The framing matters: it is **not** a Windows-only GUI clone of USB Detective. It runs on
any OS to analyse Windows evidence at fleet scale, emits diffable JSONL, and can
**re-derive every reported value deterministically from the raw bytes** — a reproducibility
chain a closed binary cannot offer. That form factor is the wedge (see whitespace below).

USB history is a **multi-source artifact domain**, not a single-parser job. On Windows the
evidence is spread across:

- **Registry** — `USBSTOR`, `Enum\USB`, `MountedDevices` (SYSTEM); Windows Portable
  Devices / `WPDBUSENUM`, `VolumeInfoCache` (SOFTWARE); `MountPoints2` (NTUSER.DAT);
  `Amcache.hve` (execution/first-seen signal)
- **`Enum\SCSI`** — UASP / USB-3 drives (`uaspstor.sys`, Win8+) enumerate here, **not**
  under `USBSTOR`; a correlator reading only `USBSTOR` silently misses the modern drives
  most likely to matter in an exfiltration case
- **SetupAPI** device-install logs (`setupapi.dev.log`) — local time, no TZ marker
- **Event Logs** (including the Partition/Diagnostic log for volume serial numbers)
- **LNK files, jump lists, shellbags** — to link files opened and directories touched on
  the device

## Where it sits in the fleet

This is an **artifact-domain analyzer**, a layer above the data-source parsers. It would
**consume** them rather than reimplement them:

```
usb-forensic  (this repo)      ── correlates USB device history, scores timestamp consistency
   ├── consumes winreg-forensic (reg4n6)   ── hive parsing (USBSTOR, MountedDevices, …)
   ├── consumes an EVTX parser             ── Partition/Diagnostic event logs
   └── consumes an NTFS/LNK parser         ── setupapi.dev.log, LNK, shellbags
```

The forensic *knowledge* (which keys, which GUIDs, which fields, MITRE mapping) already
lives in [`forensicnomicon`](https://crates.io/crates/forensicnomicon)'s artifact catalog;
this tool would apply that knowledge, not restate it.

Keeping it separate from `winreg-forensic` is deliberate: `winreg-forensic` reads a
registry hive; it has no business parsing SetupAPI logs or LNK files. The dependency runs
one way (`usb-forensic` → `winreg-forensic`), so the boundary stays clean.

## Why build it — the whitespace (corrected)

Existing tools cluster at two ends: free single-source viewers (USBDeview, USB Historian)
and broad forensic suites (AXIOM, X-Ways) where USB history is one small module. The one
tool that specializes — [USB Detective](https://usbdetective.com/) — owns a real moat:
**per-source timestamp correlation with a consistency score, and per-value provenance**.
It is Windows-only, closed-source, GUI, and ~6 years mature.

An earlier draft of this thesis claimed we could go *cross-platform with the same
confidence model* and thereby be "better." A deep pressure-test (Fable 5) and an
adversarial critique (Codex) both rejected that. The honest picture:

**Not the wedge:**

1. **"Same confidence model on macOS/Linux" is illusory.** Consistency scoring only means
   something when several *independent, persistent* sources with different update semantics
   can be cross-checked — a Windows-specific property. macOS yields ~one strongly
   timestamped source (unified logs / USBMSC, **days-to-weeks retention**) plus name-only
   plists; Linux is effectively **single-source** (journald, retention-bound). With 1–2
   sources there is nothing to score against — a "consistency score" there is vacuous, and
   marketing it would be the exact overstatement this tool exists to detect.
2. **"Match USB Detective on Windows" is not a cheap phase 1.** The scoring *algorithm* is
   a weekend; the semantic model under it is the moat — per-build timestamp-rewrite quirks,
   `Enum\SCSI`/UASP coverage, Win10 30-day device-cleanup semantics, local-vs-UTC traps.
   Realistically **12–24 months of corpus-driven differential validation** before the
   scorer is trustworthy in casework.
3. **"Open-source = court-defensible" is narrow.** Courts have admitted closed tools
   (EnCase, FTK, Cellebrite) under Daubert for decades; source availability does not get
   you *admitted*. It makes *testimony* more defensible and the opponent's re-analysis
   cheaper — a practitioner's advantage, not a doctrinal one (and it hands the opposing
   expert your bug tracker).

**The actual wedge — structural, not feature gaps Hale can patch:**

1. **Form factor USB Detective cannot match without ceasing to be itself:** headless,
   library-embeddable, pipeline-native, diffable JSONL, running on any OS to analyse
   *Windows* evidence at fleet scale. Nothing in the open ecosystem does scored multi-source
   USB correlation as a CLI/library (RegRipper = raw plugins; USBFT = unscored GUI).
2. **Reproducibility by construction** — a `--reproduce` mode re-deriving every value from
   `hive → key → raw bytes → decoding rule`, hashable and runnable by the opposing expert.
   This is the durable half of "court-ready"; the PDF/DOCX *format* is a weekend feature
   anyone copies.
3. **The customer is the pipeline operator, not the GUI examiner** (the examiner has a free
   Community edition and zero switching pressure): Velociraptor/KAPE automation, labs
   processing images at scale, integration into the fleet's own parsers and
   `forensicnomicon` MITRE catalog. Smaller, quieter market — infrastructure, not a hero
   product.

Full landscape and sources: [`docs/competitive-landscape.md`](docs/competitive-landscape.md).

## Kill criteria — build only if none of these trip

1. **The 80%-clone trap.** Community edition is *free*; a 90%-of-Windows clone offers the
   examiner nothing. If the roadmap reads "match first, differentiate later," it dies in
   the matching phase with no users. The only viable sequencing is the **inverse**: ship
   the pipeline/library form factor first (zero incumbent there) with conservative,
   honest correlation, and let Windows depth accrete under differential test.
2. **No sustained validation corpus.** An unvalidated correlator here is a liability
   generator — a miscorrelation that flags a legitimate timestamp, in a report with your
   name on it, is worse than no tool. v1 must say "consistent with / not consistent with"
   and **refuse** definitive labels like "spoofed." Requires a maintained corpus of real
   images spanning XP→11 with documented ground truth (per the fleet test-data standard).
3. **Can't generalize past USB.** Rational only if this correlation engine is the fleet's
   **first general artifact-domain analyzer** (scored, provenance-carrying correlation that
   later covers execution, persistence, …), not a one-off USB tool.

Useful lever: **USB Detective Community edition is a free differential oracle** — run both
over the same evidence; every disagreement is either your bug or a documentable edge case,
converting Hale's moat into your test suite.

## Sharpest honest positioning

> The first USB-history correlation engine built for pipelines and courtrooms rather than a
> viewer window: USB Detective-grade Windows artifact depth, running headless on any OS at
> fleet scale, with every timestamp traceable to its raw bytes and every conclusion
> re-derivable by anyone — including the other side's expert.

## Next step

None committed. This is a seed. Before any code: (1) confirm the pipeline-operator demand
is real (talk to lab-automation / Velociraptor users, not GUI examiners); (2) commit to the
validation-corpus burden or don't start; (3) scope an MVP as the **library/CLI first** —
registry + SetupAPI + `Enum\SCSI` ingestion → conservative "consistent-with" correlation →
reproducible JSONL — against the fleet's pre-publish standards.
