# Validation

A USB-history correlator that miscorrelates is worse than none — a legitimate timestamp
flagged "suspicious," or a spoofed one blessed, in a report with the examiner's name on it.
Correctness is therefore proven against an **independent oracle on real data**, never against
fixtures the project authored. Each claim below is labelled by *who confirms it* (the
[Evidence-Based Rigor](https://en.wikipedia.org/wiki/Reproducibility) tiers): **tier 1** — a
third party authored the artifact and the answer key, or it is real-world data; **tier 2** —
real engine/oracle output whose ground truth is derivable from the documented construction;
**tier 3** — a spec-defined detection rule whose correctness is defined by the specification.

## Results by source

| Artifact / source | Corpus (real) | Independent oracle | Result | Tier |
|---|---|---|---|---|
| Device-image boot sectors | NIST **CFReDS** Data-Leakage "RM#2" SanDisk stick | CFReDS answer key + raw boot-region extraction + a synthesized E01 (`ewfacquire`) | Disk signature `E221034C`, FAT volume serial `B4D8-5399`, encryption `None`; the FAT stick is **not** false-flagged encrypted | 1 |
| Registry `Enum\{USBSTOR,SCSI,USB}` | **Stolen Szechuan Sauce** `SYSTEM` hive | **regipy** (per-key value cross-check) | Device instance keys + install/first-install/last-arrival/last-removal `FILETIME`s decoded; a Windows-7 device-property `FILETIME` bug was caught against the CFReDS Win7 hive and fixed | 1 |
| Kernel-PnP Configuration event log | **Stolen Szechuan Sauce** `Microsoft-Windows-Kernel-PnP%4Configuration.evtx` (DFIRArtifactMuseum, MIT) | **python-evtx** (libyal) | SanDisk Cruzer Glide `USB\VID_0781&PID_5597\4C530000261130109435` + its USBSTOR disk layer → `LastConnected` `1600490202` (2020-09-19 04:36:42 UTC), keyed by the same serial the registry source uses; root hubs excluded | 1 |
| Partition/Diagnostic event log | DFIRArtifactMuseum `Microsoft-Windows-Partition%4Diagnostic.evtx` | **python-evtx** | 22 disk-arrival (EID 1006) events parsed; adapter mapping validated. *Caveat:* every event in this corpus is `BusType=3` (ATA), so the USB-device path is not Tier-1-validatable here — event parsing and mapping are | 1 (parsing) |
| Linux `syslog` / `dmesg` | UAC-collected syslog | Line-level cross-read | USB enumeration events decoded to connection records | 1 |
| macOS `com.apple.iPod.plist`, `system_profiler`/IORegistry, unified log | A real SanDisk stick + live Mac | `system_profiler` live cross-check | Apple-device history + USB device tree + unified-log connection events decoded on real device data | 1 |
| Timestamp epoch conversion | — | Python epoch oracle | `FILETIME`/ISO-8601 → epoch-seconds UTC confirmed against an independent computation | 2 |
| DOCX court-report export | setupapi + LNK evidence | **python-docx** + Python `zipfile` | Valid stored-ZIP, every entry passes CRC-32, three OOXML parts present, python-docx reads the report paragraphs and per-value provenance lines | 2 |

## Detection rules (tier 3 — spec-defined)

These classify rather than decode a value, so correctness is defined by the specification, not
an oracle. Each is validated against a spec-faithful input **and** a real-data non-false-positive
control:

- **BitLocker / BitLocker To Go / LUKS** — libbde *BDE format* (fixed-drive `-FVE-FS-`
  signature; the identifier GUID `4967D63B-…` scanned for To Go). Non-false-positive control:
  the real CFReDS FAT32 stick is **not** flagged encrypted. See
  [ADR 0004](decisions/0004-bitlocker-to-go-detection.md).
- **MTP-device classification** — the WPD/MTP service signature.
- **Reformatting / prior-serial** — a device whose `EMDMgmt` history carries more than one
  volume serial; validated Tier-1 on the CFReDS "IAMAN" stick (two serials).
- **Impossible-ordering** (`USB-IMPOSSIBLE-ORDERING`) — earliest FirstConnected strictly after
  latest Last* on one device; a conservative, false-positive-free clock-rollback *lead*.

## Reconciliation discipline

For each artifact: run the oracle, run `usb-forensic`, reconcile **counts and contents**, and
explain every divergence in writing. A divergence is a finding — a bug to fix or a real-world
quirk to document (a UASP drive under `Enum\SCSI` that a `USBSTOR`-only tool misses; a
boot-time `USBSTOR` LastWrite rewrite a naive comparison would flag as tampering).

## Planned differential

Not yet run (tool-/corpus-blocked, tracked in [`feature-parity.md`](feature-parity.md)):

- **USB Detective Community edition** — run both over the same evidence; every disagreement is
  our bug or a documented edge case. Blocked on installing USB Detective (Windows-only).
- **RegRipper** (`usbstor`, `mountdev`, `mountpoints2`, …) — per-key differential across a
  broader hive corpus.
- A maintained **Windows XP-through-11 image corpus** with documented ground truth, to score
  the consistency grader at breadth before broad release.

## Corpus provenance

Test artifacts and their provenance (source, hash, license, which test consumes them) are
catalogued per the fleet test-data provenance standard; large images are gitignored and
downloaded, small clearly-licensed fixtures committed. Real, ground-truth-bearing data is
preferred; synthetic fixtures are used only for adversarial edge cases real corpora lack
(truncation, lying counts, offset overflow).
