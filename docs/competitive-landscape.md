# Competitive Landscape: Windows USB-Device Forensics

*Point-in-time market research, July 2026. Pricing and feature claims drift; re-verify
before quoting a figure to a client. Claims are tiered by source: vendor site
(authoritative for that vendor's features/pricing), reputable secondary (DFIR blogs,
comparisons), or inference (flagged inline).*

## Executive Summary

The reference tool to beat is [USB Detective](https://usbdetective.com/): a niche,
Windows-only commercial product that reconstructs USB connection history from every
relevant Windows artifact and **cross-correlates the timestamps, colour-coding their
consistency** so an examiner can judge reliability. It sits between free single-source
viewers (USBDeview, USB Historian) and the broad suites (AXIOM, X-Ways) that treat USB
history as one small module. Its closest real competitors are **USB Forensic Tracker
(USBFT)** — free, broader source/OS coverage, faster, but no confidence scoring — and, to
a lesser degree, **USB Historian**. Against the big suites it wins on depth and
timestamp-defensibility but loses on breadth.

**Pricing caveat up front:** USB Detective Professional has **no public price** (routes to
an Avangate checkout, enterprise/LE quotes on request). The suite prices below are
directional from market write-ups, not vendor-confirmed. The free tools are confirmed
free.

## USB Detective — the reference product

**What it is** — a dedicated Windows USB-device forensics application by **Jason Hale**
(author of the df-stream.com DFIR blog). GUI tool. Processes artifacts from Windows XP
through Windows 11.
([usbdetective.com](https://usbdetective.com/),
[df-stream intro](https://df-stream.com/2018/03/usb-detective/),
[F-Response interview](https://www.f-response.com/blog/usb-detective-interview-jason-hale))

**Input modes** — live system; individual files/folders; logical drives (excluding C: in
Community); and (Professional) mounted forensic images and Volume Shadow Copies.

**Artifacts parsed** (vendor-authoritative, from the [features page](https://usbdetective.com/features/)):

- Registry: **SYSTEM** (USBSTOR, `Enum\USB`, MountedDevices), **SOFTWARE** (Windows
  Portable Devices / WPDBUSENUM, VolumeInfoCache), **NTUSER.DAT** (MountPoints2)
- **`Amcache.hve`** (execution / first-seen signal — confirmed on the vendor features page)
- **SetupAPI** logs (`setupapi.dev.log`)
- **Event Logs** (including the Partition/Diagnostic log for volume serial numbers)
- **Registry transaction logs** — replayed to recover data not yet flushed to the primary hive
- **Volume Shadow Copies** — auto-aggregated
- **LNK files, jump lists, shellbags** — correlated to show files opened and directories
  touched on the device

**Differentiators** (the reason it exists):

1. **Multi-source timestamp correlation with visual consistency scoring.** For each
   attribute (first/last connected, volume name, …) it queries many locations, compares
   the timestamps, and colour-codes cells by consistency, flagging unreliable or suspicious
   values. Its signature feature; competitors lack it.
2. **Per-value source provenance** — every reported value retains where it came from, for
   verification and reporting (defensibility in an expert-witness context).
3. **Deleted/removed-device recovery** — identifies devices removed by Windows 10 device
   cleanup or feature updates; recovers prior volume names/serials for formatted devices.
4. **OS-aware querying** and **timezone normalization** (local ↔ UTC).

**Editions** — **Community** (free; files/folders and logical drives, SYSTEM/SOFTWARE/
NTUSER, SetupAPI; non-commercial). **Professional** (paid; image/VSC and live processing,
commercial use, advanced correlation, LNK/jump-list, timelines; **price not public**).
Output: Excel high-level and verbose reports, plus per-device/aggregate timelines.

## Competitors (most comparable first)

| Tool | Type | USB-artifact coverage vs USB Detective | Free/Paid | Platform | Strength / weakness |
|---|---|---|---|---|---|
| [USB Forensic Tracker (USBFT)](https://e5hforensics.com/index.php/downloads/software/usb-forensic-tracker/) | Dedicated | Very broad: live, images (built-in Arsenal Image Mounter), VSCs, extracted Windows **+ macOS + Linux**; TrueCrypt/VeraCrypt volume history; file-to-device linking | **Free** | Windows (.NET) | **Closest competitor.** Broader (multi-OS, more mount options), faster, free. Weaker: no timestamp-consistency/confidence scoring — each source in its own table, correlation left to the analyst |
| [USB Historian](https://4discovery.com/our-tools/usb-historian/) | Dedicated | Windows registry (SYSTEM/SOFTWARE) history, per user profile | **Free** | Windows | Simpler, free, per-user view. Weaker: narrower sources, no correlation/confidence, reported Win10 hive-access quirks |
| [USBDeview](https://www.nirsoft.net/utils/usb_devices_view.html) (NirSoft) | Utility | Live registry enumeration of current + past devices (name, serial, VID/PID, add date); remote-machine capable. Single-source | **Free** | Windows | Fast "was it connected" triage; resilient to some cleanup. Weaker: not an image tool, no correlation |
| [USBLogView](https://www.nirsoft.net/utils/usb_log_view.html) (NirSoft) | Utility | **Real-time** plug/unplug logging on a running system only | **Free** | Windows | Complementary (live monitoring), not competing with post-hoc reconstruction |
| [KAPE](https://ericzimmerman.github.io/KapeDocs/) + [RegRipper](https://github.com/keydet89/RegRipper3.0) / [Registry Explorer](https://ericzimmerman.github.io/) | Free framework | Collects hives (Targets) then parses with RegRipper plugins (usbstor, mountdev, mountpoints2, …) or EZ tools. Full coverage possible, but **correlation is manual** | **Free / open** | Windows | Maximum flexibility, scriptable. Weaker: no built-in cross-source correlation or consistency scoring — the timeline is assembled by hand ([KAPE USB workflow](https://bakerstreetforensics.com/2021/12/17/csirt-collect-usb/)) |
| [Velociraptor](https://docs.velociraptor.app/) | Free framework | VQL artifacts for USBSTOR/USB keys, fleet-wide/live collection | **Free / open** | Cross-platform | Strong for scale/live IR. Weaker: not a purpose-built USB correlation tool *(coverage inferred; verify the specific artifact per case)* |
| [Autopsy / TSK](https://www.autopsy.com/) | Free suite | USB/registry parsing among modules; whole-disk | **Free / open** | Cross-platform | Free full suite. Weaker: USB is a minor module, shallower correlation |
| [Magnet AXIOM](https://www.magnetforensics.com/products/magnet-axiom/) | Commercial suite | USB/connected-device artifacts auto-parsed; "Connections" links devices↔artifacts↔users; unified timeline | **Paid** (high; ~five-figure/seat per market reports — verify) | Windows | Whole-case breadth (mobile/cloud/memory), court-tested reporting. Weaker on the specific USB-timestamp-consistency scoring |
| [X-Ways Forensics](https://www.x-ways.net/forensics/) | Commercial suite | Registry/USB artifacts within a fast general disk tool | **Paid** (lower-cost, ~low-four-figure — verify) | Windows | Fast, efficient, full disk forensics. Weaker: USB history not a dedicated correlated module |
| [Cellebrite Inspector](https://cellebrite.com/en/inspector/) (ex-BlackLight) | Commercial suite | USB/connected-device registry artifacts as part of Windows analysis | **Paid** (high) | Windows/macOS | Broad computer + mobile ecosystem. Weaker: one module, no equivalent scoring |
| [OpenText EnCase](https://www.opentext.com/products/encase-forensic) | Commercial suite | USB artifacts via EnScript/artifact parsing | **Paid** (high) | Windows | Court pedigree, whole-disk. Weaker: USB history shallow/manual |
| [Belkasoft X](https://belkasoft.com/x) | Commercial suite | Registry + connected-device artifacts among a broad library | **Paid** (mid; more affordable than AXIOM) | Windows | Affordable all-rounder. Weaker: smaller library, USB not specialized |

## Whitespace a new entrant could take (corrected after pressure-test)

USB Detective's genuine moat is **timestamp-consistency scoring + per-value source
provenance** on Windows. A first-pass thesis proposed beating it by going cross-platform
with the same model; a deep analysis (Fable 5) plus an adversarial critique (Codex)
rejected that framing. What survives:

**Rejected — do not pitch these as superiority:**

1. **"Same confidence model on macOS/Linux."** Consistency scoring needs several
   *independent, persistent* sources with differing update semantics to cross-check — a
   Windows property. macOS = ~one timestamped source (unified logs / USBMSC,
   **days-to-weeks retention**) + name-only plists; Linux = effectively single-source
   (journald, retention-bound; the existing tool `usbrip` is exactly this). With 1–2
   sources there is nothing to score. Cross-platform *runtime* (analyse Windows evidence
   from any OS) is real; cross-platform *scored evidence* is not.
2. **"Match Windows depth cheaply, then differentiate."** The scoring algorithm is trivial;
   the semantic model under it (per-build timestamp-rewrite quirks, `Enum\SCSI`/UASP
   coverage, Win10 30-day cleanup semantics, local-vs-UTC normalization) is ~12–24 months
   of corpus-driven differential validation. USB Detective Community edition is a usable
   free **differential oracle** to drive that validation.
3. **"Open-source is more court-defensible."** Closed tools are routinely admitted under
   Daubert; source availability aids *testimony* and opponent re-analysis, it does not gate
   admissibility. Real but narrow, and double-edged (public bug tracker = cross-exam fuel).

**Real, structural whitespace — gaps USB Detective cannot close without changing what it is:**

1. **Pipeline/library form factor.** Headless, embeddable, JSONL-diffable, fleet-scale,
   OS-agnostic *runtime* over Windows evidence. No open tool does scored multi-source USB
   correlation as a CLI/library (RegRipper = raw plugins; USBFT = unscored GUI). Customer
   is the **pipeline operator / lab-automation user**, not the GUI examiner (who has free
   Community edition and no reason to switch).
2. **Reproducibility by construction** — a deterministic `--reproduce` chain
   (`hive → key → raw bytes → decoding rule`) any party can re-run and hash. The durable
   half of "court-ready"; PDF/DOCX formatting is a weekend feature and thus not a moat.
3. **Fleet leverage** — reuse of the fleet's parsers and `forensicnomicon` artifact catalog
   as the **first instance of a general artifact-domain analyzer**, not a one-off.

**Kill criteria:** the 80%-clone trap (a free-Community clone wins no examiners → ship the
form-factor wedge first, not the match); no sustained validation-corpus commitment (an
unvalidated correlator is a liability generator → v1 says "consistent with / not consistent
with," never "spoofed"); the engine can't generalize past USB.

## Gaps, notes and uncertainties

- **Pricing is the weakest-verified area.** USB Detective Professional: no public price
  (Avangate + quote-on-request). Suite prices (AXIOM, X-Ways, EnCase, Cellebrite,
  Belkasoft) are quote-based and shift yearly; tiers above are directional from market
  write-ups, **not vendor-confirmed**. Free tools (USBFT, USB Historian, USBDeview,
  USBLogView, KAPE/RegRipper, Velociraptor, Autopsy) are confirmed free.
- **Head-to-head worth citing:** [HackMag's USB Forensics Showdown](https://hackmag.com/devops/usb-forensic-battle)
  tested USBFT vs USB Detective vs USBDeview on one machine — USBFT faster and
  broadest-source; USB Detective favoured when you want aggregated data with calculated
  cross-source correlation; USBDeview sufficient for a simple "was it connected." Single
  machine — illustrative, not benchmark-grade.
- **Not independently re-verified this pass:** exact RegRipper plugin names, USB
  Historian's current Windows 11 support (older Win10 hive-access issues reported), and
  Velociraptor's specific USB artifact — all from secondary sources; confirm per case.

## Sources

[USB Detective](https://usbdetective.com/) ·
[features](https://usbdetective.com/features/) ·
[df-stream intro](https://df-stream.com/2018/03/usb-detective/) ·
[F-Response interview](https://www.f-response.com/blog/usb-detective-interview-jason-hale) ·
[USBFT (E5h)](https://e5hforensics.com/index.php/downloads/software/usb-forensic-tracker/) ·
[HackMag showdown](https://hackmag.com/devops/usb-forensic-battle) ·
[USBDeview](https://www.nirsoft.net/utils/usb_devices_view.html) ·
[USBLogView](https://www.nirsoft.net/utils/usb_log_view.html) ·
[KapeFiles](https://github.com/EricZimmerman/KapeFiles) ·
[KAPE USB workflow](https://bakerstreetforensics.com/2021/12/17/csirt-collect-usb/) ·
[forensics.wiki USB history](https://forensics.wiki/usb_history_viewing/) ·
[Magnet AXIOM](https://www.magnetforensics.com/products/magnet-axiom/)
