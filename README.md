# usb-forensic

**Status: design seed (research only, no code yet).** This repo captures the market
research and product thesis for a Windows USB-device forensics tool. It exists to hold
the decision to build before a line of code is written.

## What this would be

A tool that reconstructs USB-device connection history from every relevant Windows
artifact and — the part that matters for a defensible report — **cross-correlates the
timestamps across sources and scores their consistency**, so an examiner can tell a
reliable first-connected time from a spoofed or partial one.

USB history is a **multi-source artifact domain**, not a single-parser job. The evidence
is spread across:

- **Registry** — `USBSTOR`, `Enum\USB`, `MountedDevices` (SYSTEM); Windows Portable
  Devices / `WPDBUSENUM`, `VolumeInfoCache` (SOFTWARE); `MountPoints2` (NTUSER.DAT)
- **SetupAPI** device-install logs (`setupapi.dev.log`)
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

## Why build it — the whitespace

Existing tools cluster at two ends: free single-source viewers (USBDeview, USB Historian)
and broad forensic suites (AXIOM, X-Ways) where USB history is one small module. The one
tool that specializes — [USB Detective](https://usbdetective.com/) — owns a real moat:
**per-source timestamp correlation with a consistency score, and per-value provenance**.
It is Windows-only and closed-source.

The gaps that moat leaves open, and that a fleet tool could take:

1. **Cross-platform** device history with the same confidence model (the scoring tools are
   all Windows-only; the one broad free tool, USBFT, parses macOS/Linux but *without*
   scoring).
2. An **open-source** tool that automates the KAPE + RegRipper correlate-and-score step
   analysts currently do by hand.
3. **Court-ready provenance export** — a per-timestamp source chain to PDF/DOCX as a
   first-class output, not an Excel dump. This is the expert-witness need directly.

Full landscape and sources: [`docs/competitive-landscape.md`](docs/competitive-landscape.md).

## Next step

None committed. This is a seed. Before any code: confirm the thesis is worth building,
then scope an MVP (likely: registry + SetupAPI ingestion → timestamp correlation → scored
report) against the fleet's pre-publish standards.
