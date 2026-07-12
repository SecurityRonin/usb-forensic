# 0004 — BitLocker To Go is detected by the identifier GUID, not the `-FVE-FS-` string

Status: Accepted

## Context

usb-forensic surfaces volume encryption so an examiner sees that a device's contents were
inaccessible. The obvious signature is the one for **fixed-drive** BitLocker: the volume boot
record's OEM identifier at offset 3 is replaced by the documented `-FVE-FS-` string (Windows
Vista `EB 52 90` / 7–10 `EB 58 90`; libbde BDE format).

That rule misses the case that matters most for removable media. **BitLocker To Go** — the
removable-drive variant — does *not* carry `-FVE-FS-`. Its discovery volume presents a
genuine FAT/exFAT boot record (`MSWIN4.1` OEM identifier, a real `FAT32   ` filesystem
signature) so that a legacy Windows can still read the To Go reader. A detector keyed on
`-FVE-FS-`, or a generic filesystem detector, sees an ordinary FAT volume and reports no
encryption — on exactly the removable devices a USB tool exists to examine.

## Decision

Detect BitLocker by the **BitLocker identifier GUID** `4967D63B-2E29-4AD8-8399-F6A339E3D001`,
which the volume header carries in both the fixed-drive layout (offset 160) and the To Go
layout (offset 424). Because the offset differs by layout version, **scan** the 512-byte
volume header for the 16-byte GUID rather than reading a fixed offset. The `-FVE-FS-` string
at offset 3 additionally distinguishes fixed-drive BitLocker (which also carries the GUID)
from To Go (which carries the GUID but a FAT OEM id). LUKS and an unrecognized-filesystem
volume are classified from the filesystem detector.

This is a spec-defined rule (libbde), so its correctness is defined by the specification, not
by a self-authored fixture. It is validated against spec-faithful volume headers and against
real unencrypted media, which must not false-positive.

## Consequences

- Removable-media BitLocker (To Go) is detected, distinct from fixed-drive BitLocker, and
  reported as its own encryption kind.
- The GUID scan is effectively false-positive-free (a 16-byte unique GUID) and robust to
  layout-version differences without hard-coding an offset.
- ADR 0003 moves this detection down into forensicnomicon/disk-forensic, where it applies to
  any volume regardless of bus or partition scheme.

Reference: libbde, *BitLocker Drive Encryption (BDE) format* — volume-header tables.
