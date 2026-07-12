# 0002 — usb-forensic is a correlation engine; parsing lives in fleet reader crates

Status: Accepted

## Context

usb-forensic could parse each artifact format itself — registry hives, event logs, boot
sectors, LNK files. Every hand-rolled parser is a format it must keep correct against
real-world quirks, fuzz, and re-validate. The fleet already ships tested reader crates for
these formats (`peripheral-core`, `winevt-extract`, `lnk-core`, `disk-forensic`, …), each
validated against real corpora and fuzzed at its own boundary.

The device-image source made this concrete. It began as a hand-rolled MBR/VBR walk. That
walk mis-read a GPT protective MBR (the `0xEE` entry pointing at the "EFI PART" header) as a
partition, flagging it as an unrecognized/encrypted filesystem — a false positive on any
GPT-partitioned USB device. Hand-rolling the partition-table matrix (MBR/GPT/APM × the
filesystem signatures) is exactly the work a tested crate already does.

## Decision

usb-forensic is a **correlation engine**. Each source adapter is a *pure mapping* from a
fleet reader's already-decoded output into `Claim`s (ADR 0001) — it does not parse the raw
format. For the device-image source specifically, partition-scheme dispatch (MBR/GPT/APM)
and filesystem detection are delegated to **`disk-forensic`**, the fleet's single abstraction
over the partition-scheme × filesystem matrix, tested against real disk corpora.

`disk-forensic` — not the lower-level `mbr-partition-forensic` — is the dependency, precisely
because its value is *being that unified abstraction*: one call handles any scheme, and APM
and future container formats come for free. Its heavier dependency tree is an acceptable cost
for a forensic CLI (this is not a size-constrained library).

## Consequences

- The GPT false positive is fixed by construction: a GPT disk is parsed as GPT, its
  partitions taken from the GPT entry array, never mis-walked as MBR partitions.
- usb-forensic does not re-validate partition/filesystem parsing; that is the reader crate's
  responsibility, proven against its own corpora.
- Two USB-attribution values are *not* yet surfaced by a general disk crate and are read from
  the volume boot record here for now — the FAT `BS_VolID` (the `EMDMgmt`/LNK join key) and
  BitLocker To Go. ADR 0003 moves this responsibility down to where it belongs.
- The same principle governs every source: event logs via `winevt-extract`, registry via
  `peripheral-core`/`winreg-core`, LNK via `lnk-core`, E01 images via `ewf`.
