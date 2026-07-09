# usb-forensic

**The USB device-history correlation engine for the SecurityRonin forensic fleet.**

!!! note "Status: pre-code design seed"
    This repository is scaffolded to the fleet standard but carries no correlation
    logic yet. It holds a validated, adversarially-pressure-tested product thesis and
    the build plan. Code is filled in under strict TDD once the thesis is committed to.

`usb-forensic` parses no raw format itself. It is the thin **orchestration** crate
that consumes the fleet's already-built reader crates, normalizes their output into
one uniform USB-device-history event, and cross-correlates the timestamps across
sources — reporting each value as *consistent with* or *not consistent with* the
others so an examiner can tell a reliable first-connected time from a partial or
contradicted one.

It is built for **pipelines and courtrooms rather than a viewer window**: headless,
library-embeddable, diffable JSONL output, and reproducible — every reported value
re-derivable from `hive → key → raw bytes → decoding rule`.

## Where it sits in the fleet

```
usb-forensic  ── correlates USB device history, scores cross-source timestamp consistency
   ├── consumes winreg-artifacts  ── USBSTOR / MountedDevices / WPDBUSENUM / Amcache / …
   ├── consumes peripheral-core   ── setupapi.dev.log device-install events
   ├── consumes winevt-forensic   ── Partition/Diagnostic event log (volume serials)
   └── consumes lnk-core          ── recent-file LNK volume-serial join
```

It is a sibling of [`useract-forensic`](https://github.com/SecurityRonin/useract-forensic)
(broad user-activity correlation): `usb-forensic` is the deep, USB-specific
consistency-scoring engine; `useract-forensic` treats a device connection as one
input among many. Both emit `forensicnomicon::report::Finding`s and feed Issen.

## The design thesis

The full, Codex-reviewed positioning — why "better than USB Detective" was rejected
in favour of a narrower, defensible wedge — is in the
[competitive landscape](competitive-landscape.md). The build sequence is in the
[roadmap](roadmap.md).

## Trust, but verify

Every finding will be an **observation** ("consistent with …"); the examiner draws
the conclusions. The crate is `#![forbid(unsafe_code)]`, panic-free (the workspace
denies `unwrap`/`expect` in production), and gates on 100% library line coverage. The
correlation logic will be validated differentially against USB Detective Community
edition and RegRipper on real disk images — see [validation](validation.md).

---

[Privacy Policy](https://securityronin.github.io/usb-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/usb-forensic/terms/) · © 2026 Security Ronin Ltd
