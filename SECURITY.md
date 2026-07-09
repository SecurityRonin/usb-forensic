# Security Policy

## Supported versions

This crate is a pre-code design seed; nothing is published yet. Once released, the
latest `0.x` line receives security fixes (pre-`1.0`, only the most recent minor).

## Reporting a vulnerability

Please report security issues privately to
[albert@securityronin.com](mailto:albert@securityronin.com) rather than opening a
public issue. Include a description, affected version, and a reproducing input if
possible. You will receive an acknowledgement within a few business days.

## Security posture

`usb-forensic` will correlate **attacker-controllable, already-decoded** USB-device
history (registry values, setupapi entries, event-log records, LNK targets). It is
built to fail safe:

- **`#![forbid(unsafe_code)]`** — no FFI, no raw pointers, no `unsafe` anywhere.
- **Panic-free production code** — the workspace denies `clippy::unwrap_used` and
  `clippy::expect_used`; missing or malformed fields degrade gracefully, never crash.
- **No network, no telemetry** — all processing is local.
- **Findings are observations, never verdicts** — the type system and the hedged-note
  convention keep the crate from asserting legal conclusions ("consistent with …").

### Fuzzing

This crate parses no raw byte format of its own — it consumes the typed output of
reader crates that are themselves fuzzed at their parse boundary (`winreg-artifacts`,
`peripheral-core`, `winevt-forensic`, `lnk-core`). The fuzzing surface lives in those
upstream crates; `usb-forensic`'s own correlation logic is total over the typed inputs
and is covered to 100% by the test suite.
