# 0001 — Correlation model: source-agnostic claims graded by tamper-independence

Status: Accepted

## Context

Windows records a USB device's history across many artifacts — registry `Enum` keys,
`MountedDevices`, `setupapi.dev.log`, event logs, `.lnk` files, `EMDMgmt`. A viewer that
shows each artifact in its own pane leaves the examiner to reconcile them by eye. The harder
and more valuable question is not *what does each artifact say* but *do the artifacts agree*,
and *how much does their agreement mean*.

Agreement is only meaningful when the agreeing records are **independent**. Two timestamps
that both come from the `SYSTEM` hive agree trivially — a single edit to that hive could set
both. Two timestamps from the hive and from an event log agreeing is stronger: they sit in
different files with different tamper surfaces.

## Decision

Every source adapter emits **`Claim { device, attribute, value, provenance }`** — a
source-agnostic atom. The correlation core groups claims by `(device, attribute)` and grades
each group's **`Consistency`** by counting *tamper-independent* sources, where independence is
a property of the **`ArtifactContainer`** the claim lives in (the `SYSTEM` hive, the `SOFTWARE`
hive, a per-user `NTUSER.DAT`, an event log, a `.lnk` file, the device media, …), **not** the
recording mechanism. Two claims in the same container are not independent.

`SourceKind` (the recording mechanism) is tracked separately and is a *weaker* independence
signal — it guards against parse error and coincidence, not against tampering.

## Consequences

- Adding a source is additive: write an adapter that emits `Claim`s; the core grades it with
  no changes. `SourceKind`/`ArtifactContainer`/`Attribute` are `#[non_exhaustive]` enums.
- Corroboration strength is honest: two SYSTEM-hive sources agreeing is *single-container*,
  not corroborated; a hive source agreeing with an event-log source is corroborated.
- The output carries every value with its `provenance` (source + locator), so a conclusion is
  traceable to the artifact and offset it came from.
- Findings (conflict, corroboration, impossible-ordering) are derived from the graded groups,
  not hand-coded per source.
