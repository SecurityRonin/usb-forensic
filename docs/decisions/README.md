# Architecture Decision Records

Each ADR captures one significant decision: the context that forced it, the decision, and its
consequences. They are immutable once accepted — a reversal is a new ADR that supersedes an
old one, not an edit.

| ADR | Decision |
|---|---|
| [0001](0001-correlation-and-consistency-model.md) | Correlation model: source-agnostic `Claim`s, graded by tamper-independent `ArtifactContainer` |
| [0002](0002-delegate-parsing-to-fleet-crates.md) | usb-forensic is a correlation engine; artifact parsing lives in fleet reader crates |
| [0003](0003-scheme-agnostic-volume-analysis.md) | Volume serial + encryption are volume properties — analysed scheme-agnostically, knowledge in forensicnomicon |
| [0004](0004-bitlocker-to-go-detection.md) | BitLocker To Go detection via the identifier GUID, not the `-FVE-FS-` string |
