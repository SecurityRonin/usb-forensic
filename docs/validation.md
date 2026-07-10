# Validation

!!! note "Status: plan, not evidence"
    This page states the validation *strategy* for the correlation engine. No
    correlation code exists yet, so there are no results to report. When Phase 1
    lands, this page is rewritten to carry the actual differential results
    (Doer-Checker evidence), not the plan.

A USB-history correlator that miscorrelates is worse than none — a legitimate
timestamp flagged "suspicious," or a spoofed one blessed, in a report with the
examiner's name on it. Correctness is therefore proven against an **independent
oracle on real data**, never against fixtures we authored ourselves.

## Independent oracles

| Domain | Oracle | Use |
|---|---|---|
| Whole-tool USB history | **USB Detective Community edition** (free) | Run both over the same evidence; every disagreement is either our bug or a documented edge case. Converts the incumbent's moat into our test suite. |
| Registry USB artifacts | **RegRipper** (`usbstor`, `mountdev`, `mountpoints2`, …) | Per-key cross-check of extracted values before correlation. |
| Ground-truth device history | Real disk images with a **known** device-connection history (documented insertions/removals) | The answer key the tools are scored against. |

## Reconciliation discipline

For each artifact: run the oracle, run `usb-forensic`, reconcile **counts and
contents**, and explain every divergence in writing. A divergence is a finding — it
is either a bug to fix or a real-world quirk to document (e.g. a UASP drive under
`Enum\SCSI` that a `USBSTOR`-only tool misses, a boot-time `USBSTOR` LastWrite rewrite
that naive comparison would flag as tampering).

## Corpus

Test images and their provenance are catalogued in `tests/data/README.md` and the
fleet-wide `docs/corpus-catalog.md` (large images gitignored, downloaded per the
fleet test-data provenance standard). Real, ground-truth-bearing images are preferred
over synthetic fixtures; synthetic images are used only for adversarial edge cases
real corpora lack (truncation, lying counts, offset overflow).

## DOCX export (Tier-2, independent oracle)

`render_docx` writes a native Word `.docx` with no dependency (hand-written stored ZIP +
CRC-32 + OOXML). It is validated against **python-docx** / Python `zipfile` as an
independent oracle: the generated file is a valid ZIP, every entry passes its CRC check,
the three OOXML parts are present, and python-docx opens it and reads the report
paragraphs (including the per-value provenance lines). Verified on setupapi + LNK
evidence via `usb4n6 --docx`.
