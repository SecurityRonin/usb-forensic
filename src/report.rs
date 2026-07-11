//! Fleet-standard output: turn correlated [`DeviceHistory`] into
//! [`forensicnomicon::report::Finding`]s so Issen and a future GUI render USB
//! findings uniformly with every other analyzer.
//!
//! Findings are observations, never verdicts. A cross-source *conflict* is reported as
//! "consistent with timestamp tampering or partial evidence" (MITRE T1070.006), never as
//! proven tampering; a *corroborated* value is reported as a reliable timeline fact.

use crate::model::Attribute;
use crate::{Consistency, DeviceHistory};
use forensicnomicon::report::{Category, Finding, Severity};
use std::collections::BTreeSet;

/// The finding code for a cross-source timestamp/value conflict.
pub const CODE_CONFLICT: &str = "USB-TIMESTAMP-CONFLICT";
/// The finding code for a corroborated device-history attribute.
pub const CODE_HISTORY: &str = "USB-DEVICE-HISTORY";
/// The finding code for a physically impossible first-vs-last timestamp ordering.
pub const CODE_IMPOSSIBLE_ORDER: &str = "USB-IMPOSSIBLE-ORDERING";

/// Convert correlated device histories into forensic findings.
///
/// - A `Conflicting` attribute → a `Medium` `Integrity` finding (independent sources
///   disagree — an anti-forensic lead), with every value retained as evidence.
/// - A `Corroborated` attribute → an `Info` `History` finding (a reliable timeline
///   fact, agreed across independent containers).
/// - A `SingleSource` attribute yields no finding on its own (it is still in the
///   timeline / JSONL); it is uncorroborated, not noteworthy.
#[must_use]
pub fn audit(histories: &[DeviceHistory]) -> Vec<Finding> {
    let mut out = Vec::new();
    for h in histories {
        let device = &h.device.0;
        for a in &h.attributes {
            match a.consistency {
                Consistency::Conflicting => {
                    let mut builder =
                        Finding::observation(Severity::Medium, Category::Integrity, CODE_CONFLICT)
                            .note(format!(
                                "device {device}: independent sources disagree on {:?} — \
                         consistent with timestamp tampering or partial evidence",
                                a.attribute
                            ))
                            .mitre("T1070.006");
                    for v in &a.values {
                        builder = builder.evidence(
                            format!("{:?}", v.provenance.source),
                            format!("{:?}", v.value),
                        );
                    }
                    out.push(builder.build());
                }
                Consistency::Corroborated => {
                    let containers = a
                        .values
                        .iter()
                        .map(|v| v.provenance.source.container())
                        .collect::<BTreeSet<_>>()
                        .len();
                    out.push(
                        Finding::observation(Severity::Info, Category::History, CODE_HISTORY)
                            .note(format!(
                                "device {device}: {:?} corroborated across {containers} \
                                 independent containers",
                                a.attribute
                            ))
                            .build(),
                    );
                }
                Consistency::SingleSource => {}
            }
        }
        if let Some(finding) = impossible_ordering(h) {
            out.push(finding);
        }
    }
    out
}

/// The earliest timestamp value across an attribute's corroborating sources, if any.
fn min_ts(h: &DeviceHistory, attr: Attribute) -> Option<i64> {
    ts_values(h, attr).min()
}

/// The latest timestamp value across an attribute's corroborating sources, if any.
fn max_ts(h: &DeviceHistory, attr: Attribute) -> Option<i64> {
    ts_values(h, attr).max()
}

/// Every timestamp value recorded for `attr` on this device.
fn ts_values(h: &DeviceHistory, attr: Attribute) -> impl Iterator<Item = i64> + '_ {
    h.attributes
        .iter()
        .filter(move |a| a.attribute == attr)
        .flat_map(|a| a.values.iter())
        .filter_map(|v| match v.value {
            crate::Value::Timestamp(t) => Some(t),
            crate::Value::Text(_) => None,
        })
}

/// Flag a device whose *earliest* first-connect is strictly later than its *latest*
/// last-connect/last-removal. That ordering is physically impossible under any reading of
/// the (possibly source-disagreeing) timestamps, so it is a conservative, false-positive-
/// free indicator — reported as *consistent with* clock rollback / timestamp manipulation,
/// never as proven tampering.
fn impossible_ordering(h: &DeviceHistory) -> Option<Finding> {
    let first = min_ts(h, Attribute::FirstConnected)?;
    let last = max_ts(h, Attribute::LastConnected)
        .into_iter()
        .chain(max_ts(h, Attribute::LastRemoved))
        .max()?;
    if first <= last {
        return None;
    }
    Some(
        Finding::observation(Severity::Medium, Category::Integrity, CODE_IMPOSSIBLE_ORDER)
            .note(format!(
                "device {}: earliest first-connection ({first}) is after the latest \
                 last-connection/removal ({last}) — consistent with clock rollback or \
                 timestamp manipulation",
                h.device.0
            ))
            .mitre("T1070.006")
            .evidence("FirstConnected", first.to_string())
            .evidence("LastConnected/LastRemoved", last.to_string())
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, DeviceKey, Provenance, SourceKind, Value};
    use crate::{correlate, Claim};

    fn claim(dev: &str, attr: Attribute, val: Value, src: SourceKind, loc: &str) -> Claim {
        Claim {
            device: DeviceKey(dev.to_string()),
            attribute: attr,
            value: val,
            provenance: Provenance {
                source: src,
                locator: loc.to_string(),
            },
        }
    }

    #[test]
    fn conflicting_attribute_yields_medium_integrity_finding() {
        let claims = [
            claim(
                "SN1",
                Attribute::FirstConnected,
                Value::Timestamp(1_700_000_000),
                SourceKind::Usbstor,
                "k",
            ),
            claim(
                "SN1",
                Attribute::FirstConnected,
                Value::Timestamp(1_699_000_000),
                SourceKind::SetupApi,
                "l",
            ),
        ];
        let findings = audit(&correlate(&claims));
        let f = findings
            .iter()
            .find(|f| f.code == CODE_CONFLICT)
            .expect("conflict finding");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_eq!(f.category, Category::Integrity);
        assert_eq!(
            f.evidence.len(),
            2,
            "both conflicting values retained as evidence"
        );
    }

    #[test]
    fn corroborated_attribute_yields_info_history_finding() {
        let ts = Value::Timestamp(1_700_000_000);
        let claims = [
            claim(
                "SN1",
                Attribute::FirstConnected,
                ts.clone(),
                SourceKind::Usbstor,
                "k",
            ),
            claim(
                "SN1",
                Attribute::FirstConnected,
                ts,
                SourceKind::SetupApi,
                "l",
            ),
        ];
        let findings = audit(&correlate(&claims));
        let f = findings
            .iter()
            .find(|f| f.code == CODE_HISTORY)
            .expect("history finding");
        assert_eq!(f.severity, Some(Severity::Info));
        assert_eq!(f.category, Category::History);
    }

    #[test]
    fn single_source_yields_no_finding() {
        let claims = [claim(
            "SN1",
            Attribute::FirstConnected,
            Value::Timestamp(1_700_000_000),
            SourceKind::Usbstor,
            "k",
        )];
        assert!(audit(&correlate(&claims)).is_empty());
    }

    #[test]
    fn first_connected_after_last_connected_is_flagged_impossible() {
        // FirstConnected (later) strictly after LastConnected (earlier) is physically
        // impossible → a clock-rollback / timestamp-manipulation lead.
        let claims = [
            claim(
                "SN1",
                Attribute::FirstConnected,
                Value::Timestamp(1_700_000_500),
                SourceKind::Usbstor,
                "k",
            ),
            claim(
                "SN1",
                Attribute::LastConnected,
                Value::Timestamp(1_700_000_100),
                SourceKind::Usbstor,
                "l",
            ),
        ];
        let f = audit(&correlate(&claims))
            .into_iter()
            .find(|f| f.code == CODE_IMPOSSIBLE_ORDER)
            .expect("impossible-ordering finding");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_eq!(f.category, Category::Integrity);
        // both boundary timestamps retained as evidence.
        assert_eq!(f.evidence.len(), 2);
    }

    #[test]
    fn last_removed_before_first_connected_is_flagged() {
        // The check also covers LastRemoved, and uses the conservative bound: the
        // EARLIEST first-connect after the LATEST last-* event.
        let claims = [
            claim(
                "SN2",
                Attribute::FirstConnected,
                Value::Timestamp(2_000),
                SourceKind::SetupApi,
                "k",
            ),
            claim(
                "SN2",
                Attribute::LastRemoved,
                Value::Timestamp(1_000),
                SourceKind::Usbstor,
                "l",
            ),
        ];
        assert!(audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_IMPOSSIBLE_ORDER));
    }

    #[test]
    fn normal_ordering_yields_no_impossible_finding() {
        // FirstConnected before LastConnected — the normal case.
        let claims = [
            claim(
                "SN3",
                Attribute::FirstConnected,
                Value::Timestamp(1_000),
                SourceKind::Usbstor,
                "k",
            ),
            claim(
                "SN3",
                Attribute::LastConnected,
                Value::Timestamp(2_000),
                SourceKind::Usbstor,
                "l",
            ),
        ];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_IMPOSSIBLE_ORDER));
    }

    #[test]
    fn non_timestamp_connect_values_are_ignored_by_the_ordering_check() {
        // A defensively-typed Text value on a connect attribute is not a timestamp, so it
        // contributes nothing to the ordering bound and never triggers a false finding.
        let claims = [
            claim(
                "SN5",
                Attribute::FirstConnected,
                Value::Text("not-a-time".into()),
                SourceKind::Usbstor,
                "k",
            ),
            claim(
                "SN5",
                Attribute::LastConnected,
                Value::Timestamp(1_000),
                SourceKind::Usbstor,
                "l",
            ),
        ];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_IMPOSSIBLE_ORDER));
    }

    #[test]
    fn equal_first_and_last_is_not_impossible() {
        // A single connect: first == last is valid, not a violation (strict `>` only).
        let claims = [
            claim(
                "SN4",
                Attribute::FirstConnected,
                Value::Timestamp(5_000),
                SourceKind::Usbstor,
                "k",
            ),
            claim(
                "SN4",
                Attribute::LastConnected,
                Value::Timestamp(5_000),
                SourceKind::Usbstor,
                "l",
            ),
        ];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_IMPOSSIBLE_ORDER));
    }
}
