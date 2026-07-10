//! Fleet-standard output: turn correlated [`DeviceHistory`] into
//! [`forensicnomicon::report::Finding`]s so Issen and a future GUI render USB
//! findings uniformly with every other analyzer.
//!
//! Findings are observations, never verdicts. A cross-source *conflict* is reported as
//! "consistent with timestamp tampering or partial evidence" (MITRE T1070.006), never as
//! proven tampering; a *corroborated* value is reported as a reliable timeline fact.

use crate::{Consistency, DeviceHistory};
use forensicnomicon::report::{Category, Finding, Severity};
use std::collections::BTreeSet;

/// The finding code for a cross-source timestamp/value conflict.
pub const CODE_CONFLICT: &str = "USB-TIMESTAMP-CONFLICT";
/// The finding code for a corroborated device-history attribute.
pub const CODE_HISTORY: &str = "USB-DEVICE-HISTORY";

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
    let _ = histories;
    unimplemented!("GREEN step")
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
}
