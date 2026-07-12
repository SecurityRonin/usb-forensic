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
/// The finding code for a device whose volume is encrypted.
pub const CODE_ENCRYPTED: &str = "USB-VOLUME-ENCRYPTED";
/// The finding code for an MTP/PTP portable device.
pub const CODE_MTP: &str = "USB-MTP-DEVICE";
/// The finding code for a volume reformatted-and-reused (label with multiple serials).
pub const CODE_REFORMATTED: &str = "USB-VOLUME-REFORMATTED";

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
        if let Some(finding) = encryption_finding(h) {
            out.push(finding);
        }
        if let Some(finding) = mtp_finding(h) {
            out.push(finding);
        }
    }
    out.extend(reformatting_findings(histories));
    out
}

/// Flag a volume whose label appears with two or more distinct volume serials across the
/// evidence — a formatted-and-reused device (the serial changes on each format, the label
/// often does not). It recovers *prior* volume serials for a formatted device and is a
/// classic anti-forensic signal (reformatting to shed traces). One finding per such label,
/// listing every serial seen. A cross-device pass: each cached volume (e.g. an `EMDMgmt`
/// record) is its own history keyed by its serial, so the reuse is only visible in aggregate.
fn reformatting_findings(histories: &[DeviceHistory]) -> Vec<Finding> {
    // label -> the set of distinct volume serials seen carrying it.
    let mut by_label: std::collections::BTreeMap<String, BTreeSet<String>> =
        std::collections::BTreeMap::new();
    for h in histories {
        let labels = text_values(h, Attribute::VolumeName);
        let serials = text_values(h, Attribute::VolumeSerial);
        for label in &labels {
            for serial in &serials {
                by_label
                    .entry(label.clone())
                    .or_default()
                    .insert(serial.clone());
            }
        }
    }
    by_label
        .into_iter()
        .filter(|(_, serials)| serials.len() >= 2)
        .map(|(label, serials)| {
            let list = serials.iter().cloned().collect::<Vec<_>>().join(", ");
            let mut builder =
                Finding::observation(Severity::Medium, Category::Integrity, CODE_REFORMATTED)
                    .note(format!(
                        "volume {label:?} appears with {} distinct volume serials ({list}) — \
                         consistent with the device having been reformatted and reused",
                        serials.len()
                    ))
                    .mitre("T1070.004");
            for serial in &serials {
                builder = builder.evidence("VolumeSerial", serial.clone());
            }
            builder.build()
        })
        .collect()
}

/// Every text value recorded for `attr` on this device.
fn text_values(h: &DeviceHistory, attr: Attribute) -> Vec<String> {
    h.attributes
        .iter()
        .filter(|a| a.attribute == attr)
        .flat_map(|a| a.values.iter())
        .filter_map(|v| match &v.value {
            crate::Value::Text(t) => Some(t.clone()),
            crate::Value::Timestamp(_) => None,
        })
        .collect()
}

/// Flag a device whose volume carries an encryption signature (e.g. `BitLocker` read from a
/// device image's boot sector). A `Low`-severity observation — encryption is a legitimate
/// data-at-rest protection, but the fact that the volume's contents are inaccessible
/// without the key is material to the investigation and is stated, not judged.
fn encryption_finding(h: &DeviceHistory) -> Option<Finding> {
    let attr = h
        .attributes
        .iter()
        .find(|a| a.attribute == Attribute::Encryption)?;
    let crate::Value::Text(kind) = &attr.values.first()?.value else {
        return None;
    };
    Some(
        Finding::observation(Severity::Low, Category::History, CODE_ENCRYPTED)
            .note(format!(
                "device {}: volume is {kind}-encrypted — its contents are not accessible \
                 without the decryption key",
                h.device.0
            ))
            .build(),
    )
}

/// Flag an MTP/PTP portable device (phone/tablet/camera). Such a device is a data-exfil
/// endpoint that leaves fewer artifacts than mass storage and never appears under
/// `USBSTOR`, so its presence is material and worth surfacing — stated, not judged.
fn mtp_finding(h: &DeviceHistory) -> Option<Finding> {
    let is_mtp = h.attributes.iter().any(|a| {
        a.attribute == Attribute::DeviceClass
            && a.values
                .iter()
                .any(|v| matches!(&v.value, crate::Value::Text(t) if t == "MTP"))
    });
    is_mtp.then(|| {
        Finding::observation(Severity::Low, Category::History, CODE_MTP)
            .note(format!(
                "device {}: MTP/PTP portable device (phone/tablet/camera) — a data-transfer \
                 endpoint that does not appear under USBSTOR",
                h.device.0
            ))
            .mitre("T1052.001")
            .build()
    })
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

    #[test]
    fn an_encrypted_device_yields_a_low_encryption_finding() {
        let claims = [claim(
            "disk-ABCD1234",
            Attribute::Encryption,
            Value::Text("BitLocker".into()),
            SourceKind::DeviceImage,
            "img.raw",
        )];
        let f = audit(&correlate(&claims))
            .into_iter()
            .find(|f| f.code == CODE_ENCRYPTED)
            .expect("encryption finding");
        assert_eq!(f.severity, Some(Severity::Low));
        assert!(f.note.contains("BitLocker"));
    }

    #[test]
    fn a_non_encrypted_device_yields_no_encryption_finding() {
        let claims = [claim(
            "SN9",
            Attribute::FirstConnected,
            Value::Timestamp(1),
            SourceKind::Usbstor,
            "k",
        )];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_ENCRYPTED));
    }

    #[test]
    fn a_label_with_two_serials_is_flagged_reformatted() {
        // Same volume label, two distinct serials (across two EMDMgmt records) → the device
        // was reformatted and reused. Matches the real CFReDS "IAMAN" case.
        let claims = [
            claim(
                "9E6A-5B82",
                Attribute::VolumeName,
                Value::Text("IAMAN".into()),
                SourceKind::EmdMgmt,
                "a",
            ),
            claim(
                "9E6A-5B82",
                Attribute::VolumeSerial,
                Value::Text("9E6A-5B82".into()),
                SourceKind::EmdMgmt,
                "a",
            ),
            claim(
                "B4D8-5399",
                Attribute::VolumeName,
                Value::Text("IAMAN".into()),
                SourceKind::EmdMgmt,
                "b",
            ),
            claim(
                "B4D8-5399",
                Attribute::VolumeSerial,
                Value::Text("B4D8-5399".into()),
                SourceKind::EmdMgmt,
                "b",
            ),
        ];
        let f = audit(&correlate(&claims))
            .into_iter()
            .find(|f| f.code == CODE_REFORMATTED)
            .expect("reformatting finding");
        assert_eq!(f.severity, Some(Severity::Medium));
        assert_eq!(f.evidence.len(), 2);
        assert!(f.note.contains("IAMAN"));
    }

    #[test]
    fn a_label_with_a_single_serial_is_not_flagged() {
        let claims = [
            claim(
                "SER1",
                Attribute::VolumeName,
                Value::Text("KINGSTON".into()),
                SourceKind::EmdMgmt,
                "a",
            ),
            claim(
                "SER1",
                Attribute::VolumeSerial,
                Value::Text("SER1".into()),
                SourceKind::EmdMgmt,
                "a",
            ),
        ];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_REFORMATTED));
    }

    #[test]
    fn a_non_text_volume_attribute_is_ignored_by_the_reformatting_scan() {
        // Defensive: a VolumeName carrying a Timestamp (mistyped) contributes no label, so
        // no spurious reformatting finding — and no panic.
        let claims = [claim(
            "SER2",
            Attribute::VolumeName,
            Value::Timestamp(1),
            SourceKind::EmdMgmt,
            "a",
        )];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_REFORMATTED));
    }

    #[test]
    fn an_mtp_device_yields_a_low_mtp_finding() {
        let claims = [claim(
            "PHONE1",
            Attribute::DeviceClass,
            Value::Text("MTP".into()),
            SourceKind::Usbstor,
            "k",
        )];
        let f = audit(&correlate(&claims))
            .into_iter()
            .find(|f| f.code == CODE_MTP)
            .expect("MTP finding");
        assert_eq!(f.severity, Some(Severity::Low));
        assert!(f.note.contains("MTP"));
    }

    #[test]
    fn a_non_mtp_device_yields_no_mtp_finding() {
        let claims = [claim(
            "SN1",
            Attribute::FirstConnected,
            Value::Timestamp(1),
            SourceKind::Usbstor,
            "k",
        )];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_MTP));
    }

    #[test]
    fn an_encryption_attribute_with_a_non_text_value_is_ignored() {
        // Defensive: the encryption type is a string; a mistyped Timestamp value yields no
        // finding rather than a panic or a garbled note.
        let claims = [claim(
            "disk-1",
            Attribute::Encryption,
            Value::Timestamp(0),
            SourceKind::DeviceImage,
            "img",
        )];
        assert!(!audit(&correlate(&claims))
            .iter()
            .any(|f| f.code == CODE_ENCRYPTED));
    }
}
