//! The correlation core: group atomic [`Claim`]s into per-device histories and grade
//! each attribute's cross-source [`Consistency`].
//!
//! This is the source-agnostic moat. Every artifact in `docs/feature-parity.md` becomes
//! "emit `Claim`s from a new source adapter"; the grading logic here does not change as
//! sources are added.

use crate::model::{Attribute, Claim, DeviceKey, Provenance, Value};
use crate::Consistency;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// A value together with where it came from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ProvenancedValue {
    /// The reported value.
    pub value: Value,
    /// Its source and locator.
    pub provenance: Provenance,
}

/// One device attribute after cross-source correlation: the grade plus every
/// provenanced value that fed it (retained for verification and reporting).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CorrelatedAttribute {
    /// Which attribute this is.
    pub attribute: Attribute,
    /// How well the sources agree on it.
    pub consistency: Consistency,
    /// Every value seen, with provenance, sorted deterministically.
    pub values: Vec<ProvenancedValue>,
}

/// A device's full correlated history — one per distinct [`DeviceKey`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceHistory {
    /// The device identity.
    pub device: DeviceKey,
    /// Its attributes, sorted deterministically.
    pub attributes: Vec<CorrelatedAttribute>,
}

/// Correlate atomic claims into per-device histories, grading each attribute by how
/// well its independent sources agree. Output is deterministic (by device key, then
/// attribute, then value+provenance) so runs are diffable and reproducible.
#[must_use]
pub fn correlate(claims: &[Claim]) -> Vec<DeviceHistory> {
    // device -> attribute -> provenanced values, all in deterministic order.
    let mut grouped: BTreeMap<DeviceKey, BTreeMap<Attribute, Vec<ProvenancedValue>>> =
        BTreeMap::new();
    for c in claims {
        grouped
            .entry(c.device.clone())
            .or_default()
            .entry(c.attribute)
            .or_default()
            .push(ProvenancedValue {
                value: c.value.clone(),
                provenance: c.provenance.clone(),
            });
    }

    grouped
        .into_iter()
        .map(|(device, attrs)| {
            let attributes = attrs
                .into_iter()
                .map(|(attribute, mut values)| {
                    values.sort();
                    DeviceHistory::grade(attribute, values)
                })
                .collect();
            DeviceHistory { device, attributes }
        })
        .collect()
}

impl DeviceHistory {
    /// Grade one attribute's values by how well its *tamper-independent* sources agree.
    ///
    /// The rule is general — it holds for any attribute and any set of sources.
    /// Independence is counted by storage *container* ([`ArtifactContainer`]), not
    /// recording mechanism ([`SourceKind`]): sources sharing one container share one
    /// tamper surface, so their agreement is not tamper-independent corroboration.
    /// Fewer than two distinct containers cannot corroborate (`SingleSource`); two or
    /// more containers reporting a single value agree (`Corroborated`); two or more
    /// reporting differing values disagree (`Conflicting`). It is a description of the
    /// evidence, not a verdict on it.
    fn grade(attribute: Attribute, values: Vec<ProvenancedValue>) -> CorrelatedAttribute {
        let containers: BTreeSet<_> = values
            .iter()
            .map(|v| v.provenance.source.container())
            .collect();
        let distinct_values: BTreeSet<&Value> = values.iter().map(|v| &v.value).collect();
        let consistency = if containers.len() < 2 {
            Consistency::SingleSource
        } else if distinct_values.len() == 1 {
            Consistency::Corroborated
        } else {
            Consistency::Conflicting
        };
        CorrelatedAttribute {
            attribute,
            consistency,
            values,
        }
    }
}

/// Serialize histories as JSONL — one JSON object per line: pipeable, greppable,
/// bounded-memory. Machine output is faithful and never truncated.
///
/// # Errors
/// Propagates any `serde_json` serialization error.
pub fn to_jsonl(histories: &[DeviceHistory]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for h in histories {
        out.push_str(&serde_json::to_string(h)?);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceKind;

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
    fn single_source_is_graded_single_source() {
        let claims = [claim(
            "SN1",
            Attribute::FirstConnected,
            Value::Timestamp(1_700_000_000),
            SourceKind::Usbstor,
            "USBSTOR\\Disk&Ven",
        )];
        let hist = correlate(&claims);
        assert_eq!(hist.len(), 1);
        assert_eq!(hist[0].device, DeviceKey("SN1".to_string()));
        assert_eq!(hist[0].attributes[0].consistency, Consistency::SingleSource);
    }

    #[test]
    fn two_sources_that_agree_are_corroborated() {
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
                "setupapi.dev.log:42",
            ),
        ];
        let hist = correlate(&claims);
        assert_eq!(hist[0].attributes[0].consistency, Consistency::Corroborated);
        assert_eq!(hist[0].attributes[0].values.len(), 2);
    }

    #[test]
    fn same_container_agreement_is_not_tamper_independent_corroboration() {
        // USBSTOR and MountedDevices are different recording mechanisms but the SAME
        // storage container (the SYSTEM hive) — one hive tamper corrupts both, so their
        // agreement is not tamper-independent corroboration. Grade conservatively.
        let ts = Value::Timestamp(1_700_000_000);
        let claims = [
            claim(
                "SN1",
                Attribute::FirstConnected,
                ts.clone(),
                SourceKind::Usbstor,
                "USBSTOR\\...",
            ),
            claim(
                "SN1",
                Attribute::FirstConnected,
                ts,
                SourceKind::MountedDevices,
                "MountedDevices\\...",
            ),
        ];
        let hist = correlate(&claims);
        assert_eq!(hist[0].attributes[0].consistency, Consistency::SingleSource);
    }

    #[test]
    fn two_sources_that_disagree_are_conflicting() {
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
                Value::Timestamp(1_699_999_000),
                SourceKind::SetupApi,
                "l",
            ),
        ];
        let hist = correlate(&claims);
        assert_eq!(hist[0].attributes[0].consistency, Consistency::Conflicting);
    }

    #[test]
    fn two_claims_from_the_same_source_are_not_corroboration() {
        let ts = Value::Timestamp(1_700_000_000);
        let claims = [
            claim(
                "SN1",
                Attribute::FirstConnected,
                ts.clone(),
                SourceKind::Usbstor,
                "k1",
            ),
            claim(
                "SN1",
                Attribute::FirstConnected,
                ts,
                SourceKind::Usbstor,
                "k2",
            ),
        ];
        let hist = correlate(&claims);
        assert_eq!(hist[0].attributes[0].consistency, Consistency::SingleSource);
    }

    #[test]
    fn groups_by_device_and_attribute_deterministically() {
        let claims = [
            claim(
                "SN2",
                Attribute::VolumeName,
                Value::Text("KINGSTON".into()),
                SourceKind::MountedDevices,
                "m",
            ),
            claim(
                "SN1",
                Attribute::LastConnected,
                Value::Timestamp(1_700_000_500),
                SourceKind::PartitionDiag,
                "e",
            ),
            claim(
                "SN1",
                Attribute::VolumeSerial,
                Value::Text("A1B2".into()),
                SourceKind::MountedDevices,
                "m",
            ),
        ];
        let hist = correlate(&claims);
        assert_eq!(hist.len(), 2);
        // sorted by device key
        assert_eq!(hist[0].device, DeviceKey("SN1".into()));
        assert_eq!(hist[1].device, DeviceKey("SN2".into()));
        // SN1's attributes sorted by declaration order (LastConnected < VolumeSerial)
        let attrs: Vec<Attribute> = hist[0].attributes.iter().map(|a| a.attribute).collect();
        assert_eq!(attrs, [Attribute::LastConnected, Attribute::VolumeSerial]);
    }

    #[test]
    fn to_jsonl_is_one_object_per_line_and_valid_json() {
        let claims = [
            claim(
                "SN1",
                Attribute::FirstConnected,
                Value::Timestamp(1_700_000_000),
                SourceKind::Usbstor,
                "k",
            ),
            claim(
                "SN2",
                Attribute::VolumeName,
                Value::Text("DISK".into()),
                SourceKind::MountedDevices,
                "m",
            ),
        ];
        let hist = correlate(&claims);
        let jsonl = to_jsonl(&hist).unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("device").is_some());
            assert!(v.get("attributes").is_some());
        }
    }
}
