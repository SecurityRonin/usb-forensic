//! Aggregate super-timeline: a single chronological stream of every timestamped event
//! across all correlated devices — the cross-device view an examiner scans to see what
//! happened when, regardless of which device or which source recorded it.
//!
//! Per-device histories answer "what do we know about this device?"; the super-timeline
//! answers the orthogonal question "what happened on this system, in order?" It is a pure
//! projection over the already-correlated [`DeviceHistory`] set — it adds no new evidence
//! and makes no consistency claim, only an ordering of timestamped facts.

use crate::correlate::DeviceHistory;
use crate::model::{Attribute, DeviceKey, SourceKind, Value};
use serde::Serialize;

/// One timestamped event on the aggregate timeline.
///
/// Field order matters: `when` is first so the derived [`Ord`] sorts chronologically,
/// with the remaining fields breaking ties deterministically (diffable, reproducible).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct TimelineEvent {
    /// Event time, epoch seconds UTC — the primary sort key.
    pub when: i64,
    /// The device the event is about.
    pub device: DeviceKey,
    /// Which attribute this event marks (`FirstConnected`, `LastRemoved`, …).
    pub attribute: Attribute,
    /// The source that recorded it.
    pub source: SourceKind,
    /// Precise locator within that source (key path, log line, …).
    pub locator: String,
}

/// Build the aggregate super-timeline: every timestamped value across all devices, in
/// chronological order (ties broken deterministically). Non-timestamp attributes (volume
/// name/serial, accessed file) carry no time and are omitted — this is the
/// *when-did-what-happen* view, not the full per-device record.
#[must_use]
pub fn super_timeline(histories: &[DeviceHistory]) -> Vec<TimelineEvent> {
    let mut events: Vec<TimelineEvent> = Vec::new();
    for history in histories {
        for attr in &history.attributes {
            for pv in &attr.values {
                if let Value::Timestamp(when) = pv.value {
                    events.push(TimelineEvent {
                        when,
                        device: history.device.clone(),
                        attribute: attr.attribute,
                        source: pv.provenance.source,
                        locator: pv.provenance.locator.clone(),
                    });
                }
            }
        }
    }
    events.sort();
    events
}

/// Serialize the super-timeline as JSONL — one event per line, chronological, greppable
/// and pipeable.
pub fn timeline_to_jsonl(events: &[TimelineEvent]) -> Result<String, serde_json::Error> {
    let mut out = String::new();
    for event in events {
        out.push_str(&serde_json::to_string(event)?);
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate;
    use crate::model::{Attribute, Claim, DeviceKey, Provenance, SourceKind, Value};

    fn ts_claim(device: &str, attr: Attribute, when: i64, src: SourceKind, loc: &str) -> Claim {
        Claim {
            device: DeviceKey(device.into()),
            attribute: attr,
            value: Value::Timestamp(when),
            provenance: Provenance {
                source: src,
                locator: loc.into(),
            },
        }
    }

    #[test]
    fn events_are_ordered_chronologically_across_devices() {
        let claims = vec![
            ts_claim(
                "B",
                Attribute::LastRemoved,
                3_000,
                SourceKind::SetupApi,
                "b-rm",
            ),
            ts_claim(
                "A",
                Attribute::FirstConnected,
                1_000,
                SourceKind::Usbstor,
                "a-fc",
            ),
            ts_claim(
                "A",
                Attribute::LastConnected,
                2_000,
                SourceKind::Usbstor,
                "a-lc",
            ),
        ];
        let histories = correlate(&claims);
        let tl = super_timeline(&histories);
        let times: Vec<i64> = tl.iter().map(|e| e.when).collect();
        assert_eq!(times, vec![1_000, 2_000, 3_000]);
        assert_eq!(tl[0].device, DeviceKey("A".into()));
        assert_eq!(tl[0].attribute, Attribute::FirstConnected);
        assert_eq!(tl[2].device, DeviceKey("B".into()));
    }

    #[test]
    fn non_timestamp_values_are_omitted() {
        let claims = vec![
            Claim {
                device: DeviceKey("A".into()),
                attribute: Attribute::VolumeName,
                value: Value::Text("KINGSTON".into()),
                provenance: Provenance {
                    source: SourceKind::Usbstor,
                    locator: "vn".into(),
                },
            },
            ts_claim(
                "A",
                Attribute::FirstConnected,
                1_000,
                SourceKind::Usbstor,
                "fc",
            ),
        ];
        let tl = super_timeline(&correlate(&claims));
        assert_eq!(tl.len(), 1);
        assert_eq!(tl[0].attribute, Attribute::FirstConnected);
    }

    #[test]
    fn equal_times_break_ties_deterministically_by_device() {
        let claims = vec![
            ts_claim(
                "Z",
                Attribute::FirstConnected,
                500,
                SourceKind::Usbstor,
                "z",
            ),
            ts_claim(
                "A",
                Attribute::FirstConnected,
                500,
                SourceKind::Usbstor,
                "a",
            ),
        ];
        let tl = super_timeline(&correlate(&claims));
        assert_eq!(tl.len(), 2);
        assert_eq!(tl[0].device, DeviceKey("A".into()));
        assert_eq!(tl[1].device, DeviceKey("Z".into()));
    }

    #[test]
    fn jsonl_is_one_line_per_event_and_round_trips_the_fields() {
        let claims = vec![
            ts_claim(
                "A",
                Attribute::FirstConnected,
                1_000,
                SourceKind::Usbstor,
                "a-fc",
            ),
            ts_claim(
                "A",
                Attribute::LastRemoved,
                2_000,
                SourceKind::SetupApi,
                "a-rm",
            ),
        ];
        let tl = super_timeline(&correlate(&claims));
        let jsonl = timeline_to_jsonl(&tl).expect("serialize");
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        // each line is a standalone JSON object carrying the event fields verbatim.
        assert!(lines[0].contains("\"when\":1000"));
        assert!(lines[0].contains("\"FirstConnected\""));
        assert!(lines[0].contains("\"Usbstor\""));
        assert!(lines[1].contains("\"when\":2000"));
        assert!(lines[1].contains("\"a-rm\""));
    }

    #[test]
    fn empty_histories_yield_an_empty_timeline() {
        assert!(super_timeline(&[]).is_empty());
        assert_eq!(timeline_to_jsonl(&[]).expect("serialize"), "");
    }
}
