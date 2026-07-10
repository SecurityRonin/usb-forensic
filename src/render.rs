//! Human view: a readable results grid (one block per device). The machine view is
//! [`to_jsonl`](crate::to_jsonl) — faithful and round-trippable; this view renders for
//! eyes (datetimes formatted, consistency labelled, values unwrapped).

use crate::{DeviceHistory, Value};

/// Format a Unix-epoch-seconds timestamp as `YYYY-MM-DD HH:MM:SS UTC`.
///
/// Uses Howard Hinnant's `civil_from_days` (public-domain), with `div_euclid` so it is
/// correct and branch-total for any `i64` — no dependency, validated against `date(1)`.
#[must_use]
pub fn format_epoch(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hour, min, sec) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02} UTC")
}

fn render_value(value: &Value) -> String {
    match value {
        Value::Timestamp(secs) => format_epoch(*secs),
        Value::Text(text) => text.clone(),
    }
}

/// Render device histories as a human-readable results grid.
#[must_use]
pub fn render_table(histories: &[DeviceHistory]) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for history in histories {
        // writeln! into a String is infallible; the discarded Result satisfies the
        // format-push-string lint without an unwrap.
        let _ = writeln!(out, "Device: {}", history.device.0);
        for attr in &history.attributes {
            let values: Vec<String> = attr
                .values
                .iter()
                .map(|pv| render_value(&pv.value))
                .collect();
            let _ = writeln!(
                out,
                "  {:<16} {:<13} {}",
                format!("{:?}", attr.attribute),
                attr.consistency.label(),
                values.join(", ")
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, DeviceKey, Provenance, SourceKind};
    use crate::{correlate, Claim};

    #[test]
    fn format_epoch_matches_the_date_oracle() {
        // `date -u -r <epoch>` ground truth.
        assert_eq!(format_epoch(0), "1970-01-01 00:00:00 UTC"); // month<=2 branch
        assert_eq!(format_epoch(1_681_760_520), "2023-04-17 19:42:00 UTC"); // month>2 branch
        assert_eq!(format_epoch(1_600_357_894), "2020-09-17 15:51:34 UTC");
    }

    #[test]
    fn table_renders_a_block_per_device_with_formatted_values() {
        let claims = [
            Claim {
                device: DeviceKey("SN1".into()),
                attribute: Attribute::FirstConnected,
                value: Value::Timestamp(1_681_760_520),
                provenance: Provenance {
                    source: SourceKind::SetupApi,
                    locator: "l".into(),
                },
            },
            Claim {
                device: DeviceKey("SN1".into()),
                attribute: Attribute::VolumeName,
                value: Value::Text("KINGSTON".into()),
                provenance: Provenance {
                    source: SourceKind::MountedDevices,
                    locator: "m".into(),
                },
            },
        ];
        let table = render_table(&correlate(&claims));
        assert!(table.contains("Device: SN1"));
        assert!(
            table.contains("2023-04-17 19:42:00 UTC"),
            "timestamp rendered human"
        );
        assert!(table.contains("KINGSTON"), "text value rendered");
        assert!(table.contains("single-source"), "consistency labelled");
    }
}
