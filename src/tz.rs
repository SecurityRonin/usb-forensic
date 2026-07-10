//! Timezone normalization — correct host-local timestamps to UTC.
//!
//! Some sources ([`SourceKind::clock_is_local`]) record local wall-clock with no zone,
//! so their readers store it naively (local-as-UTC epoch). Given the host's UTC offset,
//! this shifts those timestamps to true UTC, so a local `setupapi`/Linux time and a UTC
//! registry/LNK time for the same event line up instead of appearing to conflict.

use crate::{Claim, Value};

/// Shift every local-clock timestamp claim to UTC by the host's UTC offset in seconds
/// (e.g. `-18000` for a host at UTC−5). A local reader stored the wall-clock as-if-UTC,
/// so true UTC = stored − offset. UTC-clock claims and text values are left untouched.
///
/// Apply this to the gathered claims **before** correlation so consistency scoring
/// compares like-for-like clocks.
pub fn normalize_local_clocks(claims: &mut [Claim], host_utc_offset_secs: i64) {
    for claim in claims.iter_mut() {
        if !claim.provenance.source.clock_is_local() {
            continue;
        }
        if let Value::Timestamp(secs) = &mut claim.value {
            *secs -= host_utc_offset_secs;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, DeviceKey, Provenance, SourceKind};

    fn claim(src: SourceKind, value: Value) -> Claim {
        Claim {
            device: DeviceKey("SN1".into()),
            attribute: Attribute::FirstConnected,
            value,
            provenance: Provenance {
                source: src,
                locator: "l".into(),
            },
        }
    }

    #[test]
    fn local_timestamp_is_shifted_utc_is_not() {
        let mut claims = [
            claim(SourceKind::SetupApi, Value::Timestamp(1_700_000_000)), // local → shift
            claim(SourceKind::Usbstor, Value::Timestamp(1_700_000_000)),  // UTC → keep
            claim(SourceKind::SetupApi, Value::Text("KINGSTON".into())), // local but not a time → keep
        ];
        normalize_local_clocks(&mut claims, 3600); // host at UTC+1
        assert_eq!(claims[0].value, Value::Timestamp(1_699_996_400)); // −3600
        assert_eq!(claims[1].value, Value::Timestamp(1_700_000_000)); // untouched
        assert_eq!(claims[2].value, Value::Text("KINGSTON".into())); // untouched
    }

    #[test]
    fn clock_is_local_only_for_setupapi() {
        assert!(SourceKind::SetupApi.clock_is_local());
        assert!(!SourceKind::Usbstor.clock_is_local());
        assert!(!SourceKind::Lnk.clock_is_local());
    }
}
