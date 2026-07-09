//! The [`HistorySource`] contract: the stable integration point every reader-crate
//! adapter implements.
//!
//! An adapter is *thin* — it maps a fleet reader crate's already-decoded output (a
//! parsed registry value, a `setupapi` record, an event record) into atomic
//! [`Claim`]s. It never parses raw artifact bytes itself; that is the reader crate's
//! job, fuzzed and tested upstream. This keeps the adapter a pure, unit-testable
//! mapping and keeps the correlation core source-agnostic.

use crate::model::Claim;
use crate::DeviceHistory;

/// A source of USB-history claims — one thin adapter over one reader crate's output.
pub trait HistorySource {
    /// Emit every atomic claim this source can contribute.
    fn claims(&self) -> Vec<Claim>;
}

/// Gather claims from many sources and correlate them into per-device histories — the
/// one-call entry point a CLI or Issen uses.
#[must_use]
pub fn correlate_sources(sources: &[&dyn HistorySource]) -> Vec<DeviceHistory> {
    let all: Vec<Claim> = sources.iter().flat_map(|s| s.claims()).collect();
    crate::correlate(&all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, DeviceKey, Provenance, SourceKind, Value};
    use crate::Consistency;

    struct Mock(Vec<Claim>);
    impl HistorySource for Mock {
        fn claims(&self) -> Vec<Claim> {
            self.0.clone()
        }
    }

    fn claim(src: SourceKind) -> Claim {
        Claim {
            device: DeviceKey("SN1".into()),
            attribute: Attribute::FirstConnected,
            value: Value::Timestamp(1_700_000_000),
            provenance: Provenance {
                source: src,
                locator: "x".into(),
            },
        }
    }

    #[test]
    fn correlate_sources_merges_claims_from_every_source() {
        let a = Mock(vec![claim(SourceKind::Usbstor)]);
        let b = Mock(vec![claim(SourceKind::SetupApi)]);
        let sources: [&dyn HistorySource; 2] = [&a, &b];
        let hist = correlate_sources(&sources);
        assert_eq!(hist.len(), 1);
        // two distinct sources agreeing on the same value → corroborated
        assert_eq!(hist[0].attributes[0].consistency, Consistency::Corroborated);
    }
}
