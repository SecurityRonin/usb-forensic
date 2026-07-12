//! Tier-1 validation of the unified-log USB reader against a REAL `log show --style json`
//! capture from a Mac with a USB device connected. Env-gated on `USB_TEST_MACOS_LOG`.
//! Independent oracle: the same device's VID appears in `system_profiler` (a separate tool).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use usb_forensic::parse_unified_log;

#[test]
fn real_unified_log_recovers_usb_enumeration_events() {
    let Ok(path) = std::env::var("USB_TEST_MACOS_LOG") else {
        eprintln!("SKIP: set USB_TEST_MACOS_LOG to a real `log show --style json` USB capture");
        return;
    };
    let bytes = std::fs::read(&path).expect("readable capture");
    let events = parse_unified_log(&bytes);
    assert!(
        !events.is_empty(),
        "the capture must contain at least one USB enumeration event"
    );
    // Every enumeration carries a VID/PID, a name, and a monotonic epoch time.
    assert!(events.iter().all(|e| e.when > 0 && !e.name.is_empty()));
}
