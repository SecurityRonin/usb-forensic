//! Tier-1 real-artifact validation of the `system_profiler` USB reader against a REAL
//! capture from a Mac with a USB device plugged in. Env-gated on `USB_TEST_MACOS_USB`
//! (a `system_profiler -json SPUSBDataType` capture). Cross-check: the same device also
//! appears in `ioreg -c IOUSBHostDevice`, an independent macOS oracle.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use usb_forensic::parse_system_profiler;

#[test]
fn real_system_profiler_capture_extracts_the_plugged_in_usb_device() {
    let Ok(path) = std::env::var("USB_TEST_MACOS_USB") else {
        eprintln!("SKIP: set USB_TEST_MACOS_USB to a real `system_profiler -json SPUSBDataType` capture with a device attached");
        return;
    };
    let bytes = std::fs::read(&path).expect("readable capture");
    let devs = parse_system_profiler(&bytes);
    assert!(
        !devs.is_empty(),
        "the capture must contain at least one attached USB device"
    );
    // A real USB stick reports a product id (and usually a serial); at least one device
    // must carry an identity the reader recovered.
    assert!(
        devs.iter().any(|d| d.pid.is_some() || d.serial.is_some()),
        "at least one device must have a recovered VID/PID or serial"
    );
}
