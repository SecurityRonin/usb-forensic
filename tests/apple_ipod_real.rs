//! Tier-1 real-artifact validation of the `com.apple.iPod.plist` reader against a genuine
//! macOS `com.apple.iPod.plist`. Env-gated on `USB_TEST_IPOD_PLIST`, never committed — the
//! artifact carries real device serials / IMEIs (PII). Point it at a real plist copy.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use usb_forensic::parse_ipod_plist;

#[test]
fn real_ipod_plist_decodes_apple_device_connections() {
    let Ok(path) = std::env::var("USB_TEST_IPOD_PLIST") else {
        eprintln!("SKIP: set USB_TEST_IPOD_PLIST to a real com.apple.iPod.plist");
        return;
    };
    let bytes = std::fs::read(&path).expect("readable plist");
    let devs = parse_ipod_plist(&bytes);
    assert!(
        !devs.is_empty(),
        "the plist lists at least one Apple device"
    );
    // A real history has at least one device with both a serial and a last-connected time.
    assert!(devs
        .iter()
        .any(|d| d.serial.is_some() && d.last_connected.is_some()));
}
