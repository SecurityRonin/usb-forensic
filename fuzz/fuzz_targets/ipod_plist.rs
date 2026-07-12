#![no_main]
//! macOS `com.apple.iPod.plist` parse over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usb_forensic::parse_ipod_plist(data);
});
