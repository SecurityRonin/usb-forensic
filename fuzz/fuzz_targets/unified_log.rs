#![no_main]
//! macOS unified-log (`log show --style json`) parse over arbitrary bytes — never panics.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usb_forensic::parse_unified_log(data);
});
