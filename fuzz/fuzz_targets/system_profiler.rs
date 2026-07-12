#![no_main]
//! macOS `system_profiler -json SPUSBDataType` parse over arbitrary bytes — never panics.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usb_forensic::parse_system_profiler(data);
});
