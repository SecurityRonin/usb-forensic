#![no_main]
//! Device-image MBR/VBR boot-sector parse over arbitrary bytes — must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = usb_forensic::parse_boot_sectors(data);
});
