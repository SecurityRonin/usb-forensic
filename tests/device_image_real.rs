//! Tier-1 real-artifact validation of the device-image boot-sector reader against the
//! NIST CFReDS Data-Leakage "RM#2" USB stick image (the SanDisk "IAMAN" device).
//!
//! Ground truth from the NIST answer key + the host registry: RM#2's MBR disk signature is
//! `0xE221034C` (the `MountedDevices` disk signature for drive `E:`) and its current FAT
//! volume serial is `3034076057` (the reformatted `EMDMgmt` "IAMAN $_@" record). Env-gated:
//! extract RM#2's boot region (`img_cat rm2.E01 | head -c 131072 > rm2-boot.raw`) and point
//! `USB_TEST_DEVICE_IMAGE` at it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::doc_markdown)]

use usb_forensic::parse_boot_sectors;

#[test]
fn cfreds_rm2_boot_sectors_match_the_host_footprint() {
    let Ok(path) = std::env::var("USB_TEST_DEVICE_IMAGE") else {
        eprintln!("SKIP: set USB_TEST_DEVICE_IMAGE to the CFReDS RM#2 boot region");
        return;
    };
    let bytes = std::fs::read(&path).expect("readable device image");
    let img = parse_boot_sectors(&bytes).expect("valid MBR device image");
    // Disk signature == MountedDevices drive E: (0xE221034C).
    assert_eq!(img.disk_signature, 0xE221_034C);
    // Current FAT volume serial == the reformatted EMDMgmt "IAMAN $_@" record.
    assert_eq!(img.fat_volume_serial, Some(3_034_076_057));
    // Real FAT32 media must NOT false-positive as encrypted.
    assert_eq!(img.encryption, None);
}
