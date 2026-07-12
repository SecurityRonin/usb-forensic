//! Tier-1 validation of built-in E01 image mounting: usb4n6 reads an EnCase E01 directly
//! (no external mounter) and decodes the same device the raw extraction does. Env-gated on
//! `USB_TEST_DEVICE_E01` (a real CFReDS rm2 stick E01). Cross-check: the disk signature and
//! FAT volume serial must match the raw `rm2-boot.raw` extraction (0xE221034C / B4D8-5399).
#![allow(clippy::unwrap_used, clippy::doc_markdown)]

#[test]
fn e01_image_is_mounted_and_decoded_to_the_same_device() {
    let Ok(path) = std::env::var("USB_TEST_DEVICE_E01") else {
        eprintln!("SKIP: set USB_TEST_DEVICE_E01 to a real CFReDS rm2 E01 image");
        return;
    };
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_usb4n6"))
        .arg(&path)
        .output()
        .expect("run usb4n6");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("disk-E221034C") && stdout.contains("B4D8-5399"),
        "E01 mount must decode the rm2 stick (disk sig E221034C, FAT serial B4D8-5399); got: {stdout}"
    );
}
