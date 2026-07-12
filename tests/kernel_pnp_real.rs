//! Tier-1 validation of the Kernel-PnP source against a real `Microsoft-Windows-Kernel-PnP
//! /Configuration.evtx` (the *Stolen Szechuan Sauce* case, DFIRArtifactMuseum, MIT). Ground
//! truth cross-checked with python-evtx (libyal): a SanDisk Cruzer Glide 3.0 mass-storage
//! device, `USB\VID_0781&PID_5597\4C530000261130109435`, first seen 2020-09-19 04:36:42 UTC
//! (epoch 1600490202). Env-gated on `USB_TEST_KERNELPNP_EVTX`.
#![allow(clippy::unwrap_used, clippy::doc_markdown)]

#[test]
fn kernel_pnp_evtx_decodes_the_sandisk_usb_device() {
    let Ok(path) = std::env::var("USB_TEST_KERNELPNP_EVTX") else {
        eprintln!(
            "SKIP: set USB_TEST_KERNELPNP_EVTX to the Szechuan Kernel-PnP Configuration .evtx"
        );
        return;
    };
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_usb4n6"))
        .arg(&path)
        .output()
        .expect("run usb4n6");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // The USB-layer device, keyed by the instance serial (matches the registry USBSTOR key).
    assert!(
        stdout.contains("\"device\":\"4C530000261130109435\""),
        "must decode the SanDisk USB device keyed by serial; got: {stdout}"
    );
    // Its connection time (epoch 1600490202 = 2020-09-19T04:36:42Z), as a KernelPnp witness.
    assert!(
        stdout.contains("\"Timestamp\":1600490202") && stdout.contains("\"source\":\"KernelPnp\""),
        "must record the connection time as a Kernel-PnP LastConnected witness; got: {stdout}"
    );
    // The host's own root hubs must NOT appear as devices.
    assert!(
        !stdout.contains("ROOT_HUB"),
        "USB root-hub controllers must be excluded; got: {stdout}"
    );
}
