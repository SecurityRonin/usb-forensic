//! Validation scaffold for the DriverFrameworks-UserMode source against a real
//! `Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx`. Env-gated on
//! `USB_TEST_DRIVERFRAMEWORK_EVTX`.
//!
//! Unlike the Kernel-PnP source, no public corpus with ground truth ships this log: the
//! DriverFrameworks-UserMode/Operational channel is **disabled by default on Win8+**, so it is
//! absent from the standard forensic image sets (Stolen Szechuan Sauce, DFIRArtifactMuseum,
//! EVTX-ATTACK-SAMPLES, hayabusa-sample-evtx all lack it). The source's field structure is
//! therefore validated against two independent authoritative maps in the unit tests — Eric
//! Zimmerman's EvtxECmd map and IncideDigital's rvt2 — rather than a corpus. This test runs the
//! real-data check the moment such an `.evtx` is supplied (e.g. one captured on a host where the
//! log was enabled), completing the Tier-1 backstop. See `docs/validation.md`.
#![allow(clippy::unwrap_used, clippy::doc_markdown)]

#[test]
fn driver_framework_evtx_yields_connect_and_disconnect_witnesses() {
    let Ok(path) = std::env::var("USB_TEST_DRIVERFRAMEWORK_EVTX") else {
        eprintln!(
            "SKIP: set USB_TEST_DRIVERFRAMEWORK_EVTX to a real \
             DriverFrameworks-UserMode/Operational .evtx with USB events"
        );
        return;
    };
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_usb4n6"))
        .arg(&path)
        .output()
        .expect("run usb4n6");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // A DriverFrameworks arrival/removal must surface as a DriverFramework-sourced claim.
    assert!(
        stdout.contains("\"source\":\"DriverFramework\""),
        "a DriverFrameworks .evtx must yield a DriverFramework witness; got: {stdout}"
    );
    // The host's own root hubs must NOT appear as devices.
    assert!(
        !stdout.contains("ROOT_HUB"),
        "USB root-hub controllers must be excluded; got: {stdout}"
    );
}
