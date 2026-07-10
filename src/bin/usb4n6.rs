//! `usb4n6` — run the USB-history correlation pipeline over an evidence source and emit
//! a JSONL timeline plus graded findings.
//!
//! Thin shell (Humble Object): every decision — parsing, correlation, grading,
//! serialization — lives in the tested `usb_forensic` / `peripheral_core` libraries; this
//! binary only reads input, wires the source, and writes output.
//!
//! ```text
//! usb4n6 <setupapi.dev.log>     # JSONL device histories on stdout, findings on stderr
//! usb4n6 --version
//! ```
//! Registry (USBSTOR/SCSI/USB), LNK, and event-log sources join here as they land.

use peripheral_core::setupapi::parse_setupapi;
use std::process::ExitCode;
use usb_forensic::{audit, correlate_sources, to_jsonl, PeripheralSource};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("-V" | "--version") => {
            println!("usb4n6 {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some(path) if !path.starts_with('-') => run(path),
        _ => {
            eprintln!("usage: usb4n6 <setupapi.dev.log>   (or --version)");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &str) -> ExitCode {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            eprintln!("usb4n6: cannot read {path}: {err}");
            return ExitCode::FAILURE;
        }
    };

    let connections = parse_setupapi(&text, path);
    let source = PeripheralSource::new(&connections);
    let histories = correlate_sources(&[&source]);

    match to_jsonl(&histories) {
        Ok(jsonl) => print!("{jsonl}"),
        Err(err) => {
            eprintln!("usb4n6: serialization failed: {err}");
            return ExitCode::FAILURE;
        }
    }

    let findings = audit(&histories);
    eprintln!(
        "usb4n6: {} device(s), {} finding(s)",
        histories.len(),
        findings.len()
    );
    for finding in &findings {
        eprintln!(
            "  [{:?}] {} — {}",
            finding.severity, finding.code, finding.note
        );
    }
    ExitCode::SUCCESS
}
