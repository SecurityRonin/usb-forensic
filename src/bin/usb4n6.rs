//! `usb4n6` — run the USB-history correlation pipeline over evidence sources and emit a
//! JSONL timeline plus graded findings.
//!
//! Thin shell (Humble Object): every decision — parsing, correlation, grading,
//! serialization — lives in the tested `usb_forensic` / `peripheral_core` / `lnk_core`
//! libraries; this binary only reads input, detects its type, wires the sources, and
//! writes output.
//!
//! ```text
//! usb4n6 <file>...   # setupapi.dev.log and/or .lnk files (type auto-detected)
//! usb4n6 --version
//! ```
//! stdout: one JSON object per device history. stderr: a summary and graded findings.
//! Registry (USBSTOR/SCSI/USB) and event-log sources join here as they land.

use peripheral_core::setupapi::parse_setupapi;
use std::process::ExitCode;
use usb_forensic::{audit, correlate_sources, to_jsonl, LnkArtifact, LnkSource, PeripheralSource};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("usb4n6 {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let table = args.iter().any(|a| a == "--table");
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if paths.is_empty() {
        eprintln!(
            "usage: usb4n6 [--table] <file>...   (setupapi.dev.log and/or .lnk; or --version)"
        );
        return ExitCode::FAILURE;
    }
    run(&paths, table)
}

/// A `.lnk` / jump-list Shell Link begins with `HeaderSize` = 0x4C little-endian.
fn is_shell_link(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(&[0x4C, 0x00, 0x00, 0x00])
}

fn run(paths: &[&String], table: bool) -> ExitCode {
    let mut connections = Vec::new();
    let mut lnk_artifacts = Vec::new();

    for path in paths {
        let bytes = match std::fs::read(path.as_str()) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("usb4n6: cannot read {path}: {err}");
                return ExitCode::FAILURE;
            }
        };
        if is_shell_link(&bytes) {
            match lnk_core::parse_shell_link(&bytes) {
                Some(link) => lnk_artifacts.push(LnkArtifact {
                    source_path: (*path).clone(),
                    link,
                }),
                None => eprintln!("usb4n6: {path}: not a valid Shell Link, skipping"),
            }
        } else {
            let text = String::from_utf8_lossy(&bytes);
            connections.extend(parse_setupapi(&text, path));
        }
    }

    let peripheral = PeripheralSource::new(&connections);
    let lnk = LnkSource::new(&lnk_artifacts);
    let histories = correlate_sources(&[&peripheral, &lnk]);

    if table {
        print!("{}", usb_forensic::render_table(&histories));
    } else {
        match to_jsonl(&histories) {
            Ok(jsonl) => print!("{jsonl}"),
            Err(err) => {
                eprintln!("usb4n6: serialization failed: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    let findings = audit(&histories);
    eprintln!(
        "usb4n6: {} device(s) from {} source record(s), {} finding(s)",
        histories.len(),
        connections.len() + lnk_artifacts.len(),
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
