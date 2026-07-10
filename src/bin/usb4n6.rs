//! `usb4n6` — run the USB-history correlation pipeline over evidence sources and emit a
//! JSONL timeline plus graded findings.
//!
//! Thin shell (Humble Object): every decision — parsing, correlation, grading,
//! serialization — lives in the tested `usb_forensic` / `peripheral_core` / `lnk_core`
//! libraries; this binary only reads input, detects its type, wires the sources, and
//! writes output.
//!
//! ```text
//! usb4n6 [--table|--report] <file>...   # setupapi.dev.log, .lnk, and
//!                                        # *.automaticDestinations-ms (type auto-detected)
//! usb4n6 --version
//! ```
//! stdout: JSONL (default), a results grid (`--table`), or a court report (`--report`).
//! stderr: a summary and graded findings. Registry (USBSTOR/SCSI/USB) and event-log
//! sources join here as they land.

use peripheral_core::setupapi::parse_setupapi;
use std::process::ExitCode;
use usb_forensic::{
    audit, correlate_sources, to_jsonl, JumpListArtifact, JumpListSource, LnkArtifact, LnkSource,
    PeripheralSource,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("usb4n6 {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let mode = if args.iter().any(|a| a == "--report") {
        Output::Report
    } else if args.iter().any(|a| a == "--table") {
        Output::Table
    } else {
        Output::Jsonl
    };
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if paths.is_empty() {
        eprintln!(
            "usage: usb4n6 [--table|--report] <file>...   (setupapi.dev.log and/or .lnk; -V)"
        );
        return ExitCode::FAILURE;
    }
    run(&paths, mode)
}

/// How to render the correlated histories on stdout.
#[derive(Clone, Copy)]
enum Output {
    /// One JSON object per device (machine, round-trippable) — the default.
    Jsonl,
    /// A human-readable results grid.
    Table,
    /// A court-oriented Markdown forensic report.
    Report,
}

/// A `.lnk` Shell Link begins with `HeaderSize` = 0x4C little-endian.
fn is_shell_link(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(&[0x4C, 0x00, 0x00, 0x00])
}

/// An `*.automaticDestinations-ms` jump list is an OLE/CFB compound file.
fn is_compound_file(bytes: &[u8]) -> bool {
    bytes.get(..8) == Some(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

fn run(paths: &[&String], mode: Output) -> ExitCode {
    let mut connections = Vec::new();
    let mut lnk_artifacts = Vec::new();
    let mut jumplists = Vec::new();

    for path in paths {
        let bytes = match std::fs::read(path.as_str()) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("usb4n6: cannot read {path}: {err}");
                return ExitCode::FAILURE;
            }
        };
        if is_compound_file(&bytes) {
            match lnk_core::parse_automatic_destinations(&bytes, Some(path)) {
                Some(list) => jumplists.push(JumpListArtifact {
                    source_path: (*path).clone(),
                    list,
                }),
                None => eprintln!("usb4n6: {path}: not a valid jump list, skipping"),
            }
        } else if is_shell_link(&bytes) {
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
    let jumplist = JumpListSource::new(&jumplists);
    let histories = correlate_sources(&[&peripheral, &lnk, &jumplist]);

    let findings = audit(&histories);

    let rendered = match mode {
        Output::Jsonl => match to_jsonl(&histories) {
            Ok(jsonl) => jsonl,
            Err(err) => {
                eprintln!("usb4n6: serialization failed: {err}");
                return ExitCode::FAILURE;
            }
        },
        Output::Table => usb_forensic::render_table(&histories),
        Output::Report => usb_forensic::render_report(&histories, &findings),
    };
    print!("{rendered}");

    eprintln!(
        "usb4n6: {} device(s) from {} source record(s), {} finding(s)",
        histories.len(),
        connections.len() + lnk_artifacts.len() + jumplists.len(),
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
