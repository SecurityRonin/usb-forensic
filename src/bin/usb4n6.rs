//! `usb4n6` — run the USB-history correlation pipeline over evidence sources and emit a
//! JSONL timeline plus graded findings.
//!
//! Thin shell (Humble Object): every decision — parsing, correlation, grading,
//! serialization — lives in the tested `usb_forensic` / `peripheral_core` / `lnk_core`
//! libraries; this binary only reads input, detects its type, wires the sources, and
//! writes output.
//!
//! ```text
//! usb4n6 [--table|--timeline|--report|--docx|--pdf] [--tz-offset=<secs>] [--year=<YYYY>] <file>...
//!     # files: setupapi.dev.log, a SYSTEM hive, .lnk, *.automaticDestinations-ms,
//!     #        or a Linux syslog/dmesg (type auto-detected by content)
//! usb4n6 --version
//! ```
//! stdout: JSONL (default), a results grid (`--table`), the aggregate super-timeline as
//! JSONL (`--timeline`), a Markdown court report (`--report`), or a native `.docx`/`.pdf`
//! report. `--tz-offset=<secs>` normalizes
//! host-local (setupapi/Linux) timestamps to UTC. `--year=<YYYY>` supplies the
//! reference year for year-less Linux syslog timestamps (required when a syslog is
//! given). stderr: a summary and graded findings.

use peripheral_core::linux_syslog::parse_linux_syslog;
use peripheral_core::registry::parse_registry;
use peripheral_core::setupapi::parse_setupapi;
use std::process::ExitCode;
use usb_forensic::{
    audit, correlate_sources, to_jsonl, HistorySource, JumpListArtifact, JumpListSource,
    LnkArtifact, LnkSource, PeripheralSource, SourceKind,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("usb4n6 {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let mode = if args.iter().any(|a| a == "--pdf") {
        Output::Pdf
    } else if args.iter().any(|a| a == "--docx") {
        Output::Docx
    } else if args.iter().any(|a| a == "--report") {
        Output::Report
    } else if args.iter().any(|a| a == "--table") {
        Output::Table
    } else if args.iter().any(|a| a == "--timeline") {
        Output::Timeline
    } else {
        Output::Jsonl
    };
    // Optional host UTC offset (seconds) to normalize local-clock (setupapi/Linux) times.
    let tz_offset = args.iter().find_map(|a| {
        a.strip_prefix("--tz-offset=")
            .and_then(|v| v.parse::<i64>().ok())
    });
    // Reference year for year-less Linux syslog timestamps (required for a syslog).
    let year = args.iter().find_map(|a| {
        a.strip_prefix("--year=")
            .and_then(|v| v.parse::<i64>().ok())
    });
    let paths: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if paths.is_empty() {
        eprintln!(
            "usage: usb4n6 [--table|--timeline|--report|--docx|--pdf] [--tz-offset=<secs>] \
             [--year=<YYYY>] <file>...  \
             (setupapi.dev.log/SYSTEM hive/.lnk/jumplist/Linux syslog; -V)"
        );
        return ExitCode::FAILURE;
    }
    run(&paths, mode, tz_offset, year)
}

/// How to render the correlated histories on stdout.
#[derive(Clone, Copy)]
enum Output {
    /// One JSON object per device (machine, round-trippable) — the default.
    Jsonl,
    /// A human-readable results grid.
    Table,
    /// The aggregate super-timeline: every timestamped event across all devices,
    /// chronological, as JSONL (one event per line).
    Timeline,
    /// A court-oriented Markdown forensic report.
    Report,
    /// The forensic report as a native Word `.docx` (binary; redirect to a file).
    Docx,
    /// The forensic report as a native `.pdf` (binary; redirect to a file).
    Pdf,
}

/// A `.lnk` Shell Link begins with `HeaderSize` = 0x4C little-endian.
fn is_shell_link(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(&[0x4C, 0x00, 0x00, 0x00])
}

/// An `*.automaticDestinations-ms` jump list is an OLE/CFB compound file.
fn is_compound_file(bytes: &[u8]) -> bool {
    bytes.get(..8) == Some(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

/// A Windows registry hive begins with the `regf` base-block signature.
fn is_registry_hive(bytes: &[u8]) -> bool {
    bytes.get(..4) == Some(b"regf")
}

/// A Linux kernel log carries the `New USB device found` enumeration marker that the
/// syslog reader keys on; setupapi text does not.
fn looks_like_linux_syslog(text: &str) -> bool {
    text.contains("New USB device found")
}

/// Write a binary artifact to stdout; returns `false` (and reports) on I/O error.
fn write_binary(bytes: &[u8], label: &str) -> bool {
    use std::io::Write as _;
    match std::io::stdout().write_all(bytes) {
        Ok(()) => true,
        Err(err) => {
            eprintln!("usb4n6: cannot write {label}: {err}");
            false
        }
    }
}

/// Device connections and artifacts gathered from the input files, grouped by origin
/// so each batch is stamped with the right [`SourceKind`] (which drives container /
/// clock-locality reasoning downstream).
#[derive(Default)]
struct Ingested {
    setupapi: Vec<peripheral_core::DeviceConnection>,
    registry: Vec<peripheral_core::DeviceConnection>,
    linux: Vec<peripheral_core::DeviceConnection>,
    lnk: Vec<LnkArtifact>,
    jumplists: Vec<JumpListArtifact>,
}

impl Ingested {
    /// Total source records read, across every origin.
    fn record_count(&self) -> usize {
        self.setupapi.len()
            + self.registry.len()
            + self.linux.len()
            + self.lnk.len()
            + self.jumplists.len()
    }
}

/// Read and classify every input file by content, routing it to the matching reader.
/// Returns `None` (after reporting) on a fatal error: an unreadable file, or a Linux
/// syslog with no `--year` (its year-less timestamps would otherwise be silently wrong).
fn ingest(paths: &[&String], year: Option<i64>) -> Option<Ingested> {
    let mut g = Ingested::default();
    for path in paths {
        let bytes = match std::fs::read(path.as_str()) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("usb4n6: cannot read {path}: {err}");
                return None;
            }
        };
        if is_compound_file(&bytes) {
            match lnk_core::parse_automatic_destinations(&bytes, Some(path)) {
                Some(list) => g.jumplists.push(JumpListArtifact {
                    source_path: (*path).clone(),
                    list,
                }),
                None => eprintln!("usb4n6: {path}: not a valid jump list, skipping"),
            }
        } else if is_shell_link(&bytes) {
            match lnk_core::parse_shell_link(&bytes) {
                Some(link) => g.lnk.push(LnkArtifact {
                    source_path: (*path).clone(),
                    link,
                }),
                None => eprintln!("usb4n6: {path}: not a valid Shell Link, skipping"),
            }
        } else if is_registry_hive(&bytes) {
            match winreg_core::hive::Hive::from_bytes(bytes) {
                Ok(hive) => g.registry.extend(parse_registry(&hive, path)),
                Err(err) => eprintln!("usb4n6: {path}: not a valid registry hive: {err}"),
            }
        } else {
            let text = String::from_utf8_lossy(&bytes);
            if looks_like_linux_syslog(&text) {
                let Some(y) = year else {
                    eprintln!(
                        "usb4n6: {path}: Linux syslog timestamps are year-less — \
                         pass --year=<YYYY>"
                    );
                    return None;
                };
                g.linux.extend(parse_linux_syslog(&text, path, y));
            } else {
                g.setupapi.extend(parse_setupapi(&text, path));
            }
        }
    }
    Some(g)
}

fn run(paths: &[&String], mode: Output, tz_offset: Option<i64>, year: Option<i64>) -> ExitCode {
    let Some(g) = ingest(paths, year) else {
        return ExitCode::FAILURE;
    };

    let setupapi = PeripheralSource::new(&g.setupapi, SourceKind::SetupApi);
    let registry = PeripheralSource::new(&g.registry, SourceKind::Usbstor);
    let linux = PeripheralSource::new(&g.linux, SourceKind::LinuxKernelLog);
    let lnk = LnkSource::new(&g.lnk);
    let jumplist = JumpListSource::new(&g.jumplists);
    let sources: [&dyn HistorySource; 5] = [&setupapi, &registry, &linux, &lnk, &jumplist];

    let histories = if let Some(offset) = tz_offset {
        // Normalize local-clock timestamps to UTC before correlating.
        let mut claims: Vec<_> = sources.iter().flat_map(|s| s.claims()).collect();
        usb_forensic::normalize_local_clocks(&mut claims, offset);
        usb_forensic::correlate(&claims)
    } else {
        correlate_sources(&sources)
    };

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
        Output::Timeline => {
            let events = usb_forensic::super_timeline(&histories);
            match usb_forensic::timeline_to_jsonl(&events) {
                Ok(jsonl) => jsonl,
                Err(err) => {
                    eprintln!("usb4n6: serialization failed: {err}");
                    return ExitCode::FAILURE;
                }
            }
        }
        Output::Report => usb_forensic::render_report(&histories, &findings),
        Output::Docx => {
            if !write_binary(&usb_forensic::render_docx(&histories, &findings), "docx") {
                return ExitCode::FAILURE;
            }
            String::new()
        }
        Output::Pdf => {
            if !write_binary(&usb_forensic::render_pdf(&histories, &findings), "pdf") {
                return ExitCode::FAILURE;
            }
            String::new()
        }
    };
    print!("{rendered}");

    eprintln!(
        "usb4n6: {} device(s) from {} source record(s), {} finding(s)",
        histories.len(),
        g.record_count(),
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
