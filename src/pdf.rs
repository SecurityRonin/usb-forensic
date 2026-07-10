//! Native PDF export — the court report as a multi-page PDF with **no dependency**.
//!
//! A minimal PDF is a set of numbered objects, a byte-offset cross-reference table, and
//! a trailer. This writes the report ([`render_report`]) as
//! monospaced (Courier) text, paginated, with a correct `xref` — no font embedding, no
//! compression. The report text comes from [`render_report`]; validated against an
//! independent oracle (`pypdf` reads the pages back).

use crate::render_report;
use crate::DeviceHistory;
use forensicnomicon::report::Finding;
use std::fmt::Write as _;

const LINES_PER_PAGE: usize = 60;
const FONT_SIZE: i32 = 9;
const LEADING: i32 = 12;
const TOP: i32 = 760;
const LEFT: i32 = 40;

/// Fold to the Courier (Latin-1) glyphs the base font can render, then escape the three
/// characters special inside a PDF literal string. Common Unicode punctuation maps to its
/// ASCII form; any other non-ASCII becomes `?` so the byte stream stays well-formed.
fn pdf_escape(text: &str) -> String {
    let folded: String = text
        .chars()
        .map(|c| match c {
            '\u{2014}' | '\u{2013}' => '-',  // em / en dash
            '\u{201C}' | '\u{201D}' => '"',  // curly double quotes
            '\u{2018}' | '\u{2019}' => '\'', // curly single quotes
            c if c.is_ascii() => c,
            _ => '?',
        })
        .collect();
    folded
        .replace('\\', r"\\")
        .replace('(', r"\(")
        .replace(')', r"\)")
}

/// Render the forensic report as a multi-page PDF byte stream.
#[must_use]
pub fn render_pdf(histories: &[DeviceHistory], findings: &[Finding]) -> Vec<u8> {
    let report = render_report(histories, findings);
    // render_report always emits the title + summary + methodology, so there is at least
    // one line and thus at least one page.
    let lines: Vec<&str> = report.lines().collect();
    let pages: Vec<&[&str]> = lines.chunks(LINES_PER_PAGE).collect();
    let n = pages.len();

    // Object numbering: 1 Catalog, 2 Pages, 3 Font, 4..4+n content streams, then n Page objects.
    let content_base = 4;
    let page_base = content_base + n;
    let mut bodies: Vec<String> = Vec::with_capacity(3 + 2 * n);

    bodies.push("<< /Type /Catalog /Pages 2 0 R >>".to_string());
    let mut kids = String::new();
    for i in 0..n {
        let _ = write!(kids, "{} 0 R ", page_base + i);
    }
    bodies.push(format!("<< /Type /Pages /Kids [ {kids}] /Count {n} >>"));
    bodies.push("<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>".to_string());

    for page in &pages {
        let mut stream = String::new();
        let _ = write!(stream, "BT /F0 {FONT_SIZE} Tf {LEADING} TL {LEFT} {TOP} Td");
        for (row, line) in page.iter().enumerate() {
            // First line is positioned by Td; each subsequent line advances with T*.
            if row == 0 {
                let _ = write!(stream, " ({}) Tj", pdf_escape(line));
            } else {
                let _ = write!(stream, " T* ({}) Tj", pdf_escape(line));
            }
        }
        stream.push_str(" ET");
        bodies.push(format!(
            "<< /Length {} >>\nstream\n{stream}\nendstream",
            stream.len()
        ));
    }
    for i in 0..n {
        bodies.push(format!(
            "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] \
             /Resources << /Font << /F0 3 0 R >> >> /Contents {} 0 R >>",
            content_base + i
        ));
    }

    // Assemble, tracking each object's byte offset for the xref table.
    let mut out = String::from("%PDF-1.4\n");
    let mut offsets = Vec::with_capacity(bodies.len());
    for (idx, body) in bodies.iter().enumerate() {
        offsets.push(out.len());
        let _ = write!(out, "{} 0 obj\n{body}\nendobj\n", idx + 1);
    }
    let xref_at = out.len();
    let count = bodies.len() + 1;
    let _ = write!(out, "xref\n0 {count}\n0000000000 65535 f \n");
    for off in &offsets {
        let _ = writeln!(out, "{off:010} 00000 n ");
    }
    let _ = write!(
        out,
        "trailer\n<< /Size {count} /Root 1 0 R >>\nstartxref\n{xref_at}\n%%EOF\n"
    );
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, DeviceKey, Provenance, SourceKind, Value};
    use crate::{audit, correlate, Claim};

    #[test]
    fn pdf_escape_folds_unicode_and_escapes_specials() {
        assert_eq!(pdf_escape(r"a(b)c\d"), r"a\(b\)c\\d");
        // em/en dash → '-', curly quotes → straight, other non-ASCII → '?'.
        assert_eq!(
            pdf_escape("x\u{2014}y\u{2013}\u{201C}q\u{201D}\u{2018}r\u{2019}\u{1F600}z"),
            "x-y-\"q\"'r'?z"
        );
    }

    #[test]
    fn pdf_is_well_formed_and_paginated() {
        // Enough devices to force more than one page.
        let claims: Vec<Claim> = (0..40)
            .map(|i| Claim {
                device: DeviceKey(format!("SN{i}")),
                attribute: Attribute::FirstConnected,
                value: Value::Timestamp(1_700_000_000 + i),
                provenance: Provenance {
                    source: SourceKind::SetupApi,
                    locator: "log(1)".into(), // exercises pdf_escape on '(' / ')'
                },
            })
            .collect();
        let histories = correlate(&claims);
        let pdf = render_pdf(&histories, &audit(&histories));
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.starts_with("%PDF-1.4"));
        assert!(text.trim_end().ends_with("%%EOF"));
        assert!(text.contains("/Type /Catalog"));
        assert!(text.contains("startxref"));
        assert!(
            text.matches("/Type /Page ").count() >= 2,
            "paginated across ≥2 pages"
        );
        assert!(text.contains(r"log\(1\)"), "parens escaped in the stream");
    }

    #[test]
    fn empty_input_still_produces_one_valid_page() {
        let pdf = render_pdf(&[], &[]);
        let text = String::from_utf8_lossy(&pdf);
        assert!(text.starts_with("%PDF-1.4"));
        assert_eq!(text.matches("/Type /Page ").count(), 1);
    }
}
