//! Native DOCX export — the court-ready report as an Office Open XML `.docx`, with **no
//! dependency**: a `.docx` is a ZIP of a few XML parts, so this writes a minimal
//! stored (uncompressed) ZIP by hand. The report text comes from
//! [`render_report`](crate::render_report); each line becomes a Word paragraph.
//!
//! The output is validated against an independent oracle (python-docx opens it and reads
//! the paragraphs back) — see `docs/validation.md`.

use crate::render_report;
use crate::DeviceHistory;
use forensicnomicon::report::Finding;

/// CRC-32 (ISO-HDLC / ZIP polynomial `0xEDB88320`), the checksum each ZIP entry needs.
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg(); // 0xFFFF_FFFF when the low bit is set
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Escape the five XML predefined entities so arbitrary evidence text is safe in XML.
fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Package parts into a minimal **stored** (method 0) ZIP — enough for a valid `.docx`.
fn zip_stored(parts: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data) in parts {
        let crc = crc32(data);
        let size = data.len() as u32;
        let offset = out.len() as u32;
        // Local file header (PK\x03\x04).
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        out.extend_from_slice(&[20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // ver, flags, method 0, time, date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed == uncompressed
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
        // Central-directory record (PK\x01\x02).
        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&[20, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0]); // made-by, needed, flags, method, time, date
        central.extend_from_slice(&crc.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&size.to_le_bytes());
        central.extend_from_slice(&(name.len() as u16).to_le_bytes());
        central.extend_from_slice(&[0u8; 8]); // extra, comment, disk#, internal attrs
        central.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    let cd_len = central.len() as u32;
    let count = parts.len() as u16;
    out.extend_from_slice(&central);
    // End of central directory (PK\x05\x06).
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]); // this disk, cd-start disk
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&cd_len.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

const CONTENT_TYPES: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;

const RELS: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>"#;

/// Render the forensic report as a `.docx` byte stream.
#[must_use]
pub fn render_docx(histories: &[DeviceHistory], findings: &[Finding]) -> Vec<u8> {
    let mut body = String::from(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>"#,
    );
    for line in render_report(histories, findings).lines() {
        body.push_str("<w:p><w:r><w:t xml:space=\"preserve\">");
        body.push_str(&xml_escape(line));
        body.push_str("</w:t></w:r></w:p>");
    }
    body.push_str("</w:body></w:document>");

    zip_stored(&[
        ("[Content_Types].xml", CONTENT_TYPES.as_bytes().to_vec()),
        ("_rels/.rels", RELS.as_bytes().to_vec()),
        ("word/document.xml", body.into_bytes()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attribute, DeviceKey, Provenance, SourceKind, Value};
    use crate::{audit, correlate, Claim};

    #[test]
    fn crc32_matches_the_standard_test_vector() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn xml_escape_covers_all_five_entities() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[test]
    fn docx_is_a_valid_zip_carrying_the_document_part() {
        let claims = [Claim {
            device: DeviceKey("SN1".into()),
            attribute: Attribute::VolumeName,
            value: Value::Text("A&B<C>".into()), // forces xml escaping in the body
            provenance: Provenance {
                source: SourceKind::MountedDevices,
                locator: "m".into(),
            },
        }];
        let histories = correlate(&claims);
        let docx = render_docx(&histories, &audit(&histories));
        assert_eq!(&docx[..4], b"PK\x03\x04", "starts with a ZIP local header");
        let as_text = String::from_utf8_lossy(&docx);
        assert!(
            as_text.contains("word/document.xml"),
            "carries the document part"
        );
        assert!(as_text.contains("[Content_Types].xml"));
        assert!(
            as_text.contains("A&amp;B&lt;C&gt;"),
            "evidence text is XML-escaped"
        );
        assert_eq!(
            &docx[docx.len() - 22..docx.len() - 18],
            b"PK\x05\x06",
            "EOCD present"
        );
    }
}
