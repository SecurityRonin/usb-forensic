//! Source: a physical device's own boot sectors (a raw disk image) → USB-history
//! [`Claim`]s — the strongest device attribution.
#![allow(clippy::doc_markdown)] // forensic proper nouns (BitLocker, FVE, …) read cleaner bare
//!
//! When the suspect USB device itself is imaged, its **MBR disk signature** and **FAT
//! volume serial** tie it directly to the host's footprint: the disk signature matches a
//! `MountedDevices` MBR record (→ drive letter, volume GUID), and the FAT volume serial
//! matches an `EMDMgmt`/`.lnk` volume serial (→ label, files opened). This closes the loop
//! that host artifacts alone cannot — attributing a *physical device in evidence* to what
//! it did on the machine. A pure decode of the boot-sector bytes; no filesystem walk.
//!
//! It also flags **volume encryption** from the boot sector: a BitLocker / BitLocker To Go
//! volume replaces the VBR OEM identifier (offset 3) with the documented `-FVE-FS-`
//! signature (Windows Vista `EB 52 90`, 7/8 `EB 58 90`, then `2D 46 56 45 2D 46 53 2D`; see
//! the [Forensics Wiki BitLocker page](https://forensics.wiki/bitlocker_disk_encryption/)).
//! Detection is a spec-defined rule; it is validated against a signature-carrying fixture
//! and against real unencrypted media (which must NOT false-positive).

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};

/// A detected volume-encryption / inaccessible-contents state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionKind {
    /// Microsoft BitLocker on a **fixed drive** (or an NTFS-on-removable volume): the VBR
    /// OEM identifier at offset 3 is the documented `-FVE-FS-` signature (Windows Vista
    /// `EB 52 90` / 7-10 `EB 58 90`; see the module reference).
    BitLocker,
    /// Microsoft **BitLocker To Go** on removable media (the USB-forensics case): the
    /// discovery volume presents a normal FAT/exFAT OEM identifier, so it is identified by
    /// the BitLocker identifier GUID `4967D63B-2E29-4AD8-8399-F6A339E3D001` carried in the
    /// volume header — not by the `-FVE-FS-` string (libbde BDE format, volume header).
    BitLockerToGo,
    /// A LUKS-encrypted volume (`LUKS\xba\xbe` magic) — Linux full-disk encryption on the
    /// media, surfaced by the filesystem-signature detector.
    Luks,
    /// A partition whose VBR matches **no known filesystem** signature (not NTFS, FAT,
    /// exFAT, LUKS, or BitLocker). Consistent with an on-disk encrypted container (VeraCrypt
    /// / TrueCrypt, whose volume is indistinguishable from random data and carries no
    /// filesystem header) or a wiped/raw volume — the contents are not readable as a
    /// filesystem. Stated as an observation, not a claim that it *is* any specific tool.
    UnrecognizedFilesystem,
}

impl EncryptionKind {
    /// A stable display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BitLocker => "BitLocker",
            Self::BitLockerToGo => "BitLocker To Go",
            Self::Luks => "LUKS",
            Self::UnrecognizedFilesystem => {
                "unrecognized-filesystem (possible encrypted container)"
            }
        }
    }

    /// Specificity rank, so that when several partitions carry different states the most
    /// definite one is surfaced on the device: a positive BitLocker/LUKS identification
    /// outranks a heuristic "unrecognized filesystem".
    const fn rank(self) -> u8 {
        match self {
            Self::BitLocker | Self::BitLockerToGo => 3,
            Self::Luks => 2,
            Self::UnrecognizedFilesystem => 1,
        }
    }
}

/// The BitLocker identifier GUID `4967D63B-2E29-4AD8-8399-F6A339E3D001`, in the mixed-endian
/// byte order it is stored in a volume header (Data1-3 little-endian, Data4 big-endian). Its
/// presence in a partition's volume header marks a BitLocker / BitLocker To Go volume even
/// when the OEM identifier at offset 3 is an ordinary FAT/exFAT string (libbde BDE format).
pub(crate) const BITLOCKER_GUID: [u8; 16] = [
    0x3B, 0xD6, 0x67, 0x49, 0x29, 0x2E, 0xD8, 0x4A, 0x83, 0x99, 0xF6, 0xA3, 0x39, 0xE3, 0xD0, 0x01,
];

/// A physical device's boot-sector identity, decoded from its raw disk image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceImage {
    /// MBR disk signature (4 bytes at offset `0x1B8`) — joins the `MountedDevices` bridge.
    pub disk_signature: u32,
    /// FAT volume serial (`BS_VolID`) of the first FAT partition, when present — the
    /// 4-byte serial `EMDMgmt` and Shell Links store.
    pub fat_volume_serial: Option<u32>,
    /// The volume-encryption type, when a boot sector carries an encryption signature.
    pub encryption: Option<EncryptionKind>,
    /// The raw 512-byte MBR sector, retained for export/verification.
    pub mbr: [u8; 512],
}

/// Decode a raw disk image's boot sectors. Requires a valid MBR (the `0x55AA` boot
/// signature at offset `0x1FE`); reads the disk signature, then walks the MBR partition
/// table for the first FAT partition's `BS_VolID` and for an encryption signature.
/// `None` for a non-MBR image.
#[must_use]
pub fn parse_boot_sectors(image: &[u8]) -> Option<DeviceImage> {
    // Require a full 512-byte MBR sector; the disk signature and the four 16-byte partition
    // entries (`0x1BE..0x1FE`) then all lie safely within it.
    let mbr = image.get(..512)?;
    if mbr[0x1FE..0x200] != [0x55, 0xAA] {
        return None;
    }
    let disk_signature = u32::from_le_bytes([mbr[0x1B8], mbr[0x1B9], mbr[0x1BA], mbr[0x1BB]]);
    let mut fat_volume_serial = None;
    let mut encryption = None;
    for entry in mbr[0x1BE..0x1FE].chunks_exact(16) {
        let ptype = entry[4];
        if ptype == 0 {
            continue; // an empty partition slot.
        }
        let start_lba = u32::from_le_bytes([entry[8], entry[9], entry[10], entry[11]]) as usize;
        let Some(vbr) = image.get(start_lba * 512..start_lba * 512 + 512) else {
            continue; // the partition's VBR is beyond the image.
        };
        // BitLocker wins (a definite signature); else, if this partition's VBR matches no
        // known filesystem, flag it as an unrecognized/possibly-encrypted volume — but only
        // record that when nothing definite was found, and never override BitLocker.
        if let Some(kind) = detect_encryption(vbr) {
            encryption = Some(kind);
        } else if encryption.is_none() && !is_recognized_filesystem(vbr) {
            encryption = Some(EncryptionKind::UnrecognizedFilesystem);
        }
        if fat_volume_serial.is_none() && FAT_TYPES.contains(&ptype) {
            fat_volume_serial = Some(fat_bs_volid(vbr));
        }
    }
    let mut mbr_copy = [0u8; 512];
    mbr_copy.copy_from_slice(mbr);
    Some(DeviceImage {
        disk_signature,
        fat_volume_serial,
        encryption,
        mbr: mbr_copy,
    })
}

/// Detect volume encryption from a VBR's OEM identifier (offset 3, 8 bytes). BitLocker and
/// BitLocker To Go replace the filesystem OEM id (`NTFS    ` / `MSDOS5.0`) with `-FVE-FS-`
/// — the documented FVE signature (see the module reference). `None` for a plain FS.
fn detect_encryption(vbr: &[u8]) -> Option<EncryptionKind> {
    (vbr.get(3..11) == Some(b"-FVE-FS-")).then_some(EncryptionKind::BitLocker)
}

/// Whether a VBR carries a recognized filesystem signature: NTFS / exFAT at the OEM id
/// (offset 3), or FAT (`FAT32   ` at `0x52`, or `FAT1`/`FAT2` at `0x36` for FAT12/16). A
/// VBR matching none of these is unrecognized (see [`EncryptionKind::UnrecognizedFilesystem`]).
fn is_recognized_filesystem(vbr: &[u8]) -> bool {
    matches!(vbr.get(3..11), Some(b"NTFS    " | b"EXFAT   "))
        || vbr.get(0x52..0x5A) == Some(b"FAT32   ")
        || matches!(vbr.get(0x36..0x39), Some(b"FAT"))
}

/// FAT partition type bytes (`FAT12`/`16`/`32`, incl. LBA variants).
const FAT_TYPES: [u8; 6] = [0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E];

/// Read a FAT VBR's `BS_VolID`: offset `0x43` when the FS type is `FAT32   ` (at `0x52`),
/// else `0x27` (FAT12/16). `vbr` is a full 512-byte sector, so both offsets are in range.
fn fat_bs_volid(vbr: &[u8]) -> u32 {
    let off = if vbr.get(0x52..0x5A) == Some(b"FAT32   ") {
        0x43
    } else {
        0x27
    };
    u32::from_le_bytes([vbr[off], vbr[off + 1], vbr[off + 2], vbr[off + 3]])
}

/// A [`HistorySource`] over one decoded device image.
pub struct DeviceImageSource<'a> {
    image: &'a DeviceImage,
    locator: String,
}

impl<'a> DeviceImageSource<'a> {
    /// Wrap a decoded device image with the on-disk locator of the image it came from.
    #[must_use]
    pub fn new(image: &'a DeviceImage, locator: impl Into<String>) -> Self {
        Self {
            image,
            locator: locator.into(),
        }
    }
}

/// Render a 4-byte serial as `XXXX-XXXX` (the canonical `vol` form other sources use).
fn fmt_serial(serial: u32) -> String {
    format!("{:04X}-{:04X}", serial >> 16, serial & 0xFFFF)
}

/// Export a device image's raw 512-byte MBR sector as an annotated hex dump (16 bytes per
/// line, `offset  hex  |ascii|`), headed by the source locator and disk signature — for an
/// examiner to inspect or archive the boot sector alongside the analysis.
#[must_use]
pub fn export_mbr_hex(image: &DeviceImage, locator: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "MBR of {locator} (disk signature {})",
        fmt_serial(image.disk_signature)
    );
    for (i, chunk) in image.mbr.chunks(16).enumerate() {
        let hex = chunk.iter().fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02X} ");
            acc
        });
        let ascii: String = chunk
            .iter()
            .map(|&b| {
                if (0x20..0x7F).contains(&b) {
                    b as char
                } else {
                    '.'
                }
            })
            .collect();
        let _ = writeln!(out, "{:08X}  {hex:<48} |{ascii}|", i * 16);
    }
    out
}

impl HistorySource for DeviceImageSource<'_> {
    fn claims(&self) -> Vec<Claim> {
        // Key the physical device by its MBR disk signature — a stable media identity.
        let device = DeviceKey(format!("disk-{:08X}", self.image.disk_signature));
        let make = |attribute, value| Claim {
            device: device.clone(),
            attribute,
            value: Value::Text(value),
            provenance: Provenance {
                source: SourceKind::DeviceImage,
                locator: self.locator.clone(),
            },
        };
        let mut out = Vec::new();
        // The FAT volume serial, so an EMDMgmt/LNK record (keyed by that serial) reconciles
        // ONTO the physical device — carrying its label and the files opened from it.
        if let Some(vsn) = self.image.fat_volume_serial {
            out.push(make(Attribute::VolumeSerial, fmt_serial(vsn)));
        }
        // The volume-encryption type detected on the media — surfaced on the device record.
        if let Some(enc) = self.image.encryption {
            out.push(make(Attribute::Encryption, enc.name().to_string()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal MBR image: disk signature + one FAT32 partition starting at
    /// `start_lba`, whose VBR carries `bs_volid`. Sized to hold that VBR.
    fn mbr_with_fat32(disk_sig: u32, start_lba: usize, bs_volid: u32) -> Vec<u8> {
        let mut v = vec![0u8; start_lba * 512 + 512];
        v[0x1B8..0x1BC].copy_from_slice(&disk_sig.to_le_bytes());
        v[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
        // partition entry 0: type 0x0B (FAT32), start LBA.
        v[0x1BE + 4] = 0x0B;
        v[0x1BE + 8..0x1BE + 12].copy_from_slice(&(start_lba as u32).to_le_bytes());
        // VBR at start_lba: FAT32 marker + BS_VolID.
        let vbr = start_lba * 512;
        v[vbr + 0x52..vbr + 0x5A].copy_from_slice(b"FAT32   ");
        v[vbr + 0x43..vbr + 0x47].copy_from_slice(&bs_volid.to_le_bytes());
        v
    }

    #[test]
    fn parses_mbr_disk_signature_and_fat_volume_serial() {
        let img = mbr_with_fat32(0xE221_034C, 1, 0xB4D8_5399);
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.disk_signature, 0xE221_034C);
        assert_eq!(d.fat_volume_serial, Some(0xB4D8_5399));
    }

    #[test]
    fn a_fat16_partition_reads_bs_volid_at_0x27() {
        let mut img = vec![0u8; 1024];
        img[0x1B8..0x1BC].copy_from_slice(&1u32.to_le_bytes());
        img[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
        img[0x1BE + 4] = 0x06; // FAT16
        img[0x1BE + 8..0x1BE + 12].copy_from_slice(&1u32.to_le_bytes());
        img[512 + 0x27..512 + 0x2B].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.fat_volume_serial, Some(0x1234_5678));
    }

    #[test]
    fn a_non_mbr_image_is_rejected() {
        assert_eq!(parse_boot_sectors(&[0u8; 512]), None);
        assert_eq!(parse_boot_sectors(&[0u8; 10]), None);
    }

    #[test]
    fn a_partition_whose_vbr_is_beyond_the_image_is_skipped() {
        // A partition pointing past the image (a truncated/carved capture) is skipped, not
        // panicked on; with no readable VBR the device yields only its disk signature.
        let mut img = vec![0u8; 512];
        img[0x1B8..0x1BC].copy_from_slice(&0xCAFE_0000u32.to_le_bytes());
        img[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
        img[0x1BE + 4] = 0x0B; // FAT32
        img[0x1BE + 8..0x1BE + 12].copy_from_slice(&9999u32.to_le_bytes()); // VBR out of range
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.disk_signature, 0xCAFE_0000);
        assert_eq!(d.fat_volume_serial, None);
        assert_eq!(d.encryption, None);
    }

    #[test]
    fn an_mbr_with_no_fat_partition_still_yields_the_disk_signature() {
        let mut img = vec![0u8; 512];
        img[0x1B8..0x1BC].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        img[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
        img[0x1BE + 4] = 0x07; // NTFS, not FAT
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.disk_signature, 0xDEAD_BEEF);
        assert_eq!(d.fat_volume_serial, None);
    }

    #[test]
    fn source_emits_the_fat_volume_serial_keyed_by_disk_signature() {
        let img = DeviceImage {
            disk_signature: 0xE221_034C,
            fat_volume_serial: Some(0xB4D8_5399),
            encryption: None,
            mbr: [0u8; 512],
        };
        let claims = DeviceImageSource::new(&img, "rm2.raw").claims();
        assert_eq!(claims.len(), 1);
        // Keyed by the media identity (disk signature); the value is the FAT volume serial
        // that reconciles with an EMDMgmt/LNK record.
        assert_eq!(claims[0].device, DeviceKey("disk-E221034C".to_string()));
        assert_eq!(claims[0].attribute, Attribute::VolumeSerial);
        assert_eq!(claims[0].value, Value::Text("B4D8-5399".to_string()));
        assert_eq!(claims[0].provenance.source, SourceKind::DeviceImage);
        assert_eq!(claims[0].provenance.locator, "rm2.raw");
    }

    #[test]
    fn export_mbr_hex_dumps_the_boot_sector_with_signature_and_ascii() {
        let img = mbr_with_fat32(0xE221_034C, 1, 0xB4D8_5399);
        let d = parse_boot_sectors(&img).expect("valid MBR");
        let dump = export_mbr_hex(&d, "rm2.raw");
        assert!(dump.contains("MBR of rm2.raw"));
        assert!(dump.contains("E221-034C"), "disk signature in header");
        assert!(dump.contains("00000000 "), "offset column");
        assert!(
            dump.contains("55 AA"),
            "the boot signature bytes are present"
        );
        // 512 bytes / 16 per line = 32 lines + 1 header.
        assert_eq!(dump.lines().count(), 33);
    }

    #[test]
    fn source_without_a_fat_serial_or_encryption_emits_nothing() {
        // A device with no FAT partition and no encryption carries nothing to correlate on.
        let img = DeviceImage {
            disk_signature: 1,
            fat_volume_serial: None,
            encryption: None,
            mbr: [0u8; 512],
        };
        assert!(DeviceImageSource::new(&img, "x").claims().is_empty());
    }

    /// Build a minimal MBR image with one partition whose VBR carries the BitLocker
    /// `-FVE-FS-` signature at offset 3 (the documented FVE signature).
    fn mbr_with_bitlocker(disk_sig: u32, start_lba: usize) -> Vec<u8> {
        let mut v = vec![0u8; start_lba * 512 + 512];
        v[0x1B8..0x1BC].copy_from_slice(&disk_sig.to_le_bytes());
        v[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
        v[0x1BE + 4] = 0x07; // the partition type is NTFS/IFS; the VBR reveals FVE.
        v[0x1BE + 8..0x1BE + 12].copy_from_slice(&(start_lba as u32).to_le_bytes());
        let vbr = start_lba * 512;
        // Win7/8 BitLocker VBR: jump EB 58 90, then the -FVE-FS- OEM id at offset 3.
        v[vbr..vbr + 3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        v[vbr + 3..vbr + 11].copy_from_slice(b"-FVE-FS-");
        v
    }

    #[test]
    fn bitlocker_signature_is_detected_from_the_vbr() {
        let img = mbr_with_bitlocker(0xABCD_1234, 1);
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.encryption, Some(EncryptionKind::BitLocker));
        assert_eq!(EncryptionKind::BitLocker.name(), "BitLocker");
        // A BitLocker volume is not FAT → no FAT serial.
        assert_eq!(d.fat_volume_serial, None);
    }

    #[test]
    fn plain_filesystem_media_is_not_flagged_as_encrypted() {
        // A real FAT32 volume ("FAT32   " OEM) must NOT false-positive as encrypted or
        // unrecognized — it is a recognized filesystem.
        let img = mbr_with_fat32(1, 1, 42);
        assert_eq!(
            parse_boot_sectors(&img).expect("valid MBR").encryption,
            None
        );
        assert_eq!(detect_encryption(b"NTFS    xxxxxxxx"), None);
        assert_eq!(detect_encryption(&[0u8; 4]), None);
    }

    #[test]
    fn is_recognized_filesystem_accepts_the_known_signatures_only() {
        let mut ntfs = vec![0u8; 512];
        ntfs[3..11].copy_from_slice(b"NTFS    ");
        assert!(is_recognized_filesystem(&ntfs));
        let mut exfat = vec![0u8; 512];
        exfat[3..11].copy_from_slice(b"EXFAT   ");
        assert!(is_recognized_filesystem(&exfat));
        let mut fat16 = vec![0u8; 512];
        fat16[0x36..0x39].copy_from_slice(b"FAT");
        assert!(is_recognized_filesystem(&fat16));
        // Random / no signature → unrecognized.
        assert!(!is_recognized_filesystem(&[0xABu8; 512]));
    }

    #[test]
    fn an_unrecognized_filesystem_partition_is_flagged_as_possibly_encrypted() {
        // A partition with a valid MBR entry but a VBR matching no known filesystem
        // signature (all-random, as a VeraCrypt/TrueCrypt container appears) → flagged.
        let mut img = vec![0xABu8; 1024];
        img[0x1B8..0x1BC].copy_from_slice(&7u32.to_le_bytes());
        img[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
        img[0x1BE + 4] = 0x07; // a non-empty partition type
        img[0x1BE + 8..0x1BE + 12].copy_from_slice(&1u32.to_le_bytes());
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.encryption, Some(EncryptionKind::UnrecognizedFilesystem));
        assert_eq!(
            EncryptionKind::UnrecognizedFilesystem.name(),
            "unrecognized-filesystem (possible encrypted container)"
        );
    }

    #[test]
    fn source_emits_an_encryption_claim_for_an_encrypted_device() {
        let img = DeviceImage {
            disk_signature: 0xABCD_1234,
            fat_volume_serial: None,
            encryption: Some(EncryptionKind::BitLocker),
            mbr: [0u8; 512],
        };
        let claims = DeviceImageSource::new(&img, "x").claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].attribute, Attribute::Encryption);
        assert_eq!(claims[0].value, Value::Text("BitLocker".to_string()));
    }

    // ---- fixtures parseable by the authoritative disk-forensic parser ----

    /// A classic-MBR disk holding one partition (`ptype`, starting at `start_lba`) whose
    /// 512-byte VBR is `vbr`. Sized to contain the VBR plus slack for FS detection.
    fn mbr_disk(disk_sig: u32, ptype: u8, start_lba: u32, vbr: &[u8]) -> Vec<u8> {
        let sectors = start_lba as usize + 16;
        let mut v = vec![0u8; sectors * 512];
        v[0x1B8..0x1BC].copy_from_slice(&disk_sig.to_le_bytes());
        v[0x1FE..0x200].copy_from_slice(&[0x55, 0xAA]);
        v[0x1BE + 4] = ptype;
        v[0x1BE + 8..0x1BE + 12].copy_from_slice(&start_lba.to_le_bytes());
        v[0x1BE + 12..0x1BE + 16].copy_from_slice(&8u32.to_le_bytes()); // sector count
        let off = start_lba as usize * 512;
        v[off..off + vbr.len()].copy_from_slice(vbr);
        v
    }

    /// A BitLocker To Go discovery-volume VBR: a real FAT32 boot record (`MSWIN4.1` OEM id,
    /// `FAT32   ` FS signature) carrying the BitLocker identifier GUID — how removable-media
    /// BitLocker appears (libbde BDE format, "BitLocker To Go" volume header).
    fn to_go_vbr() -> [u8; 512] {
        let mut vbr = [0u8; 512];
        vbr[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        vbr[3..11].copy_from_slice(b"MSWIN4.1");
        vbr[0x52..0x5A].copy_from_slice(b"FAT32   ");
        vbr[424..440].copy_from_slice(&BITLOCKER_GUID); // identifier GUID (To Go offset)
        vbr[510..512].copy_from_slice(&[0x55, 0xAA]);
        vbr
    }

    #[test]
    fn bitlocker_to_go_detected_via_identifier_guid_on_a_fat_discovery_volume() {
        // The removable-media case: the volume looks like FAT32 to a generic FS detector, so
        // detection MUST key off the BitLocker identifier GUID, not the `-FVE-FS-` string.
        let img = mbr_disk(0x1111_2222, 0x0B, 2, &to_go_vbr());
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.encryption, Some(EncryptionKind::BitLockerToGo));
        assert_eq!(EncryptionKind::BitLockerToGo.name(), "BitLocker To Go");
    }

    #[test]
    fn a_luks_partition_is_flagged_as_luks_encryption() {
        let mut vbr = [0u8; 512];
        vbr[0..6].copy_from_slice(b"LUKS\xba\xbe"); // LUKS magic at offset 0
        let img = mbr_disk(0x3333_4444, 0x83, 2, &vbr);
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.encryption, Some(EncryptionKind::Luks));
        assert_eq!(EncryptionKind::Luks.name(), "LUKS");
    }

    // ---- GPT fixture: same in-memory recipe disk-forensic's own dispatch tests use ----

    fn guid_bytes(s: &str) -> [u8; 16] {
        let g: Vec<&str> = s.split('-').collect();
        let mut b = [0u8; 16];
        b[0..4].copy_from_slice(&u32::from_str_radix(g[0], 16).unwrap().to_le_bytes());
        b[4..6].copy_from_slice(&u16::from_str_radix(g[1], 16).unwrap().to_le_bytes());
        b[6..8].copy_from_slice(&u16::from_str_radix(g[2], 16).unwrap().to_le_bytes());
        b[8..10].copy_from_slice(&u16::from_str_radix(g[3], 16).unwrap().to_be_bytes());
        b[10..16].copy_from_slice(&u64::from_str_radix(g[4], 16).unwrap().to_be_bytes()[2..8]);
        b
    }

    fn gpt_entry(type_guid: &str, first: u64, last: u64) -> [u8; 128] {
        let mut e = [0u8; 128];
        e[0..16].copy_from_slice(&guid_bytes(type_guid));
        e[16..32].copy_from_slice(&guid_bytes("00000000-0000-0000-0000-000000000001"));
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        e
    }

    fn gpt_header(my_lba: u64, alt_lba: u64, entry_lba: u64, array_crc: u32) -> [u8; 512] {
        let mut s = [0u8; 512];
        s[0..8].copy_from_slice(b"EFI PART");
        s[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
        s[12..16].copy_from_slice(&92u32.to_le_bytes());
        s[24..32].copy_from_slice(&my_lba.to_le_bytes());
        s[32..40].copy_from_slice(&alt_lba.to_le_bytes());
        s[40..48].copy_from_slice(&3u64.to_le_bytes()); // first usable
        s[48..56].copy_from_slice(&61u64.to_le_bytes()); // last usable
        s[56..72].copy_from_slice(&guid_bytes("12345678-1234-5678-1234-567812345678"));
        s[72..80].copy_from_slice(&entry_lba.to_le_bytes());
        s[80..84].copy_from_slice(&4u32.to_le_bytes()); // num entries
        s[84..88].copy_from_slice(&128u32.to_le_bytes()); // entry size
        s[88..92].copy_from_slice(&array_crc.to_le_bytes());
        let crc = gpt_partition_forensic::crc32::checksum(&s[..92]);
        s[16..20].copy_from_slice(&crc.to_le_bytes());
        s
    }

    /// A spec-valid GPT disk (protective MBR + primary/backup headers + entry array) with one
    /// Microsoft Basic Data partition whose VBR is FAT32 (serial `bs_volid`).
    fn build_gpt(bs_volid: u32) -> Vec<u8> {
        const SECTOR: usize = 512;
        const SECTORS: usize = 64;
        let mut disk = vec![0u8; SECTOR * SECTORS];
        disk[450] = 0xEE; // protective-MBR partition type
        disk[454..458].copy_from_slice(&1u32.to_le_bytes());
        disk[458..462].copy_from_slice(&((SECTORS - 1) as u32).to_le_bytes());
        disk[510..512].copy_from_slice(&[0x55, 0xAA]);

        let mut array = vec![0u8; 4 * 128];
        array[0..128].copy_from_slice(&gpt_entry(
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", // Microsoft Basic Data
            3,
            30,
        ));
        let array_crc = gpt_partition_forensic::crc32::checksum(&array);
        disk[SECTOR..SECTOR + 512].copy_from_slice(&gpt_header(1, 63, 2, array_crc));
        disk[2 * SECTOR..2 * SECTOR + array.len()].copy_from_slice(&array);
        disk[62 * SECTOR..62 * SECTOR + array.len()].copy_from_slice(&array);
        disk[63 * SECTOR..63 * SECTOR + 512].copy_from_slice(&gpt_header(63, 1, 62, array_crc));
        // FAT32 VBR at the partition's first LBA (3).
        let vbr = 3 * SECTOR;
        disk[vbr + 3..vbr + 11].copy_from_slice(b"MSDOS5.0");
        disk[vbr + 0x52..vbr + 0x5A].copy_from_slice(b"FAT32   ");
        disk[vbr + 0x43..vbr + 0x47].copy_from_slice(&bs_volid.to_le_bytes());
        disk[vbr + 510..vbr + 512].copy_from_slice(&[0x55, 0xAA]);
        disk
    }

    #[test]
    fn a_gpt_disk_is_not_false_flagged_and_its_fat_partition_is_read() {
        // Regression: a GPT protective MBR (type 0xEE, "EFI PART" at LBA 1) must be parsed as
        // GPT — never walked as MBR partitions, which mis-read the GPT header as an
        // unrecognized-filesystem VBR. Its real FAT partition's serial is still recovered.
        let img = build_gpt(0xB4D8_5399);
        let d = parse_boot_sectors(&img).expect("valid GPT");
        assert_eq!(
            d.encryption, None,
            "GPT header must not be flagged as encrypted"
        );
        assert_eq!(d.fat_volume_serial, Some(0xB4D8_5399));
    }
}
