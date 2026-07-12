//! Source: a physical device's own boot sectors (a raw disk image) → USB-history
//! [`Claim`]s — the strongest device attribution.
#![allow(clippy::doc_markdown)] // forensic proper nouns (BitLocker, FVE, …) read cleaner bare
//!
//! When the suspect USB device itself is imaged, its **MBR disk signature** and **FAT
//! volume serial** tie it directly to the host's footprint: the disk signature matches a
//! `MountedDevices` MBR record (→ drive letter, volume GUID), and the FAT volume serial
//! matches an `EMDMgmt`/`.lnk` volume serial (→ label, files opened). This closes the loop
//! that host artifacts alone cannot — attributing a *physical device in evidence* to what
//! it did on the machine.
//!
//! Partition-scheme dispatch (MBR / GPT / APM) and filesystem-signature detection are
//! delegated to the [`disk_forensic`] crate, which is tested against real disk corpora
//! covering every partition-table + filesystem combination — so this source never re-parses
//! a partition table by hand (a GPT protective MBR is recognized as GPT, not mis-walked as
//! MBR partitions). On top of that partition list this source reads two USB-attribution
//! values, each from a **volume**-analysis function owned by [`forensicnomicon`] (the fleet
//! knowledge base), because a volume's serial and its encryption are properties of the
//! volume, not of the bus or partition scheme (ADR 0003):
//!
//! - the FAT/exFAT **volume serial** ([`forensicnomicon::volume_serial`]) — the 4-byte
//!   `EMDMgmt`/`.lnk` join key; and
//! - **BitLocker** ([`forensicnomicon::volume_encryption`]) — fixed-drive `-FVE-FS-` and, the
//!   case that matters most for removable media, **BitLocker To Go**, whose discovery volume
//!   presents a real FAT boot record so only the identifier GUID reveals it.
//!
//! A [`disk_forensic`]-reported LUKS or unrecognized filesystem is surfaced likewise. This
//! source holds no BitLocker signatures or field offsets of its own; the knowledge lives in
//! forensicnomicon, validated there and cross-checked here against real unencrypted media
//! (which must NOT false-positive).

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};
use disk_forensic::{analyse_disk, DiskReport};
use mbr_partition_forensic::DetectedFs;
use std::io::{Read, Seek, SeekFrom};

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

/// Decode a raw disk image's boot sectors from an in-memory slice — the convenience entry
/// for a fully-read image (and the fuzz target). Wraps the slice in a cursor and defers to
/// [`analyse_device_image`]. `None` when the image carries no MBR/GPT partition scheme.
#[must_use]
pub fn parse_boot_sectors(image: &[u8]) -> Option<DeviceImage> {
    analyse_device_image(&mut std::io::Cursor::new(image), image.len() as u64)
}

/// Decode a device image's boot sectors from any seekable reader (a raw slice cursor or an
/// [`ewf::EwfReader`] over an E01), sized by `disk_size`.
///
/// Partition-scheme detection and per-partition filesystem detection come from
/// [`disk_forensic::analyse_disk`]; on top of its partition list this reads, per partition,
/// the FAT `BS_VolID` (for the `EMDMgmt`/`.lnk` volume-serial join) and the BitLocker /
/// LUKS / unrecognized-filesystem state. `None` when no MBR/GPT scheme is present (a
/// non-disk input) or an Apple Partition Map (no Windows USB-attribution value).
pub fn analyse_device_image<R: Read + Seek>(reader: &mut R, disk_size: u64) -> Option<DeviceImage> {
    // disk-forensic owns scheme dispatch: a GPT protective MBR is parsed as GPT (partitions
    // from the GPT entries), never mis-walked as MBR partitions. `Gpt` still carries the
    // protective-MBR analysis (disk signature + partition list); `Apm` carries none.
    let report = analyse_disk(reader, disk_size).ok()?;
    let mbr = match &report {
        DiskReport::Mbr(m) | DiskReport::Gpt(m) => m,
        DiskReport::Apm(_) => return None,
    };
    // Partition byte-offsets from whichever table is authoritative for the scheme: for a GPT
    // disk `mbr.partitions` holds only the protective `0xEE` entry, so the real partitions
    // come from the GPT entry array (used entries only); otherwise the MBR partition table.
    let offsets: Vec<u64> = match &mbr.gpt {
        Some(g) => g
            .partitions
            .iter()
            .filter(|e| e.is_used())
            .map(|e| e.first_lba * g.sector_size)
            .collect(),
        None => mbr.partitions.iter().map(|p| p.byte_offset).collect(),
    };
    let disk_signature = mbr.disk_serial;
    let mbr_bytes: [u8; 512] = read_region(reader, 0, 512)?.try_into().ok()?;
    let mut fat_volume_serial = None;
    let mut encryption: Option<EncryptionKind> = None;
    for offset in offsets {
        let Some(vbr) = read_region(reader, offset, FS_PROBE_BYTES) else {
            continue; // the partition's VBR is beyond the image (a truncated capture).
        };
        // Detect the filesystem with the authoritative signature detector (the same one
        // disk-forensic uses), so MBR and GPT partitions are classified identically.
        let fs = mbr_partition_forensic::signature::detect(&vbr);
        if let Some(kind) = classify_encryption(&vbr, fs) {
            if encryption.is_none_or(|cur| kind.rank() > cur.rank()) {
                encryption = Some(kind);
            }
        }
        // The 4-byte FAT/exFAT volume serial (the `EMDMgmt`/`.lnk` join key) — the field
        // offsets are volume-serial knowledge owned by forensicnomicon (ADR 0003). An 8-byte
        // NTFS serial (`Long`) is not the FAT join key, so it is not recorded here.
        if fat_volume_serial.is_none() {
            if let Some(forensicnomicon::volume_serial::VolumeSerial::Short(v)) =
                forensicnomicon::volume_serial::volume_serial(&vbr)
            {
                fat_volume_serial = Some(v);
            }
        }
    }
    Some(DeviceImage {
        disk_signature,
        fat_volume_serial,
        encryption,
        mbr: mbr_bytes,
    })
}

/// Bytes read from each partition's start for filesystem detection: enough to reach the
/// deepest magic the detector inspects (Btrfs at 64 KiB), so ext/Btrfs volumes are not
/// mistaken for unrecognized/encrypted ones. All BitLocker and FAT fields sit in the first
/// 512 bytes, so the same buffer serves every check.
const FS_PROBE_BYTES: usize = 0x1_0000 + 0x400;

/// Seek to `offset` and read `len` bytes, zero-padding a short final read to `len`. `None`
/// when the offset is at/after EOF (nothing readable) or the seek/read errors.
fn read_region<R: Read + Seek>(reader: &mut R, offset: u64, len: usize) -> Option<Vec<u8>> {
    reader.seek(SeekFrom::Start(offset)).ok()?;
    let mut buf = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return None,
        }
    }
    (filled != 0).then_some(buf)
}

/// Classify a partition's volume-encryption state from its VBR and detected filesystem.
/// BitLocker is a spec-defined signature rule; `Luks` / `UnrecognizedFilesystem` follow the
/// filesystem detector. `None` for a recognized, unencrypted filesystem.
fn classify_encryption(vbr: &[u8], detected_fs: DetectedFs) -> Option<EncryptionKind> {
    // BitLocker detection — fixed-drive `-FVE-FS-` and BitLocker To Go's identifier GUID — is
    // volume-encryption *knowledge*, owned by forensicnomicon (ADR 0003), not this source.
    // A To Go discovery volume presents a real FAT boot record, so the filesystem detector
    // cannot see it; forensicnomicon's GUID scan can.
    if let Some(enc) = forensicnomicon::volume_encryption::detect_encryption(vbr) {
        return Some(match enc {
            forensicnomicon::volume_encryption::VolumeEncryption::BitLocker => {
                EncryptionKind::BitLocker
            }
            forensicnomicon::volume_encryption::VolumeEncryption::BitLockerToGo => {
                EncryptionKind::BitLockerToGo
            }
        });
    }
    // LUKS / unrecognized come from disk-forensic's filesystem detector.
    match detected_fs {
        DetectedFs::Luks => Some(EncryptionKind::Luks),
        DetectedFs::Unknown => Some(EncryptionKind::UnrecognizedFilesystem),
        _ => None,
    }
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

    /// A FAT32 VBR: `MSDOS5.0` OEM id (offset 3), `FAT32   ` FS signature (0x52), and
    /// `BS_VolID` (0x43) — how a Windows-formatted FAT32 volume appears.
    fn fat32_vbr(bs_volid: u32) -> [u8; 512] {
        let mut vbr = [0u8; 512];
        vbr[3..11].copy_from_slice(b"MSDOS5.0");
        vbr[0x52..0x5A].copy_from_slice(b"FAT32   ");
        vbr[0x43..0x47].copy_from_slice(&bs_volid.to_le_bytes());
        vbr[510..512].copy_from_slice(&[0x55, 0xAA]);
        vbr
    }

    /// A FAT16 VBR: `MSDOS5.0` OEM id, no FAT32 signature, `BS_VolID` at 0x27.
    fn fat16_vbr(bs_volid: u32) -> [u8; 512] {
        let mut vbr = [0u8; 512];
        vbr[3..11].copy_from_slice(b"MSDOS5.0");
        vbr[0x36..0x3E].copy_from_slice(b"FAT16   "); // BS_FilSysType (a real FAT16 boot record)
        vbr[0x27..0x2B].copy_from_slice(&bs_volid.to_le_bytes());
        vbr[510..512].copy_from_slice(&[0x55, 0xAA]);
        vbr
    }

    /// An NTFS VBR: `NTFS    ` OEM id at offset 3.
    fn ntfs_vbr() -> [u8; 512] {
        let mut vbr = [0u8; 512];
        vbr[3..11].copy_from_slice(b"NTFS    ");
        vbr[510..512].copy_from_slice(&[0x55, 0xAA]);
        vbr
    }

    #[test]
    fn parses_mbr_disk_signature_and_fat_volume_serial() {
        let img = mbr_disk(0xE221_034C, 0x0B, 2, &fat32_vbr(0xB4D8_5399));
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.disk_signature, 0xE221_034C);
        assert_eq!(d.fat_volume_serial, Some(0xB4D8_5399));
        assert_eq!(d.encryption, None);
    }

    #[test]
    fn a_fat16_partition_reads_bs_volid_at_0x27() {
        let img = mbr_disk(1, 0x06, 2, &fat16_vbr(0x1234_5678));
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.fat_volume_serial, Some(0x1234_5678));
    }

    #[test]
    fn a_non_mbr_image_is_rejected() {
        assert_eq!(parse_boot_sectors(&[0u8; 512]), None);
        assert_eq!(parse_boot_sectors(&[0u8; 10]), None);
    }

    #[test]
    fn read_region_returns_none_past_eof_and_zero_pads_a_short_read() {
        use std::io::Cursor;
        // A seek past EOF reads nothing → None (a truncated/carved capture is skipped, not
        // panicked on).
        assert_eq!(
            read_region(&mut Cursor::new(vec![0u8; 16]), 4096, 512),
            None
        );
        // A short final read is zero-padded to the requested length and returned.
        let mut backing = vec![0xAAu8; 512 + 100];
        backing[512..].fill(0xBB);
        let s = read_region(&mut Cursor::new(backing), 512, 512)
            .expect("short read still yields a buffer");
        assert_eq!(s.len(), 512);
        assert_eq!(&s[..100], &[0xBBu8; 100]);
        assert_eq!(&s[100..], &[0u8; 412]); // zero-padded tail
    }

    #[test]
    fn read_region_propagates_a_read_error() {
        // A reader that errors mid-read must surface as None (skip), never a panic.
        struct FailingReader;
        impl std::io::Read for FailingReader {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("boom"))
            }
        }
        impl std::io::Seek for FailingReader {
            fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                Ok(0)
            }
        }
        assert_eq!(read_region(&mut FailingReader, 0, 512), None);
    }

    #[test]
    fn the_most_specific_encryption_state_wins_across_partitions() {
        // Three partitions in ascending specificity — unrecognized filesystem, LUKS, then
        // BitLocker. Each definite identification outranks the less-specific one already
        // recorded, so the device surfaces the most definite (BitLocker).
        let mut img = mbr_disk(0x0AAA_0BBB, 0x07, 2, &[0xABu8; 512]); // p0: unrecognized
        let mut luks = [0u8; 512];
        luks[0..6].copy_from_slice(b"LUKS\xba\xbe");
        for (i, lba, ptype, vbr) in [(1u8, 4u32, 0x83u8, luks), (2, 6, 0x07, bitlocker_vbr())] {
            let e = 0x1BE + i as usize * 16;
            img[e + 4] = ptype;
            img[e + 8..e + 12].copy_from_slice(&lba.to_le_bytes());
            img[e + 12..e + 16].copy_from_slice(&8u32.to_le_bytes());
            let off = lba as usize * 512;
            img[off..off + 512].copy_from_slice(&vbr);
        }
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.encryption, Some(EncryptionKind::BitLocker));
    }

    #[test]
    fn the_first_fat_partitions_serial_is_kept() {
        // Two FAT32 partitions: the first partition's serial is the device's; the second is
        // not overwritten (the FAT volume serial is taken once).
        let mut img = mbr_disk(0xF00D_0001, 0x0B, 2, &fat32_vbr(0x1111_2222));
        let e = 0x1BE + 16;
        img[e + 4] = 0x0B;
        img[e + 8..e + 12].copy_from_slice(&8u32.to_le_bytes());
        img[e + 12..e + 16].copy_from_slice(&8u32.to_le_bytes());
        let off = 8 * 512;
        img[off..off + 512].copy_from_slice(&fat32_vbr(0x9999_8888));
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.fat_volume_serial, Some(0x1111_2222));
    }

    #[test]
    fn a_partition_declared_beyond_the_image_is_skipped() {
        // A valid FAT32 partition plus a second entry whose start LBA lies past the image end
        // (a truncated capture): the first is read, the out-of-range VBR is skipped.
        let mut img = mbr_disk(0xCAFE_0001, 0x0B, 2, &fat32_vbr(0xAABB_CCDD));
        let e = 0x1BE + 16;
        img[e + 4] = 0x07;
        img[e + 8..e + 12].copy_from_slice(&9000u32.to_le_bytes()); // far beyond the image
        img[e + 12..e + 16].copy_from_slice(&8u32.to_le_bytes());
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.fat_volume_serial, Some(0xAABB_CCDD));
    }

    #[test]
    fn an_ntfs_mbr_yields_the_disk_signature_with_no_fat_serial() {
        let img = mbr_disk(0xDEAD_BEEF, 0x07, 2, &ntfs_vbr());
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.disk_signature, 0xDEAD_BEEF);
        assert_eq!(d.fat_volume_serial, None);
        assert_eq!(d.encryption, None);
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
        let img = mbr_disk(0xE221_034C, 0x0B, 2, &fat32_vbr(0xB4D8_5399));
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

    /// A fixed-drive BitLocker VBR: jump `EB 58 90`, then the `-FVE-FS-` OEM id at offset 3.
    fn bitlocker_vbr() -> [u8; 512] {
        let mut vbr = [0u8; 512];
        vbr[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        vbr[3..11].copy_from_slice(b"-FVE-FS-");
        vbr[510..512].copy_from_slice(&[0x55, 0xAA]);
        vbr
    }

    #[test]
    fn bitlocker_signature_is_detected_from_the_vbr() {
        let img = mbr_disk(0xABCD_1234, 0x07, 2, &bitlocker_vbr());
        let d = parse_boot_sectors(&img).expect("valid MBR");
        assert_eq!(d.encryption, Some(EncryptionKind::BitLocker));
        assert_eq!(EncryptionKind::BitLocker.name(), "BitLocker");
        // A BitLocker volume is not FAT → no FAT serial.
        assert_eq!(d.fat_volume_serial, None);
    }

    #[test]
    fn plain_filesystem_media_is_not_flagged_as_encrypted() {
        // A real FAT32 volume must NOT false-positive as encrypted or unrecognized.
        let img = mbr_disk(1, 0x0B, 2, &fat32_vbr(42));
        assert_eq!(
            parse_boot_sectors(&img).expect("valid MBR").encryption,
            None
        );
        // The classifier itself: a plain NTFS VBR and empty bytes are not encryption.
        assert_eq!(classify_encryption(&ntfs_vbr(), DetectedFs::Ntfs), None);
        assert_eq!(classify_encryption(&[0u8; 4], DetectedFs::AllZeros), None);
    }

    #[test]
    fn an_unrecognized_filesystem_partition_is_flagged_as_possibly_encrypted() {
        // A partition whose VBR matches no known filesystem (all-random, as a VeraCrypt /
        // TrueCrypt container appears) → flagged as possibly-encrypted.
        let img = mbr_disk(7, 0x07, 2, &[0xABu8; 512]);
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
        // identifier GUID (To Go offset) — from forensicnomicon, the knowledge owner
        vbr[424..440]
            .copy_from_slice(&forensicnomicon::volume_encryption::BITLOCKER_IDENTIFIER_GUID);
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

    #[test]
    fn an_apple_partition_map_yields_no_device_image() {
        // An APM disk (Apple partitioning, `ER` DDR + `PM` map entry) carries no Windows
        // USB-attribution value, so it is not turned into a device image.
        let bs = 512usize;
        let mut d = vec![0u8; bs * 2];
        d[0..2].copy_from_slice(b"ER"); // Driver Descriptor Map signature
        d[2..4].copy_from_slice(&512u16.to_be_bytes()); // block size
        d[4..8].copy_from_slice(&4u32.to_be_bytes()); // device block count
        d[bs..bs + 2].copy_from_slice(b"PM"); // partition map entry signature
        d[bs + 4..bs + 8].copy_from_slice(&1u32.to_be_bytes()); // map entry count
        d[bs + 8..bs + 12].copy_from_slice(&1u32.to_be_bytes()); // start block
        d[bs + 12..bs + 16].copy_from_slice(&1u32.to_be_bytes()); // block count
        assert_eq!(parse_boot_sectors(&d), None);
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
