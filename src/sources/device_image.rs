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

/// A physical device's boot-sector identity.
/// A detected volume-encryption type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionKind {
    /// Microsoft BitLocker / BitLocker To Go — the VBR OEM id is replaced by `-FVE-FS-`.
    BitLocker,
}

impl EncryptionKind {
    /// A stable display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::BitLocker => "BitLocker",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceImage {
    /// MBR disk signature (4 bytes at offset `0x1B8`) — joins the `MountedDevices` bridge.
    pub disk_signature: u32,
    /// FAT volume serial (`BS_VolID`) of the first FAT partition, when present — the
    /// 4-byte serial `EMDMgmt` and Shell Links store.
    pub fat_volume_serial: Option<u32>,
    /// The volume-encryption type, when a boot sector carries an encryption signature.
    pub encryption: Option<EncryptionKind>,
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
        if encryption.is_none() {
            encryption = detect_encryption(vbr);
        }
        if fat_volume_serial.is_none() && FAT_TYPES.contains(&ptype) {
            fat_volume_serial = Some(fat_bs_volid(vbr));
        }
    }
    Some(DeviceImage {
        disk_signature,
        fat_volume_serial,
        encryption,
    })
}

/// Detect volume encryption from a VBR's OEM identifier (offset 3, 8 bytes). BitLocker and
/// BitLocker To Go replace the filesystem OEM id (`NTFS    ` / `MSDOS5.0`) with `-FVE-FS-`
/// — the documented FVE signature (see the module reference). `None` for a plain FS.
fn detect_encryption(vbr: &[u8]) -> Option<EncryptionKind> {
    (vbr.get(3..11) == Some(b"-FVE-FS-")).then_some(EncryptionKind::BitLocker)
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
    fn source_without_a_fat_serial_or_encryption_emits_nothing() {
        // A device with no FAT partition and no encryption carries nothing to correlate on.
        let img = DeviceImage {
            disk_signature: 1,
            fat_volume_serial: None,
            encryption: None,
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
        // A real FAT32 volume ("FAT32   "/"MSDOS5.0" OEM) must NOT false-positive.
        let img = mbr_with_fat32(1, 1, 42);
        assert_eq!(
            parse_boot_sectors(&img).expect("valid MBR").encryption,
            None
        );
        assert_eq!(detect_encryption(b"NTFS    xxxxxxxx"), None);
        assert_eq!(detect_encryption(&[0u8; 4]), None);
    }

    #[test]
    fn source_emits_an_encryption_claim_for_an_encrypted_device() {
        let img = DeviceImage {
            disk_signature: 0xABCD_1234,
            fat_volume_serial: None,
            encryption: Some(EncryptionKind::BitLocker),
        };
        let claims = DeviceImageSource::new(&img, "x").claims();
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].attribute, Attribute::Encryption);
        assert_eq!(claims[0].value, Value::Text("BitLocker".to_string()));
    }
}
