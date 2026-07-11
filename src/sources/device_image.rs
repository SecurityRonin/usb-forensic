//! Source: a physical device's own boot sectors (a raw disk image) → USB-history
//! [`Claim`]s — the strongest device attribution.
//!
//! When the suspect USB device itself is imaged, its **MBR disk signature** and **FAT
//! volume serial** tie it directly to the host's footprint: the disk signature matches a
//! `MountedDevices` MBR record (→ drive letter, volume GUID), and the FAT volume serial
//! matches an `EMDMgmt`/`.lnk` volume serial (→ label, files opened). This closes the loop
//! that host artifacts alone cannot — attributing a *physical device in evidence* to what
//! it did on the machine. A pure decode of the boot-sector bytes; no filesystem walk.

use crate::{Attribute, Claim, DeviceKey, HistorySource, Provenance, SourceKind, Value};

/// A physical device's boot-sector identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceImage {
    /// MBR disk signature (4 bytes at offset `0x1B8`) — joins the `MountedDevices` bridge.
    pub disk_signature: u32,
    /// FAT volume serial (`BS_VolID`) of the first FAT partition, when present — the
    /// 4-byte serial `EMDMgmt` and Shell Links store.
    pub fat_volume_serial: Option<u32>,
}

/// Decode a raw disk image's boot sectors. Requires a valid MBR (the `0x55AA` boot
/// signature at offset `0x1FE`); reads the disk signature, then walks the MBR partition
/// table for the first FAT partition and reads its `BS_VolID`. `None` for a non-MBR image.
#[must_use]
pub fn parse_boot_sectors(image: &[u8]) -> Option<DeviceImage> {
    if image.get(0x1FE..0x200)? != [0x55, 0xAA] {
        return None;
    }
    let disk_signature = u32::from_le_bytes(image.get(0x1B8..0x1BC)?.try_into().ok()?);
    Some(DeviceImage {
        disk_signature,
        fat_volume_serial: first_fat_volume_serial(image),
    })
}

/// FAT partition type bytes (`FAT12`/`16`/`32`, incl. LBA variants).
const FAT_TYPES: [u8; 6] = [0x01, 0x04, 0x06, 0x0B, 0x0C, 0x0E];

/// Walk the four MBR partition entries (16 bytes each from `0x1BE`); for the first FAT
/// partition, read its VBR `BS_VolID` (offset `0x43` for FAT32, `0x27` for FAT12/16).
fn first_fat_volume_serial(image: &[u8]) -> Option<u32> {
    for i in 0..4 {
        let entry = image.get(0x1BE + i * 16..0x1BE + i * 16 + 16)?;
        if !FAT_TYPES.contains(&entry[4]) {
            continue;
        }
        let start_lba = u32::from_le_bytes(entry[8..12].try_into().ok()?) as usize;
        let vbr = image.get(start_lba * 512..start_lba * 512 + 512)?;
        // FAT32 VBR carries "FAT32   " at 0x52 with BS_VolID at 0x43; FAT12/16 at 0x36/0x27.
        let off = if vbr.get(0x52..0x5A) == Some(b"FAT32   ") {
            0x43
        } else {
            0x27
        };
        return Some(u32::from_le_bytes(vbr.get(off..off + 4)?.try_into().ok()?));
    }
    None
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
        // Key the physical device by its MBR disk signature — a stable media identity. Emit
        // its FAT volume serial as a VolumeSerial fact so an EMDMgmt/LNK record (keyed by
        // that same serial) reconciles ONTO the physical device, carrying its label and the
        // files opened from it. The disk signature is a distinct value (it joins the
        // MountedDevices MBR bridge, not the volume-serial space) and is not emitted as a
        // VolumeSerial to avoid conflating the two.
        let Some(vsn) = self.image.fat_volume_serial else {
            return Vec::new();
        };
        vec![Claim {
            device: DeviceKey(format!("disk-{:08X}", self.image.disk_signature)),
            attribute: Attribute::VolumeSerial,
            value: Value::Text(fmt_serial(vsn)),
            provenance: Provenance {
                source: SourceKind::DeviceImage,
                locator: self.locator.clone(),
            },
        }]
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
    fn source_without_a_fat_serial_emits_nothing() {
        // A device with no FAT partition carries no volume serial to reconcile on.
        let img = DeviceImage {
            disk_signature: 1,
            fat_volume_serial: None,
        };
        assert!(DeviceImageSource::new(&img, "x").claims().is_empty());
    }
}
