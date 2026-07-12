# 0003 — Volume serial and encryption are volume properties, analysed scheme-agnostically

Status: Accepted (implementation pending — supersedes the local reads noted in ADR 0002)

## Context

After delegating partition parsing to `disk-forensic` (ADR 0002), two values were still read
from the volume boot record inside usb-forensic's device-image source: the FAT `BS_VolID` and
BitLocker To Go. That placement was wrong on two counts.

1. **They are not USB-specific.** A volume serial and a BitLocker volume are properties of a
   *volume*, identical whether the volume is reached over USB, FireWire, Thunderbolt, or SATA.
   A USB correlation engine is the wrong home for that knowledge.
2. **They are not scheme-specific either.** The same FAT/NTFS/BitLocker volume can sit in an
   MBR partition, a GPT partition, or an APM partition — its boot record is identical. So the
   logic must not be tied to `mbr-partition-forensic`; GPT and APM volumes have serials and
   encryption too. (Today only MBR partitions even carry a detected filesystem — GPT entries
   carry none, which is the same gap.)

The forensic *knowledge* — the FVE `-FVE-FS-` signature, the BitLocker identifier GUID, the
`BS_VolID`/NTFS-serial field offsets — belongs in **forensicnomicon**, the fleet's knowledge
base, alongside the filesystem-signature catalog it already owns.

## Decision

Layer the responsibility by concern, scheme-agnostically:

1. **forensicnomicon/core** owns the volume knowledge *and* the detection/extraction functions
   that operate on a volume-bytes slice: `detect_name()` (exists) plus `detect_encryption()`
   (FVE signature + identifier-GUID scan) and `volume_serial()` (the documented offsets).
   The shared filesystem / encryption / serial types live here.
2. **Each partition-scheme crate** (`mbr-`, `gpt-`, `apm-partition-forensic`) locates its
   partitions and calls forensicnomicon's volume-analysis to populate `{fs, serial, encryption}`
   on **every** partition entry, uniformly.
3. **disk-forensic** surfaces the per-partition volume info for all three schemes.
4. **usb-forensic**'s device-image source shrinks to a consumer: `DiskReport` → map
   `disk_signature` + per-partition `{volume_serial, encryption}` to `Claim`s. All boot-record
   reading, GUID scanning, and `BS_VolID` logic is deleted from here.

## Consequences

- GPT and APM volumes gain the same `{fs, serial, encryption}` that MBR volumes have; the
  MBR-only filesystem-detection gap is closed.
- The forensic knowledge lives in one place (forensicnomicon), cited to its spec, reusable by
  any tool in the fleet, not duplicated per consumer.
- The change spans three published crates (forensicnomicon, the partition crates, disk-forensic)
  plus the usb-forensic consumer refactor — three fleet publishes. It is sequenced *after* the
  working local implementation (ADR 0002) lands, so value ships first and the layering thins it.
