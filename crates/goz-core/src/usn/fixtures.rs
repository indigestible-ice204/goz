//! Byte-exact `USN_RECORD_V2`/`V3` fixture builders for tests.
//!
//! Emits exactly what `FSCTL_ENUM_USN_DATA` / `FSCTL_READ_USN_JOURNAL`
//! produce: a leading 8-byte value followed by packed records, each starting
//! 8-byte aligned relative to buffer start, with `RecordLength` padded to a
//! multiple of 8 and the padding filled with [`PAD_BYTE`] garbage (so tests
//! can prove padding never leaks into parsed names). Gated `#[cfg(any(test, doc))]`: compiled
//! for tests and for rustdoc, never in a release build.

use super::record::{FILE_ATTRIBUTE_DIRECTORY, USN_REASON_DATA_EXTEND};

/// Realistic default attribute for plain files.
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;

/// Fills alignment padding inside `RecordLength`. Deliberately
/// nonzero: real buffers contain garbage there, and a parser that reads past
/// `FileNameLength` will visibly corrupt names in tests.
pub const PAD_BYTE: u8 = 0xCC;

/// Logical description of one USN record; rendered to wire bytes by
/// [`record_bytes`] / [`build_enum_buffer`] / [`build_journal_buffer`].
#[derive(Clone, Debug)]
pub struct RecordFixture {
    /// Wire `MajorVersion` to emit: 2 or 3 (builders panic on anything
    /// else; V4/unknown records are hand-built where needed).
    pub version: u16,
    /// 64-bit FRN. For V3 it becomes the low half of the `FILE_ID_128`,
    /// high half zeroed (the NTFS zero-extension invariant).
    pub frn: u64,
    /// 64-bit parent FRN (same V3 treatment).
    pub parent: u64,
    pub usn: i64,
    /// `TimeStamp` (FILETIME).
    pub timestamp: i64,
    pub reason: u32,
    pub attributes: u32,
    /// Name as raw UTF-16 code units (unpaired surrogates permitted).
    pub name_units: Vec<u16>,
}

impl RecordFixture {
    /// A plain file record (V2, archive attribute, reason/usn/timestamp
    /// zeroed).
    pub fn file(frn: u64, parent: u64, name: &str) -> Self {
        Self {
            version: 2,
            frn,
            parent,
            usn: 0,
            timestamp: 0,
            reason: 0,
            attributes: FILE_ATTRIBUTE_ARCHIVE,
            name_units: name.encode_utf16().collect(),
        }
    }

    /// A directory record (V2, directory attribute).
    pub fn dir(frn: u64, parent: u64, name: &str) -> Self {
        Self {
            attributes: FILE_ATTRIBUTE_DIRECTORY,
            ..Self::file(frn, parent, name)
        }
    }

    pub fn with_reason(mut self, reason: u32) -> Self {
        self.reason = reason;
        self
    }

    pub fn with_version(mut self, version: u16) -> Self {
        self.version = version;
        self
    }

    pub fn with_usn(mut self, usn: i64) -> Self {
        self.usn = usn;
        self
    }

    pub fn with_timestamp(mut self, timestamp: i64) -> Self {
        self.timestamp = timestamp;
        self
    }

    pub fn with_attributes(mut self, attributes: u32) -> Self {
        self.attributes = attributes;
        self
    }

    /// Replaces the name with raw UTF-16 code units (for surrogate and
    /// non-string names).
    pub fn with_name_units(mut self, name_units: Vec<u16>) -> Self {
        self.name_units = name_units;
        self
    }
}

/// Renders one fixture to its exact wire bytes: fixed header, UTF-16LE name
/// at `FileNameOffset`, then [`PAD_BYTE`] padding out to `RecordLength`
/// (a multiple of 8, matching real NTFS output).
pub fn record_bytes(fx: &RecordFixture) -> Vec<u8> {
    let (header_len, name_off) = match fx.version {
        2 => (60usize, 60u16),
        3 => (76usize, 76u16),
        other => panic!("RecordFixture supports V2/V3 only, got version {other}"),
    };
    let name_bytes_len = fx.name_units.len() * 2;
    let rec_len = (header_len + name_bytes_len).next_multiple_of(8);

    let mut b = Vec::with_capacity(rec_len);
    b.extend_from_slice(&u32::try_from(rec_len).unwrap().to_le_bytes());
    b.extend_from_slice(&fx.version.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    match fx.version {
        2 => {
            b.extend_from_slice(&fx.frn.to_le_bytes());
            b.extend_from_slice(&fx.parent.to_le_bytes());
        }
        3 => {
            // FILE_ID_128: 64-bit FRN in the low 8 bytes, high half zero.
            b.extend_from_slice(&fx.frn.to_le_bytes());
            b.extend_from_slice(&[0u8; 8]);
            b.extend_from_slice(&fx.parent.to_le_bytes());
            b.extend_from_slice(&[0u8; 8]);
        }
        _ => unreachable!(),
    }
    b.extend_from_slice(&fx.usn.to_le_bytes());
    b.extend_from_slice(&fx.timestamp.to_le_bytes());
    b.extend_from_slice(&fx.reason.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes()); // SourceInfo
    b.extend_from_slice(&0u32.to_le_bytes()); // SecurityId
    b.extend_from_slice(&fx.attributes.to_le_bytes());
    b.extend_from_slice(&u16::try_from(name_bytes_len).unwrap().to_le_bytes());
    b.extend_from_slice(&name_off.to_le_bytes());
    for unit in &fx.name_units {
        b.extend_from_slice(&unit.to_le_bytes());
    }
    b.resize(rec_len, PAD_BYTE);
    b
}

/// Builds a full `FSCTL_ENUM_USN_DATA` output buffer: leading next
/// `StartFileReferenceNumber`, then the packed records.
pub fn build_enum_buffer(next_start_frn: u64, recs: &[RecordFixture]) -> Vec<u8> {
    let mut buf = next_start_frn.to_le_bytes().to_vec();
    for fx in recs {
        debug_assert!(buf.len().is_multiple_of(8));
        buf.extend_from_slice(&record_bytes(fx));
    }
    buf
}

/// Builds a full `FSCTL_READ_USN_JOURNAL` output buffer: leading next
/// `StartUsn`, then the packed records.
pub fn build_journal_buffer(next_usn: i64, recs: &[RecordFixture]) -> Vec<u8> {
    let mut buf = next_usn.to_le_bytes().to_vec();
    for fx in recs {
        debug_assert!(buf.len().is_multiple_of(8));
        buf.extend_from_slice(&record_bytes(fx));
    }
    buf
}

/// A plausible 80-byte `USN_RECORD_V4` (extent-range record, no file name)
/// for version-skip tests: common header + two `FILE_ID_128`s + Usn +
/// Reason + SourceInfo + RemainingExtents + NumberOfExtents + ExtentSize +
/// one 16-byte extent.
pub fn build_v4_record_bytes() -> Vec<u8> {
    let mut b = Vec::with_capacity(80);
    b.extend_from_slice(&80u32.to_le_bytes()); // RecordLength
    b.extend_from_slice(&4u16.to_le_bytes()); // MajorVersion
    b.extend_from_slice(&0u16.to_le_bytes()); // MinorVersion
    b.extend_from_slice(&0xAAAAu64.to_le_bytes()); // FRN low
    b.extend_from_slice(&[0u8; 8]); // FRN high
    b.extend_from_slice(&0x5u64.to_le_bytes()); // parent FRN low
    b.extend_from_slice(&[0u8; 8]); // parent FRN high
    b.extend_from_slice(&4096i64.to_le_bytes()); // Usn
    b.extend_from_slice(&USN_REASON_DATA_EXTEND.to_le_bytes()); // Reason
    b.extend_from_slice(&0u32.to_le_bytes()); // SourceInfo
    b.extend_from_slice(&0u32.to_le_bytes()); // RemainingExtents
    b.extend_from_slice(&1u16.to_le_bytes()); // NumberOfExtents
    b.extend_from_slice(&16u16.to_le_bytes()); // ExtentSize
    b.extend_from_slice(&0i64.to_le_bytes()); // Extents[0].Offset
    b.extend_from_slice(&65536i64.to_le_bytes()); // Extents[0].Length
    debug_assert_eq!(b.len(), 80);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_record_bytes_are_byte_exact() {
        let rb = record_bytes(
            &RecordFixture::file(0x11, 0x22, "abc")
                .with_usn(9)
                .with_timestamp(-1)
                .with_reason(0xF00D),
        );
        assert_eq!(rb.len(), 72); // 60 + 6, padded to 72
        assert_eq!(&rb[0..4], &72u32.to_le_bytes()); // RecordLength
        assert_eq!(&rb[4..6], &2u16.to_le_bytes()); // MajorVersion
        assert_eq!(&rb[6..8], &0u16.to_le_bytes()); // MinorVersion
        assert_eq!(&rb[8..16], &0x11u64.to_le_bytes()); // FRN
        assert_eq!(&rb[16..24], &0x22u64.to_le_bytes()); // parent FRN
        assert_eq!(&rb[24..32], &9i64.to_le_bytes()); // Usn
        assert_eq!(&rb[32..40], &(-1i64).to_le_bytes()); // TimeStamp
        assert_eq!(&rb[40..44], &0xF00Du32.to_le_bytes()); // Reason
        assert_eq!(&rb[44..48], &0u32.to_le_bytes()); // SourceInfo
        assert_eq!(&rb[48..52], &0u32.to_le_bytes()); // SecurityId
        assert_eq!(&rb[52..56], &0x20u32.to_le_bytes()); // FileAttributes
        assert_eq!(&rb[56..58], &6u16.to_le_bytes()); // FileNameLength
        assert_eq!(&rb[58..60], &60u16.to_le_bytes()); // FileNameOffset
        assert_eq!(&rb[60..66], b"a\0b\0c\0"); // UTF-16LE name
        assert_eq!(&rb[66..72], &[PAD_BYTE; 6]); // padding
    }

    #[test]
    fn v3_record_bytes_are_byte_exact() {
        let rb = record_bytes(&RecordFixture::dir(0x33, 0x44, "d").with_version(3));
        assert_eq!(rb.len(), 80); // 76 + 2, padded to 80
        assert_eq!(&rb[0..4], &80u32.to_le_bytes());
        assert_eq!(&rb[4..6], &3u16.to_le_bytes());
        assert_eq!(&rb[8..16], &0x33u64.to_le_bytes()); // FRN low
        assert_eq!(&rb[16..24], &[0u8; 8]); // FRN high
        assert_eq!(&rb[24..32], &0x44u64.to_le_bytes()); // parent low
        assert_eq!(&rb[32..40], &[0u8; 8]); // parent high
        assert_eq!(&rb[68..72], &FILE_ATTRIBUTE_DIRECTORY.to_le_bytes()); // attrs
        assert_eq!(&rb[72..74], &2u16.to_le_bytes()); // FileNameLength
        assert_eq!(&rb[74..76], &76u16.to_le_bytes()); // FileNameOffset
        assert_eq!(&rb[76..78], b"d\0");
        assert_eq!(&rb[78..80], &[PAD_BYTE; 2]);
    }

    #[test]
    fn buffers_keep_every_record_8_aligned() {
        let recs = [
            RecordFixture::file(1, 0, "x"),                  // 62 -> 64
            RecordFixture::file(2, 0, "yy").with_version(3), // 80 -> 80
            RecordFixture::file(3, 0, "zzz"),                // 66 -> 72
        ];
        let buf = build_enum_buffer(0, &recs);
        assert_eq!(buf.len(), 8 + 64 + 80 + 72);
        assert!(buf.len().is_multiple_of(8));
    }
}
