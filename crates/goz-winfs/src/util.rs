//! Small UTF-16 <-> Rust string helpers for the Win32 boundary.
//!
//! Manual conversion (as sanctioned by the research notes) keeps the crate
//! dependency-light; NTFS names are handled as bytes by `goz-core`, so lossy
//! decoding here only touches short, well-formed system strings (volume
//! GUID paths, filesystem names, mount points).

/// Encodes `s` as a NUL-terminated UTF-16 buffer for a `PCWSTR`.
pub(crate) fn to_wide_nul(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(core::iter::once(0)).collect()
}

/// Decodes a wide buffer up to its first NUL into a `String` (lossy).
pub(crate) fn from_wide_nul(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}
