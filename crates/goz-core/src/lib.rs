//! goz-core: the pure, OS-agnostic heart of goz.
//!
//! Everything that interprets bytes lives here: USN records, MFT enumeration
//! buffers, FILE_LAYOUT entries, the in-memory index, the query engine, the
//! wire protocol, CSV/JSON output, and the es.exe-compatible argv rules.
//! This crate has zero `cfg(windows)` code and zero platform dependencies:
//! its entire test suite runs on any OS from fixture buffers and synthetic
//! trees. The Win32 layer (`goz-winfs`) produces and consumes raw buffers, plain typed
//! structs, and opaque handles; it never parses ioctl record payloads (USN
//! records, MFT enum output, file-layout entries).

pub mod escompat;
pub mod fold;
pub mod index;
pub mod layout;
pub mod output;
pub mod proto;
pub mod query;
pub mod types;
pub mod usn;
pub mod wtf8;
