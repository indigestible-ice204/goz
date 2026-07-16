//! USN journal byte-level machinery: record parsing, output-buffer walking,
//! reason-bit normalization, and cursor validation.
//!
//! Everything here is pure: the Win32 layer (`goz-winfs`) hands over raw
//! `FSCTL_ENUM_USN_DATA` / `FSCTL_READ_USN_JOURNAL` output buffers and this
//! module turns them into typed records ([`record`]), normalizes accumulated
//! reason bitmasks into idempotent index ops ([`ops`]), and provides
//! the pure replay-vs-full-rescan decision a caller would make from a saved
//! cursor ([`cursor`]; deliberately unwired while v1 cold-bootstraps, see its
//! module docs). The whole module is testable from fixture buffers on any OS
//! ([`fixtures`]).

pub mod cursor;
pub mod ops;
pub mod record;

// `doc` as well as `test` so the fixture story stays visible in rustdoc: the
// module-level claim above links to it, and that claim is the reason the crate
// is structured this way.
#[cfg(any(test, doc))]
pub mod fixtures;

pub use cursor::{JournalInfo, RescanReason, Resync, SavedCursor, validate_cursor};
pub use ops::{UsnOp, ops_for};
pub use record::{
    EnumWalk, JournalWalk, ParsedUsnRecord, SkipCounts, WalkError, walk_enum_buffer,
    walk_journal_buffer,
};
