//! Output formatting: the byte-exact es-compatible CSV writer and FILETIME
//! conversion/formatting helpers.
//!
//! [`csv`] reproduces voidtools es.exe's `-export-csv` byte stream (spec
//! extracted from the es source), with goz's one documented deviation: the
//! UTF-8 BOM is on by default.
//! [`filetime`] converts between FILETIME ticks and Unix milliseconds and
//! renders civil UTC timestamps without a timezone database (the CLI formats
//! local time itself).

pub mod csv;
pub mod filetime;

pub use csv::{CsvOptions, CsvRow, write_csv};
pub use filetime::{
    FILETIME_UNIX_EPOCH, filetime_to_unix_ms, format_filetime_utc, unix_ms_to_filetime,
};
