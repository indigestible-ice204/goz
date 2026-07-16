//! es.exe-compatible command-line parsing.
//!
//! A pure translation of an argv slice into an [`EsPlan`] (what to search,
//! how to sort, what to output) or an [`EsFatal`] carrying the es-compatible
//! process exit code. The switch-matching rules are lifted from the voidtools
//! es source: case-sensitive names with
//! every interior dash optional, `/`-prefixed fallthrough to search text,
//! and es exit codes 4 (missing/bad switch parameter) and 6 (unknown switch).
//!
//! goz-native extensions live behind a `--` prefix (`--json`, `--status`,
//! `--insecure-no-server-check`) so they can never collide with es's
//! single-dash switch namespace.

mod argv;

pub use argv::{EsFatal, EsPlan, parse_argv};
