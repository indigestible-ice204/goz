//! End-to-end exit-code contract for the `goz` binary.
//!
//! `goz_core::escompat` already unit-tests the argv rules themselves; what no
//! unit test can observe is whether `main` actually maps an `EsFatal` onto the
//! process exit code. These spawn the real binary and check that wiring.
//!
//! Only cases that need no running daemon live here. Anything past
//! `Client::connect` depends on whether `\\.\pipe\goz-v1` happens to be live on
//! the machine running the suite, which would pass on CI and flake on a
//! developer box with `gozd` running. The three cases below all fail before the
//! first connect attempt, so they are hermetic on any OS.

use std::process::{Command, Output};

fn goz<const N: usize>(args: [&str; N]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_goz"))
        .args(args)
        .output()
        .expect("failed to spawn the goz binary")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// es exit code 6. Parsing rejects the switch before any daemon contact.
#[test]
fn unknown_switch_exits_6() {
    let out = goz(["-bogus-switch", "foo"]);
    assert_eq!(out.status.code(), Some(6), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("unknown switch: -bogus-switch"),
        "stderr: {}",
        stderr(&out)
    );
}

/// es exit code 4. `-path` consumes a following value; there is none here.
#[test]
fn missing_switch_parameter_exits_4() {
    let out = goz(["-path"]);
    assert_eq!(out.status.code(), Some(4), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("expected an additional parameter after -path"),
        "stderr: {}",
        stderr(&out)
    );
}

/// es exit code 5. The export file is created up front, so an uncreatable path
/// fails before `Client::connect` and needs no daemon.
///
/// Windows-only: on other targets `execute` short-circuits to exit 8 without
/// ever reading `-export-csv`, so this would fail on the CI ubuntu leg.
#[cfg(windows)]
#[test]
fn unwritable_export_path_exits_5() {
    // A directory that cannot exist, made unique so a stale tree cannot make
    // this pass for the wrong reason (a creatable path would reach connect).
    let missing = std::env::temp_dir()
        .join(format!("goz-absent-{}", std::process::id()))
        .join("out.csv");
    assert!(!missing.exists());

    let out = goz(["-export-csv", &missing.to_string_lossy(), "foo"]);
    assert_eq!(out.status.code(), Some(5), "stderr: {}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot create"),
        "stderr: {}",
        stderr(&out)
    );
}
