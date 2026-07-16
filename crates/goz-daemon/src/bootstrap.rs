//! Per-volume bootstrap: enumerate the MFT and enrich from FILE_LAYOUT, wiring
//! the raw Win32 buffers from `goz-winfs` through the pure parsers in
//! `goz-core` into a `VolumeIndex`.
//!
//! This is the bridge the whole design turns on: `goz-winfs` hands us bytes,
//! `goz-core` interprets them, and neither knows about the other. The daemon
//! (here) owns the buffers and the loop.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use goz_core::index::{FrnMap, NTFS_ROOT_FRN, VolumeIndex};
use goz_core::layout::{RECOMMENDED_LAYOUT_FLAGS, walk_layout_buffer};
use goz_core::usn::walk_enum_buffer;
use goz_winfs::{
    JournalInfo, JournalQuery, VolumeHandle, VolumeInfo, create_usn_journal, enum_usn_data,
    enumerate_volumes, query_file_layout, query_usn_journal,
};

/// 64 MiB minimum journal: large enough that routine churn does not wrap it
/// before we finish bootstrapping (the plan's `journal_min_size`).
const JOURNAL_MIN_SIZE: u64 = 64 * 1024 * 1024;
const JOURNAL_ALLOC_DELTA: u64 = 8 * 1024 * 1024;
/// 1 MiB ioctl buffer: ~100 ENUM round-trips per million files.
const IO_BUFFER_BYTES: usize = 1024 * 1024;

/// A freshly bootstrapped volume: its index plus the retained volume handle
/// and journal cursor the daemon needs to tail it live.
pub(crate) struct BootstrappedVolume {
    pub guid_path: String,
    pub mounts: Vec<String>,
    pub enum_secs: f64,
    pub layout_secs: f64,
    /// `None` if the volume has no usable USN journal (bootstrap still works;
    /// only the live tail would be unavailable).
    pub cursor: Option<JournalInfo>,
    pub index: VolumeIndex,
    /// Kept open for the live tail (moved into the tail thread by the daemon).
    pub handle: VolumeHandle,
}

impl BootstrappedVolume {
    pub(crate) fn entries(&self) -> usize {
        self.index.len()
    }
}

/// A volume that could not be bootstrapped, carried so the daemon can still
/// represent it.
///
/// Skipping a failed volume silently is worse than reporting it Offline: every
/// honesty signal (`--status`, `Hello.ready`, each page's `volumes_incomplete`)
/// is computed by iterating the volume set, so a volume that was never inserted
/// has no phase to be non-Live and is unreportable. A query scoped to it then
/// returns zero hits with exit 0, indistinguishable from "no such file".
pub(crate) struct FailedVolume {
    pub guid_path: String,
    pub mounts: Vec<String>,
    pub reason: String,
}

/// Everything `scan_all` learned: the volumes it indexed, and the ones it could
/// not. Both halves must reach the engine.
pub(crate) struct Scan {
    pub ok: Vec<BootstrappedVolume>,
    pub failed: Vec<FailedVolume>,
}

/// Bootstraps every fixed NTFS volume. A volume that fails to bootstrap is
/// reported and returned in `failed` rather than aborting the whole run, so one
/// unreadable volume never hides the others' results and never disappears.
pub(crate) fn scan_all() -> Result<Scan> {
    // The raw volume and journal reads need these privileges; if the process is
    // not elevated the open itself fails with a clear message, so a
    // privilege-enable failure here is only a warning.
    if let Err(e) = goz_winfs::enable_volume_privileges() {
        tracing::warn!(error = %e, "could not enable volume privileges; continuing");
    }

    let volumes = enumerate_volumes().context("enumerating volumes")?;
    let targets: Vec<VolumeInfo> = volumes
        .into_iter()
        .filter(|v| v.is_fixed && v.is_ntfs)
        .collect();
    if targets.is_empty() {
        bail!("no fixed NTFS volumes found");
    }

    let mut ok = Vec::new();
    let mut failed = Vec::new();
    for vol in &targets {
        match bootstrap_volume(vol) {
            Ok(scan) => ok.push(scan),
            Err(e) => {
                tracing::error!(
                    volume = %vol.guid_path,
                    error = %format!("{e:#}"),
                    "volume failed to bootstrap; it will be reported Failed and serve no results"
                );
                failed.push(FailedVolume {
                    guid_path: vol.guid_path.clone(),
                    mounts: vol.mounts.clone(),
                    reason: format!("{e:#}"),
                });
            }
        }
    }
    if ok.is_empty() {
        bail!("no volume could be bootstrapped (see the log for per-volume errors)");
    }
    Ok(Scan { ok, failed })
}

/// Bootstraps a single volume: journal setup → MFT enumeration → FILE_LAYOUT
/// enrichment.
fn bootstrap_volume(vol: &VolumeInfo) -> Result<BootstrappedVolume> {
    let handle = goz_winfs::open_volume(&vol.guid_path).with_context(|| {
        format!(
            "opening {} (must run elevated for raw volume access)",
            vol.guid_path
        )
    })?;

    // The journal is only needed for the live tail; a one-shot scan reads the
    // MFT directly, so an unavailable journal is not fatal here.
    let cursor = ensure_journal(&handle);
    // First-time bootstrap passes no stop flag, so the rebuild can never abort.
    let (index, enum_secs, layout_secs) =
        build_index(&handle, None)?.expect("build_index cannot abort without a stop flag");

    Ok(BootstrappedVolume {
        guid_path: vol.guid_path.clone(),
        mounts: vol.mounts.clone(),
        enum_secs,
        layout_secs,
        cursor,
        index,
        handle,
    })
}

/// Builds a fresh [`VolumeIndex`] for an already-open volume handle: a full MFT
/// enumeration followed by FILE_LAYOUT enrichment. Shared by first-time
/// bootstrap and the live tail's rescan (after a USN journal wrap/deletion),
/// which rebuilds the index on the handle it already owns. Returns the index
/// plus the enum/layout wall-clock timings. The journal is the caller's concern.
pub(crate) fn build_index(
    handle: &VolumeHandle,
    stop: Option<&AtomicBool>,
) -> Result<Option<(VolumeIndex, f64, f64)>> {
    let cancelled = || stop.is_some_and(|s| s.load(Ordering::Relaxed));
    let mut index = VolumeIndex::new(NTFS_ROOT_FRN, FrnMap::sparse());
    let mut buf = vec![0u8; IO_BUFFER_BYTES];

    // --- MFT enumeration ------------------------------------------------
    let enum_start = Instant::now();
    let mut next_frn: u64 = 0;
    loop {
        if cancelled() {
            return Ok(None); // shutdown arrived mid-rebuild: abort cooperatively
        }
        let Some(bytes) =
            enum_usn_data(handle, next_frn, &mut buf).context("FSCTL_ENUM_USN_DATA")?
        else {
            break; // ERROR_HANDLE_EOF: enumeration complete
        };
        let walk = walk_enum_buffer(&buf[..bytes]).context("parsing ENUM buffer")?;
        for rec in &walk.records {
            index.insert_enum(rec);
        }
        // The kernel guarantees forward progress; guard against a stuck cursor
        // anyway so a driver quirk can never spin forever.
        if walk.next_start_frn == next_frn && walk.records.is_empty() {
            break;
        }
        next_frn = walk.next_start_frn;
    }
    let enum_secs = enum_start.elapsed().as_secs_f64();

    // --- FILE_LAYOUT enrichment (sizes, mtimes, hard-link names) --------
    //
    // Best-effort: a failure warns and continues, leaving sizes "unknown" which
    // the query engine and CSV writer handle safely. Degrading beats failing the
    // whole bootstrap, since names alone still answer most queries.
    let layout_start = Instant::now();
    let mut restart = true;
    loop {
        if cancelled() {
            return Ok(None); // shutdown arrived mid-enrichment: abort cooperatively
        }
        match query_file_layout(handle, RECOMMENDED_LAYOUT_FLAGS, restart, &mut buf) {
            Ok(Some(bytes)) => {
                let files =
                    walk_layout_buffer(&buf[..bytes]).context("parsing FILE_LAYOUT buffer")?;
                for f in &files {
                    index.enrich(f);
                }
                restart = false;
            }
            Ok(None) => break, // end of scan
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "FILE_LAYOUT enrichment stopped; sizes and dates may be incomplete"
                );
                break;
            }
        }
    }
    let layout_secs = layout_start.elapsed().as_secs_f64();

    Ok(Some((index, enum_secs, layout_secs)))
}

/// Returns the volume's USN journal info if one is usable, else `None`.
///
/// Never fatal: a one-shot scan reads the MFT directly and does not need the
/// journal. An active journal is used as-is (and grown to
/// [`JOURNAL_MIN_SIZE`] on a best-effort basis: a read-only handle cannot
/// modify it, and a smaller journal only wraps sooner). An absent journal is
/// created on the spot on a best-effort basis and used if creation succeeds; if
/// it cannot be created, or a deletion is in progress, this yields `None`
/// (usually with a note) and live updates are unavailable.
pub(crate) fn ensure_journal(handle: &VolumeHandle) -> Option<JournalInfo> {
    match query_usn_journal(handle) {
        Ok(JournalQuery::Active(info)) => {
            if info.maximum_size < JOURNAL_MIN_SIZE
                && let Err(e) = create_usn_journal(handle, JOURNAL_MIN_SIZE, JOURNAL_ALLOC_DELTA)
            {
                tracing::warn!(
                    error = %e,
                    wanted_mib = JOURNAL_MIN_SIZE / (1024 * 1024),
                    actual_mib = info.maximum_size / (1024 * 1024),
                    "could not grow the USN journal; a smaller journal wraps sooner"
                );
            }
            Some(info)
        }
        Ok(JournalQuery::NotActive) => {
            match create_usn_journal(handle, JOURNAL_MIN_SIZE, JOURNAL_ALLOC_DELTA) {
                Ok(()) => match query_usn_journal(handle) {
                    Ok(JournalQuery::Active(info)) => Some(info),
                    // We just created a journal and it is not active. Rare, but
                    // naming it matters: a volume that should have tailed live
                    // silently will not, and every other `None` here means
                    // something different.
                    Ok(other) => {
                        tracing::warn!(
                            state = ?other,
                            "created a USN journal but it is not active; live updates unavailable"
                        );
                        None
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "created a USN journal but could not re-query it; live updates unavailable"
                        );
                        None
                    }
                },
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "no USN journal and could not create one; live updates unavailable"
                    );
                    None
                }
            }
        }
        Ok(JournalQuery::DeleteInProgress) => {
            tracing::warn!("USN journal deletion in progress; live updates unavailable");
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not query the USN journal; live updates unavailable");
            None
        }
    }
}
