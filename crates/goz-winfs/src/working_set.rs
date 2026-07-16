//! Pin the resident working set so the memory manager does not page out the
//! in-RAM filename index. The SIMD substring scan and O(1) directory rename
//! both require the index in memory; without a floor, a low-memory burst can
//! trim it to disk and make the next search pay hard page faults.

use core::mem::{size_of, zeroed};

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::Memory::SetProcessWorkingSetSizeEx;
use windows_sys::Win32::System::ProcessStatus::{
    GetProcessMemoryInfo, K32EmptyWorkingSet, PROCESS_MEMORY_COUNTERS,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::error::WinError;

// SetProcessWorkingSetSizeEx flags (winnt.h). Defined locally, matching this
// crate's convention of not pulling constant-only symbols from windows-sys.
const QUOTA_LIMITS_HARDWS_MIN_ENABLE: u32 = 0x0000_0001;
const QUOTA_LIMITS_HARDWS_MAX_DISABLE: u32 = 0x0000_0008;

/// The process's memory counters at one instant: working set (what Task
/// Manager shows) and commit charge (private bytes, the true footprint).
#[derive(Clone, Copy, Debug, Default)]
pub struct SelfMemory {
    pub working_set: u64,
    pub private_bytes: u64,
}

/// Reads the current process's own memory counters. Cheap (one syscall);
/// used by `Status` so a client can see the daemon's real footprint next to
/// the index's accounted bytes.
pub fn self_memory() -> Result<SelfMemory, WinError> {
    // SAFETY: plain Win32 FFI: current-process pseudo-handle and a stack
    // struct sized by its own `cb` field.
    unsafe {
        let mut counters: PROCESS_MEMORY_COUNTERS = zeroed();
        counters.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "GetProcessMemoryInfo",
            });
        }
        Ok(SelfMemory {
            working_set: counters.WorkingSetSize as u64,
            // PagefileUsage is the commit charge, which for a process without
            // shared writable sections equals its private bytes.
            private_bytes: counters.PagefileUsage as u64,
        })
    }
}

/// One-shot working-set trim: releases every resident page to the standby
/// list. Pages fault back in on first touch as SOFT faults (no disk I/O while
/// memory is uncontended), so the cost is a one-time ~0.2 ms/MB re-touch
/// spread over the first queries; the benefit is that the process's visible
/// memory (Task Manager's default column) drops to what queries actually
/// touch instead of the bootstrap peak.
///
/// Call ONCE per phase transition (after bootstrap / a full rescan), never
/// periodically: habitual trimming evicts hot pages and manufactures paging
/// storms.
pub fn trim_working_set() -> Result<(), WinError> {
    // SAFETY: plain Win32 FFI with the current-process pseudo-handle.
    unsafe {
        if K32EmptyWorkingSet(GetCurrentProcess()) == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "K32EmptyWorkingSet",
            });
        }
    }
    Ok(())
}

/// Pins the process's CURRENT resident set as a hard minimum so Windows will not
/// trim the index out of RAM under memory pressure. The maximum is explicitly
/// DISABLED: the index only grows from here (the journal tail adds entries, and
/// a rescan builds a second index alongside the live one before swapping), so a
/// hard ceiling would force the memory manager to page out the very pages this
/// call exists to keep resident.
///
/// Best-effort and privilege-free: call once after bootstrap. A failure is
/// non-fatal: the index still works, it just becomes trimmable again. Setting
/// a large hard minimum can be refused (`ERROR_INVALID_PARAMETER`) when it
/// exceeds the system's default working-set ceiling, so the caller logs quietly.
pub fn pin_working_set() -> Result<(), WinError> {
    // SAFETY: all three calls are plain Win32 FFI with a valid pseudo-handle
    // (GetCurrentProcess) and a stack struct sized by its own `cb` field.
    unsafe {
        let process = GetCurrentProcess();

        let mut counters: PROCESS_MEMORY_COUNTERS = zeroed();
        counters.cb = size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(process, &mut counters, counters.cb) == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "GetProcessMemoryInfo",
            });
        }

        let floor = counters.WorkingSetSize;
        // `dwMaximumWorkingSetSize` must still be greater than the minimum for
        // the call to be accepted (equal is rejected with
        // ERROR_INVALID_PARAMETER), but MAX_DISABLE means it is never enforced:
        // it is an argument the API requires, not a ceiling on the index.
        let ceiling = floor.saturating_mul(2);
        let flags = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;
        if SetProcessWorkingSetSizeEx(process, floor, ceiling, flags) == 0 {
            return Err(WinError {
                code: GetLastError(),
                context: "SetProcessWorkingSetSizeEx",
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::System::Memory::GetProcessWorkingSetSizeEx;

    /// The flags are the whole point of this module, and the call succeeds with
    /// either spelling, so nothing but the flags themselves can catch a
    /// regression here. MAX_ENABLE would cap the working set at 2x bootstrap RSS
    /// and force Windows to page out the index this module exists to pin.
    #[test]
    fn maximum_is_disabled_so_the_index_is_never_capped() {
        const MAX_ENABLE: u32 = 0x0000_0004;
        assert_eq!(
            QUOTA_LIMITS_HARDWS_MAX_DISABLE & MAX_ENABLE,
            0,
            "a hard maximum must never be enabled: it would evict the index"
        );

        pin_working_set().expect("pinning the working set must succeed");

        let mut min = 0usize;
        let mut max = 0usize;
        let mut flags = 0u32;
        // SAFETY: plain Win32 FFI with the current-process pseudo-handle and
        // three live stack out-params.
        let ok = unsafe {
            GetProcessWorkingSetSizeEx(GetCurrentProcess(), &mut min, &mut max, &mut flags)
        };
        assert_ne!(ok, 0, "GetProcessWorkingSetSizeEx failed");
        assert_ne!(
            flags & QUOTA_LIMITS_HARDWS_MIN_ENABLE,
            0,
            "the hard minimum must be in force, or the index is trimmable"
        );
        assert_eq!(
            flags & MAX_ENABLE,
            0,
            "the OS reports a hard maximum in force; it will page the index out"
        );
    }
}
