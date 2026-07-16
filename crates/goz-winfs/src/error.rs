//! The single error type returned across this crate's safe surface.

use windows_sys::Win32::Foundation::GetLastError;

/// A failed Win32 call: the `GetLastError()` code plus a static label naming
/// the operation that failed. Deliberately tiny and `Clone` so it can cross
/// thread boundaries and be logged cheaply.
#[derive(Debug, Clone)]
pub struct WinError {
    pub code: u32,
    pub context: &'static str,
}

impl std::fmt::Display for WinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed: Win32 error {}", self.context, self.code)
    }
}

impl std::error::Error for WinError {}

/// Builds a [`WinError`] from the current thread's `GetLastError()` value.
///
/// Call this immediately after the failed Win32 call, before any other API
/// (including allocation) that could clobber the thread-local error.
pub(crate) fn last_error(context: &'static str) -> WinError {
    // SAFETY: GetLastError takes no arguments and has no preconditions.
    let code = unsafe { GetLastError() };
    WinError { code, context }
}
