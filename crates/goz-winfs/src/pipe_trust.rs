//! Client-side verification that the process serving a named pipe is a trusted
//! (elevated) goz daemon, not a squatter.
//!
//! A local, unelevated user can pre-create `\\.\pipe\goz-v1` before the elevated
//! daemon starts (the daemon's `FIRST_PIPE_INSTANCE` create then fails) and
//! serve spoofed results to the client while learning its queries and scope
//! paths. The daemon's own pipe object is created by an elevated or SYSTEM
//! token, so its OWNER SID is Local System or the built-in Administrators group;
//! a non-elevated squatter's pipe is owned by the plain interactive-user SID.
//! The client reads the server pipe's owner SID and requires it to be one of the
//! trusted well-known SIDs before sending any request, unless the user opts out
//! with `--insecure-no-server-check`.
//!
//! This lives in `goz-winfs` (the designated unsafe Win32 layer) rather than in
//! the client so the raw FFI stays out of `goz-cli`.

use core::ffi::c_void;
use core::ptr;
use std::os::windows::io::{AsRawHandle, BorrowedHandle};

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows_sys::Win32::Security::{
    CreateWellKnownSid, EqualSid, OWNER_SECURITY_INFORMATION, WELL_KNOWN_SID_TYPE,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;

use crate::error::{WinError, last_error};

/// Maximum size of a SID, in bytes (`SECURITY_MAX_SID_SIZE`).
const MAX_SID_SIZE: usize = 68;

/// The well-known owners a legitimately-elevated daemon pipe can have.
const TRUSTED_OWNERS: [WELL_KNOWN_SID_TYPE; 2] = [WinLocalSystemSid, WinBuiltinAdministratorsSid];

/// Returns `Ok(true)` if the pipe referenced by `handle` is owned by Local
/// System or the built-in Administrators group: it was created by an
/// elevated/SYSTEM process (the daemon) rather than by an unprivileged squatter.
/// Returns `Ok(false)` for any other owner.
///
/// The caller must have opened the pipe with `READ_CONTROL` (implied by
/// `GENERIC_READ`) for the owner query to succeed. Taking a [`BorrowedHandle`]
/// keeps the handle valid for the duration of the call.
///
/// # Errors
/// Returns [`WinError`] if the owner SID cannot be read (`GetSecurityInfo`) or a
/// reference well-known SID cannot be constructed (`CreateWellKnownSid`). Fail
/// closed: callers should treat an error as "not trusted".
pub fn pipe_server_is_trusted(handle: BorrowedHandle<'_>) -> Result<bool, WinError> {
    let mut owner: *mut c_void = ptr::null_mut();
    let mut security_descriptor: *mut c_void = ptr::null_mut();

    // SAFETY: `handle` is a live, borrowed pipe handle valid for this call. On
    // success GetSecurityInfo sets `owner` (a pointer into the returned
    // self-relative security descriptor) and `security_descriptor` (LocalAlloc'd,
    // freed below). On failure it returns a non-zero Win32 code and sets neither.
    let rc = unsafe {
        GetSecurityInfo(
            handle.as_raw_handle(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut security_descriptor,
        )
    };
    if rc != 0 {
        return Err(WinError {
            code: rc,
            context: "GetSecurityInfo",
        });
    }

    // `owner` aliases into `security_descriptor`, so evaluate trust before the
    // free, then free exactly once. Never free `owner` separately.
    let verdict = if owner.is_null() {
        Ok(false)
    } else {
        owner_is_trusted(owner)
    };

    if !security_descriptor.is_null() {
        // SAFETY: `security_descriptor` was allocated by GetSecurityInfo, which
        // documents LocalFree as the matching deallocator.
        unsafe {
            LocalFree(security_descriptor);
        }
    }

    verdict
}

/// Returns the number of bytes currently available to read from the pipe
/// `handle` without blocking. The blocking client polls this so a wedged
/// (accepted-but-never-replying) daemon can't hang it past its read deadline.
///
/// # Errors
/// Returns [`WinError`] if the peek fails (e.g. the pipe was closed / broken).
pub fn pipe_bytes_available(handle: BorrowedHandle<'_>) -> Result<u32, WinError> {
    let mut avail: u32 = 0;
    // SAFETY: `handle` is a live borrowed pipe handle valid for this call. Every
    // out-pointer except `avail` (a live local) is null, which PeekNamedPipe
    // documents as "not wanted"; it reads no data (buffer null, size 0) and only
    // reports the available byte count.
    let ok = unsafe {
        PeekNamedPipe(
            handle.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut avail,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error("PeekNamedPipe"));
    }
    Ok(avail)
}

/// Is `owner` equal to any of the [`TRUSTED_OWNERS`] well-known SIDs?
fn owner_is_trusted(owner: *mut c_void) -> Result<bool, WinError> {
    for &kind in &TRUSTED_OWNERS {
        let mut sid = [0u8; MAX_SID_SIZE];
        let mut len = MAX_SID_SIZE as u32;
        // SAFETY: `sid` is a MAX_SID_SIZE buffer and `len` names its capacity;
        // CreateWellKnownSid writes at most `len` bytes and updates `len`. These
        // well-known SIDs need no domain SID (null).
        let ok =
            unsafe { CreateWellKnownSid(kind, ptr::null_mut(), sid.as_mut_ptr().cast(), &mut len) };
        if ok == 0 {
            return Err(last_error("CreateWellKnownSid"));
        }
        // SAFETY: both arguments are valid SIDs: `owner` from GetSecurityInfo
        // and `sid` just constructed. EqualSid only reads them.
        let equal = unsafe { EqualSid(owner, sid.as_mut_ptr().cast()) };
        if equal != 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elevation::is_elevated;
    use crate::pipe_sd::build_pipe_security;
    use crate::util::to_wide_nul;
    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    /// The trust verdict must track the elevation of the token that CREATED the
    /// pipe, which is the entire premise of the check: the daemon's SDDL sets a
    /// DACL and no owner, so the owner always comes from the creating token.
    ///
    /// This asserts both directions depending on where it runs, and neither is
    /// ambient: unelevated (a developer box) proves a squatter is rejected even
    /// when it copies the daemon's exact DACL, and elevated (an admin shell, and
    /// the GitHub windows runner) proves the real daemon is accepted. A check
    /// that only ever fails closed would pass a reject-only test while making
    /// the product unusable.
    #[test]
    fn trust_verdict_tracks_the_creating_token() {
        // The daemon's real security attributes, so a pass cannot be an artifact
        // of a permissive default DACL.
        let security = build_pipe_security().expect("goz pipe SDDL must parse");
        let name = format!(r"\\.\pipe\goz-trust-test-{}", std::process::id());
        let wide = to_wide_nul(&name);

        // SAFETY: `wide` is a NUL-terminated pipe name and `security` outlives
        // the call; the attributes pointer is only read by the pipe server.
        let server: HANDLE = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                security.attributes_ptr() as *const SECURITY_ATTRIBUTES,
            )
        };
        assert_ne!(server, INVALID_HANDLE_VALUE, "CreateNamedPipeW failed");

        // GENERIC_READ implies READ_CONTROL, which the owner query needs. This
        // is the same open the client performs against a live daemon.
        // SAFETY: `wide` names the pipe just created; every optional pointer is
        // null, which CreateFileW documents as "not wanted".
        let client: HANDLE = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null_mut(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        assert_ne!(client, INVALID_HANDLE_VALUE, "CreateFileW on our own pipe");

        // SAFETY: `client` is a live handle we own and do not close until below.
        let borrowed = unsafe { std::os::windows::io::BorrowedHandle::borrow_raw(client) };
        let verdict = pipe_server_is_trusted(borrowed);

        // SAFETY: both handles are live and owned by this test; closed once.
        unsafe {
            CloseHandle(client);
            CloseHandle(server);
        }

        let trusted = verdict.expect("owner query on our own pipe must succeed");
        let elevated = is_elevated();

        // Printed so a `--nocapture` run states which direction it actually
        // exercised. Both functions are under test here, so a bare `trusted ==
        // elevated` pass could otherwise hide the case where both are wrong the
        // same way.
        println!("pipe trust runtime check: elevated={elevated} trusted={trusted}");

        assert_eq!(
            trusted,
            elevated,
            "a pipe created by an {} token was judged trusted={trusted}; the owner \
             check must accept exactly the elevated case",
            if elevated { "ELEVATED" } else { "UNELEVATED" }
        );
    }
}
