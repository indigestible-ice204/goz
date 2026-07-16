//! Process-token queries and privilege adjustment. Everything-class volume and
//! journal access needs `SeBackupPrivilege` + `SeManageVolumePrivilege` on an
//! elevated token, so the daemon calls these at startup and reports failure.

use core::ffi::c_void;
use core::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, LUID,
};
use windows_sys::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW,
    SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::error::{WinError, last_error};
use crate::util::to_wide_nul;

/// True if the current process token is elevated (`TokenElevation`). Any
/// failure to open the token or query it is reported as "not elevated" rather
/// than an error. Callers only ever branch on the boolean.
pub fn is_elevated() -> bool {
    let token = match open_current_process_token(TOKEN_QUERY) {
        Ok(t) => t,
        Err(_) => return false,
    };
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut ret_len: u32 = 0;
    // SAFETY: `token` is a valid token handle; `elevation` is a live
    // TOKEN_ELEVATION sized correctly; `ret_len` is a live out param.
    let ok = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            ptr::from_mut(&mut elevation).cast::<c_void>(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    // SAFETY: `token` was opened above and is owned here; closed exactly once.
    unsafe { CloseHandle(token) };
    ok != 0 && elevation.TokenIsElevated != 0
}

/// Enables `SeBackupPrivilege` and `SeManageVolumePrivilege` on the current
/// process token. Returns `Ok(())` only if both were enabled; a privilege
/// the token does not hold surfaces as `ERROR_NOT_ALL_ASSIGNED`.
pub fn enable_volume_privileges() -> Result<(), WinError> {
    let token = open_current_process_token(TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES)?;
    let result = enable_privilege(token, "SeBackupPrivilege")
        .and_then(|()| enable_privilege(token, "SeManageVolumePrivilege"));
    // SAFETY: `token` is owned here; closed exactly once regardless of outcome.
    unsafe { CloseHandle(token) };
    result
}

fn open_current_process_token(access: u32) -> Result<HANDLE, WinError> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: GetCurrentProcess returns a valid pseudo-handle; `token` is a
    // live out param written on success.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), access, &mut token) };
    if ok == 0 {
        return Err(last_error("OpenProcessToken"));
    }
    Ok(token)
}

fn enable_privilege(token: HANDLE, name: &str) -> Result<(), WinError> {
    let wide = to_wide_nul(name);
    let mut luid = LUID {
        LowPart: 0,
        HighPart: 0,
    };
    // SAFETY: system name is null (local machine); `wide` is a NUL-terminated
    // privilege name; `luid` is a live out param.
    let ok = unsafe { LookupPrivilegeValueW(ptr::null(), wide.as_ptr(), &mut luid) };
    if ok == 0 {
        return Err(last_error("LookupPrivilegeValueW"));
    }

    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: `token` is valid; `privileges` is a live TOKEN_PRIVILEGES holding
    // exactly one entry; no previous-state buffer is requested.
    let ok = unsafe {
        AdjustTokenPrivileges(
            token,
            0,
            ptr::from_ref(&privileges),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(last_error("AdjustTokenPrivileges"));
    }

    // AdjustTokenPrivileges returns TRUE even when it could not enable a
    // privilege (e.g. the token does not hold it); that case is signalled only
    // via GetLastError == ERROR_NOT_ALL_ASSIGNED.
    // SAFETY: GetLastError has no preconditions.
    let gle = unsafe { GetLastError() };
    if gle == ERROR_NOT_ALL_ASSIGNED {
        return Err(WinError {
            code: gle,
            context: "AdjustTokenPrivileges: privilege not held",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_elevated;

    #[test]
    fn is_elevated_returns_without_panicking() {
        let _elevated: bool = is_elevated();
    }
}
