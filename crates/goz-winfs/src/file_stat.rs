//! Read one file's current size + last-write time by its FRN, for the live
//! enricher. USN change records carry neither size nor timestamps, so a file
//! created or modified after bootstrap needs an out-of-band stat to refresh
//! them (otherwise its size stays "unknown", which downstream renders as a
//! directory).

use core::mem::{size_of, zeroed};

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_DESCRIPTOR,
    FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GetFileInformationByHandle, OpenFileById,
};

use crate::error::WinError;
use crate::volume::VolumeHandle;

/// `FILE_ATTRIBUTE_DIRECTORY`, defined locally per this crate's convention.
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
/// `FileIdType`: a 64-bit NTFS file reference number in `FILE_ID_DESCRIPTOR`.
const FILE_ID_TYPE_FILE: i32 = 0;

/// The live size/mtime of one file.
pub struct FileStat {
    pub size: u64,
    /// Last-write time as a Windows `FILETIME` packed into `i64` (100 ns ticks
    /// since 1601), the same representation the FILE_LAYOUT path produces.
    pub mtime_ft: i64,
    pub is_dir: bool,
}

/// Opens the file identified by `frn` on `volume` and reads its size and
/// last-write time. Returns `Ok(None)` when the file cannot be opened (already
/// deleted, or transiently locked): a non-fatal "nothing to refresh", since
/// the structural create/delete was already applied from the journal.
pub fn stat_file(volume: &VolumeHandle, frn: u64) -> Result<Option<FileStat>, WinError> {
    // SAFETY: `desc`/`info` are fully initialized before use; OpenFileById gets
    // the live volume-hint handle; the opened handle is always closed before the
    // block returns. Only the FFI + union access needs unsafe. The size/mtime
    // arithmetic below reads a plain (non-union) struct and stays in safe code.
    let info = unsafe {
        let mut desc: FILE_ID_DESCRIPTOR = zeroed();
        desc.dwSize = size_of::<FILE_ID_DESCRIPTOR>() as u32;
        desc.Type = FILE_ID_TYPE_FILE;
        desc.Anonymous.FileId = frn as i64;

        let handle = OpenFileById(
            volume.as_handle(),
            &desc,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS, // also opens directories
        );
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Ok(None);
        }

        let mut info: BY_HANDLE_FILE_INFORMATION = zeroed();
        let ok = GetFileInformationByHandle(handle, &mut info);
        let last_error = if ok == 0 { GetLastError() } else { 0 };
        CloseHandle(handle);
        if ok == 0 {
            return Err(WinError {
                code: last_error,
                context: "GetFileInformationByHandle",
            });
        }
        info
    };

    let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
    let mtime_ft = ((info.ftLastWriteTime.dwHighDateTime as i64) << 32)
        | info.ftLastWriteTime.dwLowDateTime as i64;
    let is_dir = info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0;
    Ok(Some(FileStat {
        size,
        mtime_ft,
        is_dir,
    }))
}
