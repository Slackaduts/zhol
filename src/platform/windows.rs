//! Windows backend: process memory through the Win32 API.
//!
//! This preserves zhol's original behaviour; the OS calls are the same ones the
//! crate used before the platform split, only relocated behind the neutral
//! [`super`] surface and returning the neutral [`Module`]/[`Region`]/[`Protect`]
//! types instead of raw Win32 structs.

use std::time::Duration;

use anyhow::anyhow;
use windows::core::PWSTR;
use windows::Win32::Foundation::{GetLastError, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageW, ReadProcessMemory, WriteProcessMemory, FORMAT_MESSAGE_ALLOCATE_BUFFER,
    FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::Memory::{
    VirtualAllocEx, VirtualFreeEx, VirtualProtectEx, VirtualQueryEx, MEMORY_BASIC_INFORMATION,
    MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE, PAGE_GUARD,
    PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, GetModuleFileNameExA, GetModuleInformation, MODULEINFO,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ,
    PROCESS_VM_WRITE,
};

use super::{Module, Protect, Region};
use crate::process::SafeHandle;
use crate::{MemOpError, MemOpResult};

/// Per-process handle: a Win32 process `HANDLE`.
pub struct Target {
    pub handle: HANDLE,
}

unsafe impl Send for Target {}
unsafe impl Sync for Target {}

impl Target {
    /// Wrap an already-open process handle (the classic zhol entry point).
    pub fn from_handle(handle: HANDLE) -> Self {
        Target { handle }
    }
}

/// Open a target by pid with the access rights memory work needs.
pub fn open(pid: u32) -> MemOpResult<Target> {
    let handle = unsafe {
        OpenProcess(
            PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_VM_OPERATION
                | PROCESS_QUERY_INFORMATION,
            false,
            pid,
        )
    }
    .map_err(|e| MemOpError::Os((format!("OpenProcess({pid}): {e}"), None)))?;
    Ok(Target { handle })
}

pub fn last_error() -> MemOpError {
    unsafe {
        let code = GetLastError();
        let buffer = PWSTR::null();
        let n = FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            code.0,
            0,
            buffer,
            0,
            None,
        );
        let msg = if n > 0 && !buffer.is_null() {
            buffer.to_string().unwrap_or_default()
        } else {
            String::new()
        };
        MemOpError::Os((format!("Windows error {:08X}: {}", code.0, msg), None))
    }
}

fn acquire<'a>(
    handle: &'a SafeHandle,
    timeout: Option<Duration>,
) -> MemOpResult<crate::process::SafeHandleGuard<'a>> {
    handle
        .acquire_with_timeout(timeout)
        .ok_or(MemOpError::TimeoutReached((timeout, None)))
}

pub fn read_mem(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Vec<u8>> {
    let guard = acquire(handle, timeout)?;
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0usize;
    unsafe {
        ReadProcessMemory(
            guard.handle,
            addr as *const _,
            buffer.as_mut_ptr() as *mut _,
            size,
            Some(&mut bytes_read),
        )
        .map_err(|e| MemOpError::Os((format!("ReadProcessMemory @ {addr:#x}: {e}"), None)))?;
    }
    buffer.truncate(bytes_read);
    Ok(buffer)
}

pub fn write_mem(
    handle: &SafeHandle,
    addr: usize,
    bytes: &[u8],
    timeout: Option<Duration>,
) -> MemOpResult<usize> {
    let guard = acquire(handle, timeout)?;
    let mut bytes_written = 0usize;
    unsafe {
        WriteProcessMemory(
            guard.handle,
            addr as *mut _,
            bytes.as_ptr() as *const _,
            bytes.len(),
            Some(&mut bytes_written),
        )
        .map_err(|e| MemOpError::Os((format!("WriteProcessMemory @ {addr:#x}: {e}"), None)))?;
    }
    Ok(bytes_written)
}

fn module_info(handle: HANDLE, module: HMODULE) -> MemOpResult<MODULEINFO> {
    let mut info = MODULEINFO::default();
    unsafe {
        GetModuleInformation(handle, module, &mut info, std::mem::size_of::<MODULEINFO>() as u32)
            .map_err(|e| MemOpError::Os((format!("GetModuleInformation: {e}"), None)))?;
    }
    Ok(info)
}

fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

pub fn enum_modules(handle: &SafeHandle, timeout: Option<Duration>) -> MemOpResult<Vec<Module>> {
    let guard = acquire(handle, timeout)?;
    let h = guard.handle;

    let mut modules = vec![HMODULE::default(); 1024];
    let mut bytes_needed = 0u32;
    unsafe {
        EnumProcessModules(
            h,
            modules.as_mut_ptr(),
            (modules.len() * std::mem::size_of::<HMODULE>()) as u32,
            &mut bytes_needed,
        )
        .map_err(|e| MemOpError::Os((format!("EnumProcessModules: {e}"), None)))?;
        modules.truncate(bytes_needed as usize / std::mem::size_of::<HMODULE>());
    }

    let mut out = Vec::with_capacity(modules.len());
    for &module in &modules {
        let mut name_raw = [0u8; 260];
        let len = unsafe { GetModuleFileNameExA(h, module, &mut name_raw) };
        if len == 0 {
            continue;
        }
        let end = name_raw.iter().position(|&c| c == 0).unwrap_or(len as usize);
        let name = String::from_utf8_lossy(&name_raw[..end]).into_owned();
        let info = module_info(h, module)?;
        out.push(Module {
            name: basename(&name).to_string(),
            base: info.lpBaseOfDll as usize,
            size: info.SizeOfImage as usize,
        });
    }
    Ok(out)
}

pub fn query_region(
    handle: &SafeHandle,
    addr: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Region> {
    let guard = acquire(handle, timeout)?;
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let n = unsafe {
        VirtualQueryEx(
            guard.handle,
            Some(addr as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if n == 0 {
        return Err(last_error());
    }
    let p = mbi.Protect.0;
    let readable = p & 0xEE != 0; // READONLY|READWRITE|WRITECOPY|EXECUTE_READ|_READWRITE|_WRITECOPY
    let writable = p & 0xCC != 0; // READWRITE|WRITECOPY|EXECUTE_READWRITE|EXECUTE_WRITECOPY
    let executable = p & 0xF0 != 0; // EXECUTE|EXECUTE_READ|_READWRITE|_WRITECOPY
    Ok(Region {
        base: mbi.BaseAddress as usize,
        size: mbi.RegionSize,
        readable,
        writable,
        executable,
        committed: mbi.State == MEM_COMMIT,
        guarded: (p & PAGE_GUARD.0) != 0,
    })
}

pub fn alloc(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    let guard = acquire(handle, Some(Duration::from_millis(10)))?;
    let addr = unsafe {
        VirtualAllocEx(
            guard.handle,
            None,
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };
    if addr.is_null() {
        return Err(last_error());
    }
    Ok(addr as usize)
}

pub fn free(handle: &SafeHandle, addr: usize, _size: usize) -> MemOpResult<()> {
    let guard = acquire(handle, Some(Duration::from_millis(10)))?;
    unsafe {
        VirtualFreeEx(guard.handle, addr as *mut _, 0, MEM_RELEASE)
            .map_err(|e| MemOpError::Os((format!("VirtualFreeEx @ {addr:#x}: {e}"), None)))?;
    }
    Ok(())
}

pub fn protect(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
    prot: Protect,
) -> MemOpResult<Protect> {
    let guard = acquire(handle, timeout)?;
    let mut old = PAGE_PROTECTION_FLAGS(0);
    unsafe {
        VirtualProtectEx(
            guard.handle,
            addr as *mut _,
            size,
            PAGE_PROTECTION_FLAGS(prot.0),
            &mut old,
        )
        .map_err(|e| MemOpError::Os((format!("VirtualProtectEx @ {addr:#x}: {e}"), None)))?;
    }
    Ok(Protect(old.0))
}
