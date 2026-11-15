//! Writes to target memory, via the platform backend.

use std::time::Duration;


use crate::hooks::ZholHook;
use crate::memory::utils::{change_memory_protection, wait_for_safe_mem};
use crate::platform::{self, Protect};
use crate::process::SafeHandle;
use crate::MemOpResult;

use super::transmute::ZholTyped;
use super::MemOpContext;

/// Write a byte slice to `addr`. On Windows the page is temporarily made
/// executable-read-write and the original protection restored; on Unix the
/// protection calls are inert and the write goes straight through `/proc`.
pub fn write_bytes(
    handle: &SafeHandle,
    addr: usize,
    bytes: &[u8],
    timeout: Option<Duration>,
) -> MemOpResult<()> {
    let old_protect = change_memory_protection(handle, addr, bytes.len(), timeout, Protect::EXEC_RW)?;

    let _ = wait_for_safe_mem(handle, addr, timeout, true);
    let written = platform::write_mem(handle, addr, bytes, timeout)?;

    change_memory_protection(handle, addr, bytes.len(), timeout, old_protect)?;

    if written != bytes.len() {
        return Err(crate::memop_err!("An error prevented all bytes from being written.").into());
    }

    Ok(())
}

/// Hook-free typed write: write the raw bytes of a Pod `T` at `addr`.
///
/// The counterpart to [`read_pod`](crate::memory::read::read_pod); needs no
/// [`ZholHook`]/[`MemOpContext`], so it is the path for writing a plain scalar at
/// a known absolute address (pymem-style shim, `Process::write_typed`).
pub fn write_pod<T: bytemuck::Pod>(
    handle: &SafeHandle,
    addr: usize,
    value: T,
    timeout: Option<Duration>,
) -> MemOpResult<()> {
    write_bytes(handle, addr, bytemuck::bytes_of(&value), timeout)
}

/// Transmute a value to bytes and write it at `address`.
pub fn write_value<T: ZholTyped<T>>(
    hook: &ZholHook,
    address: usize,
    value: T,
    timeout: Option<Duration>,
) -> MemOpResult<()> {
    let context = MemOpContext::new(address, 0x0, false, timeout);
    let bytes = &value.byte_repr(hook, &context)?;
    write_bytes(&hook.handle(), address, &bytes.to_vec(), timeout)?;
    Ok(())
}
