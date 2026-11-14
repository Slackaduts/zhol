//! Reads from target memory, via the platform backend.

use std::any::type_name;
use std::time::Duration;

use anyhow::anyhow;

use crate::hooks::ZholHook;
use crate::memory::utils::wait_for_safe_mem;
use crate::platform;
use crate::process::SafeHandle;
use crate::MemOpResult;

use super::transmute::ZholTyped;
use super::MemOpContext;

/// Read `size` raw bytes from `addr`.
pub fn read_bytes(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Vec<u8>> {
    // Best-effort readiness wait; the platform read itself is authoritative and
    // (on Unix) tolerates holes within the range.
    let _ = wait_for_safe_mem(handle, addr, timeout, false);
    platform::read_mem(handle, addr, size, timeout)
}

pub fn read_value<T: ZholTyped<T>>(
    hook: &ZholHook,
    address: usize,
    timeout: Option<Duration>,
) -> MemOpResult<T> {
    let size = std::mem::size_of::<T>();
    let raw_buffer: Vec<u8> = read_bytes(&hook.handle(), address, size, timeout)?;
    let context = MemOpContext::new(address, 0x0, false, timeout);

    let value = match T::transmute_from(&raw_buffer, hook, &context)? {
        Some(a) => a,
        None => {
            return Err(anyhow!(
                "No data from type \"{}\" while reading from \"{address}\"",
                type_name::<T>()
            )
            .into())
        }
    };

    Ok(value)
}

/// Top-level read: resolves the hook's var pointer, then reads `T` at `+offset`.
pub fn read<T: ZholTyped<T>>(hook: &ZholHook, context: &MemOpContext) -> MemOpResult<T> {
    let data = hook.data().read();
    let ptr: usize = match context.at_pointer {
        true => read_value::<i32>(hook, data.var_mem.addr, context.timeout)? as usize,
        false => data.var_mem.addr,
    };
    drop(data);

    read_value::<T>(hook, ptr + context.offset, context.timeout)
}

/// Read a KingsIsle-style wide string (length at +0x10, inline or heap pointer).
pub fn read_wide_string(hook: &ZholHook, address: usize) -> String {
    let len: i32 = read_value::<i32>(hook, address + 16, Some(Duration::from_secs(5))).unwrap();
    if len == 0 {
        return String::new();
    }
    let byte_len = len as usize * 2;

    let string_address = if byte_len >= 8 {
        let ptr: u32 = read_value::<u32>(hook, address, Some(Duration::from_secs(5))).unwrap();
        ptr as usize
    } else {
        address
    };

    let raw = read_bytes(
        &hook.handle(),
        string_address,
        byte_len,
        Some(Duration::from_secs(5)),
    )
    .unwrap();
    let utf16: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    String::from_utf16(&utf16).unwrap()
}
