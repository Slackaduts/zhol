use crate::error::IntoMemOpResult;
use crate::hooks::ZholHook;
use crate::memory::utils::wait_for_safe_mem;
use crate::process::SafeHandle;
use crate::with_handle;
use crate::MemOpResult;

use anyhow::anyhow;
use std::time::Duration;
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;

use super::transmute::ZholTyped;
use super::MemOpContext;

use std::any::type_name;

pub fn read_bytes(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let mut bytes_read = 0;

    wait_for_safe_mem(&handle.clone(), addr, timeout, false)?;
    with_handle!(&handle.clone(), timeout, |guard| -> (), {
        unsafe {
            ReadProcessMemory(
                *guard,
                addr as *const _,
                buffer.as_mut_ptr() as *mut _,
                size,
                Some(&mut bytes_read),
            ).into_memop_result(Some(anyhow!("ReadProcessMemory in read_bytes()")))?;

            std::thread::sleep(Duration::from_nanos(1));

            Ok(())
        }
    })?;

    wait_for_safe_mem(&handle.clone(), addr, timeout, false)?;

    buffer.truncate(bytes_read);

    Ok(buffer)
}

pub fn read_value<T: ZholTyped<T>>(
    hook: &ZholHook,
    address: usize,
    timeout: Option<Duration>,
) -> MemOpResult<T> {
    // Calculate size needed for the type
    let size = std::mem::size_of::<T>();
    let raw_buffer: Vec<u8> = read_bytes(&hook.handle(), address, size, timeout)?;

    let context = MemOpContext::new(address, 0x0, false, timeout);

    // let value = T::transmute_from(&raw_buffer)?;
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

/// Top-level read function.
///
/// Use this for reading values directly out of game memory.
/// Value must implement bytemuck::Pod.
pub fn read<T: ZholTyped<T>>(hook: &ZholHook, context: &MemOpContext) -> MemOpResult<T> {
    let data = hook.data().read();
    let var_mem_addr = crate::hooks::get_var_mem_addr(&data)?;
    let ptr: usize = match context.at_pointer {
        true => read_value::<i32>(&hook, var_mem_addr, context.timeout)? as usize,
        false => var_mem_addr,
    };
    drop(data);

    read_value::<T>(&hook, ptr + context.offset, context.timeout)
}

pub fn read_wide_string(hook: &ZholHook, address: usize) -> String {
    // Length (UTF-16 code units) is at +0x10
    let len: i32 = read_value::<i32>(hook, address + 16, Some(Duration::from_secs(5))).unwrap();
    if len == 0 {
        return String::new();
    }
    let byte_len = len as usize * 2;

    // Inline vs heap-pointer distinction
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
    // Convert little-endian UTF-16 → Rust String
    let utf16: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();

    String::from_utf16(&utf16).unwrap()
}
