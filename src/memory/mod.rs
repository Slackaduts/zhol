#[cfg(feature = "async")]
pub mod async_ext;
pub mod read;
pub mod transmute;
pub mod utils;
pub mod write;

use crate::error::IntoMemOpResult;
use crate::memory::utils::allocate_memory;
use core::ffi::c_void;

use crate::process::SafeHandle;
use crate::{with_handle, MemOpResult};

use std::time::Duration;

use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use windows::Win32::System::Memory::{VirtualFree, MEM_RELEASE};

pub type Byte = Option<u8>;

/// Manages a region of memory allocated in a remote process.
/// The memory is automatically freed when the `MemoryRegion` is dropped.
#[derive(Clone)]
pub struct MemoryRegion {
    pub handle: SafeHandle,
    pub addr: usize,
    pub size: usize,
}

impl MemoryRegion {
    pub fn new(handle: SafeHandle, size: usize) -> MemOpResult<Self> {
        allocate_memory(&handle, size)
    }

    /// Zeroes out the memory region. Useful for "resetting" memory to the state prior to allocation.
    pub fn zero(&self) -> MemOpResult<()> {
        let buffer = vec![0u8; self.size]; // Create a buffer of zeros with the desired size
        let mut bytes_written = 0;

        with_handle!(&self.handle, Some(Duration::from_secs(1)), |guard| -> (), {
            unsafe {
                WriteProcessMemory(
                    *guard,
                    self.addr as *mut c_void,
                    buffer.as_ptr() as *const _,
                    self.size,
                    Some(&mut bytes_written),
                ).into_memop_result(Some(anyhow::anyhow!("WriteProcessMemory in MemoryRegion::zero()")))?;
            };

            Ok(())
        })?;

        Ok(())
    }
}

unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        _ = unsafe { VirtualFree(self.addr as *mut c_void, self.size, MEM_RELEASE) };
    }
}

/// Context for memory operations.
/// 
/// This struct is used to encapsulate the parameters needed for various memory operations.
pub struct MemOpContext {
    pub addr: usize,
    pub offset: usize,
    pub at_pointer: bool,
    pub timeout: Option<Duration>,
}

impl MemOpContext {
    pub fn new(addr: usize, offset: usize, at_pointer: bool, timeout: Option<Duration>) -> Self {
        MemOpContext {
            addr,
            offset,
            at_pointer,
            timeout,
        }
    }
}


/// Top-level read function.
///
/// Use this for reading values directly out of memory.
/// Value must implement bytemuck::Pod.
pub fn read<T: crate::memory::transmute::ZholTyped<T>>(hook: &crate::hooks::ZholHook, context: &MemOpContext) -> MemOpResult<T> {
    let data = hook.data().read();
    let var_mem_addr = crate::hooks::get_var_mem_addr(&data)?;
    let ptr: usize = match context.at_pointer {
        true => crate::memory::read::read_value::<i32>(&hook, var_mem_addr, context.timeout)? as usize,
        false => var_mem_addr,
    };
    drop(data);

    crate::memory::read::read_value::<T>(&hook, ptr + context.offset, context.timeout)
}


/// Top-level write function.
///
/// Use this for writing types directly to memory.
/// Value must implement bytemuck::Pod.
pub fn write<T: crate::memory::transmute::ZholTyped<T>>(
    hook: &crate::hooks::ZholHook,
    value: T,
    context: &MemOpContext,
) -> MemOpResult<()> {
    let data = hook.data().read();
    let var_mem_addr = crate::hooks::get_var_mem_addr(&data)?;
    let ptr: usize = match context.at_pointer {
        true => crate::memory::read::read_value::<i32>(&hook, var_mem_addr, context.timeout)? as usize,
        false => var_mem_addr,
    };

    drop(data);

    crate::memory::write::write_value::<T>(&hook, ptr + context.offset, value, context.timeout)
}