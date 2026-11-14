#[cfg(feature = "async")]
pub mod async_ext;
pub mod read;
pub mod transmute;
pub mod utils;
pub mod write;

use std::time::Duration;

use crate::memory::utils::allocate_memory;
use crate::platform;
use crate::process::SafeHandle;
use crate::MemOpResult;

pub type Byte = Option<u8>;

/// A region of scratch memory allocated in the target. Freed on drop.
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

    /// Zero the region (reset to a clean state).
    pub fn zero(&self) -> MemOpResult<()> {
        let buffer = vec![0u8; self.size];
        platform::write_mem(&self.handle, self.addr, &buffer, Some(Duration::from_secs(1)))?;
        Ok(())
    }
}

unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}

impl Drop for MemoryRegion {
    fn drop(&mut self) {
        let _ = platform::free(&self.handle, self.addr, self.size);
    }
}

/// Parameters for a memory operation originating from a hook's var memory.
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

/// Top-level read: resolves the hook's var pointer, then reads `T` at `+offset`.
pub fn read<T: crate::memory::transmute::ZholTyped<T>>(
    hook: &crate::hooks::ZholHook,
    context: &MemOpContext,
) -> MemOpResult<T> {
    let data = hook.data().read();
    let ptr: usize = match context.at_pointer {
        true => {
            crate::memory::read::read_value::<i32>(hook, data.var_mem.addr, context.timeout)?
                as usize
        }
        false => data.var_mem.addr,
    };
    drop(data);

    crate::memory::read::read_value::<T>(hook, ptr + context.offset, context.timeout)
}

/// Top-level write: resolves the hook's var pointer, then writes `T` at `+offset`.
pub fn write<T: crate::memory::transmute::ZholTyped<T>>(
    hook: &crate::hooks::ZholHook,
    value: T,
    context: &MemOpContext,
) -> MemOpResult<()> {
    let data = hook.data().read();
    let ptr: usize = match context.at_pointer {
        true => {
            crate::memory::read::read_value::<i32>(hook, data.var_mem.addr, context.timeout)?
                as usize
        }
        false => data.var_mem.addr,
    };
    drop(data);

    crate::memory::write::write_value::<T>(hook, ptr + context.offset, value, context.timeout)
}
