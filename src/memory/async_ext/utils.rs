use std::time::Duration;

use crate::platform::Protect;

use crate::process::SafeHandle;
use crate::{await_memop, MemOpResult};

#[cfg(feature = "async")]
pub async fn wait_for_safe_mem(
    handle: &SafeHandle,
    address: usize,
    timeout: Option<std::time::Duration>,
    needs_write: bool,
) -> MemOpResult<()> {
    use crate::await_memop;

    await_memop!(handle, |h| -> MemOpResult<()> {
        crate::memory::utils::wait_for_safe_mem(&h, address, timeout, needs_write)
    })
}

pub async fn change_memory_protection(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
    protection: Protect,
) -> MemOpResult<Protect> {
    await_memop!(handle, |h| -> MemOpResult<Protect> {
        crate::memory::utils::change_memory_protection(&h, addr, size, timeout, protection)
    })
}

pub async fn allocate_memory(
    handle: &SafeHandle,
    size: usize,
) -> MemOpResult<crate::memory::MemoryRegion> {
    await_memop!(handle, |h| -> MemOpResult<crate::memory::MemoryRegion> {
        crate::memory::utils::allocate_memory(&h, size)
    })
}
