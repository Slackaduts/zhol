//! Memory helpers: protection changes, readiness waiting, allocation, and the
//! fixed-size C-string helper. All OS access goes through [`crate::platform`].

#[cfg(not(unix))]
use std::thread::park_timeout;
use std::time::{Duration, Instant};

use bytemuck::{Pod, Zeroable};

use crate::memory::MemoryRegion;
use crate::platform::{self, Protect};
use crate::process::SafeHandle;
use crate::memory::transmute::AutoImplTransmutable;
use crate::{MemOpError, MemOpResult};

/// Change the protection of `[addr, addr+size)`, returning the previous value so
/// it can be restored. A no-op on Unix (writes bypass page protection).
pub fn change_memory_protection(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
    protection: Protect,
) -> MemOpResult<Protect> {
    platform::protect(handle, addr, size, timeout, protection)
}

/// Block until `[address]` is in a state safe for the requested access, or the
/// timeout elapses. Uses the platform region query.
pub fn wait_for_safe_mem(
    handle: &SafeHandle,
    address: usize,
    timeout: Option<Duration>,
    needs_write: bool,
) -> MemOpResult<()> {
    let deadline = timeout.map(|t| Instant::now() + t);
    loop {
        let region = platform::query_region(handle, address, timeout)?;
        let ok = region.committed
            && !region.guarded
            && region.readable
            && (!needs_write || region.writable);
        if ok {
            return Ok(());
        }
        // On the Unix `/proc` backend a region's readiness is static for our
        // purposes: we do not drive the target's allocation, so parking here
        // cannot make an unmapped page appear. Worse, a caller that dereferences
        // a stale/NULL game pointer (e.g. a poller reading a not-yet-hooked
        // client) would otherwise block the full timeout on every such read,
        // starving a single-threaded event loop. Fail fast instead of parking;
        // the caller's own retry loop (with its own delay) handles transients.
        #[cfg(unix)]
        {
            let _ = deadline;
            return Err(MemOpError::Message(format!(
                "memory at {address:#x} not {}",
                if needs_write { "writable" } else { "readable" }
            )));
        }
        #[cfg(not(unix))]
        match deadline {
            Some(d) => {
                let now = Instant::now();
                if now >= d {
                    return Err(MemOpError::Message(format!(
                        "memory at {address:#x} not {} before timeout",
                        if needs_write { "writable" } else { "readable" }
                    )));
                }
                park_timeout(d - now);
            }
            None => {
                return Err(MemOpError::Message(format!(
                    "memory at {address:#x} not {}",
                    if needs_write { "writable" } else { "readable" }
                )))
            }
        }
    }
}

/// Allocate `size` bytes of scratch memory in the target. On Unix this is not
/// yet available (see the backend); the error says so.
pub fn allocate_memory(handle: &SafeHandle, size: usize) -> MemOpResult<MemoryRegion> {
    let addr = platform::alloc(handle, size)?;
    Ok(MemoryRegion {
        handle: handle.clone(),
        addr,
        size,
    })
}

/// The last OS error as a [`MemOpError`].
pub fn get_last_error() -> MemOpError {
    platform::last_error()
}

#[repr(C)]
#[derive(Copy, Clone, Pod, Zeroable)]
pub struct CStr256 {
    data: [u8; 256],
}
impl AutoImplTransmutable for CStr256 {}

impl CStr256 {
    pub fn as_str(&self) -> &str {
        let end = self
            .data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.data.len());
        std::str::from_utf8(&self.data[..end]).unwrap_or("")
    }
    pub fn try_from_str(s: &str) -> Result<Self, MemOpError> {
        let bytes = s.as_bytes();
        if bytes.len() > 255 {
            return Err(MemOpError::Message(format!("string too long for CStr256")));
        }
        let mut data = [0u8; 256];
        data[..bytes.len()].copy_from_slice(bytes);
        Ok(CStr256 { data })
    }
}

impl From<&str> for CStr256 {
    fn from(s: &str) -> Self {
        let mut data = [0u8; 256];
        let bytes = s.as_bytes();
        let len = bytes.len().min(255);
        data[..len].copy_from_slice(&bytes[..len]);
        CStr256 { data }
    }
}

impl std::fmt::Display for CStr256 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
