//! Module discovery, delegated to the platform backend.
//!
//! Returns the neutral [`Module`] (name / base / size) rather than any
//! OS-specific module handle, so callers are identical on every platform.

use std::time::Duration;

use crate::memory::read::read_bytes;
use crate::platform::{self, Module};
use crate::process::SafeHandle;
use crate::{MemOpError, MemOpResult};

/// All file-backed modules loaded in the target process.
pub fn get_named_modules(
    handle: &SafeHandle,
    timeout: Option<Duration>,
) -> MemOpResult<Vec<Module>> {
    platform::enum_modules(handle, timeout)
}

/// Find a module by name. When `stem` is true (the usual case), the match is on
/// the file-name alone; backends already report the file-name, so a non-stem
/// match simply compares the same value.
pub fn module_by_name(
    handle: &SafeHandle,
    name: &str,
    _stem: bool,
    timeout: Option<Duration>,
) -> MemOpResult<Option<Module>> {
    let modules = get_named_modules(handle, timeout)?;
    Ok(modules
        .into_iter()
        .find(|m| m.name.eq_ignore_ascii_case(name)))
}

fn rd_u32(h: &SafeHandle, a: usize) -> MemOpResult<u32> {
    let b = read_bytes(h, a, 4, None)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn rd_u64(h: &SafeHandle, a: usize) -> MemOpResult<u64> {
    let b = read_bytes(h, a, 8, None)?;
    Ok(u64::from_le_bytes(b[..8].try_into().unwrap()))
}

/// Resolve the IAT slot address for import `want` in the PE mapped at `base`, by
/// walking the import directory. The slot holds the resolved function pointer;
/// overwriting it redirects every call through that import. Returns `None` if the
/// import isn't present. (A pointer-redirect hook point — the Rosetta-safe way to
/// hook on macOS, and usable anywhere.)
pub fn find_import_slot(
    handle: &SafeHandle,
    base: usize,
    want: &str,
) -> MemOpResult<Option<usize>> {
    let h = handle;
    let lfanew = rd_u32(h, base + 0x3C)? as usize;
    if &read_bytes(h, base + lfanew, 4, None)?[..] != b"PE\0\0" {
        return Err(MemOpError::Message("module is not a PE".into()));
    }
    // PE32+ optional header at +24; DataDirectory at optional+112; imports = idx 1.
    let import_rva = rd_u32(h, base + lfanew + 24 + 112 + 8)? as usize;
    if import_rva == 0 {
        return Ok(None);
    }
    let mut desc = base + import_rva;
    // Cap the descriptor walk defensively.
    for _ in 0..4096 {
        let oft = rd_u32(h, desc)? as usize;
        let name_rva = rd_u32(h, desc + 12)? as usize;
        let ft = rd_u32(h, desc + 16)? as usize;
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        if oft != 0 {
            let mut i = 0usize;
            loop {
                let ent = rd_u64(h, base + oft + i * 8)?;
                if ent == 0 {
                    break;
                }
                // Skip import-by-ordinal (high bit set); match import-by-name.
                if ent & (1 << 63) == 0 {
                    let name_addr = base + (ent as u32 & 0x7FFF_FFFF) as usize + 2;
                    let nb = read_bytes(h, name_addr, 64, None)?;
                    let end = nb.iter().position(|&c| c == 0).unwrap_or(nb.len());
                    if nb[..end].eq_ignore_ascii_case(want.as_bytes()) {
                        return Ok(Some(base + ft + i * 8));
                    }
                }
                i += 1;
                if i > 65536 {
                    break;
                }
            }
        }
        desc += 20;
    }
    Ok(None)
}
