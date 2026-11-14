//! Module discovery, delegated to the platform backend.
//!
//! Returns the neutral [`Module`] (name / base / size) rather than any
//! OS-specific module handle, so callers are identical on every platform.

use std::time::Duration;

use crate::platform::{self, Module};
use crate::process::SafeHandle;
use crate::MemOpResult;

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
