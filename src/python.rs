//! Python bindings (feature `python`): a minimal `Process` class exposing the
//! cross-platform memory surface so Python code — notably a `pymem`-compatible
//! shim driving wizwalker — can read, write, scan, and allocate in a target
//! through zhol's backend. Built as a native extension; on Linux this reaches a
//! Proton-hosted Windows game via `/proc`.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::time::Duration;

use crate::memory::read::read_bytes as zread;
use crate::memory::utils::allocate_memory;
use crate::memory::write::write_bytes as zwrite;
use crate::platform;
use crate::process::module::module_by_name;
use crate::process::pattern::pattern_scan as zscan;
use crate::process::SafeHandle;
use crate::MemOpError;

fn err(e: MemOpError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn ae(e: anyhow::Error) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

const T: Option<Duration> = Some(Duration::from_secs(5));

/// A handle to a target process, opened by pid.
#[pyclass]
pub struct Process {
    handle: SafeHandle,
    #[pyo3(get)]
    pid: u32,
}

#[pymethods]
impl Process {
    /// Open a process by pid.
    #[staticmethod]
    fn open(pid: u32) -> PyResult<Self> {
        Ok(Process {
            handle: SafeHandle::from_pid(pid).map_err(err)?,
            pid,
        })
    }

    /// Read `size` bytes from `addr`.
    fn read_bytes<'py>(&self, py: Python<'py>, addr: usize, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let data = zread(&self.handle, addr, size, T).map_err(err)?;
        Ok(PyBytes::new_bound(py, &data))
    }

    /// Write `data` to `addr`.
    fn write_bytes(&self, addr: usize, data: &[u8]) -> PyResult<()> {
        zwrite(&self.handle, addr, data, T).map_err(err)
    }

    /// Resolve a module by name to `(base, size)`, or `None`.
    fn module(&self, name: &str) -> PyResult<Option<(usize, usize)>> {
        Ok(module_by_name(&self.handle, name, true, T)
            .map_err(err)?
            .map(|m| (m.base, m.size)))
    }

    /// All modules as `[(name, base, size), ...]`.
    fn modules(&self) -> PyResult<Vec<(String, usize, usize)>> {
        let mods = platform::enum_modules(&self.handle, T).map_err(err)?;
        Ok(mods.into_iter().map(|m| (m.name, m.base, m.size)).collect())
    }

    /// Query the region containing `addr`:
    /// `(base, size, readable, writable, executable, committed)`.
    fn query(&self, addr: usize) -> PyResult<(usize, usize, bool, bool, bool, bool)> {
        let r = platform::query_region(&self.handle, addr, T).map_err(err)?;
        Ok((r.base, r.size, r.readable, r.writable, r.executable, r.committed))
    }

    /// IDA-style pattern scan over `[start, start+size)`; returns match offsets
    /// relative to `start`.
    fn pattern_scan(&self, pattern: &str, start: usize, size: usize) -> PyResult<Vec<usize>> {
        let hits = zscan(&self.handle, pattern, start, size).map_err(ae)?;
        Ok(hits.into_iter().map(|(off, _)| off).collect())
    }

    /// Allocate `size` bytes of scratch; returns the address.
    fn allocate(&self, size: usize) -> PyResult<usize> {
        let region = allocate_memory(&self.handle, size).map_err(err)?;
        let addr = region.addr;
        // Hand the raw address to Python; don't let Drop free it (no-op on Unix
        // anyway, and callers manage hook lifetime explicitly).
        std::mem::forget(region);
        Ok(addr)
    }

    /// Register an explicit code-cave arena (e.g. wizwalker's autobot).
    fn register_cave(&self, start: usize, size: usize) -> PyResult<()> {
        platform::register_cave(&self.handle, start, size).map_err(err)
    }
}

#[pymodule]
fn zhol(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Process>()?;
    Ok(())
}
