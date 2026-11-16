//! Python bindings (feature `python`): a minimal `Process` class exposing the
//! cross-platform memory surface so Python code — notably a `pymem`-compatible
//! shim driving wizwalker — can read, write, scan, and allocate in a target
//! through zhol's backend. Built as a native extension; on Linux this reaches a
//! Proton-hosted Windows game via `/proc`.

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::memory::read::read_bytes as zread;
use crate::memory::utils::allocate_memory;
use crate::memory::write::write_bytes as zwrite;
use crate::platform;
use crate::process::module::module_by_name;
use crate::process::pattern::pattern_scan as zscan;
use crate::process::SafeHandle;
use crate::raw_hook::RawHook;
use crate::MemOpError;

fn err(e: MemOpError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}


const T: Option<Duration> = Some(Duration::from_secs(5));

/// Scalar type tag for [`Process::read_typed`] / [`Process::write_typed`]. Lets
/// Python name a C scalar across the FFI boundary (generics can't cross it), so
/// typed reads happen in Rust instead of `struct.unpack` on the Python side.
/// `Usize` is a pointer-width unsigned (8 bytes on the 64-bit targets zhol runs).
#[pyclass(eq, eq_int)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DType {
    I8,
    I16,
    I32,
    I64,
    U8,
    U16,
    U32,
    U64,
    F32,
    F64,
    Bool,
    Usize,
}

impl DType {
    /// Width in bytes of the value read/written for this type.
    fn size(self) -> usize {
        match self {
            DType::I8 | DType::U8 | DType::Bool => 1,
            DType::I16 | DType::U16 => 2,
            DType::I32 | DType::U32 | DType::F32 => 4,
            DType::I64 | DType::U64 | DType::F64 | DType::Usize => 8,
        }
    }
}

/// Decode a `dtype`-sized byte buffer to a Python scalar (same mapping as
/// `read_typed`, but from an in-hand buffer so a batched read can decode N at
/// once without N syscalls).
fn dtype_from_bytes(py: Python<'_>, dtype: DType, b: &[u8]) -> PyResult<PyObject> {
    fn pod<V: bytemuck::Pod>(b: &[u8]) -> PyResult<V> {
        bytemuck::try_pod_read_unaligned::<V>(b)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("decode: {e}")))
    }
    Ok(match dtype {
        DType::I8 => pod::<i8>(b)?.into_py(py),
        DType::I16 => pod::<i16>(b)?.into_py(py),
        DType::I32 => pod::<i32>(b)?.into_py(py),
        DType::I64 => pod::<i64>(b)?.into_py(py),
        DType::U8 => pod::<u8>(b)?.into_py(py),
        DType::U16 => pod::<u16>(b)?.into_py(py),
        DType::U32 => pod::<u32>(b)?.into_py(py),
        DType::U64 => pod::<u64>(b)?.into_py(py),
        DType::F32 => pod::<f32>(b)?.into_py(py),
        DType::F64 => pod::<f64>(b)?.into_py(py),
        DType::Bool => (pod::<u8>(b)? != 0).into_py(py),
        DType::Usize => (pod::<u64>(b)? as usize).into_py(py),
    })
}

/// A handle to a target process, opened by pid.
#[pyclass]
pub struct Process {
    handle: SafeHandle,
    #[pyo3(get)]
    pid: u32,
    /// Managed hooks installed through this `Process`, so teardown can revert
    /// them all (see `Drop`). Each is also owned by the `HookHandle` returned to
    /// Python; `unhook` is idempotent, so double-revert is harmless.
    installed: Mutex<Vec<Arc<RawHook>>>,
}

#[pymethods]
impl Process {
    /// Open a process by pid.
    #[staticmethod]
    fn open(pid: u32) -> PyResult<Self> {
        Ok(Process {
            handle: SafeHandle::from_pid(pid).map_err(err)?,
            pid,
            installed: Mutex::new(Vec::new()),
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

    /// Write `data` into EXECUTABLE memory so the patch takes effect (hook jumps,
    /// je-NOPs, and their restores). Plain write on Windows/Linux; on macOS a guest
    /// W^X write via the one-shot RPC, since Rosetta ignores external writes to
    /// already-translated code. Patch must be ≤127 bytes of whole instructions.
    fn write_code(&self, py: Python<'_>, addr: usize, data: &[u8]) -> PyResult<()> {
        let handle = self.handle.clone();
        let bytes = data.to_vec();
        py.allow_threads(move || crate::rpc::write_code(&handle, addr, &bytes))
            .map_err(err)
    }

    /// Read a single scalar of `dtype` at `addr`, returning a Python int/float/
    /// bool. No hook required (goes through the hook-free `read_pod` path).
    fn read_typed(&self, py: Python<'_>, addr: usize, dtype: DType) -> PyResult<PyObject> {
        use crate::memory::read::read_pod;
        let h = &self.handle;
        let obj = match dtype {
            DType::I8 => read_pod::<i8>(h, addr, T).map_err(err)?.into_py(py),
            DType::I16 => read_pod::<i16>(h, addr, T).map_err(err)?.into_py(py),
            DType::I32 => read_pod::<i32>(h, addr, T).map_err(err)?.into_py(py),
            DType::I64 => read_pod::<i64>(h, addr, T).map_err(err)?.into_py(py),
            DType::U8 => read_pod::<u8>(h, addr, T).map_err(err)?.into_py(py),
            DType::U16 => read_pod::<u16>(h, addr, T).map_err(err)?.into_py(py),
            DType::U32 => read_pod::<u32>(h, addr, T).map_err(err)?.into_py(py),
            DType::U64 => read_pod::<u64>(h, addr, T).map_err(err)?.into_py(py),
            DType::F32 => read_pod::<f32>(h, addr, T).map_err(err)?.into_py(py),
            DType::F64 => read_pod::<f64>(h, addr, T).map_err(err)?.into_py(py),
            DType::Bool => (read_pod::<u8>(h, addr, T).map_err(err)? != 0).into_py(py),
            DType::Usize => (read_pod::<u64>(h, addr, T).map_err(err)? as usize).into_py(py),
        };
        Ok(obj)
    }

    /// Write a single scalar `value` of `dtype` at `addr`. No hook required.
    fn write_typed(&self, addr: usize, dtype: DType, value: &Bound<'_, PyAny>) -> PyResult<()> {
        use crate::memory::write::write_pod;
        let h = &self.handle;
        match dtype {
            DType::I8 => write_pod::<i8>(h, addr, value.extract()?, T).map_err(err)?,
            DType::I16 => write_pod::<i16>(h, addr, value.extract()?, T).map_err(err)?,
            DType::I32 => write_pod::<i32>(h, addr, value.extract()?, T).map_err(err)?,
            DType::I64 => write_pod::<i64>(h, addr, value.extract()?, T).map_err(err)?,
            DType::U8 => write_pod::<u8>(h, addr, value.extract()?, T).map_err(err)?,
            DType::U16 => write_pod::<u16>(h, addr, value.extract()?, T).map_err(err)?,
            DType::U32 => write_pod::<u32>(h, addr, value.extract()?, T).map_err(err)?,
            DType::U64 => write_pod::<u64>(h, addr, value.extract()?, T).map_err(err)?,
            DType::F32 => write_pod::<f32>(h, addr, value.extract()?, T).map_err(err)?,
            DType::F64 => write_pod::<f64>(h, addr, value.extract()?, T).map_err(err)?,
            DType::Bool => {
                write_pod::<u8>(h, addr, u8::from(value.extract::<bool>()?), T).map_err(err)?
            }
            DType::Usize => {
                write_pod::<u64>(h, addr, value.extract::<usize>()? as u64, T).map_err(err)?
            }
        }
        Ok(())
    }

    /// Read many `(addr, size)` regions in one call. On Linux this is a single
    /// batched `process_vm_readv` (hole-tolerant per-region fallback); elsewhere
    /// it loops. Returns one `bytes` per spec, in order — one FFI crossing for N
    /// reads (pointer-chain walks, stat blocks).
    fn read_many<'py>(
        &self,
        py: Python<'py>,
        specs: Vec<(usize, usize)>,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        #[cfg(target_os = "linux")]
        {
            let bufs = crate::platform::read_mem_many(&self.handle, &specs, T).map_err(err)?;
            return Ok(bufs.iter().map(|b| PyBytes::new_bound(py, b)).collect());
        }
        #[cfg(not(target_os = "linux"))]
        {
            let mut out = Vec::with_capacity(specs.len());
            for (addr, size) in specs {
                let data = zread(&self.handle, addr, size, T).map_err(err)?;
                out.push(PyBytes::new_bound(py, &data));
            }
            Ok(out)
        }
    }

    /// Read many `(addr, dtype)` scalars in one call — the typed sibling of
    /// `read_many`. One FFI crossing (a single batched `process_vm_readv` on
    /// Linux); returns one Python int/float/bool per spec, in order. Ideal for
    /// reading several fields of a struct at once.
    fn read_typed_many(&self, py: Python<'_>, specs: Vec<(usize, DType)>) -> PyResult<Vec<PyObject>> {
        let byte_specs: Vec<(usize, usize)> =
            specs.iter().map(|(addr, dt)| (*addr, dt.size())).collect();
        #[cfg(target_os = "linux")]
        let bufs = crate::platform::read_mem_many(&self.handle, &byte_specs, T).map_err(err)?;
        #[cfg(not(target_os = "linux"))]
        let bufs = {
            let mut out = Vec::with_capacity(byte_specs.len());
            for (addr, size) in &byte_specs {
                out.push(zread(&self.handle, *addr, *size, T).map_err(err)?);
            }
            out
        };
        specs
            .iter()
            .zip(bufs.iter())
            .map(|((_, dt), buf)| dtype_from_bytes(py, *dt, buf))
            .collect()
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
        let hits = zscan(&self.handle, pattern, start, size).map_err(err)?;
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

    /// Allocate `size` bytes of EXECUTABLE code memory reachable by a 5-byte
    /// `E9 rel32` jump from `near` (an inline hook's patch site). On macOS the cave
    /// is placed within ±2 GiB of `near` so the jump — and the cave's return jump —
    /// reach; the fresh page is translated lazily on first execution. On other
    /// platforms `near` is advisory (their caves are already reachable) and a normal
    /// executable allocation is returned.
    fn allocate_near(&self, size: usize, near: usize) -> PyResult<usize> {
        #[cfg(target_os = "macos")]
        {
            platform::alloc_code_near(&self.handle, size, near).map_err(err)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = near;
            let region = allocate_memory(&self.handle, size).map_err(err)?;
            let addr = region.addr;
            std::mem::forget(region);
            Ok(addr)
        }
    }

    /// Register an explicit code-cave arena (e.g. wizwalker's autobot).
    fn register_cave(&self, start: usize, size: usize) -> PyResult<()> {
        platform::register_cave(&self.handle, start, size).map_err(err)
    }

    /// Return a block from a prior [`allocate`] to the cave for reuse. Idempotent.
    fn free(&self, addr: usize) -> PyResult<()> {
        platform::reclaim_cave(&self.handle, addr).map_err(err)
    }

    /// Install a managed code-cave hook from caller-supplied `shellcode`.
    ///
    /// `replaced_len` bytes (>= 5) at `site` are captured and overwritten with a
    /// jump into a cave holding the shellcode. With `relocate_original` (default
    /// `True`), the displaced bytes + a jump back are appended so the original
    /// code still runs — set it `False` if your shellcode already re-runs them.
    /// Returns a [`HookHandle`]; the hook reverts on `handle.unhook()` or when
    /// this `Process` is torn down.
    #[pyo3(signature = (site, shellcode, replaced_len=5, relocate_original=true))]
    fn install_hook(
        &self,
        site: usize,
        shellcode: &[u8],
        replaced_len: usize,
        relocate_original: bool,
    ) -> PyResult<HookHandle> {
        let hook = RawHook::install(
            self.handle.clone(),
            site,
            shellcode,
            replaced_len,
            relocate_original,
        )
        .map_err(err)?;
        let hook = Arc::new(hook);
        self.installed.lock().push(Arc::clone(&hook));
        Ok(HookHandle { inner: hook })
    }

    /// Run `shellcode` once on one of the target's own threads via a one-shot
    /// self-restoring trampoline planted at `site` (a per-frame call site the
    /// caller supplies). No remote thread / ptrace. Blocks (GIL released), polling
    /// a guard byte up to `timeout_ms`, then unplants the site; returns whether
    /// the shellcode ran.
    ///
    /// `orig_len` (>= 5) whole, position-independent bytes at `site` are
    /// displaced. `done_addr` is the one-shot guard byte — pass 0 to allocate one.
    /// The trampoline lives in a code cave, so the site must be within +/-2GiB of
    /// a cave (register one near the site, e.g. the autobot).
    #[pyo3(signature = (site, shellcode, orig_len=10, done_addr=0, timeout_ms=2000))]
    fn rpc_via_hijack(
        &self,
        py: Python<'_>,
        site: usize,
        shellcode: &[u8],
        orig_len: usize,
        done_addr: usize,
        timeout_ms: u64,
    ) -> PyResult<bool> {
        let handle = self.handle.clone();
        let shell = shellcode.to_vec();
        py.allow_threads(move || {
            crate::rpc::rpc_via_hijack(
                &handle,
                site,
                &shell,
                orig_len,
                done_addr,
                Duration::from_millis(timeout_ms),
            )
        })
        .map_err(err)
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        // Best-effort revert of every managed hook on teardown (Python GC / del).
        // Panic-safe: unhook swallows nothing we can't ignore, and we never
        // unwrap. SIGKILL / hard crash can't be covered — no destructor runs.
        for hook in self.installed.lock().iter() {
            let _ = hook.unhook();
        }
    }
}

/// A live managed hook (see [`Process::install_hook`]). Reverting it restores the
/// original bytes and reclaims the cave slot; it also reverts when its owning
/// `Process` is torn down.
#[pyclass]
pub struct HookHandle {
    inner: Arc<RawHook>,
}

#[pymethods]
impl HookHandle {
    /// Revert this hook now (idempotent).
    fn unhook(&self) -> PyResult<()> {
        self.inner.unhook().map_err(err)
    }

    /// Whether the hook is still planted.
    #[getter]
    fn active(&self) -> bool {
        self.inner.is_active()
    }

    /// The hooked site address.
    #[getter]
    fn site(&self) -> usize {
        self.inner.site()
    }

    /// The cave address the shellcode was written to.
    #[getter]
    fn cave_addr(&self) -> usize {
        self.inner.cave_addr()
    }
}

#[pymodule]
fn zhol(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Process>()?;
    m.add_class::<DType>()?;
    m.add_class::<HookHandle>()?;
    Ok(())
}
