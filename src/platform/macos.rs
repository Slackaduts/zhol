//! macOS backend: process memory through the Mach VM APIs.
//!
//! Reaches a Windows game running under Wine/CrossOver the same way the Linux
//! backend reaches one under Proton: the host process's address space *is* the
//! game's, so reading the Wine process reads the game. Reads/writes go through
//! `mach_vm_read_overwrite` / `mach_vm_write` on the target task port; regions
//! come from `mach_vm_region_recurse`; module/file discovery uses libproc's
//! `proc_regionfilename` (the analogue of a `/proc/<pid>/maps` path).
//!
//! ## task_for_pid and SIP
//! Obtaining ANOTHER process's task port needs `task_for_pid`, which on a
//! SIP/hardened-runtime machine requires the caller to be code-signed with the
//! `com.apple.security.cs.debugger` entitlement (or to run as root). Reading our
//! OWN task (`mach_task_self`) always works and needs no entitlement — that is
//! what the unconditional self-process tests exercise.
//!
//! ## Reading the game under Wine/CrossOver (entitlements / SIP)
//! Verified against a live CrossOver-hosted Wizard101 (Wine 8, x86_64 under
//! Rosetta 2): the Mach code here is correct — a C probe with the identical calls
//! reads a cooperative target fine. The blocker is purely macOS's security model.
//! CrossOver's `wineloader64` runs with the **hardened runtime and no
//! `get-task-allow`**, so `task_for_pid` (and `task_read/inspect_for_pid`) are
//! refused with `kr=5` (KERN_FAILURE) for any non-root, non-Apple caller — even
//! one ad-hoc-signed with `com.apple.security.cs.debugger` (an ad-hoc cs.debugger
//! entitlement is not honored by the kernel). `vmmap` works only because it is an
//! Apple-platform binary with private task-port entitlements.
//!
//! It takes BOTH signatures (verified against the live game): the game's Wine
//! loader must carry `get-task-allow`, AND the zhol binary must itself be signed
//! with `com.apple.security.cs.debugger` — an unsigned caller is refused (kr=5)
//! even by a get-task-allow *hardened* target. (Against a NON-hardened target an
//! unsigned caller works, as before.)
//!
//! Give the target loader get-task-allow (operator's choice):
//!   A. Re-sign CrossOver's `wine64-preloader` ad-hoc with `-o runtime`, its
//!      existing entitlements, plus `com.apple.security.get-task-allow`, then
//!      relaunch the game. Persistent; it replaces the app's signature — back up.
//!   B. Use a Wine build already ad-hoc-signed with `get-task-allow` (Homebrew /
//!      Gcenx `wine` usually are) — works out of the box.
//! Sign the zhol binary itself:
//!   `codesign -s - --entitlements debugger.plist <binary>`
//! where debugger.plist grants `com.apple.security.cs.debugger`.
//! Running zhol as **root does NOT help**: on recent macOS (verified on 26.5) the
//! hardened-runtime task-port check refuses even root (`task_for_pid` kr=5).
//!
//! ## Phase status
//! Phase 1: read / write / region / module discovery / pattern scan — validated
//! against the live game. Phase 2: fresh-page allocation (`mach_vm_allocate`) +
//! protected-page writes (`mach_vm_protect`) + the generic hook/RPC engines.
//!
//! Rosetta reality (live-tested): **inline code patching does NOT work** under
//! Rosetta 2 — a cross-process write to already-translated x86 code is ignored
//! (Rosetta's self-modifying-code detection only watches the GUEST's own writes,
//! not external `mach_vm_*`), so `rpc`/`raw_hook`'s inline trampolines don't fire
//! on macOS. The viable paradigm is **pointer redirection**: overwrite a data
//! function pointer (IAT/vtable slot) to a freshly `mach_vm_allocate`'d page —
//! Rosetta has never translated it, so it is translated lazily on first execution,
//! and a 64-bit pointer reaches it with no rel32 constraint. Allocation here uses
//! fresh pages for exactly that reason; an in-image "cave" is an AOT-translated
//! page and does not work.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::Mutex;

use super::{Module, Protect, Region};
use crate::process::SafeHandle;
use crate::{MemOpError, MemOpResult};

use mach2::kern_return::KERN_SUCCESS;
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{
    mach_vm_allocate, mach_vm_deallocate, mach_vm_protect, mach_vm_read_overwrite,
    mach_vm_region_recurse, mach_vm_write,
};
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::vm_region_submap_info_64;
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

/// `VM_PROT_COPY` (0x10): force a private writable copy of a shared/COW page so a
/// write to a read-only, file-backed code page lands locally. Not re-exported by
/// mach2 in all versions, so defined here.
const VM_PROT_COPY: i32 = 0x10;

/// Per-process handle: the pid plus the target's Mach task port.
pub struct Target {
    pub pid: u32,
    task: mach_port_t,
}

// The task port is just a Mach port name (an integer); sharing it across threads
// behind the crate's `Mutex<Target>` is sound.
unsafe impl Send for Target {}
unsafe impl Sync for Target {}

/// Open a target by pid. For our own pid this is `mach_task_self` (no entitlement
/// needed); for another process it is `task_for_pid`, which needs the debugger
/// entitlement or root on a SIP machine.
pub fn open(pid: u32) -> MemOpResult<Target> {
    if pid == std::process::id() {
        return Ok(Target {
            pid,
            task: unsafe { mach_task_self() },
        });
    }
    let me_task = unsafe { mach_task_self() };
    let mut task: mach_port_t = MACH_PORT_NULL;
    let kr = unsafe { task_for_pid(me_task, pid as i32, &mut task) };
    if kr != KERN_SUCCESS {
        return Err(MemOpError::Os(format!(
            "task_for_pid({pid}) failed (kr={kr}); needs the \
             com.apple.security.cs.debugger entitlement (signed) or root on a SIP machine"
        )));
    }
    Ok(Target { pid, task })
}

/// Produce the current OS error as a `MemOpError`.
pub fn last_error() -> MemOpError {
    MemOpError::Os(std::io::Error::last_os_error().to_string())
}

fn acquire<'a>(
    handle: &'a SafeHandle,
    timeout: Option<Duration>,
) -> MemOpResult<crate::process::SafeHandleGuard<'a>> {
    handle
        .acquire_with_timeout(timeout)
        .ok_or(MemOpError::Timeout(timeout))
}

/// One readable mapped region at or above `addr`: `(start, size, prot)`.
/// `None` once there is nothing mapped at or above `addr`.
fn region_at(task: mach_port_t, addr: u64) -> Option<(u64, u64, i32)> {
    let mut address: mach_vm_address_t = addr;
    let mut size: mach_vm_size_t = 0;
    let mut depth: u32 = 0;
    let mut info: vm_region_submap_info_64 = unsafe { std::mem::zeroed() };
    // mach2 0.4.3 exposes no *_COUNT constant; the kernel wants the struct's size
    // counted in natural_t (int) units — the value of C's VM_REGION_SUBMAP_INFO_COUNT_64.
    let mut count: u32 =
        (std::mem::size_of::<vm_region_submap_info_64>() / std::mem::size_of::<u32>()) as u32;
    let kr = unsafe {
        mach_vm_region_recurse(
            task,
            &mut address,
            &mut size,
            &mut depth,
            &mut info as *mut vm_region_submap_info_64 as *mut i32,
            &mut count,
        )
    };
    if kr != KERN_SUCCESS {
        return None;
    }
    Some((address, size, info.protection))
}

/// Read `[addr, addr+size)` tolerating unmapped holes (zero-filled), so an image
/// that straddles gaps still returns a `base + offset` buffer — matching the
/// Linux backend. A single `mach_vm_read_overwrite` is tried first; on failure
/// (a hole in the range) each mapped sub-region is read individually.
pub fn read_mem(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Vec<u8>> {
    let guard = acquire(handle, timeout)?;
    let task = guard.task;
    let mut buf = vec![0u8; size];

    // Fast path: one contiguous read.
    let mut out: mach_vm_size_t = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(
            task,
            addr as mach_vm_address_t,
            size as mach_vm_size_t,
            buf.as_mut_ptr() as mach_vm_address_t,
            &mut out,
        )
    };
    if kr == KERN_SUCCESS && out as usize == size {
        return Ok(buf);
    }

    // Slow path: gather mapped sub-regions into the zero-filled buffer.
    let end = addr as u64 + size as u64;
    let mut cur = addr as u64;
    let mut any = false;
    while cur < end {
        let (rstart, rsize, prot) = match region_at(task, cur) {
            Some(r) => r,
            None => break,
        };
        if rstart >= end {
            break; // only holes remain in range
        }
        let rend = rstart + rsize;
        if prot & VM_PROT_READ != 0 {
            let from = rstart.max(addr as u64);
            let to = rend.min(end);
            if to > from {
                let mut got: mach_vm_size_t = 0;
                let dst = unsafe { buf.as_mut_ptr().add((from - addr as u64) as usize) };
                let kr = unsafe {
                    mach_vm_read_overwrite(
                        task,
                        from as mach_vm_address_t,
                        (to - from) as mach_vm_size_t,
                        dst as mach_vm_address_t,
                        &mut got,
                    )
                };
                if kr == KERN_SUCCESS {
                    any = true;
                }
            }
        }
        // Advance past this region (guard against a zero-size region).
        cur = if rend > cur { rend } else { cur + 1 };
    }
    if !any && size > 0 {
        return Err(MemOpError::Os(format!(
            "mach_vm_read_overwrite @ {addr:#x} (size {size}): no readable region in range"
        )));
    }
    Ok(buf)
}

/// Read many `(addr, size)` regions. Mach has no scatter read, so this loops
/// `read_mem` (one task-port op each); provided for surface parity with the
/// Linux backend's batched path.
pub fn read_mem_many(
    handle: &SafeHandle,
    specs: &[(usize, usize)],
    timeout: Option<Duration>,
) -> MemOpResult<Vec<Vec<u8>>> {
    let mut out = Vec::with_capacity(specs.len());
    for &(addr, size) in specs {
        out.push(read_mem(handle, addr, size, timeout)?);
    }
    Ok(out)
}

/// Host page size (16 KiB on Apple Silicon), for aligning protection changes.
fn page_size() -> u64 {
    static PS: OnceLock<u64> = OnceLock::new();
    *PS.get_or_init(|| {
        let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if v > 0 {
            v as u64
        } else {
            0x4000
        }
    })
}

/// Write `bytes` at `addr` in `task`. Plain `mach_vm_write` first (writable game
/// data); if the page is read-only/executable (a hook site in `.text`, the code
/// cave) it's refused, so temporarily add write permission with `mach_vm_protect`
/// (+`VM_PROT_COPY` to privately copy a shared code page), write, and restore the
/// original protection. This is macOS's equivalent of the Linux `/proc` write
/// bypassing page protection — what hook installation needs.
fn raw_write(task: mach_port_t, addr: u64, bytes: &[u8]) -> MemOpResult<()> {
    let plain = unsafe {
        mach_vm_write(
            task,
            addr as mach_vm_address_t,
            bytes.as_ptr() as mach2::vm_types::vm_offset_t,
            bytes.len() as u32,
        )
    };
    if plain == KERN_SUCCESS {
        return Ok(());
    }

    // Protected page: flip to writable over the touched page span, write, restore.
    let ps = page_size();
    let start = addr & !(ps - 1);
    let end = (addr + bytes.len() as u64 + ps - 1) & !(ps - 1);
    let span = end - start;
    let old_prot = region_at(task, addr).map(|(_, _, p)| p);

    let pr = unsafe {
        mach_vm_protect(
            task,
            start as mach_vm_address_t,
            span as mach_vm_size_t,
            0,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY,
        )
    };
    if pr != KERN_SUCCESS {
        return Err(MemOpError::Os(format!(
            "mach_vm_protect(rw) @ {start:#x}+{span:#x}: kr={pr} (needs the target's \
             loader signed cs.disable-executable-page-protection for code writes)"
        )));
    }
    let w = unsafe {
        mach_vm_write(
            task,
            addr as mach_vm_address_t,
            bytes.as_ptr() as mach2::vm_types::vm_offset_t,
            bytes.len() as u32,
        )
    };
    // Restore the original protection (best effort) whether or not the write took.
    if let Some(p) = old_prot {
        unsafe {
            mach_vm_protect(task, start as mach_vm_address_t, span as mach_vm_size_t, 0, p);
        }
    }
    if w != KERN_SUCCESS {
        return Err(MemOpError::Os(format!(
            "mach_vm_write(after protect) @ {addr:#x} ({} bytes): kr={w}",
            bytes.len()
        )));
    }
    Ok(())
}

/// Write `bytes` at `addr`, transparently handling read-only/executable pages
/// (see [`raw_write`]).
pub fn write_mem(
    handle: &SafeHandle,
    addr: usize,
    bytes: &[u8],
    timeout: Option<Duration>,
) -> MemOpResult<usize> {
    let guard = acquire(handle, timeout)?;
    raw_write(guard.task, addr as u64, bytes)?;
    Ok(bytes.len())
}

/// The backing file path for the region containing `addr`, via libproc.
fn region_filename(pid: u32, addr: u64) -> Option<String> {
    // PROC_PIDPATHINFO_MAXSIZE is 4*PATH_MAX; a PATH_MAX buffer is plenty here.
    let mut buf = [0u8; 4096];
    let n = unsafe {
        libc::proc_regionfilename(
            pid as libc::c_int,
            addr,
            buf.as_mut_ptr() as *mut libc::c_void,
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..n as usize]).into_owned())
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// Read exactly `buf.len()` bytes at `addr` from `task`; false on short/error.
fn task_read_exact(task: mach_port_t, addr: u64, buf: &mut [u8]) -> bool {
    let mut out: mach_vm_size_t = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(
            task,
            addr as mach_vm_address_t,
            buf.len() as mach_vm_size_t,
            buf.as_mut_ptr() as mach_vm_address_t,
            &mut out,
        )
    };
    kr == KERN_SUCCESS && out as usize == buf.len()
}

/// `SizeOfImage` of the PE whose `MZ` header is mapped at `base`, read via `task`.
/// None if it isn't a PE. Mirrors the Linux backend's PE sizing so a Wine-hosted
/// module's size is its real image size, not the (Rosetta-inflated) mapping span.
fn pe_image_size(task: mach_port_t, base: u64) -> Option<usize> {
    let mut mz = [0u8; 2];
    if !task_read_exact(task, base, &mut mz) || &mz != b"MZ" {
        return None;
    }
    let mut lfanew_b = [0u8; 4];
    if !task_read_exact(task, base + 0x3C, &mut lfanew_b) {
        return None;
    }
    let lfanew = u32::from_le_bytes(lfanew_b) as u64;
    let mut sig = [0u8; 4];
    if !task_read_exact(task, base + lfanew, &mut sig) || &sig != b"PE\0\0" {
        return None;
    }
    // Optional header starts at sig(4)+COFF(20) = +24; SizeOfImage is at +56.
    let mut size_b = [0u8; 4];
    if !task_read_exact(task, base + lfanew + 24 + 56, &mut size_b) {
        return None;
    }
    Some(u32::from_le_bytes(size_b) as usize)
}

/// Enumerate file-backed modules by walking the task's regions and resolving each
/// to its backing file.
///
/// A file whose image carries an `MZ`/PE header (a Windows module under Wine) is
/// reported at its **PE image base** with **PE `SizeOfImage`** — not the span of
/// its mappings. Under Rosetta, Wine maps unrelated file-backed pieces far below
/// the image (e.g. the real `WizardGraphicalClient.exe` image is at its
/// `0x140000000` ImageBase while other mappings of the same file sit near
/// `0x13b40_0000`), so the span is meaningless. Entries are also deduped by
/// basename preferring the PE candidate, because Wine hard-links its
/// `wine64-preloader` into the temp dir under the game's exe name — without this,
/// `module_by_name("WizardGraphicalClient.exe")` returns the preloader, not the
/// game image.
pub fn enum_modules(handle: &SafeHandle, timeout: Option<Duration>) -> MemOpResult<Vec<Module>> {
    let guard = acquire(handle, timeout)?;
    let (task, pid) = (guard.task, guard.pid);

    // Per backing path: (min mapping start, max mapping end, first MZ region seen).
    let mut order: Vec<String> = Vec::new();
    let mut spans: HashMap<String, (u64, u64, Option<u64>)> = HashMap::new();

    let mut cur: u64 = 0;
    // Bound the walk so a malformed region can't loop forever.
    for _ in 0..1_000_000 {
        let (rstart, rsize, _prot) = match region_at(task, cur) {
            Some(r) => r,
            None => break,
        };
        if let Some(path) = region_filename(pid, rstart) {
            let mut magic = [0u8; 2];
            let is_mz = task_read_exact(task, rstart, &mut magic) && &magic == b"MZ";
            let entry = spans.entry(path.clone()).or_insert_with(|| {
                order.push(path.clone());
                (rstart, rstart + rsize, None)
            });
            entry.0 = entry.0.min(rstart);
            entry.1 = entry.1.max(rstart + rsize);
            if is_mz && entry.2.is_none() {
                entry.2 = Some(rstart);
            }
        }
        cur = if rstart + rsize > cur {
            rstart + rsize
        } else {
            cur + 1
        };
    }

    // Build, deduping by basename and preferring the PE (MZ) candidate.
    let mut by_name: Vec<(String, Module, bool)> = Vec::new();
    for path in &order {
        let (min_start, max_end, mz) = spans[path];
        let is_pe = mz.is_some();
        let (base, size) = match mz {
            Some(b) => (b, pe_image_size(task, b).unwrap_or((max_end - b) as usize)),
            None => (min_start, (max_end - min_start) as usize),
        };
        let name = basename(path).to_string();
        let module = Module {
            name: name.clone(),
            base: base as usize,
            size,
        };
        match by_name.iter_mut().find(|(n, _, _)| *n == name) {
            // Replace a non-PE entry with a PE one; otherwise keep the first.
            Some(slot) if is_pe && !slot.2 => *slot = (name, module, is_pe),
            Some(_) => {}
            None => by_name.push((name, module, is_pe)),
        }
    }
    Ok(by_name.into_iter().map(|(_, m, _)| m).collect())
}

/// Query the region containing `addr`. If `addr` falls in a hole, reports an
/// uncommitted region spanning the gap up to the next mapping, so a region-walking
/// scanner advances instead of stalling (matching the Linux backend).
pub fn query_region(
    handle: &SafeHandle,
    addr: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Region> {
    let guard = acquire(handle, timeout)?;
    let task = guard.task;

    const USER_TOP: u64 = 0x7FFF_FFFF_F000;
    match region_at(task, addr as u64) {
        Some((start, size, prot)) if start <= addr as u64 => Ok(Region {
            base: start as usize,
            size: size as usize,
            readable: prot & VM_PROT_READ != 0,
            writable: prot & VM_PROT_WRITE != 0,
            executable: prot & VM_PROT_EXECUTE != 0,
            committed: true,
            guarded: false,
        }),
        Some((start, _size, _prot)) => Ok(Region {
            // Hole up to the next mapping.
            base: addr,
            size: start.saturating_sub(addr as u64) as usize,
            readable: false,
            writable: false,
            executable: false,
            committed: false,
            guarded: false,
        }),
        None => Ok(Region {
            base: addr,
            size: USER_TOP.saturating_sub(addr as u64) as usize,
            readable: false,
            writable: false,
            executable: false,
            committed: false,
            guarded: false,
        }),
    }
}

// --- Phase 2: fresh-page allocation in the target (macOS VirtualAllocEx). ---
// Unlike the Linux /proc backend (which can't allocate, so carves module-padding
// caves), macOS has mach_vm_allocate. Fresh pages are the right substrate here for
// two reasons: (1) Rosetta 2 has never translated them, so injected x86 code is
// translated lazily on first execution — an in-image "cave" lies in a page Rosetta
// AOT-translated, so cross-process writes there are ignored; (2) a 64-bit pointer
// redirect (IAT/vtable hook) reaches them from anywhere, with no rel32 constraint.
// Inline code patching does not work under Rosetta regardless, so the Linux-style
// rel32-reachable image cave is not used on macOS.

/// addr -> size of live target allocations, so free/reclaim can mach_vm_deallocate.
static ALLOCS: OnceLock<Mutex<HashMap<u64, u64>>> = OnceLock::new();

fn allocs() -> &'static Mutex<HashMap<u64, u64>> {
    ALLOCS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// VM_FLAGS_ANYWHERE: let the kernel choose the address.
const VM_FLAGS_ANYWHERE: i32 = 0x0001;

/// Allocate `size` bytes of fresh memory in the target and set `prot`.
fn vm_alloc(handle: &SafeHandle, size: usize, prot: i32) -> MemOpResult<usize> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let task = guard.task;
    let mut addr: mach_vm_address_t = 0;
    let kr = unsafe { mach_vm_allocate(task, &mut addr, size as mach_vm_size_t, VM_FLAGS_ANYWHERE) };
    if kr != KERN_SUCCESS {
        return Err(MemOpError::Os(format!("mach_vm_allocate({size}): kr={kr}")));
    }
    let pr = unsafe { mach_vm_protect(task, addr, size as mach_vm_size_t, 0, prot) };
    if pr != KERN_SUCCESS {
        unsafe { mach_vm_deallocate(task, addr, size as mach_vm_size_t) };
        return Err(MemOpError::Os(format!(
            "mach_vm_protect({prot:#x}) on fresh alloc: kr={pr} (target loader needs \
             cs.disable-executable-page-protection for RX code pages)"
        )));
    }
    allocs().lock().insert(addr, size as u64);
    Ok(addr as usize)
}

/// Deallocate a prior [`vm_alloc`] block (idempotent). Removes the tracking entry
/// first so the global lock is never held across the per-handle lock.
fn vm_free(handle: &SafeHandle, addr: usize) {
    let sz = allocs().lock().remove(&(addr as u64));
    if let Some(sz) = sz {
        if let Some(g) = handle.acquire_with_timeout(Some(Duration::from_secs(2))) {
            unsafe { mach_vm_deallocate(g.task, addr as mach_vm_address_t, sz as mach_vm_size_t) };
        }
    }
}

/// Allocate fresh writable DATA scratch (the RPC `done` byte, hook var buffers).
pub fn alloc(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    vm_alloc(handle, size, VM_PROT_READ | VM_PROT_WRITE)
}

/// Allocate fresh EXECUTABLE scratch (injected code, trampolines). RWX so we can
/// write then execute; Rosetta translates it lazily on first execution, and a
/// 64-bit pointer redirect reaches it from anywhere.
pub fn alloc_code(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    vm_alloc(handle, size, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE)
}

/// Free a block (parity with Linux's no-op signature, but macOS actually frees).
pub fn free(handle: &SafeHandle, addr: usize, _size: usize) -> MemOpResult<()> {
    vm_free(handle, addr);
    Ok(())
}

/// Reclaim a block — deallocates the fresh page. Idempotent.
pub fn reclaim_cave(handle: &SafeHandle, addr: usize) -> MemOpResult<()> {
    vm_free(handle, addr);
    Ok(())
}

/// No-op on macOS: allocation uses fresh mach_vm_allocate pages, not a registered
/// image cave. wizwalker still calls this (to hand over its autobot); succeeding
/// keeps its hook lifecycle unimpaired while we simply ignore the hint.
pub fn register_cave(_handle: &SafeHandle, _start: usize, _size: usize) -> MemOpResult<()> {
    Ok(())
}

/// Set page protection over `[addr, addr+size)` via `mach_vm_protect`. Hook/cave
/// writes manage their own protection in `raw_write`, so callers rarely need this;
/// provided for parity and completeness.
pub fn protect(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
    prot: Protect,
) -> MemOpResult<Protect> {
    // Protect(0) (the cross-platform EXEC_RW sentinel on non-Windows) carries no
    // actionable bits here; treat it as a no-op. A non-zero value is applied as a
    // raw vm_prot_t.
    if prot.0 == 0 {
        return Ok(prot);
    }
    let guard = acquire(handle, timeout)?;
    let ps = page_size();
    let start = addr as u64 & !(ps - 1);
    let end = (addr as u64 + size as u64 + ps - 1) & !(ps - 1);
    let kr = unsafe {
        mach_vm_protect(
            guard.task,
            start as mach_vm_address_t,
            (end - start) as mach_vm_size_t,
            0,
            prot.0 as i32,
        )
    };
    if kr != KERN_SUCCESS {
        return Err(MemOpError::Os(format!(
            "mach_vm_protect @ {start:#x}: kr={kr}"
        )));
    }
    Ok(prot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn self_handle() -> SafeHandle {
        SafeHandle::from_pid(std::process::id()).expect("open self task")
    }

    #[test]
    fn read_self_roundtrip() {
        let v: u64 = 0x0123_4567_89AB_CDEF;
        let addr = &v as *const u64 as usize;
        let h = self_handle();
        let got = read_mem(&h, addr, 8, None).expect("read self");
        assert_eq!(got, v.to_le_bytes());
    }

    #[test]
    fn write_self_roundtrip() {
        let mut v: u64 = 0;
        let addr = &mut v as *mut u64 as usize;
        let h = self_handle();
        write_mem(&h, addr, &0xDEAD_BEEF_u64.to_le_bytes(), None).expect("write self");
        assert_eq!(v, 0xDEAD_BEEF);
    }

    #[test]
    fn read_many_self() {
        let a: u32 = 0x1111_1111;
        let b: u64 = 0x2222_2222_2222_2222;
        let h = self_handle();
        let bufs = read_mem_many(
            &h,
            &[
                (&a as *const u32 as usize, 4),
                (&b as *const u64 as usize, 8),
            ],
            None,
        )
        .expect("read_many self");
        assert_eq!(bufs[0], a.to_le_bytes());
        assert_eq!(bufs[1], b.to_le_bytes());
    }

    #[test]
    fn query_region_self_readable() {
        let v: u64 = 42;
        let addr = &v as *const u64 as usize;
        let h = self_handle();
        let r = query_region(&h, addr, None).expect("query self region");
        assert!(r.readable, "own stack/heap region should be readable");
        assert!(addr >= r.base && addr < r.base + r.size);
    }

    #[test]
    fn enum_modules_self_nonempty() {
        let h = self_handle();
        let mods = enum_modules(&h, None).expect("enum self modules");
        assert!(!mods.is_empty(), "self should have at least one mapped module");
    }

    /// Cross-process read, ignored by default — it needs a target the caller is
    /// allowed to attach. NOTE: `task_for_pid` against a macOS *platform* binary
    /// (anything shipped under /bin, /usr/bin, …) is refused for a non-root caller
    /// regardless of entitlements, so this `/bin/sleep` child only passes under
    /// root. A non-root run needs a NON-platform child carrying `get-task-allow`
    /// (e.g. an ad-hoc-signed sleeper). Run explicitly, typically as root:
    /// `sudo cargo test -- --ignored read_child_process`.
    #[test]
    #[ignore]
    fn read_child_process() {
        use std::process::Command;
        let mut child = Command::new("/bin/sleep").arg("30").spawn().expect("spawn child");
        std::thread::sleep(Duration::from_millis(300));
        let res = SafeHandle::from_pid(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let h = res.expect("task_for_pid child (needs root for a platform binary, or a get-task-allow child)");
        // Prove we can query a region in another task.
        let r = region_at(h.acquire_with_timeout(None).unwrap().task, 0x1000);
        assert!(r.is_some());
    }
}
