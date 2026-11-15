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
//! ## Phase status
//! Phase 1 (this file): read / write / region / module discovery / pattern scan
//! (the scanner is platform-agnostic on top of `read_mem`). Cave allocation,
//! hooks, and thread-hijack RPC are NOT implemented on macOS yet — those entry
//! points return a descriptive error so the crate builds and reads work. Hook
//! injection on macOS (SIP + writing executable pages + Rosetta-translated code)
//! is a separate phase that needs a machine able to run the game.

use std::collections::HashMap;
use std::time::Duration;

use super::{Module, Protect, Region};
use crate::process::SafeHandle;
use crate::{MemOpError, MemOpResult};

use mach2::kern_return::KERN_SUCCESS;
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_region_recurse, mach_vm_write};
use mach2::vm_prot::{VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{vm_region_submap_info_64, VM_REGION_SUBMAP_INFO_COUNT_64};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};

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
    let mut count: u32 = VM_REGION_SUBMAP_INFO_COUNT_64;
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

/// Write `bytes` at `addr` via `mach_vm_write`. Works on writable pages (game
/// variables). Writing read-only/executable pages (hook installation) is not
/// supported on macOS yet — that is phase 2.
pub fn write_mem(
    handle: &SafeHandle,
    addr: usize,
    bytes: &[u8],
    timeout: Option<Duration>,
) -> MemOpResult<usize> {
    let guard = acquire(handle, timeout)?;
    let kr = unsafe {
        mach_vm_write(
            guard.task,
            addr as mach_vm_address_t,
            bytes.as_ptr() as mach2::vm_types::vm_offset_t,
            bytes.len() as u32,
        )
    };
    if kr != KERN_SUCCESS {
        return Err(MemOpError::Os(format!(
            "mach_vm_write @ {addr:#x} ({} bytes): kr={kr}",
            bytes.len()
        )));
    }
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

/// Enumerate file-backed modules by walking the task's regions and resolving each
/// to its backing file. Base is the lowest mapping of each path; size is the span
/// of its mappings. (A Wine-hosted PE is mapped from its `.exe`, so it shows up
/// here by that name — the exact base/size for a PE may want PE-header parsing
/// later, as the Linux backend does.)
pub fn enum_modules(handle: &SafeHandle, timeout: Option<Duration>) -> MemOpResult<Vec<Module>> {
    let guard = acquire(handle, timeout)?;
    let (task, pid) = (guard.task, guard.pid);

    let mut order: Vec<String> = Vec::new();
    let mut spans: HashMap<String, (u64, u64)> = HashMap::new();

    let mut cur: u64 = 0;
    // Bound the walk so a malformed region can't loop forever.
    for _ in 0..1_000_000 {
        let (rstart, rsize, _prot) = match region_at(task, cur) {
            Some(r) => r,
            None => break,
        };
        if let Some(path) = region_filename(pid, rstart) {
            let entry = spans.entry(path.clone()).or_insert_with(|| {
                order.push(path.clone());
                (rstart, rstart + rsize)
            });
            entry.0 = entry.0.min(rstart);
            entry.1 = entry.1.max(rstart + rsize);
        }
        cur = if rstart + rsize > cur {
            rstart + rsize
        } else {
            cur + 1
        };
    }

    Ok(order
        .into_iter()
        .map(|path| {
            let (start, end) = spans[&path];
            Module {
                name: basename(&path).to_string(),
                base: start as usize,
                size: (end - start) as usize,
            }
        })
        .collect())
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

// --- Phase 2 (not yet implemented on macOS): cave allocation, hooks, RPC. ---
// These return a clear error so the crate builds and the read path works; the
// hook/RPC engine on macOS (SIP, writing executable pages, Rosetta-translated
// code) needs a machine that can run the game to develop against.

fn phase2(what: &str) -> MemOpError {
    MemOpError::Message(format!(
        "macOS: {what} is not implemented yet (phase 2 — hooks/cave/RPC)"
    ))
}

pub fn alloc(_handle: &SafeHandle, _size: usize) -> MemOpResult<usize> {
    Err(phase2("data-cave allocation"))
}

pub fn alloc_code(_handle: &SafeHandle, _size: usize) -> MemOpResult<usize> {
    Err(phase2("code-cave allocation"))
}

/// No-op (parity with the Linux backend, whose `free` is also a no-op).
pub fn free(_handle: &SafeHandle, _addr: usize, _size: usize) -> MemOpResult<()> {
    Ok(())
}

/// No-op: nothing is allocated to reclaim until cave support lands.
pub fn reclaim_cave(_handle: &SafeHandle, _addr: usize) -> MemOpResult<()> {
    Ok(())
}

pub fn register_cave(_handle: &SafeHandle, _start: usize, _size: usize) -> MemOpResult<()> {
    Err(phase2("register_cave"))
}

/// No-op, returning the requested protection for signature parity (as on Linux).
/// macOS does enforce page protection, but phase-1 writes target already-writable
/// pages; executable-page writes come with the hook engine.
pub fn protect(
    _handle: &SafeHandle,
    _addr: usize,
    _size: usize,
    _timeout: Option<Duration>,
    prot: Protect,
) -> MemOpResult<Protect> {
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

    /// Cross-process read needs task_for_pid, which requires the debugger
    /// entitlement or root on a SIP machine — ignored by default. Run with
    /// `cargo test -- --ignored` on a machine/binary that can obtain it.
    #[test]
    #[ignore]
    fn read_child_process() {
        use std::process::Command;
        let mut child = Command::new("/bin/sleep").arg("30").spawn().expect("spawn child");
        std::thread::sleep(Duration::from_millis(200));
        let res = SafeHandle::from_pid(child.id());
        let _ = child.kill();
        let _ = child.wait();
        let h = res.expect("task_for_pid child (needs entitlement/root)");
        // Just prove we can query a region in another task.
        let r = region_at(h.acquire_with_timeout(None).unwrap().task, 0x1000);
        assert!(r.is_some());
    }
}
