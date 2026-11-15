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
//! against the live game. Phase 2: cave allocation + the generic hook/RPC engines
//! (`raw_hook`, `rpc`) now work on macOS too — writes to r-x pages go through
//! `mach_vm_protect` (the target's loader must carry
//! `cs.disable-executable-page-protection`, as CrossOver's does). The one
//! remaining unknown is runtime, not code: whether a cross-process patch to
//! x86 code is picked up by **Rosetta 2's translation cache** (self-modifying-code
//! detection) or whether the cached translation keeps running the old bytes — that
//! only a live hook test can answer.

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
use mach2::vm::{mach_vm_protect, mach_vm_read_overwrite, mach_vm_region_recurse, mach_vm_write};
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

// --- Phase 2: cave allocation (hooks/RPC ride on the generic raw_hook/rpc). ---
// Mirrors the Linux two-cave model (see platform/unix.rs); duplicated here rather
// than shared so the validated Linux path is untouched. The pure allocator (Cave,
// ProcCaves, take) is identical; find_cave is the macOS-specific part, parsing the
// target PE's section table via Mach reads, and the zero/code writes go through
// `raw_write` (mach_vm_protect) instead of Linux's `/proc` bypass.

fn task_read_u16(task: mach_port_t, addr: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    task_read_exact(task, addr, &mut b).then(|| u16::from_le_bytes(b))
}

fn task_read_u32(task: mach_port_t, addr: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    task_read_exact(task, addr, &mut b).then(|| u32::from_le_bytes(b))
}

/// Read `[addr, addr+size)` tolerating unmapped holes (zero-filled), via Mach —
/// the same shape as `read_mem`'s slow path, but usable while the cave lock is
/// held (no `SafeHandle` re-lock).
fn gather(task: mach_port_t, addr: u64, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    let end = addr + size as u64;
    let mut cur = addr;
    while cur < end {
        let (rstart, rsize, prot) = match region_at(task, cur) {
            Some(r) => r,
            None => break,
        };
        if rstart >= end {
            break;
        }
        let rend = rstart + rsize;
        if prot & VM_PROT_READ != 0 {
            let from = rstart.max(addr);
            let to = rend.min(end);
            if to > from {
                let s = (from - addr) as usize;
                let e = (to - addr) as usize;
                task_read_exact(task, from, &mut buf[s..e]);
            }
        }
        cur = if rend > cur { rend } else { cur + 1 };
    }
    buf
}

/// Base of the main `.exe` PE image (the region whose first bytes are `MZ` backed
/// by a `*.exe` file) in the target.
fn main_pe_base(task: mach_port_t, pid: u32) -> Option<u64> {
    let mut cur: u64 = 0;
    for _ in 0..1_000_000 {
        let (rstart, rsize, _prot) = match region_at(task, cur) {
            Some(r) => r,
            None => break,
        };
        if let Some(path) = region_filename(pid, rstart) {
            if basename(&path).to_lowercase().ends_with(".exe") {
                let mut mz = [0u8; 2];
                if task_read_exact(task, rstart, &mut mz) && &mz == b"MZ" {
                    return Some(rstart);
                }
            }
        }
        cur = if rstart + rsize > cur { rstart + rsize } else { cur + 1 };
    }
    None
}

/// Smallest trailing-padding run worth treating as a usable cave.
const MIN_CAVE: u64 = 0x400;

/// Bump allocator over one run of section padding, with a reuse free list.
/// Identical to the Linux `Cave` (platform/unix.rs).
struct Cave {
    next: u64,
    end: u64,
    live: HashMap<u64, u64>,
    free_list: Vec<(u64, u64)>,
}

impl Cave {
    fn new(next: u64, end: u64) -> Self {
        Cave {
            next,
            end,
            live: HashMap::new(),
            free_list: Vec::new(),
        }
    }

    fn take(&mut self, size: usize) -> MemOpResult<u64> {
        if let Some(i) = self.free_list.iter().position(|&(_, cap)| cap >= size as u64) {
            let (a, cap) = self.free_list.swap_remove(i);
            self.live.insert(a, cap);
            Ok(a)
        } else {
            let a = (self.next + 15) & !15;
            if a + size as u64 > self.end {
                return Err(MemOpError::Message(format!(
                    "code cave exhausted: {} bytes left, {} wanted",
                    self.end.saturating_sub(a),
                    size
                )));
            }
            self.next = a + size as u64;
            self.live.insert(a, size as u64);
            Ok(a)
        }
    }
}

/// Per-pid writable DATA cave + executable CODE cave (see the Linux `ProcCaves`).
#[derive(Default)]
struct ProcCaves {
    data: Option<Cave>,
    code: Option<Cave>,
}

static CAVES: OnceLock<Mutex<HashMap<u32, ProcCaves>>> = OnceLock::new();

fn caves() -> &'static Mutex<HashMap<u32, ProcCaves>> {
    CAVES.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Carve a cave from the target PE's section padding (same strategy as Linux):
/// `writable=true` → the alignment gap after a writable section's content (safe
/// scratch the target can write); `writable=false` → trailing zero padding of the
/// executable sections (`.text` slack, within rel32 of code). Reads via Mach.
fn find_cave(task: mach_port_t, pid: u32, writable: bool) -> MemOpResult<Cave> {
    let base = main_pe_base(task, pid)
        .ok_or_else(|| MemOpError::Message("no .exe PE image mapped in target".into()))?;

    let lfanew = task_read_u32(task, base + 0x3C)
        .ok_or_else(|| MemOpError::Message("cannot read e_lfanew".into()))? as u64;
    let mut sig = [0u8; 4];
    if !task_read_exact(task, base + lfanew, &mut sig) || &sig != b"PE\0\0" {
        return Err(MemOpError::Message("main module is not a PE".into()));
    }
    let num_sections = task_read_u16(task, base + lfanew + 6)
        .ok_or_else(|| MemOpError::Message("cannot read NumberOfSections".into()))?;
    let opt_hdr_size = task_read_u16(task, base + lfanew + 20)
        .ok_or_else(|| MemOpError::Message("cannot read SizeOfOptionalHeader".into()))?;
    let sec_table = base + lfanew + 24 + opt_hdr_size as u64;

    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    let want = if writable {
        IMAGE_SCN_MEM_WRITE
    } else {
        IMAGE_SCN_MEM_EXECUTE
    };

    let mut secs: Vec<(u64, u64, bool)> = Vec::new();
    for i in 0..num_sections as u64 {
        let sh = sec_table + i * 40;
        let vsize = task_read_u32(task, sh + 8).unwrap_or(0) as u64;
        let vaddr = task_read_u32(task, sh + 12).unwrap_or(0) as u64;
        let chars = task_read_u32(task, sh + 36).unwrap_or(0);
        if vsize == 0 {
            continue;
        }
        secs.push((vaddr, vsize, chars & want != 0));
    }
    secs.sort_by_key(|s| s.0);

    let mut best: Option<(u64, u64)> = None;
    for (idx, &(vaddr, vsize, matches)) in secs.iter().enumerate() {
        if !matches {
            continue;
        }
        let sec_start = base + vaddr;
        let content_end = sec_start + vsize;
        let span_end = match secs.get(idx + 1) {
            Some(&(next_vaddr, _, _)) => base + next_vaddr,
            None => content_end,
        };
        let pad_start = if writable {
            content_end
        } else {
            let span_len = (span_end - sec_start) as usize;
            let data = gather(task, sec_start, span_len);
            match data.iter().rposition(|&b| b != 0) {
                Some(i) => sec_start + i as u64 + 1,
                None => sec_start,
            }
        };
        let run = span_end.saturating_sub(pad_start);
        if run >= MIN_CAVE && best.map_or(true, |(s, e)| (e - s) < run) {
            best = Some((pad_start, span_end));
        }
    }

    let (start, end) = best.ok_or_else(|| {
        MemOpError::Message(format!(
            "no {} padding >= {MIN_CAVE:#x} bytes found for a cave",
            if writable { "writable-section" } else { "executable-section" }
        ))
    })?;
    Ok(Cave::new(start, end))
}

/// Allocate writable DATA scratch (buffers the target writes into, the RPC `done`
/// byte). Carved from a writable section's padding, so plain writes land.
pub fn alloc(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let (task, pid) = (guard.task, guard.pid);
    let mut map = caves().lock();
    let pc = map.entry(pid).or_default();
    if pc.data.is_none() {
        pc.data = Some(find_cave(task, pid, true)?);
    }
    let addr = pc.data.as_mut().unwrap().take(size)?;
    raw_write(task, addr, &vec![0u8; size])?;
    Ok(addr as usize)
}

/// Allocate EXECUTABLE CODE scratch (injected code, trampolines). Carved from
/// `.text` slack, or the region supplied via [`register_cave`] (wizwalker's
/// autobot). Writes go through `raw_write`, which flips protection for the r-x
/// page.
pub fn alloc_code(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let (task, pid) = (guard.task, guard.pid);
    let mut map = caves().lock();
    let pc = map.entry(pid).or_default();
    if pc.code.is_none() {
        pc.code = Some(find_cave(task, pid, false)?);
    }
    let addr = pc.code.as_mut().unwrap().take(size)?;
    raw_write(task, addr, &vec![0u8; size])?;
    Ok(addr as usize)
}

/// No-op (parity with Linux): reclamation is explicit via [`reclaim_cave`].
pub fn free(_handle: &SafeHandle, _addr: usize, _size: usize) -> MemOpResult<()> {
    Ok(())
}

/// Return a cave block for reuse. Idempotent; checks both caves.
pub fn reclaim_cave(handle: &SafeHandle, addr: usize) -> MemOpResult<()> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let pid = guard.pid;
    let mut map = caves().lock();
    if let Some(pc) = map.get_mut(&pid) {
        for cave in [pc.data.as_mut(), pc.code.as_mut()].into_iter().flatten() {
            if let Some(cap) = cave.live.remove(&(addr as u64)) {
                cave.free_list.push((addr as u64, cap));
                break;
            }
        }
    }
    Ok(())
}

/// Register an explicit executable CODE cave (wizwalker's autobot), overriding the
/// auto-discovered one; the data cave is untouched.
pub fn register_cave(handle: &SafeHandle, start: usize, size: usize) -> MemOpResult<()> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    caves().lock().entry(guard.pid).or_default().code =
        Some(Cave::new(start as u64, (start + size) as u64));
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
