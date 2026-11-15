//! Unix backend: process memory through `/proc/<pid>/mem` and `/proc/<pid>/maps`.
//!
//! This reaches a Windows game running under Wine/Proton the same way it reaches
//! a native process: the Wine process's address space *is* the game's, and
//! `/proc/<pid>/mem` exposes it. Writes go through the same file; the kernel's
//! `FOLL_FORCE` path lets a same-uid writer patch even read-only/executable
//! pages without `ptrace`, which is what hook installation needs.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::ErrorKind;
use std::os::unix::fs::FileExt;
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::Mutex;


use super::{Module, Protect, Region};
use crate::process::SafeHandle;
use crate::{MemOpError, MemOpResult};

/// Per-process handle: the pid plus an open, read/write `/proc/<pid>/mem`.
pub struct Target {
    pub pid: u32,
    mem: File,
}

unsafe impl Send for Target {}
unsafe impl Sync for Target {}

/// Open a target by pid. Fails if the process is gone or `/proc/<pid>/mem`
/// cannot be opened read/write (wrong uid, or yama/ptrace policy).
pub fn open(pid: u32) -> MemOpResult<Target> {
    let mem = OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/proc/{pid}/mem"))
        .map_err(|e| MemOpError::Os(format!("open /proc/{pid}/mem: {e}")))?;
    Ok(Target { pid, mem })
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

/// Read `size` bytes at `addr`. A single `pread` is tried first; if it straddles
/// an unmapped hole (common across a whole module image), the read falls back to
/// gathering each mapped sub-region into a zero-filled buffer so offsets stay
/// `base + offset`.
pub fn read_mem(
    handle: &SafeHandle,
    addr: usize,
    size: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Vec<u8>> {
    let guard = acquire(handle, timeout)?;
    let mem = &guard.mem;

    // Fast path: one `process_vm_readv` syscall (no file seek, no per-byte
    // FOLL_FORCE walk). Trusted only on a full-size transfer; a short read means
    // the range straddles an unmapped hole, so fall through to the hole-tolerant
    // `/proc/<pid>/mem` gather below, which preserves `base + offset` layout.
    #[cfg(target_os = "linux")]
    if let Some(buf) = vm_readv_exact(guard.pid, addr, size) {
        return Ok(buf);
    }

    let mut buf = vec![0u8; size];
    match mem.read_exact_at(&mut buf, addr as u64) {
        Ok(()) => Ok(buf),
        Err(e) if e.kind() == ErrorKind::UnexpectedEof || e.raw_os_error() == Some(libc::EIO) => {
            // Hole-tolerant gather: copy each readable region that overlaps
            // [addr, addr+size) into its slot, leaving zeros for the gaps.
            let regions = read_maps(guard.pid)?;
            let end = addr as u64 + size as u64;
            let mut any = false;
            for r in &regions {
                if !r.readable || r.end <= addr as u64 || r.start >= end {
                    continue;
                }
                let from = r.start.max(addr as u64);
                let to = r.end.min(end);
                let at = (from - addr as u64) as usize;
                let len = (to - from) as usize;
                if mem.read_exact_at(&mut buf[at..at + len], from).is_ok() {
                    any = true;
                }
            }
            if !any {
                return Err(MemOpError::Os(format!(
                    "no readable memory in [{addr:#x}, {end:#x})"
                )));
            }
            Ok(buf)
        }
        Err(e) => Err(MemOpError::Os(format!("read @ {addr:#x}: {e}"))),
    }
}

/// `process_vm_readv` fast path for one contiguous region. Returns the filled
/// buffer only on a full-size transfer; any short read (an unmapped hole in the
/// range, or `EPERM`/`ESRCH`) returns `None` so the caller falls back to the
/// hole-tolerant `/proc/<pid>/mem` gather. Drives off the pid, not the `mem` fd.
#[cfg(target_os = "linux")]
fn vm_readv_exact(pid: u32, addr: usize, size: usize) -> Option<Vec<u8>> {
    if size == 0 {
        return Some(Vec::new());
    }
    let mut buf = vec![0u8; size];
    let local = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: size,
    };
    let remote = libc::iovec {
        iov_base: addr as *mut libc::c_void,
        iov_len: size,
    };
    // Safety: the local iov points at `buf` (valid for `size` bytes); the remote
    // iov is only read by the kernel in the target's address space.
    let n = unsafe { libc::process_vm_readv(pid as libc::pid_t, &local, 1, &remote, 1, 0) };
    (n == size as isize).then_some(buf)
}

/// Batched read: fetch many `(addr, size)` regions in as few syscalls as
/// possible. One `process_vm_readv` carries up to `IOV_MAX` regions; any chunk
/// that doesn't fully transfer (a hole in one of its regions) is retried region
/// by region through the hole-tolerant [`read_mem`]. The per-handle lock is held
/// only to read the pid — the batched syscall itself needs no fd.
#[cfg(target_os = "linux")]
pub fn read_mem_many(
    handle: &SafeHandle,
    specs: &[(usize, usize)],
    timeout: Option<Duration>,
) -> MemOpResult<Vec<Vec<u8>>> {
    let pid = acquire(handle, timeout)?.pid;

    let mut bufs: Vec<Vec<u8>> = specs.iter().map(|&(_, size)| vec![0u8; size]).collect();

    const IOV_MAX: usize = 1024;
    let mut i = 0;
    while i < specs.len() {
        let end = (i + IOV_MAX).min(specs.len());
        let n = end - i;

        let mut locals: Vec<libc::iovec> = Vec::with_capacity(n);
        let mut remotes: Vec<libc::iovec> = Vec::with_capacity(n);
        let mut expected: usize = 0;
        for j in i..end {
            let (addr, size) = specs[j];
            locals.push(libc::iovec {
                iov_base: bufs[j].as_mut_ptr() as *mut libc::c_void,
                iov_len: size,
            });
            remotes.push(libc::iovec {
                iov_base: addr as *mut libc::c_void,
                iov_len: size,
            });
            expected += size;
        }

        // Safety: `locals` points into `bufs` (not resized during the call); the
        // remote iovecs are only read within the target's address space.
        let got = unsafe {
            libc::process_vm_readv(
                pid as libc::pid_t,
                locals.as_ptr(),
                n as libc::c_ulong,
                remotes.as_ptr(),
                n as libc::c_ulong,
                0,
            )
        };

        if got != expected as isize {
            // Partial/failed batch: redo this chunk through the hole-tolerant path
            // so a single unmapped region doesn't fail (or desync) the rest.
            for j in i..end {
                let (addr, size) = specs[j];
                bufs[j] = read_mem(handle, addr, size, timeout)?;
            }
        }
        i = end;
    }

    Ok(bufs)
}

/// Write `bytes` at `addr`. Page protection is irrelevant: `/proc/<pid>/mem`
/// writes land on read-only and executable pages for a same-uid writer.
pub fn write_mem(
    handle: &SafeHandle,
    addr: usize,
    bytes: &[u8],
    timeout: Option<Duration>,
) -> MemOpResult<usize> {
    let guard = acquire(handle, timeout)?;
    guard
        .mem
        .write_all_at(bytes, addr as u64)
        .map_err(|e| MemOpError::Os(format!("write @ {addr:#x}: {e}")))?;
    Ok(bytes.len())
}

/// One parsed line of `/proc/<pid>/maps`.
struct MapRegion {
    start: u64,
    end: u64,
    readable: bool,
    writable: bool,
    executable: bool,
    path: String,
}

/// Fields are single-space separated up to the path, which can itself contain
/// spaces (Proton's directories do), so the first five fields are split off and
/// the remainder is the path.
fn parse_maps_line(line: &str) -> Option<MapRegion> {
    let mut rest = line;
    let mut fields = [""; 5];
    for field in fields.iter_mut() {
        rest = rest.trim_start_matches(' ');
        let end = rest.find(' ')?;
        *field = &rest[..end];
        rest = &rest[end..];
    }
    let (start, end) = fields[0].split_once('-')?;
    let perms = fields[1].as_bytes();
    Some(MapRegion {
        start: u64::from_str_radix(start, 16).ok()?,
        end: u64::from_str_radix(end, 16).ok()?,
        readable: perms.first() == Some(&b'r'),
        writable: perms.get(1) == Some(&b'w'),
        executable: perms.get(2) == Some(&b'x'),
        path: rest.trim().to_string(),
    })
}

fn read_maps(pid: u32) -> MemOpResult<Vec<MapRegion>> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .map_err(|e| MemOpError::Os(format!("read /proc/{pid}/maps: {e}")))?;
    Ok(raw.lines().filter_map(parse_maps_line).collect())
}

/// Basename of a Windows-or-Unix path (splits on both separators).
fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\']).next().unwrap_or(path)
}

/// PE `SizeOfImage` for an image mapped at `base`, read straight from the
/// in-memory header. Wine's preloader maps only the PE header from the file and
/// lays sections out as anonymous memory, so `maps` cannot tell us the extent;
/// the header can. Returns `None` for non-PE mappings (ELF `.so`, etc.).
fn pe_image_size(mem: &File, base: u64) -> Option<usize> {
    let mut mz = [0u8; 2];
    mem.read_exact_at(&mut mz, base).ok()?;
    if &mz != b"MZ" {
        return None;
    }
    let mut lfanew = [0u8; 4];
    mem.read_exact_at(&mut lfanew, base + 0x3C).ok()?;
    let lfanew = u32::from_le_bytes(lfanew) as u64;
    let mut sig = [0u8; 4];
    mem.read_exact_at(&mut sig, base + lfanew).ok()?;
    if &sig != b"PE\0\0" {
        return None;
    }
    // SizeOfImage sits 56 bytes into the optional header, same offset for
    // PE32 and PE32+. Optional header starts at PE sig + 24.
    let mut soi = [0u8; 4];
    mem.read_exact_at(&mut soi, base + lfanew + 24 + 56).ok()?;
    Some(u32::from_le_bytes(soi) as usize)
}

/// Enumerate file-backed modules. Base is the lowest mapping of each path; size
/// is PE `SizeOfImage` when the image is a PE, else the span of its mappings.
pub fn enum_modules(handle: &SafeHandle, timeout: Option<Duration>) -> MemOpResult<Vec<Module>> {
    let guard = acquire(handle, timeout)?;
    let regions = read_maps(guard.pid)?;

    // Accumulate per distinct path: lowest start and highest end.
    let mut order: Vec<String> = Vec::new();
    let mut spans: std::collections::HashMap<String, (u64, u64)> = std::collections::HashMap::new();
    for r in &regions {
        if r.path.is_empty() || r.path.starts_with('[') {
            continue;
        }
        let entry = spans.entry(r.path.clone()).or_insert_with(|| {
            order.push(r.path.clone());
            (r.start, r.end)
        });
        entry.0 = entry.0.min(r.start);
        entry.1 = entry.1.max(r.end);
    }

    let mut modules = Vec::with_capacity(order.len());
    for path in order {
        let (start, end) = spans[&path];
        let size = pe_image_size(&guard.mem, start).unwrap_or((end - start) as usize);
        modules.push(Module {
            name: basename(&path).to_string(),
            base: start as usize,
            size,
        });
    }
    Ok(modules)
}

/// Query the region containing `addr` from `/proc/<pid>/maps`.
pub fn query_region(
    handle: &SafeHandle,
    addr: usize,
    timeout: Option<Duration>,
) -> MemOpResult<Region> {
    let guard = acquire(handle, timeout)?;
    let regions = read_maps(guard.pid)?;
    for r in &regions {
        if (addr as u64) >= r.start && (addr as u64) < r.end {
            return Ok(Region {
                base: r.start as usize,
                size: (r.end - r.start) as usize,
                readable: r.readable,
                // On this backend every mapped, readable page is writable: a
                // `/proc/<pid>/mem` write with FOLL_FORCE bypasses the page's
                // write bit (copy-on-write on a read-only file mapping, direct
                // otherwise). Reporting the raw maps `w` bit here would make the
                // readiness wait busy-spin to its timeout before every write
                // into r-x code (hook trampolines, the autobot) — the 5 s/op
                // that made hooking appear to hang.
                writable: r.readable,
                executable: r.executable,
                committed: true,
                guarded: false,
            });
        }
    }
    // Not mapped: report an uncommitted region spanning the gap up to the next
    // mapping, so a region-walking scanner advances past the hole instead of
    // stalling on a zero-size region. If nothing lies above, span to the top of
    // user address space so the walk terminates.
    const USER_TOP: u64 = 0x7FFF_FFFF_0000;
    let next = regions
        .iter()
        .map(|r| r.start)
        .filter(|&s| s > addr as u64)
        .min()
        .unwrap_or(USER_TOP);
    Ok(Region {
        base: addr,
        size: next.saturating_sub(addr as u64) as usize,
        readable: false,
        writable: false,
        executable: false,
        committed: false,
        guarded: false,
    })
}

/// Smallest trailing-padding run worth treating as a usable cave.
const MIN_CAVE: u64 = 0x400;

/// A bump allocator over one run of executable-section padding in the target,
/// with a free list so reclaimed blocks are reused before the arena grows.
struct Cave {
    next: u64,
    end: u64,
    /// addr -> capacity of blocks currently handed out, so `reclaim_cave(addr)`
    /// recovers the size without the caller tracking it.
    live: HashMap<u64, u64>,
    /// (addr, capacity) blocks returned via `reclaim_cave`, reused before bumping.
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

    /// Reserve `size` bytes, returning the chosen address. Reuses a reclaimed
    /// block big enough (first-fit) before bumping the arena, so repeated
    /// install/remove cycles (freecam toggles, RPC shellcode) don't exhaust it.
    fn take(&mut self, size: usize) -> MemOpResult<u64> {
        if let Some(i) = self.free_list.iter().position(|&(_, cap)| cap >= size as u64) {
            // A reused block keeps its original capacity, so a later reclaim
            // returns the whole thing.
            let (a, cap) = self.free_list.swap_remove(i);
            self.live.insert(a, cap);
            Ok(a)
        } else {
            // 16-byte align so code and variable blocks are naturally aligned.
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

/// Per-pid caves: a writable DATA cave for buffers the target writes into and a
/// separate executable CODE cave for injected code/trampolines. Unix has no
/// `VirtualAllocEx`: scratch is carved from the main module's section padding —
/// the data cave from a writable section's alignment gap (so the target's own
/// `mov [export], reg` lands), the code cave from `.text` slack (so it stays
/// within rel32 reach of the hooked site, and `/proc` writes populate it past
/// its r-x protection). Each is discovered lazily; `register_cave` overrides the
/// code cave (wizwalker's "autobot") for targets whose `.text` padding is too
/// small. Blocks are reclaimed explicitly, never on drop (`MemoryRegion` is
/// `Clone`, so a drop-reclaim would double-free a cloned region).
#[derive(Default)]
struct ProcCaves {
    data: Option<Cave>,
    code: Option<Cave>,
}

static CAVES: OnceLock<Mutex<HashMap<u32, ProcCaves>>> = OnceLock::new();

fn caves() -> &'static Mutex<HashMap<u32, ProcCaves>> {
    CAVES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn read_u16_at(mem: &File, addr: u64) -> Option<u16> {
    let mut b = [0u8; 2];
    mem.read_exact_at(&mut b, addr).ok()?;
    Some(u16::from_le_bytes(b))
}

fn read_u32_at(mem: &File, addr: u64) -> Option<u32> {
    let mut b = [0u8; 4];
    mem.read_exact_at(&mut b, addr).ok()?;
    Some(u32::from_le_bytes(b))
}

/// Read `[addr, addr+size)` tolerating unmapped holes (zero-filled).
fn gather(mem: &File, regions: &[MapRegion], addr: u64, size: usize) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    let end = addr + size as u64;
    for r in regions {
        if !r.readable || r.end <= addr || r.start >= end {
            continue;
        }
        let from = r.start.max(addr);
        let to = r.end.min(end);
        let at = (from - addr) as usize;
        let len = (to - from) as usize;
        let _ = mem.read_exact_at(&mut buf[at..at + len], from);
    }
    buf
}

/// Find a code/data cave in the main `.exe` module by parsing its PE section
/// table from memory (robust under Wine, where sections are anonymous rather
/// than file-backed).
///
/// `writable` selects which kind of scratch is carved:
///
/// - `false` (code): the largest run of trailing zero padding across the
///   *executable* sections. Suitable for injected code that runs in place and
///   must sit within rel32 reach of `.text`. This padding is `.text` slack, so
///   it is never a live variable.
///
/// - `true` (data): the alignment gap *after* a *writable* section's content,
///   i.e. `[section_vaddr + VirtualSize, next_section_start)`. Suitable for the
///   export/variable buffers the *target itself* writes into: those bytes lie
///   beyond the section's VirtualSize, so they are never a program global, yet
///   the loader maps them with the section's read/write protection. Carving
///   from a writable section (rather than `.text`, which is mapped r-x) is what
///   lets the target's own `mov [export], reg` land instead of faulting.
fn find_cave(target: &Target, writable: bool) -> MemOpResult<Cave> {
    let regions = read_maps(target.pid)?;
    let base = regions
        .iter()
        .filter(|r| basename(&r.path).to_lowercase().ends_with(".exe"))
        .map(|r| r.start)
        .min()
        .ok_or_else(|| MemOpError::Message(format!("no .exe module mapped in target")))?;
    let mem = &target.mem;

    let lfanew = read_u32_at(mem, base + 0x3C)
        .ok_or_else(|| MemOpError::Message(format!("cannot read e_lfanew")))? as u64;
    let mut sig = [0u8; 4];
    mem.read_exact_at(&mut sig, base + lfanew)
        .map_err(|e| MemOpError::Os(format!("read PE sig: {e}")))?;
    if &sig != b"PE\0\0" {
        return Err(MemOpError::Message(format!("main module is not a PE")));
    }
    let num_sections = read_u16_at(mem, base + lfanew + 6)
        .ok_or_else(|| MemOpError::Message(format!("cannot read NumberOfSections")))?;
    let opt_hdr_size = read_u16_at(mem, base + lfanew + 20)
        .ok_or_else(|| MemOpError::Message(format!("cannot read SizeOfOptionalHeader")))?;
    let sec_table = base + lfanew + 24 + opt_hdr_size as u64;

    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;
    let want = if writable {
        IMAGE_SCN_MEM_WRITE
    } else {
        IMAGE_SCN_MEM_EXECUTE
    };

    // Collect (vaddr, vsize, matches-wanted-protection) for every section, then
    // sort by vaddr so each section's true end-in-memory is the next section's
    // start.
    let mut secs: Vec<(u64, u64, bool)> = Vec::new();
    for i in 0..num_sections as u64 {
        let sh = sec_table + i * 40;
        let vsize = read_u32_at(mem, sh + 8).unwrap_or(0) as u64;
        let vaddr = read_u32_at(mem, sh + 12).unwrap_or(0) as u64;
        let chars = read_u32_at(mem, sh + 36).unwrap_or(0);
        if vsize == 0 {
            continue;
        }
        secs.push((vaddr, vsize, chars & want != 0));
    }
    secs.sort_by_key(|s| s.0);

    let mut best: Option<(u64, u64)> = None; // (pad_start, span_end)
    for (idx, &(vaddr, vsize, matches)) in secs.iter().enumerate() {
        if !matches {
            continue;
        }
        let sec_start = base + vaddr;
        let content_end = sec_start + vsize;
        // End of this section's mapped span: next section start, else image end.
        let span_end = match secs.get(idx + 1) {
            Some(&(next_vaddr, _, _)) => base + next_vaddr,
            None => content_end, // last section: only intra-section slack
        };
        let pad_start = if writable {
            // Only the alignment gap beyond VirtualSize is safe: everything from
            // sec_start to content_end can be a live (currently-zero) global,
            // including .bss the target zero-fills and later writes. The gap is
            // never addressed by the program, so carving it cannot clobber data
            // nor be clobbered.
            content_end
        } else {
            // Code: the zero padding from the last real byte of code to the
            // span end. `.text` has no trailing zero globals, so the whole run
            // of zeros (intra-section slack plus the alignment gap) is free.
            let span_len = (span_end - sec_start) as usize;
            let data = gather(mem, &regions, sec_start, span_len);
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

/// Allocate `size` bytes of writable in-module scratch from the target's DATA
/// cave — a writable section's alignment padding, so the target can write into
/// it (hook export/variable buffers referenced by absolute address, the RPC
/// `done` byte). Injected *code* comes from [`alloc_code`] instead.
pub fn alloc(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let pid = guard.pid;
    let mut map = caves().lock();
    let pc = map.entry(pid).or_default();
    if pc.data.is_none() {
        pc.data = Some(find_cave(&guard, true)?);
    }
    let addr = pc.data.as_mut().unwrap().take(size)?;

    guard
        .mem
        .write_all_at(&vec![0u8; size], addr)
        .map_err(|e| MemOpError::Os(format!("zero cave @ {addr:#x}: {e}")))?;

    Ok(addr as usize)
}

/// Allocate `size` bytes of EXECUTABLE in-module scratch from the target's CODE
/// cave — `.text` slack, or the region supplied via [`register_cave`]. This is
/// where injected code and trampolines live: `/proc` writes populate it past its
/// r-x protection, and the target executes it in place within rel32 of `.text`.
pub fn alloc_code(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let pid = guard.pid;
    let mut map = caves().lock();
    let pc = map.entry(pid).or_default();
    if pc.code.is_none() {
        pc.code = Some(find_cave(&guard, false)?);
    }
    let addr = pc.code.as_mut().unwrap().take(size)?;

    guard
        .mem
        .write_all_at(&vec![0u8; size], addr)
        .map_err(|e| MemOpError::Os(format!("zero cave @ {addr:#x}: {e}")))?;

    Ok(addr as usize)
}

/// No-op: see [`reclaim_cave`]. Kept a no-op because `MemoryRegion` is `Clone`
/// and calls this on drop — reclaiming here would double-free a cloned region.
pub fn free(_handle: &SafeHandle, _addr: usize, _size: usize) -> MemOpResult<()> {
    Ok(())
}

/// Return a cave block (from [`alloc`]) for reuse. Idempotent: an address that is
/// not currently live is ignored. This — not the no-op [`free`] — is what
/// reclaims cave space, so it is driven explicitly (Python `Process.free`,
/// managed-hook teardown) and never from `MemoryRegion::drop`, side-stepping the
/// Clone-on-drop double-free hazard.
pub fn reclaim_cave(handle: &SafeHandle, addr: usize) -> MemOpResult<()> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let pid = guard.pid;
    let mut map = caves().lock();
    if let Some(pc) = map.get_mut(&pid) {
        // The block belongs to exactly one of the two caves; return it there.
        for cave in [pc.data.as_mut(), pc.code.as_mut()].into_iter().flatten() {
            if let Some(cap) = cave.live.remove(&(addr as u64)) {
                cave.free_list.push((addr as u64, cap));
                break;
            }
        }
    }
    Ok(())
}

/// No-op: `/proc/<pid>/mem` writes ignore page protection, so there is nothing
/// to change or restore. Returns the requested value for signature parity.
pub fn protect(
    _handle: &SafeHandle,
    _addr: usize,
    _size: usize,
    _timeout: Option<Duration>,
    prot: Protect,
) -> MemOpResult<Protect> {
    Ok(prot)
}

/// Register an explicit code-cave arena for a target, overriding the
/// auto-discovered one. Games with a tightly-packed `.text` (Wizard101 among
/// them) expose a larger reusable region elsewhere — wizwalker's "autobot",
/// found by pattern scan — that the caller can hand in here so hook allocation
/// draws from it instead of the small section padding.
pub fn register_cave(handle: &SafeHandle, start: usize, size: usize) -> MemOpResult<()> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    // Override the executable CODE cave; the writable data cave is untouched.
    caves().lock().entry(guard.pid).or_default().code =
        Some(Cave::new(start as u64, (start + size) as u64));
    Ok(())
}
