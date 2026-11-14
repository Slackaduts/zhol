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

use anyhow::anyhow;

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
        .map_err(|e| MemOpError::Os((format!("open /proc/{pid}/mem: {e}"), None)))?;
    Ok(Target { pid, mem })
}

/// Produce the current OS error as a `MemOpError`.
pub fn last_error() -> MemOpError {
    MemOpError::Os((std::io::Error::last_os_error().to_string(), None))
}

fn acquire<'a>(
    handle: &'a SafeHandle,
    timeout: Option<Duration>,
) -> MemOpResult<crate::process::SafeHandleGuard<'a>> {
    handle
        .acquire_with_timeout(timeout)
        .ok_or(MemOpError::TimeoutReached((timeout, None)))
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
                return Err(MemOpError::Os((
                    format!("no readable memory in [{addr:#x}, {end:#x})"),
                    None,
                )));
            }
            Ok(buf)
        }
        Err(e) => Err(MemOpError::Os((format!("read @ {addr:#x}: {e}"), None))),
    }
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
        .map_err(|e| MemOpError::Os((format!("write @ {addr:#x}: {e}"), None)))?;
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
        .map_err(|e| MemOpError::Os((format!("read /proc/{pid}/maps: {e}"), None)))?;
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
                writable: r.writable,
                executable: r.executable,
                committed: true,
                guarded: false,
            });
        }
    }
    // Not mapped: report an uncommitted, inaccessible region at the address.
    Ok(Region {
        base: addr,
        size: 0,
        readable: false,
        writable: false,
        executable: false,
        committed: false,
        guarded: false,
    })
}

/// Smallest trailing-padding run worth treating as a usable cave.
const MIN_CAVE: u64 = 0x400;

/// A bump allocator over one run of executable-section padding in the target.
struct Cave {
    next: u64,
    end: u64,
}

/// Per-pid caves. Unix has no `VirtualAllocEx`: scratch for hook code and hook
/// variables is carved from the zero padding at the end of the main module's
/// executable sections. That padding lives inside the module, so it is always
/// within rel32 reach of the code being hooked (what `newmem_jmp` needs) and
/// needs no `ptrace`. The allocator bumps and never reclaims; `free` is a no-op
/// because a long-lived hook holds its memory for the process lifetime (and
/// `MemoryRegion` is `Clone`, so reclaiming on drop would be unsafe).
static CAVES: OnceLock<Mutex<HashMap<u32, Cave>>> = OnceLock::new();

fn caves() -> &'static Mutex<HashMap<u32, Cave>> {
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

/// Find the largest run of trailing zero padding across the executable sections
/// of the main `.exe` module, by parsing the PE section table from memory
/// (robust under Wine, where sections are anonymous rather than file-backed).
fn find_exe_cave(target: &Target) -> MemOpResult<Cave> {
    let regions = read_maps(target.pid)?;
    let base = regions
        .iter()
        .filter(|r| basename(&r.path).to_lowercase().ends_with(".exe"))
        .map(|r| r.start)
        .min()
        .ok_or_else(|| MemOpError::Other(anyhow!("no .exe module mapped in target")))?;
    let mem = &target.mem;

    let lfanew = read_u32_at(mem, base + 0x3C)
        .ok_or_else(|| MemOpError::Other(anyhow!("cannot read e_lfanew")))? as u64;
    let mut sig = [0u8; 4];
    mem.read_exact_at(&mut sig, base + lfanew)
        .map_err(|e| MemOpError::Os((format!("read PE sig: {e}"), None)))?;
    if &sig != b"PE\0\0" {
        return Err(MemOpError::Other(anyhow!("main module is not a PE")));
    }
    let num_sections = read_u16_at(mem, base + lfanew + 6)
        .ok_or_else(|| MemOpError::Other(anyhow!("cannot read NumberOfSections")))?;
    let opt_hdr_size = read_u16_at(mem, base + lfanew + 20)
        .ok_or_else(|| MemOpError::Other(anyhow!("cannot read SizeOfOptionalHeader")))?;
    let sec_table = base + lfanew + 24 + opt_hdr_size as u64;

    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

    // Collect (vaddr, vsize, executable) for every section, then sort by vaddr
    // so each section's true end-in-memory is the next section's start. The cave
    // lives in the zero padding from the last real byte of code to that end,
    // which spans both intra-section slack and the alignment gap before the next
    // section -- the padding a `maps`-only view would also see.
    let mut secs: Vec<(u64, u64, bool)> = Vec::new();
    for i in 0..num_sections as u64 {
        let sh = sec_table + i * 40;
        let vsize = read_u32_at(mem, sh + 8).unwrap_or(0) as u64;
        let vaddr = read_u32_at(mem, sh + 12).unwrap_or(0) as u64;
        let chars = read_u32_at(mem, sh + 36).unwrap_or(0);
        if vsize == 0 {
            continue;
        }
        secs.push((vaddr, vsize, chars & IMAGE_SCN_MEM_EXECUTE != 0));
    }
    secs.sort_by_key(|s| s.0);

    let mut best: Option<(u64, u64)> = None; // (pad_start, span_end)
    for (idx, &(vaddr, vsize, execf)) in secs.iter().enumerate() {
        if !execf {
            continue;
        }
        let sec_start = base + vaddr;
        let content_end = sec_start + vsize;
        // End of this section's mapped span: next section start, else image end.
        let span_end = match secs.get(idx + 1) {
            Some(&(next_vaddr, _, _)) => base + next_vaddr,
            None => content_end, // last section: only intra-section slack
        };
        // Find the last non-zero byte within the whole span.
        let span_len = (span_end - sec_start) as usize;
        let data = gather(mem, &regions, sec_start, span_len);
        let last_nonzero = data.iter().rposition(|&b| b != 0);
        let pad_start = match last_nonzero {
            Some(i) => sec_start + i as u64 + 1,
            None => sec_start,
        };
        let run = span_end - pad_start;
        if run >= MIN_CAVE && best.map_or(true, |(s, e)| (e - s) < run) {
            best = Some((pad_start, span_end));
        }
    }

    let (start, end) = best.ok_or_else(|| {
        MemOpError::Other(anyhow!(
            "no executable-section padding >= {MIN_CAVE:#x} bytes found for a code cave"
        ))
    })?;
    Ok(Cave { next: start, end })
}

/// Allocate `size` bytes of in-module scratch from the target's code cave.
pub fn alloc(handle: &SafeHandle, size: usize) -> MemOpResult<usize> {
    let guard = acquire(handle, Some(Duration::from_secs(2)))?;
    let pid = guard.pid;
    let mut map = caves().lock();
    if !map.contains_key(&pid) {
        let cave = find_exe_cave(&guard)?;
        map.insert(pid, cave);
    }
    let cave = map.get_mut(&pid).unwrap();

    // 16-byte align so code and variable blocks are naturally aligned.
    let addr = (cave.next + 15) & !15;
    if addr + size as u64 > cave.end {
        return Err(MemOpError::Other(anyhow!(
            "code cave exhausted: {} bytes left, {} wanted",
            cave.end.saturating_sub(addr),
            size
        )));
    }
    cave.next = addr + size as u64;

    guard
        .mem
        .write_all_at(&vec![0u8; size], addr)
        .map_err(|e| MemOpError::Os((format!("zero cave @ {addr:#x}: {e}"), None)))?;

    Ok(addr as usize)
}

/// No-op: cave space is not reclaimed (hooks are long-lived and `MemoryRegion`
/// is `Clone`, so zeroing on drop could clobber live scratch).
pub fn free(_handle: &SafeHandle, _addr: usize, _size: usize) -> MemOpResult<()> {
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
    caves().lock().insert(
        guard.pid,
        Cave {
            next: start as u64,
            end: (start + size) as u64,
        },
    );
    Ok(())
}
