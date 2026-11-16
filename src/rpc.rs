//! One-shot thread-hijack RPC.
//!
//! Runs caller-supplied `shellcode` exactly once on one of the target's OWN
//! threads — no `CreateRemoteThread`, no `ptrace`. A self-restoring trampoline is
//! planted over a per-frame call `site` the caller supplies (e.g. wizwalker's
//! movement-update call site). The next time that site executes, the trampoline
//! saves every volatile register + flags, 16-aligns the stack, calls the
//! shellcode once (guarded by a `done` byte so it fires a single time), restores
//! everything, re-runs the displaced original bytes, and jumps back past them.
//! Meanwhile this function polls the `done` byte and, once it flips (or the
//! timeout elapses), unplants the site.
//!
//! ## Why hand-emitted bytes, not dynasm
//! The emitted trampoline is byte-for-byte the layout wizwalker's Python
//! `_build_rpc_trampoline` produces, which is validated against a live client.
//! This is a *fixed* template, not dynamic codegen, and it can't be exercised in
//! a unit test (executing it hijacks a thread) while a subtly wrong encoding
//! crashes the game — so byte-identity with the proven reference is a stronger
//! correctness guarantee here than re-deriving the sequence through an assembler.
//!
//! ## Reach / caller contract
//! The trampoline is placed in a code cave; the `E9 rel32` plant at the site must
//! reach it (±2 GiB), so the caller should `register_cave` a region near the
//! hijack site (wizwalker's autobot is in the module's own `.text`, next to the
//! site). `orig_len` bytes at the site must be whole instructions and
//! position-independent (no RIP-relative/rel operands in the replaced range).
//!
//! ## Lifetime
//! The site is restored and every cave slot reclaimed on *every* return path
//! (success, timeout, error, or panic) via an internal RAII guard. Because the
//! Python `Process` borrows `&self` across the call, it cannot be torn down
//! mid-flight, so the synchronous design is inherently drop-safe. SIGKILL / a hard
//! crash still can't be covered — no destructor runs.

use std::time::{Duration, Instant};


use crate::memory::read::read_bytes;
use crate::memory::write::write_bytes;
use crate::platform;
use crate::process::SafeHandle;
use crate::{MemOpError, MemOpResult};

const T: Option<Duration> = Some(Duration::from_secs(5));
#[cfg(not(target_os = "macos"))]
/// Length of an `E9 rel32` near jump.
const JMP_LEN: usize = 5;

#[cfg(not(target_os = "macos"))]
fn rel32(from_after: i64, to: i64) -> Result<i32, MemOpError> {
    let d = to - from_after;
    if d < i32::MIN as i64 || d > i32::MAX as i64 {
        return Err(MemOpError::Message(format!(
            "trampoline {to:#x} out of rel32 reach of site {from_after:#x} (delta {d}); \
             register a code cave within +/-2GiB of the hijack site"
        )));
    }
    Ok(d as i32)
}

/// Build the one-shot, self-restoring trampoline. Byte-identical to wizwalker's
/// proven `_build_rpc_trampoline(done, shell, orig, ret)`.
///
/// Layout: save volatile regs+flags; if `done != 0` skip the call; else 16-align
/// the stack, `call shell` once, set `done = 1`; restore regs+flags; re-run the
/// displaced `orig` bytes; `jmp [ret_addr]`.
#[cfg(not(target_os = "macos"))]
fn build_trampoline(done_addr: usize, shell_addr: usize, orig: &[u8], ret_addr: usize) -> Vec<u8> {
    let done = (done_addr as u64).to_le_bytes();
    let shell = (shell_addr as u64).to_le_bytes();
    let ret = (ret_addr as u64).to_le_bytes();

    // The guarded block: aligned, one-shot call to the shellcode, then done=1.
    let mut guarded = Vec::new();
    guarded.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0]); // push rbp; mov rbp,rsp; and rsp,-16
    guarded.extend_from_slice(&[0x48, 0xB8]);
    guarded.extend_from_slice(&shell); // mov rax, shell_addr
    guarded.extend_from_slice(&[0xFF, 0xD0]); // call rax
    guarded.extend_from_slice(&[0x48, 0x89, 0xEC, 0x5D]); // mov rsp,rbp; pop rbp
    guarded.extend_from_slice(&[0x48, 0xB8]);
    guarded.extend_from_slice(&done); // mov rax, done_addr
    guarded.extend_from_slice(&[0xC6, 0x00, 0x01]); // mov byte[rax], 1
    debug_assert!(guarded.len() < 128, "guarded block must fit a jnz rel8");

    let mut out = Vec::new();
    // Save volatile regs + flags, then skip the guarded block if done != 0.
    out.extend_from_slice(&[
        0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x9C,
    ]); // push rax,rcx,rdx,r8,r9,r10,r11; pushfq
    out.extend_from_slice(&[0x48, 0xB8]);
    out.extend_from_slice(&done); // mov rax, done_addr
    out.extend_from_slice(&[0x80, 0x38, 0x00]); // cmp byte[rax], 0
    out.extend_from_slice(&[0x75, guarded.len() as u8]); // jnz +len(guarded)
    out.extend_from_slice(&guarded);
    // Restore flags + regs, re-run the displaced original, jump back.
    out.extend_from_slice(&[
        0x9D, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58,
    ]); // popfq; pop r11,r10,r9,r8,rdx,rcx,rax
    out.extend_from_slice(orig);
    out.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]); // jmp qword[rip+0]
    out.extend_from_slice(&ret); // dq ret_addr
    out
}

#[cfg(not(target_os = "macos"))]
/// Restores the site and reclaims cave slots on every exit path (incl. panic).
struct Cleanup<'a> {
    handle: &'a SafeHandle,
    site: usize,
    orig: Vec<u8>,
    planted: bool,
    slots: Vec<usize>,
}

#[cfg(not(target_os = "macos"))]
impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        // Panic-safe: a panic in drop aborts the process, so never unwrap here.
        if self.planted {
            let _ = write_bytes(self.handle, self.site, &self.orig, T);
        }
        for &slot in &self.slots {
            let _ = platform::reclaim_cave(self.handle, slot);
        }
    }
}

/// Run `shellcode` once on a target thread via a planted trampoline at `site`.
///
/// `orig_len` (>= 5) whole, position-independent bytes at `site` are displaced.
/// `done_addr` is the one-shot guard byte; pass 0 to have one allocated. Blocks,
/// polling up to `timeout`, then unplants. Returns whether the shellcode ran.
#[cfg(not(target_os = "macos"))]
pub fn rpc_via_hijack(
    handle: &SafeHandle,
    site: usize,
    shellcode: &[u8],
    orig_len: usize,
    done_addr: usize,
    timeout: Duration,
) -> MemOpResult<bool> {
    if orig_len < JMP_LEN {
        return Err(MemOpError::Message(format!(
            "orig_len {orig_len} < {JMP_LEN} (need room for an E9 rel32 plant)"
        )));
    }
    if shellcode.is_empty() {
        return Err(MemOpError::Message(format!("empty shellcode")));
    }

    let orig = read_bytes(handle, site, orig_len, T)?;
    let mut cu = Cleanup {
        handle,
        site,
        orig: orig.clone(),
        planted: false,
        slots: Vec::new(),
    };

    // Shellcode slot — EXECUTABLE (the trampoline calls it): code cave.
    let shell_addr = platform::alloc_code(handle, shellcode.len())?;
    cu.slots.push(shell_addr);
    write_bytes(handle, shell_addr, shellcode, T)?;

    // Guard byte (allocate one if the caller didn't supply it), zeroed. The
    // target writes it via its executing trampoline, so it must be WRITABLE:
    // data cave, not the r-x code cave.
    let done = if done_addr == 0 {
        let a = platform::alloc(handle, 8)?;
        cu.slots.push(a);
        a
    } else {
        done_addr
    };
    write_bytes(handle, done, &[0u8], T)?;

    // Trampoline slot — EXECUTABLE (the site jumps into it): code cave.
    let ret_addr = site + orig_len;
    let tramp = build_trampoline(done, shell_addr, &orig, ret_addr);
    let tramp_addr = platform::alloc_code(handle, tramp.len())?;
    cu.slots.push(tramp_addr);
    write_bytes(handle, tramp_addr, &tramp, T)?;

    // Plant the jump into the trampoline (point of no return → arm restore).
    let site_rel = rel32((site + JMP_LEN) as i64, tramp_addr as i64)?;
    let mut patch = Vec::with_capacity(orig_len);
    patch.push(0xE9);
    patch.extend_from_slice(&site_rel.to_le_bytes());
    patch.resize(orig_len, 0x90);
    write_bytes(handle, site, &patch, T)?;
    cu.planted = true;

    // Poll the guard byte until it flips or we time out.
    let start = Instant::now();
    let mut ran = false;
    while start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(5));
        if let Ok(b) = read_bytes(handle, done, 1, T) {
            if b.first().copied() == Some(1) {
                ran = true;
                break;
            }
        }
    }

    // `cu` drops here: restores the site and reclaims every slot.
    Ok(ran)
}


// ---- macOS: pointer-redirect RPC (Rosetta-safe) ----------------------------
// Inline code patching is ignored by Rosetta 2's cached translations, so on macOS
// we don't hijack a code `site`. Instead we redirect a hot import's IAT slot (a
// DATA pointer) to a fresh-page detour trampoline that runs `shellcode` once and
// tail-calls the original import. Fresh `mach_vm_allocate` pages are translated
// lazily on first execution; the 64-bit pointer reaches them with no rel32 limit.

/// Win64 detour: run `shell` once (guarded by `done`), preserving the import's arg
/// registers, then tail-call `original`. Entry rsp is 16n+8 (post-`call [slot]`).
#[cfg(target_os = "macos")]
fn build_detour(done: u64, shell: u64, original: u64) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&[0x51, 0x52, 0x41, 0x50, 0x41, 0x51]); // push rcx;rdx;r8;r9
    c.extend_from_slice(&[0x48, 0xB8]);
    c.extend_from_slice(&done.to_le_bytes()); // mov rax, done
    c.extend_from_slice(&[0x80, 0x38, 0x00]); // cmp byte[rax],0
    c.extend_from_slice(&[0x75, 0x29]); // jne +41 (skip guarded block)
    // guarded block (41 bytes): align, 32B shadow, call shell once, done=1
    c.extend_from_slice(&[0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xE4, 0xF0, 0x48, 0x83, 0xEC, 0x20]);
    c.extend_from_slice(&[0x48, 0xB8]);
    c.extend_from_slice(&shell.to_le_bytes()); // mov rax, shell
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    c.extend_from_slice(&[0x48, 0x89, 0xEC, 0x5D]); // mov rsp,rbp; pop rbp
    c.extend_from_slice(&[0x48, 0xB8]);
    c.extend_from_slice(&done.to_le_bytes()); // mov rax, done
    c.extend_from_slice(&[0xC6, 0x00, 0x01]); // mov byte[rax],1
    // skip:
    c.extend_from_slice(&[0x41, 0x59, 0x41, 0x58, 0x5A, 0x59]); // pop r9;r8;rdx;rcx
    c.extend_from_slice(&[0x48, 0xB8]);
    c.extend_from_slice(&original.to_le_bytes()); // mov rax, original
    c.extend_from_slice(&[0xFF, 0xE0]); // jmp rax
    c
}

/// Hot imports to redirect; whichever the target actually calls fires first. A
/// shared `done` guard makes the shellcode run exactly once across all of them.
#[cfg(target_os = "macos")]
const RPC_CANDIDATE_IMPORTS: &[&str] = &[
    "timeGetTime",
    "QueryPerformanceCounter",
    "GetTickCount64",
    "GetTickCount",
    "GetSystemTimeAsFileTime",
];

/// Per-pid cache of resolved (import slot, original pointer) pairs. Enumerating
/// modules + parsing the import table is the slow part of an RPC (~seconds); the
/// slots are stable per process and each is always restored to its original, so
/// caching is safe and keeps freecam toggles snappy.
#[cfg(target_os = "macos")]
static RPC_SLOTS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u32, Vec<(usize, u64)>>>,
> = std::sync::OnceLock::new();

#[cfg(target_os = "macos")]
fn macos_import_slots(handle: &SafeHandle) -> MemOpResult<Vec<(usize, u64)>> {
    use crate::process::module::{find_import_slot, get_named_modules};

    // pid — scoped so the guard drops before the re-locking reads below.
    let pid = {
        let g = handle.acquire_with_timeout(T).ok_or(MemOpError::Timeout(T))?;
        g.pid
    };

    let cache = RPC_SLOTS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&pid) {
        return Ok(v.clone());
    }

    let exe = get_named_modules(handle, T)?
        .into_iter()
        .find(|m| m.name.to_lowercase().ends_with(".exe"))
        .ok_or_else(|| MemOpError::Message("no .exe module in target".into()))?;

    let mut v: Vec<(usize, u64)> = Vec::new();
    for name in RPC_CANDIDATE_IMPORTS {
        if let Some(slot) = find_import_slot(handle, exe.base, name)? {
            let ob = read_bytes(handle, slot, 8, T)?;
            v.push((slot, u64::from_le_bytes(ob[..8].try_into().unwrap())));
        }
    }
    if v.is_empty() {
        return Err(MemOpError::Message(
            "no redirectable hot import found in target".into(),
        ));
    }
    cache.lock().unwrap().insert(pid, v.clone());
    Ok(v)
}

#[cfg(target_os = "macos")]
pub fn rpc_via_hijack(
    handle: &SafeHandle,
    _site: usize,
    shellcode: &[u8],
    _orig_len: usize,
    _done_addr: usize,
    timeout: Duration,
) -> MemOpResult<bool> {
    if shellcode.is_empty() {
        return Err(MemOpError::Message("empty shellcode".into()));
    }

    // Resolve the candidate import slots (and their original pointers) once per
    // process and cache them: enumerating 179 modules + parsing the import table on
    // every RPC cost ~5-8s, which would make a freecam toggle feel frozen. The IAT
    // slots are stable for a process, and we always restore each slot to its
    // original, so a cached original stays valid across calls.
    let slots = macos_import_slots(handle)?;

    let done = platform::alloc(handle, 8)?;
    write_bytes(handle, done, &[0u8; 8], T)?;
    let shell = platform::alloc_code(handle, shellcode.len())?;
    write_bytes(handle, shell, shellcode, T)?;

    // Redirect every candidate slot to its own detour trampoline.
    let mut hooked: Vec<(usize, u64, usize)> = Vec::new(); // (slot, original, tramp)
    for &(slot, original) in &slots {
        let tramp = platform::alloc_code(handle, 128)?;
        let code = build_detour(done as u64, shell as u64, original);
        write_bytes(handle, tramp, &code, T)?;
        write_bytes(handle, slot, &(tramp as u64).to_le_bytes(), T)?;
        hooked.push((slot, original, tramp));
    }

    // Poll the done byte up to the timeout.
    let start = Instant::now();
    let mut ran = false;
    while start.elapsed() < timeout {
        std::thread::sleep(Duration::from_millis(5));
        if read_bytes(handle, done, 1, T).map(|b| b[0] == 1).unwrap_or(false) {
            ran = true;
            break;
        }
    }

    // Restore every redirected slot so the game stops routing through us.
    for &(slot, original, _) in &hooked {
        let _ = write_bytes(handle, slot, &original.to_le_bytes(), T);
    }

    // IMPORTANT: do NOT free the executed pages (shellcode + trampolines) or the
    // done byte. Rosetta 2 caches translations BY ADDRESS; if a later RPC's
    // mach_vm_allocate reused a freed trampoline address, Rosetta would run the
    // stale translation of the PREVIOUS detour (writing the previous, now-freed
    // done byte) and the new RPC's done would never flip — so a second RPC in the
    // same process (e.g. freecam ON then OFF) would silently time out. Leaking
    // these small pages guarantees every RPC gets a never-before-translated
    // address. They're a few pages each; a whole session's toggles are negligible.
    // (The caller's shellcode *staging* block is separate and still freed by the
    // caller — it is never executed, so no stale translation applies to it.)

    Ok(ran)
}

// --- Guest W^X code writes (macOS / Rosetta) -------------------------------
//
// Under Rosetta 2, a cross-process `mach_vm_write` to an already-translated x86
// page is invisible to the translator, so an inline patch written from outside
// never takes effect. Rosetta only re-translates a page when the GUEST performs
// a W^X transition on it (make it writable+non-executable, write, make it
// executable again) — the same JIT-coherency path browsers use. Live-proven:
// patching a code site this way froze/unfroze the game's movement update, while
// both an external write and a guest RWX write (no W^X transition) did nothing.
//
// `write_code` builds that `VirtualProtect(RW) -> write -> VirtualProtect(RX) ->
// FlushInstructionCache` sequence as a shellcode function and runs it once via
// the existing one-shot RPC, which executes it on a fresh page AS THE GUEST. So
// callers patch `.text` through `write_code` and the patch actually takes hold.

/// Per-pid cache of (VirtualProtect, FlushInstructionCache) addresses in the
/// target's kernel32, resolved from its export table once (the scan is the slow
/// part; the addresses are stable per process).
#[cfg(target_os = "macos")]
static WX_FUNCS: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<u32, (u64, u64)>>,
> = std::sync::OnceLock::new();

/// Read a NUL-terminated ASCII export name at `addr` (bounded).
#[cfg(target_os = "macos")]
fn read_cstr(handle: &SafeHandle, addr: usize) -> MemOpResult<Vec<u8>> {
    let raw = read_bytes(handle, addr, 64, T)?;
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    Ok(raw[..end].to_vec())
}

/// Resolve an export by name from a PE module's export directory in the target.
/// Export names are sorted, so binary-search them (~log2(n) reads).
#[cfg(target_os = "macos")]
fn resolve_export(handle: &SafeHandle, base: usize, name: &str) -> MemOpResult<Option<u64>> {
    let u32_at = |off: usize| -> MemOpResult<u32> {
        let b = read_bytes(handle, off, 4, T)?;
        Ok(u32::from_le_bytes(b[..4].try_into().unwrap()))
    };
    let e_lfanew = u32_at(base + 0x3C)? as usize;
    let pe = base + e_lfanew;
    // PE32+ optional header starts at pe+24; DataDirectory[0] (export) is at +0x70.
    let exp_rva = u32_at(pe + 24 + 0x70)? as usize;
    if exp_rva == 0 {
        return Ok(None);
    }
    let ed = base + exp_rva;
    let hdr = read_bytes(handle, ed, 40, T)?;
    let num_names = u32::from_le_bytes(hdr[24..28].try_into().unwrap()) as usize;
    let addr_funcs = base + u32::from_le_bytes(hdr[28..32].try_into().unwrap()) as usize;
    let addr_names = base + u32::from_le_bytes(hdr[32..36].try_into().unwrap()) as usize;
    let addr_ords = base + u32::from_le_bytes(hdr[36..40].try_into().unwrap()) as usize;
    let target = name.as_bytes();
    let (mut lo, mut hi) = (0usize, num_names);
    while lo < hi {
        let mid = (lo + hi) / 2;
        let nrva = u32_at(addr_names + mid * 4)? as usize;
        let nm = read_cstr(handle, base + nrva)?;
        match nm.as_slice().cmp(target) {
            std::cmp::Ordering::Less => lo = mid + 1,
            std::cmp::Ordering::Greater => hi = mid,
            std::cmp::Ordering::Equal => {
                let ob = read_bytes(handle, addr_ords + mid * 2, 2, T)?;
                let ord = u16::from_le_bytes(ob[..2].try_into().unwrap()) as usize;
                let frva = u32_at(addr_funcs + ord * 4)? as u64;
                return Ok(Some(base as u64 + frva));
            }
        }
    }
    Ok(None)
}

/// Resolve + cache kernel32's VirtualProtect and FlushInstructionCache.
#[cfg(target_os = "macos")]
fn wx_funcs(handle: &SafeHandle) -> MemOpResult<(u64, u64)> {
    use crate::process::module::get_named_modules;
    let pid = {
        let g = handle.acquire_with_timeout(T).ok_or(MemOpError::Timeout(T))?;
        g.pid
    };
    let cache = WX_FUNCS.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()));
    if let Some(v) = cache.lock().unwrap().get(&pid) {
        return Ok(*v);
    }
    let k32 = get_named_modules(handle, T)?
        .into_iter()
        .find(|m| m.name.to_lowercase().ends_with("kernel32.dll"))
        .ok_or_else(|| MemOpError::Message("kernel32.dll not found in target".into()))?;
    let vp = resolve_export(handle, k32.base, "VirtualProtect")?
        .ok_or_else(|| MemOpError::Message("VirtualProtect not exported by kernel32".into()))?;
    let fic = resolve_export(handle, k32.base, "FlushInstructionCache")?
        .ok_or_else(|| MemOpError::Message("FlushInstructionCache not exported by kernel32".into()))?;
    cache.lock().unwrap().insert(pid, (vp, fic));
    Ok((vp, fic))
}

/// Emit one patch's W^X sequence into `c` (no prologue/epilogue): VirtualProtect
/// (addr,n,PAGE_READWRITE,&old@rsp+0x20) -> write `bytes` -> VirtualProtect(addr,n,
/// old,&old2@rsp+0x28) -> FlushInstructionCache(-1,addr,n). The RW(non-exec) -> RX
/// toggle is the W^X transition Rosetta re-translates on. The &old slots are reused
/// per patch (the old value is consumed by the restore before the next patch).
#[cfg(target_os = "macos")]
fn emit_wx_patch(c: &mut Vec<u8>, addr: u64, bytes: &[u8], vp: u64, fic: u64) {
    let n = bytes.len() as u32;
    c.extend_from_slice(&[0x48, 0xB9]); // mov rcx, addr
    c.extend_from_slice(&addr.to_le_bytes());
    c.push(0xBA); // mov edx, n
    c.extend_from_slice(&n.to_le_bytes());
    c.extend_from_slice(&[0x41, 0xB8, 0x04, 0x00, 0x00, 0x00]); // mov r8d, 0x04 PAGE_READWRITE
    c.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x20]); // lea r9,[rsp+0x20]
    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, VirtualProtect
    c.extend_from_slice(&vp.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, addr
    c.extend_from_slice(&addr.to_le_bytes());
    for (i, b) in bytes.iter().enumerate() {
        c.extend_from_slice(&[0xC6, 0x40, i as u8, *b]); // mov byte [rax+i], b  (i<128)
    }
    c.extend_from_slice(&[0x48, 0xB9]); // mov rcx, addr
    c.extend_from_slice(&addr.to_le_bytes());
    c.push(0xBA); // mov edx, n
    c.extend_from_slice(&n.to_le_bytes());
    c.extend_from_slice(&[0x44, 0x8B, 0x44, 0x24, 0x20]); // mov r8d,[rsp+0x20] (old)
    c.extend_from_slice(&[0x4C, 0x8D, 0x4C, 0x24, 0x28]); // lea r9,[rsp+0x28]
    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, VirtualProtect
    c.extend_from_slice(&vp.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
    c.extend_from_slice(&[0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF]); // mov rcx,-1
    c.extend_from_slice(&[0x48, 0xBA]); // mov rdx, addr
    c.extend_from_slice(&addr.to_le_bytes());
    c.extend_from_slice(&[0x49, 0xC7, 0xC0]); // mov r8, n (imm32 sign-extended)
    c.extend_from_slice(&(n as i32).to_le_bytes());
    c.extend_from_slice(&[0x48, 0xB8]); // mov rax, FlushInstructionCache
    c.extend_from_slice(&fic.to_le_bytes());
    c.extend_from_slice(&[0xFF, 0xD0]); // call rax
}

/// One patch, wrapped in a stack frame (shadow + two &old slots) and `ret`.
#[cfg(target_os = "macos")]
fn build_wx_shellcode(addr: u64, bytes: &[u8], vp: u64, fic: u64) -> Vec<u8> {
    let mut c: Vec<u8> = vec![0x48, 0x83, 0xEC, 0x48]; // sub rsp,0x48
    emit_wx_patch(&mut c, addr, bytes, vp, fic);
    c.extend_from_slice(&[0x48, 0x83, 0xC4, 0x48, 0xC3]); // add rsp,0x48 ; ret
    c
}

/// Many patches applied in ONE shellcode (one stack frame, each patch's full W^X
/// sequence in sequence, one `ret`) — so a whole batch of hook installs costs a
/// SINGLE RPC round trip instead of one per site.
#[cfg(target_os = "macos")]
fn build_wx_batch_shellcode(patches: &[(usize, Vec<u8>)], vp: u64, fic: u64) -> Vec<u8> {
    let mut c: Vec<u8> = vec![0x48, 0x83, 0xEC, 0x48]; // sub rsp,0x48
    for (addr, bytes) in patches {
        emit_wx_patch(&mut c, *addr as u64, bytes, vp, fic);
    }
    c.extend_from_slice(&[0x48, 0x83, 0xC4, 0x48, 0xC3]); // add rsp,0x48 ; ret
    c
}

/// Write `bytes` into executable target memory so the patch actually takes effect.
///
/// On macOS this runs a guest W^X write via the one-shot RPC (see the module note
/// above). The patch range should be whole and small (≤127 bytes; the page is
/// briefly non-executable). On Windows/Linux it is a plain memory write.
#[cfg(target_os = "macos")]
pub fn write_code(handle: &SafeHandle, addr: usize, bytes: &[u8]) -> MemOpResult<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    if bytes.len() > 127 {
        return Err(MemOpError::Message(
            "write_code: patch must be ≤127 bytes (one W^X shellcode call)".into(),
        ));
    }
    let (vp, fic) = wx_funcs(handle)?;
    let shell = build_wx_shellcode(addr as u64, bytes, vp, fic);
    let ran = rpc_via_hijack(handle, 0, &shell, 0, 0, Duration::from_secs(5))?;
    if !ran {
        return Err(MemOpError::Message(
            "write_code: guest W^X RPC did not run within timeout".into(),
        ));
    }
    Ok(())
}

/// Apply many code patches in ONE guest W^X RPC (macOS). Installing a batch of
/// inline hooks this way costs a single RPC round trip instead of one per site —
/// the dominant attach cost when the target is throttled in the background.
#[cfg(target_os = "macos")]
pub fn write_code_batch(handle: &SafeHandle, patches: &[(usize, Vec<u8>)]) -> MemOpResult<()> {
    let patches: Vec<(usize, Vec<u8>)> = patches
        .iter()
        .filter(|(_, b)| !b.is_empty())
        .cloned()
        .collect();
    if patches.is_empty() {
        return Ok(());
    }
    if patches.iter().any(|(_, b)| b.len() > 127) {
        return Err(MemOpError::Message(
            "write_code_batch: each patch must be ≤127 bytes".into(),
        ));
    }
    let (vp, fic) = wx_funcs(handle)?;
    let shell = build_wx_batch_shellcode(&patches, vp, fic);
    let ran = rpc_via_hijack(handle, 0, &shell, 0, 0, Duration::from_secs(5))?;
    if !ran {
        return Err(MemOpError::Message(
            "write_code_batch: guest W^X RPC did not run within timeout".into(),
        ));
    }
    Ok(())
}

/// Plain memory write on non-macOS platforms (no Rosetta translation to invalidate).
#[cfg(not(target_os = "macos"))]
pub fn write_code(handle: &SafeHandle, addr: usize, bytes: &[u8]) -> MemOpResult<()> {
    write_bytes(handle, addr, bytes, T)?;
    Ok(())
}

/// Plain per-patch writes on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn write_code_batch(handle: &SafeHandle, patches: &[(usize, Vec<u8>)]) -> MemOpResult<()> {
    for (addr, bytes) in patches {
        write_bytes(handle, *addr, bytes, T)?;
    }
    Ok(())
}

#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use super::*;

    #[test]
    fn trampoline_layout() {
        let orig = [0x48, 0x8B, 0xC4, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56]; // 10 bytes
        let t = build_trampoline(0x1111_2222_3333_4444, 0x5555_6666_7777_8888, &orig, 0x9999_AAAA_BBBB_CCCC);

        // Opens with: push rax,rcx,rdx,r8,r9,r10,r11; pushfq.
        assert_eq!(
            &t[..12],
            &[0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x9C]
        );
        // mov rax, done_addr (abs64) immediately after.
        assert_eq!(&t[12..14], &[0x48, 0xB8]);
        assert_eq!(&t[14..22], &0x1111_2222_3333_4444u64.to_le_bytes());
        // cmp byte[rax],0 ; jnz rel8 over the guarded block.
        assert_eq!(&t[22..25], &[0x80, 0x38, 0x00]);
        assert_eq!(t[25], 0x75);
        let guarded_len = t[26] as usize;
        // The displaced original appears verbatim before the final jump-back.
        let tail_jmp = [0xFF, 0x25, 0x00, 0x00, 0x00, 0x00];
        let ret = 0x9999_AAAA_BBBB_CCCCu64.to_le_bytes();
        assert_eq!(&t[t.len() - 8..], &ret);
        assert_eq!(&t[t.len() - 14..t.len() - 8], &tail_jmp);
        assert_eq!(&t[t.len() - 14 - orig.len()..t.len() - 14], &orig);
        // popfq; pop r11..rax precedes the displaced original.
        let post = [0x9D, 0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58, 0x5A, 0x59, 0x58];
        let post_start = t.len() - 14 - orig.len() - post.len();
        assert_eq!(&t[post_start..post_start + 12], &post);
        // The jnz skips exactly the guarded block (lands on popfq).
        assert_eq!(27 + guarded_len, post_start);
    }
}
