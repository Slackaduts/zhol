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
/// Length of an `E9 rel32` near jump.
const JMP_LEN: usize = 5;

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

/// Restores the site and reclaims cave slots on every exit path (incl. panic).
struct Cleanup<'a> {
    handle: &'a SafeHandle,
    site: usize,
    orig: Vec<u8>,
    planted: bool,
    slots: Vec<usize>,
}

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

#[cfg(test)]
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
