//! Pointer-hijack probe: prove that redirecting a *data* function pointer (not
//! patching translated code) causes the target to execute freshly-written code —
//! the Rosetta-safe hooking paradigm for macOS.
//!
//!     cargo run --example iatprobe -- <pid> [timeout_secs] [import_name]
//!
//! It parses the main PE's import table, finds a hot import (default
//! `QueryPerformanceCounter`), and overwrites its IAT slot to point at a cave
//! trampoline: `mov [done],1 ; jmp original`. The game's `call [IAT_slot]` reads
//! the (uncached) data pointer each call, jumps to our fresh cave page (which
//! Rosetta translates lazily — no stale translation), runs our code, then
//! tail-calls the real import so behavior is unchanged. When `done` flips we
//! restore the slot. If it flips, pointer-hijack hooking is viable under Rosetta.

use std::time::{Duration, Instant};

use zhol::memory::read::read_bytes;
use zhol::memory::write::write_bytes;
use zhol::platform::{alloc, alloc_code, reclaim_cave};
use zhol::process::module::module_by_name;
use zhol::process::SafeHandle;

const EXE: &str = "WizardGraphicalClient.exe";

fn rd_u32(h: &SafeHandle, a: usize) -> Result<u32, Box<dyn std::error::Error>> {
    let b = read_bytes(h, a, 4, None)?;
    Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn rd_u64(h: &SafeHandle, a: usize) -> Result<u64, Box<dyn std::error::Error>> {
    let b = read_bytes(h, a, 8, None)?;
    Ok(u64::from_le_bytes(b[..8].try_into().unwrap()))
}
fn rd_cstr(h: &SafeHandle, a: usize) -> String {
    let b = read_bytes(h, a, 64, None).unwrap_or_default();
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Resolve the IAT slot VA for `want` by walking the PE import table. Returns the
/// slot address (holding the resolved function pointer).
fn find_iat_slot(
    h: &SafeHandle,
    base: usize,
    want: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    let lfanew = rd_u32(h, base + 0x3C)? as usize;
    if &read_bytes(h, base + lfanew, 4, None)?[..] != b"PE\0\0" {
        return Err("not a PE".into());
    }
    let opt = base + lfanew + 24;
    // PE32+ DataDirectory starts at optional offset 112; import dir is index 1.
    let import_rva = rd_u32(h, opt + 112 + 8)? as usize;
    if import_rva == 0 {
        return Err("no import directory".into());
    }
    // Walk 20-byte import descriptors until a zero terminator.
    let mut desc = base + import_rva;
    loop {
        let oft = rd_u32(h, desc)? as usize; // OriginalFirstThunk (INT)
        let name_rva = rd_u32(h, desc + 12)? as usize;
        let ft = rd_u32(h, desc + 16)? as usize; // FirstThunk (IAT)
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        if oft != 0 {
            // Parallel-walk INT (names) and IAT (slots).
            let mut i = 0usize;
            loop {
                let int_ent = rd_u64(h, base + oft + i * 8)?;
                if int_ent == 0 {
                    break;
                }
                if int_ent & (1 << 63) == 0 {
                    // Import by name: low 31 bits = RVA to {u16 hint, name...}.
                    let name = rd_cstr(h, base + (int_ent as u32 & 0x7FFF_FFFF) as usize + 2);
                    if name == want {
                        return Ok(base + ft + i * 8);
                    }
                }
                i += 1;
            }
        }
        desc += 20;
    }
    Err(format!("import {want} not found").into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid: u32 = std::env::args().nth(1).ok_or("usage: iatprobe <pid> [secs] [import]")?.parse()?;
    let secs: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(10);
    let want = std::env::args().nth(3).unwrap_or_else(|| "QueryPerformanceCounter".into());

    println!("attaching to pid {pid}");
    let h = SafeHandle::from_pid(pid)?;
    let module = module_by_name(&h, EXE, true, Some(Duration::from_secs(5)))?
        .ok_or_else(|| format!("module {EXE} not found"))?;
    println!("module {EXE} base={:#x}", module.base);

    let slot = find_iat_slot(&h, module.base, &want)?;
    let original = rd_u64(&h, slot)? as usize;
    println!("IAT slot for {want}: {slot:#x} -> original {original:#x}");

    // Cave: done byte (data) + trampoline (code, a fresh page Rosetta hasn't seen).
    let done = alloc(&h, 8)?;
    let tramp = alloc_code(&h, 32)?;

    // mov rax, done ; mov byte[rax],1 ; mov rax, original ; jmp rax
    let mut code = Vec::new();
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&(done as u64).to_le_bytes());
    code.extend_from_slice(&[0xC6, 0x00, 0x01]);
    code.extend_from_slice(&[0x48, 0xB8]);
    code.extend_from_slice(&(original as u64).to_le_bytes());
    code.extend_from_slice(&[0xFF, 0xE0]);
    write_bytes(&h, tramp, &code, None)?;
    write_bytes(&h, done, &[0u8; 8], None)?;

    // Repoint the IAT slot (data write — seen immediately, no translation cache).
    write_bytes(&h, slot, &(tramp as u64).to_le_bytes(), None)?;
    println!("slot repointed to trampoline {tramp:#x}; waiting up to {secs}s...");

    let deadline = Instant::now() + Duration::from_secs(secs);
    let mut ran = false;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        if read_bytes(&h, done, 1, None)?[0] == 1 {
            ran = true;
            break;
        }
    }

    // Restore the slot FIRST (stop routing through us), then reclaim the caves.
    write_bytes(&h, slot, &(original as u64).to_le_bytes(), None)?;
    let _ = reclaim_cave(&h, tramp);
    let _ = reclaim_cave(&h, done);

    if ran {
        println!("RESULT: ran=true — pointer-hijack EXECUTED under Rosetta. Hooking viable via pointer redirection.");
    } else {
        println!("RESULT: ran=false — import not called, or redirect not taken, within {secs}s. Slot restored.");
    }
    Ok(())
}
