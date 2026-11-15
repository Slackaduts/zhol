//! Isolated thread-hijack RPC probe — the minimal test of whether the target
//! actually EXECUTES cross-process-injected x86 code (the open question on macOS,
//! where Rosetta 2 may keep running a cached translation of the original bytes).
//!
//!     cargo run --example rpcprobe -- <pid> [timeout_secs]
//!
//! The movement-update site may only run while the character is moving, so for a
//! conclusive test pass a longer timeout (e.g. 10) and MOVE the character the
//! whole time; a bare `ran=false` with an idle character is inconclusive.
//!
//! It finds wizwalker's movement-update call site by
//! pattern, then runs `rpc_via_hijack` with a one-byte `ret` payload. The
//! trampoline saves state, calls the payload once, sets a `done` byte, restores,
//! re-runs the displaced original, and jumps back. If `done` flips (ran == true),
//! the target executed our injected code. If it doesn't, it times out and the
//! site is restored — no crash. No wizwalker runtime needed; pure zhol.

use std::time::Duration;

use zhol::process::module::module_by_name;
use zhol::process::pattern::pattern_scan;
use zhol::process::SafeHandle;
use zhol::rpc::rpc_via_hijack;

// wizwalker's current movement-update site: FF 50 ?? 48 8B 83 ?? ?? ?? ?? 48 8D ?? ?? 48 2B
const MOVE_UPDATE: &str = "FF 50 ?? 48 8B 83 ?? ?? ?? ?? 48 8D ?? ?? 48 2B";
const EXE: &str = "WizardGraphicalClient.exe";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid: u32 = std::env::args()
        .nth(1)
        .ok_or("usage: rpcprobe <pid> [timeout_secs]")?
        .parse()?;
    let timeout_secs: u64 = std::env::args()
        .nth(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);
    println!("attaching to pid {pid}");

    let handle = SafeHandle::from_pid(pid)?;
    let t = Some(Duration::from_secs(5));

    let module = module_by_name(&handle, EXE, true, t)?
        .ok_or_else(|| format!("module {EXE} not found"))?;
    println!("module {EXE} base={:#x} size={:#x}", module.base, module.size);

    let matches = pattern_scan(&handle, MOVE_UPDATE, module.base, module.size)?;
    let (off, _) = *matches
        .first()
        .ok_or("movement-update pattern not found (pattern may be stale)")?;
    let site = module.base + off;
    println!("movement-update site: {site:#x}");

    // One-shot payload: `ret`. The trampoline calls it, then sets done = 1.
    let shellcode = [0xC3u8];
    println!(
        "planting one-shot RPC (ret payload); waiting up to {timeout_secs}s — MOVE the character so the site runs..."
    );
    let ran = rpc_via_hijack(&handle, site, &shellcode, 10, 0, Duration::from_secs(timeout_secs))?;

    if ran {
        println!("RESULT: ran=true — the target EXECUTED injected code (Rosetta re-translated the patch). Hooks viable.");
    } else {
        println!("RESULT: ran=false — timed out; the patch was not executed (likely Rosetta ran a cached translation). Site restored, no crash.");
    }
    Ok(())
}
