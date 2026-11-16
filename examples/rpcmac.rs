//! Library macOS RPC test: calls `zhol::rpc::rpc_via_hijack` — which on macOS is
//! the pointer-redirect path (resolve a hot import's IAT slot, redirect to a
//! fresh-page detour that runs the payload once and tail-calls the original) — with
//! a one-byte `ret` payload. This exercises the exact library path wizwalker's
//! `start_thread` uses, end to end: import resolution + detour + run-once + restore.
//!
//!     cargo run --example rpcmac -- <pid> [timeout_secs]
//!
//! ran=true proves the target executed our injected code via pointer redirection
//! (and the game continued — the detour tail-called the real import). On Linux this
//! same call takes the inline path and would need a real code site, so run it on
//! macOS against the live game.

use std::time::Duration;

use zhol::process::SafeHandle;
use zhol::rpc::rpc_via_hijack;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let pid: u32 = std::env::args().nth(1).ok_or("usage: rpcmac <pid> [secs]")?.parse()?;
    let secs: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(10);

    // Number of consecutive RPCs in one process (default 2): the key regression is
    // a SECOND RPC failing because a reused page address hit a stale Rosetta
    // translation. With the leak fix both must return ran=true.
    let iters: usize = std::env::args().nth(3).and_then(|s| s.parse().ok()).unwrap_or(2);

    println!("attaching to pid {pid}");
    let h = SafeHandle::from_pid(pid)?;

    let mut all_ok = true;
    for i in 1..=iters {
        // site / orig_len / done_addr are ignored on macOS; payload is a bare `ret`.
        let ran = rpc_via_hijack(&h, 0, &[0xC3], 10, 0, Duration::from_secs(secs))?;
        println!("RPC #{i}: ran={ran}");
        all_ok &= ran;
    }

    if all_ok {
        println!("RESULT: all {iters} RPCs ran — repeated pointer-redirect RPC works in one process (leak fix OK).");
    } else {
        println!("RESULT: at least one RPC did NOT run within {secs}s each.");
    }
    Ok(())
}
