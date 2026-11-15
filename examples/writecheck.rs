//! Non-destructive write round-trip against a running process, proving the OS
//! write path (the same path hook installation needs).
//!
//!     cargo run --example writecheck -- [pid | exe-name]
//!
//! It finds a writable region, reads 8 bytes, writes a sentinel, confirms it
//! landed, then restores the original bytes (so game state is unchanged).

use std::time::Duration;

use zhol::memory::read::read_bytes;
use zhol::memory::write::write_bytes;
use zhol::platform::query_region;
use zhol::process::SafeHandle;

fn find_pid_by_exe(name: &str) -> Option<u32> {
    let want = name.to_lowercase();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let pid: u32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(p) => p,
            None => continue,
        };
        if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
            let argv0 = raw.split(|&b| b == 0).next().unwrap_or_default();
            let base = String::from_utf8_lossy(argv0)
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default()
                .to_lowercase();
            if base == want {
                return Some(pid);
            }
        }
    }
    None
}

/// First large writable, non-executable, committed region — heap-like, the safest
/// place to prove a write without touching mapped code. Portable: walks regions
/// via `query_region` rather than parsing `/proc/<pid>/maps` (absent on macOS).
fn writable_region_addr(handle: &SafeHandle, t: Option<Duration>) -> Option<usize> {
    let mut addr: usize = 0x1_0000; // skip the null page
    for _ in 0..200_000 {
        let r = query_region(handle, addr, t).ok()?;
        if r.size == 0 {
            break;
        }
        if r.committed && r.readable && r.writable && !r.executable && r.size >= 0x100000 {
            return Some(r.base + 0x10000);
        }
        let next = r.base.checked_add(r.size)?;
        addr = if next > addr { next } else { addr.checked_add(0x1000)? };
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "WizardGraphicalClient.exe".into());
    let pid = if arg.chars().all(|c| c.is_ascii_digit()) {
        arg.parse()?
    } else {
        find_pid_by_exe(&arg).ok_or_else(|| format!("no process named {arg}"))?
    };
    println!("attaching to pid {pid}");

    let handle = SafeHandle::from_pid(pid)?;
    let t = Some(Duration::from_secs(5));

    let addr = writable_region_addr(&handle, t)
        .ok_or_else(|| format!("no writable region found"))?;
    println!("writable test address: {addr:#x}");

    let original = read_bytes(&handle, addr, 8, t)?;
    println!("read original:   {original:02X?}");

    // Write a distinct sentinel, confirm it landed (proves mutation), then
    // restore the original bytes so game state is unchanged.
    let sentinel: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x11, 0x22, 0x33, 0x44];
    write_bytes(&handle, addr, &sentinel, t)?;
    let after = read_bytes(&handle, addr, 8, t)?;
    println!("read after write:{after:02X?}");
    if !(after == sentinel) { return Err("sentinel not observed: write did not take".into()); }

    write_bytes(&handle, addr, &original, t)?;
    let restored = read_bytes(&handle, addr, 8, t)?;
    println!("read after restore:{restored:02X?}");
    if !(restored == original) { return Err("restore failed".into()); }
    println!("OK: write mutated memory and was restored cleanly");
    Ok(())
}
