//! Non-destructive write round-trip against a running process, proving the
//! `/proc/<pid>/mem` write path (the same path hook installation needs).
//!
//!     cargo run --example writecheck -- [pid | exe-name]
//!
//! It finds a writable anonymous region, reads 8 bytes, writes the SAME bytes
//! back (so game state is unchanged), and confirms the read-back matches.

use std::time::Duration;

use zhol::memory::read::read_bytes;
use zhol::memory::write::write_bytes;
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

/// First writable, non-executable, anonymous (no file path) region — heap-like,
/// the safest place to prove a write without touching mapped code or data.
fn writable_anon_addr(pid: u32) -> Option<usize> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let range = it.next()?;
        let perms = it.next()?;
        let _off = it.next();
        let _dev = it.next();
        let _inode = it.next();
        let path = it.next();
        if perms.starts_with("rw") && !perms.contains('x') && path.is_none() {
            let (start, end) = range.split_once('-')?;
            let start = usize::from_str_radix(start, 16).ok()?;
            let end = usize::from_str_radix(end, 16).ok()?;
            if end - start >= 0x100000 {
                return Some(start + 0x10000);
            }
        }
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

    let addr = writable_anon_addr(pid)
        .ok_or_else(|| format!("no writable anonymous region found"))?;
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
