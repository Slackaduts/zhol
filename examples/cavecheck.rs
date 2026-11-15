//! Exercise the Unix code-cave allocator against a running process.
//!
//!     cargo run --example cavecheck -- [pid | exe-name]
//!
//! Allocates a few scratch blocks and confirms they land inside the main
//! module's image and read back as zeros (the allocator zeroes handed-out
//! scratch). Proves hook memory can be sourced on Unix without VirtualAllocEx.

use std::time::Duration;

use zhol::memory::read::read_bytes;
use zhol::memory::utils::allocate_memory;
use zhol::process::module::module_by_name;
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "WizardGraphicalClient.exe".into());
    let pid = if arg.chars().all(|c| c.is_ascii_digit()) {
        arg.parse()?
    } else {
        find_pid_by_exe(&arg).ok_or_else(|| format!("no process named {arg}"))?
    };
    let exe = if arg.chars().all(|c| c.is_ascii_digit()) {
        "WizardGraphicalClient.exe".to_string()
    } else {
        arg.clone()
    };
    println!("attaching to pid {pid}");

    let handle = SafeHandle::from_pid(pid)?;
    let t = Some(Duration::from_secs(5));
    let module = module_by_name(&handle, &exe, true, t)?
        .ok_or_else(|| format!("module {exe} not found"))?;
    let lo = module.base;
    let hi = module.base + module.size;
    println!("module {} image: [{lo:#x}, {hi:#x})", module.name);

    for size in [0x200usize, 0x80, 0x40] {
        let region = allocate_memory(&handle, size)?;
        let in_image = region.addr >= lo && region.addr + size <= hi;
        let back = read_bytes(&handle, region.addr, size.min(16), t)?;
        println!(
            "  alloc {size:#06x} -> {:#x}  in-image={in_image}  first bytes zero={}",
            region.addr,
            back.iter().all(|&b| b == 0)
        );
        if !(in_image) { return Err("allocation fell outside the module image".into()); }
        if !(back.iter().all(|&b| b == 0)) { return Err("scratch not zeroed".into()); }
        std::mem::forget(region); // don't run Drop (free is a no-op anyway)
    }

    println!("OK: code-cave allocator returns in-image, zeroed scratch");
    Ok(())
}
