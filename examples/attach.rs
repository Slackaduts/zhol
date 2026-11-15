//! Attach to a running process and exercise the Unix memory backend.
//!
//!     cargo run --example attach -- [pid | exe-name]
//!
//! With no argument it finds the first `WizardGraphicalClient.exe` in `/proc`.
//! It opens the target, enumerates modules, and against the main module reads
//! the `MZ`/`PE` header and runs a pattern scan — proving read + module
//! resolution + scanning work against a Proton-hosted Windows client from a
//! native-Linux process.

use std::time::Duration;

use zhol::memory::read::read_bytes;
use zhol::process::module::{get_named_modules, module_by_name};
use zhol::process::pattern::pattern_scan;
use zhol::process::SafeHandle;

const DEFAULT_EXE: &str = "WizardGraphicalClient.exe";

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
    let arg = std::env::args().nth(1);
    let (pid, exe) = match arg {
        Some(a) if a.chars().all(|c| c.is_ascii_digit()) => (a.parse::<u32>()?, None),
        Some(a) => (
            find_pid_by_exe(&a).ok_or_else(|| format!("no process named {a}"))?,
            Some(a),
        ),
        None => (
            find_pid_by_exe(DEFAULT_EXE)
                .ok_or_else(|| format!("no {DEFAULT_EXE} running"))?,
            Some(DEFAULT_EXE.to_string()),
        ),
    };
    let exe = exe.unwrap_or_else(|| DEFAULT_EXE.to_string());
    println!("attaching to pid {pid} ({exe})");

    let handle = SafeHandle::from_pid(pid)?;
    let t = Some(Duration::from_secs(5));

    let modules = get_named_modules(&handle, t)?;
    println!("enumerated {} modules", modules.len());
    for m in modules.iter().take(8) {
        println!("  {:<32} base={:#018x} size={:#x}", m.name, m.base, m.size);
    }

    let module = module_by_name(&handle, &exe, true, t)?
        .ok_or_else(|| format!("module {exe} not found in target"))?;
    println!(
        "main module: {} base={:#x} size={:#x}",
        module.name, module.base, module.size
    );

    let header = read_bytes(&handle, module.base, 2, t)?;
    println!(
        "header bytes: {:02X?}  ({})",
        header,
        if header == b"MZ" { "valid PE/MZ" } else { "unexpected" }
    );

    // Scan the first 64 KiB of the image for the MZ magic; it must be at 0.
    let scan_len = module.size.min(0x10000);
    let matches = pattern_scan(&handle, "4D 5A", module.base, scan_len)?;
    println!(
        "pattern scan '4D 5A' over {:#x} bytes: {} match(es), first at offset {:?}",
        scan_len,
        matches.len(),
        matches.first().map(|(off, _)| *off)
    );

    println!("OK: read + module resolution + scan all succeeded against the live client");
    Ok(())
}
