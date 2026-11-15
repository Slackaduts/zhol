//! Managed raw code-cave hook: the caller supplies the shellcode, zhol owns the
//! whole lifecycle (capture original bytes, allocate a cave slot, write the
//! shellcode, plant the jump + optional trampoline, and revert on `unhook`/drop).
//!
//! This is deliberately *lower-level* than the [`crate::hooks`] `HookImpl`
//! engine: it makes no assumption about what the shellcode does, so a caller with
//! hand-written x64 (e.g. wizwalker's existing per-hook bytecode) can adopt it
//! unchanged while handing alloc/inject/restore/teardown to zhol.
//!
//! ## Model (classic code-cave hook)
//! At `site`, `replaced_len` bytes (>= 5) are overwritten with `E9 rel32` into the
//! cave, NOP-padded. The cave holds `[shellcode]`, and when `relocate_original` is
//! set, `[displaced original bytes][E9 rel32 back to site+replaced_len]`, so the
//! game's own work still runs. The caller is responsible for register preservation
//! in its shellcode and for choosing `replaced_len` on whole-instruction
//! boundaries; as with any code-cave hook the displaced bytes must be
//! position-independent (no rel/RIP-relative operands in the replaced range).
//!
//! ## Lifetime / safety
//! `unhook` is idempotent (an atomic `active` flag) and `Drop` calls it, so a
//! dropped `RawHook` reverts its site and reclaims its cave slot. SIGKILL / a hard
//! crash cannot be covered — no destructor runs — which is why the on-disk autobot
//! self-heal exists at the wizwalker layer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;


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
            "target {to:#x} out of rel32 reach of {from_after:#x} (delta {d})"
        )));
    }
    Ok(d as i32)
}

/// A planted, revertible managed hook. Clone-free: the single owner's drop
/// reverts it.
pub struct RawHook {
    handle: SafeHandle,
    site: usize,
    original: Vec<u8>,
    cave_addr: usize,
    active: AtomicBool,
}

impl RawHook {
    /// Install a jump at `site` into `shellcode` placed in a freshly-allocated
    /// cave slot. `replaced_len` bytes at `site` are captured and overwritten.
    /// With `relocate_original`, zhol appends the displaced bytes + a jump back so
    /// the original code still executes.
    pub fn install(
        handle: SafeHandle,
        site: usize,
        shellcode: &[u8],
        replaced_len: usize,
        relocate_original: bool,
    ) -> MemOpResult<Self> {
        if replaced_len < JMP_LEN {
            return Err(MemOpError::Message(format!(
                "replaced_len {replaced_len} < {JMP_LEN} (need room for an E9 rel32 jump)"
            )));
        }

        let original = read_bytes(&handle, site, replaced_len, T)?;

        // Lay out the cave: shellcode, then (optionally) the displaced original
        // bytes and a jump back to just past the planted jump at the site.
        let tail = if relocate_original {
            original.len() + JMP_LEN
        } else {
            0
        };
        let cave_size = shellcode.len() + tail;
        // EXECUTABLE: the site jumps into this cave and runs the shellcode there.
        let cave_addr = platform::alloc_code(&handle, cave_size)?;

        // Build cave contents; reclaim the slot on any failure before the plant.
        let build = || -> MemOpResult<Vec<u8>> {
            let mut cave = Vec::with_capacity(cave_size);
            cave.extend_from_slice(shellcode);
            if relocate_original {
                cave.extend_from_slice(&original);
                let jmpback_at = cave_addr + shellcode.len() + original.len();
                let rel = rel32(
                    (jmpback_at + JMP_LEN) as i64,
                    (site + replaced_len) as i64,
                )?;
                cave.push(0xE9);
                cave.extend_from_slice(&rel.to_le_bytes());
            }
            Ok(cave)
        };
        let site_rel = rel32((site + JMP_LEN) as i64, cave_addr as i64);
        let cave_bytes = build().and_then(|c| site_rel.map(|r| (c, r)));
        let (cave_bytes, site_rel) = match cave_bytes {
            Ok(v) => v,
            Err(e) => {
                let _ = platform::reclaim_cave(&handle, cave_addr);
                return Err(e);
            }
        };

        if let Err(e) = write_bytes(&handle, cave_addr, &cave_bytes, T) {
            let _ = platform::reclaim_cave(&handle, cave_addr);
            return Err(e);
        }

        // Plant the jump last (the point of no return): E9 rel32 + NOP padding.
        let mut patch = Vec::with_capacity(replaced_len);
        patch.push(0xE9);
        patch.extend_from_slice(&site_rel.to_le_bytes());
        patch.resize(replaced_len, 0x90);
        if let Err(e) = write_bytes(&handle, site, &patch, T) {
            let _ = platform::reclaim_cave(&handle, cave_addr);
            return Err(e);
        }

        Ok(RawHook {
            handle,
            site,
            original,
            cave_addr,
            active: AtomicBool::new(true),
        })
    }

    /// Restore the original bytes and reclaim the cave slot. Idempotent: a second
    /// call (e.g. explicit then drop) is a no-op.
    pub fn unhook(&self) -> MemOpResult<()> {
        if self.active.swap(false, Ordering::SeqCst) {
            write_bytes(&self.handle, self.site, &self.original, T)?;
            let _ = platform::reclaim_cave(&self.handle, self.cave_addr);
        }
        Ok(())
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }
    pub fn site(&self) -> usize {
        self.site
    }
    pub fn cave_addr(&self) -> usize {
        self.cave_addr
    }
}

impl Drop for RawHook {
    fn drop(&mut self) {
        // Panic-safe: a panic in drop aborts the process, so never unwrap here.
        let _ = self.unhook();
    }
}
