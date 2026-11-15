//! Platform abstraction for process memory access.
//!
//! The rest of the crate talks to a target process only through the functions
//! and types re-exported here, never through OS APIs directly. Two backends
//! implement the same surface:
//!
//! * [`windows`] — the Win32 API (`ReadProcessMemory`, `VirtualAllocEx`, …),
//!   the original zhol target.
//! * [`unix`] — `/proc/<pid>/mem` and `/proc/<pid>/maps`, which also reach a
//!   Windows game running under Wine/Proton (the memory of the Wine process is
//!   the game's memory).
//!
//! Where a Windows concept has no Unix equivalent the difference is handled at
//! the backend rather than leaking upward: page-protection changes are a no-op
//! on Unix (writes through `/proc/<pid>/mem` ignore page protection), and
//! remote allocation (`VirtualAllocEx`) has no portable equivalent, so the Unix
//! backend returns a descriptive error until cave-based allocation lands with
//! the hook engine.

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::*;

#[cfg(target_os = "linux")]
mod unix;
#[cfg(target_os = "linux")]
pub use unix::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

/// A loaded module (executable or library) in the target process.
#[derive(Clone, Debug)]
pub struct Module {
    /// File-name of the module (the stem, e.g. `WizardGraphicalClient.exe`).
    pub name: String,
    /// Base address the module is mapped at.
    pub base: usize,
    /// Size of the mapped image in bytes (PE `SizeOfImage` when resolvable).
    pub size: usize,
}

/// A queried region of the target's address space.
#[derive(Clone, Copy, Debug)]
pub struct Region {
    pub base: usize,
    pub size: usize,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
    /// Backed by committed/real memory (vs. reserved or unmapped).
    pub committed: bool,
    /// Guard page (Windows `PAGE_GUARD`); never set on Unix.
    pub guarded: bool,
}

/// An opaque page-protection value.
///
/// On Windows it carries the `PAGE_*` flag so the original protection can be
/// restored after a write. On Unix it is inert.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protect(pub u32);

impl Protect {
    /// Read/write/execute — what a hook write requests. `PAGE_EXECUTE_READWRITE`
    /// (0x40) on Windows; inert on Unix.
    #[cfg(windows)]
    pub const EXEC_RW: Protect = Protect(0x40);
    #[cfg(unix)]
    pub const EXEC_RW: Protect = Protect(0);
}
