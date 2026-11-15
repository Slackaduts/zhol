pub mod module;
pub mod pattern;

use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, MutexGuard};

use crate::platform::Target;
use crate::{MemOpError, MemOpResult};

/// A macro for safely acquiring and using a handle with timeout support.
///
/// Acquires the handle's guard (which derefs to the platform [`Target`]),
/// evaluates `$block`, and maps a timeout to [`MemOpError::Timeout`].
#[macro_export]
macro_rules! with_handle {
    ($handle:expr, $timeout:expr, |$guard:ident| -> $ret:ty, $block:expr) => {{
        let safe_handle: &$crate::process::SafeHandle = $handle;
        let result: $crate::MemOpResult<$ret> = match safe_handle.acquire_with_timeout($timeout) {
            Some($guard) => $block,
            None => Err($crate::MemOpError::Timeout($timeout)),
        };
        result
    }};
}

/// A thread-safe wrapper around a target process, synchronising access to the
/// platform handle with a mutex and optional acquisition timeout.
///
/// The wrapped value is a [`Target`] — a Win32 `HANDLE` on Windows, a pid plus
/// an open `/proc/<pid>/mem` on Unix — so the rest of the crate never names an
/// OS-specific handle type.
pub struct SafeHandle {
    inner: Arc<Mutex<Target>>,
}

impl Clone for SafeHandle {
    fn clone(&self) -> Self {
        SafeHandle {
            inner: Arc::clone(&self.inner),
        }
    }
}

// Target carries its own Send+Sync justification per backend.
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

/// RAII guard giving exclusive access to the target. Derefs to [`Target`].
pub struct SafeHandleGuard<'a> {
    _guard: MutexGuard<'a, Target>,
}

impl SafeHandle {
    /// Wrap an already-constructed platform target.
    pub fn from_target(target: Target) -> Self {
        SafeHandle {
            inner: Arc::new(Mutex::new(target)),
        }
    }

    /// Open a target process by pid (cross-platform).
    pub fn from_pid(pid: u32) -> MemOpResult<Self> {
        Ok(Self::from_target(crate::platform::open(pid)?))
    }

    /// Acquire exclusive access, optionally bounded by `timeout`.
    pub fn acquire_with_timeout(&self, timeout: Option<Duration>) -> Option<SafeHandleGuard<'_>> {
        match timeout {
            Some(duration) => self.inner.try_lock_for(duration),
            None => Some(self.inner.lock()),
        }
        .map(|guard| SafeHandleGuard { _guard: guard })
    }
}

#[cfg(windows)]
impl SafeHandle {
    /// Wrap an already-open Win32 process handle (classic zhol entry point).
    pub fn new(handle: windows::Win32::Foundation::HANDLE) -> Self {
        Self::from_target(Target::from_handle(handle))
    }
}

impl<'a> std::ops::Deref for SafeHandleGuard<'a> {
    type Target = Target;

    fn deref(&self) -> &Self::Target {
        &self._guard
    }
}

/// Convenience: a timeout helper used by the backends.
pub(crate) fn _timeout_err(timeout: Option<Duration>) -> MemOpError {
    MemOpError::Timeout(timeout)
}
