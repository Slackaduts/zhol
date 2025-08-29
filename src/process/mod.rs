// pub mod handle;
// pub mod input;
pub mod module;
pub mod pattern;
// pub mod utils;

/// A macro for safely acquiring and using a handle with timeout support.
/// 
/// This macro provides a convenient way to acquire a handle with an optional timeout,
/// execute code with the acquired handle guard, and properly handle timeout errors.
/// 
/// # Arguments
/// 
/// * `$handle` - A reference to a `SafeHandle` instance
/// * `$timeout` - An `Option<Duration>` specifying the timeout for acquiring the handle
/// * `$guard` - The identifier for the handle guard variable in the code block
/// * `$ret` - The return type of the code block
/// * `$block` - The code block to execute with the acquired handle
/// 
/// # Returns
/// 
/// Returns a `MemOpResult<$ret>` where success contains the result of the code block,
/// or an error if the timeout is reached or other operation fails.
/// 
/// # Examples
/// 
/// ```rust,norun
/// let handle = SafeHandle::new(some_windows_handle);
/// let result = with_handle!(&handle, Some(Duration::from_secs(5)), |guard| -> windows::Win32::Foundation::HANDLE, {
///     // Use the handle through guard
///     do_something_with_handle(*guard)?;
///     Ok()
/// });
/// ```
#[macro_export]
macro_rules! with_handle {
    ($handle:expr, $timeout:expr, |$guard:ident| -> $ret:ty, $block:expr) => {{
        let safe_handle: &$crate::process::SafeHandle = $handle;
        let result: crate::MemOpResult<$ret> = match safe_handle.acquire_with_timeout($timeout) {
            Some($guard) => $block,
            None => Err(crate::MemOpError::TimeoutReached(($timeout, None))),
        };
        result
    }};
}

use std::sync::Arc;
use windows::Win32::Foundation::HANDLE;

use parking_lot::{Mutex, MutexGuard};
use std::time::Duration;

/// A thread-safe wrapper for Windows handles with timeout-based locking.
/// 
/// `SafeHandle` provides synchronized access to a Windows handle across multiple threads
/// using a mutex. It supports both blocking and timeout-based acquisition of the handle,
/// making it suitable for scenarios where handle access needs to be coordinated between
/// multiple threads or where deadlock prevention is important.
pub struct SafeHandle {
    /// The mutex-protected handle wrapped in an Arc for shared ownership
    inner: Arc<Mutex<HANDLE>>,
}

impl Clone for SafeHandle {
    /// Creates a new `SafeHandle` that shares the same underlying handle.
    /// 
    /// Cloning a `SafeHandle` creates a new reference to the same underlying
    /// mutex-protected handle. All clones will synchronize access to the same handle.
    fn clone(&self) -> Self {
        SafeHandle {
            inner: Arc::clone(&self.inner),
        }
    }
}


// We are taking special care to ensure these are actually compatible with Send + Sync, tokio is just an overly restrictive mess :) -S
unsafe impl Send for SafeHandle {}
unsafe impl Sync for SafeHandle {}

/// A RAII guard that provides exclusive access to a Windows handle.
/// 
/// `SafeHandleGuard` is returned by `SafeHandle::acquire_with_timeout()` and ensures
/// that the handle remains locked for the duration of the guard's lifetime. The handle
/// is automatically released when the guard is dropped.
/// 
/// The guard implements `Deref` to provide direct access to the underlying `HANDLE`.
pub struct SafeHandleGuard<'a> {
    /// The mutex guard that maintains exclusive access to the handle
    _guard: MutexGuard<'a, HANDLE>,
}

impl SafeHandle {
    /// Creates a new `SafeHandle` from a Windows API handle.
    /// 
    /// # Arguments
    /// 
    /// * `handle` - The Windows `HANDLE` to wrap in a thread-safe container
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// use zhol::process::SafeHandle;
    /// 
    /// let safe_handle = SafeHandle::new(some_windows_handle);
    /// ```
    pub fn new(handle: HANDLE) -> Self {
        SafeHandle {
            inner: Arc::new(Mutex::new(handle)),
        }
    }

    /// Attempts to acquire exclusive access to the handle with an optional timeout.
    /// 
    /// # Arguments
    /// 
    /// * `timeout` - Optional timeout duration. If `Some(duration)`, the method will
    ///   wait up to that duration for the handle to become available. If `None`,
    ///   the method will block indefinitely until the handle is available.
    /// 
    /// # Returns
    /// 
    /// Returns `Some(SafeHandleGuard)` if the handle was successfully acquired,
    /// or `None` if the timeout was reached (when a timeout was specified).
    /// 
    /// # Examples
    /// 
    /// ```rust,norun
    /// // Try to acquire with a 5-second timeout
    /// if let Some(guard) = handle.acquire_with_timeout(Some(Duration::from_secs(5))) {
    ///     // Use the handle through the guard
    ///     // Handle is automatically released when guard is dropped
    /// }
    /// 
    /// // Acquire without timeout (blocks until available)
    /// let guard = handle.acquire_with_timeout(None).unwrap();
    /// ```
    pub fn acquire_with_timeout(&self, timeout: Option<Duration>) -> Option<SafeHandleGuard<'_>> {
        match timeout {
            Some(duration) => self.inner.try_lock_for(duration),
            None => Some(self.inner.lock()),
        }
        .map(|guard| SafeHandleGuard { _guard: guard })
    }
}

impl<'a> std::ops::Deref for SafeHandleGuard<'a> {
    type Target = HANDLE;

    /// Provides direct access to the underlying Windows handle.
    /// 
    /// This allows the guard to be used as if it were the handle itself,
    /// enabling transparent usage in Windows API calls while maintaining
    /// the safety guarantees of the mutex protection.
    fn deref(&self) -> &Self::Target {
        &*self._guard
    }
}