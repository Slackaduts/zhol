use std::time::Duration;

/// An error from a zhol memory or hook operation.
///
/// Concrete and matchable: callers branch on the variant rather than parsing a
/// message. `#[non_exhaustive]` so adding variants later is not a breaking
/// change. Messages follow the Rust API guidelines (lowercase, no trailing
/// punctuation) since they compose into larger messages.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MemOpError {
    /// The operation did not complete before its deadline.
    #[error("operation did not complete within {0:?}")]
    Timeout(Option<Duration>),

    /// A pattern scan found no match.
    #[error("pattern not found")]
    PatternNotFound,

    /// An OS/syscall-level failure (Win32 on Windows; errno / `/proc` on Unix).
    #[error("os error: {0}")]
    Os(String),

    /// An ad-hoc error carrying only a message (produced by [`memop_err!`]).
    #[error("{0}")]
    Message(String),

    /// A foreign error, type-erased but with its chain preserved via
    /// [`std::error::Error::source`]. The type-erased escape hatch.
    #[error(transparent)]
    Other(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl MemOpError {
    /// Wrap any foreign error as [`MemOpError::Other`], preserving its chain.
    pub fn other<E>(err: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        MemOpError::Other(Box::new(err))
    }

    /// True for a timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self, MemOpError::Timeout(_))
    }
}

/// `From` for the std errors occasionally propagated with `?`; each boxes into
/// [`MemOpError::Other`]. Kept explicit (rather than a blanket `From<E: Error>`)
/// because a blanket impl collides with the reflexive `From<T> for T`.
macro_rules! from_std_error {
    ($($ty:ty),* $(,)?) => {
        $(impl From<$ty> for MemOpError {
            fn from(err: $ty) -> Self {
                MemOpError::other(err)
            }
        })*
    };
}
from_std_error!(
    std::io::Error,
    std::fmt::Error,
    std::str::Utf8Error,
    std::string::FromUtf8Error,
    std::num::ParseIntError,
    std::num::ParseFloatError,
    std::str::ParseBoolError,
    std::char::ParseCharError,
);

pub type MemOpResult<T> = Result<T, MemOpError>;

/// Build a [`MemOpError::Message`] from a format string — an ad-hoc error with
/// the same call syntax as `format!`.
#[macro_export]
macro_rules! memop_err {
    ($msg:literal $(,)?) => {
        $crate::MemOpError::Message($msg.to_string())
    };
    ($fmt:literal, $($arg:tt)*) => {
        $crate::MemOpError::Message(format!($fmt, $($arg)*))
    };
    ($err:expr $(,)?) => {
        $crate::MemOpError::Message(format!("{}", $err))
    };
}
