use std::{
    char::ParseCharError,
    fmt,
    num::{ParseFloatError, ParseIntError},
    str::ParseBoolError,
    time::Duration,
};

/// Represents errors that can occur during a given memory operation.
#[derive(Debug)]
pub enum MemOpError {
    /// Operation timed out.
    TimeoutReached((Option<Duration>, Option<anyhow::Error>)),
    /// Memory is in an invalid state for the requested operation. Carries a
    /// human description of what was wrong (platform-neutral).
    MemoryStateInvalid((String, Option<anyhow::Error>)),
    /// A requested pattern was not found.
    PatternNotFound,
    /// An OS-level error (Win32 on Windows, errno/`/proc` on Unix).
    Os((String, Option<anyhow::Error>)),
    /// Generic error that wraps an `anyhow::Error`.
    Other(anyhow::Error),
}

impl MemOpError {
    /// Creates a new `MemOpError::Other` from anything implementing `std::error::Error`.
    pub fn new<E>(error: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        MemOpError::Other(anyhow::Error::new(error))
    }

    pub fn from_boxed(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        MemOpError::Other(anyhow::anyhow!("{}", err))
    }

    pub fn into_inner(self) -> Option<anyhow::Error> {
        match self {
            MemOpError::Other(err) => Some(err),
            _ => None,
        }
    }

    pub fn is_timeout(&self) -> bool {
        matches!(self, MemOpError::TimeoutReached(_))
    }

    pub fn is_memory_state_invalid(&self) -> bool {
        matches!(self, MemOpError::MemoryStateInvalid(_))
    }

    /// True for an OS-level error.
    pub fn is_os(&self) -> bool {
        matches!(self, MemOpError::Os(_))
    }

    pub fn root_cause_string(&self) -> String {
        match self {
            MemOpError::TimeoutReached((timeout, err)) => match (timeout, err) {
                (Some(t), Some(e)) => format!(
                    "Timeout operation of context \"{e}\" failed to complete within timeout \"{:#?}\".",
                    t
                ),
                (Some(t), None) => {
                    format!("Timeout operation failed to complete within timeout \"{:#?}\".", t)
                }
                (None, None) => "Timeout operation failed to complete within timeout.".to_string(),
                (None, Some(e)) => format!(
                    "Timeout operation of context \"{e}\" failed to complete with its timeout."
                ),
            },
            MemOpError::MemoryStateInvalid((desc, err)) => match err {
                Some(e) => format!("Memory operation of context \"{e}\" failed: {desc}"),
                None => format!("Memory operation failed: {desc}"),
            },
            MemOpError::Os((msg, err)) => match err {
                Some(e) => format!("OS call with context \"{e}\" failed: \"{msg}\""),
                None => format!("OS call failed: \"{msg}\""),
            },
            MemOpError::PatternNotFound => "Pattern not found".to_string(),
            MemOpError::Other(err) => format!("{:#}", err),
        }
    }
}

impl fmt::Display for MemOpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MemOpError: \"{}\"", &self.root_cause_string())
    }
}

impl std::error::Error for MemOpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MemOpError::Other(err) => err.source(),
            _ => None,
        }
    }
}

impl From<anyhow::Error> for MemOpError {
    fn from(err: anyhow::Error) -> Self {
        MemOpError::Other(err)
    }
}

impl From<std::io::Error> for MemOpError {
    fn from(err: std::io::Error) -> Self {
        MemOpError::Other(anyhow::Error::new(err))
    }
}

impl From<std::fmt::Error> for MemOpError {
    fn from(err: std::fmt::Error) -> Self {
        MemOpError::Other(anyhow::Error::new(err))
    }
}

impl From<std::str::Utf8Error> for MemOpError {
    fn from(err: std::str::Utf8Error) -> Self {
        MemOpError::Other(anyhow::Error::new(err))
    }
}

impl From<std::string::FromUtf8Error> for MemOpError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        MemOpError::Other(anyhow::Error::new(err))
    }
}

pub type MemOpResult<T> = Result<T, MemOpError>;

/// Extension trait to add anyhow-like methods to `MemOpResult`.
pub trait MemOpResultExt<T> {
    fn context<C>(self, context: C) -> MemOpResult<T>
    where
        C: fmt::Display + Send + Sync + 'static;

    fn with_context<C, F>(self, f: F) -> MemOpResult<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C;

    fn ok_or_else<E, F>(self, err: F) -> MemOpResult<T>
    where
        E: std::error::Error + Send + Sync + 'static,
        F: FnOnce() -> E;

    fn and_then<U, F>(self, op: F) -> MemOpResult<U>
    where
        F: FnOnce(T) -> MemOpResult<U>;

    fn ok_or<E>(self, err: E) -> MemOpResult<T>
    where
        Self: Sized,
        E: Into<MemOpError>;

    fn map_ok<U, F>(self, op: F) -> MemOpResult<U>
    where
        F: FnOnce(T) -> U;
}

impl<T> MemOpResultExt<T> for MemOpResult<T> {
    fn context<C>(self, context: C) -> MemOpResult<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.map_err(|err| {
            if let MemOpError::Other(inner) = err {
                MemOpError::Other(inner.context(context))
            } else {
                MemOpError::Other(anyhow::anyhow!("{}: {}", context, err))
            }
        })
    }

    fn with_context<C, F>(self, f: F) -> MemOpResult<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.map_err(|err| {
            if let MemOpError::Other(inner) = err {
                MemOpError::Other(inner.context(f()))
            } else {
                MemOpError::Other(anyhow::anyhow!("{}: {}", f(), err))
            }
        })
    }

    fn ok_or_else<E, F>(self, err: F) -> MemOpResult<T>
    where
        E: std::error::Error + Send + Sync + 'static,
        F: FnOnce() -> E,
    {
        match self {
            Ok(value) => Ok(value),
            Err(_) => Err(MemOpError::new(err())),
        }
    }

    fn and_then<U, F>(self, op: F) -> MemOpResult<U>
    where
        F: FnOnce(T) -> MemOpResult<U>,
    {
        match self {
            Ok(value) => op(value),
            Err(err) => Err(err),
        }
    }

    fn ok_or<E>(self, err: E) -> MemOpResult<T>
    where
        Self: Sized,
        E: Into<MemOpError>,
    {
        match self {
            Ok(value) => Ok(value),
            Err(_) => Err(err.into()),
        }
    }

    fn map_ok<U, F>(self, op: F) -> MemOpResult<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Ok(value) => Ok(op(value)),
            Err(err) => Err(err),
        }
    }
}

#[macro_export]
macro_rules! memop_err {
    ($msg:literal $(,)?) => {
        $crate::MemOpError::Other(anyhow::anyhow!($msg))
    };
    ($err:expr $(,)?) => {
        $crate::MemOpError::Other(anyhow::anyhow!($err))
    };
    ($fmt:literal, $($arg:tt)*) => {
        $crate::MemOpError::Other(anyhow::anyhow!($fmt, $($arg)*))
    };
}

impl<T> MemOpResultExt<T> for Option<T> {
    fn context<C>(self, context: C) -> MemOpResult<T>
    where
        C: fmt::Display + Send + Sync + 'static,
    {
        self.ok_or_else(|| MemOpError::Other(anyhow::anyhow!("{}", context)))
    }

    fn with_context<C, F>(self, f: F) -> MemOpResult<T>
    where
        C: fmt::Display + Send + Sync + 'static,
        F: FnOnce() -> C,
    {
        self.ok_or_else(|| MemOpError::Other(anyhow::anyhow!("{}", f())))
    }

    fn ok_or_else<E, F>(self, err: F) -> MemOpResult<T>
    where
        E: std::error::Error + Send + Sync + 'static,
        F: FnOnce() -> E,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(MemOpError::new(err())),
        }
    }

    fn and_then<U, F>(self, op: F) -> MemOpResult<U>
    where
        F: FnOnce(T) -> MemOpResult<U>,
    {
        match self {
            Some(value) => op(value),
            None => Err(memop_err!("Option is None")),
        }
    }

    fn ok_or<E>(self, err: E) -> MemOpResult<T>
    where
        Self: Sized,
        E: Into<MemOpError>,
    {
        match self {
            Some(value) => Ok(value),
            None => Err(err.into()),
        }
    }

    fn map_ok<U, F>(self, op: F) -> MemOpResult<U>
    where
        F: FnOnce(T) -> U,
    {
        match self {
            Some(value) => Ok(op(value)),
            None => Err(memop_err!("Option is None")),
        }
    }
}

pub trait IntoMemOpResult<T, E> {
    fn into_memop_result(self, ctx: Option<anyhow::Error>) -> MemOpResult<T>;
}

impl<T, E> IntoMemOpResult<T, E> for Result<T, E>
where
    E: std::error::Error + Send + Sync + 'static,
{
    fn into_memop_result(self, _ctx: Option<anyhow::Error>) -> MemOpResult<T> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => Err(MemOpError::new(err)),
        }
    }
}

pub trait FromAnyhow<T> {
    fn into_memop_result(self) -> MemOpResult<T>;
}

impl<T> FromAnyhow<T> for anyhow::Result<T> {
    fn into_memop_result(self) -> MemOpResult<T> {
        match self {
            Ok(value) => Ok(value),
            Err(err) => Err(MemOpError::Other(err)),
        }
    }
}

/// Trait for errors we don't care to match on further; folds into `Other`.
pub trait GenericError: Send + Sync + Clone + PartialEq + Eq + std::fmt::Debug {}
impl GenericError for ParseIntError {}
impl GenericError for ParseBoolError {}
impl GenericError for ParseCharError {}
impl GenericError for ParseFloatError {}

impl<T: GenericError> From<T> for MemOpError {
    fn from(err: T) -> Self {
        memop_err!("{:#?}", err)
    }
}
