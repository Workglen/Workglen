//! First-party application errors. Keep typed causes for authorization and
//! delivery decisions, and preserve the context printed by the CLI/logs.
// SPDX-License-Identifier: Apache-2.0
use std::{error::Error as StdError, fmt};

pub struct Error {
    inner: Box<dyn StdError + Send + Sync>,
}
pub type Result<T, E = Error> = std::result::Result<T, E>;
pub use crate::{bail, ensure};

#[derive(Debug)]
struct Message(String);
impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl StdError for Message {}

#[derive(Debug)]
struct ContextError {
    message: String,
    source: Box<dyn StdError + Send + Sync>,
}
impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl StdError for ContextError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(self.source.as_ref())
    }
}

// As with the former error container, this wrapper deliberately does not
// implement StdError: that permits generic conversion without overlapping
// std's From<T> for T. The boxed underlying errors do implement StdError.
impl<E: StdError + Send + Sync + 'static> From<E> for Error {
    fn from(error: E) -> Self {
        Self {
            inner: Box::new(error),
        }
    }
}
impl Error {
    pub fn msg(message: impl fmt::Display) -> Self {
        Message(message.to_string()).into()
    }
    pub fn context(self, message: impl fmt::Display) -> Self {
        Self {
            inner: Box::new(ContextError {
                message: message.to_string(),
                source: self.inner,
            }),
        }
    }
    pub fn downcast_ref<E: StdError + Send + Sync + 'static>(&self) -> Option<&E> {
        let mut current = self.inner.as_ref();
        loop {
            if let Some(value) = current.downcast_ref::<E>() {
                return Some(value);
            }
            // Follow only our context wrappers. Do not broaden classification
            // to arbitrary nested library errors that the former API did not
            // downcast, which could change SMTP retry or permission decisions.
            current = current.downcast_ref::<ContextError>()?.source.as_ref();
        }
    }
    pub fn is<E: StdError + Send + Sync + 'static>(&self) -> bool {
        self.downcast_ref::<E>().is_some()
    }
    pub fn chain(&self) -> Chain<'_> {
        Chain {
            next: Some(self.inner.as_ref()),
        }
    }
}
pub struct Chain<'a> {
    next: Option<&'a (dyn StdError + 'static)>,
}
impl<'a> Iterator for Chain<'a> {
    type Item = &'a (dyn StdError + 'static);
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next.take()?;
        self.next = next.source();
        Some(next)
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            for (index, cause) in self.chain().enumerate() {
                if index > 0 {
                    f.write_str(": ")?;
                }
                write!(f, "{cause}")?;
            }
            Ok(())
        } else {
            fmt::Display::fmt(&self.inner, f)
        }
    }
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            return fmt::Debug::fmt(&self.inner, f);
        }
        write!(f, "{}", self.inner)?;
        let causes: Vec<_> = self.chain().skip(1).collect();
        if !causes.is_empty() {
            f.write_str("\n\nCaused by:")?;
            for (index, cause) in causes.iter().enumerate() {
                let prefix = if causes.len() > 1 {
                    format!("    {index}: ")
                } else {
                    "    ".into()
                };
                let mut lines = cause
                    .to_string()
                    .split('\n')
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
                    .into_iter();
                write!(f, "\n{prefix}{}", lines.next().unwrap_or_default())?;
                for line in lines {
                    write!(f, "\n{}{line}", " ".repeat(prefix.len()))?;
                }
            }
        }
        Ok(())
    }
}

pub trait Context<T> {
    fn context(self, message: impl fmt::Display) -> Result<T>;
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T>;
}
impl<T, E: Into<Error>> Context<T> for std::result::Result<T, E> {
    fn context(self, message: impl fmt::Display) -> Result<T> {
        self.map_err(|error| error.into().context(message))
    }
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T> {
        self.map_err(|error| error.into().context(message()))
    }
}
impl<T> Context<T> for Option<T> {
    fn context(self, message: impl fmt::Display) -> Result<T> {
        self.ok_or_else(|| Error::msg(message))
    }
    fn with_context(self, message: impl FnOnce() -> String) -> Result<T> {
        self.ok_or_else(|| Error::msg(message()))
    }
}

#[macro_export]
macro_rules! error {
    ($fmt:literal $(, $($args:tt)*)?) => { $crate::error::Error::msg(format!($fmt $(, $($args)*)?)) };
    ($error:expr $(,)?) => { $crate::error::Error::from($error) };
}
#[macro_export]
macro_rules! bail {
    ($($args:tt)*) => { return Err($crate::error!($($args)*)) };
}
#[macro_export]
macro_rules! ensure {
    ($condition:expr $(,)?) => { $crate::ensure!($condition, "Condition failed: {}", stringify!($condition)) };
    ($condition:expr, $($args:tt)*) => { if !$condition { $crate::bail!($($args)*); } };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    #[test]
    fn contexts_preserve_typed_causes_and_display() {
        let error = Error::from(io::Error::new(io::ErrorKind::TimedOut, "timed out"))
            .context("connect")
            .context("deliver");
        assert!(error.is::<io::Error>());
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::TimedOut
        );
        assert_eq!(error.to_string(), "deliver");
        assert_eq!(format!("{error:#}"), "deliver: connect: timed out");
        assert_eq!(error.chain().count(), 3);
    }
    #[test]
    fn permission_and_delivery_markers_survive_context() {
        let denied = Error::from(crate::rbac::Denied).context("permission");
        assert!(denied.is::<crate::rbac::Denied>());
        fn permanent() -> Result<()> {
            bail!(crate::relay::Permanent("5.4.4 no usable MX".into()));
        }
        assert!(permanent().unwrap_err().is::<crate::relay::Permanent>());
        let multiline = Error::from(io::Error::other("last\n")).context("outer");
        assert_eq!(
            format!("{multiline:?}"),
            "outer\n\nCaused by:\n    last\n    "
        );
        let timed_out = Error::from(io::Error::from(io::ErrorKind::WouldBlock)).context("read");
        assert!(crate::net::timeout(&timed_out));
        let other = Error::msg("timed out");
        assert!(!crate::net::timeout(&other));
    }
    #[test]
    fn result_option_and_lazy_context_keep_values_and_causes() {
        let ok: Result<u8> = Ok(7);
        assert_eq!(
            ok.with_context(|| panic!("evaluated on success")).unwrap(),
            7
        );
        let fail: std::result::Result<u8, _> = Err(io::Error::from(io::ErrorKind::NotFound));
        assert!(fail.context("open").unwrap_err().is::<io::Error>());
        assert_eq!(
            None::<u8>.context("missing").unwrap_err().to_string(),
            "missing"
        );
        assert_eq!(Some(3).context("unused").unwrap(), 3);
    }
    #[test]
    fn errors_are_send_sync_and_macros_evaluate_once() {
        fn check<T: Send + Sync>() {}
        check::<Error>();
        fn guard(calls: &mut u8) -> Result<()> {
            ensure!(
                {
                    *calls += 1;
                    false
                },
                "number {}",
                *calls
            );
            Ok(())
        }
        let mut calls = 0;
        assert_eq!(guard(&mut calls).unwrap_err().to_string(), "number 1");
        assert_eq!(calls, 1);
    }
}
