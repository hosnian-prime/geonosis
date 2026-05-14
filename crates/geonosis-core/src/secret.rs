//! Secret-wrapping newtype.
//!
//! `Secret<T>` keeps a value out of `Debug` output and zeroes it on drop
//! (when `T: Zeroize`). Tracing-aware code MUST NOT log `Secret` fields.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Wrapper that hides the inner value from `Debug` and zeroizes on drop.
///
/// `T: Zeroize` is required so callers can't smuggle a non-scrubbable type
/// (such as `Vec<u8>` without the feature flag) past the type system.
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    pub fn new(v: T) -> Self {
        Self(v)
    }

    /// Borrow the inner value. Treat as sensitive — never log.
    pub fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Secret").field("value", &"***").finish()
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize + PartialEq> PartialEq for Secret<T> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Zeroize + Eq> Eq for Secret<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts() {
        let s = Secret::new("hunter2".to_string());
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(dbg.contains("***"));
    }

    #[test]
    fn expose_returns_inner() {
        let s = Secret::new(42);
        assert_eq!(*s.expose(), 42);
    }
}
