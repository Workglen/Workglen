//! The narrow part of `lazaret-verify` used by the vendored Lazaret archive crate.
//!
//! Lazaret's full verification facade is intentionally not duplicated here. The
//! archive crate uses only Pratique's bounded inflater, which Workglen already
//! vendors and reviews as a first-party dependency.

#![forbid(unsafe_code)]

pub use pratique::inflate;
