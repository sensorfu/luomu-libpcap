#![deny(
    future_incompatible,
    nonstandard_style,
    rust_2018_compatibility,
    rust_2018_idioms,
    unused,
    unsafe_code,
    missing_docs
)]

//! # luomu-common
//!
//! Common types and functions for (low) level network programming.

use std::fmt;

mod address;
pub use address::Address;

mod macaddr;
pub use macaddr::MacAddr;

/// Invalid address error
#[derive(Debug)]
pub struct InvalidAddress;

impl std::error::Error for InvalidAddress {}

impl fmt::Display for InvalidAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid address")
    }
}
