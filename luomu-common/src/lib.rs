#![deny(
    future_incompatible,
    nonstandard_style,
    rust_2018_compatibility,
    rust_2018_idioms,
    rustdoc,
    unused,
    unsafe_code,
    missing_docs
)]

//! # luomu-common
//!
//! Common types and functions for (low) level network programming.

mod address;
pub use address::{Address, InvalidAddress};

mod macaddr;
pub use macaddr::MacAddr;
