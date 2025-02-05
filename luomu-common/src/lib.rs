//! # luomu-common
//!
//! Common types and functions for (low level) network programming.

use std::fmt;

mod address;
pub use address::Address;

mod macaddr;
pub use macaddr::MacAddr;

mod directed_addr;
pub use directed_addr::{Destination, Source};

mod addr_pair;
pub use addr_pair::{AddrPair, IPPair, MacPair, PortPair};

/// Functions to check if IP addresses are valid for source, destination or
/// forwardable
pub mod ipaddr;

/// Invalid address error
#[derive(Debug)]
pub struct InvalidAddress;

impl std::error::Error for InvalidAddress {}

impl fmt::Display for InvalidAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid address")
    }
}
