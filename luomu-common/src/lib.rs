#![doc = include_str!("../README.md")]

use std::fmt;

mod address;
pub use address::Address;

mod macaddr;
pub use macaddr::MacAddr;

mod directed_addr;
pub use directed_addr::{Destination, Source};

mod addr_pair;
pub use addr_pair::{AddrPair, IPPair, Ipv4Pair, Ipv6Pair, MacPair, PortPair, TaggedMacPair};

mod tagged_macaddr;
pub use tagged_macaddr::TaggedMacAddr;

/// Functions to check if IP addresses are valid for source, destination or
/// forwardable
pub mod ipaddr;

/// Invalid address error
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InvalidAddress;

impl std::error::Error for InvalidAddress {}

impl fmt::Display for InvalidAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid address")
    }
}

/// Errors specific to VLAN IDs (tags)
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TagError {
    /// Tag stack is full and no additional tags can be added
    TooManyTags,
    /// The given tag is too large
    TooLargeTag,
}

impl fmt::Display for TagError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TagError::TooLargeTag => f.write_str("the given tag is too large"),
            TagError::TooManyTags => f.write_str("too many VLAN tags"),
        }
    }
}

impl std::error::Error for TagError {}
