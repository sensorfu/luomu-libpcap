use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{tagged_macaddr::TagStack, MacAddr, TagError};

use super::{Destination, Source};

/// In network protocol implementations addresses usually comes in pairs: Source
/// and destination IP address, source and destination ports, etc.
///
/// This trait is abstraction of this idea.
pub trait AddrPair<ADDR> {
    /// Construct new [AddrPair] with given [Source] and [Destination]
    /// addresses.
    fn new(src: Source<ADDR>, dst: Destination<ADDR>) -> Self;

    /// Return source address from address pair.
    fn source(&self) -> Source<ADDR>;

    /// Return destination address from address pair.
    fn destination(&self) -> Destination<ADDR>;

    /// Return new address pair with source and destination addresses flipped.
    fn flip(&self) -> Self;
}

/// In protocols IP addresses usually appear in pairs: Source and destination
/// IP. This enum provides such pair for both IPv4 and IPv6 addresses.
///
/// Main benefit of using this is to have the protocol version associated with
/// both addresses at the same time providing ergonomics and a bit less memory
/// consumption.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub enum IPPair {
    /// IPv4 address pair
    V4 {
        /// Source IPv4 address
        src: Source<Ipv4Addr>,
        /// Destination IPv4 address
        dst: Destination<Ipv4Addr>,
    },
    /// IPv6 address pair
    V6 {
        /// Source IPv6 address
        src: Source<Ipv6Addr>,
        /// Destination IPv4 address
        dst: Destination<Ipv6Addr>,
    },
}

impl AddrPair<IpAddr> for IPPair {
    /// Construct a new `IPPair`.
    ///
    /// # Panics
    /// Both [IpAddr] need to be same IP version or the call will panic. Use
    /// [IPPair::new_checked], [IPPair::new_v4] or [IPPair::new_v6] instead for
    /// safe versions.
    fn new(src: Source<IpAddr>, dst: Destination<IpAddr>) -> IPPair {
        match (src.into_inner(), dst.into_inner()) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                IPPair::new_v4(Source::new(src), Destination::new(dst))
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                IPPair::new_v6(Source::new(src), Destination::new(dst))
            }
            _ => panic!(
                "IPPair::new() invalid IP address families provided. src: {:?}, dst: {:?}",
                src, dst
            ),
        }
    }

    /// Returns the source IP address from pair.
    fn source(&self) -> Source<IpAddr> {
        match self {
            IPPair::V4 { src, .. } => Source::new(IpAddr::from(src.into_inner())),
            IPPair::V6 { src, .. } => Source::new(IpAddr::from(src.into_inner())),
        }
    }

    /// Returns the destination IP address from pair.
    fn destination(&self) -> Destination<IpAddr> {
        match self {
            IPPair::V4 { dst, .. } => Destination::new(IpAddr::from(dst.into_inner())),
            IPPair::V6 { dst, .. } => Destination::new(IpAddr::from(dst.into_inner())),
        }
    }

    /// Flip source and destination around: Source is new destination and
    /// destination is new source.
    fn flip(&self) -> IPPair {
        IPPair::new(self.destination().flip(), self.source().flip())
    }
}

impl From<(Source<Ipv4Addr>, Destination<Ipv4Addr>)> for IPPair {
    fn from(value: (Source<Ipv4Addr>, Destination<Ipv4Addr>)) -> Self {
        let (src, dst) = value;
        IPPair::new_v4(src, dst)
    }
}

impl From<(Destination<Ipv4Addr>, Source<Ipv4Addr>)> for IPPair {
    fn from(value: (Destination<Ipv4Addr>, Source<Ipv4Addr>)) -> Self {
        let (dst, src) = value;
        IPPair::new_v4(src, dst)
    }
}

impl From<(Source<Ipv6Addr>, Destination<Ipv6Addr>)> for IPPair {
    fn from(value: (Source<Ipv6Addr>, Destination<Ipv6Addr>)) -> Self {
        let (src, dst) = value;
        IPPair::new_v6(src, dst)
    }
}

impl From<(Destination<Ipv6Addr>, Source<Ipv6Addr>)> for IPPair {
    fn from(value: (Destination<Ipv6Addr>, Source<Ipv6Addr>)) -> Self {
        let (dst, src) = value;
        IPPair::new_v6(src, dst)
    }
}

impl IPPair {
    /// Creates [IPPair] for given source and destination addresses.
    /// None is returned if addresses are of different address families.
    pub fn new_checked(src: Source<IpAddr>, dst: Destination<IpAddr>) -> Option<IPPair> {
        match (src.into_inner(), dst.into_inner()) {
            (IpAddr::V4(s), IpAddr::V4(d)) => {
                Some(IPPair::new_v4(Source::new(s), Destination::new(d)))
            }
            (IpAddr::V6(s), IpAddr::V6(d)) => {
                Some(IPPair::new_v6(Source::new(s), Destination::new(d)))
            }
            _ => None,
        }
    }
    /// Construct a new `IPPair` from two [Ipv4Addr].
    pub const fn new_v4(src: Source<Ipv4Addr>, dst: Destination<Ipv4Addr>) -> IPPair {
        IPPair::V4 { src, dst }
    }

    /// Construct a new `IPPair` from two [Ipv6Addr].
    pub const fn new_v6(src: Source<Ipv6Addr>, dst: Destination<Ipv6Addr>) -> IPPair {
        IPPair::V6 { src, dst }
    }

    /// Returns true if IP pair are IPv4 addresses.
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, IPPair::V4 { .. })
    }

    /// Returns true if IP pair are IPv6 addresses.
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, IPPair::V6 { .. })
    }
}

/// A pair of IPv4 addresses. Useful for IPv4 only protocols like ARP.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Ipv4Pair {
    src: Source<Ipv4Addr>,
    dst: Destination<Ipv4Addr>,
}

impl AddrPair<Ipv4Addr> for Ipv4Pair {
    fn new(src: Source<Ipv4Addr>, dst: Destination<Ipv4Addr>) -> Self {
        Self { src, dst }
    }

    fn source(&self) -> Source<Ipv4Addr> {
        self.src
    }

    fn destination(&self) -> Destination<Ipv4Addr> {
        self.dst
    }

    fn flip(&self) -> Self {
        Self {
            src: self.dst.flip(),
            dst: self.src.flip(),
        }
    }
}

impl From<Ipv4Pair> for IPPair {
    fn from(ip_pair: Ipv4Pair) -> Self {
        IPPair::new_v4(ip_pair.source(), ip_pair.destination())
    }
}

/// A pair of IPv6 addresses.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Ipv6Pair {
    src: Source<Ipv6Addr>,
    dst: Destination<Ipv6Addr>,
}

impl AddrPair<Ipv6Addr> for Ipv6Pair {
    fn new(src: Source<Ipv6Addr>, dst: Destination<Ipv6Addr>) -> Self {
        Self { src, dst }
    }

    fn source(&self) -> Source<Ipv6Addr> {
        self.src
    }

    fn destination(&self) -> Destination<Ipv6Addr> {
        self.dst
    }

    fn flip(&self) -> Self {
        Self {
            src: self.dst.flip(),
            dst: self.src.flip(),
        }
    }
}

impl From<Ipv6Pair> for IPPair {
    fn from(ip_pair: Ipv6Pair) -> Self {
        IPPair::new_v6(ip_pair.source(), ip_pair.destination())
    }
}

/// TCP and UDP use 16 bit port numbers and protocol implementations need to
/// handle both source and destination port numbers together. This keeps both
/// port numbers.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct PortPair {
    src: Source<u16>,
    dst: Destination<u16>,
}

impl From<(Source<u16>, Destination<u16>)> for PortPair {
    fn from(value: (Source<u16>, Destination<u16>)) -> Self {
        let (src, dst) = value;
        PortPair::new(src, dst)
    }
}

impl From<(Destination<u16>, Source<u16>)> for PortPair {
    fn from(value: (Destination<u16>, Source<u16>)) -> Self {
        let (dst, src) = value;
        PortPair::new(src, dst)
    }
}

impl AddrPair<u16> for PortPair {
    /// Construct new `PortPair` with `Source` and `Destination` ports.
    fn new(src: Source<u16>, dst: Destination<u16>) -> PortPair {
        Self { src, dst }
    }

    /// Return the source port.
    fn source(&self) -> Source<u16> {
        self.src
    }

    /// Return the destionation port.
    fn destination(&self) -> Destination<u16> {
        self.dst
    }

    /// Flip source and destination ports.
    fn flip(&self) -> PortPair {
        Self {
            src: self.dst.flip(),
            dst: self.src.flip(),
        }
    }
}

/// A pair of MAC addresses.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct MacPair {
    src: Source<MacAddr>,
    dst: Destination<MacAddr>,
}

impl From<(Source<MacAddr>, Destination<MacAddr>)> for MacPair {
    fn from(value: (Source<MacAddr>, Destination<MacAddr>)) -> Self {
        let (src, dst) = value;
        MacPair::new(src, dst)
    }
}

impl From<(Destination<MacAddr>, Source<MacAddr>)> for MacPair {
    fn from(value: (Destination<MacAddr>, Source<MacAddr>)) -> Self {
        let (dst, src) = value;
        MacPair::new(src, dst)
    }
}

impl AddrPair<MacAddr> for MacPair {
    /// Construct new `MacPair` with `Source` and `Destination` MAC addresses.
    fn new(src: Source<MacAddr>, dst: Destination<MacAddr>) -> Self {
        Self { src, dst }
    }

    /// Return the source Mac.
    fn source(&self) -> Source<MacAddr> {
        self.src
    }

    /// Return the destionation Mac.
    fn destination(&self) -> Destination<MacAddr> {
        self.dst
    }

    /// Flip source and destination MAC addresses.
    fn flip(&self) -> Self {
        Self {
            src: self.dst.flip(),
            dst: self.src.flip(),
        }
    }
}

/// A pair of MAC addresses with support for storing a stack of VLAN IDs.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct TaggedMacPair {
    src: Source<MacAddr>,
    dst: Destination<MacAddr>,
    tag_stack: TagStack,
}

impl TaggedMacPair {
    /// Push a VLAN tag into the stack. The outermost tag should be pushed
    /// first.
    pub const fn push_tag(&mut self, tag: u16) -> Result<(), TagError> {
        self.tag_stack.push_tag(tag)
    }

    /// Pop a VLAN tag from the stack. The innermost tag pops out first.
    pub const fn pop_tag(&mut self) -> Option<u16> {
        self.tag_stack.pop_tag()
    }

    /// Peek a next tag in stack, but don't pop it out.
    pub const fn peek_tag(&self) -> Option<u16> {
        self.tag_stack.peek_tag()
    }

    /// Get all tags as an array.
    pub fn tag_array(&self) -> [u16; 5] {
        self.tag_stack.tag_array()
    }
}

impl From<(Source<MacAddr>, Destination<MacAddr>)> for TaggedMacPair {
    fn from(value: (Source<MacAddr>, Destination<MacAddr>)) -> Self {
        let (src, dst) = value;
        TaggedMacPair::new(src, dst)
    }
}

impl From<(Destination<MacAddr>, Source<MacAddr>)> for TaggedMacPair {
    fn from(value: (Destination<MacAddr>, Source<MacAddr>)) -> Self {
        let (dst, src) = value;
        TaggedMacPair::new(src, dst)
    }
}

impl AddrPair<MacAddr> for TaggedMacPair {
    /// Construct new `TaggedMacPair` with `Source` and `Destination` MAC addresses.
    fn new(src: Source<MacAddr>, dst: Destination<MacAddr>) -> Self {
        Self {
            src,
            dst,
            tag_stack: TagStack::new(),
        }
    }

    /// Return the source Mac.
    fn source(&self) -> Source<MacAddr> {
        self.src
    }

    /// Return the destionation Mac.
    fn destination(&self) -> Destination<MacAddr> {
        self.dst
    }

    /// Flip source and destination MAC addresses.
    fn flip(&self) -> Self {
        Self {
            src: self.dst.flip(),
            dst: self.src.flip(),
            tag_stack: self.tag_stack,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::{AddrPair, Destination, IPPair, PortPair, Source};

    #[test]
    fn test_ip_pair_checked_v4() {
        let ip1: IpAddr = "192.0.2.5".parse().unwrap();
        let ip2: IpAddr = "198.51.100.255".parse().unwrap();

        let ippair1 = IPPair::new_checked(Source::new(ip1), Destination::new(ip2)).unwrap();
        let ippair2 = ippair1.flip();
        assert_eq!(ippair2.source().into_inner(), ip2);
        assert_eq!(ippair2.destination().into_inner(), ip1);
    }

    #[test]
    fn test_ip_pair_checked_v6() {
        let ip1: IpAddr = "2001:db8::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:42::12:765".parse().unwrap();

        let ippair1 = IPPair::new_checked(Source::new(ip1), Destination::new(ip2)).unwrap();
        let ippair2 = ippair1.flip();
        assert_eq!(ippair2.source().into_inner(), ip2);
        assert_eq!(ippair2.destination().into_inner(), ip1);
    }

    #[test]
    fn test_ip_pair_checked_invalid() {
        let ip1: IpAddr = "192.0.2.5".parse().unwrap();
        let ip2: IpAddr = "198.51.100.255".parse().unwrap();
        let ip3: IpAddr = "2001:db8::1".parse().unwrap();
        let ip4: IpAddr = "2001:db8:42::12:765".parse().unwrap();

        assert_eq!(
            IPPair::new_checked(Source::new(ip1), Destination::new(ip3)),
            None
        );
        assert_eq!(
            IPPair::new_checked(Source::new(ip2), Destination::new(ip4)),
            None
        );
        assert_eq!(
            IPPair::new_checked(Source::new(ip3), Destination::new(ip1)),
            None
        );
        assert_eq!(
            IPPair::new_checked(Source::new(ip4), Destination::new(ip2)),
            None
        );
    }

    #[test]
    fn test_ip4_pair() {
        let ip1: Ipv4Addr = "192.0.2.5".parse().unwrap();
        let ip2: Ipv4Addr = "198.51.100.255".parse().unwrap();

        let ippair1 = IPPair::new_v4(Source::new(ip1), Destination::new(ip2));
        let ippair2 = ippair1.flip();
        assert_eq!(ippair2.source().into_inner(), ip2);
        assert_eq!(ippair2.destination().into_inner(), ip1);
    }

    #[test]
    fn test_ip6_pair() {
        let ip1: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ip2: Ipv6Addr = "2001:db8:42::12:765".parse().unwrap();

        let ippair1 = IPPair::new_v6(Source::new(ip1), Destination::new(ip2));
        let ippair2 = ippair1.flip();
        assert_eq!(ippair2.source().into_inner(), ip2);
        assert_eq!(ippair2.destination().into_inner(), ip1);
    }

    #[test]
    #[should_panic]
    fn test_ip_pair_fail() {
        let ip1: IpAddr = "192.0.2.5".parse().unwrap();
        let ip2: IpAddr = "2001:db8:42::12:765".parse().unwrap();

        IPPair::new(Source::new(ip1), Destination::new(ip2));
    }

    #[test]
    fn test_port_pair() {
        let (p1, p2) = (42, 12765);
        let port_pair = PortPair::new(Source::new(p1), Destination::new(p2));
        let flipped = port_pair.flip();
        assert_eq!(p1, flipped.destination().into_inner());
        assert_eq!(p2, flipped.source().into_inner());
    }
}
