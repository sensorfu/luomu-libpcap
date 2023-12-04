use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::MacAddr;

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
        match (src.unwrap(), dst.unwrap()) {
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
            IPPair::V4 { src, .. } => Source::new(IpAddr::from(src.unwrap())),
            IPPair::V6 { src, .. } => Source::new(IpAddr::from(src.unwrap())),
        }
    }

    /// Returns the destination IP address from pair.
    fn destination(&self) -> Destination<IpAddr> {
        match self {
            IPPair::V4 { dst, .. } => Destination::new(IpAddr::from(dst.unwrap())),
            IPPair::V6 { dst, .. } => Destination::new(IpAddr::from(dst.unwrap())),
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
        match (src.unwrap(), dst.unwrap()) {
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
        assert_eq!(ippair2.source().unwrap(), ip2);
        assert_eq!(ippair2.destination().unwrap(), ip1);
    }

    #[test]
    fn test_ip_pair_checked_v6() {
        let ip1: IpAddr = "2001:db8::1".parse().unwrap();
        let ip2: IpAddr = "2001:db8:42::12:765".parse().unwrap();

        let ippair1 = IPPair::new_checked(Source::new(ip1), Destination::new(ip2)).unwrap();
        let ippair2 = ippair1.flip();
        assert_eq!(ippair2.source().unwrap(), ip2);
        assert_eq!(ippair2.destination().unwrap(), ip1);
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
        assert_eq!(ippair2.source().unwrap(), ip2);
        assert_eq!(ippair2.destination().unwrap(), ip1);
    }

    #[test]
    fn test_ip6_pair() {
        let ip1: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let ip2: Ipv6Addr = "2001:db8:42::12:765".parse().unwrap();

        let ippair1 = IPPair::new_v6(Source::new(ip1), Destination::new(ip2));
        let ippair2 = ippair1.flip();
        assert_eq!(ippair2.source().unwrap(), ip2);
        assert_eq!(ippair2.destination().unwrap(), ip1);
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
        assert_eq!(p1, flipped.destination().unwrap());
        assert_eq!(p2, flipped.source().unwrap());
    }
}
