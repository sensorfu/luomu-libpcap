/// A `Source` of any kind. For example an IP address.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Source<ADDR>(ADDR);

impl<ADDR> Source<ADDR> {
    /// Constructs a new `Source`.
    pub const fn new(addr: ADDR) -> Self {
        Self(addr)
    }

    /// Make a [Destination] out from `Source`.
    pub fn flip(self) -> Destination<ADDR> {
        Destination(self.unwrap())
    }

    /// Returns the underlying value inside `Source`.
    pub fn unwrap(self) -> ADDR {
        self.0
    }
}

/// A `Destination` of any kind. For example an IP address.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub struct Destination<ADDR>(ADDR);

impl<ADDR> Destination<ADDR> {
    /// Constructs a new `Destination`.
    pub const fn new(addr: ADDR) -> Self {
        Self(addr)
    }

    /// Make a [Source] out from `Destination`.
    pub fn flip(self) -> Source<ADDR> {
        Source(self.unwrap())
    }

    /// Returns the underlying value inside `Destination`.
    pub fn unwrap(self) -> ADDR {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

    use super::{Destination, Source};

    #[test]
    fn test_src_dst_flip() {
        let i1 = Destination::new(42);
        let i2 = i1.flip();
        let i3 = i2.flip();

        assert_eq!(i2.unwrap(), 42);
        assert_eq!(i1, i3);
    }

    #[test]
    fn test_src_dst_ipaddr() {
        let ip1 = Destination::new(Ipv4Addr::UNSPECIFIED);
        let ip2 = Source::new(Ipv4Addr::UNSPECIFIED);
        let ip3 = Destination::new(Ipv6Addr::UNSPECIFIED);
        let ip4 = Source::new(Ipv6Addr::UNSPECIFIED);

        let ip5 = Destination::new(IpAddr::from(ip1.unwrap()));
        let ip6 = Source::new(IpAddr::from(ip2.unwrap()));
        let ip7 = Destination::new(IpAddr::from(ip3.unwrap()));
        let ip8 = Source::new(IpAddr::from(ip4.unwrap()));

        assert_eq!(ip5.unwrap(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(ip6.unwrap(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(ip7.unwrap(), Ipv6Addr::UNSPECIFIED);
        assert_eq!(ip8.unwrap(), Ipv6Addr::UNSPECIFIED);
    }

    #[test]
    fn test_src_dst_socketaddr() {
        let sa1 = Destination::new(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 42));
        let sa2 = Source::new(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 42));
        let sa3 = Destination::new(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 42, 0, 0));
        let sa4 = Source::new(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 42, 0, 0));

        let sa5 = Destination::new(SocketAddr::from(sa1.unwrap()));
        let sa6 = Source::new(SocketAddr::from(sa2.unwrap()));
        let sa7 = Destination::new(SocketAddr::from(sa3.unwrap()));
        let sa8 = Source::new(SocketAddr::from(sa4.unwrap()));

        assert_eq!(
            (sa5.unwrap().ip(), sa5.unwrap().port()),
            (Ipv4Addr::UNSPECIFIED.into(), 42)
        );
        assert_eq!(
            (sa6.unwrap().ip(), sa6.unwrap().port()),
            (Ipv4Addr::UNSPECIFIED.into(), 42)
        );
        assert_eq!(
            (sa7.unwrap().ip(), sa7.unwrap().port()),
            (Ipv6Addr::UNSPECIFIED.into(), 42)
        );
        assert_eq!(
            (sa8.unwrap().ip(), sa8.unwrap().port()),
            (Ipv6Addr::UNSPECIFIED.into(), 42)
        );
    }
}
