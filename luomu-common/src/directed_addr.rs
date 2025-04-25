use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::{Deref, DerefMut};

/// A `Source` of any kind. For example an IP address.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
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

    /// Return new [Source] where function f has been applied to ADDR.
    pub fn map<ADDR2, F>(self, f: F) -> Source<ADDR2>
    where
        F: FnOnce(ADDR) -> ADDR2,
    {
        Source(f(self.0))
    }

    /// Returns the underlying value inside `Source`.
    #[deprecated(note = "unwrap() will be removed, use into_inner() instead")]
    pub fn unwrap(self) -> ADDR {
        self.0
    }

    /// Returns the underlying value inside this `Source`
    pub fn into_inner(self) -> ADDR {
        self.0
    }
}

impl<ADDR> From<ADDR> for Source<ADDR> {
    fn from(addr: ADDR) -> Self {
        Self::new(addr)
    }
}

impl<ADDR> From<Destination<ADDR>> for Source<ADDR> {
    fn from(addr: Destination<ADDR>) -> Self {
        addr.flip()
    }
}

impl<ADDR> Deref for Source<ADDR> {
    type Target = ADDR;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<ADDR> DerefMut for Source<ADDR> {
    fn deref_mut(&mut self) -> &mut ADDR {
        &mut self.0
    }
}

impl<ADDR> AsRef<ADDR> for Source<ADDR> {
    fn as_ref(&self) -> &ADDR {
        &self.0
    }
}

impl<ADDR> AsMut<ADDR> for Source<ADDR> {
    fn as_mut(&mut self) -> &mut ADDR {
        &mut self.0
    }
}

impl From<Source<Ipv4Addr>> for Source<IpAddr> {
    fn from(addr: Source<Ipv4Addr>) -> Self {
        Source::new(IpAddr::V4(addr.unwrap()))
    }
}

impl From<Source<Ipv6Addr>> for Source<IpAddr> {
    fn from(addr: Source<Ipv6Addr>) -> Self {
        Source::new(IpAddr::V6(addr.unwrap()))
    }
}

/// A `Destination` of any kind. For example an IP address.
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
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

    /// Return new [Destination] where function f has been applied to ADDR.
    pub fn map<ADDR2, F>(self, f: F) -> Destination<ADDR2>
    where
        F: FnOnce(ADDR) -> ADDR2,
    {
        Destination(f(self.0))
    }

    /// Returns the underlying value inside `Destination`.
    #[deprecated(note = "unwrap() will be removed, use into_inner() instead")]
    pub fn unwrap(self) -> ADDR {
        self.0
    }

    /// Returns the underlying value inside this `Destination`
    pub fn into_inner(self) -> ADDR {
        self.0
    }
}

impl<ADDR> From<ADDR> for Destination<ADDR> {
    fn from(addr: ADDR) -> Self {
        Self::new(addr)
    }
}

impl<ADDR> From<Source<ADDR>> for Destination<ADDR> {
    fn from(addr: Source<ADDR>) -> Self {
        addr.flip()
    }
}

impl<ADDR> Deref for Destination<ADDR> {
    type Target = ADDR;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<ADDR> DerefMut for Destination<ADDR> {
    fn deref_mut(&mut self) -> &mut ADDR {
        &mut self.0
    }
}

impl<ADDR> AsRef<ADDR> for Destination<ADDR> {
    fn as_ref(&self) -> &ADDR {
        &self.0
    }
}

impl<ADDR> AsMut<ADDR> for Destination<ADDR> {
    fn as_mut(&mut self) -> &mut ADDR {
        &mut self.0
    }
}

impl From<Destination<Ipv4Addr>> for Destination<IpAddr> {
    fn from(addr: Destination<Ipv4Addr>) -> Self {
        Destination::new(IpAddr::V4(addr.unwrap()))
    }
}

impl From<Destination<Ipv6Addr>> for Destination<IpAddr> {
    fn from(addr: Destination<Ipv6Addr>) -> Self {
        Destination::new(IpAddr::V6(addr.unwrap()))
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

    #[test]
    fn test_deref() {
        let a = Source::new(Ipv4Addr::UNSPECIFIED);
        assert_eq!(*a, Ipv4Addr::UNSPECIFIED);
        assert!(a.is_unspecified());

        let mut b = Source::new(Ipv4Addr::UNSPECIFIED);
        *b = Ipv4Addr::BROADCAST;
        assert_eq!(*b, Ipv4Addr::BROADCAST);
        assert!(b.is_broadcast());
    }

    #[test]
    fn test_no_copy_type() {
        let hello: &str = "Hello World!";
        let a: Source<&str> = hello.into();
        assert_eq!(*a, hello);
    }

    #[test]
    fn test_map() {
        let src_port: Source<u16> = Source::new(12765);
        let new_port = src_port.map(|p| p.wrapping_add(1));
        assert_eq!(new_port.unwrap(), src_port.unwrap() + 1);

        let dst_port: Destination<u16> = Destination::new(12765);
        let new_port = dst_port.map(|p| p.wrapping_add(2));
        assert_eq!(new_port.unwrap(), src_port.unwrap() + 2);

        let src_ip: Source<Ipv4Addr> = Source::new(Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            src_ip.map(IpAddr::V4),
            Source::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        );

        let dst_ip: Destination<Ipv6Addr> = Destination::new(Ipv6Addr::UNSPECIFIED);
        assert_eq!(
            dst_ip.map(IpAddr::V6),
            Destination::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        );
    }
}
