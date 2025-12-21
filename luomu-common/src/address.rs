use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{InvalidAddress, MacAddr};

/// [Address] of some sort. IPv4, IPv6 or MAC.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    /// IPv4 address
    Ipv4(Ipv4Addr),
    /// IPv6 address
    Ipv6(Ipv6Addr),
    /// MAC address
    Mac(MacAddr),
}

impl Address {
    /// True if IPv4 address
    pub const fn is_ipv4(&self) -> bool {
        matches!(self, Address::Ipv4(_))
    }

    /// True if IPv6 address
    pub const fn is_ipv6(&self) -> bool {
        matches!(self, Address::Ipv6(_))
    }

    /// True if either IPv4 or IPv6 address
    pub const fn is_ip(&self) -> bool {
        self.is_ipv4() || self.is_ipv6()
    }

    /// True if MAC address
    pub const fn is_mac(&self) -> bool {
        matches!(self, Address::Mac(_))
    }

    /// Return the `Ipv4Addr` or None
    pub const fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Address::Ipv4(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Return the `Ipv6Addr` or None
    pub const fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Address::Ipv6(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Return the `IpAddr` or None
    pub const fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Address::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            Address::Mac(_) => None,
        }
    }

    /// Return the `MacAddr` or None
    pub const fn as_mac(&self) -> Option<MacAddr> {
        match self {
            Address::Ipv4(_) | Address::Ipv6(_) => None,
            Address::Mac(mac) => Some(*mac),
        }
    }
}

impl From<Ipv4Addr> for Address {
    fn from(ip: Ipv4Addr) -> Self {
        Address::Ipv4(ip)
    }
}

impl From<Ipv6Addr> for Address {
    fn from(ip: Ipv6Addr) -> Self {
        Address::Ipv6(ip)
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Address::Ipv4(ip),
            IpAddr::V6(ip) => Address::Ipv6(ip),
        }
    }
}

impl From<MacAddr> for Address {
    fn from(mac: MacAddr) -> Self {
        Address::Mac(mac)
    }
}

impl From<[u8; 6]> for Address {
    fn from(mac: [u8; 6]) -> Self {
        Address::Mac(MacAddr::from(mac))
    }
}

impl From<&[u8; 6]> for Address {
    fn from(mac: &[u8; 6]) -> Self {
        Address::Mac(MacAddr::from(mac))
    }
}

impl TryFrom<Address> for Ipv4Addr {
    type Error = InvalidAddress;

    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv4(ip) => Ok(ip),
            _ => Err(InvalidAddress),
        }
    }
}

impl TryFrom<Address> for Ipv6Addr {
    type Error = InvalidAddress;

    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv6(ip) => Ok(ip),
            _ => Err(InvalidAddress),
        }
    }
}

impl TryFrom<Address> for IpAddr {
    type Error = InvalidAddress;

    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv4(ip) => Ok(ip.into()),
            Address::Ipv6(ip) => Ok(ip.into()),
            Address::Mac(_) => Err(InvalidAddress),
        }
    }
}

impl TryFrom<&Address> for Ipv4Addr {
    type Error = InvalidAddress;

    fn try_from(addr: &Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv4(ip) => Ok(*ip),
            Address::Ipv6(_) | Address::Mac(_) => Err(InvalidAddress),
        }
    }
}

impl TryFrom<&Address> for Ipv6Addr {
    type Error = InvalidAddress;

    fn try_from(addr: &Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv6(ip) => Ok(*ip),
            Address::Ipv4(_) | Address::Mac(_) => Err(InvalidAddress),
        }
    }
}

impl TryFrom<&Address> for IpAddr {
    type Error = InvalidAddress;

    fn try_from(addr: &Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv4(ip) => Ok((*ip).into()),
            Address::Ipv6(ip) => Ok((*ip).into()),
            Address::Mac(_) => Err(InvalidAddress),
        }
    }
}

impl TryFrom<Address> for MacAddr {
    type Error = InvalidAddress;

    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Mac(mac) => Ok(mac),
            Address::Ipv4(_) | Address::Ipv6(_) => Err(InvalidAddress),
        }
    }
}
