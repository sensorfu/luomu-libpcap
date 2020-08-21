use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{InvalidAddress, MacAddr};

/// Address of some sort. IPv4, IPv6, MAC.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
    pub fn is_ipv4(&self) -> bool {
        match self {
            Address::Ipv4(_) => true,
            _ => false,
        }
    }

    /// True if IPv6 address
    pub fn is_ipv6(&self) -> bool {
        match self {
            Address::Ipv6(_) => true,
            _ => false,
        }
    }

    /// True if either IPv4 or IPv6 address
    pub fn is_ip(&self) -> bool {
        self.is_ipv4() || self.is_ipv6()
    }

    /// True if MAC address
    pub fn is_mac(&self) -> bool {
        match self {
            Address::Mac(_) => true,
            _ => false,
        }
    }

    /// Return the `Ipv4Addr` or None
    pub fn as_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            Address::Ipv4(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Return the `Ipv6Addr` or None
    pub fn as_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            Address::Ipv6(ip) => Some(*ip),
            _ => None,
        }
    }

    /// Return the `IpAddr` or None
    pub fn as_ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ipv4(ip) => Some((*ip).into()),
            Address::Ipv6(ip) => Some((*ip).into()),
            _ => None,
        }
    }

    /// Return the `MacAddr` or None
    pub fn as_mac(&self) -> Option<MacAddr> {
        match self {
            Address::Mac(mac) => Some(*mac),
            _ => None,
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
            _ => Err(InvalidAddress),
        }
    }
}

impl TryFrom<&Address> for Ipv4Addr {
    type Error = InvalidAddress;

    fn try_from(addr: &Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv4(ip) => Ok(*ip),
            _ => Err(InvalidAddress),
        }
    }
}

impl TryFrom<&Address> for Ipv6Addr {
    type Error = InvalidAddress;

    fn try_from(addr: &Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv6(ip) => Ok(*ip),
            _ => Err(InvalidAddress),
        }
    }
}

impl TryFrom<&Address> for IpAddr {
    type Error = InvalidAddress;

    fn try_from(addr: &Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Ipv4(ip) => Ok((*ip).into()),
            Address::Ipv6(ip) => Ok((*ip).into()),
            _ => Err(InvalidAddress),
        }
    }
}

impl TryFrom<Address> for MacAddr {
    type Error = InvalidAddress;

    fn try_from(addr: Address) -> Result<Self, Self::Error> {
        match addr {
            Address::Mac(mac) => Ok(mac),
            _ => Err(InvalidAddress),
        }
    }
}
