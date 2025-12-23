use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

use crate::{InvalidAddress, TagError};

/// The MAC address portion of u64
const MAC_BITS: u64 = 0x0000_FFFF_FFFF_FFFF;

/// The VLAN tag portion of u64
const TAG_BITS: u64 = 0x0FFF_0000_0000_0000;

/// Address bytes for Ethernet multicast MAC for All Nodes IPv6 multicast.
const ALL_NODES_MAC: [u8; 6] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01];

/// Base address to use when creating mac addresses for IPv6 multicast
/// addresses. See RFC2464 sect 7.
const IPV6_MULTICAST_BASE_MAC: [u8; 6] = [0x33, 0x33, 0x0, 0x0, 0x0, 0x0];

/// Base address to use when creating mac addresses for IPv4 multicast
/// addresses. Ses RFC1112 sect6.4
const IPV4_MULTICAST_BASE_MAC: [u8; 6] = [0x01, 0x00, 0x5E, 0x0, 0x0, 0x0];

/// A Mac address used for example with Ethernet.
///
/// Mac address is handled as big endian value. All `From<T>` implementations
/// returning [MacAddr] expect input as big endian. `From<u64>` also expects
/// address to reside in lowest 6 bytes. All `From<MacAddr>` and
/// `TryFrom<MacAddr>` implementations return their bytes as big endian.
///
/// **Storing tag**:
///
/// The [MacAddr] type has space to store one VLAN ID (a tag). See
/// [crate::TaggedMacAddr] for type with more space for storing tag stack.
///
/// **Comparison**:
///
/// [MacAddr] are compared fully with [PartialEq] and [Eq] including the VLAN
/// tag. To compare only MAC address part use [MacAddr::eq_mac] or
/// [MacAddr::eq_tag] to only compare VLAN tags.
///
/// **Sorting**:
///
/// [MacAddr]s are sorted by MAC address portion first and then by VLAN tags. So
/// same MAC addresses should be grouped together.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr(u64);

impl MacAddr {
    /// An unspecified MAC address (00:00:00:00:00:00)
    pub const UNSPECIFIED: MacAddr = MacAddr(0);

    /// A broadcast MAC address (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: MacAddr = MacAddr(MAC_BITS);

    /// Return MAC address as byte array in big endian order.
    #[allow(clippy::missing_panics_doc)]
    pub fn as_array(&self) -> [u8; 6] {
        // Taking range of [2,7] is safe from u64. See kani proof in bunnies
        // module.
        self.0.to_be_bytes()[2..=7]
            .try_into()
            .expect("this cannot happen")
    }
}

impl MacAddr {
    /// Checks if this address is unspecified (`00:00:00:00:00:00`) address.
    pub const fn is_unspecified(&self) -> bool {
        self.0 & MAC_BITS == 0
    }

    /// Checks if this address is a multicast address.
    pub const fn is_multicast(&self) -> bool {
        // https://en.wikipedia.org/wiki/MAC_address#Unicast_vs._multicast_(I/G_bit)
        // The least significant bit of an address's first octet is referred to
        // as the I/G, or Individual/Group, bit. When this bit is 0 (zero),
        // the frame is meant to reach only one receiving NIC
        ((self.0 >> 40) & 0x01) == 0x01
    }

    /// Compare the MAC address of two [MacAddr]s. Return true if the MAC
    /// addresses are identical even if the tags are different.
    pub const fn eq_mac(&self, other: &MacAddr) -> bool {
        (self.0 ^ other.0) & MAC_BITS == 0
    }

    /// Compare tags of two [MacAddr]s. Return true if the tags are identical
    /// even if the MAC addresses are different.
    pub const fn eq_tag(&self, other: &MacAddr) -> bool {
        (self.0 ^ other.0) & TAG_BITS == 0
    }

    /// Push VLAN tag.
    pub const fn push_tag(&mut self, tag: u16) -> Result<(), TagError> {
        if tag > 0x0FFF {
            return Err(TagError::TooLargeTag);
        }

        self.0 = (self.0 & !TAG_BITS) | ((tag as u64) << 48);
        Ok(())
    }

    /// Pop a VLAN tag.
    pub const fn pop_tag(&mut self) -> Option<u16> {
        let Some(tag) = self.peek_tag() else {
            return None;
        };
        _ = self.push_tag(0);
        Some(tag)
    }

    /// Peek a tag, but don't pop it out.
    pub const fn peek_tag(&self) -> Option<u16> {
        #[allow(clippy::cast_possible_truncation)]
        match (self.0 >> 48) & 0x0FFF {
            n if n > 0 => Some(n as u16),
            _ => None,
        }
    }

    /// Creates corresponding [MacAddr] for multicast address `addr`.
    ///
    /// If `addr` is a multicast address, the MAC address is created for it
    /// according to relevant specification. For non-multicast addresses
    /// broadcast Mac is returned.
    pub fn multicast_mac_for_ip4(addr: Ipv4Addr) -> Self {
        if !addr.is_multicast() {
            return MacAddr::BROADCAST;
        }

        // RFC 1112 sect 6.4:
        // An IP host group address is mapped to an Ethernet multicast address
        // by placing the low-order 23-bits of the IP address into the low-order
        // 23 bits of the Ethernet multicast address 01-00-5E-00-00-00 (hex).
        let mut mac = IPV4_MULTICAST_BASE_MAC;
        let addr_bytes = addr.octets();
        mac[3] = 0xef & addr_bytes[1];
        mac[4] = addr_bytes[2];
        mac[5] = addr_bytes[3];
        MacAddr::from(mac)
    }

    /// Creates corresponding [MacAddr] for multicast address `addr`.
    ///
    /// If `addr` is a multicast address, the MAC address is created for it
    /// according to relevant specification. For non-multicast addresses
    /// all-nodes multicast address is returned.
    pub fn multicast_mac_for_ip6(addr: Ipv6Addr) -> Self {
        if !addr.is_multicast() {
            return MacAddr::from(ALL_NODES_MAC);
        }

        // RFC 2464 sect 7:
        // An IPv6 packet with a multicast destination address DST, consisting
        // of the sixteen octets DST[1] through DST[16], is transmitted to the
        // Ethernet multicast address whose first two octets are the value 3333
        // hexadecimal and whose last four octets are the last four octets of
        // DST.
        let mut mac = IPV6_MULTICAST_BASE_MAC;
        mac[2] = addr.octets()[12];
        mac[3] = addr.octets()[13];
        mac[4] = addr.octets()[14];
        mac[5] = addr.octets()[15];
        MacAddr::from(mac)
    }

    /// Creates corresponding [MacAddr] for multicast address `addr`.
    ///
    /// If `addr` is a multicast address, the MAC address is created for it
    /// according to relevant specification. For non-multicast addresses either
    /// broadcast Mac (IPv4) or all-nodes multicast address (IPv6) is returned.
    pub fn multicast_mac_for(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(a) => Self::multicast_mac_for_ip4(a),
            IpAddr::V6(a) => Self::multicast_mac_for_ip6(a),
        }
    }
}

impl Ord for MacAddr {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.rotate_left(16).cmp(&other.0.rotate_left(16))
    }
}

impl PartialOrd for MacAddr {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(v: [u8; 6]) -> Self {
        Self::from(&v)
    }
}

impl From<&[u8; 6]> for MacAddr {
    fn from(v: &[u8; 6]) -> Self {
        Self(u64::from_be_bytes([0, 0, v[0], v[1], v[2], v[3], v[4], v[5]]))
    }
}

impl TryFrom<u64> for MacAddr {
    type Error = InvalidAddress;

    fn try_from(mac: u64) -> Result<Self, Self::Error> {
        if mac > MAC_BITS {
            return Err(InvalidAddress);
        }

        Ok(Self(mac))
    }
}

impl From<MacAddr> for u64 {
    fn from(mac: MacAddr) -> Self {
        Self::from(&mac)
    }
}

impl From<&MacAddr> for u64 {
    fn from(mac: &MacAddr) -> Self {
        mac.0 & MAC_BITS
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(mac: MacAddr) -> Self {
        mac.as_array()
    }
}

impl From<&MacAddr> for [u8; 6] {
    fn from(mac: &MacAddr) -> Self {
        mac.as_array()
    }
}

impl FromStr for MacAddr {
    type Err = InvalidAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.splitn(6, ':')
            .filter(|s| s.len() == 2)
            .filter(|s| s.chars().all(|c| c.is_ascii_hexdigit()))
            .map(|v| u8::from_str_radix(v, 16).ok())
            .enumerate()
            .try_fold((0, [0u8; 6]), |(_, mut addr), (i, v)| {
                addr[i] = v?;
                Some((i, addr))
            })
            .map_or(Err(InvalidAddress), |(i, val)| match i {
                5 => Ok(MacAddr::from(val)),
                _ => Err(InvalidAddress),
            })
    }
}

impl TryFrom<&str> for MacAddr {
    type Error = InvalidAddress;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self
            .as_array()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Box<[String]>>()
            .join(":");
        f.write_str(&h)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(tag) = self.peek_tag() {
            write!(f, "MacAddr({self}, tag: {tag})")
        } else {
            write!(f, "MacAddr({self})")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        convert::{TryFrom, TryInto},
        net::{Ipv4Addr, Ipv6Addr},
    };

    use quickcheck::quickcheck;

    use crate::macaddr::ALL_NODES_MAC;

    use super::{MacAddr, TagError};

    #[test]
    fn test_fmt_debug() {
        let mac: MacAddr = [0x00, 0xff, 0x11, 0xee, 0x22, 0xdd].into();
        let debug = format!("{mac:?}");
        assert_eq!(&debug, "MacAddr(00:ff:11:ee:22:dd)");
    }

    #[test]
    fn test_mac_to_array() {
        let slice = [0x00, 0xff, 0x11, 0xee, 0x22, 0xdd];
        let mac: MacAddr = slice.into();
        let array: [u8; 6] = mac.into();
        assert_eq!(slice, array);
    }

    #[test]
    fn test_try_from_u64_bounds() {
        let i0 = 0x0000_0000_0000_0000;
        assert!(MacAddr::try_from(i0).is_ok());

        let i1 = 0x0000_FFFF_FFFF_FFFF;
        assert!(MacAddr::try_from(i1).is_ok());

        let i2 = 0x0001_0000_0000_0000;
        assert!(MacAddr::try_from(i2).is_err());

        let i3 = 0xFFFF_FFFF_FFFF_FFFF;
        assert!(MacAddr::try_from(i3).is_err());
    }

    #[test]
    fn test_try_from_u64_byteoder() {
        let i = 0x0000_1234_5678_9ABC;
        let mac = MacAddr::try_from(i).unwrap();
        let b: [u8; 6] = mac.as_array();
        assert_eq!(&b, &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
    }

    #[test]
    fn test_from_str() {
        let expected: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into();
        let parsed: MacAddr = "00:11:22:33:44:55".try_into().unwrap();
        assert_eq!(parsed, expected);
    }
    #[test]
    fn test_parse() {
        let expected: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into();
        let parsed: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn test_from_str_invalid() {
        assert!(MacAddr::try_from("").is_err());
        assert!(MacAddr::try_from("00:11").is_err()); // short
        assert!(MacAddr::try_from("00:11:22:33:44:55:66:77").is_err()); // long
        assert!(MacAddr::try_from("00:11:22:zz:44:55").is_err()); // invalid bytes
        assert!(MacAddr::try_from("00::22:33:44:55").is_err()); // omitted value

        assert!(MacAddr::try_from("00:11:22:033:44:FF").is_err());
        assert!(MacAddr::try_from("00:11:22:+33:44:FF").is_err());
        assert!(MacAddr::try_from("00:11:22:-33:44:FF").is_err());
        assert!(MacAddr::try_from("00:11:22:+3:44:FF").is_err());
        assert!(MacAddr::try_from("00:11:22:-3:44:FF").is_err());
    }

    #[test]
    fn test_to_string() {
        let str = "00:11:22:33:44:55";
        let addr: MacAddr = str.try_into().unwrap();

        assert_eq!(addr.to_string(), str);
    }

    #[test]
    fn test_is_unspecified() {
        let addr1: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        assert!(!addr1.is_unspecified());
        let addr2: MacAddr = "ff:ff:ff:ff:ff:ff".parse().unwrap();
        assert!(!addr2.is_unspecified());
        let addr3: MacAddr = "00:00:00:00:00:00".parse().unwrap();
        assert!(addr3.is_unspecified());
    }

    #[test]
    fn test_is_multicast() {
        let addr1: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        assert!(!addr1.is_multicast());
        let addr2: MacAddr = "ff:ff:ff:ff:ff:ff".parse().unwrap();
        assert!(addr2.is_multicast());
        let addr3: MacAddr = "33:33:33:00:00:01".parse().unwrap();
        assert!(addr3.is_multicast());
    }

    #[test]
    fn test_eq_mac_tag() {
        let mut addr1: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        let mut addr2: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        let mut addr3: MacAddr = "ff:ff:ff:ff:ff:ff".parse().unwrap();

        assert!(addr1.eq_mac(&addr2));
        assert!(!addr1.eq_mac(&addr3));

        assert!(addr1.eq_tag(&addr2));
        assert!(addr1.eq_tag(&addr3));

        addr1.push_tag(42).unwrap();
        addr2.push_tag(1337).unwrap();
        addr3.push_tag(42).unwrap();

        assert!(addr1.eq_mac(&addr2));
        assert!(!addr1.eq_mac(&addr3));

        assert!(!addr1.eq_tag(&addr2));
        assert!(addr1.eq_tag(&addr3));
    }

    #[test]
    fn test_macaddr_ordering() {
        let mut addr1: MacAddr = "ff:ff:ff:ff:ff:ff".parse().unwrap();
        let mut addr2: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        let mut addr3: MacAddr = "00:11:22:33:44:55".parse().unwrap();

        addr1.push_tag(42).unwrap();
        addr2.push_tag(1337).unwrap();
        addr3.push_tag(42).unwrap();

        let mut v = [addr1, addr2, addr3];
        v.sort();

        assert_eq!(v[0], addr3);
        assert_eq!(v[1], addr2);
        assert_eq!(v[2], addr1);
    }

    #[test]
    fn test_push_pop_tag() {
        let mut addr1: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        assert_eq!(addr1.pop_tag(), None);

        addr1.push_tag(42).unwrap();
        assert_eq!(addr1.pop_tag(), Some(42));

        addr1.push_tag(3999).unwrap();
        assert_eq!(addr1.pop_tag(), Some(3999));

        addr1.push_tag(0).unwrap();
        assert_eq!(addr1.pop_tag(), None);

        assert_eq!(addr1.push_tag(0x0FFF + 1), Err(TagError::TooLargeTag));
    }

    #[test]
    fn test_create_multicast_mac_for6() {
        let mut addr: Ipv6Addr = "ff02::1".parse().unwrap();
        let mut mac = MacAddr::multicast_mac_for_ip6(addr);
        assert_eq!(mac, MacAddr::from(&[0x33, 0x033, 0x00, 0x00, 0x00, 0x01]));
        assert_eq!(mac, MacAddr::multicast_mac_for(addr.into()));

        addr = "ff02::aabb:ccdd:eeff".parse().unwrap();
        mac = MacAddr::multicast_mac_for_ip6(addr);
        assert_eq!(mac, MacAddr::from(&[0x33, 0x33, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(mac, MacAddr::multicast_mac_for(addr.into()));
    }

    #[test]
    fn test_create_multicast_mac_for4() {
        let mut addr: Ipv4Addr = "224.0.0.251".parse().unwrap();
        let mut mac = MacAddr::multicast_mac_for_ip4(addr);
        assert_eq!(mac, MacAddr::from(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]));
        assert_eq!(mac, MacAddr::multicast_mac_for(addr.into()));

        addr = "224.255.127.127".parse().unwrap();
        mac = MacAddr::multicast_mac_for_ip4(addr);
        assert_eq!(mac, MacAddr::from(&[0x01, 0x00, 0x5e, 0xef, 0x7f, 0x7f]));
        assert_eq!(mac, MacAddr::multicast_mac_for(addr.into()));
    }

    #[test]
    fn test_create_multicast_mac_for4_unicast() {
        let addr = "192.0.2.1".parse().unwrap();
        let mac = MacAddr::multicast_mac_for_ip4(addr);
        assert_eq!(mac, MacAddr::BROADCAST);
        assert_eq!(mac, MacAddr::multicast_mac_for(addr.into()));
    }
    #[test]
    fn test_create_multicast_mac_for6_unicast() {
        let addr = "2001:db8::1".parse().unwrap();
        let mac = MacAddr::multicast_mac_for_ip6(addr);
        assert_eq!(mac, MacAddr::from(ALL_NODES_MAC));
        assert_eq!(mac, MacAddr::multicast_mac_for(addr.into()));
    }

    quickcheck! {
        fn prop_macaddr_to_from(xs: (u8, u8, u8, u8, u8, u8)) -> bool {
            let b1: [u8; 6] = [xs.0, xs.1, xs.2, xs.3, xs.4, xs.5];
            let mac = MacAddr::from(b1);
            let b2: [u8; 6] = mac.into();
            b1 == b2
        }

        fn prop_macaddr_vlan(xs: (u8, u8, u8, u8, u8, u8, u16)) -> bool {
            let b1: [u8; 6] = [xs.0, xs.1, xs.2, xs.3, xs.4, xs.5];
            let b2: [u8; 8] = [0, 0, xs.0, xs.1, xs.2, xs.3, xs.4, xs.5];
            let vlan: u16 = xs.6 & 0x0FFF;
            // Zero is special case for vlans
            if vlan == 0 {
                return true;
            }
            let mut mac = MacAddr::from(b1);
            assert_eq!(mac.pop_tag(), None);
            mac.push_tag(vlan).unwrap();

            assert_eq!(mac.as_array(), b1);
            assert_eq!(u64::from(mac), u64::from_be_bytes(b2));

            vlan == mac.pop_tag().unwrap()
        }
    }
}

#[cfg(kani)]
mod bunnies {
    use crate::MacAddr;

    #[kani::proof]
    fn check_macaddr_try_from() {
        let i: u64 = kani::any();
        kani::assume(i <= 0x00FFFFFFFFFFFF);
        assert!(MacAddr::try_from(i).is_ok());
    }

    #[kani::proof]
    fn check_macaddr_as_array() {
        let i: u64 = kani::any();
        kani::assume(i <= 0x00FFFFFFFFFFFF);
        let mac = MacAddr::try_from(i).unwrap();
        mac.as_array();
    }
}
