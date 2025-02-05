use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use crate::{InvalidAddress, TagError};

// The MAC address portion of u64
const MAC_BITS: u64 = 0x0000FFFFFFFFFFFF;

// The VLAN tag portion of u64
const TAG_BITS: u64 = 0x0FFF000000000000;

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

    /// Return MAC address as bytearray in big endian order.
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
        match (self.0 >> 48) & 0x0FFF {
            n if n > 0 => Some(n as u16),
            _ => None,
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
        Self(u64::from_be_bytes([
            0, 0, v[0], v[1], v[2], v[3], v[4], v[5],
        ]))
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
        s.splitn(6, ":")
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
            .map(|b| format!("{:02x}", b))
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
    use std::convert::{TryFrom, TryInto};

    use quickcheck::quickcheck;

    use super::{MacAddr, TagError};

    #[test]
    fn test_fmt_debug() {
        let mac: MacAddr = [0x00, 0xff, 0x11, 0xee, 0x22, 0xdd].into();
        let debug = format!("{:?}", mac);
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
        let i0 = 0x0000000000000000;
        assert!(MacAddr::try_from(i0).is_ok());

        let i1 = 0x0000FFFFFFFFFFFF;
        assert!(MacAddr::try_from(i1).is_ok());

        let i2 = 0x0001000000000000;
        assert!(MacAddr::try_from(i2).is_err());

        let i3 = 0xFFFFFFFFFFFFFFFF;
        assert!(MacAddr::try_from(i3).is_err());
    }

    #[test]
    fn test_try_from_u64_byteoder() {
        let i = 0x0000123456789ABC;
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

        let mut v = vec![addr1, addr2, addr3];
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
