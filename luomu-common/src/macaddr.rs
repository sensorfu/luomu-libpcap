use std::convert::{TryFrom, TryInto};
use std::fmt;
use std::str::FromStr;

use super::InvalidAddress;

/// A Mac address used for example with Ethernet.
///
/// Mac address is handled as big endian value. All `From<T>` implementations
/// returning `MacAddr` expect input as big endian. `From<u64>` also expects
/// address to reside in lowest 6 bytes. All `From<MacAddr>` and
/// `TryFrom<MacAddr>` implementations return their bytes as big endian.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(u64);

impl MacAddr {
    /// A unspecified MAC address (00:00:00:00:00:00)
    pub const UNSPECIFIED: MacAddr = MacAddr(0);

    /// A broadcast MAC address (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: MacAddr = MacAddr(0x0000FFFFFFFFFFFF);

    /// Return MAC address as bytearray in big endian order.
    pub fn as_array(&self) -> [u8; 6] {
        u64::from(self).to_be_bytes()[2..=7].try_into().unwrap()
    }
}

impl MacAddr {
    /// Checks if this address is unspecified (`00:00:00:00:00:00`) address.
    pub const fn is_unspecified(&self) -> bool {
        self.0 & 0x0000FFFFFFFFFFFF == 0
    }

    /// Checks if this address is a multicast address.
    pub const fn is_multicast(&self) -> bool {
        // https://en.wikipedia.org/wiki/MAC_address#Unicast_vs._multicast_(I/G_bit)
        // The least significant bit of an address's first octet is referred to
        // as the I/G, or Individual/Group, bit. When this bit is 0 (zero),
        // the frame is meant to reach only one receiving NIC
        ((self.0 >> 40) & 0x01) == 0x01
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(v: [u8; 6]) -> Self {
        Self::from(&v)
    }
}

impl From<&[u8; 6]> for MacAddr {
    fn from(v: &[u8; 6]) -> Self {
        let r = (u64::from(v[0]) << 40)
            + (u64::from(v[1]) << 32)
            + (u64::from(v[2]) << 24)
            + (u64::from(v[3]) << 16)
            + (u64::from(v[4]) << 8)
            + u64::from(v[5]);
        Self(r)
    }
}

impl TryFrom<u64> for MacAddr {
    type Error = InvalidAddress;

    fn try_from(mac: u64) -> Result<Self, Self::Error> {
        if mac > 0x0000FFFFFFFFFFFF {
            return Err(InvalidAddress);
        }

        Ok(Self(mac))
    }
}

impl From<MacAddr> for u64 {
    fn from(mac: MacAddr) -> Self {
        mac.0
    }
}

impl From<&MacAddr> for u64 {
    fn from(mac: &MacAddr) -> Self {
        mac.0
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
            .try_fold(([0u8; 6], 0), |(mut addr, _), (i, v)| {
                addr[i] = v?;
                Some((addr, i))
            })
            .map_or(Err(InvalidAddress), |(val, i)| {
                match i {
                    5 => Ok(MacAddr::from(val)),
                    _ => Err(InvalidAddress),
                }
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
        let h = self.as_array()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Box<[String]>>()
            .join(":");
        f.write_str(&h)
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({})", self)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::{TryFrom, TryInto};

    use quickcheck::quickcheck;

    use super::MacAddr;

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
        assert_eq!(parsed, expected)
    }
    #[test]
    fn test_parse() {
        let expected: MacAddr = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into();
        let parsed: MacAddr = "00:11:22:33:44:55".parse().unwrap();
        assert_eq!(parsed, expected)
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

    quickcheck! {
        fn prop_macaddr_to_from(xs: (u8, u8, u8, u8, u8, u8)) -> bool {
            let b1: [u8; 6] = [xs.0, xs.1, xs.2, xs.3, xs.4, xs.5];
            let mac = MacAddr::from(b1);
            let b2: [u8; 6] = mac.into();
            b1 == b2
        }
    }
}
