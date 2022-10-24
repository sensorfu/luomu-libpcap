use std::convert::{TryFrom, TryInto};
use std::fmt;

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
    /// A broadcast MAC address (FF:FF:FF:FF:FF:FF)
    pub const BROADCAST: MacAddr = MacAddr(0x0000FFFFFFFFFFFF);
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
        (&mac).into()
    }
}

impl From<&MacAddr> for [u8; 6] {
    fn from(mac: &MacAddr) -> Self {
        u64::from(mac).to_be_bytes()[2..=7].try_into().unwrap()
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b: [u8; 6] = self.into();
        let h = b
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        f.write_str(&h)
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryFrom;

    use quickcheck::quickcheck;

    use super::MacAddr;

    #[test]
    fn test_fmt_debug() {
        let mac: MacAddr = [0x00, 0xff, 0x11, 0xee, 0x22, 0xdd].into();
        let debug = format!("{:?}", mac);
        assert_eq!(&debug, "00:ff:11:ee:22:dd");
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
        let b: [u8; 6] = mac.into();
        assert_eq!(&b, &[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);
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
