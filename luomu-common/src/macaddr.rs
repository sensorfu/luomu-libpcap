use std::convert::TryFrom;
use std::fmt;

use super::InvalidAddress;

/// A Mac address used for example with Ethernet.
///
/// Mac address is handled as big endian value. All `From<T>` implementations
/// returning `MacAddr` expect input as big endian. `From<u64>` also expects
/// address to reside in lowest 6 bytes. All `From<MacAddr>` and
/// `TryFrom<MacAddr>` implementations return their bytes as big endian.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr([u8; 6]);

impl From<[u8; 6]> for MacAddr {
    fn from(val: [u8; 6]) -> Self {
        Self(val)
    }
}

impl From<&[u8; 6]> for MacAddr {
    fn from(val: &[u8; 6]) -> Self {
        Self(val.to_owned())
    }
}

impl From<MacAddr> for [u8; 6] {
    fn from(val: MacAddr) -> Self {
        val.0
    }
}

impl<'a> From<&'a MacAddr> for &'a [u8; 6] {
    fn from(val: &'a MacAddr) -> Self {
        &val.0
    }
}

impl<'a> From<&'a MacAddr> for &'a [u8] {
    fn from(val: &'a MacAddr) -> Self {
        &val.0
    }
}

impl TryFrom<u64> for MacAddr {
    type Error = InvalidAddress;

    fn try_from(mac: u64) -> Result<Self, Self::Error> {
        if mac > 0x0000FFFFFFFFFFFF {
            return Err(InvalidAddress);
        }

        let b = mac.to_be_bytes();
        Ok(MacAddr([b[2], b[3], b[4], b[5], b[6], b[7]]))
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let h = self
            .0
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(":");
        f.write_str(&h)
    }
}

impl std::ops::Deref for MacAddr {
    type Target = [u8; 6];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::MacAddr;
    use std::convert::TryFrom;

    #[test]
    fn test_fmt_debug() {
        let mac: MacAddr = [0x00, 0xff, 0x11, 0xee, 0x22, 0xdd].into();
        let debug = format!("{:?}", mac);
        assert_eq!(&debug, "00:ff:11:ee:22:dd");
    }

    #[test]
    fn test_try_from_u64() {
        let i0 = 0x0000000000000000;
        assert!(MacAddr::try_from(i0).is_ok());

        let i1 = 0x0000FFFFFFFFFFFF;
        assert!(MacAddr::try_from(i1).is_ok());

        let i2 = 0x0001000000000000;
        assert!(MacAddr::try_from(i2).is_err());

        let i3 = 0xFFFFFFFFFFFFFFFF;
        assert!(MacAddr::try_from(i3).is_err());
    }
}
