use std::fmt;

/// A MAC address used for example with Ethernet
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

    #[test]
    fn test_fmt_debug() {
        let mac: MacAddr = [0x00, 0xff, 0x11, 0xee, 0x22, 0xdd].into();
        let debug = format!("{:?}", mac);
        assert_eq!(&debug, "00:ff:11:ee:22:dd");
    }
}
