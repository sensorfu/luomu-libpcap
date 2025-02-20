use crate::{MacAddr, TagError};

// Size of our tag stack. 64bit integer can store up to five VLAN tags.
type TagStack = u64;

/// A [MacAddr] with additional support for storing stack of VLAN IDs.
///
/// Tags are stored as a stack where the outermost tag should be pushed first
/// and popped last (aka LIFO). There's enough room to store up to five VLAN
/// IDs.
///
/// ```rust
/// use luomu_common::{MacAddr, TaggedMacAddr};
///
/// let mut mac = TaggedMacAddr::new("11:22:33:aa:bb:cc".parse().unwrap());
/// assert_eq!(mac.pop_tag(), None);
///
/// mac.push_tag(42);
/// mac.push_tag(1337);
/// assert_eq!(mac.pop_tag(), Some(1337));
/// assert_eq!(mac.pop_tag(), Some(42));
/// assert_eq!(mac.pop_tag(), None);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TaggedMacAddr {
    mac: MacAddr,
    tag_stack: TagStack,
}

impl TaggedMacAddr {
    /// Construct new [TaggedMacAddr].
    pub const fn new(mac: MacAddr) -> Self {
        Self { mac, tag_stack: 0 }
    }

    /// Get a reference to a [MacAddr].
    pub fn mac(&self) -> &MacAddr {
        &self.mac
    }

    /// Get a mutable reference to [MacAddr].
    pub fn mac_mut(&mut self) -> &mut MacAddr {
        &mut self.mac
    }

    /// Push a VLAN tag into the stack. The outermost tag should be pushed
    /// first.
    pub const fn push_tag(&mut self, tag: u16) -> Result<(), TagError> {
        if tag > 0x0FFF {
            return Err(TagError::TooLargeTag);
        }

        #[allow(clippy::unusual_byte_groupings)] // groups of 12 bits
        if self.tag_stack & 0x0FFF_000_000_000_000 == 0 {
            self.tag_stack = (self.tag_stack << 12) | tag as TagStack;
            return Ok(());
        }

        Err(TagError::TooManyTags)
    }

    /// Pop a VLAN tag from the stack. The innermost tag pops out first.
    pub const fn pop_tag(&mut self) -> Option<u16> {
        let Some(tag) = self.peek_tag() else {
            return None;
        };
        self.tag_stack >>= 12;
        Some(tag)
    }

    /// Peek a next tag in stack, but don't pop it out.
    pub const fn peek_tag(&self) -> Option<u16> {
        let tag = self.tag_stack & 0x0000000000000FFF;
        if tag > 0 {
            return Some(tag as u16);
        }

        None
    }

    /// Get all tags as an array.
    #[allow(clippy::unusual_byte_groupings)]
    pub fn tag_array(&self) -> [u16; 5] {
        let mut tags = [0u16; 5];
        tags[0] = ((self.tag_stack & 0x0FFF_000_000_000_000) >> 48) as u16;
        tags[1] = ((self.tag_stack & 0x0000_FFF_000_000_000) >> 36) as u16;
        tags[2] = ((self.tag_stack & 0x0000_000_FFF_000_000) >> 24) as u16;
        tags[3] = ((self.tag_stack & 0x0000_000_000_FFF_000) >> 12) as u16;
        tags[4] = (self.tag_stack & 0x0000_000_000_000_FFF) as u16;
        tags
    }
}

impl From<MacAddr> for TaggedMacAddr {
    fn from(mac: MacAddr) -> Self {
        Self::new(mac)
    }
}

impl From<TaggedMacAddr> for MacAddr {
    fn from(tagged_mac: TaggedMacAddr) -> Self {
        tagged_mac.mac
    }
}

impl std::ops::Deref for TaggedMacAddr {
    type Target = MacAddr;

    fn deref(&self) -> &Self::Target {
        self.mac()
    }
}

#[cfg(test)]
mod tests {
    use crate::{MacAddr, TagError, TaggedMacAddr};

    #[test]
    fn test_tagged_macaddr_large_tag() {
        let mac: MacAddr = "11:22:33:AA:BB:CC".parse().unwrap();
        let mut tagged_mac: TaggedMacAddr = mac.into();
        assert_eq!(tagged_mac.push_tag(0x1000), Err(TagError::TooLargeTag));
    }

    #[test]
    fn test_tagged_macaddr_tag_push_pop() {
        let mac: MacAddr = "11:22:33:AA:BB:CC".parse().unwrap();
        let mut tagged_mac: TaggedMacAddr = mac.into();
        assert_eq!(tagged_mac.pop_tag(), None);

        tagged_mac.push_tag(42).unwrap();
        assert_eq!(tagged_mac.pop_tag(), Some(42));

        tagged_mac.push_tag(42).unwrap();
        tagged_mac.push_tag(1337).unwrap();
        tagged_mac.push_tag(0x0FFF).unwrap();
        tagged_mac.push_tag(3).unwrap();
        tagged_mac.push_tag(2).unwrap();
        assert_eq!(tagged_mac.push_tag(1), Err(TagError::TooManyTags));

        assert_eq!(tagged_mac.pop_tag(), Some(2));
        assert_eq!(tagged_mac.pop_tag(), Some(3));
        assert_eq!(tagged_mac.pop_tag(), Some(0x0FFF));
        assert_eq!(tagged_mac.pop_tag(), Some(1337));
        assert_eq!(tagged_mac.pop_tag(), Some(42));
        assert_eq!(tagged_mac.pop_tag(), None);
    }

    #[test]
    fn test_tagged_macaddr_peek() {
        let mac: MacAddr = "11:22:33:AA:BB:CC".parse().unwrap();
        let mut tagged_mac: TaggedMacAddr = mac.into();
        assert_eq!(tagged_mac.pop_tag(), None);
        assert_eq!(tagged_mac.peek_tag(), None);

        tagged_mac.push_tag(42).unwrap();
        tagged_mac.push_tag(1337).unwrap();
        assert_eq!(tagged_mac.peek_tag(), Some(1337));
        assert_eq!(tagged_mac.pop_tag(), Some(1337));
        assert_eq!(tagged_mac.peek_tag(), Some(42));
        assert_eq!(tagged_mac.pop_tag(), Some(42));
        assert_eq!(tagged_mac.peek_tag(), None);
        assert_eq!(tagged_mac.pop_tag(), None);
    }

    #[test]
    fn test_mac() {
        let mac: MacAddr = "11:22:33:AA:BB:CC".parse().unwrap();
        let tagged_mac: TaggedMacAddr = mac.into();

        assert_eq!(tagged_mac.mac().is_unspecified(), false);
    }

    #[test]
    fn test_mac_mut() {
        let mac: MacAddr = "11:22:33:AA:BB:CC".parse().unwrap();
        let mut tagged_mac: TaggedMacAddr = mac.into();

        assert_eq!(tagged_mac.mac().peek_tag(), None);
        assert_eq!(tagged_mac.mac_mut().push_tag(42), Ok(()));
        assert_eq!(tagged_mac.mac_mut().pop_tag(), Some(42));
        assert_eq!(tagged_mac.mac().peek_tag(), None);
    }

    #[test]
    fn test_tagged_macaddr_tag_array() {
        let mac: MacAddr = "11:22:33:AA:BB:CC".parse().unwrap();
        let mut tagged_mac: TaggedMacAddr = mac.into();
        assert_eq!(tagged_mac.tag_array(), [0; 5]);

        tagged_mac.push_tag(42).unwrap();
        tagged_mac.push_tag(1337).unwrap();
        tagged_mac.push_tag(0x0FFF).unwrap();
        tagged_mac.push_tag(3).unwrap();
        tagged_mac.push_tag(2).unwrap();
        assert_eq!(tagged_mac.tag_array(), [42, 1337, 0x0FFF, 3, 2]);
    }

    #[test]
    fn test_deref_peek_tag() {
        let mut mac: MacAddr = "11:22:33:AA:BB:CC".parse().unwrap();
        mac.push_tag(42).unwrap();

        let mut tagged_mac: TaggedMacAddr = mac.into();
        tagged_mac.push_tag(1337).unwrap();

        // This peek_tag is for TaggedMacAddr
        assert_eq!(tagged_mac.peek_tag(), Some(1337));

        // This peek_tag is for MacAddr via dereference
        assert_eq!((*tagged_mac).peek_tag(), Some(42));
    }
}
