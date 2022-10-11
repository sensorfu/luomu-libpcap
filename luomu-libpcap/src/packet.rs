use std::time::SystemTime;

/// A trait for handling Borrowed and Owned Packet data from libpcap.
pub trait Packet {
    /// get a timestamp of a packet
    ///
    /// When capturing traffic, each packet is given a timestamp representing
    /// the arrival time of the packet. This time is an approximation.
    ///
    /// <https://www.tcpdump.org/manpages/pcap-tstamp.7.html>
    fn timestamp(&self) -> SystemTime;

    /// Get the contents of a packet.
    fn packet(&self) -> &[u8];

    /// Get the contents of a packet.
    fn to_vec(self) -> Vec<u8>;

    /// Length of captured packet.
    ///
    /// Packet should always have some bytes so length is never zero.
    fn len(&self) -> usize {
        self.packet().len()
    }

    /// The packet is never empty. But you might want to make sure.
    fn is_empty(&self) -> bool {
        self.packet().is_empty()
    }
}

/// A network packet with ownership of the underlying bytes.
///
/// Calling `OwnedPacket::to_vec()` consumes the type and returns the packet
/// contents in `Vec<u8>` without doing a copy.
#[derive(Clone, Debug)]
pub struct OwnedPacket {
    timestamp: SystemTime,
    packet: Vec<u8>,
}

impl Packet for OwnedPacket {
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    fn packet(&self) -> &[u8] {
        &self.packet
    }

    fn to_vec(self) -> Vec<u8> {
        self.packet
    }
}

/// A network packet captured by libpcap.
///
/// This structure contains memory owned by `libpcap`. The `libpcap` owned data
/// is good for doing a simple filtering in the receive loop as it eliminates
/// making a copy of the data.
//
/// If you want to keep the contents, make a `OwnedPacket` by calling
/// `BorrowedPacket::to_owned()` before getting next `Packet` from `libpcap`.
#[derive(Debug)]
pub struct BorrowedPacket {
    timestamp: SystemTime,
    ptr: *const u8,
    len: usize,
}

impl BorrowedPacket {
    /// Construct a new `BorrowedPacket`.
    pub(crate) fn new(timestamp: SystemTime, ptr: *const u8, len: usize) -> Self {
        BorrowedPacket {
            timestamp,
            ptr,
            len,
        }
    }

    /// Copy the contents of `BorrowedPacket` and turn it into `OwnedPacket`.
    pub fn to_owned(self) -> OwnedPacket {
        OwnedPacket {
            timestamp: self.timestamp,
            packet: self.to_vec(),
        }
    }
}

impl Packet for BorrowedPacket {
    fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    fn to_vec(self) -> Vec<u8> {
        self.packet().to_vec()
    }
}

impl From<BorrowedPacket> for OwnedPacket {
    fn from(p: BorrowedPacket) -> Self {
        p.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use crate::{BorrowedPacket, OwnedPacket, Packet};

    const TIMESTAMP: SystemTime = SystemTime::UNIX_EPOCH;
    const BUF: &[u8] = b"Hello world";
    const BORROWED_PACKET: BorrowedPacket = BorrowedPacket {
        timestamp: TIMESTAMP,
        ptr: BUF.as_ptr(),
        len: BUF.len(),
    };

    #[test]
    fn test_packet_timestamp() {
        assert_eq!(BORROWED_PACKET.timestamp(), TIMESTAMP);
        assert_eq!(BORROWED_PACKET.to_owned().timestamp(), TIMESTAMP);
    }

    #[test]
    fn test_packet_packet() {
        assert_eq!(BORROWED_PACKET.packet(), BUF);
        assert_eq!(BORROWED_PACKET.to_owned().packet(), BUF);
    }

    #[test]
    fn test_packet_to_vec() {
        assert_eq!(BORROWED_PACKET.to_vec(), Vec::from(BUF));
        assert_eq!(BORROWED_PACKET.to_owned().to_vec(), Vec::from(BUF));
    }

    #[test]
    fn test_packet_to_owned() {
        let packet = BORROWED_PACKET.to_owned();
        assert_eq!(packet.timestamp(), BORROWED_PACKET.timestamp());
        assert_eq!(packet.packet(), BORROWED_PACKET.packet());
    }

    #[test]
    fn test_packet_len() {
        assert_eq!(BORROWED_PACKET.len(), BUF.len());
        assert_eq!(BORROWED_PACKET.to_owned().len(), BUF.len());
    }

    #[test]
    fn test_packet_is_empty() {
        assert!(!BORROWED_PACKET.is_empty());
        assert!(!BORROWED_PACKET.to_owned().is_empty());

        let p = OwnedPacket {
            timestamp: TIMESTAMP,
            packet: Vec::new(),
        };

        assert!(p.is_empty());
    }
}
