use std::time::{Duration, SystemTime, UNIX_EPOCH};

use luomu_libpcap_sys::pcap_pkthdr;

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
    fn len(&self) -> usize;

    /// The packet is never empty. But you might want to make sure.
    fn is_empty(&self) -> bool;

    /// Return a reference to the [pcap_pkthdr] structure of a packet.
    fn pkthdr(&self) -> &pcap_pkthdr;
}

/// A network packet with ownership of the underlying bytes.
///
/// Calling `OwnedPacket::to_vec()` consumes the type and returns the packet
/// contents in `Vec<u8>` without doing a copy.
#[derive(Clone, Debug)]
pub struct OwnedPacket {
    header: pcap_pkthdr,
    packet: Vec<u8>,
}

impl Packet for OwnedPacket {
    fn timestamp(&self) -> SystemTime {
        let ts: libc::timeval = self.header.ts;
        UNIX_EPOCH + Duration::new(ts.tv_sec as u64, (ts.tv_usec as u32) * 1000)
    }

    fn packet(&self) -> &[u8] {
        &self.packet
    }

    fn to_vec(self) -> Vec<u8> {
        self.packet
    }

    fn len(&self) -> usize {
        self.packet.len()
    }

    fn is_empty(&self) -> bool {
        self.packet.is_empty()
    }

    fn pkthdr(&self) -> &pcap_pkthdr {
        &self.header
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
pub struct BorrowedPacket {
    pkthdr: *const pcap_pkthdr,
    ptr: *const u8,
}

impl BorrowedPacket {
    /// Construct a new `BorrowedPacket`.
    pub(crate) fn new(pkthdr: *const pcap_pkthdr, ptr: *const u8) -> Self {
        BorrowedPacket { pkthdr, ptr }
    }

    /// Copy the contents of `BorrowedPacket` and turn it into `OwnedPacket`.
    pub fn to_owned(self) -> OwnedPacket {
        OwnedPacket {
            header: unsafe { *(self.pkthdr) },
            packet: self.to_vec(),
        }
    }
}

impl Packet for BorrowedPacket {
    fn timestamp(&self) -> SystemTime {
        let ts: libc::timeval = unsafe { (*self.pkthdr).ts };
        UNIX_EPOCH + Duration::new(ts.tv_sec as u64, (ts.tv_usec as u32) * 1000)
    }

    fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len()) }
    }

    fn to_vec(self) -> Vec<u8> {
        self.packet().to_vec()
    }

    fn len(&self) -> usize {
        let len = unsafe { (*self.pkthdr).caplen };
        len as usize
    }

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn pkthdr(&self) -> &pcap_pkthdr {
        unsafe { &*self.pkthdr }
    }
}

impl From<BorrowedPacket> for OwnedPacket {
    fn from(p: BorrowedPacket) -> Self {
        p.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use luomu_libpcap_sys::pcap_pkthdr;

    use crate::{BorrowedPacket, Packet};

    const BUF: &[u8] = b"Hello world";
    const LEN: usize = BUF.len();
    const TS: libc::timeval = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    const PKTHDR: pcap_pkthdr = pcap_pkthdr {
        ts: TS,
        caplen: LEN as u32,
        len: LEN as u32,
    };

    fn timestamp() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::new(TS.tv_sec as u64, 1000 * TS.tv_usec as u32)
    }

    fn borrowed_packet() -> BorrowedPacket {
        BorrowedPacket {
            pkthdr: &PKTHDR,
            ptr: BUF.as_ptr(),
        }
    }

    #[test]
    fn test_packet_timestamp() {
        assert_eq!(borrowed_packet().timestamp(), timestamp());
        assert_eq!(borrowed_packet().to_owned().timestamp(), timestamp());
    }

    #[test]
    fn test_packet_packet() {
        assert_eq!(borrowed_packet().packet(), BUF);
        assert_eq!(borrowed_packet().to_owned().packet(), BUF);
    }

    #[test]
    fn test_packet_to_vec() {
        assert_eq!(borrowed_packet().to_vec(), Vec::from(BUF));
        assert_eq!(borrowed_packet().to_owned().to_vec(), Vec::from(BUF));
    }

    #[test]
    fn test_packet_to_owned() {
        assert_eq!(borrowed_packet().timestamp(), borrowed_packet().timestamp());
        assert_eq!(borrowed_packet().packet(), borrowed_packet().packet());
    }

    #[test]
    fn test_packet_len() {
        assert_eq!(borrowed_packet().len(), LEN);
        assert_eq!(borrowed_packet().to_owned().len(), LEN);
    }

    #[test]
    fn test_packet_is_empty() {
        assert!(!borrowed_packet().is_empty());
        assert!(!borrowed_packet().to_owned().is_empty());
    }
}
