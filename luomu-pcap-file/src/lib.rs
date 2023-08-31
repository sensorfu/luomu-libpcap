//! <https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html>
//!

#![deny(
    future_incompatible,
    nonstandard_style,
    rust_2018_compatibility,
    rust_2018_idioms,
    rust_2021_compatibility,
    unused,
//    missing_docs
)]

use std::io;

use luomu_libpcap_sys::pcap_pkthdr;

use byteorder::{NativeEndian as NE, WriteBytesExt};

pub struct PcapWriter<W> {
    writer: W,
}

impl<W> PcapWriter<W> {
    pub fn new(writer: W, snaplen: u32, linktype: u32) -> io::Result<PcapWriter<W>>
    where
        W: io::Write,
    {
        let mut pcap_writer = PcapWriter { writer };
        pcap_writer.write_file_header(snaplen, linktype)?;
        Ok(pcap_writer)
    }

    pub fn write(&mut self, pkthdr: &pcap_pkthdr, packet: &[u8]) -> io::Result<()>
    where
        W: io::Write,
    {
        self.write_packet_header(pkthdr)?;
        self.writer.write_all(packet)
    }

    pub fn flush(&mut self) -> io::Result<()>
    where
        W: io::Write,
    {
        self.writer.flush()
    }

    fn write_file_header(&mut self, snaplen: u32, linktype: u32) -> io::Result<()>
    where
        W: WriteBytesExt,
    {
        //     1                   2                   3
        //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  0 |                          Magic Number                         |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  4 |          Major Version        |         Minor Version         |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  8 |                           Reserved1                           |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 12 |                           Reserved2                           |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 16 |                            SnapLen                            |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 20 | FCS |f|                   LinkType                            |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        // Magic Number
        self.writer.write_u32::<NE>(0xA1B2C3D4)?;

        // Major Version
        self.writer.write_u16::<NE>(0x0002)?;

        // Minor Version
        self.writer.write_u16::<NE>(0x0004)?;

        // Reserved1 & Reserved2
        self.writer.write_u64::<NE>(0)?;

        // SnapLen
        self.writer.write_u32::<NE>(snaplen)?;

        // LinkType
        self.writer.write_u32::<NE>(linktype)?;

        Ok(())
    }

    fn write_packet_header(&mut self, pkthdr: &pcap_pkthdr) -> io::Result<()>
    where
        W: WriteBytesExt,
    {
        //    1                   2                   3
        //    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  0 |                      Timestamp (Seconds)                      |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  4 |            Timestamp (Microseconds or nanoseconds)            |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        //  8 |                    Captured Packet Length                     |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 12 |                    Original Packet Length                     |
        //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        // 16 /                                                               /
        //    /                          Packet Data                          /
        //    /                        variable length                        /
        //    /                                                               /
        //    +---------------------------------------------------------------+

        // Timestamp
        let ts: libc::timeval = unsafe { std::mem::transmute(pkthdr.ts) };
        self.writer.write_u32::<NE>(ts.tv_sec as u32)?;
        self.writer.write_u32::<NE>(ts.tv_usec as u32)?;

        // Original Packet Length
        self.writer.write_u32::<NE>(pkthdr.caplen)?;

        // Captured Packet Length
        self.writer.write_u32::<NE>(pkthdr.len)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use luomu_libpcap::Packet;

    use crate::PcapWriter;

    #[test]
    fn test_vec_writer() -> io::Result<()> {
        let mut buf = Vec::new();
        {
            let mut pcap_writer = PcapWriter::new(&mut buf, 65535, luomu_libpcap_sys::DLT_EN10MB)?;
            let ts = libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            };
            let pkthdr = luomu_libpcap_sys::pcap_pkthdr {
                ts: unsafe { std::mem::transmute(ts) },
                caplen: 0,
                len: 0,
            };
            pcap_writer.write(&pkthdr, &[])?;
        }

        // file header 24 bytes + packet header 16 bytes = 40 bytes.
        assert_eq!(buf.len(), 40);
        Ok(())
    }

    #[test]
    fn test_file_writer() -> io::Result<()> {
        let mut file = tempfile::NamedTempFile::new()?;

        {
            let mut pcap_writer = PcapWriter::new(&mut file, 65535, luomu_libpcap_sys::DLT_EN10MB)?;
            let ts = libc::timeval {
                tv_sec: 42,
                tv_usec: 12765,
            };
            let pkthdr = luomu_libpcap_sys::pcap_pkthdr {
                ts: unsafe { std::mem::transmute(ts) },
                caplen: 0,
                len: 0,
            };
            pcap_writer.write(&pkthdr, &[])?;
        }

        let pcap = luomu_libpcap::Pcap::offline(file.path())?;
        for packet in pcap.capture() {
            println!("{:?}", packet.pkthdr());
        }

        Ok(())
    }
}
