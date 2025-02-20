#![allow(missing_docs, unsafe_code)]
#![cfg(target_os = "linux")]

use std::error::Error;
use std::ffi::CString;
use std::fmt;
use std::time::{Duration, SystemTime};

use luomu_libpcap::PcapFilter;

mod if_packet;
mod ringbuf;
mod socket;

/// Get interface index for given interface name using if_nametoindex
fn ifindex_for(ifname: &str) -> libc::c_uint {
    let ifname_c = CString::new(ifname).unwrap(); // XXX unwrap
    unsafe { libc::if_nametoindex(ifname_c.as_ptr()) }
}

/// Fanout mode to use for spreading traffic across sockets. Requires as a
/// parameter the fanout group ID. See packet(7) for description of different
/// fanout modes.
#[derive(Copy, Clone)]
pub enum FanoutMode {
    HASH(u16),
    LB(u16),
    ROLLOVER(u16),
    RND(u16),
    QM(u16),
    CBPF(u16),
    EBPF(u16),
    CPU(u16),
}

impl FanoutMode {
    // Get the actual numeric code for this fanout mode
    fn val(&self) -> libc::c_int {
        match self {
            FanoutMode::HASH(_) => if_packet::PACKET_FANOUT_HASH,
            FanoutMode::LB(_) => if_packet::PACKET_FANOUT_LB,
            FanoutMode::ROLLOVER(_) => if_packet::PACKET_FANOUT_ROLLOVER,
            FanoutMode::RND(_) => if_packet::PACKET_FANOUT_RND,
            FanoutMode::QM(_) => if_packet::PACKET_FANOUT_QM,
            FanoutMode::CBPF(_) => if_packet::PACKET_FANOUT_CBPF,
            FanoutMode::EBPF(_) => if_packet::PACKET_FANOUT_EBPF,
            FanoutMode::CPU(_) => if_packet::PACKET_FANOUT_CPU,
        }
    }

    fn arg(&self) -> i32 {
        let group_id = match self {
            FanoutMode::HASH(v) => v,
            FanoutMode::LB(v) => v,
            FanoutMode::ROLLOVER(v) => v,
            FanoutMode::RND(v) => v,
            FanoutMode::QM(v) => v,
            FanoutMode::CBPF(v) => v,
            FanoutMode::EBPF(v) => v,
            FanoutMode::CPU(v) => v,
        };

        *group_id as i32 | (self.val() << 16)
    }
}

/// Parameters for tpacket reader.
///
/// These parameters are used to configure the memory allocated for packet
/// receive ringbuffer and fanout mode to use. See
/// <https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt> for
/// detailed information about the configuration.
#[derive(Copy, Clone)]
pub struct ReaderParameters {
    /// Size for a single block. Needs to be a multiple of pagesize
    pub block_size: u32,
    /// Number of blocks to allocate.
    pub block_count: u32,
    /// Maximum size for single packet.
    pub frame_size: u32,
    /// Fanout mode to set, None for no fanout mode.
    pub fanout: Option<FanoutMode>,
}

impl Default for ReaderParameters {
    fn default() -> Self {
        ReaderParameters {
            block_count: 32,
            block_size: 1024 * 1024 * 2, // 2MB blocks
            frame_size: 2048,
            fanout: None,
        }
    }
}

impl ReaderParameters {
    fn frame_count(&self) -> u32 {
        (self.block_size * self.block_count) / self.frame_size
    }
}

/// Reader instance to use for reading captured packets.
///
/// Use `wait_block()` to get iterator for packets within that block. Once all
/// packets have been consumed call `flush_block()` to indicate kernel that the
/// block can once again be filled with packets. After `flush_block()` has been
/// called, `wait_block()` can be used to wait for next block to fill.
pub struct Reader<'a> {
    // Map is not accessed, but needs to be dropped once Reader is dropped. Not before.
    #[allow(dead_code)]
    map: ringbuf::Map, // Memory mapping for ringbuffer
    // Socket for readers
    sock: socket::Fd,
    blocks: Vec<ringbuf::BlockDescriptor<'a>>,
    block_index: usize,
}

/// Get new reader instance reading packets from given interface.
///
/// `pcap_filter` should contain "libpcap filter string" that can be used to
/// filter incoming traffic or None to indicate that no filtering should be
/// done. The `parameters` are used to configure the ringbuffer used for
/// capturing. On success returns `Reader` instance to use to read captured
/// packets.
pub fn reader<'a>(
    interface: &str,
    pcap_filter: Option<&str>,
    parameters: ReaderParameters,
) -> Result<Reader<'a>, String> {
    let index = ifindex_for(interface);
    log::trace!("Index for interface {} is {}", interface, index);
    let sock = socket::Fd::create().map_err(|e| format!("Can not create socket {}", e))?;

    // try to compile the filter, if one is set, first
    let filter = match pcap_filter {
        Some(f) => Some(PcapFilter::compile(f).map_err(|e| format!("Invalid pcap filter: {}", e))?),
        None => None,
    };

    // set version to tpacket_v3
    let opt = socket::OptValue {
        val: if_packet::TPACKET_V3,
    };
    log::trace!("Setting packet version");
    sock.setopt(socket::Option::PacketVersion(opt))
        .map_err(|e| format!("packet version sockopt failed: {}", e))?;

    let req = if_packet::tpacket_req3 {
        tp_block_size: parameters.block_size,
        tp_block_nr: parameters.block_count,
        tp_frame_size: parameters.frame_size,
        tp_frame_nr: parameters.frame_count(),
        tp_retire_blk_tov: 100,
        tp_feature_req_word: 0,
        tp_sizeof_priv: 0,
    };

    log::trace!("setting RX_PACKET request");
    sock.setopt(socket::Option::PacketRxRing(socket::OptValue { val: req }))
        .map_err(|e| format!("RX_RING sockopt failed: {}", e))?;

    if let Some(f) = filter {
        log::trace!("setting filter");
        sock.set_filter(f)
            .map_err(|e| format!("Can not set filter: {}", e))?;
    }

    log::trace!("Setting PROMISC mode");
    let mr = libc::packet_mreq {
        mr_ifindex: index as libc::c_int,
        mr_type: libc::PACKET_MR_PROMISC as u16,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    sock.setopt(socket::Option::PacketAddMembership(socket::OptValue {
        val: mr,
    }))
    .map_err(|e| format!("ADD_MEMBERSHIP sockopt failed: {}", e))?;

    log::trace!("Mapping ring");
    let map = ringbuf::Map::create(parameters.block_size, parameters.block_count, sock.raw_fd())
        .map_err(|e| format!("Can not mmap for ringbuffer: {}", e))?;

    log::trace!("binding to interface");
    let ll = libc::sockaddr_ll {
        sll_family: libc::AF_PACKET as u16,
        sll_protocol: socket::htons(libc::ETH_P_ALL as u16),
        sll_ifindex: index as i32,
        sll_hatype: 0, // the rest of the struct is not used when binding according to man packet(7)
        sll_pkttype: 0, // but we need to fill them to keep compiler happy
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    sock.bind(&ll)
        .map_err(|e| format!("Can not bind socket to interface: {}", e))?;

    if let Some(mode) = parameters.fanout {
        log::trace!("Setting fanout mode {:0X}", mode.arg());
        sock.setopt(socket::Option::PacketFanout(socket::OptValue {
            val: mode.arg(),
        }))
        .map_err(|e| format!("Could not set fanout mode: {}", e))?;
    }

    let mut blocks: Vec<ringbuf::BlockDescriptor<'_>> = Vec::new();
    for i in 0..parameters.block_count {
        blocks.push(map.get_descriptor_ptr_for(i as isize).into());
    }
    Ok(Reader {
        map,
        sock,
        blocks,
        block_index: 0,
    })
}

/// Error returned by `Reader::wait_block()` to indicate that no packets
/// are available at this time.
#[derive(Debug)]
pub enum WaitError {
    /// Timed out waiting for block to be ready. Try again.
    Timeout,
    /// I/O error occurered with socket.
    IoError(std::io::Error),
    /// Socket was signalled to be ready for reading, but current block
    /// is not ready. Usually should not happen unless `flush_block()` has
    /// not been called after reading packets.
    BlockNotReady,
}

impl fmt::Display for WaitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WaitError::Timeout => write!(f, "Timed out waiting for block"),
            WaitError::BlockNotReady => write!(f, "Block not ready"),
            WaitError::IoError(e) => write!(f, "Error while polling: {}", e),
        }
    }
}

impl Error for WaitError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            WaitError::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for WaitError {
    fn from(e: std::io::Error) -> Self {
        WaitError::IoError(e)
    }
}

impl<'a> Reader<'a> {
    /// Get statistics for this reader, returns Result with tuple containing
    /// packets captured (first element) and dropped (second element) or
    /// Err if stats could not be read.
    pub fn stats(&self) -> Result<(u32, u32), String> {
        let t_stats = if_packet::tpacket_stats_v3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };

        let ret = self
            .sock
            .getopt(socket::Option::PacketStatistics(socket::OptValue {
                val: t_stats,
            }))
            .map_err(|e| format!("PACKET_STATISTICS failed: {}", e))?;

        Ok((ret.tp_packets, ret.tp_drops))
    }

    /// Waits for given duration for a block to be ready. Returns iterator
    /// for all captured packets or `WaitError` indicating error.
    /// Once all packets have been handled, `flush_block()` must be called
    /// before calling `wait_block()` again. On error, `flush_block()` should
    /// not be called.
    pub fn wait_block(&self, timeout: Duration) -> Result<PacketIter<'a>, WaitError> {
        let idx = self.block_index;
        log::trace!("Waiting block {}", idx);
        match self.sock.poll(timeout) {
            Ok(ready) => {
                if !ready {
                    return Err(WaitError::Timeout);
                }
                if !self.blocks[idx].is_ready() {
                    return Err(WaitError::BlockNotReady);
                }
                let pkt = self.blocks[idx].get_first_packet();
                let count = self.blocks[idx].get_number_of_packets();
                log::trace!("Block {} ready with {} packets", idx, count);
                Ok(PacketIter {
                    pkt: Some(pkt),
                    count,
                    index: 0,
                })
            }
            Err(e) => Err(WaitError::from(e)),
        }
    }

    /// Flush the current block. This will indicate kernel that block is
    /// ready for capturing new packets and advance `Reader` to poll next
    /// block when `wait_block()` is called.
    pub fn flush_block(&mut self) {
        log::trace!("Flushing block {}", self.block_index);
        self.blocks[self.block_index].flush();
        self.block_index = (self.block_index + 1) % self.blocks.len();
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        log::trace!("Dropping reader");
        self.sock.close();
    }
}

/// Packet read from network.
pub struct Packet<'a> {
    buf: &'a [u8],
    timestamp: SystemTime,
    vlan_tci: Option<u32>,
    vlan_tpid: Option<u16>,
}

impl<'a> Packet<'a> {
    /// Get timestamp when this packet was captured.
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Get the actual packet data.
    /// The packet contents must be copied before `Reader::flush_block()` is
    /// called as the packet data is owned by the capture ringbuffer.
    pub fn packet(&self) -> &'a [u8] {
        self.buf
    }

    /// Get vlan Tag Protocol Identifier field if one was provided by the tpacket
    /// interface. Sometimes the vlan information is stripped from the
    /// returned packet, in that case vlan information can be read using
    /// this method. See also `vlan_tci()`.
    pub fn vlan_tpid(&self) -> Option<u16> {
        self.vlan_tpid
    }

    /// Get vlan Tag Control Information field if one was provided by the tpacket
    /// interface. Sometimes the vlan information is stripped from the
    /// returned packet, in that case vlan information can be read using
    /// this method. See also `vlan_tpid()`.
    pub fn vlan_tci(&self) -> Option<u32> {
        self.vlan_tci
    }
}

/// Iterator to read all packets available in single block.
/// Once this iterator returns None, no more packets are
/// available on the block.
pub struct PacketIter<'a> {
    pkt: Option<ringbuf::PacketDescriptor<'a>>,
    count: u32,
    index: u32,
    // block: &'a mut ringbuf::BlockDescriptor<'a>,
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(pkt) = self.pkt.take() {
            if self.index >= self.count {
                None
            } else {
                log::trace!("Consuming packet {}/{}", self.index, self.count);
                let vlan_tci = if pkt.has_vlan_tci() {
                    Some(pkt.get_vlan_tci())
                } else {
                    None
                };
                let vlan_tpid = if pkt.has_vlan_tpid() {
                    Some(pkt.get_vlan_tpid())
                } else {
                    None
                };
                self.index += 1;
                let ret = Packet {
                    buf: pkt.get_packet_data(),
                    timestamp: pkt.get_timestamp(),
                    vlan_tci,
                    vlan_tpid,
                };
                self.pkt = Some(pkt.get_next());
                Some(ret)
            }
        } else {
            None
        }
    }
}
