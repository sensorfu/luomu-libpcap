#![allow(missing_docs, unsafe_code)]
#![cfg(target_os = "linux")]

use std::error::Error;
use std::ffi::CString;
use std::fmt::{self, Display};
use std::time::{Duration, SystemTime};

use luomu_libpcap::PcapFilter;

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
    fn val(self) -> u32 {
        match self {
            FanoutMode::HASH(_) => libc::PACKET_FANOUT_HASH,
            FanoutMode::LB(_) => libc::PACKET_FANOUT_LB,
            FanoutMode::ROLLOVER(_) => libc::PACKET_FANOUT_ROLLOVER,
            FanoutMode::RND(_) => libc::PACKET_FANOUT_RND,
            FanoutMode::QM(_) => libc::PACKET_FANOUT_QM,
            FanoutMode::CBPF(_) => libc::PACKET_FANOUT_CBPF,
            FanoutMode::EBPF(_) => libc::PACKET_FANOUT_EBPF,
            FanoutMode::CPU(_) => libc::PACKET_FANOUT_CPU,
        }
    }

    fn arg(self) -> u32 {
        let group_id = match self {
            FanoutMode::HASH(v)
            | FanoutMode::LB(v)
            | FanoutMode::ROLLOVER(v)
            | FanoutMode::RND(v)
            | FanoutMode::QM(v)
            | FanoutMode::CBPF(v)
            | FanoutMode::EBPF(v)
            | FanoutMode::CPU(v) => v,
        };

        u32::from(group_id) | (self.val() << 16)
    }
}

/// Error returned by [ParameterBuilder::build] if parameters are invalid
#[derive(Debug, Copy, Clone)]
pub enum ParameterError {
    /// Block size is invalid
    InvalidBlockSize,
    /// Block count is invalid
    InvalidBlockCount,
    /// Frame size is invalid
    InvalidFrameSize,
}

impl Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBlockSize => f.write_str("block size needs to be multiple of page size"),
            Self::InvalidBlockCount => f.write_str("invalid block count, need non-zero integer"),
            Self::InvalidFrameSize => write!(
                f,
                "invalid frame size, frame size needs to be at least {} bytes",
                libc::TPACKET3_HDRLEN
            ),
        }
    }
}

impl Error for ParameterError {}

/// Parameters for tpacket reader.
///
/// Use [ReaderParameters::builder()] to get a builder which can be used to
/// build parameters for Reeader. [ReaderParameters::default()] will  return
/// default parameters which can be used.
///
/// These parameters are used to configure the memory allocated for packet
/// receive ringbuffer and fanout mode to use. See
/// <https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt> for
/// detailed information about the configuration.
///
///
#[derive(Copy, Clone)]
pub struct ReaderParameters {
    /// Size for a single block. Needs to be a multiple of pagesize
    block_size: u32,
    /// Number of blocks to allocate.
    block_count: u32,
    /// Maximum size for single packet.
    frame_size: u32,
    /// Fanout mode to set, None for no fanout mode.
    fanout: Option<FanoutMode>,
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

/// Builder for creating [ReaderParameters]
///
/// Use [ReaderParameters::builder()] to get instance of builder and
/// [ParameterBuilder::build()] to create parameters.
pub struct ParameterBuilder(ReaderParameters);

impl ParameterBuilder {
    /// Creates [ReaderParameters] according to values given to builder. Returns
    /// error if parameters are invalid.
    pub fn build(self) -> Result<ReaderParameters, ParameterError> {
        let psize = u32::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap_or(4096);
        if !self.0.block_size.is_multiple_of(psize) {
            return Err(ParameterError::InvalidBlockSize);
        }
        if self.0.block_count == 0 {
            return Err(ParameterError::InvalidBlockCount);
        }
        if self.0.frame_size < u32::try_from(libc::TPACKET3_HDRLEN).unwrap_or(0) {
            return Err(ParameterError::InvalidFrameSize);
        }
        Ok(self.0)
    }

    /// Sets block size
    ///
    /// This is the size of a single block to allocate, it needs to be a
    /// multiple of systems page size.
    #[must_use]
    pub fn with_block_size(mut self, block_size: u32) -> Self {
        self.0.block_size = block_size;
        self
    }

    /// Sets block count
    ///
    /// This is the number of blocks to allocate. The total size for packet
    /// ringbuffer is block_count * block_size
    #[must_use]
    pub fn with_block_count(mut self, block_count: u32) -> Self {
        self.0.block_count = block_count;
        self
    }

    /// Sets maximum size for frame that can be received.
    #[must_use]
    pub fn with_frame_size(mut self, frame_size: u32) -> Self {
        self.0.frame_size = frame_size;
        self
    }

    /// Sets fanout mode, [None] for no fanout mode.
    #[must_use]
    pub fn with_fanout_mode(mut self, fanout: Option<FanoutMode>) -> Self {
        self.0.fanout = fanout;
        self
    }
}

impl ReaderParameters {
    /// Returns a [PacketBuilder] instance that can be used to create set
    /// of parameters.
    pub fn builder() -> ParameterBuilder {
        ParameterBuilder(Self::default())
    }
    /// Returns the maximum number of frames that fit the allocated buffer.
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
    let sock = socket::Fd::create().map_err(|e| format!("Can not create socket {e}"))?;
    tracing::trace!("Index for interface {interface} is {index}");

    // try to compile the filter, if one is set, first
    let filter = match pcap_filter {
        Some(f) => Some(PcapFilter::compile(f).map_err(|e| format!("Invalid pcap filter: {e}"))?),
        None => None,
    };

    // set version to tpacket_v3
    let opt = socket::OptValue {
        val: libc::tpacket_versions::TPACKET_V3,
    };
    tracing::trace!("Setting packet version");
    sock.setopt(&socket::Option::PacketVersion(opt))
        .map_err(|e| format!("packet version sockopt failed: {e}"))?;

    let req = libc::tpacket_req3 {
        tp_block_size: parameters.block_size,
        tp_block_nr: parameters.block_count,
        tp_frame_size: parameters.frame_size,
        tp_frame_nr: parameters.frame_count(),
        tp_retire_blk_tov: 100,
        tp_feature_req_word: 0,
        tp_sizeof_priv: 0,
    };

    tracing::trace!("setting RX_PACKET request");
    sock.setopt(&socket::Option::PacketRxRing(socket::OptValue { val: req }))
        .map_err(|e| format!("RX_RING sockopt failed: {e}"))?;

    if let Some(f) = filter {
        tracing::trace!("setting filter");
        sock.set_filter(&f)
            .map_err(|e| format!("Can not set filter: {e}"))?;
    }

    tracing::trace!("Setting PROMISC mode");
    let mr = libc::packet_mreq {
        mr_ifindex: libc::c_int::try_from(index).unwrap_or(libc::c_int::MAX),
        #[allow(clippy::cast_possible_truncation)]
        mr_type: libc::PACKET_MR_PROMISC as u16,
        mr_alen: 0,
        mr_address: [0; 8],
    };
    sock.setopt(&socket::Option::PacketAddMembership(socket::OptValue { val: mr }))
        .map_err(|e| format!("ADD_MEMBERSHIP sockopt failed: {e}"))?;

    tracing::trace!("Mapping ring");
    let map = ringbuf::Map::create(parameters.block_size, parameters.block_count, sock.raw_fd())
        .map_err(|e| format!("Can not mmap for ringbuffer: {e}"))?;

    tracing::trace!("binding to interface");
    let ll = libc::sockaddr_ll {
        #[allow(clippy::cast_possible_truncation)]
        sll_family: libc::AF_PACKET as u16,
        #[allow(clippy::cast_possible_truncation)]
        sll_protocol: socket::htons(libc::ETH_P_ALL as u16),
        sll_ifindex: i32::try_from(index).unwrap_or(i32::MAX),
        sll_hatype: 0, // the rest of the struct is not used when binding according to man packet(7)
        sll_pkttype: 0, // but we need to fill them to keep compiler happy
        sll_halen: 0,
        sll_addr: [0; 8],
    };
    sock.bind(&ll)
        .map_err(|e| format!("Can not bind socket to interface: {e}"))?;

    if let Some(mode) = parameters.fanout {
        tracing::trace!("Setting fanout mode {:0X}", mode.arg());
        sock.setopt(&socket::Option::PacketFanout(socket::OptValue {
            val: mode.arg(),
        }))
        .map_err(|e| format!("Could not set fanout mode: {e}"))?;
    }

    let mut blocks: Vec<ringbuf::BlockDescriptor<'_>> = Vec::new();
    for i in 0..parameters.block_count {
        let i = isize::try_from(i).unwrap_or(isize::MAX);
        blocks.push(map.get_descriptor_ptr_for(i).into());
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
            WaitError::IoError(e) => write!(f, "Error while polling: {e}"),
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
        let t_stats = libc::tpacket_stats_v3 {
            tp_packets: 0,
            tp_drops: 0,
            tp_freeze_q_cnt: 0,
        };

        let ret = self
            .sock
            .getopt(socket::Option::PacketStatistics(socket::OptValue {
                val: t_stats,
            }))
            .map_err(|e| format!("PACKET_STATISTICS failed: {e}"))?;

        Ok((ret.tp_packets, ret.tp_drops))
    }

    /// Waits for given duration for a block to be ready. Returns iterator
    /// for all captured packets or `WaitError` indicating error.
    /// Once all packets have been handled, `flush_block()` must be called
    /// before calling `wait_block()` again. On error, `flush_block()` should
    /// not be called.
    pub fn wait_block(&self, timeout: Duration) -> Result<PacketIter<'a>, WaitError> {
        let idx = self.block_index;
        tracing::trace!("Waiting block {idx}");
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
                tracing::trace!("Block {idx} ready with {count} packets");
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
        tracing::trace!("Flushing block {}", self.block_index);
        self.blocks[self.block_index].flush();
        self.block_index = (self.block_index + 1) % self.blocks.len();
    }
}

impl Drop for Reader<'_> {
    fn drop(&mut self) {
        tracing::trace!("Dropping reader");
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
}

impl<'a> Iterator for PacketIter<'a> {
    type Item = Packet<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(pkt) = self.pkt.take() {
            if self.index >= self.count {
                None
            } else {
                tracing::trace!("Consuming packet {}/{}", self.index, self.count);
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
