#![deny(
    future_incompatible,
    nonstandard_style,
    rust_2018_compatibility,
    rust_2018_idioms,
    unused,
    missing_docs
)]

//! # luomu-libpcap
//!
//! Safe and mostly sane Rust bindings for [libpcap](https://www.tcpdump.org/).
//!
//! We are split in two different crates:
//!
//!   * `luomu-libpcap-sys` for unsafe Rust bindings generated directly from
//!     `libpcap`.
//!   * `luomu-libpcap` for safe and sane libpcap interface.
//!
//! `luomu-libpcap` crate is split into two parts itself:
//!
//!   * `functions` module contains safe wrappers and sane return values for
//!     libpcap functions.
//!   * the root of the project contains `Pcap` struct et al. for more Rusty API
//!     to interact with libpcap.
//!
//! You probably want to use the `Pcap` struct and other things from root of
//! this crate.

use std::collections::{BTreeSet, HashSet};
use std::convert::TryFrom;
use std::default;
use std::net::IpAddr;
use std::ops::Deref;
use std::path::Path;
use std::result;
use std::time::{Duration, SystemTime};

use luomu_common::{Address, MacAddr};
use luomu_libpcap_sys as libpcap;

pub mod functions;
use functions::*;

mod error;
pub use error::Error;

#[cfg(feature = "async-tokio")]
pub mod tokio;

/// A `Result` wrapping luomu-libpcap's errors in `Err` side
pub type Result<T> = result::Result<T, Error>;

/// Keeper of the `libpcap`'s `pcap_t`.
pub struct PcapT {
    pcap_t: *mut libpcap::pcap_t,
    #[allow(dead_code)]
    errbuf: Vec<u8>,
    interface: Option<String>,
}

// I assume the pcap_t pointer is safe to move between threads, but it can only
// be used from one thread. libpcap documentation is vague about thread safety,
// so we try this.
unsafe impl Send for PcapT {}

impl PcapT {
    /// get interface name
    ///
    /// `get_interface` returns the interface name if known or "<unknown>".
    pub fn get_inteface(&self) -> String {
        if let Some(name) = &self.interface {
            name.to_owned()
        } else {
            String::from("<unknown>")
        }
    }

    /// get libpcap error message text
    ///
    /// `get_error()` returns the error pertaining to the last pcap library error.
    ///
    /// This function can also fail, how awesome is that? The `Result` of
    /// `Ok(Error)` contains the error from libpcap as intended. `Err(Error)`
    /// contains the error happened while calling this function.
    pub fn get_error(&self) -> Result<Error> {
        get_error(self)
    }
}

impl Drop for PcapT {
    fn drop(&mut self) {
        log::trace!("PcapT::drop({:p})", self.pcap_t);
        unsafe { luomu_libpcap_sys::pcap_close(self.pcap_t) }
    }
}

/// Pcap capture
///
/// This contains everything needed to capture the packets from network.
///
/// To get started use `Pcap::builder()` to start a new Pcap capture builder.
/// Use it to set required options for the capture and then call
/// `PcapBuider::activate()` to activate the capture.
///
/// Then `Pcap::capture()` can be used to start an iterator for capturing
/// packets.
pub struct Pcap {
    pcap_t: PcapT,
}

impl Pcap {
    /// Create a live capture handle
    ///
    /// This is used to create a packet capture handle to look at packets on the
    /// network. `source` is a string that specifies the network device to open.
    pub fn new(source: &str) -> Result<Pcap> {
        let pcap_t = pcap_create(source)?;
        Ok(Pcap { pcap_t })
    }

    /// Create a capture handle for reading packets from given savefile.
    ///
    /// This function can be used to create handle to read packes from saved
    /// pcap -file. Use `capture()` to get iterator for packets in the file.
    pub fn offline<P: AsRef<Path>>(savefile: P) -> Result<Pcap> {
        Ok(Pcap {
            pcap_t: pcap_open_offline(savefile)?,
        })
    }

    /// Use builder to create a live capture handle
    ///
    /// This is used to create a packet capture handle to look at packets on the
    /// network. source is a string that specifies the network device to open.
    pub fn builder(source: &str) -> Result<PcapBuilder> {
        let pcap_t = pcap_create(source)?;
        Ok(PcapBuilder { pcap_t })
    }

    /// set a filter expression
    ///
    /// `Set a filter for capture. See
    /// [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html)
    /// for the syntax of that string.
    pub fn set_filter(&self, filter: &str) -> Result<()> {
        let mut bpf_program = PcapFilter::compile_with_pcap_t(&self.pcap_t, filter)?;
        pcap_setfilter(&self.pcap_t, &mut bpf_program)
    }

    /// Start capturing packets
    ///
    /// This returns an iterator `PcapIter` which can be used to get captured
    /// packets.
    pub fn capture(&self) -> PcapIter<'_> {
        PcapIter::new(&self.pcap_t)
    }

    /// Transmit a packet
    pub fn inject(&self, buf: &[u8]) -> Result<usize> {
        pcap_inject(&self.pcap_t, buf)
    }

    /// activate a capture
    ///
    /// This is used to activate a packet capture to look at packets on the
    /// network, with the options that were set on the handle being in effect.
    pub fn activate(&self) -> Result<()> {
        pcap_activate(&self.pcap_t)
    }

    /// get capture statistics
    ///
    /// Returns statistics from current capture. The values represent packet
    /// statistics from the start of the run to the time of the call.
    pub fn stats(&self) -> Result<PcapStat> {
        let mut stats: PcapStat = Default::default();
        match pcap_stats(&self.pcap_t, &mut stats) {
            Ok(()) => Ok(stats),
            Err(e) => Err(e),
        }
    }
}

impl Deref for Pcap {
    type Target = PcapT;

    fn deref(&self) -> &Self::Target {
        &self.pcap_t
    }
}

/// Builder for a `Pcap`. Call `Pcap::builder()` to get started.
pub struct PcapBuilder {
    pcap_t: PcapT,
}

impl PcapBuilder {
    /// set the buffer size for a capture
    ///
    /// `set_buffer_size()` sets the buffer size that will be used on a capture
    /// handle when the handle is activated to buffer_size, which is in units of
    /// bytes.
    pub fn set_buffer_size(self, buffer_size: usize) -> Result<PcapBuilder> {
        pcap_set_buffer_size(&self.pcap_t, buffer_size)?;
        Ok(self)
    }

    /// set promiscuous mode for a capture
    ///
    /// `set_promisc()` sets whether promiscuous mode should be set on a capture
    /// handle when the handle is activated.
    pub fn set_promiscuous(self, promiscuous: bool) -> Result<PcapBuilder> {
        pcap_set_promisc(&self.pcap_t, promiscuous)?;
        Ok(self)
    }

    /// set immediate mode for a capture
    ///
    /// `set_immediate_mode()` sets whether immediate mode should be set on a
    /// capture handle when the handle is activated. In immediate mode, packets
    /// are always delivered as soon as they arrive, with no buffering.
    pub fn set_immediate(self, immediate: bool) -> Result<PcapBuilder> {
        pcap_set_immediate_mode(&self.pcap_t, immediate)?;
        Ok(self)
    }

    /// set packet buffer timeout for a capture
    ///
    /// `pcap_set_timeout()` sets the packet buffer timeout that will be used on a
    /// capture handle when the handle is activated to to_ms, which is in units of
    /// milliseconds.
    pub fn set_timeout(self, to_ms: Duration) -> Result<PcapBuilder> {
        pcap_set_timeout(
            &self.pcap_t,
            (to_ms.as_millis().min(i32::MAX as u128)) as i32,
        )?;
        Ok(self)
    }

    /// set the snapshot length for a capture
    ///
    /// `set_snaplen()` sets the snapshot length to be used on a capture handle
    /// when the handle is activated to snaplen.
    ///
    /// `libpcap` says 65535 bytes should be enough for everyone.
    pub fn set_snaplen(self, snaplen: usize) -> Result<PcapBuilder> {
        pcap_set_snaplen(&self.pcap_t, snaplen)?;
        Ok(self)
    }

    /// activate a capture
    ///
    /// `activate()` is used to activate a packet capture to look at packets on
    /// the network, with the options that were set on the handle being in
    /// effect.
    pub fn activate(self) -> Result<Pcap> {
        pcap_activate(&self.pcap_t)?;
        Ok(Pcap {
            pcap_t: self.pcap_t,
        })
    }
}

/// A BPF filter program for Pcap.
pub struct PcapFilter {
    bpf_program: libpcap::bpf_program,
}

impl PcapFilter {
    /// compile a filter expression
    ///
    /// `compile()` is used to compile the filter into a filter program. See
    /// [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html)
    /// for the syntax of that string.
    pub fn compile(filter: &str) -> Result<PcapFilter> {
        let pcap = pcap_open_dead()?;
        pcap_compile(&pcap, filter)
    }

    /// compile a filter expression with `PcapT`
    ///
    /// `compile_with_pcap_t()` is used to compile the filter into a filter
    /// program. See
    /// [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html)
    /// for the syntax of that string.
    pub fn compile_with_pcap_t(pcap_t: &PcapT, filter_str: &str) -> Result<PcapFilter> {
        pcap_compile(pcap_t, filter_str)
    }

    /// Get length of the compiled filter
    pub fn get_raw_filter_len(&self) -> u32 {
        self.bpf_program.bf_len
    }

    /// Get pointer to the raw compiled filter program.
    /// Raw filter may be used when attaching filter to socket outside libpcap.
    /// # Safety
    /// Note that the pointer is valid only as long as this filter is valid.
    /// The returned pointer will be cast as *void since there is no common
    /// structure to which export the program.
    pub unsafe fn get_raw_filter(&self) -> &std::ffi::c_void {
        (self.bpf_program.bf_insns as *const std::ffi::c_void)
            .as_ref()
            .unwrap()
    }
}

impl Drop for PcapFilter {
    fn drop(&mut self) {
        log::trace!("PcapFilter::drop({:p})", &self.bpf_program);
        unsafe { luomu_libpcap_sys::pcap_freecode(&mut self.bpf_program) }
    }
}

/// Pcap capture iterator
pub struct PcapIter<'p> {
    pcap_t: &'p PcapT,
}

impl<'p> PcapIter<'p> {
    fn new(pcap_t: &'p PcapT) -> Self {
        PcapIter { pcap_t }
    }
}

impl<'p> Iterator for PcapIter<'p> {
    type Item = Packet;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match pcap_next_ex(self.pcap_t) {
                Ok(p) => return Some(p),
                Err(e) => match e {
                    // pcap_next_ex() sometimes seems to return
                    // "packet buffer expired" (whatever that means),
                    // even if the immediate mode is set. Just retry in
                    // this case.
                    Error::Timeout => continue,
                    _ => return None,
                },
            }
        }
    }
}

/// Pcap capture statistics
pub struct PcapStat {
    stats: libpcap::pcap_stat,
}

impl default::Default for PcapStat {
    fn default() -> Self {
        PcapStat {
            stats: libpcap::pcap_stat {
                ps_recv: 0,
                ps_drop: 0,
                ps_ifdrop: 0,
            },
        }
    }
}

impl PcapStat {
    /// Return number of packets received.
    pub fn packets_received(&self) -> u32 {
        self.stats.ps_recv
    }

    /// Return number of packets dropped because there was no room in the
    /// operating system's buffer when they arrived, because packets weren't
    /// being read fast enough.
    pub fn packets_dropped(&self) -> u32 {
        self.stats.ps_drop
    }

    /// Return number of packets dropped by the network interface or its driver.
    pub fn packets_dropped_interface(&self) -> u32 {
        self.stats.ps_ifdrop
    }
}

/// A network packet captured by libpcap.
///
/// This struct contains memory owned by `libpcap`. Copy the contents out before
/// getting next `Packet` from `libpcap`.
pub struct Packet {
    timestamp: SystemTime,
    ptr: *const libc::c_uchar,
    len: usize,
}

impl Packet {
    /// get a timestamp of a packet
    ///
    /// When capturing traffic, each packet is given a timestamp representing
    /// the arrival time of the packet. This time is an approximation.
    ///
    /// <https://www.tcpdump.org/manpages/pcap-tstamp.7.html>
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Get the contents of a packet.
    pub fn packet(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    /// Get the contents of a packet as `Bytes`. This makes a copy of the data.
    #[cfg(feature = "bytes")]
    pub fn packet_bytes(&self) -> bytes::Bytes {
        bytes::Bytes::copy_from_slice(self.packet())
    }

    /// Length of captured packet.
    ///
    /// Packet should always have some bytes so length is never zero.
    pub fn len(&self) -> usize {
        self.len
    }

    /// The packet is never empty. But you might want to make sure.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// A Packet from network capture. This type owns the packet content so at least
/// one copy of the data has been done constructing this.
#[derive(Debug)]
pub struct OwnedPacket {
    packet: Vec<u8>,
    timestamp: SystemTime,
}

impl OwnedPacket {
    /// get a timestamp of a packet
    ///
    /// When capturing traffic, each packet is given a timestamp representing
    /// the arrival time of the packet. This time is an approximation.
    ///
    /// <https://www.tcpdump.org/manpages/pcap-tstamp.7.html>
    pub fn timestamp(&self) -> SystemTime {
        self.timestamp
    }

    /// Get the contents of a packet.
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }

    /// Get the contents of a packet  as `Bytes` without copying.
    #[cfg(feature = "bytes")]
    pub fn packet_bytes(self) -> bytes::Bytes {
        bytes::Bytes::from(self.packet)
    }

    /// Length of captured packet.
    ///
    /// Packet should always have some bytes so length is never zero.
    pub fn len(&self) -> usize {
        self.packet.len()
    }

    /// The packet is never empty. But you might want to make sure.
    pub fn is_empty(&self) -> bool {
        self.packet.is_empty()
    }
}

impl From<Packet> for OwnedPacket {
    fn from(p: Packet) -> Self {
        Self {
            packet: p.packet().to_vec(),
            timestamp: p.timestamp(),
        }
    }
}

/// Keeper of the `libpcap`'s `pcap_if_t`.
pub struct PcapIfT {
    pcap_if_t: *mut libpcap::pcap_if_t,
}

impl PcapIfT {
    /// get a list of capture devices
    ///
    /// Constructs a list of network devices that can be opened with
    /// `Pcap::new()` and `Pcap::builder()`. Note that there may be network
    /// devices that cannot be opened by the process calling, because, for
    /// example, that process does not have sufficient privileges to open them
    /// for capturing; if so, those devices will not appear on the list.
    pub fn new() -> Result<Self> {
        pcap_findalldevs()
    }

    /// Return iterator for iterating capture devices.
    pub fn iter(&self) -> InterfaceIter {
        InterfaceIter {
            start: self.pcap_if_t,
            next: Some(self.pcap_if_t),
        }
    }

    /// Get all capture devices.
    pub fn get_interfaces(&self) -> HashSet<Interface> {
        self.iter().collect()
    }

    /// Find capture device with interface name `name`.
    pub fn find_interface_with_name(&self, name: &str) -> Option<Interface> {
        for interface in self.get_interfaces() {
            if interface.has_name(name) {
                log::trace!("find_interface_with_name({}) = {:?}", name, interface);
                return Some(interface);
            }
        }
        None
    }

    /// Find capture device which have IP address `ip`.
    pub fn find_interface_with_ip(&self, ip: &IpAddr) -> Option<String> {
        for interface in self.get_interfaces() {
            if interface.has_address(ip) {
                log::trace!("find_interface_with_ip({}) = {:?}", ip, interface);
                return Some(interface.name);
            }
        }
        None
    }
}

impl Drop for PcapIfT {
    fn drop(&mut self) {
        log::trace!("PcapIfT::drop({:?})", self.pcap_if_t);
        unsafe { luomu_libpcap_sys::pcap_freealldevs(self.pcap_if_t) }
    }
}

/// A network device that can be opened with `Pcap::new()` and
/// `Pcap::builder()`.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Interface {
    /// Devices name
    pub name: String,
    /// Devices description
    pub description: Option<String>,
    /// All addresses found from device
    pub addresses: BTreeSet<InterfaceAddress>,
    /// Flags set for device
    pub flags: BTreeSet<InterfaceFlag>,
}

impl Interface {
    /// True if interface is up
    pub fn is_up(&self) -> bool {
        self.flags.get(&InterfaceFlag::Up).is_some()
    }

    /// True if interface is running
    pub fn is_running(&self) -> bool {
        self.flags.get(&InterfaceFlag::Running).is_some()
    }

    /// True if interface is loopback
    pub fn is_loopback(&self) -> bool {
        self.flags.get(&InterfaceFlag::Loopback).is_some()
    }

    /// True if interface is has name `name`
    pub fn has_name(&self, name: &str) -> bool {
        self.name == name
    }

    /// Return MAC aka Ethernet address of the interface
    pub fn get_ether_address(&self) -> Option<MacAddr> {
        for ia in &self.addresses {
            if let Address::Mac(addr) = ia.addr {
                return Some(addr);
            }
        }
        None
    }

    /// Return IP addresses of interface
    pub fn get_ip_addresses(&self) -> HashSet<IpAddr> {
        self.addresses
            .iter()
            .filter_map(|i| IpAddr::try_from(&i.addr).ok())
            .collect()
    }

    /// True if interface is has IP address `ip`
    pub fn has_address(&self, ip: &IpAddr) -> bool {
        self.get_ip_addresses().get(ip).is_some()
    }
}

/// Interface iterator
///
/// Iterates all capture interfaces.
pub struct InterfaceIter {
    // First item in linked list, only used for trace logging
    start: *mut libpcap::pcap_if_t,
    // Next item in linked list, used for iteration
    next: Option<*mut libpcap::pcap_if_t>,
}

impl Iterator for InterfaceIter {
    type Item = Interface;

    fn next(&mut self) -> Option<Interface> {
        log::trace!(
            "InterfaceIter(start: {:p}, next: {:p})",
            self.start,
            self.next.unwrap_or(std::ptr::null_mut())
        );

        let pcap_if_t = self.next?;
        if pcap_if_t.is_null() {
            self.next = None;
            return None;
        }

        let next = unsafe { (*pcap_if_t).next };
        if next.is_null() {
            self.next = None;
        } else {
            self.next = Some(next);
        }

        match try_interface_from(pcap_if_t) {
            Ok(dev) => Some(dev),
            Err(err) => {
                log::error!("try_interface_from{:p}: {}", pcap_if_t, err);
                None
            }
        }
    }
}

/// Collection of addresses for network interface.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceAddress {
    /// Network interface's address
    addr: Address,
    /// The netmask corresponding to the address pointed to by addr.
    netmask: Option<Address>,
    /// The broadcast address corresponding to the address pointed to by addr;
    /// may be `None` if the device doesn't support broadcasts.
    broadaddr: Option<Address>,
    /// The destination address corresponding to the address pointed to by addr;
    /// may be `None` if the device isn't a point-to-point interface.
    dstaddr: Option<Address>,
}

/// Iterator for network device's addresses.
pub struct AddressIter {
    // First item in linked list, only used for trace logging
    start: *mut libpcap::pcap_addr_t,
    // Next item in linked list, used for iteration
    next: Option<*mut libpcap::pcap_addr_t>,
}

impl Iterator for AddressIter {
    type Item = InterfaceAddress;

    fn next(&mut self) -> Option<InterfaceAddress> {
        log::trace!(
            "AddressIter(start: {:p}, next: {:p})",
            self.start,
            self.next.unwrap_or(std::ptr::null_mut())
        );

        let pcap_addr_t = self.next?;
        if pcap_addr_t.is_null() {
            self.next = None;
            return None;
        }

        let next = unsafe { (*pcap_addr_t).next };
        if next.is_null() {
            self.next = None;
        } else {
            self.next = Some(next);
        }

        if let Some(dev) = try_address_from(pcap_addr_t) {
            Some(dev)
        } else {
            // Address was something we don't know how to handle. Move
            // to next address in list.
            self.next()
        }
    }
}

/// Various flags which can be set on network interface
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InterfaceFlag {
    /// set if the interface is a loopback interface
    Loopback,
    /// set if the interface is up
    Up,
    /// set if the interface is running
    Running,
}
