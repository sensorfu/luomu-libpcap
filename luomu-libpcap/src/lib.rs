#![allow(unsafe_code)]

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
use std::time::Duration;

use luomu_common::{Address, MacAddr};
use luomu_libpcap_sys as libpcap;

pub mod functions;
use functions::*;

mod error;
pub use error::Error;

mod packet;
pub use packet::{BorrowedPacket, OwnedPacket, Packet};

#[cfg(feature = "async-tokio")]
pub mod tokio;

/// A `Result` wrapping luomu-libpcap's errors in `Err` side
pub type Result<T> = result::Result<T, Error>;

/// Keeper of the `libpcap`'s `pcap_t`.
pub struct PcapT {
    pcap_t: *mut libpcap::pcap_t,
    #[allow(dead_code)]
    errbuf: Errbuf,
    interface: Option<Box<str>>,
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
            name.to_string()
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
        tracing::trace!("PcapT::drop({:p})", self.pcap_t);
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

    /// Start capturing packet in non-blocking mode.
    ///
    /// Returned iterator can be used to get captured packets, it no packets
    /// are available within given `wait_time` [None] is returned by the
    /// `next()` method of the iterator. [Error] is returned if capture
    /// could not be placed into non-blocking mode.
    ///
    /// Note that captures opened with [Self::offline()] can not be put on
    /// non-blocking mode and calling this method will return error.
    pub fn capture_nonblocking(&self, wait_time: Duration) -> Result<NonBlockingIter<'_>> {
        NonBlockingIter::new(&self.pcap_t, wait_time)
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

/// Libpcap's buffer to hold possible error messages. Buffer is large enough to
/// hold at least [libpcap::PCAP_ERRBUF_SIZE] bytes.
struct Errbuf(Box<[u8]>);

impl Errbuf {
    /// Initialize new memory buffer to hold libpcap's error messages.
    fn new() -> Errbuf {
        let buf: Box<[u8]> = Box::new([0u8; libpcap::PCAP_ERRBUF_SIZE as usize]);
        Self(buf)
    }

    /// Return libpcap's error message as borrowed string.
    fn as_str(&self) -> Result<&str> {
        use std::ffi::CStr;
        let cstr = unsafe { CStr::from_ptr(self.0.as_ptr() as *const libc::c_char) };
        Ok(cstr.to_str()?)
    }

    /// Return libpcap's error message as String.
    fn as_string(&self) -> Result<String> {
        Ok(self.as_str()?.to_string())
    }

    /// Return libcap's error as [Error] type.
    fn as_error<T>(&self) -> Result<T> {
        Err(Error::PcapError(self.as_string()?))
    }

    fn as_mut_ptr<T>(&mut self) -> *mut T {
        self.0.as_mut_ptr() as *mut T
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
        pcap_set_timeout(&self.pcap_t, (to_ms.as_millis().min(i32::MAX as u128)) as i32)?;
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
        Ok(Pcap { pcap_t: self.pcap_t })
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
    pub const fn get_raw_filter_len(&self) -> u32 {
        self.bpf_program.bf_len
    }

    /// Get pointer to the raw compiled filter program.
    ///
    /// Raw filter may be used when attaching filter to socket outside libpcap.
    /// # Safety
    /// Note that the pointer is valid only as long as this filter is valid.
    /// The returned pointer will be cast as *void since there is no common
    /// structure to which export the program.
    pub const fn get_raw_filter(&self) -> *const std::ffi::c_void {
        self.bpf_program.bf_insns as *const std::ffi::c_void
    }
}

impl Drop for PcapFilter {
    fn drop(&mut self) {
        tracing::trace!("PcapFilter::drop({:p})", &self.bpf_program);
        unsafe { luomu_libpcap_sys::pcap_freecode(&mut self.bpf_program) }
    }
}

/// A PcapDumper
pub struct PcapDumper {
    pcap_dumper_t: *mut libpcap::pcap_dumper_t,
}

impl PcapDumper {
    /// Dump (save) a [Packet] to a savefile.
    pub fn dump<P: Packet>(&mut self, packet: P) {
        self.dump_raw(packet.pkthdr(), packet.packet())
    }

    /// Dump (save) a header and bytes to a savefile.
    pub fn dump_raw(&mut self, pkthdr: &luomu_libpcap_sys::pcap_pkthdr, bytes: &[u8]) {
        pcap_dump(self, pkthdr, bytes)
    }
}

impl Drop for PcapDumper {
    fn drop(&mut self) {
        tracing::trace!("PcapDumper::drop({:p})", self.pcap_dumper_t);
        let _res = pcap_dump_flush(self);
        unsafe { luomu_libpcap_sys::pcap_dump_close(self.pcap_dumper_t) }
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

impl Iterator for PcapIter<'_> {
    type Item = BorrowedPacket;

    fn next(&mut self) -> Option<Self::Item> {
        pcap_next_ex(self.pcap_t).ok()
    }
}

/// Pcap capture iterator for reading packets in nonblocking mdoe.
///
/// The [Self::next()] method will return [None] if no packets have been
/// received within the timeout given as parameter when this iterator is created
/// with [Pcap::capture_nonblocking()] method.
///
/// To allow detecting that capturing device has been removed or other error
/// occurs while reading packets, this iterator returns [Result].
pub struct NonBlockingIter<'p> {
    /// Pcap handle
    pcap_t: &'p PcapT,
    /// Selectable file descriptor to use when waiting for packet
    fd: i32,
    /// how long to wait for packet to be available
    wait_time: Duration,
}

impl<'p> NonBlockingIter<'p> {
    /// Creates new instance of nonblocking iterator with `wait_times` as
    /// the timeout for how long to wait for packets.
    fn new(pcap_t: &'p PcapT, wait_time: Duration) -> Result<Self> {
        pcap_set_nonblock(pcap_t, true)?;
        let fd = pcap_get_selectable_fd(pcap_t)?;
        Ok(Self {
            pcap_t,
            fd,
            wait_time,
        })
    }
}

impl Iterator for NonBlockingIter<'_> {
    type Item = Result<BorrowedPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        // first check if there is already packet available
        match pcap_next_ex(self.pcap_t) {
            Ok(pkt) => return Some(Ok(pkt)),
            Err(Error::Timeout) => {}
            Err(err) => return Some(Err(err)),
        }

        let timeout = match pcap_get_required_select_timeout(self.pcap_t) {
            Some(min_tv) => min_tv.max(self.wait_time),
            None => self.wait_time,
        };
        match poll_fd_in(self.fd, timeout) {
            Ok(true) => match pcap_next_ex(self.pcap_t) {
                Ok(pkt) => Some(Ok(pkt)),
                Err(Error::Timeout) => None,
                Err(err) => Some(Err(err)),
            },
            Ok(false) => None,
            Err(err) => {
                // return None if we get error while polling, expecting that
                // pcap_next_ex() will return error next time if the handle
                // is no longer valid etc.
                tracing::trace!("Error while polling: {err}");
                None
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
    pub const fn packets_received(&self) -> u32 {
        self.stats.ps_recv
    }

    /// Return number of packets dropped because there was no room in the
    /// operating system's buffer when they arrived, because packets weren't
    /// being read fast enough.
    pub const fn packets_dropped(&self) -> u32 {
        self.stats.ps_drop
    }

    /// Return number of packets dropped by the network interface or its driver.
    pub const fn packets_dropped_interface(&self) -> u32 {
        self.stats.ps_ifdrop
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
    pub const fn iter(&self) -> InterfaceIter {
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
                tracing::trace!("find_interface_with_name({name}) = {interface:?}");
                return Some(interface);
            }
        }
        None
    }

    /// Find capture device which have IP address `ip`.
    pub fn find_interface_with_ip(&self, ip: &IpAddr) -> Option<String> {
        for interface in self.get_interfaces() {
            if interface.has_address(ip) {
                tracing::trace!("find_interface_with_ip({ip}) = {interface:?}");
                return Some(interface.name.into_string());
            }
        }
        None
    }
}

impl Drop for PcapIfT {
    fn drop(&mut self) {
        tracing::trace!("PcapIfT::drop({:?})", self.pcap_if_t);
        unsafe { luomu_libpcap_sys::pcap_freealldevs(self.pcap_if_t) }
    }
}

/// A network device that can be opened with `Pcap::new()` and
/// `Pcap::builder()`.
#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Interface {
    /// Devices name
    pub name: Box<str>,
    /// Devices description
    pub description: Option<Box<str>>,
    /// All addresses found from device
    pub addresses: BTreeSet<InterfaceAddress>,
    /// Flags set for device
    pub flags: BTreeSet<InterfaceFlag>,
}

impl Interface {
    /// True if interface is up
    pub fn is_up(&self) -> bool {
        self.flags.contains(&InterfaceFlag::Up)
    }

    /// True if interface is running
    pub fn is_running(&self) -> bool {
        self.flags.contains(&InterfaceFlag::Running)
    }

    /// True if interface is loopback
    pub fn is_loopback(&self) -> bool {
        self.flags.contains(&InterfaceFlag::Loopback)
    }

    /// True if interface is has name `name`
    pub fn has_name(&self, name: &str) -> bool {
        self.name.as_ref() == name
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
        self.get_ip_addresses().contains(ip)
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
        tracing::trace!(
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
                tracing::error!("try_interface_from{:p}: {err}", pcap_if_t);
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
        tracing::trace!(
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
