use std::collections::{BTreeSet, HashSet};
use std::net::IpAddr;
use std::ops::Deref;
use std::rc::Rc;
use std::result;

use luomu_libpcap_sys as libpcap;

pub mod functions;
use functions::*;

mod error;
pub use error::Error;

pub type Result<T> = result::Result<T, Error>;

/// Keeper of the `libpcap`'s `pcap_t`.
pub struct PcapT {
    pcap_t: *mut libpcap::pcap_t,
    #[allow(dead_code)]
    errbuf: Vec<u8>,
}

impl PcapT {
    pub fn get_error(&self) -> Result<Error> {
        get_error(&self)
    }
}

impl Drop for Pcap {
    fn drop(&mut self) {
        pcap_close(&mut self.pcap_t)
    }
}

pub struct Pcap {
    pcap_t: PcapT,
    #[allow(dead_code)]
    pcap_filter: Option<PcapFilter>,
}

impl Pcap {
    pub fn builder(source: &str) -> Result<PcapBuilder> {
        let pcap_t = pcap_create(source)?;
        let pcap_filter = None;
        Ok(PcapBuilder {
            pcap_t,
            pcap_filter,
        })
    }

    pub fn capture(&self) -> PcapIter<'_> {
        PcapIter::new(&self.pcap_t)
    }

    /// Transmit a packet
    pub fn inject(&self, buf: &[u8]) -> Result<usize> {
        pcap_inject(&self.pcap_t, buf)
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
    pcap_filter: Option<String>,
}

impl PcapBuilder {
    pub fn set_promiscuous(self, promiscuous: bool) -> Result<PcapBuilder> {
        pcap_set_promisc(&self.pcap_t, promiscuous)?;
        Ok(self)
    }

    pub fn set_immediate(self, immediate: bool) -> Result<PcapBuilder> {
        pcap_set_immediate_mode(&self.pcap_t, immediate)?;
        Ok(self)
    }

    pub fn set_filter(mut self, filter_str: &str) -> Result<PcapBuilder> {
        self.pcap_filter = Some(filter_str.to_owned());
        Ok(self)
    }

    /// `libpcap` says 65535 bytes should be enough for everyone.
    pub fn set_snaplen(self, snaplen: usize) -> Result<PcapBuilder> {
        pcap_set_snaplen(&self.pcap_t, snaplen)?;
        Ok(self)
    }

    pub fn activate(self) -> Result<Pcap> {
        pcap_activate(&self.pcap_t)?;

        let pcap_filter = match self.pcap_filter {
            Some(filter) => {
                let mut pcap_filter = pcap_compile(&self.pcap_t, &filter)?;
                pcap_setfilter(&self.pcap_t, &mut pcap_filter)?;
                Some(pcap_filter)
            }
            None => None,
        };

        Ok(Pcap {
            pcap_t: self.pcap_t,
            pcap_filter,
        })
    }
}

/// A BPF filter program for Pcap.
pub struct PcapFilter {
    bpf_program: libpcap::bpf_program,
}

impl PcapFilter {
    pub fn compile(pcap_t: &PcapT, filter_str: &str) -> Result<PcapFilter> {
        pcap_compile(pcap_t, filter_str)
    }
}

impl Drop for PcapFilter {
    fn drop(&mut self) {
        pcap_freecode(self)
    }
}

pub struct PcapIter<'p> {
    pcap_t: &'p PcapT,
}

impl<'p> PcapIter<'p> {
    pub fn new(pcap_t: &'p PcapT) -> Self {
        PcapIter { pcap_t }
    }
}

impl<'p> Iterator for PcapIter<'p> {
    type Item = Packet<'p>;

    fn next(&mut self) -> Option<Self::Item> {
        pcap_next_ex(&self.pcap_t).ok()
    }
}

pub enum Packet<'p> {
    /// Borrowed content is wrapped into `Rc` to advice compiler that `Packet`
    /// is not `Sync` nor `Send`. This is done because `libpcap` owns the
    /// borrowed memory and next call to `pcap_next_ex` could change the
    /// contents.
    Borrowed(Rc<&'p [u8]>),
    Owned(Vec<u8>),
}

impl<'p> Packet<'p> {
    fn to_vec(&self) -> Vec<u8> {
        match self {
            Packet::Borrowed(packet) => packet.to_vec(),
            Packet::Owned(packet) => packet.clone(),
        }
    }
}

impl<'p> ToOwned for Packet<'p> {
    type Owned = Packet<'p>;

    fn to_owned(&self) -> Self {
        Packet::Owned(self.to_vec())
    }
}

impl<'p> Deref for Packet<'p> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            Packet::Borrowed(packet) => packet,
            Packet::Owned(packet) => packet.as_ref(),
        }
    }
}

pub struct PcapIfT {
    pcap_if_t: *mut libpcap::pcap_if_t,
}

impl PcapIfT {
    pub fn new() -> Result<Self> {
        pcap_findalldevs()
    }

    pub fn iter(&self) -> InterfaceIter {
        InterfaceIter {
            start: self.pcap_if_t,
            next: Some(self.pcap_if_t),
        }
    }

    pub fn get_interfaces(&self) -> HashSet<Interface> {
        self.iter().collect()
    }

    pub fn find_interface_with_ip(&self, ip: &IpAddr) -> Option<String> {
        for interface in self.get_interfaces() {
            if interface.has_address(ip) {
                return Some(interface.name);
            }
        }
        None
    }
}

impl Drop for PcapIfT {
    fn drop(&mut self) {
        pcap_freealldevs(self)
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct Interface {
    pub name: String,
    pub description: Option<String>,
    pub addresses: BTreeSet<InterfaceAddress>,
    pub flags: BTreeSet<InterfaceFlag>,
}

impl Interface {
    pub fn is_up(&self) -> bool {
        self.flags.get(&InterfaceFlag::Up).is_some()
    }

    pub fn is_running(&self) -> bool {
        self.flags.get(&InterfaceFlag::Running).is_some()
    }

    pub fn is_loopback(&self) -> bool {
        self.flags.get(&InterfaceFlag::Loopback).is_some()
    }

    pub fn get_addresses(&self) -> HashSet<IpAddr> {
        self.addresses.iter().map(|i| i.addr).collect()
    }

    pub fn has_address(&self, ip: &IpAddr) -> bool {
        self.get_addresses().get(ip).is_some()
    }
}

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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InterfaceAddress {
    addr: IpAddr,
    netmask: Option<IpAddr>,
    broadaddr: Option<IpAddr>,
    dstaddr: Option<IpAddr>,
}

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
            return self.next();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InterfaceFlag {
    /// set if the interface is a loopback interface
    Loopback,
    /// set if the interface is up
    Up,
    /// set if the interface is running
    Running,
}
