use std::collections::BTreeSet;
use std::convert::{TryFrom, TryInto};
use std::ffi::{c_void, CStr, CString};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::rc::Rc;

use log::trace;

use luomu_libpcap_sys as libpcap;
use crate::Address;

use super::{
    AddressIter, Error, Interface, InterfaceAddress, InterfaceFlag, Packet, PcapFilter, PcapIfT,
    PcapT, Result,
};

pub fn pcap_create(source: &str) -> Result<PcapT> {
    let mut errbuf: Vec<u8> = vec![0; libpcap::PCAP_ERRBUF_SIZE as usize];
    let source = CString::new(source)?;

    let pcap_t =
        unsafe { libpcap::pcap_create(source.as_ptr(), errbuf.as_mut_ptr() as *mut libc::c_char) };

    trace!("pcap_create({:?}) => {:p}", source, pcap_t);

    if pcap_t.is_null() {
        let cstr = unsafe { CStr::from_ptr(errbuf.as_ptr() as *const libc::c_char) };
        let err = cstr.to_str()?.to_owned();
        return Err(Error::PcapError(err));
    }

    Ok(PcapT { pcap_t, errbuf })
}

pub fn pcap_close(pcap_t: &mut PcapT) {
    trace!("get_close({:p})", pcap_t.pcap_t);
    unsafe { libpcap::pcap_close(pcap_t.pcap_t) }
    pcap_t.pcap_t = std::ptr::null_mut();
    pcap_t.errbuf = Vec::new();
}

pub fn pcap_set_promisc(pcap_t: &PcapT, promiscuous: bool) -> Result<()> {
    trace!("pcap_set_promisc({:p}, {})", pcap_t.pcap_t, promiscuous);
    let promisc = if promiscuous { 1 } else { 0 };
    let ret = unsafe { libpcap::pcap_set_promisc(pcap_t.pcap_t, promisc) };
    match ret {
        0 => Ok(()),
        libpcap::PCAP_ERROR_ACTIVATED => Err(Error::AlreadyActivated),
        n => panic!("Unknown return code {}", n),
    }
}

pub fn pcap_set_snaplen(pcap_t: &PcapT, snaplen: usize) -> Result<()> {
    trace!("pcap_set_snaplen({:p}, {})", pcap_t.pcap_t, snaplen);
    let ret = unsafe { libpcap::pcap_set_snaplen(pcap_t.pcap_t, snaplen as libc::c_int) };
    match ret {
        0 => Ok(()),
        libpcap::PCAP_ERROR_ACTIVATED => Err(Error::AlreadyActivated),
        n => panic!("Unknown return code {}", n),
    }
}

pub fn pcap_set_immediate_mode(pcap_t: &PcapT, immediate: bool) -> Result<()> {
    trace!(
        "pcap_set_immediate_mode({:p}, {})",
        pcap_t.pcap_t,
        immediate
    );
    let immediate = if immediate { 1 } else { 0 };
    let ret = unsafe { libpcap::pcap_set_immediate_mode(pcap_t.pcap_t, immediate) };
    match ret {
        0 => Ok(()),
        libpcap::PCAP_ERROR_ACTIVATED => Err(Error::AlreadyActivated),
        n => panic!("Unknown return code {}", n),
    }
}

pub fn pcap_activate(pcap_t: &PcapT) -> Result<()> {
    trace!("pcap_activate({:p})", pcap_t.pcap_t);
    let ret = unsafe { libpcap::pcap_activate(pcap_t.pcap_t) };
    match ret {
        0 => Ok(()),
        -1 => Err(get_error(pcap_t)?),
        n => Err(Error::PcapWarning(status_to_str(n)?)),
    }
}

pub fn get_error(pcap_t: &PcapT) -> Result<Error> {
    trace!("get_error({:p})", pcap_t.pcap_t);
    let ptr = unsafe { libpcap::pcap_geterr(pcap_t.pcap_t) };
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let err = cstr.to_str()?.to_owned();
    Ok(Error::PcapError(err))
}

pub fn pcap_inject(pcap_t: &PcapT, buf: &[u8]) -> Result<usize> {
    trace!("pcap_inject({:p})", pcap_t.pcap_t);
    let ret =
        unsafe { libpcap::pcap_inject(pcap_t.pcap_t, buf.as_ptr() as *const c_void, buf.len()) };
    if ret == -1 {
        return Err(get_error(pcap_t)?);
    }
    Ok(ret as usize)
}

pub fn pcap_compile(pcap_t: &PcapT, filter: &str) -> Result<PcapFilter> {
    trace!("pcap_compile({:p}, {})", pcap_t.pcap_t, filter);
    let mut bpf_program: libpcap::bpf_program = unsafe { std::mem::zeroed() };
    let filter = CString::new(filter)?;
    let optimize = 0;
    let netmask = libpcap::PCAP_NETMASK_UNKNOWN;

    let ret = unsafe {
        libpcap::pcap_compile(
            pcap_t.pcap_t,
            &mut bpf_program,
            filter.as_ptr(),
            optimize,
            netmask,
        )
    };
    if ret == -1 {
        return Err(get_error(pcap_t)?);
    }
    Ok(PcapFilter { bpf_program })
}

pub fn pcap_setfilter(pcap_t: &PcapT, pcap_filter: &mut PcapFilter) -> Result<()> {
    trace!(
        "pcap_setfilter({:p}, {:p})",
        pcap_t.pcap_t,
        &pcap_filter.bpf_program
    );
    let ret = unsafe { libpcap::pcap_setfilter(pcap_t.pcap_t, &mut pcap_filter.bpf_program) };
    if ret == -1 {
        return Err(get_error(pcap_t)?);
    }
    Ok(())
}

pub fn pcap_freecode(pcap_filter: &mut PcapFilter) {
    trace!("pcap_freecode({:p})", &pcap_filter.bpf_program);
    unsafe { libpcap::pcap_freecode(&mut pcap_filter.bpf_program) };
    pcap_filter.bpf_program = unsafe { std::mem::zeroed() };
}

/// If data is needed, copy it before calling this again.
pub fn pcap_next_ex<'p>(pcap_t: &PcapT) -> Result<Packet<'p>> {
    trace!("pcap_next_ex({:p})", pcap_t.pcap_t);
    let mut header: *mut libpcap::pcap_pkthdr = std::ptr::null_mut();
    let mut packet: *const libc::c_uchar = std::ptr::null();

    let ret = unsafe { libpcap::pcap_next_ex(pcap_t.pcap_t, &mut header, &mut packet) };
    match ret {
        1 => (),
        0 => return Err(Error::Timeout),
        -1 => return Err(get_error(pcap_t)?),
        -2 => return Err(Error::NoMorePackets),
        n => panic!("Unknown return code {}", n),
    }

    if header.is_null() || packet.is_null() {
        panic!("header or packet NULL.");
    }

    let len: usize = unsafe { (*header).caplen } as usize;
    let raw = unsafe { std::slice::from_raw_parts(packet, len) };

    Ok(Packet::Borrowed(Rc::new(raw)))
}

pub fn pcap_findalldevs() -> Result<PcapIfT> {
    let mut pcap_if_t: *mut libpcap::pcap_if_t = std::ptr::null_mut();
    let mut errbuf: Vec<u8> = vec![0; libpcap::PCAP_ERRBUF_SIZE as usize];

    let ret = unsafe {
        libpcap::pcap_findalldevs(&mut pcap_if_t, errbuf.as_mut_ptr() as *mut libc::c_char)
    };

    if ret == -1 {
        let cstr = unsafe { CStr::from_ptr(errbuf.as_ptr() as *const libc::c_char) };
        let err = cstr.to_str()?.to_owned();
        return Err(Error::PcapError(err));
    }

    trace!("pcap_findalldevs() => {:p}", pcap_if_t);

    Ok(PcapIfT { pcap_if_t })
}

pub fn pcap_freealldevs(pcap_if_t: &mut PcapIfT) {
    trace!("pcap_freealldevs({:p})", pcap_if_t.pcap_if_t);
    unsafe { libpcap::pcap_freealldevs(pcap_if_t.pcap_if_t) };
    pcap_if_t.pcap_if_t = std::ptr::null_mut();
}

pub(crate) fn try_interface_from(pcap_if_t: *mut libpcap::pcap_if_t) -> Result<Interface> {
    trace!("try_interface_from({:p})", pcap_if_t);
    let name: String = {
        let name = unsafe { (*pcap_if_t).name };
        if name.is_null() {
            panic!("pcap_if_t.name is null");
        } else {
            let s = unsafe { CStr::from_ptr(name) };
            s.to_str()?.to_owned()
        }
    };

    let description: Option<String> = {
        let descr = unsafe { (*pcap_if_t).description };
        if descr.is_null() {
            None
        } else {
            let s = unsafe { CStr::from_ptr(descr) };
            Some(s.to_str()?.to_owned())
        }
    };

    let addresses = {
        let pcap_addr_t: *mut libpcap::pcap_addr_t = unsafe { (*pcap_if_t).addresses };
        let addrs = AddressIter {
            start: pcap_addr_t,
            next: Some(pcap_addr_t),
        };

        let mut addresses = BTreeSet::new();
        for addr in addrs {
            addresses.insert(addr);
        }
        addresses
    };

    let flags = {
        let f = unsafe { (*pcap_if_t).flags };
        get_interface_flags(f)
    };

    Ok(Interface {
        name,
        description,
        addresses,
        flags,
    })
}

fn from_sockaddr(addr: *const libc::sockaddr) -> Option<Address> {
    trace!("from_sockaddr({:p})", addr);
    if addr.is_null() {
        return None;
    }
    let family = unsafe { (*addr).sa_family };
    match i32::from(family) {
        libc::AF_INET => {
            let inet4: *const libc::sockaddr_in = addr as *const libc::sockaddr_in;
            let s_addr = unsafe { (*inet4).sin_addr.s_addr };
            Some(Ipv4Addr::from(u32::from_be(s_addr)).into())
        }
        libc::AF_INET6 => {
            let inet6: *const libc::sockaddr_in6 = addr as *const libc::sockaddr_in6;
            let s6_addr = unsafe { (*inet6).sin6_addr.s6_addr };
            Some(Ipv6Addr::from(s6_addr).into())
        }
        #[cfg(target_os = "macos")]
        libc::AF_LINK => {
            // Link local address aka interface MAC/Ethernet address
            let dl_sock: *const libc::sockaddr_dl = addr as *const libc::sockaddr_dl;
            let start = unsafe { (*dl_sock).sdl_nlen } as usize;
            let dl_addr: [u8; 6] = unsafe {[
                *(*dl_sock).sdl_data.get(start+0)? as u8,
                *(*dl_sock).sdl_data.get(start+1)? as u8,
                *(*dl_sock).sdl_data.get(start+2)? as u8,
                *(*dl_sock).sdl_data.get(start+3)? as u8,
                *(*dl_sock).sdl_data.get(start+4)? as u8,
                *(*dl_sock).sdl_data.get(start+5)? as u8,
            ]};
            Some(dl_addr.into())
        }
        n => {
            log::error!("Unsupported sa_family {}", n);
            None
        }
    }
}

pub(crate) fn try_address_from(pcap_addr_t: *mut libpcap::pcap_addr_t) -> Option<InterfaceAddress> {
    trace!("try_address_from({:p})", pcap_addr_t);
    debug_assert!(!pcap_addr_t.is_null(), "null pointer");
    let addr = {
        let addr: *const libc::sockaddr = unsafe { (*pcap_addr_t).addr };
        from_sockaddr(addr)?
    };

    let netmask = {
        let addr: *const libc::sockaddr = unsafe { (*pcap_addr_t).netmask };
        from_sockaddr(addr)
    };

    let broadaddr = {
        let addr: *const libc::sockaddr = unsafe { (*pcap_addr_t).broadaddr };
        from_sockaddr(addr)
    };

    let dstaddr = {
        let addr: *const libc::sockaddr = unsafe { (*pcap_addr_t).dstaddr };
        from_sockaddr(addr)
    };

    Some(InterfaceAddress {
        addr,
        netmask,
        broadaddr,
        dstaddr,
    })
}

fn get_interface_flags(val: u32) -> BTreeSet<InterfaceFlag> {
    trace!("get_interface_flags({})", val);
    let mut flags = BTreeSet::new();
    use InterfaceFlag::*;
    for flag in &[
        libpcap::PCAP_IF_LOOPBACK,
        libpcap::PCAP_IF_UP,
        libpcap::PCAP_IF_RUNNING,
    ] {
        if (val & flag) > 0 {
            match *flag {
                libpcap::PCAP_IF_LOOPBACK => flags.insert(Loopback),
                libpcap::PCAP_IF_UP => flags.insert(Up),
                libpcap::PCAP_IF_RUNNING => flags.insert(Running),
                _ => panic!("Unsupported InterfaceFlag field: {:b}", flag),
            };
        }
    }
    flags
}

fn status_to_str(error: libc::c_int) -> Result<String> {
    trace!("status_to_str");
    let ptr = unsafe { libpcap::pcap_statustostr(error) };
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let status = cstr.to_str()?.to_owned();
    Ok(status)
}
