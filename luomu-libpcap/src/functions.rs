//! Safe wrappers for `libpcap` functions.
//!
//! The functions in this module call the libpcap functions of the same name,
//! but provide safe (as opposite of unsafe) and Rust'y interface to them.
//! Functions handle libpcap errors and use `Result` to return either `Ok` on
//! success or `Err` on failure.
//!
//! Documentation for functions is copied from
//! <https://www.tcpdump.org/manpages/> and modified as needed to fit the
//! implementations.
//!
//! Log level of "trace" (see <https://docs.rs/log/>) is used to log invocations
//! of these functions.

#![allow(unsafe_code)]

use std::collections::BTreeSet;
use std::ffi::{c_void, CStr, CString};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::Path;
use std::time::Duration;

use log::trace;

use crate::{
    Address, AddressIter, BorrowedPacket, Errbuf, Error, Interface, InterfaceAddress,
    InterfaceFlag, MacAddr, PcapDumper, PcapFilter, PcapIfT, PcapStat, PcapT, Result,
};

use luomu_libpcap_sys as libpcap;

// libpcap doesn't have constant for success, but man pages state 0 is success.
// For symmetry define it here together with PCAP_ERROR.
const PCAP_SUCCESS: i32 = 0;
const PCAP_ERROR: i32 = libpcap::PCAP_ERROR;

/// Create a live capture handle
///
/// `pcap_create()` is used to create a packet capture handle to look at packets
/// on the network. `source` is a string that specifies the network device to
/// open.
///
/// <https://www.tcpdump.org/manpages/pcap_create.3pcap.html>
pub fn pcap_create(source: &str) -> Result<PcapT> {
    let mut errbuf = Errbuf::new();
    let interface = Some(source.into());
    let src = CString::new(source)?;

    let pcap_t = unsafe { libpcap::pcap_create(src.as_ptr(), errbuf.as_mut_ptr()) };

    trace!("pcap_create({}) => {:p}", source, pcap_t);
    if pcap_t.is_null() {
        errbuf.as_error()?;
    }
    Ok(PcapT {
        pcap_t,
        errbuf,
        interface,
    })
}

/// Create a capture handle for reading data from savefile
///
/// `pcap_open_offline()` is used to open given savefile for reading.
///
/// <https://www.tcpdump.org/manpages/pcap_open_offline.3pcap.html>
pub fn pcap_open_offline<P: AsRef<Path>>(savefile: P) -> Result<PcapT> {
    let mut errbuf = Errbuf::new();
    let fname = CString::new(savefile.as_ref().to_string_lossy().as_ref())?;

    let pcap_t = unsafe { libpcap::pcap_open_offline(fname.as_ptr(), errbuf.as_mut_ptr()) };

    trace!("pcap_open_offline({:?}) => {:p}", fname, pcap_t);
    if pcap_t.is_null() {
        errbuf.as_error()?;
    }
    Ok(PcapT {
        pcap_t,
        errbuf,
        interface: None,
    })
}

/// Close a capture device or savefile
///
/// `pcap_close()` closes the files associated with `PcapT` and deallocates
/// resources.
///
/// <https://www.tcpdump.org/manpages/pcap_close.3pcap.html>
pub fn pcap_close(pcap_t: PcapT) {
    trace!("pcap_close({:p})", pcap_t.pcap_t);
    // PcapT is owned by this function and dropped at this point since it's no
    // longer needed. Dropping frees the allocated resources.
}

/// set the buffer size for a not-yet-activated capture handle
///
/// `pcap_set_buffer_size()` sets the buffer size that will be used on a capture
/// handle when the handle is activated to buffer_size, which is in units of
/// bytes.
///
/// <https://www.tcpdump.org/manpages/pcap_set_buffer_size.3pcap.html>
pub fn pcap_set_buffer_size(pcap_t: &PcapT, buffer_size: usize) -> Result<()> {
    trace!("pcap_set_buffer_size({:p}, {})", pcap_t.pcap_t, buffer_size);
    let ret = unsafe { libpcap::pcap_set_buffer_size(pcap_t.pcap_t, buffer_size as libc::c_int) };
    check_pcap_error(pcap_t, ret)
}

/// set promiscuous mode for a not-yet-activated capture handle
///
/// `pcap_set_promisc()` sets whether promiscuous mode should be set on a
/// capture handle when the handle is activated.
///
/// <https://www.tcpdump.org/manpages/pcap_set_promisc.3pcap.html>
pub fn pcap_set_promisc(pcap_t: &PcapT, promiscuous: bool) -> Result<()> {
    trace!("pcap_set_promisc({:p}, {})", pcap_t.pcap_t, promiscuous);
    let ret = unsafe { libpcap::pcap_set_promisc(pcap_t.pcap_t, promiscuous.into()) };
    check_pcap_error(pcap_t, ret)
}

/// set the snapshot length for a not-yet-activated capture handle
///
/// `pcap_set_snaplen()` sets the snapshot length to be used on a capture handle
/// when the handle is activated to snaplen.
///
/// <https://www.tcpdump.org/manpages/pcap_set_snaplen.3pcap.html>
pub fn pcap_set_snaplen(pcap_t: &PcapT, snaplen: usize) -> Result<()> {
    trace!("pcap_set_snaplen({:p}, {})", pcap_t.pcap_t, snaplen);
    let ret = unsafe { libpcap::pcap_set_snaplen(pcap_t.pcap_t, snaplen as libc::c_int) };
    check_pcap_error(pcap_t, ret)
}

/// set immediate mode for a not-yet-activated capture handle
///
/// `pcap_set_immediate_mode()` sets whether immediate mode should be set on a
/// capture handle when the handle is activated. In immediate mode, packets are
/// always delivered as soon as they arrive, with no buffering.
///
/// <https://www.tcpdump.org/manpages/pcap_set_immediate_mode.3pcap.html>
pub fn pcap_set_immediate_mode(pcap_t: &PcapT, immediate: bool) -> Result<()> {
    trace!(
        "pcap_set_immediate_mode({:p}, {})",
        pcap_t.pcap_t,
        immediate
    );
    let ret = unsafe { libpcap::pcap_set_immediate_mode(pcap_t.pcap_t, immediate.into()) };
    check_pcap_error(pcap_t, ret)
}

/// set the packet buffer timeout for a not-yet-activated capture handle
///
/// `pcap_set_timeout()` sets the packet buffer timeout that will be used on a
/// capture handle when the handle is activated to to_ms, which is in units of
/// milliseconds.
///
/// <https://www.tcpdump.org/manpages/pcap_set_timeout.3pcap.html>
pub fn pcap_set_timeout(pcap_t: &PcapT, to_ms: i32) -> Result<()> {
    trace!("pcap_set_timeout({:p}, {})", pcap_t.pcap_t, to_ms);
    let ret = unsafe { libpcap::pcap_set_timeout(pcap_t.pcap_t, to_ms as libc::c_int) };
    check_pcap_error(pcap_t, ret)
}

/// Sets the capture handle non-blocking mode.
///
/// <https://www.tcpdump.org/manpages/pcap_setnonblock.3pcap.html>
pub fn pcap_set_nonblock(pcap_t: &PcapT, nonblock: bool) -> Result<()> {
    let mut errbuf = Errbuf::new();

    let arg: libc::c_int = match nonblock {
        true => 1,
        false => 0,
    };

    let ret = unsafe { libpcap::pcap_setnonblock(pcap_t.pcap_t, arg, errbuf.as_mut_ptr()) };
    match ret {
        PCAP_SUCCESS => Ok(()),
        PCAP_ERROR => errbuf.as_error(),
        n => Err(Error::PcapErrorCode(n)),
    }
}

/// Returns file descriptor number for file descriptor where select() etc.
/// can be done to read packets without blocking.
///
/// <https://www.tcpdump.org/manpages/pcap_get_selectable_fd.3pcap.html>
pub fn pcap_get_selectable_fd(pcap_t: &PcapT) -> Result<i32> {
    let ret = unsafe { libpcap::pcap_get_selectable_fd(pcap_t.pcap_t) };
    check_pcap_error(pcap_t, ret)?;
    Ok(ret)
}

/// Returns minimum timeout values that should be used for select() etc.
///
/// <https://www.tcpdump.org/manpages/pcap_get_required_select_timeout.3pcap.html>
pub fn pcap_get_required_select_timeout(pcap_t: &PcapT) -> Option<Duration> {
    let tv = unsafe { libpcap::pcap_get_required_select_timeout(pcap_t.pcap_t) };
    if tv.is_null() {
        None
    } else {
        Some(Duration::from_micros(unsafe {
            (*tv).tv_sec as u64 * 1_000_000 + (*tv).tv_usec as u64
        }))
    }
}

/// activate a capture handle
///
/// `pcap_activate()` is used to activate a packet capture handle to look at
/// packets on the network, with the options that were set on the handle being
/// in effect.
///
/// <https://www.tcpdump.org/manpages/pcap_activate.3pcap.html>
pub fn pcap_activate(pcap_t: &PcapT) -> Result<()> {
    trace!("pcap_activate({:p})", pcap_t.pcap_t);
    let ret = unsafe { libpcap::pcap_activate(pcap_t.pcap_t) };
    check_pcap_error(pcap_t, ret)?;

    // pcap_activate() returns 0 on success without warnings, a non-zero
    // positive value on success with warnings, and a negative value on error. A
    // non-zero return value indicates what warning or error condition occurred.
    if ret > 0 {
        return Err(Error::PcapWarning(status_to_str(ret)?));
    }

    Ok(())
}

/// get libpcap error message text
///
/// `pcap_geterr()` returns the error pertaining to the last pcap library error.
///
/// This function can also fail, how awesome is that? The `Result` of
/// `Ok(Error)` contains the error from libpcap as intended. `Err(Error)`
/// contains the error happened while calling this function.
///
/// <https://www.tcpdump.org/manpages/pcap_geterr.3pcap.html>
pub fn get_error(pcap_t: &PcapT) -> Result<Error> {
    trace!("get_error({:p})", pcap_t.pcap_t);
    let ptr = unsafe { libpcap::pcap_geterr(pcap_t.pcap_t) };
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let err = cstr.to_str()?.to_owned();
    Ok(Error::PcapError(err))
}

/// get capture statistics
///
///  `pcap_stats()` fills in the struct `PcapStat` pointed to by its second
///  argument. The values represent packet statistics from the start of the run
///  to the time of the call.
///
/// <https://www.tcpdump.org/manpages/pcap_stats.3pcap.html>
pub fn pcap_stats(pcap_t: &PcapT, stat: &mut PcapStat) -> Result<()> {
    let ret = unsafe { libpcap::pcap_stats(pcap_t.pcap_t, &mut stat.stats) };
    check_pcap_error(pcap_t, ret)
}

/// transmit a packet
///
/// `pcap_inject()` sends a raw packet through the network interface; buf points
/// to the data of the packet, including the link-layer header.
///
/// `pcap_inject()` returns the number of bytes written on success.
///
/// <https://www.tcpdump.org/manpages/pcap_inject.3pcap.html>
pub fn pcap_inject(pcap_t: &PcapT, buf: &[u8]) -> Result<usize> {
    trace!(
        "pcap_inject({:p}, {:?}, {})",
        pcap_t.pcap_t,
        buf.as_ptr(),
        buf.len()
    );
    let ret =
        unsafe { libpcap::pcap_inject(pcap_t.pcap_t, buf.as_ptr() as *const c_void, buf.len()) };

    if ret < 0 {
        check_pcap_error(pcap_t, ret)?;
    }

    Ok(ret as usize)
}

/// compile a filter expression
///
/// `pcap_compile()` is used to compile the filter into a filter program. See
/// [pcap-filter(7)](https://www.tcpdump.org/manpages/pcap-filter.7.html) for
/// the syntax of that string.
///
/// Optimization of the filter turned on by default.
///
/// C library's `pcap_compile()` supports specifying IPv4 netmask, but we use
/// `PCAP_NETMASK_UNKNOWN` by default.
///
/// <https://www.tcpdump.org/manpages/pcap_compile.3pcap.html>
pub fn pcap_compile(pcap_t: &PcapT, filter: &str) -> Result<PcapFilter> {
    trace!("pcap_compile({:p}, {})", pcap_t.pcap_t, filter);
    let mut bpf_program: MaybeUninit<libpcap::bpf_program> = MaybeUninit::zeroed();
    let filter = CString::new(filter)?;
    let optimize = 1;
    let netmask = libpcap::PCAP_NETMASK_UNKNOWN;

    let ret = unsafe {
        libpcap::pcap_compile(
            pcap_t.pcap_t,
            bpf_program.as_mut_ptr(),
            filter.as_ptr(),
            optimize,
            netmask,
        )
    };

    check_pcap_error(pcap_t, ret)?;

    // pcap_compile() has been succesfully compiled so contents of bpf_program
    // can be assumed to be valid.
    let bpf_program = unsafe { bpf_program.assume_init() };
    Ok(PcapFilter { bpf_program })
}

/// set the filter
///
/// `pcap_setfilter()` is used to specify a filter program. pcap_filter is a
/// reference  to a `PcapFilter`, usually the result of a call to
/// `pcap_compile()`.
///
/// <https://www.tcpdump.org/manpages/pcap_setfilter.3pcap.html>
pub fn pcap_setfilter(pcap_t: &PcapT, pcap_filter: &mut PcapFilter) -> Result<()> {
    trace!(
        "pcap_setfilter({:p}, {:p})",
        pcap_t.pcap_t,
        &pcap_filter.bpf_program
    );

    let ret = unsafe { libpcap::pcap_setfilter(pcap_t.pcap_t, &mut pcap_filter.bpf_program) };
    check_pcap_error(pcap_t, ret)
}

/// free a BPF program
///
/// `pcap_freecode()` is used to free up allocated memory pointed to by a
/// bpf_program struct generated by `pcap_compile()` when that BPF program is no
/// longer needed, for example after it has been made the filter program for a
/// pcap structure by a call to `pcap_setfilter()`.
///
/// <https://www.tcpdump.org/manpages/pcap_freecode.3pcap.html>
pub fn pcap_freecode(pcap_filter: PcapFilter) {
    trace!("pcap_freecode({:p})", &pcap_filter.bpf_program);
    // PcapFilter is owned by this function and dropped at this point since it's
    // no longer needed. Dropping frees the allocated resources.
}

/// read the next packet from a `PcapT`
///
/// If data is needed, copy it before calling this again.
///
/// <https://www.tcpdump.org/manpages/pcap_next_ex.3pcap.html>
pub fn pcap_next_ex(pcap_t: &PcapT) -> Result<BorrowedPacket> {
    trace!("pcap_next_ex({:p})", pcap_t.pcap_t);
    let mut header: *mut libpcap::pcap_pkthdr = std::ptr::null_mut();
    let mut packet: *const libc::c_uchar = std::ptr::null();

    let ret = unsafe { libpcap::pcap_next_ex(pcap_t.pcap_t, &mut header, &mut packet) };

    // pcap_next_ex() returns 1 if the packet was read without problems, 0 if
    // packets are being read from a live capture and the packet buffer timeout
    // expired.
    match ret {
        1 => (),
        0 => return Err(Error::Timeout),
        n => check_pcap_error(pcap_t, n)?,
    }

    if header.is_null() || packet.is_null() {
        panic!("header or packet NULL.");
    }

    Ok(BorrowedPacket::new(header, packet))
}

/// open a fake `PcapT` for compiling filters
///
/// `pcap_open_dead()` is used for creating a `PcapT` structure to use when
/// calling the other functions in libpcap. It is typically used when just using
/// libpcap for compiling BPF code.
///
/// This function defaults to opening `LINKTYPE_ETHERNET` (IEEE 802.3 Ethernet
/// (10Mb, 100Mb, 1000Mb, and up)) link-layer with snapshot length of 65535.
///
/// <https://www.tcpdump.org/manpages/pcap_open_dead.3pcap.html>
pub fn pcap_open_dead() -> Result<PcapT> {
    let pcap_t = unsafe { libpcap::pcap_open_dead(libpcap::DLT_EN10MB as libc::c_int, 65535) };

    // pcap_open_dead return value is not documented.
    debug_assert!(!pcap_t.is_null(), "Can pcap_open_dead() fail?");

    Ok(PcapT {
        pcap_t,
        errbuf: Errbuf::new(),
        interface: None,
    })
}

/// open a file to which to write packets
///
/// `pcap_dump_fopen()` is called to write data to an existing open file; The
/// stream is assumed to be at the beginning of a file that has been newly
/// created or truncated, so that writes will start at the beginning of the
/// file.
///
/// <https://www.tcpdump.org/manpages/pcap_dump_open.3pcap.html>
//
// Rust compiler doesn't require it, but we want to take `&mut PcapDumper`
// because we write into a file pointed by `PcapDumper`.
#[allow(clippy::needless_pass_by_value)]
pub fn pcap_dump_fopen(pcap_t: &PcapT, file: &mut std::fs::File) -> Result<PcapDumper> {
    trace!("pcap_dump_fopen({:p}, {:?})", pcap_t.pcap_t, file);
    let mode = b"wb\0";

    let filedesc = unsafe { libc::fdopen(file.as_raw_fd(), mode.as_ptr() as *const libc::c_char) };
    if filedesc.is_null() {
        return Err(Error::IO(std::io::Error::last_os_error()));
    }

    let ret = unsafe { libpcap::pcap_dump_fopen(pcap_t.pcap_t, filedesc) };
    if ret.is_null() {
        return Err(get_error(pcap_t)?);
    }

    Ok(PcapDumper { pcap_dumper_t: ret })
}

/// flush to a savefile packets dumped
///
/// `pcap_dump_flush()` flushes the output buffer to the savefile, so that
/// any packets written with pcap_dump(3PCAP) but not yet written to the
/// savefile will be written.
///
/// <https://www.tcpdump.org/manpages/pcap_dump_flush.3pcap.html>
//
// Rust compiler doesn't require it, but we want to take `&mut PcapDumper`
// because we write into a file pointed by `PcapDumper`.
#[allow(clippy::needless_pass_by_value)]
pub fn pcap_dump_flush(dumper: &mut PcapDumper) -> Result<()> {
    trace!("pcap_dump_flush({:p})", dumper.pcap_dumper_t);
    let ret = unsafe { libpcap::pcap_dump_flush(dumper.pcap_dumper_t) };
    if ret == 0 {
        Ok(())
    } else {
        // https://github.com/the-tcpdump-group/libpcap/blob/f828383609906455b9369b1ae86a75f0bd4ba374/sf-pcap.c#L1171C1-L1179
        //
        // pcap_dump_flush calls fflush() which sets errno so we can probably
        // dig that error out.
        Err(Error::IO(std::io::Error::last_os_error()))
    }
}

/// write a packet to a capture file
///
/// `pcap_dump()` outputs a packet to the savefile opened with
/// `pcap_dump_open()`. Note that its calling arguments are suitable for use
/// with `pcap_dispatch()` or `pcap_loop`. If called directly, the user
/// parameter is of type `pcap_dumper_t` as returned by `pcap_dump_open()`.
///
/// <https://www.tcpdump.org/manpages/pcap_dump.3pcap.html>
//
// Rust compiler doesn't require it, but we want to take `&mut PcapDumper`
// because we write into a file pointed by `PcapDumper`.
#[allow(clippy::needless_pass_by_value)]
pub fn pcap_dump(dumper: &mut PcapDumper, pkthdr: &libpcap::pcap_pkthdr, bytes: &[u8]) {
    trace!("pcap_dump({:p}, {:?})", dumper.pcap_dumper_t, pkthdr);
    unsafe {
        libpcap::pcap_dump(
            dumper.pcap_dumper_t as *mut libc::c_uchar,
            pkthdr,
            bytes.as_ptr(),
        )
    }
}

/// get a list of capture devices
///
/// `pcap_findalldevs()` constructs a list of network devices that can be opened
/// with `pcap_create()` and `pcap_activate()` or with `pcap_open_live()`. Note
/// that there may be network devices that cannot be opened by the process
/// calling `pcap_findalldevs()`, because, for example, that process does not
/// have sufficient privileges to open them for capturing; if so, those devices
/// will not appear on the list.
///
/// <https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html>
pub fn pcap_findalldevs() -> Result<PcapIfT> {
    let mut pcap_if_t: *mut libpcap::pcap_if_t = std::ptr::null_mut();
    let mut errbuf = Errbuf::new();

    let ret = unsafe { libpcap::pcap_findalldevs(&mut pcap_if_t, errbuf.as_mut_ptr()) };

    match ret {
        PCAP_SUCCESS => {
            trace!("pcap_findalldevs() => {:p}", pcap_if_t);
            Ok(PcapIfT { pcap_if_t })
        }
        PCAP_ERROR => errbuf.as_error(),
        n => Err(Error::PcapErrorCode(n)),
    }
}

/// free a list of capture devices
///
/// Free a list of network devices produced by `pcap_findalldevs()`.
///
/// <https://www.tcpdump.org/manpages/pcap_findalldevs.3pcap.html>
pub fn pcap_freealldevs(pcap_if_t: PcapIfT) {
    trace!("pcap_freealldevs({:p})", pcap_if_t.pcap_if_t);
    // PcapIfT is owned by this function and dropped at this point since it's no
    // longer needed. Dropping frees the allocated resources.
}

pub(crate) fn try_interface_from(pcap_if_t: *mut libpcap::pcap_if_t) -> Result<Interface> {
    trace!("try_interface_from({:p})", pcap_if_t);
    let name: Box<str> = {
        let name = unsafe { (*pcap_if_t).name };
        if name.is_null() {
            panic!("pcap_if_t.name is null");
        } else {
            let s = unsafe { CStr::from_ptr(name) };
            s.to_str()?.into()
        }
    };

    let description: Option<Box<str>> = {
        let descr = unsafe { (*pcap_if_t).description };
        if descr.is_null() {
            None
        } else {
            let s = unsafe { CStr::from_ptr(descr) };
            Some(s.to_str()?.into())
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
            let s_addr: u32 = unsafe { (*inet4).sin_addr.s_addr };
            Some(Ipv4Addr::from(u32::from_be(s_addr)).into())
        }

        libc::AF_INET6 => {
            let inet6: *const libc::sockaddr_in6 = addr as *const libc::sockaddr_in6;
            let s6_addr: [u8; 16] = unsafe { (*inet6).sin6_addr.s6_addr };
            Some(Ipv6Addr::from(s6_addr).into())
        }

        #[cfg(target_os = "macos")]
        libc::AF_LINK => {
            let dl_sock: *const libc::sockaddr_dl = addr as *const libc::sockaddr_dl;
            let start = unsafe { (*dl_sock).sdl_nlen } as usize;
            let dl_addr: [u8; 6] = unsafe {
                [
                    *(*dl_sock).sdl_data.get(start)? as u8,
                    *(*dl_sock).sdl_data.get(start + 1)? as u8,
                    *(*dl_sock).sdl_data.get(start + 2)? as u8,
                    *(*dl_sock).sdl_data.get(start + 3)? as u8,
                    *(*dl_sock).sdl_data.get(start + 4)? as u8,
                    *(*dl_sock).sdl_data.get(start + 5)? as u8,
                ]
            };
            Some(MacAddr::from(dl_addr).into())
        }

        #[cfg(target_os = "linux")]
        libc::AF_PACKET => {
            let ll_sock: *const libc::sockaddr_ll = addr as *const libc::sockaddr_ll;
            let mut ll_addr = [0u8; 6];
            ll_addr.copy_from_slice(unsafe { &(&(*ll_sock).sll_addr)[0..6] });
            Some(MacAddr::from(ll_addr).into())
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
        let addr = unsafe { (*pcap_addr_t).addr as *const libc::sockaddr };
        from_sockaddr(addr)?
    };

    let netmask = {
        let addr = unsafe { (*pcap_addr_t).netmask as *const libc::sockaddr };
        from_sockaddr(addr)
    };

    let broadaddr = {
        let addr = unsafe { (*pcap_addr_t).broadaddr as *const libc::sockaddr };
        from_sockaddr(addr)
    };

    let dstaddr = {
        let addr = unsafe { (*pcap_addr_t).dstaddr as *const libc::sockaddr };
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
    trace!("status_to_str({})", error);
    let ptr = unsafe { libpcap::pcap_statustostr(error) };
    let cstr = unsafe { CStr::from_ptr(ptr) };
    let status = cstr.to_str()?.to_owned();
    Ok(status)
}

/// Check for `libpcap` error.
fn check_pcap_error(pcap_t: &PcapT, ret: i32) -> Result<()> {
    if log::log_enabled!(log::Level::Trace) {
        let status = match ret {
            0 => "ok".to_string(),
            n => status_to_str(n).unwrap_or_default(),
        };
        trace!(
            "check_pcap_error({:p}, {}) = {}",
            pcap_t.pcap_t,
            ret,
            status
        );
    }

    match ret {
        PCAP_SUCCESS => Ok(()),
        PCAP_ERROR => Err(get_error(pcap_t)?),
        libpcap::PCAP_ERROR_BREAK => Err(Error::Break),
        libpcap::PCAP_ERROR_NOT_ACTIVATED => Err(Error::NotActivated(pcap_t.get_inteface())),
        libpcap::PCAP_ERROR_ACTIVATED => Err(Error::AlreadyActivated(pcap_t.get_inteface())),
        libpcap::PCAP_ERROR_NO_SUCH_DEVICE => Err(Error::NoSuchDevice(pcap_t.get_inteface())),
        libpcap::PCAP_ERROR_RFMON_NOTSUP => {
            Err(Error::MonitorModeNotSupported(pcap_t.get_inteface()))
        }
        libpcap::PCAP_ERROR_NOT_RFMON => Err(Error::OnlySupportedInMonitorMode),
        libpcap::PCAP_ERROR_PERM_DENIED => Err(Error::PermissionDenied(pcap_t.get_inteface())),
        libpcap::PCAP_ERROR_IFACE_NOT_UP => Err(Error::InterfaceNotUp(pcap_t.get_inteface())),
        libpcap::PCAP_ERROR_CANTSET_TSTAMP_TYPE => {
            Err(Error::TimestampTypeNotSupported(pcap_t.get_inteface()))
        }
        libpcap::PCAP_ERROR_PROMISC_PERM_DENIED => {
            Err(Error::PromiscuousPermissionDenied(pcap_t.get_inteface()))
        }
        libpcap::PCAP_ERROR_TSTAMP_PRECISION_NOTSUP => Err(Error::TimestampPrecisionNotSupported),
        n if n < 0 => Err(Error::PcapErrorCode(n)),
        _ => Ok(()),
    }
}

/// Polls for given `fd` for `timeout` to become readable returning `true` if
/// `fd` is readable.
pub fn poll_fd_in(fd: i32, timeout: Duration) -> std::io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let ret = unsafe { libc::poll(&mut pfd, 1, timeout.as_millis() as i32) };
    match ret {
        0 => Ok(false),
        -1 => Err(std::io::Error::last_os_error()),
        _ => {
            if pfd.revents & libc::POLLIN == libc::POLLIN {
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test for https://github.com/sensorfu/luomu-libpcap/pull/10
    //
    // Alone this is trivial and doesn't do much, but combine it with Clang's
    // LeakSanitizer:
    //
    //   $ RUSTFLAGS="-Z sanitizer=leak" cargo +nightly test
    //
    // and it reproduces issue described in above pull request.
    #[test]
    fn test_pcap_t_drop() {
        let _pcap_t: PcapT = pcap_create("").expect("pcap_create");
    }

    #[test]
    fn test_pcap_if_t() {
        let _pcap_if_t: PcapIfT = pcap_findalldevs().expect("pcap_findalldevs");
    }
}
