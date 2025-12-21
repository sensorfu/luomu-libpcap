#![doc = include_str!("../README.md")]
#![cfg(unix)]
#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use luomu_common::{Address, MacAddr};

#[cfg(target_os = "macos")]
use std::slice;

mod flags;
pub use flags::Flags;

mod stats;
pub use stats::IfStats;

/// Length of MAC address in bytes
const MAC_ADDR_LEN: usize = 6;

/// Returns a linked list describing the network interfaces of
/// the local system.
pub fn getifaddrs() -> io::Result<IfAddrs> {
    let mut base_ptr = MaybeUninit::uninit();
    let ret = unsafe { libc::getifaddrs(base_ptr.as_mut_ptr()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    let base_ptr = unsafe { base_ptr.assume_init() };
    let ifaddrs = IfAddrs {
        base_ptr,
        curr_ptr: Some(base_ptr),
    };
    Ok(ifaddrs)
}

/// Provides access to list containing information about network interfaces.
#[derive(Debug)]
pub struct IfAddrs {
    // Base pointer is used to free the whole linked list
    base_ptr: *mut libc::ifaddrs,
    // Current pointer points to current item in linked list
    curr_ptr: Option<*mut libc::ifaddrs>,
}

impl IfAddrs {
    /// Returns information about current list item or [None] if no more
    /// interfaces are available.
    const fn ifaddr(&self) -> Option<IfAddr> {
        if let Some(ptr) = self.curr_ptr {
            return Some(IfAddr { ptr });
        }
        None
    }

    /// Advance to next interface on the list.
    fn next(&mut self) {
        if let Some(curr_ptr) = self.curr_ptr.take() {
            let next_ptr = unsafe { *curr_ptr }.ifa_next;
            if !next_ptr.is_null() {
                self.curr_ptr = Some(next_ptr);
            }
        }
    }

    /// Returns all IP addresses of network interface with given name.
    ///
    /// Returned [Iterator] yields no values if interface with given name
    /// does not exist.
    pub fn ip_addresses(self, interface: &str) -> impl Iterator<Item = IpAddr> + '_ {
        self.iter_interface(interface)
            .filter_map(|ifa| ifa.addr().and_then(|a| a.as_ip()))
    }

    /// Returns MAC address of interface with given name
    ///
    /// Returns [None] if no interface with given name does not exist
    pub fn mac_address(self, interface: &str) -> Option<MacAddr> {
        // there should be only one MAC address for interface thus it is
        // ok to return the first mac address we get for given interface
        self.iter_interface(interface)
            .find_map(|ifa| ifa.addr().and_then(|a| a.as_mac()))
    }

    /// Returns statistics for interface with given name
    ///
    /// Returns [None] if no interface with given name does not exist
    pub fn if_stats(self, interface: &str) -> Option<stats::LinkStats> {
        self.iter_interface(interface).find_map(|ifa| ifa.data())
    }

    fn iter_interface(self, interface: &str) -> impl Iterator<Item = IfAddr> {
        self.into_iter().filter(move |ifa| ifa.name() == interface)
    }
}

impl Drop for IfAddrs {
    fn drop(&mut self) {
        if !self.base_ptr.is_null() {
            unsafe { libc::freeifaddrs(self.base_ptr) };
        }
    }
}

impl Iterator for IfAddrs {
    type Item = IfAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(ifaddr) = self.ifaddr() {
            self.next();
            return Some(ifaddr);
        }
        None
    }
}

/// Returns address family value from [libc::sockaddr]
const fn sa_get_family(sa: *const libc::sockaddr) -> i32 {
    unsafe { *sa }.sa_family as libc::c_int
}

/// Returns given [libc::sockaddr] pointer as a pointer to [libc::sockaddr_in]
const fn sa_as_sockaddr_in(sa: *const libc::sockaddr) -> libc::sockaddr_in {
    unsafe { *(sa.cast::<libc::sockaddr_in>()) }
}

/// Returns given [libc::sockaddr] pointer as a pointer to [libc::sockaddr_in6]
const fn sa_as_sockaddr_in6(sa: *const libc::sockaddr) -> libc::sockaddr_in6 {
    unsafe { *(sa.cast::<libc::sockaddr_in6>()) }
}

#[cfg(target_os = "macos")]
/// Returns given [libc::sockaddr] pointer as a pointer to [libc::sockaddr_dl]
const fn sa_as_sockaddr_dl(sa: *const libc::sockaddr) -> libc::sockaddr_dl {
    unsafe { *(sa.cast::<libc::sockaddr_dl>()) }
}

/// This struct provides access to information about network interface.
pub struct IfAddr {
    /// pointer for the interface data
    ptr: *const libc::ifaddrs,
}

impl IfAddr {
    /// Access the [libc::ifaddrs] this element points to
    const fn ifa(&self) -> libc::ifaddrs {
        unsafe { *(self.ptr) }
    }

    /// Returns collected information about this interface.
    pub fn ifaddress(&self) -> IfAddress<'_> {
        IfAddress {
            name: self.name(),
            flags: self.flags(),
            addr: self.addr(),
            netmask: self.netmask(),
            dstaddr: self.dstaddr(),
            data: self.data(),
        }
    }

    /// Interface name
    // Interface name comes from OS and should be sane (aka ASCII?)
    #[allow(clippy::missing_panics_doc)]
    pub fn name(&self) -> &str {
        unsafe { CStr::from_ptr(self.ifa().ifa_name) }
            .to_str()
            .expect("convert interface name to UTF-8")
    }

    /// Interface flags
    pub const fn flags(&self) -> Flags {
        #[allow(clippy::cast_possible_wrap)]
        Flags::from_bits_truncate(self.ifa().ifa_flags as i32)
    }

    /// Interface address
    pub fn addr(&self) -> Option<Address> {
        IfAddr::read_addr(self.ifa().ifa_addr)
    }

    /// Interface netmask
    pub fn netmask(&self) -> Option<IpAddr> {
        IfAddr::read_addr(self.ifa().ifa_netmask).and_then(|a| a.as_ip())
    }

    /// Destination address for Point-to-Point link
    pub fn dstaddr(&self) -> Option<IpAddr> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                IfAddr::read_addr(self.ifa().ifa_dstaddr).and_then(|a| a.as_ip())
            } else if #[cfg(target_os = "linux")] {
                IfAddr::read_addr(self.ifa().ifa_ifu).and_then(|a| a.as_ip())
            }
        }
    }

    /// Returns link statistics data, if available.
    pub fn data(&self) -> Option<stats::LinkStats> {
        if self.ifa().ifa_addr.is_null() || self.ifa().ifa_data.is_null() {
            return None;
        }

        let family = sa_get_family(self.ifa().ifa_addr);

        #[cfg(target_os = "linux")]
        if family != libc::AF_PACKET {
            return None;
        }

        #[cfg(target_os = "macos")]
        if family != libc::AF_LINK {
            return None;
        }

        let ifa_data = self.ifa().ifa_data;
        let link_stats = unsafe { &*(ifa_data as *const stats::LinkStats) };
        Some(*link_stats)
    }

    /// Reads address information from given socket address pointer.
    ///
    /// Address may contain IP address or Link address, the returned
    /// [Addr] reflects which one was read. [None] is returned if no address
    /// was available, or it could not be read.
    fn read_addr(ifa_addr: *const libc::sockaddr) -> Option<Address> {
        if ifa_addr.is_null() {
            return None;
        }

        let family = sa_get_family(ifa_addr);

        match family {
            libc::AF_INET => {
                let a: libc::sockaddr_in = sa_as_sockaddr_in(ifa_addr);
                Some(Address::from(Ipv4Addr::from(u32::from_be(a.sin_addr.s_addr))))
            }
            libc::AF_INET6 => {
                let a: libc::sockaddr_in6 = sa_as_sockaddr_in6(ifa_addr);
                Some(Address::from(Ipv6Addr::from(a.sin6_addr.s6_addr)))
            }
            #[cfg(target_os = "macos")]
            libc::AF_LINK => {
                // MAC address for this interface
                let a: libc::sockaddr_dl = sa_as_sockaddr_dl(ifa_addr);
                // length of the address
                let a_len = usize::from(a.sdl_alen);
                // length of the name
                let n_len = usize::from(a.sdl_nlen);
                // If seems that name is stored to sdl_data before the mac
                // address of the interface. However, libc::sockaddr_dl::sdl_data has been
                // defined to contain 12 bytes. Thus, if name of the interface
                // is longer than 6 bytes (characters), we can not read the MAC
                // address of that interface.
                if a_len != MAC_ADDR_LEN || n_len + a_len > a.sdl_data.len() {
                    return None;
                }
                // also, sdl_data has been defined as i8 for whatever reason,
                // we need bytes for mac address, thus a bit of unsafery
                let data = &a.sdl_data;
                let sdl_data_as_u8: &[u8] =
                    unsafe { slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len()) };
                let mut address = [0u8; MAC_ADDR_LEN];
                // mac address stored after name
                // You may want to look into LLADDR() macro somewhere on Mac OS headers
                let offset = usize::from(a.sdl_nlen);
                address[..MAC_ADDR_LEN].copy_from_slice(&sdl_data_as_u8[offset..offset + MAC_ADDR_LEN]);
                Some(Address::from(address))
            }
            #[cfg(target_os = "linux")]
            libc::AF_PACKET => {
                // Mac address of the interface
                let a: libc::sockaddr_ll = unsafe { *(ifa_addr.cast::<libc::sockaddr_ll>()) };
                let a_len = usize::from(a.sll_halen);
                debug_assert!(a_len == MAC_ADDR_LEN);
                if a_len != MAC_ADDR_LEN {
                    return None;
                }
                let mut address = [0u8; MAC_ADDR_LEN];
                address[..MAC_ADDR_LEN].copy_from_slice(&a.sll_addr[..MAC_ADDR_LEN]);
                Some(Address::from(address))
            }
            _ => None,
        }
    }
}

/// A view into interface data
#[derive(Debug, Hash)]
pub struct IfAddress<'a> {
    /// Interface name
    pub name: &'a str,
    /// Interface flags
    pub flags: Flags,
    /// Interface address
    pub addr: Option<Address>,
    /// Interface netmask
    pub netmask: Option<IpAddr>,
    /// P2P interface destination or interface broadcast address
    pub dstaddr: Option<IpAddr>,
    /// Address specific data
    pub data: Option<stats::LinkStats>,
}

#[cfg(test)]
mod tests {
    use std::io;

    use crate::getifaddrs;

    #[test]
    fn test_getifaddrs() -> io::Result<()> {
        let _ifaddrs = getifaddrs()?;
        Ok(())
    }

    #[test]
    fn test_getifaddrs_iterator() -> io::Result<()> {
        let ifaddrs = getifaddrs()?;
        for ifaddr in ifaddrs {
            let _addrs = ifaddr.ifaddress();
        }
        Ok(())
    }
}
