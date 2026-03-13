#![doc = include_str!("../README.md")]
#![cfg(unix)]
#![allow(unsafe_code)]

use std::ffi::CStr;
use std::io;
use std::mem::MaybeUninit;
use std::net::IpAddr;

use luomu_common::sockaddr::from_sockaddr;
use luomu_common::{Address, MacAddr};

mod flags;
pub use flags::Flags;

mod stats;
pub use stats::IfStats;

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
        from_sockaddr(self.ifa().ifa_addr)
    }

    /// Interface netmask
    pub fn netmask(&self) -> Option<IpAddr> {
        from_sockaddr(self.ifa().ifa_netmask).and_then(|a| a.as_ip())
    }

    /// Destination address for Point-to-Point link
    pub fn dstaddr(&self) -> Option<IpAddr> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                from_sockaddr(self.ifa().ifa_dstaddr).and_then(|a| a.as_ip())
            } else if #[cfg(target_os = "linux")] {
                from_sockaddr(self.ifa().ifa_ifu).and_then(|a| a.as_ip())
            }
        }
    }

    /// Returns link statistics data, if available.
    pub fn data(&self) -> Option<stats::LinkStats> {
        if self.ifa().ifa_addr.is_null() || self.ifa().ifa_data.is_null() {
            return None;
        }

        let family = i32::from(unsafe { *self.ifa().ifa_addr }.sa_family);

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
