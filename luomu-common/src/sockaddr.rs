#![allow(unsafe_code)]
//! Utilities to handle [libc::sockaddr] and related structs.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::Address;

/// Length of MAC address in bytes
const MAC_ADDR_LEN: usize = 6;

/// Reads address information from given socket address pointer.
///
/// Address may contain IP address or Link address, the returned [Address]
/// reflects which one was read. [None] is returned if no address was available,
/// or it could not be read.
// We do our best to validate that the pointer given in `ifa_addr` is valid.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn from_sockaddr(ifa_addr: *const libc::sockaddr) -> Option<Address> {
    if ifa_addr.is_null() {
        return None;
    }

    let family = i32::from(unsafe { (*ifa_addr).sa_family });

    #[cfg(target_os = "macos")]
    let sa_len = usize::from(unsafe { (*ifa_addr).sa_len });

    match family {
        #[cfg(target_os = "macos")]
        libc::AF_INET if sa_len < 16 => {
            debug_assert!((5..=8).contains(&sa_len), "invalid sa_len {sa_len} for AF_INET");
            // We keep ifa_addr as sockaddr, but read it like it's sockaddr_in:
            //
            //   pub struct sockaddr_in {
            //       pub sin_len: u8,
            //       pub sin_family: u8,
            //       pub sin_port: u16,     \ These two are in sockaddr.sa_data
            //       pub sin_addr: u32,     /
            //       pub sin_zero: [c_char; 8],
            //   }
            //
            // We want to read the partial bytes from sin_addr, the length is
            // dictated by sa_len. sockaddr.sa_data contains first sin_port
            // which we skip and then sin_addr.
            let len = sa_len.saturating_sub(2); // remove length of sin_len and sin_family
            let mut iret = [0i8; 4];
            let sa_data: &[i8] = unsafe { std::slice::from_raw_parts((*ifa_addr).sa_data.as_ptr(), len) };
            iret[0..len.saturating_sub(2)].copy_from_slice(&sa_data[2..len]);
            let uret: [u8; 4] = unsafe { std::mem::transmute(iret) };
            Some(Address::from(Ipv4Addr::from_octets(uret)))
        }

        libc::AF_INET => {
            #[cfg(target_os = "macos")]
            debug_assert_eq!(sa_len, 16, "invalid sa_len {sa_len} for AF_INET");
            let a: libc::sockaddr_in = unsafe { *(ifa_addr.cast::<libc::sockaddr_in>()) };
            Some(Address::from(Ipv4Addr::from_bits(u32::from_be(
                a.sin_addr.s_addr,
            ))))
        }

        libc::AF_INET6 => {
            #[cfg(target_os = "macos")]
            debug_assert_eq!(sa_len, 28, "invalid sa_len {sa_len} for AF_INET6");
            let a: libc::sockaddr_in6 = unsafe { *(ifa_addr.cast::<libc::sockaddr_in6>()) };
            Some(Address::from(Ipv6Addr::from_octets(a.sin6_addr.s6_addr)))
        }

        #[cfg(target_os = "macos")]
        libc::AF_LINK => {
            debug_assert!(
                sa_len == 20 || sa_len == 24,
                "invalid sa_len {sa_len} for AF_LINK"
            );
            // MAC address for this interface
            let a: libc::sockaddr_dl = unsafe { *(ifa_addr.cast::<libc::sockaddr_dl>()) };
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
                unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), data.len()) };
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
