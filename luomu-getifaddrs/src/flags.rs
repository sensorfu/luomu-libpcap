use bitflags::bitflags;

bitflags! {
    /// Interface flags
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct Flags: libc::c_int {
        const UP = libc::IFF_UP;
        const BROADCAST = libc::IFF_BROADCAST;
        const DEBUG = libc::IFF_DEBUG;
        const LOOPBACK = libc::IFF_LOOPBACK;
        const POINTOPOINT = libc::IFF_POINTOPOINT;
        const RUNNING = libc::IFF_RUNNING;
        const NOARP = libc::IFF_NOARP;
        const PROMISC = libc::IFF_PROMISC;
        const NOTRAILERS = libc::IFF_NOTRAILERS;
        const ALLMULTI = libc::IFF_ALLMULTI;
        const MULTICAST = libc::IFF_MULTICAST;

        #[cfg(target_os = "macos")]
        const OACTIVE = libc::IFF_OACTIVE;
        #[cfg(target_os = "macos")]
        const SIMPLEX = libc::IFF_SIMPLEX;
        #[cfg(target_os = "macos")]
        const LINK0 = libc::IFF_LINK0;
        #[cfg(target_os = "macos")]
        const LINK1 = libc::IFF_LINK1;
        #[cfg(target_os = "macos")]
        const LINK2 = libc::IFF_LINK2;
        #[cfg(target_os = "macos")]
        const ALTPHYS = libc::IFF_ALTPHYS;

        #[cfg(target_os = "linux")]
        const MASTER = libc::IFF_MASTER;
        #[cfg(target_os = "linux")]
        const SLAVE = libc::IFF_SLAVE;
        #[cfg(target_os = "linux")]
        const PORTSEL = libc::IFF_PORTSEL;
        #[cfg(target_os = "linux")]
        const AUTOMEDIA = libc::IFF_AUTOMEDIA;
        #[cfg(target_os = "linux")]
        const DYNAMIC = libc::IFF_DYNAMIC;
        #[cfg(target_os = "linux")]
        const LOWER_UP = libc::IFF_LOWER_UP;
        #[cfg(target_os = "linux")]
        const DORMANT = libc::IFF_DORMANT;
        #[cfg(target_os = "linux")]
        const ECHO = libc::IFF_ECHO;
    }
}
