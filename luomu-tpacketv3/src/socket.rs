use std::mem;
use std::time::Duration;

use luomu_libpcap::PcapFilter;

pub fn htons(val: u16) -> u16 {
    val.to_be()
}
pub struct OptValue<T> {
    pub val: T,
}

impl<T> OptValue<T> {
    fn ptr(&self) -> *const libc::c_void {
        (&raw const self.val).cast::<libc::c_void>()
    }

    fn mut_ptr(&mut self) -> *mut libc::c_void {
        (&raw mut self.val).cast::<libc::c_void>()
    }

    #[allow(clippy::unused_self)]
    fn optlen(&self) -> libc::socklen_t {
        libc::socklen_t::try_from(mem::size_of::<T>()).unwrap_or(libc::socklen_t::MAX)
    }
}

pub enum Option<T> {
    PacketVersion(OptValue<T>),
    PacketRxRing(OptValue<T>),
    PacketAddMembership(OptValue<T>),
    PacketStatistics(OptValue<T>),
    PacketFanout(OptValue<T>),
    SocketAttachFilter(OptValue<T>),
}

impl<T> Option<T> {
    fn level(&self) -> libc::c_int {
        match self {
            Option::SocketAttachFilter(_) => libc::SOL_SOCKET,
            _ => libc::SOL_PACKET,
        }
    }

    fn name(&self) -> libc::c_int {
        match self {
            Option::PacketVersion(_) => libc::PACKET_VERSION,
            Option::PacketRxRing(_) => libc::PACKET_RX_RING,
            Option::PacketAddMembership(_) => libc::PACKET_ADD_MEMBERSHIP,
            Option::PacketStatistics(_) => libc::PACKET_STATISTICS,
            Option::PacketFanout(_) => libc::PACKET_FANOUT,
            Option::SocketAttachFilter(_) => libc::SO_ATTACH_FILTER,
        }
    }

    fn val(&self) -> &OptValue<T> {
        match self {
            Option::PacketAddMembership(v)
            | Option::PacketFanout(v)
            | Option::PacketRxRing(v)
            | Option::PacketStatistics(v)
            | Option::PacketVersion(v)
            | Option::SocketAttachFilter(v) => v,
        }
    }

    fn mut_val(&mut self) -> &mut OptValue<T> {
        match self {
            Option::PacketAddMembership(v)
            | Option::PacketFanout(v)
            | Option::PacketRxRing(v)
            | Option::PacketStatistics(v)
            | Option::PacketVersion(v)
            | Option::SocketAttachFilter(v) => v,
        }
    }
}

#[derive(Copy, Clone)]
pub struct Fd {
    fd: libc::c_int,
}

impl Fd {
    pub fn create() -> Result<Fd, std::io::Error> {
        #[allow(clippy::cast_possible_truncation)]
        let proto = libc::c_int::from(htons(libc::ETH_P_ALL as u16));
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            tracing::warn!("Unable to create socket");
            return Err(std::io::Error::last_os_error());
        }
        tracing::trace!("Created socket with fd={fd}");
        Ok(Fd { fd })
    }

    pub fn raw_fd(self) -> libc::c_int {
        self.fd
    }

    pub fn setopt<T>(&self, opt: &Option<T>) -> Result<(), std::io::Error> {
        tracing::trace!(
            "option value ptr={:?} oplen={}",
            opt.val().ptr(),
            opt.val().optlen()
        );
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                opt.level(),
                opt.name(),
                opt.val().ptr(),
                opt.val().optlen(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(())
    }

    pub fn getopt<T: Copy>(&self, mut opt: Option<T>) -> Result<T, std::io::Error> {
        let mut l = opt.val().optlen();

        let ret = unsafe {
            libc::getsockopt(
                self.fd,
                opt.level(),
                opt.name(),
                opt.mut_val().mut_ptr(),
                (&raw mut l).cast::<u32>(),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(opt.val().val)
    }

    pub fn bind(&self, sll: &libc::sockaddr_ll) -> Result<(), std::io::Error> {
        let ret = unsafe {
            libc::bind(
                self.fd,
                (std::ptr::from_ref(sll).cast::<libc::c_void>()).cast::<libc::sockaddr>(),
                u32::try_from(mem::size_of::<libc::sockaddr_ll>()).unwrap_or(u32::MAX),
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    pub fn close(self) {
        tracing::trace!("Closing socket with fd={}", self.fd);
        unsafe { libc::close(self.fd) };
    }

    /// Poll this fd for availability of data
    /// Returns Ok(false) if no data was available within timeout (XXX)
    /// Ok(true) if there is data available
    pub fn poll(&self, timeout: Duration) -> Result<bool, std::io::Error> {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN | libc::POLLERR,
            revents: 0,
        };

        let timeout = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let ret = unsafe { libc::poll(&raw mut pfd, 1, timeout) };
        match ret {
            0 => Ok(false),
            -1 => Err(std::io::Error::last_os_error()),
            _ => Ok(true),
        }
    }

    /// Attach given BPF filter to socket.
    pub fn set_filter(&self, filt: &PcapFilter) -> Result<(), std::io::Error> {
        let prog = sock_fprog {
            len: u16::try_from(filt.get_raw_filter_len()).unwrap_or(u16::MAX),
            filter: filt.get_raw_filter(),
        };
        self.setopt(&Option::SocketAttachFilter(OptValue { val: prog }))
    }
}

// This struct is given as parameter to SO_ATTACH_FILTER sockopt.
// the filter should be be a pointer to sock_filter, but we treat
// it as opaque pointer as we do not really care about how the filter
// program is represented, just trust that the PcapFilter will provide
// us with pointer to proper struct.
#[repr(C)]
#[allow(non_camel_case_types)]
struct sock_fprog {
    len: u16,
    filter: *const libc::c_void,
}
