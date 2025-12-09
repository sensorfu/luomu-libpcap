use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Descriptor for single packet within a block in mmapped ringbuffer
pub struct PacketDescriptor<'a> {
    ptr: *mut u8,
    hdr: &'a libc::tpacket3_hdr,
}

impl<'a> PacketDescriptor<'a> {
    #[allow(clippy::cast_ptr_alignment)]
    pub fn get_next(self) -> PacketDescriptor<'a> {
        let next_offset = isize::try_from(self.hdr.tp_next_offset).unwrap_or(isize::MAX);
        let next_ptr = unsafe { self.ptr.offset(next_offset) };
        let next_hdr_ptr = next_ptr as *const libc::tpacket3_hdr;
        PacketDescriptor {
            ptr: next_ptr,
            hdr: unsafe { next_hdr_ptr.as_ref().unwrap() },
        }
    }

    pub fn get_timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::new(u64::from(self.hdr.tp_sec), self.hdr.tp_nsec)
    }

    pub fn get_packet_data(&self) -> &'a [u8] {
        let tp_mac = isize::try_from(self.hdr.tp_mac).unwrap_or(isize::MAX);
        let data_ptr = unsafe { self.ptr.offset(tp_mac) };
        let snaplen = usize::try_from(self.hdr.tp_snaplen).unwrap_or(usize::MAX);
        unsafe { std::slice::from_raw_parts(data_ptr, snaplen) }
    }

    pub fn has_vlan_tci(&self) -> bool {
        (self.hdr.tp_status & libc::TP_STATUS_VLAN_VALID) == libc::TP_STATUS_VLAN_VALID
    }

    pub fn has_vlan_tpid(&self) -> bool {
        (self.hdr.tp_status & libc::TP_STATUS_VLAN_TPID_VALID) == libc::TP_STATUS_VLAN_TPID_VALID
    }

    pub fn get_vlan_tci(&self) -> u32 {
        self.hdr.hv1.tp_vlan_tci
    }

    pub fn get_vlan_tpid(&self) -> u16 {
        self.hdr.hv1.tp_vlan_tpid
    }
}

impl From<*mut u8> for PacketDescriptor<'_> {
    #[allow(clippy::cast_ptr_alignment)]
    fn from(ptr: *mut u8) -> Self {
        let hdr_ptr = ptr as *const libc::tpacket3_hdr;
        let hdr = unsafe { hdr_ptr.as_ref().unwrap() };
        PacketDescriptor { ptr, hdr }
    }
}

/// Descriptor for a block inside the mmapped ringbuffer.
///
/// Block is either owned by kernel or ready. Ready block contains 1 or more
/// packets which can be read. Once all packets have been consumed, flush()
/// needs to be called to indicate kernel that it free to use this block again
pub struct BlockDescriptor<'a> {
    ptr: *mut u8,                           // pointer to the start of the data
    desc: &'a mut libc::tpacket_block_desc, // the actual block descriptor
}

unsafe impl Send for BlockDescriptor<'_> {}

impl<'a> BlockDescriptor<'a> {
    // Returns reference to block header
    fn block_header(&self) -> &libc::tpacket_hdr_v1 {
        unsafe { &self.desc.hdr.bh1 }
    }

    pub fn flush(&mut self) {
        self.desc.hdr.bh1.block_status = libc::TP_STATUS_KERNEL;
    }

    pub fn is_ready(&self) -> bool {
        self.block_header().block_status & libc::TP_STATUS_USER != 0
    }

    pub fn get_number_of_packets(&self) -> u32 {
        self.block_header().num_pkts
    }

    pub fn get_first_packet(&self) -> PacketDescriptor<'a> {
        let offset = isize::try_from(self.block_header().offset_to_first_pkt).unwrap_or(isize::MAX);
        unsafe { self.ptr.offset(offset) }.into()
    }
}

impl From<*mut u8> for BlockDescriptor<'_> {
    #[allow(clippy::cast_ptr_alignment)]
    fn from(ptr: *mut u8) -> Self {
        let desc_ptr = ptr.cast::<libc::tpacket_block_desc>();

        BlockDescriptor {
            ptr,
            desc: unsafe { desc_ptr.as_mut().unwrap() },
        }
    }
}

impl fmt::Display for BlockDescriptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "block@{:?} ready:{}, num_packets: {}",
            self.ptr,
            self.is_ready(),
            self.get_number_of_packets()
        )
    }
}

/// mmapped ringbuffer. Contains blocks of packet data, each block will be filled
/// with packets by the kernel
#[allow(clippy::struct_field_names)]
pub struct Map {
    ptr: *mut libc::c_void,
    map_size: libc::size_t,
    #[allow(dead_code)]
    block_size: u32,
    block_count: u32,
}

unsafe impl Send for Map {}

impl Map {
    /// Create new ringbuffer.
    /// Buffer will contain given number of blocks of given size.
    pub fn create(block_size: u32, block_count: u32, fd: libc::c_int) -> Result<Map, std::io::Error> {
        let size = usize::try_from(block_size).unwrap_or(usize::MAX)
            * usize::try_from(block_count).unwrap_or(usize::MAX);
        let p = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_LOCKED | libc::MAP_NORESERVE,
                fd,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Map {
            ptr: p,
            map_size: size,
            block_size,
            block_count,
        })
    }

    /// get pointer for descriptor block with given index.
    pub fn get_descriptor_ptr_for(&self, index: isize) -> *mut u8 {
        assert!(
            index < isize::try_from(self.block_count).unwrap_or(isize::MAX),
            "Trying to read block {index}, but only {} blocks available",
            self.block_count
        );
        let my_ptr = self.ptr;
        let buf_ptr = my_ptr.cast::<u8>();
        let block_size = isize::try_from(self.block_size).unwrap_or(isize::MAX);
        let offset = index * block_size;
        unsafe { buf_ptr.offset(offset) }
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        tracing::trace!("Dropping mapping @{:?}", self.ptr);
        unsafe { libc::munmap(self.ptr, self.map_size) };
    }
}
