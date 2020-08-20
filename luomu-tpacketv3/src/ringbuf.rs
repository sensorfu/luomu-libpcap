use crate::if_packet;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Descriptor for single packet within a block in mmapped ringbuffer
pub struct PacketDescriptor<'a> {
    ptr: *mut u8,
    hdr: &'a if_packet::tpacket3_hdr,
}

impl<'a> PacketDescriptor<'a> {
    #[allow(clippy::cast_ptr_alignment)]
    pub fn get_next(self) -> PacketDescriptor<'a> {
        let next_ptr = unsafe { self.ptr.offset(self.hdr.tp_next_offset as isize) };
        let next_hdr_ptr = next_ptr as *const if_packet::tpacket3_hdr;
        PacketDescriptor {
            ptr: next_ptr,
            hdr: unsafe { next_hdr_ptr.as_ref().unwrap() },
        }
    }

    pub fn get_timestamp(&self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.hdr.tp_sec as u64, self.hdr.tp_nsec)
    }

    pub fn get_packet_data(&self) -> &'a [u8] {
        let data_ptr = unsafe { self.ptr.offset(self.hdr.tp_mac as isize) };
        unsafe { std::slice::from_raw_parts(data_ptr, self.hdr.tp_snaplen as usize) }
    }
}

impl<'a> From<*mut u8> for PacketDescriptor<'a> {
    #[allow(clippy::cast_ptr_alignment)]
    fn from(ptr: *mut u8) -> Self {
        let hdr_ptr = ptr as *const if_packet::tpacket3_hdr;
        let hdr = unsafe { hdr_ptr.as_ref().unwrap() };
        PacketDescriptor { ptr, hdr }
    }
}

#[derive(Debug)]
/// Descriptor for a block inside the mmapped ringbuffer.
/// Block is either owned by kernel or ready. Ready block contains 1 or more
/// packets which can be read. Once all packets have been consumed,
/// flush() needs to be called to indicate kernel that it free to use this
/// block again
pub struct BlockDescriptor<'a> {
    ptr: *mut u8,                                // pointer to the start of the data
    desc: &'a mut if_packet::tpacket_block_desc, // the actual block descriptor
    name: String,
}

unsafe impl Send for BlockDescriptor<'_> {}

impl<'a> BlockDescriptor<'a> {
    pub fn flush(&mut self) {
        self.desc.hdr.block_status = if_packet::TP_STATUS_KERNEL
    }

    pub fn is_ready(&self) -> bool {
        self.desc.hdr.block_status & if_packet::TP_STATUS_USER != 0
    }

    pub fn get_number_of_packets(&self) -> u32 {
        self.desc.hdr.num_packets
    }

    pub fn get_first_packet(&self) -> PacketDescriptor<'a> {
        unsafe { self.ptr.offset(self.desc.hdr.offset_to_first_pkt as isize) }.into()
    }
}

impl<'a> From<*mut u8> for BlockDescriptor<'a> {
    #[allow(clippy::cast_ptr_alignment)]
    fn from(ptr: *mut u8) -> Self {
        let desc_ptr = ptr as *mut if_packet::tpacket_block_desc;

        BlockDescriptor {
            name: format!("block@{:?}", ptr),
            ptr,
            desc: unsafe { desc_ptr.as_mut().unwrap() },
        }
    }
}

impl fmt::Display for BlockDescriptor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ready:{}, num_packets: {}",
            self.name,
            self.is_ready(),
            self.get_number_of_packets()
        )
    }
}

/// mmapped ringbuffer. Contains blocks of packet data, each block will be filled
/// with packets by the kernel
pub struct Map {
    ptr: *mut libc::c_void,
    map_size: libc::size_t,
    block_size: u32,
    block_count: u32,
}

unsafe impl Send for Map {}

impl Map {
    /// Create new ringbuffer.
    /// Buffer will contain given number of blocks of given size.
    pub fn create(
        block_size: u32,
        block_count: u32,
        fd: libc::c_int,
    ) -> Result<Map, std::io::Error> {
        let size = (block_size * block_count) as libc::size_t;
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
        if index >= self.block_count as isize {
            panic!(
                "Trying to read block {}, but only {} blocks available",
                index, self.block_count
            );
        }
        let my_ptr = self.ptr;
        let buf_ptr = my_ptr as *mut u8;
        let offset = index * self.block_size as isize;
        unsafe { buf_ptr.offset(offset) }
    }
}

impl Drop for Map {
    fn drop(&mut self) {
        trace!("Dropping mapping @{:?}", self.ptr);
        unsafe { libc::munmap(self.ptr, self.map_size) };
    }
}
