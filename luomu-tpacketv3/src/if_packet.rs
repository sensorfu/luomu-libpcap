//! structures, types and constants from <linux/if_packet.h>

#![allow(dead_code)] // not all declared types are used yet

pub const TPACKET_V3: libc::c_int = 2;

// socket options
pub const PACKET_ADD_MEMBERSHIP: libc::c_int = libc::PACKET_ADD_MEMBERSHIP;
pub const PACKET_RX_RING: libc::c_int = 5;
pub const PACKET_VERSION: libc::c_int = 10;
pub const PACKET_STATISTICS: libc::c_int = 6;
pub const PACKET_FANOUT: libc::c_int = 18;

// FANOUT modes
pub const PACKET_FANOUT_HASH: libc::c_int = 0;
pub const PACKET_FANOUT_LB: libc::c_int = 1;
pub const PACKET_FANOUT_CPU: libc::c_int = 2;
pub const PACKET_FANOUT_ROLLOVER: libc::c_int = 3;
pub const PACKET_FANOUT_RND: libc::c_int = 4;
pub const PACKET_FANOUT_QM: libc::c_int = 5;
pub const PACKET_FANOUT_CBPF: libc::c_int = 6;
pub const PACKET_FANOUT_EBPF: libc::c_int = 7;
// FANOUT flags
pub const PACKET_FANOUT_FLAG_ROLLOVER: libc::c_int = 0x1000;
pub const PACKET_FANOUT_FLAG_UNIQUEID: libc::c_int = 0x2000;
pub const PACKET_FLANOUT_FLAG_DEFRAG: libc::c_int = 0x800;

pub const TP_STATUS_KERNEL: u32 = 0;
pub const TP_STATUS_USER: u32 = 1;
pub const TP_STATUS_VLAN_VALID: u32 = 1 << 4;
pub const TP_STATUS_VLAN_TPID_VALID: u32 = 1 << 6;

#[repr(C)]
#[allow(non_camel_case_types)]
pub struct tpacket_req3 {
    pub tp_block_size: libc::c_uint,
    pub tp_block_nr: libc::c_uint,
    pub tp_frame_size: libc::c_uint,
    pub tp_frame_nr: libc::c_uint,
    pub tp_retire_blk_tov: libc::c_uint,
    pub tp_sizeof_priv: libc::c_uint,
    pub tp_feature_req_word: libc::c_uint,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct tpacket_hdr_variant1 {
    pub tp_rxhash: u32,
    pub tp_vlan_tci: u32,
    pub tp_vlan_tpid: u16,
    tp_padding: u16,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct tpacket3_hdr {
    pub tp_next_offset: u32,
    pub tp_sec: u32,
    pub tp_nsec: u32,
    pub tp_snaplen: u32,
    pub tp_len: u32,
    pub tp_status: u32,
    pub tp_mac: u16,
    pub tp_net: u16,
    pub hv1: tpacket_hdr_variant1,
    tp_padding: [u8; 8],
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct tpacket_bd_ts {
    pub ts_sec: libc::c_uint,
    pub ts_nsec: libc::c_uint, // really an union of ts_usec & ts_nsec
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct tpacket_hdr_v1 {
    pub block_status: u32,
    pub num_packets: u32,
    pub offset_to_first_pkt: u32,
    pub blk_len: u32,
    pub seq_num: u32,
    pub ts_first_packet: tpacket_bd_ts,
    pub ts_last_packet: tpacket_bd_ts,
}

#[repr(C)]
#[derive(Debug)]
#[allow(non_camel_case_types)]
pub struct tpacket_block_desc {
    pub version: u32,
    pub offset_to_priv: u32,
    pub hdr: tpacket_hdr_v1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub struct tpacket_stats_v3 {
    pub tp_packets: libc::c_uint,
    pub tp_drops: libc::c_uint,
    pub tp_freeze_q_cnt: libc::c_uint,
}
