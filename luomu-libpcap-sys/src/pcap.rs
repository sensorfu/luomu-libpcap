/* automatically generated by rust-bindgen 0.54.1 */

pub const PCAP_VERSION_MAJOR: u32 = 2;
pub const PCAP_VERSION_MINOR: u32 = 4;
pub const PCAP_ERRBUF_SIZE: u32 = 256;
pub const PCAP_IF_LOOPBACK: u32 = 1;
pub const PCAP_IF_UP: u32 = 2;
pub const PCAP_IF_RUNNING: u32 = 4;
pub const PCAP_IF_WIRELESS: u32 = 8;
pub const PCAP_IF_CONNECTION_STATUS: u32 = 48;
pub const PCAP_IF_CONNECTION_STATUS_UNKNOWN: u32 = 0;
pub const PCAP_IF_CONNECTION_STATUS_CONNECTED: u32 = 16;
pub const PCAP_IF_CONNECTION_STATUS_DISCONNECTED: u32 = 32;
pub const PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE: u32 = 48;
pub const PCAP_ERROR: i32 = -1;
pub const PCAP_ERROR_BREAK: i32 = -2;
pub const PCAP_ERROR_NOT_ACTIVATED: i32 = -3;
pub const PCAP_ERROR_ACTIVATED: i32 = -4;
pub const PCAP_ERROR_NO_SUCH_DEVICE: i32 = -5;
pub const PCAP_ERROR_RFMON_NOTSUP: i32 = -6;
pub const PCAP_ERROR_NOT_RFMON: i32 = -7;
pub const PCAP_ERROR_PERM_DENIED: i32 = -8;
pub const PCAP_ERROR_IFACE_NOT_UP: i32 = -9;
pub const PCAP_ERROR_CANTSET_TSTAMP_TYPE: i32 = -10;
pub const PCAP_ERROR_PROMISC_PERM_DENIED: i32 = -11;
pub const PCAP_ERROR_TSTAMP_PRECISION_NOTSUP: i32 = -12;
pub const PCAP_WARNING: u32 = 1;
pub const PCAP_WARNING_PROMISC_NOTSUP: u32 = 2;
pub const PCAP_WARNING_TSTAMP_TYPE_NOTSUP: u32 = 3;
pub const PCAP_NETMASK_UNKNOWN: u32 = 4294967295;
pub const PCAP_TSTAMP_HOST: u32 = 0;
pub const PCAP_TSTAMP_HOST_LOWPREC: u32 = 1;
pub const PCAP_TSTAMP_HOST_HIPREC: u32 = 2;
pub const PCAP_TSTAMP_ADAPTER: u32 = 3;
pub const PCAP_TSTAMP_ADAPTER_UNSYNCED: u32 = 4;
pub const PCAP_TSTAMP_PRECISION_MICRO: u32 = 0;
pub const PCAP_TSTAMP_PRECISION_NANO: u32 = 1;
pub const PCAP_BUF_SIZE: u32 = 1024;
pub const PCAP_SRC_FILE: u32 = 2;
pub const PCAP_SRC_IFLOCAL: u32 = 3;
pub const PCAP_SRC_IFREMOTE: u32 = 4;
pub const PCAP_SRC_FILE_STRING: &'static [u8; 8usize] = b"file://\0";
pub const PCAP_SRC_IF_STRING: &'static [u8; 9usize] = b"rpcap://\0";
pub const PCAP_OPENFLAG_PROMISCUOUS: u32 = 1;
pub const PCAP_OPENFLAG_DATATX_UDP: u32 = 2;
pub const PCAP_OPENFLAG_NOCAPTURE_RPCAP: u32 = 4;
pub const PCAP_OPENFLAG_NOCAPTURE_LOCAL: u32 = 8;
pub const PCAP_OPENFLAG_MAX_RESPONSIVENESS: u32 = 16;
pub const PCAP_SAMP_NOSAMP: u32 = 0;
pub const PCAP_SAMP_1_EVERY_N: u32 = 1;
pub const PCAP_SAMP_FIRST_AFTER_N_MS: u32 = 2;
pub type bpf_int32 = libc::c_int;
pub type bpf_u_int32 = u_int;
#[repr(C)]
pub struct bpf_program {
    pub bf_len: u_int,
    pub bf_insns: *mut bpf_insn,
}
#[test]
fn bindgen_test_layout_bpf_program() {
    assert_eq!(
        ::core::mem::size_of::<bpf_program>(),
        16usize,
        concat!("Size of: ", stringify!(bpf_program))
    );
    assert_eq!(
        ::core::mem::align_of::<bpf_program>(),
        8usize,
        concat!("Alignment of ", stringify!(bpf_program))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<bpf_program>())).bf_len as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_program),
            "::",
            stringify!(bf_len)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<bpf_program>())).bf_insns as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_program),
            "::",
            stringify!(bf_insns)
        )
    );
}
#[repr(C)]
pub struct bpf_insn {
    pub code: u_short,
    pub jt: u_char,
    pub jf: u_char,
    pub k: bpf_u_int32,
}
#[test]
fn bindgen_test_layout_bpf_insn() {
    assert_eq!(
        ::core::mem::size_of::<bpf_insn>(),
        8usize,
        concat!("Size of: ", stringify!(bpf_insn))
    );
    assert_eq!(
        ::core::mem::align_of::<bpf_insn>(),
        4usize,
        concat!("Alignment of ", stringify!(bpf_insn))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<bpf_insn>())).code as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_insn),
            "::",
            stringify!(code)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<bpf_insn>())).jt as *const _ as usize },
        2usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_insn),
            "::",
            stringify!(jt)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<bpf_insn>())).jf as *const _ as usize },
        3usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_insn),
            "::",
            stringify!(jf)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<bpf_insn>())).k as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(bpf_insn),
            "::",
            stringify!(k)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcap {
    _unused: [u8; 0],
}
pub type pcap_t = pcap;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcap_dumper {
    _unused: [u8; 0],
}
pub type pcap_dumper_t = pcap_dumper;
pub type pcap_if_t = pcap_if;
pub type pcap_addr_t = pcap_addr;
#[repr(C)]
pub struct pcap_file_header {
    pub magic: bpf_u_int32,
    pub version_major: u_short,
    pub version_minor: u_short,
    pub thiszone: bpf_int32,
    pub sigfigs: bpf_u_int32,
    pub snaplen: bpf_u_int32,
    pub linktype: bpf_u_int32,
}
#[test]
fn bindgen_test_layout_pcap_file_header() {
    assert_eq!(
        ::core::mem::size_of::<pcap_file_header>(),
        24usize,
        concat!("Size of: ", stringify!(pcap_file_header))
    );
    assert_eq!(
        ::core::mem::align_of::<pcap_file_header>(),
        4usize,
        concat!("Alignment of ", stringify!(pcap_file_header))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_file_header>())).magic as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_file_header),
            "::",
            stringify!(magic)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_file_header>())).version_major as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_file_header),
            "::",
            stringify!(version_major)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_file_header>())).version_minor as *const _ as usize },
        6usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_file_header),
            "::",
            stringify!(version_minor)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_file_header>())).thiszone as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_file_header),
            "::",
            stringify!(thiszone)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_file_header>())).sigfigs as *const _ as usize },
        12usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_file_header),
            "::",
            stringify!(sigfigs)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_file_header>())).snaplen as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_file_header),
            "::",
            stringify!(snaplen)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_file_header>())).linktype as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_file_header),
            "::",
            stringify!(linktype)
        )
    );
}
pub const pcap_direction_t_PCAP_D_INOUT: pcap_direction_t = 0;
pub const pcap_direction_t_PCAP_D_IN: pcap_direction_t = 1;
pub const pcap_direction_t_PCAP_D_OUT: pcap_direction_t = 2;
pub type pcap_direction_t = u32;
#[repr(C)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: bpf_u_int32,
    pub len: bpf_u_int32,
}
#[test]
fn bindgen_test_layout_pcap_pkthdr() {
    assert_eq!(
        ::core::mem::size_of::<pcap_pkthdr>(),
        24usize,
        concat!("Size of: ", stringify!(pcap_pkthdr))
    );
    assert_eq!(
        ::core::mem::align_of::<pcap_pkthdr>(),
        8usize,
        concat!("Alignment of ", stringify!(pcap_pkthdr))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_pkthdr>())).ts as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_pkthdr),
            "::",
            stringify!(ts)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_pkthdr>())).caplen as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_pkthdr),
            "::",
            stringify!(caplen)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_pkthdr>())).len as *const _ as usize },
        20usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_pkthdr),
            "::",
            stringify!(len)
        )
    );
}
#[repr(C)]
pub struct pcap_stat {
    pub ps_recv: u_int,
    pub ps_drop: u_int,
    pub ps_ifdrop: u_int,
}
#[test]
fn bindgen_test_layout_pcap_stat() {
    assert_eq!(
        ::core::mem::size_of::<pcap_stat>(),
        12usize,
        concat!("Size of: ", stringify!(pcap_stat))
    );
    assert_eq!(
        ::core::mem::align_of::<pcap_stat>(),
        4usize,
        concat!("Alignment of ", stringify!(pcap_stat))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_stat>())).ps_recv as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_stat),
            "::",
            stringify!(ps_recv)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_stat>())).ps_drop as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_stat),
            "::",
            stringify!(ps_drop)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_stat>())).ps_ifdrop as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_stat),
            "::",
            stringify!(ps_ifdrop)
        )
    );
}
#[repr(C)]
pub struct pcap_if {
    pub next: *mut pcap_if,
    pub name: *mut libc::c_char,
    pub description: *mut libc::c_char,
    pub addresses: *mut pcap_addr,
    pub flags: bpf_u_int32,
}
#[test]
fn bindgen_test_layout_pcap_if() {
    assert_eq!(
        ::core::mem::size_of::<pcap_if>(),
        40usize,
        concat!("Size of: ", stringify!(pcap_if))
    );
    assert_eq!(
        ::core::mem::align_of::<pcap_if>(),
        8usize,
        concat!("Alignment of ", stringify!(pcap_if))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_if>())).next as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_if),
            "::",
            stringify!(next)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_if>())).name as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_if),
            "::",
            stringify!(name)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_if>())).description as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_if),
            "::",
            stringify!(description)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_if>())).addresses as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_if),
            "::",
            stringify!(addresses)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_if>())).flags as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_if),
            "::",
            stringify!(flags)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcap_addr {
    pub next: *mut pcap_addr,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}
#[test]
fn bindgen_test_layout_pcap_addr() {
    assert_eq!(
        ::core::mem::size_of::<pcap_addr>(),
        40usize,
        concat!("Size of: ", stringify!(pcap_addr))
    );
    assert_eq!(
        ::core::mem::align_of::<pcap_addr>(),
        8usize,
        concat!("Alignment of ", stringify!(pcap_addr))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_addr>())).next as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_addr),
            "::",
            stringify!(next)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_addr>())).addr as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_addr),
            "::",
            stringify!(addr)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_addr>())).netmask as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_addr),
            "::",
            stringify!(netmask)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_addr>())).broadaddr as *const _ as usize },
        24usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_addr),
            "::",
            stringify!(broadaddr)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_addr>())).dstaddr as *const _ as usize },
        32usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_addr),
            "::",
            stringify!(dstaddr)
        )
    );
}
pub type pcap_handler = ::core::option::Option<
    unsafe extern "C" fn(arg1: *mut u_char, arg2: *const pcap_pkthdr, arg3: *const u_char),
>;
extern "C" {
    pub fn pcap_lookupdev(arg1: *mut libc::c_char) -> *mut libc::c_char;
}
extern "C" {
    pub fn pcap_lookupnet(
        arg1: *const libc::c_char,
        arg2: *mut bpf_u_int32,
        arg3: *mut bpf_u_int32,
        arg4: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_create(arg1: *const libc::c_char, arg2: *mut libc::c_char) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_promisc(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_rfmon(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_timeout(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_tstamp_type(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_tstamp_precision(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_activate(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_list_tstamp_types(arg1: *mut pcap_t, arg2: *mut *mut libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_free_tstamp_types(arg1: *mut libc::c_int);
}
extern "C" {
    pub fn pcap_tstamp_type_name_to_val(arg1: *const libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_tstamp_type_val_to_name(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_tstamp_type_val_to_description(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_open_live(
        arg1: *const libc::c_char,
        arg2: libc::c_int,
        arg3: libc::c_int,
        arg4: libc::c_int,
        arg5: *mut libc::c_char,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_dead(arg1: libc::c_int, arg2: libc::c_int) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_dead_with_tstamp_precision(
        arg1: libc::c_int,
        arg2: libc::c_int,
        arg3: u_int,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_offline_with_tstamp_precision(
        arg1: *const libc::c_char,
        arg2: u_int,
        arg3: *mut libc::c_char,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_offline(arg1: *const libc::c_char, arg2: *mut libc::c_char) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_fopen_offline_with_tstamp_precision(
        arg1: *mut FILE,
        arg2: u_int,
        arg3: *mut libc::c_char,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut libc::c_char) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_close(arg1: *mut pcap_t);
}
extern "C" {
    pub fn pcap_loop(
        arg1: *mut pcap_t,
        arg2: libc::c_int,
        arg3: pcap_handler,
        arg4: *mut u_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_dispatch(
        arg1: *mut pcap_t,
        arg2: libc::c_int,
        arg3: pcap_handler,
        arg4: *mut u_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_next(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const u_char;
}
extern "C" {
    pub fn pcap_next_ex(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const u_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_breakloop(arg1: *mut pcap_t);
}
extern "C" {
    pub fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> libc::c_int;
}
extern "C" {
    pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> libc::c_int;
}
extern "C" {
    pub fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_setnonblock(
        arg1: *mut pcap_t,
        arg2: libc::c_int,
        arg3: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_inject(arg1: *mut pcap_t, arg2: *const libc::c_void, arg3: size_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_sendpacket(
        arg1: *mut pcap_t,
        arg2: *const u_char,
        arg3: libc::c_int,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_statustostr(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_strerror(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut libc::c_char;
}
extern "C" {
    pub fn pcap_perror(arg1: *mut pcap_t, arg2: *const libc::c_char);
}
extern "C" {
    pub fn pcap_compile(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const libc::c_char,
        arg4: libc::c_int,
        arg5: bpf_u_int32,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_compile_nopcap(
        arg1: libc::c_int,
        arg2: libc::c_int,
        arg3: *mut bpf_program,
        arg4: *const libc::c_char,
        arg5: libc::c_int,
        arg6: bpf_u_int32,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_freecode(arg1: *mut bpf_program);
}
extern "C" {
    pub fn pcap_offline_filter(
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const u_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_datalink(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_datalink(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_free_datalinks(arg1: *mut libc::c_int);
}
extern "C" {
    pub fn pcap_datalink_name_to_val(arg1: *const libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_datalink_val_to_name(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_datalink_val_to_description(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_datalink_val_to_description_or_dlt(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_snapshot(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_is_swapped(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_major_version(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_minor_version(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_bufsize(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;
}
extern "C" {
    pub fn pcap_fileno(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const libc::c_char) -> *mut pcap_dumper_t;
}
extern "C" {
    pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
}
extern "C" {
    pub fn pcap_dump_open_append(
        arg1: *mut pcap_t,
        arg2: *const libc::c_char,
    ) -> *mut pcap_dumper_t;
}
extern "C" {
    pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
}
extern "C" {
    pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> libc::c_long;
}
extern "C" {
    pub fn pcap_dump_ftell64(arg1: *mut pcap_dumper_t) -> i64;
}
extern "C" {
    pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_dump_close(arg1: *mut pcap_dumper_t);
}
extern "C" {
    pub fn pcap_dump(arg1: *mut u_char, arg2: *const pcap_pkthdr, arg3: *const u_char);
}
extern "C" {
    pub fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_freealldevs(arg1: *mut pcap_if_t);
}
extern "C" {
    pub fn pcap_lib_version() -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_get_required_select_timeout(arg1: *mut pcap_t) -> *mut timeval;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcap_rmtauth {
    pub type_: libc::c_int,
    pub username: *mut libc::c_char,
    pub password: *mut libc::c_char,
}
#[test]
fn bindgen_test_layout_pcap_rmtauth() {
    assert_eq!(
        ::core::mem::size_of::<pcap_rmtauth>(),
        24usize,
        concat!("Size of: ", stringify!(pcap_rmtauth))
    );
    assert_eq!(
        ::core::mem::align_of::<pcap_rmtauth>(),
        8usize,
        concat!("Alignment of ", stringify!(pcap_rmtauth))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_rmtauth>())).type_ as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_rmtauth),
            "::",
            stringify!(type_)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_rmtauth>())).username as *const _ as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_rmtauth),
            "::",
            stringify!(username)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_rmtauth>())).password as *const _ as usize },
        16usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_rmtauth),
            "::",
            stringify!(password)
        )
    );
}
extern "C" {
    pub fn pcap_open(
        source: *const libc::c_char,
        snaplen: libc::c_int,
        flags: libc::c_int,
        read_timeout: libc::c_int,
        auth: *mut pcap_rmtauth,
        errbuf: *mut libc::c_char,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_createsrcstr(
        source: *mut libc::c_char,
        type_: libc::c_int,
        host: *const libc::c_char,
        port: *const libc::c_char,
        name: *const libc::c_char,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_parsesrcstr(
        source: *const libc::c_char,
        type_: *mut libc::c_int,
        host: *mut libc::c_char,
        port: *mut libc::c_char,
        name: *mut libc::c_char,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_findalldevs_ex(
        source: *const libc::c_char,
        auth: *mut pcap_rmtauth,
        alldevs: *mut *mut pcap_if_t,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcap_samp {
    pub method: libc::c_int,
    pub value: libc::c_int,
}
#[test]
fn bindgen_test_layout_pcap_samp() {
    assert_eq!(
        ::core::mem::size_of::<pcap_samp>(),
        8usize,
        concat!("Size of: ", stringify!(pcap_samp))
    );
    assert_eq!(
        ::core::mem::align_of::<pcap_samp>(),
        4usize,
        concat!("Alignment of ", stringify!(pcap_samp))
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_samp>())).method as *const _ as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_samp),
            "::",
            stringify!(method)
        )
    );
    assert_eq!(
        unsafe { &(*(::core::ptr::null::<pcap_samp>())).value as *const _ as usize },
        4usize,
        concat!(
            "Offset of field: ",
            stringify!(pcap_samp),
            "::",
            stringify!(value)
        )
    );
}
extern "C" {
    pub fn pcap_setsampling(p: *mut pcap_t) -> *mut pcap_samp;
}
extern "C" {
    pub fn pcap_remoteact_accept(
        address: *const libc::c_char,
        port: *const libc::c_char,
        hostlist: *const libc::c_char,
        connectinghost: *mut libc::c_char,
        auth: *mut pcap_rmtauth,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_remoteact_list(
        hostlist: *mut libc::c_char,
        sep: libc::c_char,
        size: libc::c_int,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_remoteact_close(
        host: *const libc::c_char,
        errbuf: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_remoteact_cleanup();
}