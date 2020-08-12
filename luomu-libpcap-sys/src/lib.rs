#![no_std]
#![allow(non_camel_case_types, non_upper_case_globals)]
#![allow(clippy::redundant_static_lifetimes)]

use libc::{size_t, sockaddr, timeval, FILE};

use libc::c_uchar as u_char;
use libc::c_uint as u_int;
use libc::c_ushort as u_short;

include!("bindings.rs");
