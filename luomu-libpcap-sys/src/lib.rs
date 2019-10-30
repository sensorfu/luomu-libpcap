#![no_std]
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case)]
#![allow(clippy::unreadable_literal, clippy::redundant_static_lifetimes)]

use libc::{sockaddr, timeval, FILE};

use libc::c_uchar as u_char;
use libc::c_uint as u_int;
use libc::c_ushort as u_short;

include!("bindings.rs");
