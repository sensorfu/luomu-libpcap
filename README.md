# luomu-libpcap

Safe and mostly sane Rust bindings for [libpcap](https://www.tcpdump.org/) and
some other network related functionalities.

## Crates

- `luomu-common` contains utilities for working with IP Addresses, MAC addresses
  and such.
- `luomu-getifaddrs` provides Rust bindings for `getiffaddrs()` to get network
  interface addresses and statistics.
- `luomu-libpcap` for safe and sane libpcap interface.
- `luomu-libpcap-sys` for unsafe Rust bindings generated directly from
  `libpcap`.
- `luomu-tpacketv3` contains Rust bindings for capturing network traffic on
  Linux with `AF_PACKET` sockets and
  [tpacket_v3](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt)

## License

See [LICENSE](LICENSE). MIT license.
