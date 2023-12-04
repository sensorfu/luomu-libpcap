# luomu-libpcap

Safe and mostly sane Rust bindings for [libpcap](https://www.tcpdump.org/) and
some other network related functionalities.

## Lipcap bindings

Libpacp bindings are split in two different crates:

- `luomu-libpcap-sys` for unsafe Rust bindings generated directly from
  `libpcap`.
- `luomu-libpcap` for safe and sane libpcap interface.

`luomu-libpcap` crate is split into two parts itself:

- `functions` module contains safe wrappers and sane return values for libpcap
  functions.
- the root of the project contains `Pcap` struct et al. for more Rusty API to
  interact with libpcap.

### Example

```rust
use luomu_libpcap::{Pcap, Result};

fn main() -> Result<()> {
    let pcap = Pcap::builder("en0")?
        .set_promiscuous(true)?
        .set_immediate(true)?
        .set_snaplen(65535)?
        .set_buffer_size(512 * 1024)?
        .activate()?;

    pcap.set_filter("udp")?;

    for packet in pcap.capture() {
        let mut hex = String::new();
        for i in 0..packet.len() {
            if i % 4 == 0 {
                hex.push(' ');
            }
            if i % 32 == 0 {
                hex.push('\n');
            }
            hex.push_str(&format!("{:02x}", packet[i]));
        }
        println!("{}", hex);
    }

    Ok(())
}
```

## Other crates

Other crates, these do not require or use `libpcap`:

- `luomu-tpacketv3` contains Rust bindings for capturing network traffic on
  Linux with `AF_PACKET` sockets and
  [tpcacket_v3](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt)
- `luomu-getifaddrs` provides Rust bindings for `getiffaddrs()` to get network
  interface addresses and statistics with
- `luomu-common` contains utilities for working with IP Addresses, MAC addresses
  and such.

You probably want to use the `Pcap` struct and other things from root of this
crate.

## License

See [LICENSE](LICENSE). MIT license.
