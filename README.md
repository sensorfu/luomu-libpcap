# luomu-libpcap

Safe and mostly sane Rust bindings for [libpcap](https://www.tcpdump.org/).

We are split in two different crates:
  * `luomu-libpcap-sys` for unsafe Rust bindings generated directly from
    `libpcap`.
  * `luomu-libpcap` for safe and sane libpcap interface.

`luomu-libpcap` crate is split into two parts itself:
  * `functions` module contains safe wrappers and sane return values for libpcap
    functions.
  * the root of the project contains `Pcap` struct et al. for more Rusty API to
    interact with libpcap.

You probably want to use the `Pcap` struct and other things from root of this
crate.

## Example

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

## License

See [LICENSE](LICENSE). MIT license.
