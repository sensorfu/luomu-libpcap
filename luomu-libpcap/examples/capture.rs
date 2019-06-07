use luomu_libpcap::{Pcap, Result};

fn main() -> Result<()> {
    env_logger::init();

    let pcap = Pcap::builder("en0")?
        .set_promiscuous(true)?
        .set_immediate(true)?
        .set_filter("udp")?
        .set_snaplen(65535)?
        .activate()?;

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
