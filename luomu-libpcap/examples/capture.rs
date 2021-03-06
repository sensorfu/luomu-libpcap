use luomu_libpcap::{Pcap, Result};

fn main() -> Result<()> {
    env_logger::init();

    let pcap = Pcap::builder("en0")?
        .set_promiscuous(true)?
        .set_immediate(true)?
        .set_snaplen(65535)?
        .set_buffer_size(512 * 1024)?
        .activate()?;

    pcap.set_filter("udp")?;

    let mut count = 0;
    for packet in pcap.capture() {
        let packet = packet.packet();
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
        count += 1;
        println!("{}", hex);
        if count % 100 == 0 && count != 0 {
            match pcap.stats() {
                Ok(stats) => println!(
                    "\nStats: received: {} packets, dropped: {} packets, dropped on interface {} packets",
                    stats.packets_received(),
                    stats.packets_dropped(),
                    stats.packets_dropped_interface()
                ),
                Err(_) => {}
            }
        }
    }

    Ok(())
}
