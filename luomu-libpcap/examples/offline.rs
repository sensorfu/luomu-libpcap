#![allow(missing_docs)]

use std::env;

use luomu_libpcap::{Packet, Pcap};

fn main() {
    env_logger::init();
    let fname = match env::args().nth(1) {
        None => {
            log::error!("No PCAP file name given");
            return;
        }
        Some(n) => n,
    };

    let pcap = Pcap::offline(&fname).unwrap();
    for (count, pkt) in pcap.capture().enumerate() {
        let packet = pkt.packet();
        let mut hex = String::new();
        for (i, _) in packet.iter().enumerate() {
            if i % 4 == 0 {
                hex.push(' ');
            }
            if i % 32 == 0 {
                hex.push('\n');
            }
            hex.push_str(&format!("{:02x}", packet[i]));
        }
        println!("Packet {} ({} bytes): {}", count + 1, packet.len(), hex);
    }
}
