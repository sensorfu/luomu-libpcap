#![allow(missing_docs)]

use std::env;
use std::fmt::Write;

use luomu_libpcap::{Packet, Pcap};

fn main() {
    tracing_subscriber::fmt::init();

    let Some(fname) = env::args().nth(1) else {
        tracing::error!("No PCAP file name given");
        return;
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
            let _ = write!(hex, "{:02x}", packet[i]);
        }
        println!("Packet {} ({} bytes): {}", count + 1, packet.len(), hex);
    }
}
