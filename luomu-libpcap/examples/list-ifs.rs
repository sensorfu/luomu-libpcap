#![allow(missing_docs)]

use luomu_libpcap::{PcapIfT, Result};

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let pcap_ifs = PcapIfT::new()?;
    for interface in pcap_ifs.get_interfaces() {
        println!("{interface:#?}");
    }

    Ok(())
}
