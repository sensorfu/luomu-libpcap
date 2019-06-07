use luomu_libpcap::{PcapIfT, Result};

fn main() -> Result<()> {
    env_logger::init();

    let pcap_ifs = PcapIfT::new()?;
    for interface in pcap_ifs.get_interfaces() {
        println!("{:#?}", interface);
    }

    Ok(())
}
