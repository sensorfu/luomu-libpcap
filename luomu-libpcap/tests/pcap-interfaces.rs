use std::net::IpAddr;

use luomu_libpcap::{PcapIfT, Result};

#[test]
fn test_get_interfaces() -> Result<()> {
    let pcap_ifs = PcapIfT::new()?;
    let _ = pcap_ifs.get_interfaces();
    Ok(())
}

#[test]
fn test_find_localhost() -> Result<()> {
    let localhost: IpAddr = "127.0.0.1".parse().unwrap();
    let pcap_ifs = PcapIfT::new()?;
    for interface in pcap_ifs.get_interfaces() {
        if interface.has_address(&localhost) {
            return Ok(());
        }
    }
    assert!(false, "Couldn't find localhost");
    unreachable!("execution shouldn't get here")
}
