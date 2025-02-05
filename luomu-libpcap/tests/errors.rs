#![allow(missing_docs)]

#[test]
fn test_anyhow_error() {
    fn do_stuff() -> anyhow::Result<()> {
        let _pcap = luomu_libpcap::Pcap::new("lo0")?;
        Ok(())
    }
    let _stuff = do_stuff();
}
