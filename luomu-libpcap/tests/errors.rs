#[test]
fn test_anyhow_error() {
    fn do_stuff() -> anyhow::Result<()> {
        let _ = luomu_libpcap::Pcap::new("lo0")?;
        Ok(())
    }
    let _ = do_stuff();
}
