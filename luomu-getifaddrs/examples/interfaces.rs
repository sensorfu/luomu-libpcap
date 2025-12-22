//! List all interfaces and their information

fn main() -> std::io::Result<()> {
    luomu_getifaddrs::getifaddrs()?
        .into_iter()
        .for_each(|ifaddr| println!("{:#?}", ifaddr.ifaddress()));
    Ok(())
}
