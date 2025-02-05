#![allow(missing_docs)]

fn main() -> std::io::Result<()> {
    use luomu_getifaddrs::getifaddrs;

    let ifaddrs = getifaddrs()?;

    for ifaddr in ifaddrs {
        println!("{:#?}", ifaddr.ifaddress())
    }

    Ok(())
}
