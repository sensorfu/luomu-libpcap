#![allow(missing_docs)]

/// Prints Mac Addresses for all interfaces found
fn main() -> std::io::Result<()> {
    for ifa in luomu_getifaddrs::getifaddrs()? {
        if let Some(a) = ifa.addr().and_then(|a| a.as_mac()) {
            println!("{} {a}", ifa.name());
        }
    }

    Ok(())
}
